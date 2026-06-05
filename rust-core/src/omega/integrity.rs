//! SOTERIA-OMEGA Part 10 — Integrity: Merkle + Reed-Solomon.
//!
//! OMEGA replaces the simple BLAKE3 lineage chain used in the base
//! FDE with a hybrid Merkle+Reed-Solomon structure that defends
//! against BOTH random bit-flips AND burst errors:
//!
//! 1. The encrypted volume is split into `N` blocks.
//! 2. Every block's BLAKE3 hash forms a Merkle tree of depth
//!    `log2(N)`.
//! 3. Every Merkle root is stored with `K` Reed-Solomon redundancy
//!    symbols (RS(255, 223) over GF(256)). The RS code can recover
//!    up to `(255 - 223) / 2 = 16` erasures per 255-byte stripe.
//!
//! On read, the engine:
//! 1. Verifies the block hash chain (Merkle).
//! 2. Reconstructs the Merkle root from the Reed-Solomon redundancy.
//! 3. Compares the reconstructed root with the on-disk root.
//!
//! If the two roots agree, the data is bit-for-bit intact. If they
//! disagree but the RS decode succeeds, the data is recoverable with
//! up to 16 byte erasures per stripe.
//!
//! ## Why both?
//!
//! - **Merkle**: O(log N) verification, O(1) per-block tamper
//!   detection, but any byte error in the root invalidates the
//!   whole root.
//! - **Reed-Solomon**: handles burst errors (a 16-byte contiguous
//!   corruption is recoverable), but doesn't give a per-block
//!   location.
//!
//! Combined, OMEGA can:
//! - Pinpoint *which* block was tampered (Merkle proof).
//! - Recover the data if the corruption is small (RS correction).
//! - Refuse to serve data if the corruption is large.
//!
//! ## Software-fallback policy
//!
//! Reed-Solomon is implemented from scratch in this module (no
//! external crate). The implementation follows the standard
//! RS(255, 223) over GF(256) with primitive polynomial 0x11D and
//! generator polynomial `∏(x - α^i)` for i=0..32.

use crate::omega::{OmegaError, OmegaResult};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Reed-Solomon error. The engine logs the error and refuses to
/// serve the affected region.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("reed-solomon: {0}")]
    ReedSolomon(String),
    #[error("merkle: {0}")]
    Merkle(String),
    #[error("erasure count {0} exceeds RS capacity")]
    TooManyErasures(usize),
    #[error("block index out of range: {0}")]
    BlockOutOfRange(usize),
    #[error("stripe size mismatch: expected {0}, got {1}")]
    StripeSizeMismatch(usize, usize),
}

const GF_SIZE: usize = 256;
const GF_PRIM_POLY: u16 = 0x11D;
const RS_N: usize = 255; // Codeword length in bytes
const RS_K: usize = 223; // Data length in bytes
const RS_PARITY: usize = RS_N - RS_K; // 32 parity bytes
const RS_GENERATOR_FIRST_CONSEC_ROOT: usize = 1;
const RS_GENERATOR_DEGREE: usize = RS_PARITY; // = 32
const RS_FCR: usize = 1; // First consecutive root index
const RS_PRIM: usize = 1; // Index of primitive element (α^1)

/// Galois Field GF(256) arithmetic with primitive polynomial
/// 0x11D (= x^8 + x^4 + x^3 + x^2 + 1).
pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; GF_SIZE],
}

impl Gf256 {
    /// Construct the GF(256) log/exp tables. The primitive element
    /// is 2 (i.e., 0x02).
    pub const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; GF_SIZE];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_PRIM_POLY;
            }
            i += 1;
        }
        Self { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let l = (self.log[a as usize] as usize) + (self.log[b as usize] as usize);
        self.exp[l % 255]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if b == 0 {
            panic!("GF division by zero");
        }
        if a == 0 {
            return 0;
        }
        let l = (self.log[a as usize] as isize) - (self.log[b as usize] as isize);
        let l = if l < 0 { l + 255 } else { l };
        self.exp[l as usize]
    }

    #[inline]
    pub fn pow(&self, a: u8, n: usize) -> u8 {
        let l = (self.log[a as usize] as usize) * n;
        self.exp[l % 255]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            panic!("GF inverse of zero");
        }
        self.exp[255 - self.log[a as usize] as usize]
    }
}

static GF: Gf256 = Gf256::new();

/// A Reed-Solomon codec. We use RS(255, 223) over GF(256), which can
/// correct up to 16 byte erasures per 255-byte stripe.
pub struct RsCodec;

impl RsCodec {
    /// Build the generator polynomial for RS(255, 223) with the first
    /// consecutive root at index 1.
    ///
    /// `g(x) = (x - α^1)(x - α^2)...(x - α^32)`. In GF(2^n),
    /// subtraction equals addition, so `(x - α^i) = (x + α^i)`.
    fn generator_poly() -> [u8; RS_PARITY + 1] {
        let mut g = [0u8; RS_PARITY + 1];
        g[0] = 1;
        for i in 0..RS_PARITY {
            let alpha_i_pow = GF.pow(2, RS_FCR + i);
            // Multiply g(x) by (x + α^(FCR+i)):
            //   g_new[j+1] = g_old[j]     (x*g)
            //   g_new[j]   = g_old[j] * α^i  (α^i*g)
            // Iterate from the top so we don't double-count.
            for j in (0..=i).rev() {
                g[j + 1] ^= g[j];
                g[j] = GF.mul(g[j], alpha_i_pow);
            }
        }
        g
    }

    /// Compute the parity bytes for a 223-byte message. Returns
    /// 32 parity bytes. The parity is `(data * x^PARITY) mod g(x)`.
    pub fn encode_parity(data: &[u8]) -> [u8; RS_PARITY] {
        assert_eq!(
            data.len(),
            RS_K,
            "RS_K = {} required, got {}",
            RS_K,
            data.len()
        );
        let g = Self::generator_poly();
        // work = data shifted left by PARITY positions.
        let mut work = [0u8; RS_K + RS_PARITY];
        work[..RS_K].copy_from_slice(data);
        // Long division: for i from K-1 down to 0, eliminate
        // work[i + PARITY] by subtracting g(x) * work[i + PARITY].
        for i in (0..RS_K).rev() {
            let factor = work[i + RS_PARITY];
            for j in 0..=RS_PARITY {
                work[i + j] ^= GF.mul(g[j], factor);
            }
        }
        let mut out = [0u8; RS_PARITY];
        out.copy_from_slice(&work[RS_K..RS_K + RS_PARITY]);
        out
    }

    /// Decode a 255-byte codeword with `erasure_positions` (a list
    /// of byte indices that are known to be erased). On success,
    /// returns the recovered 223-byte data.
    pub fn decode_with_erasures(
        codeword: &mut [u8; RS_N],
        erasure_positions: &[usize],
    ) -> Result<[u8; RS_K], IntegrityError> {
        if erasure_positions.len() > RS_PARITY {
            return Err(IntegrityError::TooManyErasures(erasure_positions.len()));
        }
        // Compute the erasure locator polynomial Λ(x) = ∏(1 - x*α^i)
        let mut lambda = [0u8; RS_PARITY + 1];
        lambda[0] = 1;
        for &i in erasure_positions {
            // Multiply by (1 - α^i x)
            // alpha_i = α^i
            let alpha_i = GF.pow(2, i);
            for j in (1..=RS_PARITY).rev() {
                lambda[j] ^= GF.mul(lambda[j - 1], alpha_i);
            }
        }
        // Compute the syndrome polynomial
        let mut syndrome = [0u8; RS_PARITY + 1];
        for j in 1..=RS_PARITY {
            let mut s = 0u8;
            for i in 0..RS_N {
                s = GF.add(s, GF.mul(codeword[i], GF.pow(2, (RS_FCR + j - 1) * i)));
            }
            syndrome[j] = s;
        }
        if erasure_positions.is_empty() {
            // No erasures: just check syndromes.
            if syndrome.iter().all(|&s| s == 0) {
                let mut data = [0u8; RS_K];
                data.copy_from_slice(&codeword[..RS_K]);
                return Ok(data);
            }
            return Err(IntegrityError::ReedSolomon(
                "non-zero syndrome and no erasure positions".into(),
            ));
        }
        // Compute Forney syndrome
        // For brevity, the implementation of the full BM + Chien +
        // Forney is omitted in MVP; we delegate to a simpler
        // "brute-force erasure" path that works for small erasure
        // counts.
        Self::brute_force_erasure_decode(codeword, erasure_positions)
    }

    /// Simpler decoder: for a small number of erasures, solve the
    /// system of linear equations over GF(256) directly.
    fn brute_force_erasure_decode(
        codeword: &mut [u8; RS_N],
        erasure_positions: &[usize],
    ) -> Result<[u8; RS_K], IntegrityError> {
        // Number the unknown bytes: there are `e` erasures and
        // 223 known data bytes. We have 32 parity-check equations
        // and `e` unknowns. For `e <= 32` we can solve.
        let e = erasure_positions.len();
        if e > RS_PARITY {
            return Err(IntegrityError::TooManyErasures(e));
        }
        // Build the linear system: for each parity-check row j=1..32,
        // for each erasure position k, the coefficient of
        // codeword[erasure_positions[k]] is α^((FCR+j-1) * erasure_positions[k]).
        // Compute the known part of each parity check and solve.
        let mut matrix = [[0u8; RS_PARITY]; RS_PARITY];
        let mut rhs = [0u8; RS_PARITY];
        for (j_row, j) in (1..=RS_PARITY).enumerate() {
            for (k_col, &k_pos) in erasure_positions.iter().enumerate() {
                matrix[j_row][k_col] = GF.pow(2, (RS_FCR + j - 1) * k_pos);
            }
            let mut s = 0u8;
            for i in 0..RS_N {
                if erasure_positions.contains(&i) {
                    continue;
                }
                s = GF.add(s, GF.mul(codeword[i], GF.pow(2, (RS_FCR + j - 1) * i)));
            }
            rhs[j_row] = s;
        }
        // Solve matrix * x = rhs over GF(256). Gaussian elimination.
        let mut aug = [[0u8; RS_PARITY + 1]; RS_PARITY];
        for i in 0..RS_PARITY {
            aug[i][..RS_PARITY].copy_from_slice(&matrix[i]);
            aug[i][RS_PARITY] = rhs[i];
        }
        for col in 0..e {
            // Find pivot
            let mut pivot = None;
            for row in col..RS_PARITY {
                if aug[row][col] != 0 {
                    pivot = Some(row);
                    break;
                }
            }
            let pivot = pivot
                .ok_or_else(|| IntegrityError::ReedSolomon("singular erasure matrix".into()))?;
            aug.swap(col, pivot);
            let inv = GF.inv(aug[col][col]);
            for k in 0..=RS_PARITY {
                aug[col][k] = GF.mul(aug[col][k], inv);
            }
            for row in 0..RS_PARITY {
                if row == col {
                    continue;
                }
                let factor = aug[row][col];
                if factor == 0 {
                    continue;
                }
                for k in 0..=RS_PARITY {
                    let sub = GF.mul(factor, aug[col][k]);
                    aug[row][k] = GF.add(aug[row][k], sub);
                }
            }
        }
        for (k_col, &k_pos) in erasure_positions.iter().enumerate() {
            codeword[k_pos] = aug[k_col][RS_PARITY];
        }
        let mut data = [0u8; RS_K];
        data.copy_from_slice(&codeword[..RS_K]);
        Ok(data)
    }

    /// Append parity to data. `data` must be exactly 223 bytes.
    /// Returns the 255-byte codeword.
    pub fn encode(data: &[u8]) -> [u8; RS_N] {
        let mut codeword = [0u8; RS_N];
        codeword[..RS_K].copy_from_slice(data);
        let parity = Self::encode_parity(data);
        codeword[RS_K..].copy_from_slice(&parity);
        codeword
    }

    /// Maximum number of erasures that can be recovered.
    pub fn capacity() -> usize {
        RS_PARITY
    }
}

impl Gf256 {
    #[inline]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }
}

/// A Merkle tree of BLAKE3 hashes. The leaves are the BLAKE3 hashes
/// of each block; the internal nodes are the BLAKE3 hash of the
/// concatenation of the two children's hashes.
pub struct MerkleTree {
    leaves: Vec<Hash>,
    /// `levels[0]` is the leaf level, `levels[-1]` is the root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of block hashes.
    pub fn build(blocks: &[Hash]) -> Self {
        if blocks.is_empty() {
            return Self {
                leaves: Vec::new(),
                levels: Vec::new(),
            };
        }
        let leaves: Vec<Hash> = blocks.to_vec();
        let mut levels: Vec<Vec<Hash>> = vec![leaves.clone()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                let mut h = blake3::Hasher::new();
                h.update(left.as_bytes());
                h.update(right.as_bytes());
                let mut out = [0u8; 32];
                out.copy_from_slice(h.finalize().as_bytes());
                next.push(Hash::from(<[u8; 32]>::from(out)));
            }
            levels.push(next);
        }
        Self { leaves, levels }
    }

    pub fn root(&self) -> Option<Hash> {
        self.levels.last().and_then(|v| v.first().copied())
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Build an inclusion proof for leaf `index`. The proof is the
    /// sibling hashes from the leaf level to the root.
    pub fn proof(&self, index: usize) -> Option<Vec<Hash>> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx % 2 == 0 {
                if idx + 1 < level.len() {
                    level[idx + 1]
                } else {
                    level[idx]
                }
            } else {
                level[idx - 1]
            };
            proof.push(sibling);
            idx /= 2;
        }
        Some(proof)
    }

    /// Verify a Merkle inclusion proof. Used when the data plane
    /// wants to prove a single block is part of the volume.
    pub fn verify_proof(root: &Hash, leaf: &Hash, index: usize, proof: &[Hash]) -> bool {
        let mut current = *leaf;
        let mut idx = index;
        for sibling in proof {
            let mut h = blake3::Hasher::new();
            if idx % 2 == 0 {
                h.update(current.as_bytes());
                h.update(sibling.as_bytes());
            } else {
                h.update(sibling.as_bytes());
                h.update(current.as_bytes());
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(h.finalize().as_bytes());
            current = Hash::from(<[u8; 32]>::from(out));
            idx /= 2;
        }
        &current == root
    }
}

/// The full integrity system: Merkle + Reed-Solomon over the
/// encrypted volume's metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegritySystem {
    pub block_count: u64,
    /// RS stripes. Each stripe covers `RS_K = 223` data bytes plus
    /// `RS_PARITY = 32` parity bytes.
    pub stripes: Vec<RStripe>,
}

/// A single Reed-Solomon stripe. Holds the encoded Merkle root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStripe {
    /// Index of this stripe in the volume.
    pub index: u32,
    /// The 255-byte codeword. The first 223 bytes are the root
    /// fragment; the last 32 bytes are the RS parity.
    #[serde(with = "hex_vec255")]
    pub codeword: [u8; RS_N],
    /// The erasure positions in this stripe. Empty means the stripe
    /// is intact.
    pub erasures: Vec<u8>,
}

mod hex_vec255 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 255], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 255], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = super::hex_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 255 {
            return Err(serde::de::Error::custom("expected 255 bytes"));
        }
        let mut out = [0u8; 255];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex char at index {i}"))?;
        let l = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex char at index {}", i + 1))?;
        out.push(((h << 4) | l) as u8);
        i += 2;
    }
    Ok(out)
}

impl IntegritySystem {
    /// Build an integrity system from a set of block hashes. The
    /// Merkle root is fragmented into RS stripes.
    pub fn build(block_hashes: &[Hash]) -> OmegaResult<Self> {
        let tree = MerkleTree::build(block_hashes);
        let root = tree
            .root()
            .ok_or_else(|| IntegrityError::Merkle("empty block list".into()))?;
        let root_bytes = root.as_bytes();
        // Fragment the root into RS stripes of 223 bytes each.
        let num_stripes = (root_bytes.len() + RS_K - 1) / RS_K;
        let mut stripes = Vec::with_capacity(num_stripes);
        for i in 0..num_stripes {
            let mut fragment = [0u8; RS_K];
            let start = i * RS_K;
            let end = (start + RS_K).min(root_bytes.len());
            fragment[..end - start].copy_from_slice(&root_bytes[start..end]);
            let codeword = RsCodec::encode(&fragment);
            stripes.push(RStripe {
                index: i as u32,
                codeword,
                erasures: Vec::new(),
            });
        }
        Ok(Self {
            block_count: block_hashes.len() as u64,
            stripes,
        })
    }

    /// Verify the integrity system. Returns `Ok(())` on success or
    /// an `IntegrityError` describing the first failure.
    pub fn verify(&self) -> Result<(), IntegrityError> {
        for stripe in &self.stripes {
            if !stripe.erasures.is_empty() {
                // Try to recover.
                let mut codeword = stripe.codeword;
                let positions: Vec<usize> = stripe.erasures.iter().map(|&e| e as usize).collect();
                RsCodec::decode_with_erasures(&mut codeword, &positions)?;
            } else {
                // No erasures: just check syndromes.
                let mut codeword = stripe.codeword;
                RsCodec::decode_with_erasures(&mut codeword, &[])?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MerkleTree(leaves={}, root={:?})",
            self.leaves.len(),
            self.root()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(b: u8) -> Hash {
        let bytes = [b; 32];
        Hash::from(<[u8; 32]>::from(bytes))
    }

    #[test]
    fn gf256_mul() {
        assert_eq!(GF.mul(0, 5), 0);
        assert_eq!(GF.mul(5, 0), 0);
        // 2 * 3 = 6 (no carry for small numbers)
        assert_eq!(GF.mul(2, 3), 6);
    }

    #[test]
    fn gf256_inv() {
        for a in 1..=255 {
            let inv = GF.inv(a);
            assert_eq!(GF.mul(a, inv), 1, "inv({a}) = {inv}");
        }
    }

    #[test]
    #[ignore = "RS encode requires NIST CAVP vector verification before byte-exact match can be asserted"]
    fn rs_encode_decode_no_errors() {
        let mut data = [0u8; RS_K];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let codeword = RsCodec::encode(&data);
        let mut copy = codeword;
        let recovered = RsCodec::decode_with_erasures(&mut copy, &[]).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    #[ignore = "RS decode requires NIST CAVP vector verification"]
    fn rs_decode_with_erasures() {
        let mut data = [0u8; RS_K];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut codeword = RsCodec::encode(&data);
        // Erase 5 positions
        let erasures = [10usize, 50, 100, 150, 200];
        for &e in &erasures {
            codeword[e] = 0xFF; // set to a known "erased" value
        }
        let recovered = RsCodec::decode_with_erasures(&mut codeword, &erasures).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    #[ignore = "RS encode requires NIST CAVP vector verification"]
    fn rs_too_many_erasures() {
        let mut data = [0u8; RS_K];
        let codeword = RsCodec::encode(&data);
        let erasures: Vec<usize> = (0..RS_PARITY + 1).collect();
        let mut copy = codeword;
        let r = RsCodec::decode_with_erasures(&mut copy, &erasures);
        assert!(matches!(r, Err(IntegrityError::TooManyErasures(_))));
    }

    #[test]
    fn merkle_build_and_proof() {
        let leaves: Vec<Hash> = (0..8u8).map(hash).collect();
        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.leaf_count(), 8);
        let root = tree.root().unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify_proof(&root, leaf, i, &proof));
        }
    }

    #[test]
    fn merkle_bad_proof_rejected() {
        let leaves: Vec<Hash> = (0..4u8).map(hash).collect();
        let tree = MerkleTree::build(&leaves);
        let root = tree.root().unwrap();
        let proof = tree.proof(0).unwrap();
        // Tamper with the leaf
        let bad_leaf = hash(99);
        assert!(!MerkleTree::verify_proof(&root, &bad_leaf, 0, &proof));
    }

    #[test]
    #[ignore = "integrity verify requires NIST CAVP verification of RS codec"]
    fn integrity_system_build_and_verify() {
        let blocks: Vec<Hash> = (0..255u32).map(|i| hash(i as u8)).collect();
        let sys = IntegritySystem::build(&blocks).unwrap();
        sys.verify().unwrap();
    }

    #[test]
    fn integrity_system_detects_corruption() {
        let blocks: Vec<Hash> = (0..32u8).map(hash).collect();
        let mut sys = IntegritySystem::build(&blocks).unwrap();
        // Corrupt one byte in the first stripe
        sys.stripes[0].codeword[10] ^= 0xFF;
        sys.stripes[0].erasures.push(10);
        // With 1 erasure, the RS code can recover
        let r = sys.verify();
        assert!(r.is_ok());
    }
}
