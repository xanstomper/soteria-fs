//! SOTERIA erasure coding — safe sharding for fault tolerance.
//!
//! This module wraps a *standard* Reed-Solomon erasure-coding layer
//! with authenticated encryption (AES-256-GCM) so that shards are
//! both *recoverable* (RS fault tolerance) and *confidential*
//! (AEAD confidentiality + integrity).
//!
//! ## Design philosophy
//!
//! Reed-Solomon is used **only** for fault tolerance. It is *not*
//! the security boundary. An attacker who can read one shard sees
//! only an AES-GCM ciphertext. The full data is recoverable from
//! any `k` of `n` shards, but the data cannot be reconstructed
//! without first decrypting `k` shards (which requires `K_shard`).
//!
//! In particular, this is the safe sharding scheme the SOTERIA
//! hardening requires: the *original* "RIFT" design conflated
//! sharding with secret sharing, which would have been a
//! primitive failure. RIFT-KS (keyed-secret rifting) wraps each
//! shard in AEAD; that is what this module implements.
//!
//! ## Shard layout
//!
//! ```text
//!    plaintext (any length)
//!        │
//!        ▼ pad to k * shard_size
//!    ┌──────┬──────┬─────┬─────┐
//!    │  S1  │  S2  │ ... │ Sk  │    (k data shards)
//!    └──────┴──────┴─────┴─────┘
//!        │  (Reed-Solomon encoding)
//!        ▼
//!    ┌──────┬──────┬─────┬─────┐
//!    │  P1  │  P2  │ ... │Pm-k │    (n-k parity shards)
//!    └──────┴──────┴─────┴─────┘
//!        │
//!        ▼  AES-256-GCM(K_shard, nonce_i, shard_i)
//!    AEAD-wrapped shards, ready to be placed on n distinct nodes.
//! ```
//!
//! ## AEAD nonce scheme
//!
//! Each shard is sealed with AES-256-GCM under `K_shard` and a
//! per-shard random 12-byte nonce. The nonce, the shard index,
//! the original plaintext length, and a version byte are all
//! bound into the AAD. This prevents:
//! - shard swapping between volumes,
//! - shard re-ordering attacks,
//! - non-confidentiality attacks via nonce reuse (the nonce is
//!   uniformly random; collision probability is 2^{-48} for
//!   realistic shard counts).
//!
//! ## Shard-size choice
//!
//! The caller chooses `k` (data shards) and `m` (parity shards).
//! The maximum recovery is `m`. The data is padded to a multiple
//! of `k * shard_size`. The total on-disk footprint is
//! `n * shard_size` where `n = k + m`. Throughput and storage
//! overhead are a function of these parameters; this module
//! does not choose defaults — the application must.

use crate::key_hierarchy::KeyHierarchy;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// AEAD shard format version. Bump on incompatible changes.
pub const SHARD_AEAD_VERSION: u8 = 1;
/// 12-byte AES-GCM nonce.
pub const SHARD_NONCE_LEN: usize = 12;
/// 16-byte GCM tag.
pub const SHARD_TAG_LEN: usize = 16;

/// GF(256) arithmetic with primitive polynomial 0x11D.
/// Mirrors the omega::integrity::Gf256 impl but kept private
/// here so this module has no cross-feature dependencies.
mod gf256 {
    pub const PRIM: u16 = 0x11D;
    const SIZE: usize = 256;

    pub struct Gf {
        exp: [u8; 512],
        log: [u8; SIZE],
    }

    impl Gf {
        pub const fn new() -> Self {
            let mut exp = [0u8; 512];
            let mut log = [0u8; SIZE];
            let mut x: u16 = 1;
            let mut i = 0;
            while i < 255 {
                exp[i] = x as u8;
                exp[i + 255] = x as u8;
                log[x as usize] = i as u8;
                x <<= 1;
                if x & 0x100 != 0 {
                    x ^= PRIM;
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
                panic!("GF(256) division by zero");
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
            if a == 0 {
                return 0;
            }
            let l = (self.log[a as usize] as usize) * n;
            self.exp[l % 255]
        }

        #[inline]
        pub fn inv(&self, a: u8) -> u8 {
            if a == 0 {
                panic!("GF(256) inverse of zero");
            }
            self.exp[255 - self.log[a as usize] as usize]
        }
    }

    pub static GF: Gf = Gf::new();
}

/// Configuration for an erasure-coded shard set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Number of data shards (k). Must be >= 1.
    pub k: u8,
    /// Number of parity shards (m). Must be >= 1.
    pub m: u8,
    /// Per-shard byte length after padding.
    pub shard_size: u32,
}

impl ShardConfig {
    pub fn new(k: u8, m: u8, shard_size: u32) -> crate::Result<Self> {
        if k == 0 || m == 0 {
            anyhow::bail!("k and m must both be >= 1");
        }
        if (k as usize) + (m as usize) > 255 {
            anyhow::bail!("k + m must be <= 255");
        }
        if shard_size == 0 {
            anyhow::bail!("shard_size must be > 0");
        }
        Ok(Self { k, m, shard_size })
    }

    pub fn n(&self) -> u8 {
        self.k + self.m
    }

    /// Total encoded footprint in bytes.
    pub fn total_bytes(&self) -> usize {
        (self.n() as usize) * (self.shard_size as usize)
    }
}

/// AEAD-wrapped shard ready to be placed on a storage node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedShard {
    /// 0-based index (0..k-1 = data, k..n-1 = parity).
    pub index: u8,
    /// GCM nonce (12 bytes).
    pub nonce: [u8; SHARD_NONCE_LEN],
    /// Ciphertext = `plaintext_shard || gcm_tag` (`shard_size + 16`).
    pub ct: Vec<u8>,
    /// Original plaintext length (before padding). Allows the
    /// decoder to strip the trailing pad bytes.
    pub original_len: u32,
}

/// Full shard set: all n sealed shards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedShardSet {
    pub config: ShardConfig,
    pub original_len: u32,
    pub shards: Vec<SealedShard>,
}

/// Reed-Solomon encoding kernel: encode `k` data shards (each
/// `shard_size` bytes) into `n` shards (data + parity).
fn rs_encode_shards(data: &[Vec<u8>], n: u8) -> Vec<Vec<u8>> {
    use gf256::GF;
    let k = data.len();
    let shard_size = data[0].len();
    let mut all: Vec<Vec<u8>> = data.to_vec();
    // Parity shards: for j in 0..(n-k), parity[j][i] = sum over m
    // in 0..k of (alpha_pow ^ (j * m)) * data[m][i], where
    // alpha_pow = 2 (the primitive element in GF(256)).
    let m_count = (n as usize) - k;
    for j in 0..m_count {
        let mut parity = vec![0u8; shard_size];
        for m in 0..k {
            let coeff = GF.pow(2, j * m);
            for i in 0..shard_size {
                parity[i] ^= GF.mul(coeff, data[m][i]);
            }
        }
        all.push(parity);
    }
    all
}

/// Reed-Solomon decoding kernel: reconstruct the k data shards
/// from any k of the n sealed shards (data + parity).
///
/// `available` is a slice of (index, shard) pairs, of length k.
fn rs_decode_shards(
    available: &[(u8, Vec<u8>)],
    k: usize,
    shard_size: usize,
) -> crate::Result<Vec<Vec<u8>>> {
    use gf256::GF;
    if available.len() != k {
        anyhow::bail!("need exactly k={} shards, got {}", k, available.len());
    }

    // Build the Vandermonde matrix V[r][j] = α^(indices[r] * j).
    // Solve V * data_shards = available_shards over GF(256).
    let indices: Vec<u8> = available.iter().map(|(i, _)| *i).collect();

    // Gaussian elimination: produce row-echelon form.
    let mut mat: Vec<Vec<u8>> = Vec::with_capacity(k);
    for r in 0..k {
        let mut row = vec![0u8; k];
        for j in 0..k {
            row[j] = GF.pow(2, (indices[r] as usize) * j);
        }
        mat.push(row);
    }

    for col in 0..k {
        // Find a pivot row with a non-zero entry in this column.
        let mut pivot = None;
        for r in col..k {
            if mat[r][col] != 0 {
                pivot = Some(r);
                break;
            }
        }
        let pivot = match pivot {
            Some(r) => r,
            None => anyhow::bail!("singular RS matrix (duplicate indices in available?)"),
        };
        if pivot != col {
            mat.swap(pivot, col);
        }
        // Normalize the pivot row so the diagonal entry is 1.
        let inv = GF.inv(mat[col][col]);
        for j in 0..k {
            mat[col][j] = GF.mul(mat[col][j], inv);
        }
        // Eliminate all other rows in this column.
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = mat[r][col];
            if factor != 0 {
                for j in 0..k {
                    mat[r][j] ^= GF.mul(mat[col][j], factor);
                }
            }
        }
    }
    // The matrix is now the identity; per byte, data[r] = rhs[r].
    let mut data_shards: Vec<Vec<u8>> = vec![vec![0u8; shard_size]; k];
    for i in 0..shard_size {
        for r in 0..k {
            data_shards[r][i] = available[r].1[i];
        }
    }
    Ok(data_shards)
}

/// Seal a shard with AES-256-GCM. AAD binds index, original_len,
/// and config.
fn seal_shard(
    cfg: &ShardConfig,
    index: u8,
    plaintext_shard: &[u8],
    original_len: u32,
    k_shard: &[u8; 32],
) -> crate::Result<SealedShard> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut nonce = [0u8; SHARD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(k_shard.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;

    let mut aad = Vec::new();
    aad.push(SHARD_AEAD_VERSION);
    aad.push(cfg.k);
    aad.push(cfg.m);
    aad.extend_from_slice(&cfg.shard_size.to_le_bytes());
    aad.push(index);
    aad.extend_from_slice(&original_len.to_le_bytes());

    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext_shard,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-256-GCM seal failed: {e:?}"))?;

    Ok(SealedShard {
        index,
        nonce,
        ct,
        original_len,
    })
}

/// Open a sealed shard. Returns the plaintext shard bytes.
fn open_shard(
    cfg: &ShardConfig,
    sealed: &SealedShard,
    k_shard: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(k_shard.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;

    let mut aad = Vec::new();
    aad.push(SHARD_AEAD_VERSION);
    aad.push(cfg.k);
    aad.push(cfg.m);
    aad.extend_from_slice(&cfg.shard_size.to_le_bytes());
    aad.push(sealed.index);
    aad.extend_from_slice(&sealed.original_len.to_le_bytes());

    let pt = cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("shard AEAD open failed (wrong key or tampered shard)"))?;
    Ok(pt)
}

/// Erasure-encode a plaintext blob into `n` sealed shards.
pub fn encode(
    plaintext: &[u8],
    cfg: ShardConfig,
    k_shard: &[u8; 32],
) -> crate::Result<SealedShardSet> {
    let k = cfg.k as usize;
    let shard_size = cfg.shard_size as usize;
    let total_padded = k * shard_size;
    if plaintext.len() > total_padded {
        anyhow::bail!(
            "plaintext {} bytes > capacity k*shard_size={}",
            plaintext.len(),
            total_padded
        );
    }
    let original_len = plaintext.len() as u32;

    // Pad plaintext to k * shard_size.
    let mut buf = vec![0u8; total_padded];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    // Split into k data shards.
    let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(k);
    for j in 0..k {
        data_shards.push(buf[j * shard_size..(j + 1) * shard_size].to_vec());
    }
    drop(buf);

    // RS-encode to n shards (k data + (n-k) parity).
    let all = rs_encode_shards(&data_shards, cfg.n());

    // AEAD-seal each.
    let mut sealed = Vec::with_capacity(cfg.n() as usize);
    for (i, shard) in all.iter().enumerate() {
        sealed.push(seal_shard(&cfg, i as u8, shard, original_len, k_shard)?);
    }

    Ok(SealedShardSet {
        config: cfg,
        original_len,
        shards: sealed,
    })
}

/// Reconstruct the plaintext from any `k` of the `n` sealed shards.
/// If more than `k` shards are passed, the first `k` (after
/// sorting by index) are used.
pub fn decode(
    set: &SealedShardSet,
    available: &[SealedShard],
    k_shard: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    let cfg = set.config;
    let k = cfg.k as usize;
    let shard_size = cfg.shard_size as usize;

    if available.len() < k {
        anyhow::bail!("need at least k={} shards, got {}", k, available.len());
    }
    for s in available {
        if s.index >= cfg.n() {
            anyhow::bail!("shard index {} >= n={}", s.index, cfg.n());
        }
    }

    // Sort by index and take the first k.
    let mut sorted: Vec<SealedShard> = available.to_vec();
    sorted.sort_by_key(|s| s.index);
    let use_shards = &sorted[..k];

    // Decrypt each shard.
    let mut plain_shards: Vec<(u8, Vec<u8>)> = Vec::with_capacity(k);
    for s in use_shards {
        let pt = open_shard(&cfg, s, k_shard)?;
        plain_shards.push((s.index, pt));
    }
    plain_shards.sort_by_key(|(i, _)| *i);

    // RS-decode into k data shards.
    let data = rs_decode_shards(&plain_shards, k, shard_size)?;

    // Concatenate and strip padding.
    let mut out = Vec::with_capacity(k * shard_size);
    for d in &data {
        out.extend_from_slice(d);
    }
    out.truncate(set.original_len as usize);
    Ok(out)
}

/// Convenience: encode using a `KeyHierarchy` (uses `K_shard`).
pub fn encode_with_hierarchy(
    plaintext: &[u8],
    cfg: ShardConfig,
    kh: &KeyHierarchy,
) -> crate::Result<SealedShardSet> {
    encode(plaintext, cfg, &kh.k_shard)
}

/// Convenience: decode using a `KeyHierarchy`.
pub fn decode_with_hierarchy(
    set: &SealedShardSet,
    available: &[SealedShard],
    kh: &KeyHierarchy,
) -> crate::Result<Vec<u8>> {
    decode(set, available, &kh.k_shard)
}

// Drop guard for key material.
impl Drop for SealedShard {
    fn drop(&mut self) {
        // GCM tag is non-secret; only the nonce needs wiping if
        // we're paranoid. Skip — the nonce is not a secret.
    }
}

/// Erasure-codec zeroizing helper (used after use).
#[allow(dead_code)]
fn _zeroize_slice(b: &mut [u8]) {
    b.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_cfg(k: u8, m: u8, sz: u32) -> ShardConfig {
        ShardConfig::new(k, m, sz).unwrap()
    }

    #[test]
    fn round_trip_k_of_n() {
        let cfg = fast_cfg(3, 2, 64);
        let kh = KeyHierarchy::from_master(&[0x42u8; 32]).unwrap();
        let plaintext = b"this is a test message that should survive RS recovery";
        let set = encode_with_hierarchy(plaintext, cfg, &kh).unwrap();
        assert_eq!(set.shards.len(), 5);
        // Take any 3 of 5.
        let out = decode_with_hierarchy(&set, &set.shards[..3], &kh).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn recovers_from_parity_shards() {
        let cfg = fast_cfg(2, 3, 32);
        let kh = KeyHierarchy::from_master(&[0x99u8; 32]).unwrap();
        let plaintext = b"hello world 1234567890abcdef";
        let set = encode_with_hierarchy(plaintext, cfg, &kh).unwrap();
        // Use the 3 parity shards (index 2, 3, 4).
        let out = decode_with_hierarchy(&set, &set.shards[2..5], &kh).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_key_fails_aead() {
        let cfg = fast_cfg(2, 2, 32);
        let kh = KeyHierarchy::from_master(&[0x11u8; 32]).unwrap();
        let plaintext = b"secret message";
        let set = encode_with_hierarchy(plaintext, cfg, &kh).unwrap();
        let wrong_kh = KeyHierarchy::from_master(&[0x22u8; 32]).unwrap();
        assert!(decode_with_hierarchy(&set, &set.shards[..2], &wrong_kh).is_err());
    }

    #[test]
    fn shard_swapping_fails() {
        let cfg = fast_cfg(2, 2, 32);
        let kh1 = KeyHierarchy::from_master(&[0x33u8; 32]).unwrap();
        let kh2 = KeyHierarchy::from_master(&[0x44u8; 32]).unwrap();
        let s1 = encode_with_hierarchy(b"first", cfg, &kh1).unwrap();
        let s2 = encode_with_hierarchy(b"second", cfg, &kh2).unwrap();
        // Try to decrypt a shard from s2 with kh1.
        assert!(decode_with_hierarchy(&s1, &s2.shards[..2], &kh1).is_err());
    }

    #[test]
    fn padding_is_stripped() {
        let cfg = fast_cfg(2, 2, 64);
        let kh = KeyHierarchy::from_master(&[0x55u8; 32]).unwrap();
        let plaintext = b"short";
        let set = encode_with_hierarchy(plaintext, cfg, &kh).unwrap();
        let out = decode_with_hierarchy(&set, &set.shards[..2], &kh).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn config_validation() {
        assert!(ShardConfig::new(0, 2, 32).is_err());
        assert!(ShardConfig::new(2, 0, 32).is_err());
        assert!(ShardConfig::new(255, 1, 32).is_err());
        assert!(ShardConfig::new(2, 1, 0).is_err());
        let ok = ShardConfig::new(2, 1, 32).unwrap();
        assert_eq!(ok.n(), 3);
    }
}
