//! Shamir's Secret Sharing over GF(256).
//!
//! Splits a 32-byte master key into `n` shares, any `k` of which can
//! reconstruct the key. This is the **anti-forensic** primitive: the
//! volume key is XOR-split across multiple shares stored on different
//! media (e.g., a USB drive, a smart card, a printed QR code). An
//! attacker who steals the disk but not the shares cannot recover the
//! key; an attacker who steals the disk and some but not all shares
//! still cannot recover the key (information-theoretic security).
//!
//! ## Why GF(256)?
//!
//! Operations are byte-level, no big-integer arithmetic needed.
//! The irreducible polynomial is `x^8 + x^4 + x^3 + x + 1` (0x11B),
//! the same one used by AES. The share format is "1 byte share index,
//! 32 bytes of share data" — compact, printable, and copy-pasteable.
//!
//! ## Caveats
//!
//! - **Information-theoretic, not computational**: there is no "hard"
//!   problem; with k shares you can recover the secret. The security
//!   is that k-1 shares reveal nothing.
//! - **No share integrity**: a single bit flip in a share produces a
//!   wrong secret. If integrity matters, wrap each share in a BLAKE3
//!   hash. (VeraCrypt does this; we leave it as a TODO for a future
//!   iteration. The current API does NOT protect against tampered
//!   shares — it will return *some* 32 bytes, just the wrong ones.)
//! - **Share index = 0 is forbidden**: x = 0 would make the share
//!   equal to the secret. Indices start at 1.

use rand::{rngs::OsRng, RngCore};

/// A single share: 1-byte index + 32 bytes of share data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub data: [u8; 32],
}

impl Share {
    /// Encode to a 33-byte binary form, suitable for hex-encoding.
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = self.index;
        out[1..].copy_from_slice(&self.data);
        out
    }

    pub fn from_bytes(b: &[u8; 33]) -> Result<Self, ShareError> {
        if b[0] == 0 {
            return Err(ShareError::ZeroIndex);
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(&b[1..]);
        Ok(Self { index: b[0], data })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("share index cannot be 0")]
    ZeroIndex,
    #[error("threshold k must be in 2..=255 and <= number of shares")]
    BadThreshold,
    #[error("not enough shares: have {have}, need {need}")]
    NotEnough { have: usize, need: usize },
    #[error("duplicate share index: {0}")]
    DuplicateIndex(u8),
}

/// Split a 32-byte secret into `n` shares with threshold `k`.
///
/// - `k`: minimum shares to reconstruct; must be in 2..=n and <= 255.
/// - `n`: total shares; must be >= k and <= 255.
pub fn split_secret(secret: &[u8; 32], k: u8, n: u8) -> Result<Vec<Share>, ShareError> {
    if !(2..=255).contains(&k) || k > n {
        return Err(ShareError::BadThreshold);
    }
    if n < k || n == 0 {
        return Err(ShareError::BadThreshold);
    }
    // For each byte of the secret, we sample a random polynomial of
    // degree k-1 in GF(256) and evaluate at indices 1..=n.
    //
    // We use ONE polynomial per byte. There are 32 polynomials, each
    // with k-1 random coefficients (the constant term is the secret
    // byte). This is the standard Shamir construction.
    let mut polys: Vec<Vec<u8>> = Vec::with_capacity(32);
    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; k as usize];
        OsRng.fill_bytes(&mut coeffs);
        coeffs[0] = secret[byte_idx]; // constant term = secret byte
        polys.push(coeffs);
    }
    let mut shares = Vec::with_capacity(n as usize);
    for idx in 1..=n {
        let mut data = [0u8; 32];
        for (byte_idx, poly) in polys.iter().enumerate() {
            data[byte_idx] = eval_poly(poly, idx);
        }
        shares.push(Share { index: idx, data });
    }
    Ok(shares)
}

/// Reconstruct the 32-byte secret from at least `k` shares.
///
/// `shares` must be a slice of length >= k with all distinct non-zero indices.
pub fn combine_shares(shares: &[Share]) -> Result<[u8; 32], ShareError> {
    if shares.is_empty() {
        return Err(ShareError::NotEnough { have: 0, need: 1 });
    }
    // Lagrange interpolation in GF(256), evaluated at x=0.
    let mut secret = [0u8; 32];
    for i in 0..shares.len() {
        let xi = shares[i].index;
        if xi == 0 {
            return Err(ShareError::ZeroIndex);
        }
        // Compute the Lagrange basis coefficient L_i(0) =
        //   prod_{j != i} x_j / (x_j - x_i)
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..shares.len() {
            if i == j {
                continue;
            }
            let xj = shares[j].index;
            num = gf_mul(num, xj);
            den = gf_mul(den, xj ^ xi);
        }
        let basis = gf_mul(num, gf_inv(den));
        for byte_idx in 0..32 {
            secret[byte_idx] ^= gf_mul(basis, shares[i].data[byte_idx]);
        }
    }
    // Check uniqueness (defends against accidentally-combined shares
    // that would have collided).
    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if !seen.insert(s.index) {
            return Err(ShareError::DuplicateIndex(s.index));
        }
    }
    Ok(secret)
}

/// Evaluate a polynomial at `x` in GF(256). Coeffs are constant term first.
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method: (((a_n) * x + a_{n-1}) * x + ...) * x + a_0
    let mut acc = 0u8;
    for c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ *c;
    }
    acc
}

/// GF(256) multiplication, AES-style with reduction polynomial 0x11B.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// GF(256) inverse. AES uses the same polynomial, so we can use the
/// standard table-based inverse (Fermat's little theorem: a^-1 = a^254).
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut r = a;
    for _ in 0..6 {
        r = gf_mul(r, r);
        r = gf_mul(r, a);
    }
    gf_mul(r, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_2_of_3() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        // Any 2 of 3 should recover the secret.
        let s1 = combine_shares(&shares[0..2]).unwrap();
        let s2 = combine_shares(&shares[1..3]).unwrap();
        let s3 = combine_shares(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(s1, secret);
        assert_eq!(s2, secret);
        assert_eq!(s3, secret);
    }

    #[test]
    fn roundtrip_5_of_7() {
        let secret = [0xCDu8; 32];
        let shares = split_secret(&secret, 5, 7).unwrap();
        let recovered = combine_shares(&shares[0..5]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn zero_index_rejected() {
        let bytes = [0u8; 33];
        let r = Share::from_bytes(&bytes);
        assert!(matches!(r, Err(ShareError::ZeroIndex)));
    }

    #[test]
    fn bad_threshold_rejected() {
        let secret = [0u8; 32];
        assert!(matches!(
            split_secret(&secret, 1, 3),
            Err(ShareError::BadThreshold)
        ));
        assert!(matches!(
            split_secret(&secret, 3, 2),
            Err(ShareError::BadThreshold)
        ));
    }

    #[test]
    fn gf_mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
        }
    }

    #[test]
    fn gf_inv_inverts() {
        // 0 has no inverse, but every other element should.
        for a in 1..=255u8 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a={a}, inv={inv}");
        }
    }
}
