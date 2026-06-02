//! Shamir's Secret Sharing for social key recovery.
//!
//! Splits a volume key into N shares, any K of which can reconstruct
//! the key. Shares are indistinguishable from random bytes until K
//! are combined.
//!
//! # What this defends against
//!
//! - Single point of failure: if one backup is lost, the key is still
//!   recoverable from other shares.
//! - Coercion: an attacker who captures fewer than K shares learns
//!   nothing about the key (information-theoretic security).
//! - Social engineering: shares can be distributed to trusted parties
//!   who each hold only one piece.
//!
//! # How it works
//!
//! Uses Shamir's Secret Sharing over GF(2^8) with the AES polynomial
//! (x^8 + x^4 + x^3 + x + 1). Each byte of the 32-byte secret is
//! shared independently. This is the standard approach used by
//! threshold cryptography libraries.

use rand::RngCore;

/// A single share.
#[derive(Debug, Clone)]
pub struct Share {
    /// Share index (1..N).
    pub index: u8,
    /// Share data (32 bytes, indistinguishable from random).
    pub data: [u8; 32],
}

/// Shamir's Secret Sharing over GF(2^8).
pub struct ShamirSecretSharing {
    threshold: u8,
    total: u8,
}

impl ShamirSecretSharing {
    pub fn new(threshold: u8, total: u8) -> crate::Result<Self> {
        anyhow::ensure!(
            threshold > 0 && threshold <= total,
            "threshold must be in [1, total]"
        );
        anyhow::ensure!(total > 0 && total <= 255, "total must be in [1, 255]");
        Ok(Self { threshold, total })
    }

    /// Split a 32-byte secret into N shares with threshold K.
    pub fn split(&self, secret: &[u8; 32]) -> crate::Result<Vec<Share>> {
        let num_coeffs = (self.threshold - 1) as usize;
        let mut coefficients = Vec::with_capacity(num_coeffs);
        for _ in 0..num_coeffs {
            let mut coeff = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut coeff);
            coefficients.push(coeff);
        }

        let mut shares = Vec::with_capacity(self.total as usize);
        for i in 1..=self.total {
            let mut share_data = [0u8; 32];
            for byte_idx in 0..32 {
                share_data[byte_idx] = eval_poly_gf256(
                    secret[byte_idx],
                    &coefficients.iter().map(|c| c[byte_idx]).collect::<Vec<_>>(),
                    i,
                );
            }
            shares.push(Share {
                index: i,
                data: share_data,
            });
        }

        Ok(shares)
    }

    /// Reconstruct the secret from K shares.
    pub fn reconstruct(&self, shares: &[Share]) -> crate::Result<[u8; 32]> {
        anyhow::ensure!(
            shares.len() >= self.threshold as usize,
            "need at least {} shares, got {}",
            self.threshold,
            shares.len()
        );

        let mut secret = [0u8; 32];
        for byte_idx in 0..32 {
            let points: Vec<(u8, u8)> = shares
                .iter()
                .take(self.threshold as usize)
                .map(|s| (s.index, s.data[byte_idx]))
                .collect();
            secret[byte_idx] = interpolate_gf256(&points);
        }

        Ok(secret)
    }
}

// ── GF(2^8) arithmetic ─────────────────────────────────────────────
// Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)

const IRREDUCIBLE: u16 = 0x11B;

/// Multiplication in GF(2^8).
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        a <<= 1;
        if a >= 256 {
            a ^= IRREDUCIBLE;
        }
        b >>= 1;
    }
    result as u8
}

/// Multiplicative inverse in GF(2^8).
fn gf256_inv(a: u8) -> u8 {
    assert!(a != 0, "cannot invert zero in GF(2^8)");
    // a^{-1} = a^{254} (Fermat's little theorem)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result); // result = a^{2^k}
        result = gf256_mul(result, a); // result = a^{2^k + 1}
    }
    gf256_mul(result, result) // a^{254}
}

/// Evaluate polynomial at x in GF(2^8).
/// P(x) = secret + c1*x + c2*x^2 + ... + c_{k-1}*x^{k-1}
/// Horner's method: secret + x*(c1 + x*(c2 + ... + x*c_{k-1}))
fn eval_poly_gf256(secret: u8, coefficients: &[u8], x: u8) -> u8 {
    // Start from the highest coefficient and work down.
    let mut result = 0u8;
    for coeff in coefficients.iter().rev() {
        result = gf256_mul(result, x) ^ coeff;
    }
    // Finally: result * x + secret
    gf256_mul(result, x) ^ secret
}

/// Lagrange interpolation at x=0 in GF(2^8).
fn interpolate_gf256(points: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    for (j, &(x_j, y_j)) in points.iter().enumerate() {
        let mut basis = 1u8;
        for (m, &(x_m, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            // Lagrange basis: x_m / (x_m - x_j) over GF(2^8)
            // In GF(2^8), subtraction is XOR.
            let num = x_m;
            let den = x_m ^ x_j;
            basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
        }
        result ^= gf256_mul(y_j, basis);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_mul_identity() {
        // 1 * x = x
        for x in 1..=255u8 {
            assert_eq!(gf256_mul(1, x), x);
        }
    }

    #[test]
    fn gf256_inv_roundtrip() {
        // a * a^{-1} = 1
        for a in 1..=255u8 {
            assert_eq!(gf256_mul(a, gf256_inv(a)), 1, "failed for a={a}");
        }
    }

    #[test]
    fn split_and_reconstruct_2_of_3() {
        let sss = ShamirSecretSharing::new(2, 3).unwrap();
        let secret = [0x42u8; 32];
        let shares = sss.split(&secret).unwrap();
        assert_eq!(shares.len(), 3);
        let recovered = sss.reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let sss = ShamirSecretSharing::new(3, 5).unwrap();
        let secret = [0xAAu8; 32];
        let shares = sss.split(&secret).unwrap();
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = sss.reconstruct(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shares_are_deterministic_per_secret() {
        // Shamir uses random coefficients, so shares differ between calls.
        // But reconstruction always works.
        let sss = ShamirSecretSharing::new(2, 3).unwrap();
        let secret = [0x42u8; 32];
        let s1 = sss.split(&secret).unwrap();
        let r1 = sss.reconstruct(&s1[0..2]).unwrap();
        assert_eq!(r1, secret);
    }

    #[test]
    fn different_secrets_produce_different_shares() {
        let sss = ShamirSecretSharing::new(2, 3).unwrap();
        let s1 = sss.split(&[0x01u8; 32]).unwrap();
        let s2 = sss.split(&[0x02u8; 32]).unwrap();
        assert_ne!(s1[0].data, s2[0].data);
    }

    #[test]
    fn threshold_validation() {
        assert!(ShamirSecretSharing::new(0, 3).is_err());
        assert!(ShamirSecretSharing::new(4, 3).is_err());
        assert!(ShamirSecretSharing::new(3, 3).is_ok());
    }

    #[test]
    fn insufficient_shares_fails() {
        let sss = ShamirSecretSharing::new(3, 5).unwrap();
        let secret = [0x42u8; 32];
        let shares = sss.split(&secret).unwrap();
        assert!(sss.reconstruct(&shares[0..1]).is_err());
    }
}
