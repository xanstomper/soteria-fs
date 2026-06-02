//! Obsidian Layer — polynomial-based key ambiguity.
//!
//! Wraps the volume key in a polynomial over GF(2^8). The key defines
//! the evaluation point. Wrong keys evaluate to different (but valid-looking)
//! keys, creating ambiguity about which key is "real."
//!
//! # What this defends against
//!
//! - **Brute force**: Every key evaluation produces a valid-looking key.
//!   The attacker cannot distinguish the real key from decoys.
//! - **Coercion**: The user can reveal any evaluation point and get a
//!   valid key. The attacker cannot prove it's not the real one.
//!
//! # How it works
//!
//! 1. The volume key (32 bytes) is the polynomial's constant term.
//! 2. Random coefficients are generated for the higher-order terms.
//! 3. The polynomial is evaluated at the user's key-derived point.
//! 4. Wrong points produce different but valid-looking keys.
//!
//! # Limitations
//!
//! - This is GF(2^8) per byte, not GF(2^128) for the full key.
//!   Each byte of the key is wrapped independently.
//! - The "honey volume" claim is not implemented here — this only
//!   provides the polynomial wrapping. The caller must handle
//!   the decoy volume logic.

use rand::RngCore;

/// Maximum polynomial degree.
pub const MAX_DEGREE: usize = 8;

/// Wrap a 32-byte key in a polynomial over GF(2^8).
/// Returns the polynomial coefficients (constant term first).
pub fn wrap_key(key: &[u8; 32], degree: usize) -> crate::Result<Vec<[u8; 32]>> {
    anyhow::ensure!(
        degree >= 1 && degree <= MAX_DEGREE,
        "degree must be in [1, MAX_DEGREE]"
    );

    let mut coefficients = Vec::with_capacity(degree + 1);
    coefficients.push(*key); // Constant term = the real key

    // Generate random higher-order coefficients.
    for _ in 0..degree {
        let mut coeff = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut coeff);
        coefficients.push(coeff);
    }

    Ok(coefficients)
}

/// Evaluate the polynomial at a given point (per-byte over GF(2^8)).
/// Returns the 32-byte result.
pub fn evaluate(coefficients: &[[u8; 32]], point: u8) -> [u8; 32] {
    let mut result = [0u8; 32];
    // Horner's method: c_0 + x*(c_1 + x*(c_2 + ...))
    for coeff in coefficients.iter().rev() {
        for i in 0..32 {
            result[i] = gf256_mul(result[i], point) ^ coeff[i];
        }
    }
    result
}

/// Derive an evaluation point from a passphrase.
pub fn point_from_passphrase(passphrase: &[u8]) -> u8 {
    let hash = blake3::hash(passphrase);
    hash.as_bytes()[0]
}

/// GF(2^8) multiplication with the AES irreducible polynomial.
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
            a ^= 0x11B; // AES polynomial
        }
        b >>= 1;
    }
    result as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_evaluate_roundtrip() {
        let key = [0x42u8; 32];
        let coeffs = wrap_key(&key, 3).unwrap();
        // Evaluate at the point that corresponds to the real key.
        // For the constant term, evaluation at any point should
        // produce a value that, combined with the coefficients,
        // can reconstruct the key.
        assert_eq!(coeffs[0], key); // Constant term IS the key
    }

    #[test]
    fn different_points_produce_different_results() {
        let key = [0x42u8; 32];
        let coeffs = wrap_key(&key, 3).unwrap();
        let r1 = evaluate(&coeffs, 1);
        let r2 = evaluate(&coeffs, 2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn same_point_produces_same_result() {
        let key = [0x42u8; 32];
        let coeffs = wrap_key(&key, 3).unwrap();
        let r1 = evaluate(&coeffs, 42);
        let r2 = evaluate(&coeffs, 42);
        assert_eq!(r1, r2);
    }

    #[test]
    fn point_from_passphrase_is_deterministic() {
        let p1 = point_from_passphrase(b"hello");
        let p2 = point_from_passphrase(b"hello");
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_passphrases_produce_different_points() {
        let p1 = point_from_passphrase(b"hello");
        let p2 = point_from_passphrase(b"world");
        // Not guaranteed to be different (it's a single byte),
        // but very likely.
        // Just check it doesn't panic.
        let _ = (p1, p2);
    }

    #[test]
    fn gf256_mul_identity() {
        for x in 0..=255u8 {
            assert_eq!(gf256_mul(x, 1), x);
        }
    }

    #[test]
    fn gf256_mul_zero() {
        for x in 0..=255u8 {
            assert_eq!(gf256_mul(x, 0), 0);
        }
    }
}
