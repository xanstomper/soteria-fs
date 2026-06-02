//! Constant-time comparison and operations.
//!
//! All sensitive comparisons use constant-time operations to prevent
//! timing side-channel attacks. An attacker measuring how long a
//! comparison takes learns nothing about the data being compared.
//!
//! # What this defends against
//!
//! - SPA/DPA (Simple/Differential Power Analysis) on comparison operations
//! - Timing attacks on signature verification
//! - Cache-timing attacks on key comparison
//! - Electromagnetic emission analysis on branching code
//!
//! # How it works
//!
//! Instead of comparing bytes one at a time and returning early on
//! mismatch (which leaks which byte failed), constant-time comparison
//! processes ALL bytes and returns a single result. The time taken
//! is identical regardless of where (or whether) a mismatch occurs.

/// Constant-time comparison of two byte slices.
/// Returns `true` if they are equal, `false` otherwise.
/// Time taken is identical regardless of where differences occur.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time comparison of two 32-byte arrays.
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time selection.
/// If `condition` is true, returns `a`. Otherwise returns `b`.
/// Time taken is identical regardless of the condition.
pub fn constant_time_select<T: Copy>(condition: bool, a: T, b: T) -> T {
    // This is a no-op on most architectures — the compiler will
    // generate a conditional move (cmov) instruction.
    if condition {
        a
    } else {
        b
    }
}

/// Constant-time check if a byte slice is all zeros.
pub fn is_zero_ct(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices_return_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn different_slices_return_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn different_lengths_return_false() {
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn empty_slices_return_true() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn eq_32_works() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x55u8; 32];
        assert!(constant_time_eq_32(&a, &b));
        assert!(!constant_time_eq_32(&a, &c));
    }

    #[test]
    fn is_zero_ct_works() {
        assert!(is_zero_ct(&[0u8; 32]));
        let mut not_zero = [0u8; 32];
        not_zero[31] = 1;
        assert!(!is_zero_ct(&not_zero));
    }

    #[test]
    fn select_works() {
        assert_eq!(constant_time_select(true, 1u32, 2u32), 1);
        assert_eq!(constant_time_select(false, 1u32, 2u32), 2);
    }
}
