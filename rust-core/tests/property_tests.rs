//! Property-based tests for Soteria's cryptographic operations.
//!
//! These tests verify invariants that must hold for ALL inputs,
//! not just the specific test cases we thought of.

use proptest::prelude::*;

proptest! {
    #[test]
    fn aead_roundtrip_xchacha(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        use soteria_core::crypto_engine::aead::{AeadAlgorithm, CryptoEngine};
        let key = [0x42u8; 32];
        let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, key);
        let envelope = engine.encrypt(&plaintext, b"aad").unwrap();
        let decrypted = engine.decrypt(&envelope, b"aad").unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aead_roundtrip_aes_gcm(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        use soteria_core::crypto_engine::aead::{AeadAlgorithm, CryptoEngine};
        let key = [0x42u8; 32];
        let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, key);
        let envelope = engine.encrypt(&plaintext, b"aad").unwrap();
        let decrypted = engine.decrypt(&envelope, b"aad").unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aead_tampered_ciphertext_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
        flip_byte in 0usize..1024,
    ) {
        use soteria_core::crypto_engine::aead::{AeadAlgorithm, CryptoEngine};
        let key = [0x42u8; 32];
        let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, key);
        let mut envelope = engine.encrypt(&plaintext, b"aad").unwrap();
        // Tamper with the ciphertext.
        if flip_byte < envelope.ciphertext.len() {
            envelope.ciphertext[flip_byte] ^= 0xFF;
        }
        let result = engine.decrypt(&envelope, b"aad");
        prop_assert!(result.is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn blake3_deterministic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let h1 = blake3::hash(&data);
        let h2 = blake3::hash(&data);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_different_inputs_different_hashes(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(data1 != data2);
        let h1 = blake3::hash(&data1);
        let h2 = blake3::hash(&data2);
        prop_assert_ne!(h1, h2);
    }

    #[test]
    fn gf256_mul_identity(x in 0u8..=255) {
        use soteria_core::defense::shamir_recovery::ShamirSecretSharing;
        // GF(2^8) multiplication with 1 should be identity.
        // We test this indirectly through Shamir roundtrip.
        let sss = ShamirSecretSharing::new(2, 3).unwrap();
        let secret = [x; 32];
        let shares = sss.split(&secret).unwrap();
        let recovered = sss.reconstruct(&shares[0..2]).unwrap();
        prop_assert_eq!(recovered, secret);
    }

    #[test]
    fn constant_time_eq_reflexive(data in prop::collection::vec(any::<u8>(), 0..256)) {
        use soteria_core::defense::constant_time::constant_time_eq;
        prop_assert!(constant_time_eq(&data, &data));
    }

    #[test]
    fn constant_time_eq_different_lengths(
        a in prop::collection::vec(any::<u8>(), 0..128),
        b in prop::collection::vec(any::<u8>(), 129..256),
    ) {
        use soteria_core::defense::constant_time::constant_time_eq;
        prop_assert!(!constant_time_eq(&a, &b));
    }
}
