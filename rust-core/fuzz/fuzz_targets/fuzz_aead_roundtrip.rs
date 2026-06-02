#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::crypto_engine::aead::{AeadAlgorithm, CryptoEngine};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 1024 {
        return;
    }
    let key = [0x42u8; 32];
    let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, key);
    // Encrypt must never panic.
    if let Ok(envelope) = engine.encrypt(data, b"aad") {
        // Decrypt must recover the original plaintext.
        let decrypted = engine.decrypt(&envelope, b"aad").unwrap();
        assert_eq!(decrypted, data);
    }
});
