#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::crypto_engine::aead::{AeadAlgorithm, CryptoEngine};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let key = [0x42u8; 32];
    let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, key);
    if let Ok(env) = engine.encrypt(data, b"aad") {
        let dec = engine.decrypt(&env, b"aad").unwrap();
        assert_eq!(dec, data);
    }
});
