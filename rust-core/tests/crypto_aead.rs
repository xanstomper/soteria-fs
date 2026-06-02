use soteria_core::crypto_engine::{AeadAlgorithm, CryptoEngine};

#[test]
fn xchacha_roundtrip() {
    let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, [3u8; 32]);
    let aad = b"file-meta";
    let env = engine.encrypt(b"plaintext", aad).unwrap();
    let pt = engine.decrypt(&env, aad).unwrap();
    assert_eq!(pt, b"plaintext");
}

#[test]
fn aes_gcm_roundtrip() {
    let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, [4u8; 32]);
    let aad = b"file-meta";
    let env = engine.encrypt(b"plaintext", aad).unwrap();
    let pt = engine.decrypt(&env, aad).unwrap();
    assert_eq!(pt, b"plaintext");
}

#[test]
fn aad_tamper_detected() {
    let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, [5u8; 32]);
    let env = engine.encrypt(b"plaintext", b"good-aad").unwrap();
    let result = engine.decrypt(&env, b"bad-aad");
    assert!(result.is_err());
}
