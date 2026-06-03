#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::crypto_engine::block::BlockCrypto;
use soteria_core::crypto_engine::AeadAlgorithm;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let key = [0x42u8; 32];
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, key);
    if let Ok(ct) = crypto.encrypt_block(0, data, "GENESIS") {
        let pt = crypto.decrypt_block(&ct).unwrap();
        assert_eq!(pt, data);
    }
});
