use soteria_core::crypto_engine::block::{build_block_salt, BlockCrypto};
use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::snapshot_engine::VersionChain;

#[test]
fn per_block_keys_are_independent() {
    let domain_key = [9u8; 32];
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, domain_key);
    let ct0 = crypto.encrypt_block(0, b"hello", "GENESIS").unwrap();
    let ct1 = crypto.encrypt_block(1, b"world", "GENESIS").unwrap();
    assert_ne!(ct0.envelope.nonce, ct1.envelope.nonce);
    assert_ne!(ct0.envelope.ciphertext, ct1.envelope.ciphertext);
    let pt0 = crypto.decrypt_block(&ct0).unwrap();
    let pt1 = crypto.decrypt_block(&ct1).unwrap();
    assert_eq!(pt0, b"hello");
    assert_eq!(pt1, b"world");
}

#[test]
fn hkdf_salt_distinct_per_block_index() {
    // Different block_index → different salt, even with the same lineage_prev.
    let s0 = build_block_salt(0, "GENESIS");
    let s1 = build_block_salt(1, "GENESIS");
    let s7 = build_block_salt(7, "GENESIS");
    assert_ne!(s0, s1);
    assert_ne!(s1, s7);
    assert_ne!(s0, s7);
    // First 8 bytes are the little-endian block_index.
    assert_eq!(&s0[..8], &0u64.to_le_bytes());
    assert_eq!(&s1[..8], &1u64.to_le_bytes());
    assert_eq!(&s7[..8], &7u64.to_le_bytes());
}

#[test]
fn hkdf_salt_distinct_per_lineage_prev() {
    // Same block_index, different lineage_prev → different salt.
    // This is the security upgrade: a lineage break now rotates the key.
    let fake_lineage_a = "a".repeat(64);
    let fake_lineage_b = "b".repeat(64);
    let s_genesis = build_block_salt(0, "GENESIS");
    let s_a = build_block_salt(1, &fake_lineage_a);
    let s_b = build_block_salt(1, &fake_lineage_b);
    assert_ne!(s_genesis[..8], s_a[..8]);
    // The first 8 bytes (block_index) match for the last two.
    assert_eq!(&s_a[..8], &s_b[..8]);
    // The lineage hash bytes differ.
    assert_ne!(&s_a[8..], &s_b[8..]);
}

#[test]
fn lineage_break_breaks_downstream_decryption() {
    // Encrypt two blocks, then mutate the FIRST block's lineage_prev on the
    // SECOND block and confirm decrypt fails. This proves the lineage_prev is
    // mixed into the per-block key derivation.
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [4u8; 32]);
    let b0 = crypto.encrypt_block(0, b"first", "GENESIS").unwrap();
    let b1 = crypto.encrypt_block(1, b"second", &b0.lineage_new).unwrap();

    // Sanity: honest decrypt works.
    assert_eq!(crypto.decrypt_block(&b1).unwrap(), b"second");

    // Now tamper: pretend block 1's lineage_prev is something else.
    let mut tampered_b1 = b1.clone();
    tampered_b1.lineage_prev = "0".repeat(64);
    assert!(crypto.decrypt_block(&tampered_b1).is_err());
}

#[test]
fn lineage_chain_detects_replacement() {
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [1u8; 32]);
    let mut chain = VersionChain::default();
    let block = crypto.encrypt_block(0, b"payload", "GENESIS").unwrap();
    let _ = chain.append(&block.envelope.ciphertext);
    let original = block.envelope.ciphertext.clone();
    let mut tampered = original.clone();
    tampered[0] ^= 0xFF;
    let cts = vec![tampered.as_slice()];
    assert!(!chain.verify(&cts));
}

#[test]
fn lineage_chain_accepts_untampered_records() {
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [2u8; 32]);
    let mut chain = VersionChain::default();
    let b0 = crypto.encrypt_block(0, b"alpha", "GENESIS").unwrap();
    let b1 = crypto.encrypt_block(1, b"beta", "GENESIS").unwrap();
    let _ = chain.append(&b0.envelope.ciphertext);
    let _ = chain.append(&b1.envelope.ciphertext);
    let cts = vec![
        b0.envelope.ciphertext.as_slice(),
        b1.envelope.ciphertext.as_slice(),
    ];
    assert!(chain.verify(&cts));
}
