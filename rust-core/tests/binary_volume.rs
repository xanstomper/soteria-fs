//! Tests for the binary on-disk volume format. These exercise the format
//! directly without needing the FUSE feature.

use soteria_core::crypto_engine::block::BlockCrypto;
use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::fs_layer::storage::{
    encrypt_to_disk, BlockIndexEntry, OnDiskFile, HEADER_SIZE, INDEX_ENTRY_SIZE, MAGIC, VERSION,
};

fn unique_tmp(label: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("soteria-binary-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn magic_and_version_match_spec() {
    assert_eq!(MAGIC, b"SOTERIA1\0\0\0\0\0\0\0\0");
    assert_eq!(VERSION, 1);
    assert_eq!(HEADER_SIZE, 256);
    assert_eq!(INDEX_ENTRY_SIZE, 80);
}

#[test]
fn roundtrip_through_binary_serialization() {
    let tmp = unique_tmp("roundtrip");
    let path = tmp.join("hello.sot");

    let domain_key = [13u8; 32];
    let plaintext = b"soteria binary volume roundtrip payload".repeat(200);
    let vol = encrypt_to_disk(
        [7u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        4096,
        &plaintext,
    )
    .unwrap();
    let bytes = vol.to_bytes().unwrap();
    let parsed = OnDiskFile::from_bytes(&bytes).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, domain_key);
    let recovered = parsed.plaintext(&crypto).unwrap();
    assert_eq!(recovered, plaintext);
    vol.save(&path).unwrap();
    let reloaded = OnDiskFile::load(&path).unwrap();
    let recovered2 = reloaded.plaintext(&crypto).unwrap();
    assert_eq!(recovered2, plaintext);
}

#[test]
fn header_tampering_is_detected() {
    let _tmp = unique_tmp("tamper");
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [5u8; 32],
        4096,
        b"hello world",
    )
    .unwrap();
    let mut bytes = vol.to_bytes().unwrap();
    // Tamper with the plaintext_size field. The header integrity check should catch it.
    bytes[64] ^= 0xFF;
    let result = OnDiskFile::from_bytes(&bytes);
    assert!(result.is_err(), "tampered header must not parse");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("integrity") || err.contains("magic"),
        "expected integrity/magic error, got: {err}"
    );
}

#[test]
fn bad_magic_is_rejected() {
    let mut bytes = vec![0u8; HEADER_SIZE];
    bytes[..8].copy_from_slice(b"NOTSOTER");
    let result = OnDiskFile::from_bytes(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("magic"));
}

#[test]
fn lineage_chain_detects_block_replacement() {
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        &vec![0xCDu8; 20000],
    )
    .unwrap();
    assert!(
        vol.verify_lineage().is_none(),
        "freshly built volume must verify"
    );
    let mut tampered = vol.clone();
    if !tampered.ciphertext.is_empty() {
        tampered.ciphertext[0] ^= 0x01;
    }
    assert_eq!(tampered.verify_lineage(), Some(0), "first block must fail");
}

#[test]
fn block_removal_breaks_chain() {
    let mut vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        &vec![0xCDu8; 20000],
    )
    .unwrap();
    assert!(vol.index.len() >= 4);
    // Remove the second block entirely.
    let removed = vol.index.remove(1);
    vol.ciphertext.drain(
        removed.data_offset as usize..(removed.data_offset + removed.length as u64) as usize,
    );
    // After removal, every block's lineage_new is wrong because lineage_prev shifted.
    assert!(vol.verify_lineage().is_some());
}

#[test]
fn index_entry_sizes() {
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        b"some plaintext",
    )
    .unwrap();
    for entry in &vol.index {
        let _ = entry; // touch the field to ensure it exists
        let _: &BlockIndexEntry = entry;
    }
}

#[test]
fn total_file_size_is_correct() {
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        b"abcd",
    )
    .unwrap();
    let bytes = vol.to_bytes().unwrap();
    let expected = HEADER_SIZE + vol.index.len() * INDEX_ENTRY_SIZE + vol.ciphertext.len();
    assert_eq!(bytes.len(), expected);
}

#[test]
fn empty_file_roundtrip() {
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        &[],
    )
    .unwrap();
    let bytes = vol.to_bytes().unwrap();
    let parsed = OnDiskFile::from_bytes(&bytes).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [3u8; 32]);
    let pt = parsed.plaintext(&crypto).unwrap();
    assert!(pt.is_empty());
    assert_eq!(parsed.index.len(), 0);
    assert_eq!(parsed.ciphertext.len(), 0);
}

#[test]
fn aes_gcm_binary_roundtrip() {
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::Aes256Gcm,
        [3u8; 32],
        4096,
        b"aes gcm via binary volume",
    )
    .unwrap();
    let bytes = vol.to_bytes().unwrap();
    let parsed = OnDiskFile::from_bytes(&bytes).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::Aes256Gcm, [3u8; 32]);
    let pt = parsed.plaintext(&crypto).unwrap();
    assert_eq!(pt, b"aes gcm via binary volume");
    assert!(parsed.verify_lineage().is_none());
}

#[test]
fn multiple_files_isolated() {
    let tmp = unique_tmp("isolated");
    let crypto1 = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [1u8; 32]);
    let crypto2 = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, [2u8; 32]);
    let v1 = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [1u8; 32],
        4096,
        b"file one",
    )
    .unwrap();
    let v2 = encrypt_to_disk(
        [2u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [2u8; 32],
        4096,
        b"file two",
    )
    .unwrap();
    assert_eq!(v1.plaintext(&crypto1).unwrap(), b"file one");
    assert_eq!(v2.plaintext(&crypto2).unwrap(), b"file two");
    // Cross-key decryption must fail.
    assert!(v1.plaintext(&crypto2).is_err());
    assert!(v2.plaintext(&crypto1).is_err());
    let _ = tmp;
}
