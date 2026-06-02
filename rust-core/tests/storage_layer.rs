use soteria_core::crypto_engine::{AeadAlgorithm, CryptoEngine};
use soteria_core::fs_layer::storage::{
    encrypt_to_disk, inode_for, name_for_inode, OnDiskFile, BACKING_EXT,
};
use std::path::PathBuf;

fn unique_tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("soteria-test-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn encrypt_decrypt_roundtrip_through_disk() {
    let tmp = unique_tmp("disk-roundtrip");
    let backing = tmp.join("backing");
    std::fs::create_dir_all(&backing).unwrap();

    let domain_key = [11u8; 32];
    let block_size = 4096;
    let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(50);

    let file_id: [u8; 32] = blake3::hash(b"file-1").into();
    let on_disk = encrypt_to_disk(
        file_id,
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        block_size,
        &plaintext,
    )
    .unwrap();
    on_disk.save(&backing.join("hello.sot")).unwrap();

    let loaded = OnDiskFile::load(&backing.join("hello.sot")).unwrap();
    let crypto = soteria_core::crypto_engine::block::BlockCrypto::new(
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
    );
    let recovered = loaded.plaintext(&crypto).unwrap();
    assert_eq!(recovered, plaintext);
    assert_eq!(loaded.plaintext_size as usize, plaintext.len());
}

#[test]
fn multiple_blocks_have_independent_keys() {
    let tmp = unique_tmp("multi-block");
    let backing = tmp.join("backing");
    std::fs::create_dir_all(&backing).unwrap();

    let domain_key = [22u8; 32];
    let plaintext = vec![0xABu8; 100_000]; // spans multiple 4096-byte blocks
    let on_disk = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        4096,
        &plaintext,
    )
    .unwrap();
    assert!(on_disk.index.len() >= 24);
    // Adjacent blocks must have different ciphertext (independent nonces/keys).
    // Compare the first 16 bytes of each block's ciphertext slice.
    let mut prev: Option<&[u8]> = None;
    for entry in &on_disk.index {
        let start = entry.data_offset as usize;
        let end = start + entry.length as usize;
        let slice = &on_disk.ciphertext[start..end];
        if let Some(p) = prev {
            assert_ne!(
                &p[..16],
                &slice[..16],
                "adjacent blocks share a 16-byte prefix"
            );
        }
        prev = Some(slice);
    }
    let _ = backing;
}

#[test]
fn inode_roundtrip() {
    let ino = inode_for("hello");
    let tmp = unique_tmp("inode");
    let backing = tmp.join("backing");
    std::fs::create_dir_all(&backing).unwrap();
    std::fs::write(backing.join(format!("hello.{BACKING_EXT}")), b"{}").unwrap();
    let resolved = name_for_inode(&backing, ino).unwrap();
    assert_eq!(resolved, "hello");
}

#[test]
fn ciphertext_on_disk_contains_no_plaintext_markers() {
    let tmp = unique_tmp("ct-marker");
    let backing = tmp.join("backing");
    std::fs::create_dir_all(&backing).unwrap();
    let plaintext = b"PASSWORD=hunter2;SECRET=do-not-leak";
    let on_disk = encrypt_to_disk(
        [9u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        [3u8; 32],
        4096,
        plaintext,
    )
    .unwrap();
    on_disk.save(&backing.join("secret.sot")).unwrap();
    let raw = std::fs::read(backing.join("secret.sot")).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(!raw_str.contains("PASSWORD"));
    assert!(!raw_str.contains("hunter2"));
    assert!(!raw_str.contains("SECRET"));
}

#[test]
fn aead_engine_works_through_storage_path() {
    let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, [4u8; 32]);
    let env = engine.encrypt(b"hello", b"aad").unwrap();
    let pt = engine.decrypt(&env, b"aad").unwrap();
    assert_eq!(pt, b"hello");
}
