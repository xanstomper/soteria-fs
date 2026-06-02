//! Tests for Argon2id-based volume key derivation and the KDF sidecar file.

use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::fs_layer::kdf::{
    derive_volume_key, derive_volume_key_zeroing_passphrase, kdf_path_for, KdfParams, VolumeKeyFile,
};
use soteria_core::fs_layer::storage::{
    decrypt_from_disk_with_passphrase, encrypt_to_disk_with_passphrase,
};
use std::path::PathBuf;
use std::time::Instant;

fn unique_tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("soteria-kdf-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn kdf_params_have_reasonable_defaults() {
    let p = KdfParams::production();
    assert!(p.m_cost >= 19_456, "OWASP minimum m_cost is 19_456 KiB");
    assert!(p.t_cost >= 2, "OWASP minimum t_cost is 2");
    assert!(p.p_cost >= 1, "p_cost must be >= 1");
    let fast = KdfParams::fast_test();
    assert!(fast.m_cost < p.m_cost, "fast_test should be cheaper");
    assert!(fast.t_cost <= p.t_cost);
}

#[test]
fn derive_is_deterministic_for_same_inputs() {
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0x42u8; 16],
    };
    let a = derive_volume_key(b"correct horse battery staple", &kdf).unwrap();
    let b = derive_volume_key(b"correct horse battery staple", &kdf).unwrap();
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn derive_differs_for_different_passphrase() {
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0x55u8; 16],
    };
    let a = derive_volume_key(b"hunter2", &kdf).unwrap();
    let b = derive_volume_key(b"hunter3", &kdf).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn derive_differs_for_different_salt() {
    let params = KdfParams::fast_test();
    let mut salt_a = [0u8; 16];
    salt_a[0] = 1;
    let mut salt_b = [0u8; 16];
    salt_b[0] = 2;
    let kdf_a = VolumeKeyFile {
        kdf_id: 1,
        params,
        salt: salt_a,
    };
    let kdf_b = VolumeKeyFile {
        kdf_id: 1,
        params,
        salt: salt_b,
    };
    let a = derive_volume_key(b"hunter2", &kdf_a).unwrap();
    let b = derive_volume_key(b"hunter2", &kdf_b).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn derive_differs_for_different_params() {
    let mut salt = [0u8; 16];
    salt[0] = 7;
    let kdf_a = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        },
        salt,
    };
    let kdf_b = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams {
            m_cost: 128,
            t_cost: 1,
            p_cost: 1,
        },
        salt,
    };
    let a = derive_volume_key(b"hunter2", &kdf_a).unwrap();
    let b = derive_volume_key(b"hunter2", &kdf_b).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn kdf_sidecar_roundtrip() {
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0xABu8; 16],
    };
    let bytes = kdf.to_bytes();
    assert_eq!(bytes.len(), 61);
    let parsed = VolumeKeyFile::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, kdf);
}

#[test]
fn kdf_sidecar_detects_tampering() {
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0xCDu8; 16],
    };
    let mut bytes = kdf.to_bytes();
    bytes[20] ^= 0xFF; // tamper with a salt byte
    let result = VolumeKeyFile::from_bytes(&bytes);
    assert!(result.is_err(), "tampered KDF must fail integrity");
}

#[test]
fn kdf_sidecar_rejects_wrong_size() {
    let bytes = vec![0u8; 30];
    let result = VolumeKeyFile::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn kdf_sidecar_rejects_unknown_kdf_id() {
    let mut bytes = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0u8; 16],
    }
    .to_bytes();
    bytes[0] = 99;
    let result = VolumeKeyFile::from_bytes(&bytes);
    assert!(result.is_err(), "unknown kdf_id must fail");
}

#[test]
fn kdf_path_for_appends_dot_kdf() {
    let data = PathBuf::from("/tmp/foo.sot");
    let kdf = kdf_path_for(&data);
    assert_eq!(kdf, PathBuf::from("/tmp/foo.sot.kdf"));
}

#[test]
fn derive_volume_key_zeroing_passphrase_wipes_input() {
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0xEFu8; 16],
    };
    let original = b"sensitive-passphrase".to_vec();
    let mut copy = original.clone();
    let _ = derive_volume_key_zeroing_passphrase(std::mem::take(&mut copy), &kdf).unwrap();
    assert_eq!(copy, Vec::<u8>::new(), "passphrase buffer must be zeroed");
    assert_eq!(&original, b"sensitive-passphrase", "original is untouched");
}

#[test]
fn fast_test_derivation_is_actually_fast() {
    // A unit test budget: a single derivation with fast_test() must complete
    // in well under a second. (OWASP production parameters take ~100ms and
    // are tested in `production_derivation_meets_owasp_budget`.)
    let kdf = VolumeKeyFile {
        kdf_id: 1,
        params: KdfParams::fast_test(),
        salt: [0u8; 16],
    };
    let start = Instant::now();
    let _ = derive_volume_key(b"benchmark-passphrase", &kdf).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 1000,
        "fast_test derivation took {elapsed:?}, expected < 1s"
    );
}

#[test]
fn passphrase_volume_roundtrip() {
    let tmp = unique_tmp("roundtrip");
    let path = tmp.join("secret.sot");
    let passphrase = b"correct-horse-battery-staple".to_vec();
    let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(50);

    let vol = encrypt_to_disk_with_passphrase(
        &path,
        AeadAlgorithm::XChaCha20Poly1305,
        KdfParams::fast_test(),
        4096,
        &passphrase,
        &plaintext,
    )
    .unwrap();

    // KDF sidecar must exist.
    assert!(kdf_path_for(&path).exists());

    // Decrypt with the right passphrase.
    let (vol2, recovered) = decrypt_from_disk_with_passphrase(&path, &passphrase).unwrap();
    assert_eq!(vol2.file_id, vol.file_id);
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrong_passphrase_fails_to_decrypt() {
    let tmp = unique_tmp("wrong-pw");
    let path = tmp.join("secret.sot");
    let plaintext = b"secret payload that must not leak".to_vec();
    encrypt_to_disk_with_passphrase(
        &path,
        AeadAlgorithm::XChaCha20Poly1305,
        KdfParams::fast_test(),
        4096,
        b"original-passphrase",
        &plaintext,
    )
    .unwrap();
    let result = decrypt_from_disk_with_passphrase(&path, b"wrong-passphrase");
    assert!(result.is_err(), "wrong passphrase must fail AEAD auth");
}

#[test]
fn missing_kdf_sidecar_is_an_error() {
    let tmp = unique_tmp("missing-kdf");
    let path = tmp.join("secret.sot");
    encrypt_to_disk_with_passphrase(
        &path,
        AeadAlgorithm::XChaCha20Poly1305,
        KdfParams::fast_test(),
        4096,
        b"any-passphrase",
        b"plaintext",
    )
    .unwrap();
    // Remove the KDF sidecar.
    std::fs::remove_file(kdf_path_for(&path)).unwrap();
    let result = decrypt_from_disk_with_passphrase(&path, b"any-passphrase");
    assert!(result.is_err(), "missing KDF sidecar must fail");
}
