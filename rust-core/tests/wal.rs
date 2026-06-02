//! Tests for the crash-safe write-ahead log used by Soteria volumes.

use soteria_core::crypto_engine::block::BlockCrypto;
use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::fs_layer::storage::{encrypt_to_disk, OnDiskFile};
use soteria_core::fs_layer::wal::{wal_path_for, Wal, WalState, WAL_COMMIT, WAL_MAGIC};
use std::path::PathBuf;

fn unique_tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("soteria-wal-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn wal_path_is_sibling_with_dot_wal_suffix() {
    let data = PathBuf::from("/tmp/foo.sot");
    let wal = wal_path_for(&data);
    assert_eq!(wal, PathBuf::from("/tmp/foo.sot.wal"));
}

#[test]
fn wal_write_produces_committed_state() {
    let tmp = unique_tmp("write-committed");
    let wal = tmp.join("v.sot.wal");
    let payload = b"hello, world".to_vec();
    Wal::write(&wal, &payload).unwrap();
    match Wal::inspect(&wal).unwrap() {
        WalState::Committed(p) => assert_eq!(p, payload),
        other => panic!("expected Committed, got {other:?}"),
    }
}

#[test]
fn wal_parse_rejects_truncated_buffer() {
    assert_eq!(Wal::parse(b""), WalState::Uncommitted);
    assert_eq!(Wal::parse(&WAL_MAGIC[..]), WalState::Uncommitted);
    let mut too_short = WAL_MAGIC.to_vec();
    too_short.extend_from_slice(&4u32.to_le_bytes());
    too_short.extend_from_slice(b"ab"); // only 2 of 4 payload bytes
    too_short.extend_from_slice(&WAL_COMMIT[..]);
    assert_eq!(Wal::parse(&too_short), WalState::Uncommitted);
}

#[test]
fn wal_parse_rejects_missing_commit_marker() {
    // Valid header + payload but no commit marker at the end.
    let mut bytes = WAL_MAGIC.to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(b"abc");
    // No WAL_COMMIT appended.
    assert_eq!(Wal::parse(&bytes), WalState::Uncommitted);
}

#[test]
fn wal_parse_rejects_wrong_magic() {
    let mut bytes = b"XXXX".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(b"abc");
    bytes.extend_from_slice(&WAL_COMMIT[..]);
    assert_eq!(Wal::parse(&bytes), WalState::Uncommitted);
}

#[test]
fn wal_parse_accepts_valid_buffer() {
    let mut bytes = WAL_MAGIC.to_vec();
    let payload = b"some-payload".to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&WAL_COMMIT[..]);
    match Wal::parse(&bytes) {
        WalState::Committed(p) => assert_eq!(p, payload),
        other => panic!("expected Committed, got {other:?}"),
    }
}

#[test]
fn recover_is_noop_when_no_wal_exists() {
    let tmp = unique_tmp("recover-noop");
    let data = tmp.join("v.sot");
    let state = Wal::recover(&data).unwrap();
    assert_eq!(state, WalState::Absent);
    assert!(!data.exists());
    assert!(!wal_path_for(&data).exists());
}

#[test]
fn recover_replays_committed_wal() {
    // Simulate a crash: the WAL was written and committed, but the rename to
    // the data path never completed. The data file does not exist. On
    // recovery, the payload must be applied to the data file.
    let tmp = unique_tmp("recover-replay");
    let data = tmp.join("v.sot");
    let wal = wal_path_for(&data);
    let payload = b"\x00\x01\x02hello-world\xff".to_vec();
    Wal::write(&wal, &payload).unwrap();
    assert!(!data.exists());

    let state = Wal::recover(&data).unwrap();
    assert!(state.is_committed());
    let applied = std::fs::read(&data).unwrap();
    assert_eq!(applied, payload);
    // The WAL is cleaned up after recovery.
    assert!(!wal.exists());
}

#[test]
fn recover_discards_uncommitted_wal() {
    // A WAL was started but crashed before the commit marker was written.
    // Recovery must leave the data file alone and remove the WAL.
    let tmp = unique_tmp("recover-uncommitted");
    let data = tmp.join("v.sot");
    let wal = wal_path_for(&data);
    // Write a valid magic + length + payload but NO commit marker.
    let mut bytes = WAL_MAGIC.to_vec();
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(b"junk");
    std::fs::write(&wal, &bytes).unwrap();

    let state = Wal::recover(&data).unwrap();
    assert_eq!(state, WalState::Uncommitted);
    assert!(!data.exists());
    assert!(!wal.exists());
}

#[test]
fn save_cleans_up_wal_on_success() {
    // After a successful save, the WAL must be gone and the data file must
    // contain the volume bytes (not WAL-framed bytes).
    let tmp = unique_tmp("save-cleanup");
    let path = tmp.join("v.sot");
    let domain_key = [7u8; 32];
    let plaintext = b"soteria crash-safe save payload".repeat(40);
    let vol = encrypt_to_disk(
        [1u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        4096,
        &plaintext,
    )
    .unwrap();
    vol.save(&path).unwrap();

    // Data file exists, is non-empty, and is NOT WAL-framed.
    let raw = std::fs::read(&path).unwrap();
    assert!(raw.len() > 12);
    assert_ne!(&raw[..4], WAL_MAGIC, "data file must not be WAL-framed");
    // First 4 bytes are the SOTERIA1 magic.
    assert_eq!(&raw[..8], b"SOTERIA1");

    // WAL is gone.
    assert!(!wal_path_for(&path).exists());

    // Reload roundtrips.
    let reloaded = OnDiskFile::load(&path).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, domain_key);
    let pt = reloaded.plaintext(&crypto).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn load_recovers_from_orphaned_committed_wal() {
    // End-to-end: build a volume, save it, then simulate a crash where the
    // data file disappears but a committed WAL remains. The next load must
    // recover the volume from the WAL.
    let tmp = unique_tmp("load-recover");
    let path = tmp.join("v.sot");
    let domain_key = [11u8; 32];
    let plaintext = b"recovery-from-wal end-to-end payload".repeat(30);
    let vol = encrypt_to_disk(
        [3u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        4096,
        &plaintext,
    )
    .unwrap();

    // Write the new bytes to a WAL, then simulate "crash" by deleting the
    // data file before the rename ever happens.
    let bytes = vol.to_bytes().unwrap();
    let wal = wal_path_for(&path);
    Wal::write(&wal, &bytes).unwrap();
    // Crash: data file never created.
    assert!(!path.exists());

    // load() must apply the WAL and then parse the recovered bytes.
    let reloaded = OnDiskFile::load(&path).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, domain_key);
    let pt = reloaded.plaintext(&crypto).unwrap();
    assert_eq!(pt, plaintext);
    // WAL is gone after recovery.
    assert!(!wal.exists());
}

#[test]
fn load_ignores_uncommitted_wal_keeps_old_data() {
    // If a partial (uncommitted) WAL exists, the existing data file must
    // remain authoritative and the WAL must be removed.
    let tmp = unique_tmp("load-uncommitted");
    let path = tmp.join("v.sot");
    let domain_key = [17u8; 32];
    let original_plaintext = b"the original committed data".to_vec();
    let vol = encrypt_to_disk(
        [5u8; 32],
        AeadAlgorithm::XChaCha20Poly1305,
        domain_key,
        4096,
        &original_plaintext,
    )
    .unwrap();
    vol.save(&path).unwrap();

    // Now simulate a crash where a new, uncommitted WAL appears.
    let wal = wal_path_for(&path);
    let mut trash = WAL_MAGIC.to_vec();
    trash.extend_from_slice(&5u32.to_le_bytes());
    trash.extend_from_slice(b"trash");
    std::fs::write(&wal, &trash).unwrap();

    // Load must succeed using the original data file.
    let reloaded = OnDiskFile::load(&path).unwrap();
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, domain_key);
    let pt = reloaded.plaintext(&crypto).unwrap();
    assert_eq!(pt, original_plaintext);
    // WAL is cleaned up.
    assert!(!wal.exists());
}
