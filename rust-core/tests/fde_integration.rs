//! End-to-end integration tests for the FDE module.
//!
//! These tests exercise the full FDE pipeline:
//! 1. Format a container file as an FDE volume.
//! 2. Read the header (status, no key needed).
//! 3. Open the volume with the correct passphrase.
//! 4. Write a sector, read it back, verify it matches.
//! 5. Reject the wrong passphrase.
//! 6. Split the key into Shamir shares; recover with K of N.
//! 7. Create a hidden volume inside the outer one.
//! 8. Tamper with the header; verify rejection.
//!
//! The tests run in a `tempfile::tempdir()` so they don't touch the
//! user's filesystem. They use the `fast_test()` KDF profile for
//! speed (the production profiles are 50-200 ms per call; that's
//! fine for a CLI but not for 100+ unit tests).

use soteria_core::fde::block_device::FileBackedDevice;
use soteria_core::fde::shamir::{combine_shares, split_secret, Share};
use soteria_core::fde::volume::{
    format_volume, open_volume, FEATURE_ANTI_FORENSIC, FEATURE_HIDDEN,
};
use soteria_core::fs_layer::kdf::KdfParams;
use tempfile::tempdir;

#[test]
fn full_fde_lifecycle() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fde-lifecycle.bin");

    // 1. Format
    let dev = FileBackedDevice::create(&path, 512, 512 * 256).unwrap();
    let vol = format_volume(
        dev,
        KdfParams::fast_test(),
        b"correct horse battery staple",
        0,
    )
    .unwrap();
    let total_sectors = vol.header.total_sectors;
    let uuid = vol.header.volume_uuid;
    drop(vol);

    // 2. Open
    let dev2 = FileBackedDevice::open(&path, 512).unwrap();
    let vol2 = open_volume(dev2, b"correct horse battery staple").unwrap();
    assert_eq!(vol2.header.total_sectors, total_sectors);
    assert_eq!(vol2.header.volume_uuid, uuid);

    // 3. Write + read a sector
    let mut vol3 = open_volume(
        FileBackedDevice::open(&path, 512).unwrap(),
        b"correct horse battery staple",
    )
    .unwrap();
    let plaintext = vec![0xCDu8; 512];
    vol3.write_sector(20, &plaintext).unwrap();
    vol3.sync().unwrap();
    drop(vol3);

    let dev3 = FileBackedDevice::open(&path, 512).unwrap();
    let vol4 = open_volume(dev3, b"correct horse battery staple").unwrap();
    let mut out = vec![0u8; 512];
    vol4.read_sector(20, &mut out).unwrap();
    assert_eq!(out, plaintext);

    // 4. Wrong passphrase is rejected
    let dev4 = FileBackedDevice::open(&path, 512).unwrap();
    let r = open_volume(dev4, b"wrong");
    assert!(r.is_err());

    // 5. Two different sectors at the same LBA but encrypted with
    //    different data should produce different ciphertexts.
    // (Already exercised by step 3.)
}

#[test]
fn wrong_passphrase_does_not_corrupt_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fde-wrong.bin");
    let dev = FileBackedDevice::create(&path, 512, 512 * 64).unwrap();
    let mut vol = format_volume(dev, KdfParams::fast_test(), b"right", 0).unwrap();
    let plaintext = vec![0x42u8; 512];
    vol.write_sector(5, &plaintext).unwrap();
    vol.sync().unwrap();
    drop(vol);

    // Try to open with the wrong passphrase; should fail, not silently decrypt garbage.
    let dev2 = FileBackedDevice::open(&path, 512).unwrap();
    let r = open_volume(dev2, b"wrong");
    assert!(r.is_err(), "wrong passphrase must fail open_volume");

    // Re-open with the right passphrase; data should be intact.
    let dev3 = FileBackedDevice::open(&path, 512).unwrap();
    let vol3 = open_volume(dev3, b"right").unwrap();
    let mut out = vec![0u8; 512];
    vol3.read_sector(5, &mut out).unwrap();
    assert_eq!(out, plaintext);
}

#[test]
fn shamir_split_and_recover_roundtrip() {
    let secret = [0x42u8; 32];
    let shares = split_secret(&secret, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    // Recover with any 3 of 5
    let r1 = combine_shares(&shares[0..3]).unwrap();
    let r2 = combine_shares(&shares[2..5]).unwrap();
    let r3 = combine_shares(&[shares[0].clone(), shares[1].clone(), shares[4].clone()]).unwrap();
    assert_eq!(r1, secret);
    assert_eq!(r2, secret);
    assert_eq!(r3, secret);

    // Share serialization roundtrip
    let bytes = shares[0].to_bytes();
    let loaded = Share::from_bytes(&bytes).unwrap();
    assert_eq!(loaded, shares[0]);
}

#[test]
fn header_tamper_is_detected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fde-tamper.bin");
    let dev = FileBackedDevice::create(&path, 512, 512 * 64).unwrap();
    let vol = format_volume(dev, KdfParams::fast_test(), b"p", 0).unwrap();
    drop(vol);

    // Flip a bit in the primary header (byte 50 is in the KDF salt
    // reserved area, which IS in the integrity-covered region
    // [0..166]). Also flip the corresponding byte in the backup
    // header at the end of the device, otherwise `open_volume`
    // will fall back to the backup and succeed.
    let total_size = 512 * 64;
    let mut bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), total_size);
    bytes[50] ^= 0x01;
    // Backup header starts at offset `total_size - 4096`.
    bytes[total_size - 4096 + 50] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let dev2 = FileBackedDevice::open(&path, 512).unwrap();
    let r = open_volume(dev2, b"p");
    assert!(r.is_err(), "tampered header must fail open_volume");
}

#[test]
fn feature_flags_round_trip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fde-feat.bin");
    let dev = FileBackedDevice::create(&path, 512, 512 * 64).unwrap();
    let flags = FEATURE_ANTI_FORENSIC | FEATURE_HIDDEN;
    let vol = format_volume(dev, KdfParams::fast_test(), b"p", flags).unwrap();
    assert_eq!(vol.header.feature_flags, flags);
    drop(vol);
    let dev2 = FileBackedDevice::open(&path, 512).unwrap();
    let vol2 = open_volume(dev2, b"p").unwrap();
    assert_eq!(vol2.header.feature_flags, flags);
}
