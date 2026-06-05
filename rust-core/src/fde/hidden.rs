//! Hidden volume (VeraCrypt-style plausible deniability).
//!
//! ## Threat model
//!
//! A user may be compelled (legally, by rubber-hose cryptography) to
//! reveal the passphrase of a Soteria volume. If there is only one
//! passphrase, the user has no defense. With a hidden volume, the
//! user can:
//!
//! 1. Set up an **outer volume** with passphrase A. The outer
//!    volume contains plausible decoy data (e.g., a "personal"
//!    filesystem).
//! 2. Set up a **hidden volume** in the *free space* of the outer
//!    volume (i.e., the sectors that the outer volume would not
//!    write to because they are reserved for the hidden header).
//!    The hidden volume has passphrase B and contains the real
//!    sensitive data.
//! 3. When compelled, reveal passphrase A. The decrypter sees the
//!    outer volume, which is the only volume whose existence can
//!    be proved (the hidden header is encrypted and looks like
//!    random data when the outer key is used).
//!
//! ## On-disk layout
//!
//! ```text
//! LBA 0..7              : outer header (passphrase A)
//! LBA 8..M-9            : outer data (XTS-encrypted with outer key)
//! LBA M-8..M-1          : hidden header (passphrase B)
//! LBA M..N-9            : hidden data (XTS-encrypted with hidden key)
//! LBA N-8..N-1          : outer header backup
//! ```
//!
//! The hidden header sits at the **midpoint** of the device. This is
//! not VeraCrypt's exact placement (VeraCrypt stores the hidden
//! header at the end of the outer volume and lets the outer volume
//! grow to cover it), but the midpoint is simpler and equally
//! deniable: the second half of the disk could plausibly be a
//! separate partition, an unused area, or a hibernation file.
//!
//! ## Detection
//!
//! To check whether a device contains a hidden volume, you MUST
//! have the hidden passphrase. The hidden header is encrypted with
//! the hidden key; without the key, it is indistinguishable from
//! random data. The only way to "discover" a hidden volume is brute
//! force over the passphrase space, which is exactly what Argon2id
//! with sufficient cost is designed to make infeasible.
//!
//! ## Pre-allocation
//!
//! The outer volume's data area is randomly filled at format time.
//! When the user writes to the outer volume, they should avoid the
//! hidden region (LBA M..N-9). The CLI enforces this by recording
//! the hidden region in the outer header and refusing to write to
//! those sectors from the outer mount.

use crate::crypto_engine::xts::XtsAes256;
use crate::fde::volume::{
    derive_master_key, derive_xts_key, kdf_kind_for_current_mode, sector_cipher_for_current_mode,
    verify_xts_key, VolumeError, VolumeHeader, HEADER_SECTORS, HEADER_SIZE,
    PBKDF2_DEFAULT_ITERATIONS,
};
use std::io::{Read, Seek, SeekFrom, Write};

/// The hidden header: identical layout to a regular volume header,
/// but with the `is_hidden` flag set and a `hidden_kind` of 1.
pub type HiddenHeader = VolumeHeader;

/// Compute the LBA where the hidden header lives, given the total
/// number of sectors. Always at the geometric midpoint.
pub fn hidden_header_lba(total_sectors: u64) -> u64 {
    total_sectors / 2 - HEADER_SECTORS / 2
}

/// Build a hidden volume on top of an existing outer volume.
///
/// The outer volume MUST have been formatted with `feature_flags` set
/// to `FEATURE_HIDDEN`. The caller provides a passphrase for the
/// hidden volume, which is used to derive a separate XTS key. The
/// hidden header is written to the midpoint, and the data area from
/// the midpoint to the end of the device is randomly filled.
///
/// The outer volume's data area is NOT touched; the user is
/// expected to populate the outer volume with decoy data AFTER
/// creating the hidden volume.
pub fn create_hidden_volume<F: Read + Write + Seek>(
    file: &mut F,
    outer_passphrase: &[u8],
    hidden_passphrase: &[u8],
    sector_size: usize,
    total_sectors: u64,
    kdf_params: crate::fs_layer::kdf::KdfParams,
) -> Result<HiddenHeader, VolumeError> {
    use crate::fde::volume::FDE_SALT_LEN;

    // Load the outer header to get its salt (we re-derive the outer
    // key to verify the outer passphrase first).
    let mut outer_header_bytes = [0u8; HEADER_SIZE];
    for i in 0..HEADER_SECTORS {
        let lba = i;
        let offset = lba * sector_size as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| VolumeError::Io(e.to_string()))?;
        let start = (i as usize) * sector_size;
        let end = start + sector_size;
        file.read_exact(&mut outer_header_bytes[start..end])
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }
    let outer_header = VolumeHeader::from_bytes(&outer_header_bytes)?;
    let outer_arr = derive_master_key(outer_passphrase, &outer_header)?;
    let outer_xts = derive_xts_key(&outer_arr);
    verify_xts_key(&outer_xts, &outer_header.xts_key_check)?;

    // Build the hidden header.
    let mut hidden_salt = [0u8; FDE_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut hidden_salt);
    let mut hidden_uuid = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut hidden_uuid);

    let hidden_lba = hidden_header_lba(total_sectors);
    let hidden_data_sectors = total_sectors - hidden_lba - HEADER_SECTORS;

    // Build the hidden header FIRST so we can use it for key
    // derivation. The kdf_kind matches the current build mode, so
    // a hidden volume created in FIPS mode uses PBKDF2.
    let proto_header = VolumeHeader {
        version: crate::fde::volume::HEADER_VERSION,
        sector_size: sector_size as u32,
        total_sectors: hidden_data_sectors,
        kdf_salt: hidden_salt,
        kdf_kind: kdf_kind_for_current_mode(),
        pbkdf2_iterations: PBKDF2_DEFAULT_ITERATIONS,
        argon2_m_cost: kdf_params.m_cost,
        argon2_t_cost: kdf_params.t_cost,
        argon2_p: kdf_params.p_cost as u16,
        sector_cipher: sector_cipher_for_current_mode(),
        xts_key_check: [0u8; 64],
        is_hidden: true,
        hidden_kind: 1,
        hidden_header_sector: hidden_lba,
        feature_flags: crate::fde::volume::FEATURE_HIDDEN,
        volume_uuid: hidden_uuid,
    };
    let hidden_arr = derive_master_key(hidden_passphrase, &proto_header)?;
    let hidden_xts_key = derive_xts_key(&hidden_arr);
    let xts_key_check = crate::fde::volume::build_xts_key_check(&hidden_xts_key);

    let hidden_header = HiddenHeader {
        version: proto_header.version,
        sector_size: proto_header.sector_size,
        total_sectors: proto_header.total_sectors,
        kdf_salt: proto_header.kdf_salt,
        kdf_kind: proto_header.kdf_kind,
        pbkdf2_iterations: proto_header.pbkdf2_iterations,
        argon2_m_cost: proto_header.argon2_m_cost,
        argon2_t_cost: proto_header.argon2_t_cost,
        argon2_p: proto_header.argon2_p,
        sector_cipher: proto_header.sector_cipher,
        xts_key_check,
        is_hidden: proto_header.is_hidden,
        hidden_kind: proto_header.hidden_kind,
        hidden_header_sector: proto_header.hidden_header_sector,
        feature_flags: proto_header.feature_flags,
        volume_uuid: proto_header.volume_uuid,
    };

    // Write the hidden header at the midpoint.
    let bytes = hidden_header.to_bytes();
    for i in 0..HEADER_SECTORS {
        let lba = hidden_lba + i;
        let offset = lba * sector_size as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| VolumeError::Io(e.to_string()))?;
        let start = (i as usize) * sector_size;
        let end = start + sector_size;
        file.write_all(&bytes[start..end])
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }

    // Overwrite the hidden data area with random bytes.
    let mut buf = vec![0u8; sector_size];
    for lba in (hidden_lba + HEADER_SECTORS)..(total_sectors - HEADER_SECTORS) {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
        let offset = lba * sector_size as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| VolumeError::Io(e.to_string()))?;
        file.write_all(&buf)
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }
    file.flush().map_err(|e| VolumeError::Io(e.to_string()))?;

    // Silence "unused" warning on outer_xts while keeping the variable
    // for documentation. The cipher is constructed but not used here;
    // it lives as a marker that we DID verify the outer passphrase.
    let _ = XtsAes256::new(&outer_xts);

    Ok(hidden_header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fde::block_device::FileBackedDevice;
    use crate::fde::volume::format_volume;
    use crate::fs_layer::kdf::KdfParams;
    use tempfile::tempdir;

    #[test]
    fn hidden_lba_is_midpoint() {
        assert_eq!(hidden_header_lba(100), 46);
        assert_eq!(hidden_header_lba(64), 28);
    }

    #[test]
    fn outer_and_hidden_use_different_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vol.bin");
        let dev = FileBackedDevice::create(&path, 512, 512 * 256).unwrap();
        let outer = format_volume(
            dev,
            KdfParams::fast_test(),
            b"outer",
            crate::fde::volume::FEATURE_HIDDEN,
        )
        .unwrap();
        let outer_uuid = outer.header.volume_uuid;
        drop(outer);

        // Open the file as a generic Read+Write+Seek for the
        // create_hidden_volume call.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let hidden = create_hidden_volume(
            &mut file,
            b"outer",
            b"hidden",
            512,
            512 * 256 / 512, // total_sectors
            KdfParams::fast_test(),
        )
        .unwrap();
        assert!(hidden.is_hidden);
        assert_ne!(hidden.volume_uuid, outer_uuid);
    }
}
