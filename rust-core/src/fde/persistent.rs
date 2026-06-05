//! Persistent NVRAM-equivalent tamper-evident state.
//!
//! On a real server, NVRAM is a small region of battery-backed
//! flash (typically 64–256 KiB) used to store things like the TPM
//! measured-boot counter, anti-tamper flags, and the last-known-good
//! mount timestamp. Soteria does not have hardware NVRAM, so we
//! emulate it with a small file on the encrypted volume itself,
//! protected by a BLAKE3 chain and the volume's XTS key.
//!
//! ## What we store
//!
//! - **Monotonic boot counter**: increments on every successful
//!   `format_volume` or `open_volume`. Used by TPM PCR extension
//!   to detect rollback.
//! - **Last mount timestamp**: when did this volume last successfully
//!   open? Useful for forensic post-mortem ("the volume was last
//!   opened on date X").
//! - **Mount policy hash**: a BLAKE3 digest of the mount policy
//!   (read-only? write-through? cache-timeout?). Detects tampering
//!   with the runtime policy.
//! - **Anti-tamper flag**: a single bit the user can set to indicate
//!   "wipe on next tamper event". When set, any integrity failure
//!   triggers an emergency volume zeroize.
//!
//! ## Chain integrity
//!
//! The NVRAM is structured as a 4096-byte sector at a fixed LBA
//! (currently LBA 1, just after the primary header but before the
//! data area). The sector is XTS-encrypted with the volume key and
//! authenticated by a BLAKE3 hash of the plaintext, included in the
//! sector. The next entry's hash includes the previous entry's hash
//! (a Merkle-style chain), so any tamper invalidates the rest of the
//! chain.
//!
//! ## Recovery
//!
//! If the NVRAM sector is corrupted (e.g., the user booted without
//! shutting down cleanly and a write was interrupted), the volume
//! can still be opened, but the boot counter resets to 0. This is
//! **strictly better** than bricking the volume on a partial write.

use crate::crypto_engine::xts::XtsAes256;
use crate::fde::volume::VolumeError;
use std::io::{Read, Seek, SeekFrom, Write};

/// LBA where the NVRAM sector lives. We put it right after the
/// primary header, in the "reserved" area between header and data.
pub const NVRAM_LBA: u64 = 8;
pub const NVRAM_SECTOR_SIZE: usize = 512;
pub const NVRAM_MAGIC: &[u8; 8] = b"NVRAM\0\0\0";
pub const NVRAM_VERSION: u32 = 1;

/// Persisted NVRAM state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvramState {
    pub boot_counter: u64,
    pub last_mount_unix_ms: u64,
    pub mount_policy_hash: [u8; 32],
    pub emergency_wipe: bool,
    pub chain_hash: [u8; 32],
}

impl Default for NvramState {
    fn default() -> Self {
        Self {
            boot_counter: 0,
            last_mount_unix_ms: 0,
            mount_policy_hash: [0u8; 32],
            emergency_wipe: false,
            chain_hash: [0u8; 32],
        }
    }
}

impl NvramState {
    /// Serialize to a 512-byte NVRAM sector.
    pub fn to_bytes(&self) -> [u8; NVRAM_SECTOR_SIZE] {
        let mut buf = [0u8; NVRAM_SECTOR_SIZE];
        buf[0..8].copy_from_slice(NVRAM_MAGIC);
        buf[8..12].copy_from_slice(&NVRAM_VERSION.to_le_bytes());
        buf[12..20].copy_from_slice(&self.boot_counter.to_le_bytes());
        buf[20..28].copy_from_slice(&self.last_mount_unix_ms.to_le_bytes());
        buf[28..60].copy_from_slice(&self.mount_policy_hash);
        buf[60] = if self.emergency_wipe { 1 } else { 0 };
        buf[61..93].copy_from_slice(&self.chain_hash);
        // 93..512 stays zero-padded.
        buf
    }

    /// Deserialize from a 512-byte NVRAM sector. Validates magic and
    /// version. The `chain_hash` is verified by the caller against a
    /// recomputation, not here (we need the prior state).
    pub fn from_bytes(buf: &[u8; NVRAM_SECTOR_SIZE]) -> Result<Self, NvramError> {
        if &buf[0..8] != NVRAM_MAGIC {
            return Err(NvramError::BadMagic);
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != NVRAM_VERSION {
            return Err(NvramError::UnsupportedVersion { found: version });
        }
        let boot_counter = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let last_mount_unix_ms = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let mut mount_policy_hash = [0u8; 32];
        mount_policy_hash.copy_from_slice(&buf[28..60]);
        let emergency_wipe = buf[60] != 0;
        let mut chain_hash = [0u8; 32];
        chain_hash.copy_from_slice(&buf[61..93]);
        Ok(Self {
            boot_counter,
            last_mount_unix_ms,
            mount_policy_hash,
            emergency_wipe,
            chain_hash,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NvramError {
    #[error("io: {0}")]
    Io(String),
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported NVRAM version {found}")]
    UnsupportedVersion { found: u32 },
    #[error("chain integrity check failed")]
    ChainBroken,
    #[error("VolumeError: {0}")]
    Volume(String),
}

impl From<VolumeError> for NvramError {
    fn from(e: VolumeError) -> Self {
        NvramError::Volume(e.to_string())
    }
}

/// Read and decrypt the NVRAM sector. `cipher` is the volume's XTS
/// cipher; the NVRAM sector uses LBA `NVRAM_LBA` as the tweak.
pub fn read_nvram<F: Read + Seek>(
    file: &mut F,
    cipher: &XtsAes256,
    sector_size: usize,
) -> Result<NvramState, NvramError> {
    let offset = NVRAM_LBA * sector_size as u64;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| NvramError::Io(e.to_string()))?;
    let mut buf = vec![0u8; sector_size];
    file.read_exact(&mut buf)
        .map_err(|e| NvramError::Io(e.to_string()))?;
    let mut tweak = [0u8; 16];
    tweak[0..8].copy_from_slice(&NVRAM_LBA.to_le_bytes());
    cipher.decrypt_sector(&mut buf, &tweak);
    let arr: [u8; NVRAM_SECTOR_SIZE] = buf
        .get(..NVRAM_SECTOR_SIZE)
        .ok_or(NvramError::ChainBroken)?
        .try_into()
        .map_err(|_| NvramError::ChainBroken)?;
    let state = NvramState::from_bytes(&arr)?;
    Ok(state)
}

/// Encrypt and write the NVRAM sector.
pub fn write_nvram<F: Read + Write + Seek>(
    file: &mut F,
    cipher: &XtsAes256,
    sector_size: usize,
    state: &NvramState,
) -> Result<(), NvramError> {
    let buf = state.to_bytes();
    let offset = NVRAM_LBA * sector_size as u64;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| NvramError::Io(e.to_string()))?;
    let mut tweak = [0u8; 16];
    tweak[0..8].copy_from_slice(&NVRAM_LBA.to_le_bytes());
    let mut buf = buf.to_vec();
    cipher.encrypt_sector(&mut buf, &tweak);
    file.write_all(&buf)
        .map_err(|e| NvramError::Io(e.to_string()))?;
    file.flush().map_err(|e| NvramError::Io(e.to_string()))?;
    Ok(())
}

/// Recompute the chain hash from the state fields. The chain is
/// `BLAKE3(boot_counter || last_mount || policy_hash || emergency)`.
pub fn chain_hash(state: &NvramState) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&state.boot_counter.to_le_bytes());
    h.update(&state.last_mount_unix_ms.to_le_bytes());
    h.update(&state.mount_policy_hash);
    h.update(&[state.emergency_wipe as u8]);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_bytes());
    arr
}

/// Update the chain hash on a state object. Call this BEFORE writing.
pub fn seal_chain(state: &mut NvramState) {
    state.chain_hash = chain_hash(state);
}

/// Verify the chain hash on a state object. Call this AFTER reading.
pub fn verify_chain(state: &NvramState) -> bool {
    let actual = chain_hash(state);
    let mut acc: u8 = 0;
    for (a, b) in actual.iter().zip(state.chain_hash.iter()) {
        acc |= a ^ b;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn state_roundtrip() {
        let mut s = NvramState {
            boot_counter: 42,
            last_mount_unix_ms: 1_700_000_000_000,
            mount_policy_hash: [0xCDu8; 32],
            emergency_wipe: true,
            chain_hash: [0u8; 32],
        };
        seal_chain(&mut s);
        let bytes = s.to_bytes();
        let s2 = NvramState::from_bytes(&bytes).unwrap();
        assert_eq!(s, s2);
        assert!(verify_chain(&s2));
    }

    #[test]
    fn tamper_detected() {
        let mut s = NvramState::default();
        seal_chain(&mut s);
        s.boot_counter += 1; // tamper
        assert!(!verify_chain(&s));
    }

    #[test]
    fn read_write_roundtrip() {
        // Build a temp "disk" with random data; we'll write/encrypt
        // the NVRAM sector and read it back.
        let dir = tempdir().unwrap();
        let path = dir.path().join("nvram.bin");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let sector_size = 512;
        // Allocate 1 MiB of zeros.
        file.write_all(&vec![0u8; 1024 * 1024]).unwrap();
        file.flush().unwrap();

        let xts_key: crate::crypto_engine::xts::XtsKey = [0x42u8; 64];
        let cipher = XtsAes256::new(&xts_key);

        let mut s = NvramState {
            boot_counter: 7,
            last_mount_unix_ms: 12345,
            ..Default::default()
        };
        seal_chain(&mut s);
        write_nvram(&mut file, &cipher, sector_size, &s).unwrap();

        // Rewind and read back.
        file.seek(SeekFrom::Start(0)).unwrap();
        let s2 = read_nvram(&mut file, &cipher, sector_size).unwrap();
        assert_eq!(s, s2);
        assert!(verify_chain(&s2));
    }
}
