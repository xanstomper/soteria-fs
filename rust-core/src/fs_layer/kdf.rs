//! Argon2id-based volume key derivation.
//!
//! The volume binary format itself does not embed the KDF parameters; instead
//! they live in a sidecar file `<data_path>.sot.kdf` that is written alongside
//! the volume when the volume key is derived from a passphrase.
//!
//! ## Sidecar file format (53 bytes total)
//!
//! ```text
//! +----------------+   offset 0
//! |  kdf_id        |   1 byte (1 = Argon2id)
//! +----------------+   offset 1
//! |  m_cost        |   u32 LE (memory in KiB)
//! +----------------+   offset 5
//! |  t_cost        |   u32 LE (iterations)
//! +----------------+   offset 9
//! |  p_cost        |   u32 LE (parallelism)
//! +----------------+   offset 13
//! |  salt          |   16 bytes
//! +----------------+   offset 29
//! |  integrity     |   32 bytes (BLAKE3 of bytes 0..29)
//! +----------------+   offset 61
//! ```
//!
//! ## Default Argon2id parameters
//!
//! Per OWASP 2024 recommendations for interactive authentication on commodity
//! hardware. Tuned so a single derivation takes roughly 50-200 ms on a
//! modern x86-64 core.
//!
//! ## Test mode
//!
//! Tests use [`KdfParams::fast_test()`] which lowers the memory cost to make
//! CI loops sub-second. Production code must use [`KdfParams::production()`].

use crate::crypto_engine::kdf::argon2id_root_from_password;
use crate::fs_layer::durability::fsync_dir;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const KDF_FILE_EXT: &str = "kdf";
pub const KDF_FILE_SIZE: usize = 61;
pub const KDF_ID_ARGON2ID: u8 = 1;

/// Argon2id cost parameters. The trio is what determines the work factor of
/// the derivation. All three must be stored in the sidecar file so future
/// reads can re-derive with the exact same parameters.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP 2024 recommended interactive parameters: 19 MiB, 2 iterations,
    /// 1 lane. ~50-200 ms on a modern x86-64 core.
    pub const fn production() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }

    /// Lower-cost parameters suitable for unit tests. NOT FOR PRODUCTION.
    /// 64 KiB, 1 iteration, 1 lane. < 5 ms on any machine.
    pub const fn fast_test() -> Self {
        Self {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// High-security parameters: 1 GiB, 3 iterations, 1 lane.
    /// ~1-5 seconds on a modern x86-64 core. Suitable for sensitive data.
    pub const fn high_security() -> Self {
        Self {
            m_cost: 1_048_576, // 1 GiB
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Paranoid parameters: 4 GiB, 5 iterations, 1 lane.
    /// ~10-30 seconds on a modern x86-64 core. For high-risk environments.
    /// A single brute-force attempt requires 4 GiB of RAM and ~20 seconds.
    pub const fn paranoid() -> Self {
        Self {
            m_cost: 4_194_304, // 4 GiB
            t_cost: 5,
            p_cost: 1,
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::production()
    }
}

/// The on-disk sidecar for an Argon2id-derived volume key.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VolumeKeyFile {
    pub kdf_id: u8,
    pub params: KdfParams,
    pub salt: [u8; 16],
}

impl VolumeKeyFile {
    /// Generate a fresh sidecar with a random salt and the given params.
    pub fn generate(params: KdfParams) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            kdf_id: KDF_ID_ARGON2ID,
            params,
            salt,
        }
    }

    /// Serialize to the on-disk byte format. Returns exactly 61 bytes.
    pub fn to_bytes(&self) -> [u8; KDF_FILE_SIZE] {
        let mut buf = [0u8; KDF_FILE_SIZE];
        buf[0] = self.kdf_id;
        buf[1..5].copy_from_slice(&self.params.m_cost.to_le_bytes());
        buf[5..9].copy_from_slice(&self.params.t_cost.to_le_bytes());
        buf[9..13].copy_from_slice(&self.params.p_cost.to_le_bytes());
        buf[13..29].copy_from_slice(&self.salt);
        let integrity = blake3::hash(&buf[..29]);
        buf[29..61].copy_from_slice(integrity.as_bytes());
        buf
    }

    /// Parse from the on-disk byte format. Verifies integrity.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != KDF_FILE_SIZE {
            anyhow::bail!(
                "KDF file: wrong size (got {}, expected {})",
                bytes.len(),
                KDF_FILE_SIZE
            );
        }
        let stored = &bytes[29..61];
        let computed = blake3::hash(&bytes[..29]);
        if stored != computed.as_bytes() {
            anyhow::bail!("KDF file: integrity check failed");
        }
        let kdf_id = bytes[0];
        if kdf_id != KDF_ID_ARGON2ID {
            anyhow::bail!("KDF file: unknown kdf_id {kdf_id}");
        }
        let m_cost = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        let t_cost = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
        let p_cost = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
        if p_cost == 0 || m_cost == 0 || t_cost == 0 {
            anyhow::bail!("KDF file: invalid cost parameters");
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[13..29]);
        Ok(Self {
            kdf_id,
            params: KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
            salt,
        })
    }

    /// Write the sidecar to `path`, then fsync the file and parent directory.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_bytes().as_slice())?;
        if let Ok(f) = std::fs::File::open(path) {
            let _ = f.sync_all();
        }
        fsync_dir(path);
        Ok(())
    }

    /// Read the sidecar from `path`.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Return the sidecar path for a given volume data path. `foo.sot` -> `foo.sot.kdf`.
pub fn kdf_path_for(data_path: &Path) -> PathBuf {
    let mut s = data_path.as_os_str().to_owned();
    s.push(".");
    s.push(KDF_FILE_EXT);
    PathBuf::from(s)
}

/// Derive a 32-byte volume key from `passphrase` using the parameters and
/// salt in `kdf_file`. The output is `Zeroizing` so it is wiped on drop.
pub fn derive_volume_key(
    passphrase: &[u8],
    kdf_file: &VolumeKeyFile,
) -> crate::Result<Zeroizing<[u8; 32]>> {
    if kdf_file.kdf_id != KDF_ID_ARGON2ID {
        anyhow::bail!("unsupported kdf_id: {}", kdf_file.kdf_id);
    }
    argon2id_root_from_password(
        passphrase,
        &kdf_file.salt,
        kdf_file.params.m_cost,
        kdf_file.params.t_cost,
    )
}

/// Convenience: derive a volume key and zeroize the passphrase buffer in place.
pub fn derive_volume_key_zeroing_passphrase(
    mut passphrase: Vec<u8>,
    kdf_file: &VolumeKeyFile,
) -> crate::Result<Zeroizing<[u8; 32]>> {
    let result = derive_volume_key(&passphrase, kdf_file);
    passphrase.zeroize();
    result
}
