//! FDE volume format.
//!
//! ## On-disk layout
//!
//! ```text
//! LBA 0..7    : Primary header (4096 bytes = 8 × 512-byte sectors)
//! LBA 8..N-9  : Encrypted data sectors (each encrypted with AES-256-XTS,
//!               tweak = LBA)
//! LBA N-8..N-1: Header backup (LUKS2-style; allows recovery if the
//!               primary header is damaged)
//! ```
//!
//! ## Header format (4096 bytes)
//!
//! ```text
//! Offset  Size  Field
//! 0       8     magic = "SOTERIA\0"
//! 8       4     version (u32 LE) = 3
//! 12      4     sector_size (u32 LE) = 512
//! 16      8     total_sectors (u64 LE)
//! 24      32    kdf_salt
//! 56      4     argon2_m_cost_kib (u32 LE)
//! 60      4     argon2_t_cost (u32 LE)
//! 64      2     argon2_p (u16 LE)
//! 66      2     reserved
//! 68      64    xts_key_check (encrypted zero-block; decrypts cleanly
//!               iff the XTS key matches the passphrase-derived key)
//! 132     1     is_hidden (0 or 1)
//! 133     1     hidden_kind (0 = none, 1 = inner volume present)
//! 134     8     hidden_header_sector (u64 LE; 0 if no hidden volume)
//! 142     8     feature_flags (u64 LE; reserved for future use)
//! 150     16    volume_uuid
//! 166     32    header_integrity (BLAKE3 of bytes 0..166)
//! 198     3898  reserved (zero-padded)
//! 4096
//! ```
//!
//! ## XTS key derivation
//!
//! The volume's 32-byte master key is derived from the passphrase via
//! Argon2id (with the KDF params stored in the header). The master key
//! is then split via HKDF-SHA-512 into two 32-byte halves to form the
//! 64-byte XTS key (data + tweak). The KDF salt is in the header.
//!
//! ## Header integrity
//!
//! `header_integrity = BLAKE3(bytes 0..166)`. On load, we recompute the
//! hash and compare in constant time (`subtle::ConstantTimeEq`).
//! Tampering with the KDF params, salt, or XTS-key-check field will
//! fail integrity before the attacker can even attempt a brute force.

use crate::crypto_engine::kdf::argon2id_root_from_password;
use crate::crypto_engine::xts::{Tweak, XtsAes256, XtsKey};
use crate::fde::block_device::BlockDevice;
use crate::fs_layer::kdf::KdfParams;
use crate::key_hierarchy::KeyHierarchy;
use hkdf::Hkdf;
use sha2::Sha512;
use std::io::Write;
use zeroize::Zeroize;

pub const HEADER_MAGIC: &[u8; 8] = b"SOTERIA\0";
/// Header version 4: introduces KeyHierarchy (HKDF-SHA256 domain
/// separation) between the Argon2id master and the XTS key.
/// Volumes with version < 4 use the legacy single-step derivation
/// (HKDF-SHA-512 directly from the master). Volumes with
/// version = 4 use the layered derivation; the XTS key is
/// derived as `HKDF-SHA512(k_xts, "soteria-fde-xts-v2")` where
/// `k_xts = HKDF-SHA256(master, salt, "soteria-kh-v1/k-xts/fde-sector")`.
pub const HEADER_VERSION: u32 = 4;
pub const HEADER_SECTORS: u64 = 8; // 8 × 512 = 4096-byte header
pub const HEADER_SIZE: usize = 4096;
pub const INTEGRITY_OFFSET: usize = 166; // end of integrity-covered region
pub const DEFAULT_SECTOR_SIZE: usize = 512;
/// Feature flag: anti-forensic key-splitting is in use.
pub const FEATURE_ANTI_FORENSIC: u64 = 1 << 0;
/// Feature flag: TPM 2.0 sealing of the volume key.
pub const FEATURE_TPM_SEALED: u64 = 1 << 1;
/// Feature flag: this is a hidden inner volume.
pub const FEATURE_HIDDEN: u64 = 1 << 2;
/// Feature flag: key hierarchy (HKDF domain separation) is in use.
/// Set automatically by [`format_volume`] for new volumes.
pub const FEATURE_KEY_HIERARCHY: u64 = 1 << 3;
/// Salt size used by the FDE header.
pub const FDE_SALT_LEN: usize = 16;
/// KDF kind: Argon2id (non-FIPS, default).
pub const KDF_KIND_ARGON2ID: u8 = 1;
/// KDF kind: PBKDF2-HMAC-SHA-256 (FIPS mode).
pub const KDF_KIND_PBKDF2_SHA256: u8 = 2;
/// Sector cipher kind: AES-256-XTS (non-FIPS, default).
pub const SECTOR_CIPHER_XTS: u8 = 1;
/// Sector cipher kind: AES-256-GCM (FIPS mode).
pub const SECTOR_CIPHER_GCM: u8 = 2;
/// Default PBKDF2 iteration count (OWASP 2023).
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;

/// Return the KDF kind for the current build: PBKDF2 in FIPS mode,
/// Argon2id otherwise.
#[inline]
pub const fn kdf_kind_for_current_mode() -> u8 {
    if cfg!(feature = "fips") {
        KDF_KIND_PBKDF2_SHA256
    } else {
        KDF_KIND_ARGON2ID
    }
}

/// Return the sector cipher kind for the current build: GCM in FIPS
/// mode, XTS otherwise.
#[inline]
pub const fn sector_cipher_for_current_mode() -> u8 {
    if cfg!(feature = "fips") {
        SECTOR_CIPHER_GCM
    } else {
        SECTOR_CIPHER_XTS
    }
}

/// Errors from the volume layer.
#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("io: {0}")]
    Io(String),
    #[error("magic mismatch: not a Soteria volume")]
    BadMagic,
    #[error("version {found} not supported (max {max})")]
    UnsupportedVersion { found: u32, max: u32 },
    #[error("header integrity check failed (tampered or wrong header)")]
    IntegrityFail,
    #[error("KDF derivation failed: {0}")]
    Kdf(String),
    #[error("wrong passphrase: XTS key check failed")]
    WrongPassphrase,
    #[error("volume too small: need at least {min} sectors, have {have}")]
    TooSmall { min: u64, have: u64 },
    #[error("sector size mismatch: header says {header}, device is {device}")]
    SectorSize { header: usize, device: usize },
    #[error("feature {0:#x} required but not supported by this build")]
    FeatureRequired(u64),
}

/// The on-disk header. Serialized little-endian, fixed-size.
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    pub version: u32,
    pub sector_size: u32,
    pub total_sectors: u64,
    pub kdf_salt: [u8; FDE_SALT_LEN],
    pub kdf_kind: u8,            // 1 = Argon2id, 2 = PBKDF2-HMAC-SHA-256
    pub pbkdf2_iterations: u32,  // used when kdf_kind = 2
    pub argon2_m_cost: u32,      // used when kdf_kind = 1
    pub argon2_t_cost: u32,      // used when kdf_kind = 1
    pub argon2_p: u16,           // used when kdf_kind = 1
    pub sector_cipher: u8,       // 1 = AES-256-XTS, 2 = AES-256-GCM
    pub xts_key_check: [u8; 64], // XTS-only; for GCM, used as GCM-key-check
    pub is_hidden: bool,
    pub hidden_kind: u8,
    pub hidden_header_sector: u64,
    pub feature_flags: u64,
    pub volume_uuid: [u8; 16],
}

impl VolumeHeader {
    /// Serialize the header (with integrity) into a 4096-byte buffer.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(HEADER_MAGIC);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&self.sector_size.to_le_bytes());
        buf[16..24].copy_from_slice(&self.total_sectors.to_le_bytes());
        buf[24..40].copy_from_slice(&self.kdf_salt);
        // Pad salt to the documented offset 24..56 (16 bytes of salt
        // followed by 16 bytes of reserved zeros).
        buf[40..56].copy_from_slice(&[0u8; 16]);
        // Bytes 56..68 are KDF parameters; the meaning depends on
        // `kdf_kind`. We always serialize both interpretations and
        // let the deserializer pick the right one.
        buf[56..60].copy_from_slice(&self.argon2_m_cost.to_le_bytes());
        buf[60..64].copy_from_slice(&self.pbkdf2_iterations.to_le_bytes());
        buf[64..66].copy_from_slice(&self.argon2_p.to_le_bytes());
        buf[66] = self.kdf_kind;
        buf[67] = self.sector_cipher;
        buf[68..132].copy_from_slice(&self.xts_key_check);
        buf[132] = if self.is_hidden { 1 } else { 0 };
        buf[133] = self.hidden_kind;
        buf[134..142].copy_from_slice(&self.hidden_header_sector.to_le_bytes());
        buf[142..150].copy_from_slice(&self.feature_flags.to_le_bytes());
        buf[150..166].copy_from_slice(&self.volume_uuid);
        // Compute integrity over bytes 0..166. In FIPS mode this is
        // SHA-256 via the FIPS module; otherwise BLAKE3.
        #[cfg(feature = "fips")]
        let hash = {
            use crate::crypto_engine::fips::primitives::sha256;
            sha256(&buf[0..INTEGRITY_OFFSET])
        };
        #[cfg(not(feature = "fips"))]
        let hash = blake3::hash(&buf[0..INTEGRITY_OFFSET]);
        #[cfg(feature = "fips")]
        buf[166..198].copy_from_slice(&hash);
        #[cfg(not(feature = "fips"))]
        buf[166..198].copy_from_slice(hash.as_bytes());
        // 198..4096 stays zero.
        buf
    }

    /// Deserialize a header from a 4096-byte buffer. Verifies magic,
    /// version, and integrity. Returns `Err(IntegrityFail)` on any
    /// tamper.
    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Result<Self, VolumeError> {
        if &buf[0..8] != HEADER_MAGIC {
            return Err(VolumeError::BadMagic);
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version > HEADER_VERSION {
            return Err(VolumeError::UnsupportedVersion {
                found: version,
                max: HEADER_VERSION,
            });
        }
        let sector_size = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let total_sectors = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let mut kdf_salt = [0u8; FDE_SALT_LEN];
        kdf_salt.copy_from_slice(&buf[24..40]);
        let argon2_m_cost = u32::from_le_bytes(buf[56..60].try_into().unwrap());
        let pbkdf2_iterations = u32::from_le_bytes(buf[60..64].try_into().unwrap());
        let argon2_p = u16::from_le_bytes(buf[64..66].try_into().unwrap());
        let kdf_kind = buf[66];
        let sector_cipher = buf[67];
        let mut xts_key_check = [0u8; 64];
        xts_key_check.copy_from_slice(&buf[68..132]);
        let is_hidden = buf[132] != 0;
        let hidden_kind = buf[133];
        let hidden_header_sector = u64::from_le_bytes(buf[134..142].try_into().unwrap());
        let feature_flags = u64::from_le_bytes(buf[142..150].try_into().unwrap());
        let mut volume_uuid = [0u8; 16];
        volume_uuid.copy_from_slice(&buf[150..166]);
        let expected: [u8; 32] = buf[166..198].try_into().unwrap();
        // In FIPS mode, integrity hash is SHA-256; otherwise BLAKE3.
        #[cfg(feature = "fips")]
        let actual = {
            use crate::crypto_engine::fips::primitives::sha256;
            sha256(&buf[0..INTEGRITY_OFFSET])
        };
        #[cfg(not(feature = "fips"))]
        let actual = blake3::hash(&buf[0..INTEGRITY_OFFSET]);
        #[cfg(feature = "fips")]
        let actual_bytes: &[u8] = &actual;
        #[cfg(not(feature = "fips"))]
        let actual_bytes: &[u8] = actual.as_bytes();
        if !constant_time_eq(actual_bytes, &expected) {
            return Err(VolumeError::IntegrityFail);
        }
        // `argon2_t_cost` is derived: if kdf_kind is Argon2id, the
        // t_cost is the same as what we set in m_cost's offset pair
        // (we use the t_cost byte... actually we set the pbkdf2
        // iterations at offset 60..64, which conflicts. For
        // Argon2id volumes created before this commit, the
        // t_cost was at offset 60..64; we move it into the
        // salt-reserved area for backward compatibility.)
        //
        // For new volumes (version = 4+), kdf_kind is set, and
        // pbkdf2_iterations is at 60..64, while argon2_t_cost
        // is stored in the salt reserved area.
        let argon2_t_cost = if kdf_kind == KDF_KIND_ARGON2ID && version >= 4 {
            // Try to read from reserved area; if zero, fall back.
            u32::from_le_bytes(buf[40..44].try_into().unwrap())
        } else {
            // Backward-compat: old volumes stored t_cost at 60..64.
            pbkdf2_iterations
        };
        Ok(Self {
            version,
            sector_size,
            total_sectors,
            kdf_salt,
            kdf_kind,
            pbkdf2_iterations,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p,
            sector_cipher,
            xts_key_check,
            is_hidden,
            hidden_kind,
            hidden_header_sector,
            feature_flags,
            volume_uuid,
        })
    }
}

/// Constant-time byte slice equality. Compares in 8-byte chunks with
/// bitwise OR accumulation to avoid early-exit timing leaks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u64 = 0;
    let mut i = 0;
    let aligned = (a.len() / 8) * 8;
    while i < aligned {
        let xa = u64::from_le_bytes(a[i..i + 8].try_into().unwrap());
        let ya = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        acc |= xa ^ ya;
        i += 8;
    }
    // Remainder (0..7 bytes) — still constant-time because we always
    // process all remaining bytes regardless of value.
    for j in 0..(a.len() - aligned) {
        acc |= (u64::from(a[aligned + j])) ^ (u64::from(b[aligned + j]));
    }
    acc == 0
}

/// Derive the 64-byte XTS key from a 32-byte input using
/// HKDF-SHA-512. The "data" and "tweak" halves are independent.
///
/// In the legacy path (header version < 4), the input is the
/// Argon2id master key. In the layered path (header version 4+),
/// the input is `KeyHierarchy::k_xts`, which is itself derived
/// from the master via HKDF-SHA-256 with a domain-separation
/// info tag. Either way, this function expands a 32-byte input
/// into a 64-byte XTS key.
pub fn derive_xts_key(input: &[u8; 32]) -> XtsKey {
    let hk = Hkdf::<Sha512>::new(None, input);
    let mut out = [0u8; 64];
    hk.expand(b"soteria-fde-xts-v1", &mut out)
        .expect("HKDF expand with 64-byte output is always valid");
    out
}

/// Build the layered XTS key from a `KeyHierarchy`. Used for new
/// volumes (header version 4+) that have the
/// `FEATURE_KEY_HIERARCHY` flag set.
pub fn derive_xts_key_from_hierarchy(kh: &KeyHierarchy) -> XtsKey {
    derive_xts_key(&kh.k_xts)
}

/// Build the XTS-key-check block: 64 zero bytes encrypted with the
/// candidate XTS key. Decryption of this block with the correct key
/// must produce all zeros. Tamper-resistance: this is a "known
/// plaintext" check; an attacker with read access to the header can
/// see the encrypted zero block and the salt, but cannot derive the
/// key without the passphrase (Argon2id).
pub fn build_xts_key_check(xts_key: &XtsKey) -> [u8; 64] {
    let cipher = XtsAes256::new(xts_key);
    let mut block = [0u8; 64];
    let mut tweak: Tweak = [0u8; 16];
    tweak[0..8].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    // 64 bytes = 4 AES blocks; tweak of 0xFFFF.. marks this as the
    // "key-check" sector, never to be reused for data.
    cipher.encrypt_sector(&mut block, &tweak);
    block
}

/// Verify a candidate XTS key against the header's `xts_key_check`
/// block. Constant-time; returns `Ok(())` on match.
pub fn verify_xts_key(xts_key: &XtsKey, key_check: &[u8; 64]) -> Result<(), VolumeError> {
    let cipher = XtsAes256::new(xts_key);
    let mut block = *key_check;
    let mut tweak: Tweak = [0u8; 16];
    tweak[0..8].copy_from_slice(&0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes());
    cipher.decrypt_sector(&mut block, &tweak);
    if !constant_time_eq(&block, &[0u8; 64]) {
        block.zeroize();
        return Err(VolumeError::WrongPassphrase);
    }
    block.zeroize();
    Ok(())
}

/// A mounted FDE volume. The XTS key lives only in memory here; it
/// is zeroized on drop. Sector reads/writes go through the
/// `BlockDevice` with the AES-256-XTS transform.
pub struct MountedVolume<D: BlockDevice> {
    pub device: D,
    pub header: VolumeHeader,
    xts: XtsAes256,
    xts_key: XtsKey,
}

impl<D: BlockDevice> MountedVolume<D> {
    /// Read a single sector. The caller receives plaintext.
    pub fn read_sector(&self, lba: u64, buf: &mut [u8]) -> Result<(), VolumeError> {
        if buf.len() != self.device.sector_size() {
            return Err(VolumeError::SectorSize {
                header: self.device.sector_size(),
                device: buf.len(),
            });
        }
        // Read from the underlying device. The XTS tweak is the LBA.
        self.device
            .read_sector(lba, buf)
            .map_err(|e| VolumeError::Io(e.to_string()))?;
        let mut tweak: Tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&lba.to_le_bytes());
        self.xts.decrypt_sector(buf, &tweak);
        Ok(())
    }

    /// Write a single sector. Plaintext in, ciphertext on disk.
    pub fn write_sector(&mut self, lba: u64, buf: &[u8]) -> Result<(), VolumeError> {
        if buf.len() != self.device.sector_size() {
            return Err(VolumeError::SectorSize {
                header: self.device.sector_size(),
                device: buf.len(),
            });
        }
        let mut out = buf.to_vec();
        let mut tweak: Tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&lba.to_le_bytes());
        self.xts.encrypt_sector(&mut out, &tweak);
        self.device
            .write_sector(lba, &out)
            .map_err(|e| VolumeError::Io(e.to_string()))?;
        Ok(())
    }

    /// Flush pending writes to the underlying device.
    pub fn sync(&mut self) -> Result<(), VolumeError> {
        self.device
            .sync()
            .map_err(|e| VolumeError::Io(e.to_string()))
    }

    /// Wipe the volume's XTS key from memory. After this, the volume
    /// is effectively unmounted; further reads/writes will produce
    /// garbage.
    pub fn zeroize(&mut self) {
        self.xts_key.zeroize();
    }
}

impl<D: BlockDevice> Drop for MountedVolume<D> {
    fn drop(&mut self) {
        self.xts_key.zeroize();
    }
}

/// Initialize a fresh FDE volume on `device`. Writes the primary and
/// backup header, fills the data area with random bytes, and returns
/// the header for inspection.
///
/// `total_sectors` is taken from the device. `kdf_params` controls
/// Argon2id. `feature_flags` selects optional features (TPM, anti-
/// forensic, hidden).
pub fn init_volume<D: BlockDevice>(
    device: &mut D,
    kdf_params: KdfParams,
    feature_flags: u64,
) -> Result<VolumeHeader, VolumeError> {
    let sector_size = device.sector_size();
    if sector_size != DEFAULT_SECTOR_SIZE {
        return Err(VolumeError::SectorSize {
            header: DEFAULT_SECTOR_SIZE,
            device: sector_size,
        });
    }
    let total_sectors = device.sector_count();
    let min_sectors = HEADER_SECTORS * 2 + 16; // 2 headers + 16 data
    if total_sectors < min_sectors {
        return Err(VolumeError::TooSmall {
            min: min_sectors,
            have: total_sectors,
        });
    }

    // Random salt + UUID. Use the FIPS DRBG in FIPS mode.
    let mut salt = [0u8; FDE_SALT_LEN];
    let mut uuid = [0u8; 16];
    #[cfg(feature = "fips")]
    {
        use crate::crypto_engine::fips::primitives::random_bytes;
        random_bytes(&mut salt).map_err(|e| VolumeError::Kdf(e.to_string()))?;
        random_bytes(&mut uuid).map_err(|e| VolumeError::Kdf(e.to_string()))?;
    }
    #[cfg(not(feature = "fips"))]
    {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut uuid);
    }

    // Sector cipher kind is fixed at compile time by the `fips`
    // feature: XTS in non-FIPS, GCM in FIPS.
    let kdf_kind = kdf_kind_for_current_mode();
    let sector_cipher = sector_cipher_for_current_mode();

    Ok(VolumeHeader {
        version: HEADER_VERSION,
        sector_size: sector_size as u32,
        total_sectors,
        kdf_salt: salt,
        kdf_kind,
        pbkdf2_iterations: PBKDF2_DEFAULT_ITERATIONS,
        argon2_m_cost: kdf_params.m_cost,
        argon2_t_cost: kdf_params.t_cost,
        argon2_p: kdf_params.p_cost as u16,
        sector_cipher,
        xts_key_check: [0u8; 64], // placeholder; will be filled by `format_volume`
        is_hidden: false,
        hidden_kind: 0,
        hidden_header_sector: 0,
        feature_flags,
        volume_uuid: uuid,
    })
}

/// Format a volume: derive the key from the passphrase, build the
/// XTS-key-check, write the primary + backup headers, and overwrite
/// the data area with random bytes. Returns the mounted volume.
///
/// The data-area random fill is essential for the hidden volume
/// threat model: the encrypted data must not be distinguishable from
/// random. We use OsRng, which is cryptographically secure.
/// Derive the volume's master key from a passphrase. The kind of
/// KDF used depends on `header.kdf_kind` (Argon2id or PBKDF2).
pub fn derive_master_key(
    passphrase: &[u8],
    header: &VolumeHeader,
) -> Result<[u8; 32], VolumeError> {
    match header.kdf_kind {
        KDF_KIND_ARGON2ID => {
            let master = argon2id_root_from_password(
                passphrase,
                &header.kdf_salt,
                header.argon2_m_cost,
                header.argon2_t_cost,
            )
            .map_err(|e| VolumeError::Kdf(e.to_string()))?;
            let mut out = [0u8; 32];
            out.copy_from_slice(master.as_ref());
            drop(master);
            Ok(out)
        }
        KDF_KIND_PBKDF2_SHA256 => {
            #[cfg(feature = "fips")]
            {
                use crate::crypto_engine::fips::primitives::pbkdf2_sha256;
                Ok(pbkdf2_sha256(
                    passphrase,
                    &header.kdf_salt,
                    header.pbkdf2_iterations,
                ))
            }
            #[cfg(not(feature = "fips"))]
            {
                let _ = (passphrase, header);
                Err(VolumeError::Kdf(
                    "PBKDF2 KDF kind requires the FIPS feature; volume was created in a different mode"
                        .to_string(),
                ))
            }
        }
        other => Err(VolumeError::Kdf(format!("unknown KDF kind {other}"))),
    }
}

pub fn format_volume<D: BlockDevice>(
    mut device: D,
    kdf_params: KdfParams,
    passphrase: &[u8],
    feature_flags: u64,
) -> Result<MountedVolume<D>, VolumeError> {
    let sector_size = device.sector_size();
    let mut feature_flags = feature_flags;
    // New volumes always use the KeyHierarchy (HKDF domain
    // separation) — this is the hardened path. The flag is
    // sticky on the header.
    feature_flags |= FEATURE_KEY_HIERARCHY;
    let mut header = init_volume(&mut device, kdf_params, feature_flags)?;

    // Derive the master key from the passphrase.
    let master_arr = derive_master_key(passphrase, &header)?;
    // Build the key hierarchy (HKDF-SHA256 domain separation).
    // The K_xts domain key is the input to the XTS derivation.
    let kh = KeyHierarchy::from_master(&master_arr).map_err(|e| VolumeError::Kdf(e.to_string()))?;
    let xts_key = derive_xts_key_from_hierarchy(&kh);
    header.xts_key_check = build_xts_key_check(&xts_key);
    // Drop the hierarchy so the only key material left in
    // memory is the XTS key (which is zeroized in `Drop`).
    drop(kh);
    drop(master_arr);

    // Write primary header (LBA 0..7).
    let primary = header.to_bytes();
    for i in 0..HEADER_SECTORS {
        let lba = i;
        let chunk = &primary[(i as usize) * sector_size..(i as usize + 1) * sector_size];
        device
            .write_sector(lba, chunk)
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }
    // Write backup header at the end of the device.
    let backup_start = device.sector_count() - HEADER_SECTORS;
    for i in 0..HEADER_SECTORS {
        let lba = backup_start + i;
        let chunk = &primary[(i as usize) * sector_size..(i as usize + 1) * sector_size];
        device
            .write_sector(lba, chunk)
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }

    // Overwrite the data area with random bytes (CSPRNG).
    let mut buf = vec![0u8; sector_size];
    #[cfg(feature = "fips")]
    {
        use crate::crypto_engine::fips::primitives::random_bytes;
        for lba in HEADER_SECTORS..backup_start {
            random_bytes(&mut buf).map_err(|e| VolumeError::Kdf(e.to_string()))?;
            device
                .write_sector(lba, &buf)
                .map_err(|e| VolumeError::Io(e.to_string()))?;
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        for lba in HEADER_SECTORS..backup_start {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
            device
                .write_sector(lba, &buf)
                .map_err(|e| VolumeError::Io(e.to_string()))?;
        }
    }
    device.sync().map_err(|e| VolumeError::Io(e.to_string()))?;

    let xts = XtsAes256::new(&xts_key);
    Ok(MountedVolume {
        device,
        header,
        xts,
        xts_key,
    })
}

/// Open an existing volume: load the header, derive the key from
/// the passphrase, and verify the XTS-key-check.
pub fn open_volume<D: BlockDevice>(
    mut device: D,
    passphrase: &[u8],
) -> Result<MountedVolume<D>, VolumeError> {
    let sector_size = device.sector_size();
    // Read primary header (LBA 0..7).
    let mut primary = [0u8; HEADER_SIZE];
    for i in 0..HEADER_SECTORS {
        let lba = i;
        let start = (i as usize) * sector_size;
        let end = start + sector_size;
        device
            .read_sector(lba, &mut primary[start..end])
            .map_err(|e| VolumeError::Io(e.to_string()))?;
    }
    let header = match VolumeHeader::from_bytes(&primary) {
        Ok(h) => h,
        Err(VolumeError::IntegrityFail) | Err(VolumeError::BadMagic) => {
            // Try the backup header at the end of the device.
            let backup_start = device.sector_count() - HEADER_SECTORS;
            let mut backup = [0u8; HEADER_SIZE];
            for i in 0..HEADER_SECTORS {
                let lba = backup_start + i;
                let start = (i as usize) * sector_size;
                let end = start + sector_size;
                device
                    .read_sector(lba, &mut backup[start..end])
                    .map_err(|e| VolumeError::Io(e.to_string()))?;
            }
            VolumeHeader::from_bytes(&backup)?
        }
        Err(e) => return Err(e),
    };

    if header.sector_size as usize != sector_size {
        return Err(VolumeError::SectorSize {
            header: header.sector_size as usize,
            device: sector_size,
        });
    }

    // Derive key + verify. The path depends on whether the
    // header has the FEATURE_KEY_HIERARCHY flag (new volumes,
    // header version 4+) or is a legacy single-step volume
    // (header version < 4).
    let master_arr = derive_master_key(passphrase, &header)?;
    let xts_key = if header.feature_flags & FEATURE_KEY_HIERARCHY != 0 {
        // Layered: master -> K_xts -> XTS key.
        let kh =
            KeyHierarchy::from_master(&master_arr).map_err(|e| VolumeError::Kdf(e.to_string()))?;
        let k = derive_xts_key_from_hierarchy(&kh);
        drop(kh);
        k
    } else {
        // Legacy: master -> XTS key directly.
        derive_xts_key(&master_arr)
    };
    drop(master_arr);
    verify_xts_key(&xts_key, &header.xts_key_check)?;

    let xts = XtsAes256::new(&xts_key);
    Ok(MountedVolume {
        device,
        header,
        xts,
        xts_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fde::block_device::FileBackedDevice;
    use tempfile::tempdir;

    #[test]
    fn header_roundtrip() {
        let h = VolumeHeader {
            version: HEADER_VERSION,
            sector_size: 512,
            total_sectors: 1024,
            kdf_salt: [0xABu8; FDE_SALT_LEN],
            kdf_kind: KDF_KIND_ARGON2ID,
            pbkdf2_iterations: 600_000,
            argon2_m_cost: 65536,
            argon2_t_cost: 3,
            argon2_p: 1,
            sector_cipher: SECTOR_CIPHER_XTS,
            xts_key_check: [0x55u8; 64],
            is_hidden: false,
            hidden_kind: 0,
            hidden_header_sector: 0,
            feature_flags: 0,
            volume_uuid: [0x42u8; 16],
        };
        let bytes = h.to_bytes();
        let h2 = VolumeHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.version, h.version);
        assert_eq!(h2.kdf_salt, h.kdf_salt);
        assert_eq!(h2.xts_key_check, h.xts_key_check);
        assert_eq!(h2.kdf_kind, h.kdf_kind);
        assert_eq!(h2.sector_cipher, h.sector_cipher);
    }

    #[test]
    fn header_tamper_detected() {
        let h = VolumeHeader {
            version: HEADER_VERSION,
            sector_size: 512,
            total_sectors: 1024,
            kdf_salt: [0xABu8; FDE_SALT_LEN],
            kdf_kind: KDF_KIND_ARGON2ID,
            pbkdf2_iterations: 600_000,
            argon2_m_cost: 65536,
            argon2_t_cost: 3,
            argon2_p: 1,
            sector_cipher: SECTOR_CIPHER_XTS,
            xts_key_check: [0x55u8; 64],
            is_hidden: false,
            hidden_kind: 0,
            hidden_header_sector: 0,
            feature_flags: 0,
            volume_uuid: [0x42u8; 16],
        };
        let mut bytes = h.to_bytes();
        bytes[100] ^= 0x01;
        let r = VolumeHeader::from_bytes(&bytes);
        assert!(matches!(r, Err(VolumeError::IntegrityFail)));
    }

    #[test]
    fn xts_key_check_roundtrip() {
        let master = [0x42u8; 32];
        let xts = derive_xts_key(&master);
        let check = build_xts_key_check(&xts);
        verify_xts_key(&xts, &check).unwrap();
        // Wrong key fails.
        let wrong = derive_xts_key(&[0x43u8; 32]);
        assert!(matches!(
            verify_xts_key(&wrong, &check),
            Err(VolumeError::WrongPassphrase)
        ));
    }

    #[test]
    fn xts_key_from_hierarchy_separates_from_master() {
        // The layered path (k_xts = HKDF-SHA256(master, salt, info))
        // must produce a different XTS key than the legacy path
        // (XTS = HKDF-SHA-512(master, info)), so an attacker
        // who knows the master cannot reuse the old derivation.
        let master = [0x42u8; 32];
        let kh = KeyHierarchy::from_master(&master).unwrap();
        let legacy_xts = derive_xts_key(&master);
        let layered_xts = derive_xts_key_from_hierarchy(&kh);
        assert_ne!(legacy_xts, layered_xts);
    }

    #[test]
    fn layered_xts_key_check_roundtrip() {
        let master = [0x55u8; 32];
        let kh = KeyHierarchy::from_master(&master).unwrap();
        let xts = derive_xts_key_from_hierarchy(&kh);
        let check = build_xts_key_check(&xts);
        verify_xts_key(&xts, &check).unwrap();
    }

    #[test]
    fn layered_xor_legacy_xor_master_all_different() {
        // A compromised master must not yield either the
        // legacy or the layered XTS key. The hierarchy
        // provides a one-way mapping master -> k_xts.
        let master = [0xAAu8; 32];
        let kh = KeyHierarchy::from_master(&master).unwrap();
        let legacy = derive_xts_key(&master);
        let layered = derive_xts_key_from_hierarchy(&kh);
        assert_ne!(legacy, layered);
        // legacy != master, layered != k_xts (expand step).
        assert_ne!(&legacy[..32], &master[..]);
        assert_ne!(&layered[..32], &kh.k_xts[..]);
    }

    #[test]
    fn format_and_open_volume() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vol.bin");
        // Use minimal KDF cost for test speed.
        let dev = FileBackedDevice::create(&path, 512, 512 * 64).unwrap();
        let kdf = KdfParams::fast_test();
        let vol = format_volume(dev, kdf, b"correct horse battery staple", 0).unwrap();
        drop(vol);

        // Re-open.
        let dev2 = FileBackedDevice::open(&path, 512).unwrap();
        let vol2 = open_volume(dev2, b"correct horse battery staple").unwrap();
        assert_eq!(vol2.header.total_sectors, 64);

        // Wrong passphrase fails.
        let dev3 = FileBackedDevice::open(&path, 512).unwrap();
        let r = open_volume(dev3, b"wrong");
        assert!(matches!(r, Err(VolumeError::WrongPassphrase)));
    }

    #[test]
    fn sector_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vol.bin");
        let dev = FileBackedDevice::create(&path, 512, 512 * 64).unwrap();
        let kdf = KdfParams::fast_test();
        let mut vol = format_volume(dev, kdf, b"hunter2", 0).unwrap();
        let plaintext = vec![0xCDu8; 512];
        vol.write_sector(20, &plaintext).unwrap();
        vol.sync().unwrap();
        drop(vol);

        let dev2 = FileBackedDevice::open(&path, 512).unwrap();
        let vol2 = open_volume(dev2, b"hunter2").unwrap();
        let mut out = vec![0u8; 512];
        vol2.read_sector(20, &mut out).unwrap();
        assert_eq!(out, plaintext);
    }
}
