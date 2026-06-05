//! Binary on-disk volume format for Soteria encrypted files.
//!
//! Layout (all multi-byte fields little-endian):
//!
//! ```text
//! +-------------------+   offset 0
//! |  HEADER (256 B)   |
//! +-------------------+   offset 256
//! |  BLOCK INDEX (N * 72 B) |
//! +-------------------+
//! |  CIPHERTEXT BLOB  |   contiguous, indexed by (offset, length) per block
//! +-------------------+
//! ```
//!
//! ## Header (256 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 16   | magic "SOTERIA1" + 8 padding zeros |
//! | 16     | 4    | version (u32 LE, currently 1) |
//! | 20     | 1    | algorithm (1 = XChaCha20-Poly1305, 2 = AES-256-GCM) |
//! | 21     | 3    | reserved |
//! | 24     | 32   | file_id |
//! | 56     | 4    | block_size (u32 LE) |
//! | 60     | 4    | reserved |
//! | 64     | 8    | plaintext_size (u64 LE) |
//! | 72     | 4    | block_count (u32 LE) |
//! | 76     | 4    | reserved |
//! | 80     | 32   | header_blake3 (BLAKE3 of bytes 0..80) |
//! | 112    | 144  | reserved (zero-padded) |
//!
//! ## Index entry (72 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0      | 4    | block_index (u32 LE) |
//! | 4      | 4    | reserved |
//! | 8      | 8    | data_offset (u64 LE, from start of ciphertext blob) |
//! | 16     | 4    | length (u32 LE, ciphertext bytes including auth tag) |
//! | 20     | 4    | reserved |
//! | 24     | 24   | nonce (24 bytes; AEAD reads what it needs) |
//! | 48     | 32   | lineage_new (BLAKE3 of lineage_prev \|\| ciphertext) |
//!
//! ## Data region
//!
//! Contiguous ciphertext bytes. Each block's slice is `[data_offset, data_offset+length)`.

use crate::crypto_engine::aead::AeadEnvelope;
use crate::crypto_engine::block::{BlockCiphertext, BlockCrypto};
use crate::crypto_engine::AeadAlgorithm;
use crate::fs_layer::durability::fsync_dir;
use crate::fs_layer::kdf::{derive_volume_key, kdf_path_for, KdfParams, VolumeKeyFile};
use crate::fs_layer::wal::{wal_path_for, Wal};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const BACKING_EXT: &str = "sot";

pub const HEADER_SIZE: usize = 256;
pub const INDEX_ENTRY_SIZE: usize = 80;
pub const MAGIC: &[u8; 16] = b"SOTERIA1\0\0\0\0\0\0\0\0";
pub const VERSION: u32 = 2;
const ALG_XCHACHA: u8 = 1;
const ALG_AES_GCM: u8 = 2;
const HEADER_INTEGRITY_OFFSET: usize = 80;
const HEADER_INTEGRITY_SIZE: usize = 32;
const KDF_HASH_OFFSET: usize = 112;
const KDF_HASH_SIZE: usize = 32;

/// Hard cap on the index entry count we accept on load. Caps a maliciously
/// crafted header at a known-bounded allocation. With 4 KiB blocks, this is
/// 256 TiB max volume, which is the practical ceiling for any consumer use.
pub const MAX_BLOCK_COUNT: u32 = 1 << 26; // 64M blocks = 256 TiB @ 4 KiB

/// Hard cap on the WAL payload length we accept on load (see wal.rs).
pub const MAX_WAL_PAYLOAD: usize = 1 << 30; // 1 GiB

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VolumeError {
    pub reason: String,
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "volume: {}", self.reason)
    }
}

impl std::error::Error for VolumeError {}

impl From<VolumeError> for crate::Result<()> {
    fn from(e: VolumeError) -> Self {
        Err(anyhow::anyhow!(e.reason))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    pub block_index: u32,
    pub data_offset: u64,
    pub length: u32,
    pub nonce: [u8; 24],
    pub lineage_new: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskFile {
    pub file_id: [u8; 32],
    pub block_size: u32,
    pub plaintext_size: u64,
    pub algorithm: AeadAlgorithm,
    pub index: Vec<BlockIndexEntry>,
    pub ciphertext: Vec<u8>,
    /// BLAKE3 hash of the KDF sidecar file. Stored in the volume header
    /// to prevent KDF sidecar swapping attacks (PATCH-05).
    #[serde(default)]
    pub kdf_hash: Option<[u8; 32]>,
}

impl OnDiskFile {
    /// Serialize this volume to its binary representation.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(
            HEADER_SIZE + self.index.len() * INDEX_ENTRY_SIZE + self.ciphertext.len(),
        );
        let mut header = [0u8; HEADER_SIZE];
        header[..16].copy_from_slice(MAGIC);
        header[16..20].copy_from_slice(&VERSION.to_le_bytes());
        header[20] = match self.algorithm {
            AeadAlgorithm::XChaCha20Poly1305 => ALG_XCHACHA,
            AeadAlgorithm::Aes256Gcm => ALG_AES_GCM,
        };
        header[24..56].copy_from_slice(&self.file_id);
        header[56..60].copy_from_slice(&self.block_size.to_le_bytes());
        header[64..72].copy_from_slice(&self.plaintext_size.to_le_bytes());
        header[72..76].copy_from_slice(&(self.index.len() as u32).to_le_bytes());
        // PATCH-05 + V-AUDIT-2: Write KDF sidecar hash to header BEFORE
        // computing integrity, so the integrity hash covers the KDF_HASH field.
        if let Some(kdf_hash) = &self.kdf_hash {
            header[KDF_HASH_OFFSET..KDF_HASH_OFFSET + KDF_HASH_SIZE].copy_from_slice(kdf_hash);
        }
        // Header integrity covers everything from offset 0 to the KDF_HASH field
        // (inclusive). This binds the KDF_HASH to the integrity check, fixing
        // the bypass where the old layout put integrity in the middle and
        // covered only bytes 0..80.
        let integrity_end = KDF_HASH_OFFSET + KDF_HASH_SIZE;
        let integrity = blake3::hash(&header[..integrity_end]);
        header[HEADER_INTEGRITY_OFFSET..HEADER_INTEGRITY_OFFSET + HEADER_INTEGRITY_SIZE]
            .copy_from_slice(integrity.as_bytes());
        buf.extend_from_slice(&header);
        for entry in &self.index {
            buf.extend_from_slice(&entry.block_index.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf.extend_from_slice(&entry.data_offset.to_le_bytes());
            buf.extend_from_slice(&entry.length.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf.extend_from_slice(&entry.nonce);
            buf.extend_from_slice(&entry.lineage_new);
        }
        buf.extend_from_slice(&self.ciphertext);
        Ok(buf)
    }

    /// Parse a volume from its binary representation. Verifies magic, version,
    /// and header integrity (including the KDF_HASH field). Does NOT verify
    /// the lineage chain of data blocks; use `verify_lineage` for that.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < HEADER_SIZE {
            anyhow::bail!("volume: input shorter than header");
        }
        if &bytes[..16] != MAGIC {
            anyhow::bail!("volume: bad magic");
        }
        let version = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if version != VERSION {
            anyhow::bail!("volume: unsupported version {version}");
        }
        let alg = match bytes[20] {
            ALG_XCHACHA => AeadAlgorithm::XChaCha20Poly1305,
            ALG_AES_GCM => AeadAlgorithm::Aes256Gcm,
            other => anyhow::bail!("volume: unknown algorithm id {other}"),
        };
        let mut file_id = [0u8; 32];
        file_id.copy_from_slice(&bytes[24..56]);
        let block_size = u32::from_le_bytes(bytes[56..60].try_into().unwrap());
        let plaintext_size = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let block_count = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
        // V-AUDIT-11: Bound block_count before computing index_size to prevent
        // a maliciously large header causing an OOM allocation.
        if block_count > MAX_BLOCK_COUNT {
            anyhow::bail!(
                "volume: block_count {} exceeds max {}",
                block_count,
                MAX_BLOCK_COUNT
            );
        }
        // V-AUDIT-2: Verify header integrity over bytes 0..KDF_HASH_END, so
        // the KDF_HASH is now bound to the integrity check.
        let integrity_end = KDF_HASH_OFFSET + KDF_HASH_SIZE;
        let stored =
            &bytes[HEADER_INTEGRITY_OFFSET..HEADER_INTEGRITY_OFFSET + HEADER_INTEGRITY_SIZE];
        let computed = blake3::hash(&bytes[..integrity_end]);
        if stored != computed.as_bytes() {
            anyhow::bail!("volume: header integrity check failed");
        }
        // Read KDF sidecar hash from header.
        let kdf_hash = {
            let hash_bytes = &bytes[KDF_HASH_OFFSET..KDF_HASH_OFFSET + KDF_HASH_SIZE];
            if hash_bytes.iter().all(|&b| b == 0) {
                None
            } else {
                let mut h = [0u8; 32];
                h.copy_from_slice(hash_bytes);
                Some(h)
            }
        };

        let block_count_us = block_count as usize;
        let index_size = block_count_us
            .checked_mul(INDEX_ENTRY_SIZE)
            .ok_or_else(|| anyhow::anyhow!("volume: index size overflow"))?;
        if bytes.len() < HEADER_SIZE + index_size {
            anyhow::bail!("volume: input shorter than index");
        }
        let mut index = Vec::with_capacity(block_count_us);
        for i in 0..block_count_us {
            let off = HEADER_SIZE + i * INDEX_ENTRY_SIZE;
            let block_index = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            let data_offset = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
            let length = u32::from_le_bytes(bytes[off + 16..off + 20].try_into().unwrap());
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&bytes[off + 24..off + 48]);
            let mut lineage_new = [0u8; 32];
            lineage_new.copy_from_slice(&bytes[off + 48..off + 80]);
            index.push(BlockIndexEntry {
                block_index,
                data_offset,
                length,
                nonce,
                lineage_new,
            });
        }
        let ciphertext = bytes[HEADER_SIZE + index_size..].to_vec();
        Ok(Self {
            file_id,
            block_size,
            plaintext_size,
            algorithm: alg,
            index,
            ciphertext,
            kdf_hash,
        })
    }

    pub fn load(path: &Path) -> crate::Result<Self> {
        // First, recover any committed-but-unrenamed WAL. This is a no-op
        // when the previous save completed cleanly.
        let _ = Wal::recover(path);
        let raw = std::fs::read(path)?;
        Self::from_bytes(&raw)
    }

    pub fn save(&self, path: &Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = self.to_bytes()?;
        // Crash-safe write:
        //   1. Stage the new bytes in a sibling WAL with a commit marker and
        //      fsync. The WAL is the durable "intent" record.
        //   2. fsync the parent directory so the WAL entry is durable.
        //   3. Atomically rename the data temp file to the data path. The
        //      single rename is the crash-safe transition from old to new.
        //   4. fsync the parent directory so the rename is durable.
        //   5. fsync the data file so the bytes themselves are durable.
        //   6. Best-effort: remove the WAL and fsync the dir again. If this
        //      step is lost to a crash, the next load will see the WAL,
        //      replay it, and clean up.
        let wal = wal_path_for(path);
        Wal::write(&wal, &bytes).map_err(|e| anyhow::anyhow!("WAL write: {e}"))?;
        fsync_dir(&wal);
        let tmp = path.with_extension("sot.tmp");
        std::fs::write(&tmp, &bytes)?;
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, path).map_err(|e| anyhow::anyhow!("rename: {e}"))?;
        // fsync the data file at its new path so the renamed bytes are
        // durable, then fsync the parent directory so the directory entry
        // is durable.
        if let Ok(f) = std::fs::File::open(path) {
            let _ = f.sync_all();
        }
        fsync_dir(path);
        let _ = std::fs::remove_file(&wal);
        fsync_dir(path);
        Ok(())
    }

    /// Decrypt all blocks and return the plaintext. Verifies the lineage chain
    /// before returning; if the chain is broken, returns an error pointing to
    /// the first bad block index. This is V-AUDIT-3.
    pub fn plaintext(&self, crypto: &BlockCrypto) -> crate::Result<Vec<u8>> {
        // V-AUDIT-3: Refuse to decrypt if the lineage chain is broken.
        if let Some(bad) = self.verify_lineage() {
            anyhow::bail!("volume: lineage chain broken at block {bad}");
        }
        let mut out = Vec::with_capacity(self.plaintext_size as usize);
        for entry in &self.index {
            let start = entry.data_offset as usize;
            let end = start + entry.length as usize;
            if end > self.ciphertext.len() {
                anyhow::bail!("volume: ciphertext slice out of bounds");
            }
            let block = BlockCiphertext {
                block_index: entry.block_index as u64,
                lineage_prev: lineage_prev_for(self, entry),
                lineage_new: blake3_hex(&entry.lineage_new),
                envelope: AeadEnvelope {
                    algorithm: self.algorithm,
                    nonce: entry.nonce[..nonce_len(self.algorithm)].to_vec(),
                    aad_blake3: compute_aad(self, entry),
                    ciphertext: self.ciphertext[start..end].to_vec(),
                },
            };
            let pt = crypto.decrypt_block(&block)?;
            out.extend_from_slice(&pt);
        }
        out.truncate(self.plaintext_size as usize);
        Ok(out)
    }

    /// Verify the full lineage chain. Each block's `lineage_new` must equal
    /// `BLAKE3(lineage_prev || ciphertext)`. Returns the index of the first
    /// tampered block, or `None` if the chain is intact.
    pub fn verify_lineage(&self) -> Option<usize> {
        let mut prev_hex = "GENESIS".to_string();
        for (i, entry) in self.index.iter().enumerate() {
            let start = entry.data_offset as usize;
            let end = start + entry.length as usize;
            if end > self.ciphertext.len() {
                return Some(i);
            }
            let mut material = prev_hex.as_bytes().to_vec();
            material.extend_from_slice(&self.ciphertext[start..end]);
            let computed = blake3::hash(&material).to_hex().to_string();
            if computed != blake3_hex(&entry.lineage_new) {
                return Some(i);
            }
            prev_hex = blake3_hex(&entry.lineage_new);
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.plaintext_size == 0
    }
}

fn lineage_prev_for(file: &OnDiskFile, entry: &BlockIndexEntry) -> String {
    if entry.block_index == 0 {
        return "GENESIS".into();
    }
    let prev = &file.index[entry.block_index as usize - 1];
    blake3_hex(&prev.lineage_new)
}

fn blake3_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn compute_aad(file: &OnDiskFile, entry: &BlockIndexEntry) -> String {
    let prev = if entry.block_index == 0 {
        "GENESIS".to_string()
    } else {
        blake3_hex(&file.index[entry.block_index as usize - 1].lineage_new)
    };
    let aad_bytes = format!("soteria:block:{}:prev:{}", entry.block_index, prev);
    blake3::hash(aad_bytes.as_bytes()).to_hex().to_string()
}

fn nonce_len(alg: AeadAlgorithm) -> usize {
    match alg {
        AeadAlgorithm::XChaCha20Poly1305 => 24,
        AeadAlgorithm::Aes256Gcm => 12,
    }
}

/// Build a binary volume from plaintext, splitting at `block_size` boundaries.
pub fn encrypt_to_disk(
    file_id: [u8; 32],
    algorithm: AeadAlgorithm,
    domain_key: [u8; 32],
    block_size: usize,
    plaintext: &[u8],
) -> crate::Result<OnDiskFile> {
    let crypto = BlockCrypto::new(algorithm, domain_key);
    let mut index = Vec::new();
    let mut ciphertext = Vec::new();
    let mut prev = "GENESIS".to_string();
    for (i, chunk) in plaintext.chunks(block_size).enumerate() {
        let ct = crypto.encrypt_block(i as u64, chunk, &prev)?;
        let offset = ciphertext.len() as u64;
        let length = ct.envelope.ciphertext.len() as u32;
        let mut nonce = [0u8; 24];
        let n = ct.envelope.nonce.len().min(24);
        nonce[..n].copy_from_slice(&ct.envelope.nonce[..n]);
        let lineage_new_bytes = hex_to_bytes(&ct.lineage_new);
        let mut lineage_new = [0u8; 32];
        let m = lineage_new_bytes.len().min(32);
        lineage_new[..m].copy_from_slice(&lineage_new_bytes[..m]);
        index.push(BlockIndexEntry {
            block_index: i as u32,
            data_offset: offset,
            length,
            nonce,
            lineage_new,
        });
        ciphertext.extend_from_slice(&ct.envelope.ciphertext);
        prev = ct.lineage_new;
    }
    Ok(OnDiskFile {
        file_id,
        block_size: block_size as u32,
        plaintext_size: plaintext.len() as u64,
        algorithm,
        index,
        ciphertext,
        kdf_hash: None,
    })
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("00"), 16)
        {
            out.push(b);
        }
        i += 2;
    }
    out
}

/// Resolve a mount-level filename to the corresponding backing file path.
pub fn backing_path_for(backing_root: &Path, mount_name: &str) -> PathBuf {
    backing_root.join(format!("{mount_name}.{BACKING_EXT}"))
}

/// Derive a stable 64-bit inode number from a mount-level filename.
pub fn inode_for(name: &str) -> u64 {
    let h = blake3::hash(name.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&h.as_bytes()[..8]);
    bytes[7] &= 0x7F;
    u64::from_le_bytes(bytes)
}

/// Inverse of `inode_for`: walk the backing directory and return the filename
/// matching the supplied inode.
pub fn name_for_inode(backing_root: &Path, ino: u64) -> Option<String> {
    let entries = std::fs::read_dir(backing_root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some(BACKING_EXT) {
            continue;
        }
        let name = path.file_stem()?.to_string_lossy().to_string();
        if inode_for(&name) == ino {
            return Some(name);
        }
    }
    None
}

/// List all mount-level filenames currently present in the backing directory.
pub fn list_files(backing_root: &Path) -> crate::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(backing_root)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some(BACKING_EXT) {
            if let Some(stem) = path.file_stem() {
                out.push(stem.to_string_lossy().to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Passphrase-derived volume keys (Argon2id via the sidecar KDF file).
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` to a new volume at `data_path`, deriving the volume
/// key from `passphrase` with Argon2id using the supplied `kdf_params`.
///
/// Writes both the volume file (`<data_path>`) and the KDF sidecar
/// (`<data_path>.sot.kdf`). The KDF sidecar stores the salt and cost
/// parameters so the same passphrase can re-derive the same key on reload.
pub fn encrypt_to_disk_with_passphrase(
    data_path: &Path,
    algorithm: AeadAlgorithm,
    kdf_params: KdfParams,
    block_size: usize,
    passphrase: &[u8],
    plaintext: &[u8],
) -> crate::Result<OnDiskFile> {
    let kdf_file = VolumeKeyFile::generate(kdf_params);
    let key = derive_volume_key(passphrase, &kdf_file)?;
    let mut file_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut file_id);
    let vol = encrypt_to_disk(file_id, algorithm, *key, block_size, plaintext)?;
    vol.save(data_path)?;
    kdf_file.save(&kdf_path_for(data_path))?;
    Ok(vol)
}

/// Load a volume at `data_path` and decrypt it using a key derived from
/// `passphrase`. Returns `Err` if the KDF sidecar is missing, malformed, or
/// if the derived key fails to decrypt any block.
pub fn decrypt_from_disk_with_passphrase(
    data_path: &Path,
    passphrase: &[u8],
) -> crate::Result<(OnDiskFile, Vec<u8>)> {
    let kdf_path = kdf_path_for(data_path);
    let kdf_file = VolumeKeyFile::load(&kdf_path)
        .map_err(|e| anyhow::anyhow!("KDF sidecar load failed: {e}"))?;
    let key = derive_volume_key(passphrase, &kdf_file)?;
    decrypt_from_disk_with_key(data_path, &key)
}

/// Load a volume at `data_path` and decrypt it with a raw 32-byte key. Used
/// after `ShareFile::unlock` recovers the key from a recipient's secret key.
pub fn decrypt_from_disk_with_key(
    data_path: &Path,
    key: &[u8; 32],
) -> crate::Result<(OnDiskFile, Vec<u8>)> {
    let vol = OnDiskFile::load(data_path)?;
    let crypto = BlockCrypto::new(vol.algorithm, *key);
    let pt = vol.plaintext(&crypto)?;
    Ok((vol, pt))
}

/// Verify that `key` correctly decrypts the first block of the volume at
/// `data_path`. Returns `Ok(())` if the AEAD auth check passes, `Err`
/// otherwise. Used to confirm that a passphrase-derived key matches the
/// volume (defends share-sidecar creation against wrong-passphrase attacks).
pub fn verify_key_for_volume(data_path: &Path, key: &[u8; 32]) -> crate::Result<()> {
    let vol = OnDiskFile::load(data_path)?;
    if vol.index.is_empty() {
        return Ok(());
    }
    let crypto = BlockCrypto::new(vol.algorithm, *key);
    let first = &vol.index[0];
    let start = first.data_offset as usize;
    let end = start + first.length as usize;
    if end > vol.ciphertext.len() {
        anyhow::bail!("volume: ciphertext slice out of bounds");
    }
    let envelope = AeadEnvelope {
        algorithm: vol.algorithm,
        nonce: first.nonce[..nonce_len(vol.algorithm)].to_vec(),
        aad_blake3: compute_aad(&vol, first),
        ciphertext: vol.ciphertext[start..end].to_vec(),
    };
    let block = BlockCiphertext {
        block_index: first.block_index as u64,
        lineage_prev: lineage_prev_for(&vol, first),
        lineage_new: blake3_hex(&first.lineage_new),
        envelope,
    };
    crypto
        .decrypt_block(&block)
        .map_err(|e| anyhow::anyhow!("key verification failed: {e}"))?;
    Ok(())
}
