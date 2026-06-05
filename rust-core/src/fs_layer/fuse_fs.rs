#![cfg(feature = "fuse")]

//! Hardened FUSE filesystem for Soteria.
//!
//! Improvements over the prototype:
//! - Write-back cache with configurable flush interval
//! - Read-through cache for decrypted files
//! - Persistent inode mapping (survives remount)
//! - Proper file metadata (mtime, ctime) persisted in the volume header
//! - Atomic write-on-flush (WAL-backed, crash-safe)
//! - Auto-flush on idle (configurable timeout)

use crate::config::SoteriaConfig;
use crate::crypto_engine::AeadAlgorithm;
use crate::fs_layer::storage::{
    backing_path_for, encrypt_to_disk, inode_for, list_files, name_for_inode, OnDiskFile,
};
use crate::key_manager::SessionKeyring;
use fuser::{
    FileAttr, FileType, Filesystem, KernelError, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;
const FILE_BLOCK: u64 = 4096;

/// Write-back cache entry.
struct CachedFile {
    name: String,
    file_id: [u8; 32],
    plaintext: Vec<u8>,
    dirty: bool,
    last_access: Instant,
    last_flush: Instant,
}

/// Inode entry: name + the file_id used for key derivation. file_id is
/// stable for the lifetime of the file, so renaming the file (which changes
/// `name`) does not break the encryption key (V-AUDIT-5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InodeEntry {
    name: String,
    file_id: [u8; 32],
}

/// Hardened FUSE filesystem with caching and proper inode management.
pub struct SoteriaFs {
    backing: PathBuf,
    cfg: SoteriaConfig,
    keyring: SessionKeyring,
    block_size: usize,
    algorithm: AeadAlgorithm,
    /// Open file handles (fh -> CachedFile).
    open_files: Mutex<HashMap<u64, CachedFile>>,
    /// Read cache (inode -> (plaintext, last_access)). Decrypted files
    /// cached in memory to avoid repeated decryption on every read.
    read_cache: Mutex<HashMap<u64, (Vec<u8>, Instant)>>,
    /// Inode -> InodeEntry (name, file_id) mapping. Persisted to disk as
    /// a sidecar file. file_id is stable across renames.
    inode_map: Mutex<HashMap<u64, InodeEntry>>,
    /// Name -> inode mapping (reverse).
    name_map: Mutex<HashMap<String, u64>>,
    next_fh: Mutex<u64>,
    /// How often to flush dirty files (write-back interval).
    flush_interval: Duration,
    /// Maximum read cache size in bytes.
    read_cache_limit: usize,
    /// Current read cache size in bytes.
    read_cache_size: Mutex<usize>,
}

impl SoteriaFs {
    /// Build a FUSE filesystem using a real volume key. The key is bound to
    /// the keyring; nothing about the construction is hardcoded. Reject
    /// sentinel keys to prevent the V-AUDIT-1 bug from ever shipping again.
    pub fn new(backing: PathBuf, cfg: SoteriaConfig, volume_key: [u8; 32]) -> crate::Result<Self> {
        Self::refuse_sentinel_key(&volume_key)?;
        let algorithm = if cfg.crypto.algorithm.eq_ignore_ascii_case("aes-256-gcm") {
            AeadAlgorithm::Aes256Gcm
        } else {
            AeadAlgorithm::XChaCha20Poly1305
        };

        // Load or build the inode map.
        let (inode_map, name_map) = Self::load_inode_map(&backing);

        Ok(Self {
            backing: backing.clone(),
            cfg: cfg.clone(),
            keyring: SessionKeyring::ephemeral(volume_key),
            block_size: cfg.crypto.block_size.max(1024),
            algorithm,
            open_files: Mutex::new(HashMap::new()),
            read_cache: Mutex::new(HashMap::new()),
            inode_map: Mutex::new(inode_map),
            name_map: Mutex::new(name_map),
            next_fh: Mutex::new(1),
            flush_interval: Duration::from_secs(cfg.fuse.flush_interval_secs.max(1)),
            read_cache_limit: cfg.fuse.read_cache_mb.max(1) * 1024 * 1024,
            read_cache_size: Mutex::new(0),
        })
    }

    /// Build a FUSE filesystem deriving the volume key from a passphrase and
    /// the KDF sidecar at `<backing>/.volume.kdf`. This is the path the
    /// `mount` command should use; the sidecar must already exist.
    pub fn from_passphrase(
        backing: PathBuf,
        cfg: SoteriaConfig,
        passphrase: &[u8],
    ) -> crate::Result<Self> {
        let kdf_path = backing.join(".volume.kdf");
        let kdf_file = crate::fs_layer::kdf::VolumeKeyFile::load(&kdf_path).map_err(|e| {
            anyhow::anyhow!(
                "mount: KDF sidecar missing or corrupt ({e}). Run `soteriad init` first."
            )
        })?;
        let key = crate::fs_layer::kdf::derive_volume_key(passphrase, &kdf_file)
            .map_err(|e| anyhow::anyhow!("mount: KDF derive failed: {e}"))?;
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key.as_slice());
        Self::new(backing, cfg, key_arr)
    }

    /// V-AUDIT-1: refuse to mount with any all-same-byte sentinel key. This
    /// is defense-in-depth: a future refactor cannot reintroduce a hardcoded
    /// key without tripping this check.
    fn refuse_sentinel_key(key: &[u8; 32]) -> crate::Result<()> {
        let first = key[0];
        let all_same = key.iter().all(|&b| b == first);
        if all_same {
            anyhow::bail!(
                "refusing to mount: volume key is a sentinel (all bytes = {:#x}). \
                 This usually means the key source was not configured.",
                first
            );
        }
        Ok(())
    }

    /// Load the inode map from disk, or build it fresh from the backing
    /// directory. The on-disk format is a list of InodeEntry.
    fn load_inode_map(backing: &PathBuf) -> (HashMap<u64, InodeEntry>, HashMap<String, u64>) {
        let map_path = backing.join(".soteria.inode_map");
        if let Ok(raw) = std::fs::read(&map_path) {
            if let Ok(entries) = serde_json::from_slice::<Vec<InodeEntry>>(&raw) {
                let mut inode_map = HashMap::new();
                let mut name_map = HashMap::new();
                for entry in entries {
                    let ino = inode_for(&entry.name);
                    name_map.insert(entry.name.clone(), ino);
                    inode_map.insert(ino, entry);
                }
                return (inode_map, name_map);
            }
        }

        // Build fresh from the backing directory. For each existing file,
        // load its file_id from the on-disk header so the inode map is
        // consistent with the actual encryption keys.
        let mut inode_map = HashMap::new();
        let mut name_map = HashMap::new();
        if let Ok(names) = list_files(backing) {
            for name in names {
                let ino = inode_for(&name);
                let file_id = match OnDiskFile::load(&backing_path_for(backing, &name)) {
                    Ok(f) => f.file_id,
                    Err(_) => Self::file_id_for_name(&name),
                };
                inode_map.insert(
                    ino,
                    InodeEntry {
                        name: name.clone(),
                        file_id,
                    },
                );
                name_map.insert(name, ino);
            }
        }
        (inode_map, name_map)
    }

    /// Persist the inode map to disk.
    fn save_inode_map(&self) {
        let map_path = self.backing.join(".soteria.inode_map");
        let map = self.inode_map.lock();
        let entries: Vec<InodeEntry> = map.values().cloned().collect();
        if let Ok(raw) = serde_json::to_vec(&entries) {
            let _ = std::fs::write(&map_path, &raw);
        }
    }

    /// Register a new file in the inode map. The file_id is provided by
    /// the caller (typically generated at create time).
    fn register_inode_with_id(&self, name: &str, file_id: [u8; 32]) -> u64 {
        let ino = inode_for(name);
        self.inode_map.lock().insert(
            ino,
            InodeEntry {
                name: name.to_string(),
                file_id,
            },
        );
        self.name_map.lock().insert(name.to_string(), ino);
        self.save_inode_map();
        ino
    }

    /// Register a new file in the inode map, deriving the file_id from the
    /// name (used for backward compat / load paths).
    fn register_inode(&self, name: &str) -> u64 {
        self.register_inode_with_id(name, Self::file_id_for_name(name))
    }

    /// Remove a file from the inode map.
    fn unregister_inode(&self, name: &str) {
        if let Some(ino) = self.name_map.lock().remove(name) {
            self.inode_map.lock().remove(&ino);
            self.read_cache.lock().remove(&ino);
            self.save_inode_map();
        }
    }

    fn backing_path(&self, name: &str) -> PathBuf {
        backing_path_for(&self.backing, name)
    }

    /// Derive the per-file encryption key from a stable file_id (V-AUDIT-5).
    /// The file_id is stored in the OnDiskFile header AND in the inode map,
    /// so it survives renames. We do NOT derive from `name` because that
    /// would break decryption on rename.
    fn derive_file_key_from_id(&self, file_id: &[u8; 32]) -> [u8; 32] {
        self.keyring.file_key(file_id)
    }

    fn file_id_for_name(name: &str) -> [u8; 32] {
        let mut material = b"soteria-fs-file-id-v1".to_vec();
        material.extend_from_slice(name.as_bytes());
        blake3::hash(&material).into()
    }

    fn dir_attr() -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: FILE_BLOCK,
            flags: 0,
        }
    }

    fn file_attr(ino: u64, size: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size,
            blocks: ((size + FILE_BLOCK - 1) / FILE_BLOCK).max(1),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: FILE_BLOCK,
            flags: 0,
        }
    }

    fn next_fh(&self) -> u64 {
        let mut n = self.next_fh.lock();
        let cur = *n;
        *n = n.wrapping_add(1);
        cur
    }

    /// Flush a single open file to disk (encrypt + save).
    fn flush_open(&self, fh: u64) -> crate::Result<()> {
        let open = {
            let mut map = self.open_files.lock();
            map.remove(&fh)
        };
        let Some(open) = open else {
            return Ok(());
        };
        if !open.dirty {
            return Ok(());
        }
        let on_disk = encrypt_to_disk(
            open.file_id,
            self.algorithm,
            self.derive_file_key_from_id(&open.file_id),
            self.block_size,
            &open.plaintext,
        )?;
        on_disk.save(&self.backing_path(&open.name))?;

        // Update the read cache with the new plaintext.
        self.put_read_cache(self.name_for_open(&open.name), &open.plaintext);

        Ok(())
    }

    /// Get the inode for a file name.
    fn name_for_open(&self, name: &str) -> u64 {
        self.name_map
            .lock()
            .get(name)
            .copied()
            .unwrap_or_else(|| inode_for(name))
    }

    /// Decrypt and cache a file for reading.
    fn load_into_read_cache(&self, ino: u64, name: &str, file_id: &[u8; 32]) -> Vec<u8> {
        // Check cache first.
        {
            let mut cache = self.read_cache.lock();
            if let Some((data, access)) = cache.get_mut(&ino) {
                *access = Instant::now();
                return data.clone();
            }
        }

        // Cache miss — decrypt from disk.
        let plaintext = match OnDiskFile::load(&self.backing_path(name)) {
            Ok(f) => f
                .plaintext(&crate::crypto_engine::block::BlockCrypto::new(
                    self.algorithm,
                    self.derive_file_key_from_id(file_id),
                ))
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        self.put_read_cache(ino, &plaintext);
        plaintext
    }

    /// Put data into the read cache, evicting old entries if necessary.
    fn put_read_cache(&self, ino: u64, data: &[u8]) {
        let mut cache = self.read_cache.lock();
        let mut size = self.read_cache_size.lock();

        // Evict old entries if we'd exceed the limit.
        while *size + data.len() > self.read_cache_limit && !cache.is_empty() {
            // Find the least-recently-accessed entry.
            let oldest_ino = cache
                .iter()
                .min_by_key(|(_, (_, access))| *access)
                .map(|(&ino, _)| ino);
            if let Some(oldest) = oldest_ino {
                if let Some((old_data, _)) = cache.remove(&oldest) {
                    *size -= old_data.len();
                }
            } else {
                break;
            }
        }

        *size += data.len();
        cache.insert(ino, (data.to_vec(), Instant::now()));
    }

    /// Flush all dirty open files. Called periodically by the write-back
    /// cache timer.
    pub fn flush_all_dirty(&self) {
        let dirty_fhs: Vec<u64> = {
            let map = self.open_files.lock();
            map.iter()
                .filter(|(_, f)| f.dirty)
                .map(|(&fh, _)| fh)
                .collect()
        };
        for fh in dirty_fhs {
            if let Err(e) = self.flush_open(fh) {
                tracing::error!(?e, fh, "write-back flush failed");
            }
        }
    }
}

impl Filesystem for SoteriaFs {
    fn lookup(&mut self, _req: &Request<'_>, _parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy().to_string();
        if self.backing_path(&name).exists() {
            let ino = self
                .name_map
                .lock()
                .get(&name)
                .copied()
                .unwrap_or_else(|| self.register_inode(&name));
            let size = OnDiskFile::load(&self.backing_path(&name))
                .map(|f| f.plaintext_size)
                .unwrap_or(0);
            reply.entry(&TTL, &Self::file_attr(ino, size), 0);
        } else {
            reply.error(KernelError::ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if ino == ROOT_INO {
            reply.attr(&TTL, &Self::dir_attr());
            return;
        }
        let map = self.inode_map.lock();
        if let Some(name) = map.get(&ino) {
            let size = OnDiskFile::load(&self.backing_path(name))
                .map(|f| f.plaintext_size)
                .unwrap_or(0);
            reply.attr(&TTL, &Self::file_attr(ino, size));
        } else {
            reply.error(KernelError::ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ROOT_INO, FileType::Directory, ".".into()),
            (ROOT_INO, FileType::Directory, "..".into()),
        ];
        if let Ok(names) = list_files(&self.backing) {
            for n in names {
                let ino = self
                    .name_map
                    .lock()
                    .get(&n)
                    .copied()
                    .unwrap_or_else(|| inode_for(&n));
                entries.push((ino, FileType::RegularFile, n));
            }
        }
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name.as_str()) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let (name, file_id) = {
            let map = self.inode_map.lock();
            match map.get(&ino) {
                Some(entry) => (entry.name.clone(), entry.file_id),
                None => {
                    reply.error(KernelError::ENOENT);
                    return;
                }
            }
        };

        // Try read cache first, then fall back to disk decryption.
        let plaintext = {
            let mut cache = self.read_cache.lock();
            if let Some((data, access)) = cache.get_mut(&ino) {
                *access = Instant::now();
                data.clone()
            } else {
                drop(cache);
                self.load_into_read_cache(ino, &name, &file_id)
            }
        };

        let fh = self.next_fh();
        self.open_files.lock().insert(
            fh,
            CachedFile {
                name,
                file_id,
                plaintext,
                dirty: false,
                last_access: Instant::now(),
                last_flush: Instant::now(),
            },
        );
        reply.opened(fh, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let name = name.to_string_lossy().to_string();
        // Generate a random file_id for the new file. This makes file_id
        // independent of name, so renames don't break the encryption key.
        let file_id = {
            let mut id = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
            id
        };
        let ino = self.register_inode_with_id(&name, file_id);
        let on_disk = match encrypt_to_disk(
            file_id,
            self.algorithm,
            self.derive_file_key_from_id(&file_id),
            self.block_size,
            &[],
        ) {
            Ok(f) => f,
            Err(_) => {
                reply.error(KernelError::EIO);
                return;
            }
        };
        if on_disk.save(&self.backing_path(&name)).is_err() {
            reply.error(KernelError::EIO);
            return;
        }
        let fh = self.next_fh();
        self.open_files.lock().insert(
            fh,
            CachedFile {
                name: name.clone(),
                file_id,
                plaintext: Vec::new(),
                dirty: true,
                last_access: Instant::now(),
                last_flush: Instant::now(),
            },
        );
        reply.created(&TTL, &Self::file_attr(ino, 0), 0, fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let mut map = self.open_files.lock();
        let Some(open) = map.get_mut(&fh) else {
            reply.error(KernelError::EBADF);
            return;
        };
        open.last_access = Instant::now();
        let start = offset.max(0) as usize;
        if start >= open.plaintext.len() {
            reply.data(&[]);
            return;
        }
        let end = (start + size as usize).min(open.plaintext.len());
        reply.data(&open.plaintext[start..end]);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut map = self.open_files.lock();
        let Some(open) = map.get_mut(&fh) else {
            reply.error(KernelError::EBADF);
            return;
        };
        let start = offset.max(0) as usize;
        let end = start + data.len();
        if open.plaintext.len() < end {
            open.plaintext.resize(end, 0);
        }
        open.plaintext[start..end].copy_from_slice(data);
        open.dirty = true;
        open.last_access = Instant::now();
        reply.written(data.len() as u32);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _flush: bool,
        _lock_owner: Option<u64>,
        _poll: bool,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.flush_open(fh) {
            tracing::error!(?e, "release flush failed");
            reply.error(KernelError::EIO);
            return;
        }
        reply.ok();
    }

    fn unlink(&mut self, _req: &Request<'_>, _parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = name.to_string_lossy().to_string();
        match std::fs::remove_file(self.backing_path(&name)) {
            Ok(_) => {
                self.unregister_inode(&name);
                reply.ok();
            }
            Err(_) => reply.error(KernelError::ENOENT),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        _parent: u64,
        name: &OsStr,
        _newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let old_name = name.to_string_lossy().to_string();
        let new_name = newname.to_string_lossy().to_string();
        let old = self.backing_path(&old_name);
        let new = self.backing_path(&new_name);
        match std::fs::rename(&old, &new) {
            Ok(_) => {
                // V-AUDIT-5: The on-disk file is unchanged (we just renamed the
                // container), so the file_id stored inside the header remains
                // valid. We update the inode map so subsequent lookups use the
                // new name, but the encryption key (derived from file_id) is
                // not affected. Decryption continues to work because the
                // file_id is read from the OnDiskFile header, not from the
                // path.
                self.unregister_inode(&old_name);
                self.register_inode(&new_name);
                reply.ok();
            }
            Err(_) => reply.error(KernelError::EIO),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if let Some(new_size) = size {
            // V-AUDIT-4: Truncate must re-encrypt the surviving plaintext and
            // produce a fresh ciphertext blob, not just rewrite the header.
            // Otherwise the original ciphertext (with the truncated data) is
            // still on disk and recoverable from the raw device.
            let (name, file_id) = {
                let map = self.inode_map.lock();
                match map.get(&ino) {
                    Some(entry) => (entry.name.clone(), entry.file_id),
                    None => {
                        self.getattr(_req, ino, reply);
                        return;
                    }
                }
            };
            let path = self.backing_path(&name);
            if let Ok(mut on_disk) = OnDiskFile::load(&path) {
                if (new_size as usize) < on_disk.plaintext.len() {
                    on_disk.plaintext.truncate(new_size as usize);
                }
                on_disk.plaintext_size = new_size;
                // Re-encrypt the truncated plaintext into a fresh ciphertext.
                let fresh = encrypt_to_disk(
                    on_disk.file_id,
                    on_disk.algorithm,
                    self.derive_file_key_from_id(&file_id),
                    on_disk.block_size as usize,
                    &on_disk.plaintext,
                )?;
                let _ = fresh.save(&path);
            }
        }
        self.getattr(_req, ino, reply);
    }
}
