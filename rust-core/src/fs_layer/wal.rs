//! Crash-safe write-ahead log for Soteria volumes.
//!
//! The on-disk volume format is updated in two steps:
//!
//! 1. Write the new full volume bytes to `<data_path>.sot.wal` followed by a
//!    `COM\x01` commit marker, then `fsync` the WAL file.
//! 2. Atomically rename the WAL to the data path. This single rename is the
//!    crash-safe transition from "old volume" to "new volume".
//!
//! On any subsequent access, [`Wal::recover`] inspects the WAL and either
//! applies a committed-but-unrenamed payload (crash happened between step 1
//! and step 2) or discards an uncommitted one (crash happened mid-write).
//!
//! ## Wire format
//!
//! ```text
//! +----------------+   offset 0
//! |  "WAL\x01"     |   4 bytes
//! +----------------+   offset 4
//! |  payload_len   |   u32 LE
//! +----------------+   offset 8
//! |  payload       |   payload_len bytes (full new volume bytes)
//! +----------------+   offset 8 + payload_len
//! |  "COM\x01"     |   4 bytes
//! +----------------+
//! ```

use crate::fs_layer::durability::fsync_dir;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const WAL_EXT: &str = "wal";
pub const WAL_MAGIC: &[u8; 4] = b"WAL\x01";
pub const WAL_COMMIT: &[u8; 4] = b"COM\x01";

/// Return the WAL path associated with a given volume data path.
///
/// `foo.sot` -> `foo.sot.wal`.
pub fn wal_path_for(data_path: &Path) -> PathBuf {
    let mut s = data_path.as_os_str().to_owned();
    s.push(".");
    s.push(WAL_EXT);
    PathBuf::from(s)
}

/// The state of a WAL on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalState {
    /// No WAL file present. The data file is the source of truth.
    Absent,
    /// WAL exists, is well-formed, and carries a commit marker. The payload
    /// must be applied to the data file to recover.
    Committed(Vec<u8>),
    /// WAL exists but is truncated or missing the commit marker. It must be
    /// discarded; the data file (if any) is the source of truth.
    Uncommitted,
}

impl WalState {
    pub fn is_committed(&self) -> bool {
        matches!(self, WalState::Committed(_))
    }
}

/// Write-ahead log writer and recovery.
pub struct Wal;

impl Wal {
    /// Write `payload` to `wal_path` with a commit marker, then `fsync`
    /// the file and the parent directory.
    ///
    /// The file is created or truncated. After this call returns, the bytes
    /// are durably on disk: either the WAL appears with both the magic and the
    /// commit marker, or it does not exist at all.
    pub fn write(wal_path: &Path, payload: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = wal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(wal_path)?;
        let len = u32::try_from(payload.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload too large")
        })?;
        file.write_all(WAL_MAGIC)?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(payload)?;
        file.write_all(WAL_COMMIT)?;
        file.sync_all()?;
        // Make the WAL's directory entry durable so a subsequent `recover`
        // call can find it after a crash.
        fsync_dir(wal_path);
        Ok(())
    }

    /// Inspect a WAL file. Returns the state and (if committed) the payload.
    pub fn inspect(wal_path: &Path) -> std::io::Result<WalState> {
        if !wal_path.exists() {
            return Ok(WalState::Absent);
        }
        let bytes = std::fs::read(wal_path)?;
        Ok(Self::parse(&bytes))
    }

    /// Parse a WAL byte buffer into a [`WalState`]. Pure function, useful for
    /// tests and for inspecting in-memory WAL data.
    pub fn parse(bytes: &[u8]) -> WalState {
        // Minimum size: 4 (magic) + 4 (len) + 0 (payload) + 4 (commit) = 12.
        if bytes.len() < 12 {
            return WalState::Uncommitted;
        }
        if &bytes[..4] != WAL_MAGIC {
            return WalState::Uncommitted;
        }
        if &bytes[bytes.len() - 4..] != WAL_COMMIT {
            return WalState::Uncommitted;
        }
        let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let payload_start = 8usize;
        let payload_end = payload_start.saturating_add(len);
        let commit_start = payload_end;
        if commit_start + 4 != bytes.len() {
            return WalState::Uncommitted;
        }
        if payload_end > bytes.len().saturating_sub(4) {
            return WalState::Uncommitted;
        }
        WalState::Committed(bytes[payload_start..payload_end].to_vec())
    }

    /// Recover a volume at `data_path`.
    ///
    /// - If the WAL is committed, apply the payload to the data file (atomic
    ///   temp + rename), then fsync the data file and the parent directory.
    ///   Finally remove the WAL.
    /// - If the WAL is uncommitted, just remove the WAL; the old data file is
    ///   the source of truth.
    /// - If no WAL exists, this is a no-op.
    pub fn recover(data_path: &Path) -> std::io::Result<WalState> {
        let wal_path = wal_path_for(data_path);
        let state = Self::inspect(&wal_path)?;
        if let WalState::Committed(payload) = &state {
            if let Some(parent) = data_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = data_path.with_extension("sot.recover.tmp");
            std::fs::write(&tmp, payload)?;
            std::fs::rename(&tmp, data_path)?;
            if let Ok(f) = std::fs::File::open(data_path) {
                let _ = f.sync_all();
            }
            fsync_dir(data_path);
        }
        // Best-effort WAL removal (ignore "not found").
        let _ = std::fs::remove_file(&wal_path);
        fsync_dir(data_path);
        Ok(state)
    }
}
