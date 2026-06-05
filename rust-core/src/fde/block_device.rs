//! Block device abstraction for full-disk encryption.
//!
//! This module defines a `BlockDevice` trait that the encrypted volume
//! layer talks to, plus a `FileBackedDevice` implementation that maps
//! the trait to a regular file (useful for testing, loopback mounts, and
//! VeraCrypt-style container files).
//!
//! ## Real-device support
//!
//! On production deployments, the trait would be implemented by:
//! - **Linux**: `open(O_DIRECT)` on `/dev/sdX` or `/dev/nvme0n1`, with
//!   sector-aligned reads/writes.
//! - **Windows**: `CreateFileW` with `FILE_FLAG_NO_BUFFERING` on
//!   `\\.\PhysicalDriveN`, with `FSCTL_LOCK_VOLUME` first.
//!
//! We intentionally do not implement the real-device path here. It is
//! OS-specific and requires admin/root. The container-file path is fully
//! functional and runs in any user context, which is what this MVP needs.
//!
//! ## Sector size
//!
//! The on-disk sector size is **512 bytes** by default (the historical
//! disk sector size; AES-XTS is defined for 16-byte blocks, so any
//! multiple of 16 works, but 512 is what real drives use). The LBA in
//! the XTS tweak is the 0-indexed sector number. The volume layer
//! preserves this convention.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Errors from the block device layer. We keep them coarse; more
/// granular errors (bad sector, short read) can be added when a real
/// device driver is wired in.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sector {sector} out of range (device has {total} sectors)")]
    OutOfRange { sector: u64, total: u64 },
    #[error("sector size mismatch: device is {device}, request was {request}")]
    SectorSize { device: usize, request: usize },
}

/// A block device. The contract is:
/// - Sector size is fixed for the lifetime of the device (call
///   `sector_size()` to get it; defaults to 512).
/// - Sector count is the total number of addressable sectors.
/// - Reads return exactly `sector_size()` bytes; if the device is
///   short, it's an error (real disks either have a full sector or
///   don't; we don't model partial sectors).
pub trait BlockDevice: Send + Sync {
    fn sector_size(&self) -> usize;
    fn sector_count(&self) -> u64;
    /// Read sector `lba` into `buf`. `buf.len()` must equal `sector_size()`.
    fn read_sector(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Write `buf` to sector `lba`. `buf.len()` must equal `sector_size()`.
    fn write_sector(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Flush all pending writes to stable storage.
    fn sync(&mut self) -> Result<(), BlockError>;
}

/// A file-backed block device. The file must be sized to an integer
/// multiple of `sector_size` (typically 512 bytes). On creation we
/// `ftruncate`/`seek` to the requested total size, which is useful for
/// spinning up a fresh container.
pub struct FileBackedDevice {
    file: File,
    path: PathBuf,
    sector_size: usize,
    sector_count: u64,
}

impl FileBackedDevice {
    /// Open an existing file as a block device. The file must already
    /// be sized; we don't resize on open.
    pub fn open<P: AsRef<Path>>(path: P, sector_size: usize) -> Result<Self, BlockError> {
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let len = file.metadata()?.len();
        if len % sector_size as u64 != 0 {
            return Err(BlockError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("file size {len} is not a multiple of sector size {sector_size}"),
            )));
        }
        Ok(Self {
            file,
            path: path.as_ref().to_path_buf(),
            sector_size,
            sector_count: len / sector_size as u64,
        })
    }

    /// Create a new container file of the requested total size and
    /// open it as a block device. The file is pre-allocated and zeroed
    /// (the zeroing is best-effort; SSDs may compress).
    pub fn create<P: AsRef<Path>>(
        path: P,
        sector_size: usize,
        total_size: u64,
    ) -> Result<Self, BlockError> {
        if total_size % sector_size as u64 != 0 {
            return Err(BlockError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("total_size {total_size} is not a multiple of sector size {sector_size}"),
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let mut file = file;
        file.set_len(total_size)?;
        // Pre-zero so XTS doesn't have a non-zero plaintext lying around.
        let zeros = vec![0u8; sector_size];
        let mut written = 0u64;
        while written < total_size {
            file.write_all(&zeros)?;
            written += sector_size as u64;
        }
        file.sync_all()?;
        Ok(Self {
            file,
            path: path.as_ref().to_path_buf(),
            sector_size,
            sector_count: total_size / sector_size as u64,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl BlockDevice for FileBackedDevice {
    fn sector_size(&self) -> usize {
        self.sector_size
    }
    fn sector_count(&self) -> u64 {
        self.sector_count
    }
    fn read_sector(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        if lba >= self.sector_count {
            return Err(BlockError::OutOfRange {
                sector: lba,
                total: self.sector_count,
            });
        }
        if buf.len() != self.sector_size {
            return Err(BlockError::SectorSize {
                device: self.sector_size,
                request: buf.len(),
            });
        }
        let offset = lba * self.sector_size as u64;
        // We need a mut file handle. Re-open for read with mut access.
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)?;
        Ok(())
    }
    fn write_sector(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if lba >= self.sector_count {
            return Err(BlockError::OutOfRange {
                sector: lba,
                total: self.sector_count,
            });
        }
        if buf.len() != self.sector_size {
            return Err(BlockError::SectorSize {
                device: self.sector_size,
                request: buf.len(),
            });
        }
        let offset = lba * self.sector_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }
    fn sync(&mut self) -> Result<(), BlockError> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// `anyhow::Error` glue so the rest of the codebase can use a single
/// error type. We can't impl `From<BlockError> for anyhow::Error`
/// directly because `anyhow` already provides a blanket `From<E>`
/// for any `std::error::Error + Send + Sync + 'static`. Since
/// `BlockError` is derived from `thiserror::Error` it qualifies,
/// and the blanket impl is sufficient. The conversion lives at the
/// call sites via `?`.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn file_backed_device_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("container.bin");
        let mut dev = FileBackedDevice::create(&path, 512, 4096).unwrap();
        assert_eq!(dev.sector_count(), 8);

        let mut buf = vec![0u8; 512];
        dev.read_sector(0, &mut buf).unwrap();
        assert_eq!(buf, vec![0u8; 512]);

        // Write to sector 3, read back.
        let mut payload = vec![0xABu8; 512];
        dev.write_sector(3, &payload).unwrap();
        dev.read_sector(3, &mut buf).unwrap();
        assert_eq!(buf, payload);

        // Out-of-range
        assert!(matches!(
            dev.read_sector(99, &mut buf),
            Err(BlockError::OutOfRange { .. })
        ));
    }

    #[test]
    fn file_backed_device_rejects_misaligned_size() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        std::fs::write(&path, vec![0u8; 100]).unwrap();
        // 100 bytes is not a multiple of 512.
        let r = FileBackedDevice::open(&path, 512);
        assert!(r.is_err());
    }
}
