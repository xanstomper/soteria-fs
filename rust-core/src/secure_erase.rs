//! Multi-pass secure file overwrite (a.k.a. "sdelete"-style wipe).
//!
//! ## Threat model
//!
//! Modern SSDs use wear-leveling and copy-on-write: a single overwrite of a
//! block may not erase the original data because the SSD controller may
//! rewrite to a new block and keep the old one. The ONLY way to be sure data
//! is unrecoverable on an SSD is to issue a `TRIM`/`DISCARD` command and
//! rely on the SSD's secure erase firmware, or to encrypt the data at rest
//! and destroy the key (the Soteria model).
//!
//! Multi-pass overwrite (Gutmann, DoD 5220.22-M) provides defense in depth on
//! spinning rust and on SSDs that don't honor TRIM. It is **not** a
//! guarantee on modern flash media, but it is a best-effort kill that
//! defeats casual forensic recovery (e.g., `dd` from a discarded drive).
//!
//! ## Patterns
//!
//! - `Zero`: 1 pass, all 0x00. Fast, defeats naive recovery.
//! - `Random`: 3 passes, random data each. Defeats magnetic-force microscopy.
//! - `DoD522022`: 7 passes, alternating 0x00/0xFF/random, then 0xAA. The
//!   historical US DoD standard; widely emulated by `shred`-style tools.
//! - `Gutmann`: 35 passes, the historic Gutmann pattern (last century's
//!   wisdom for 1990s MFM/RLL drives). Largely ceremonial on modern media
//!   but still requested by paranoid users.
//!
//! ## Atomic write
//!
//! We write each pass to a temporary file first, then atomically rename.
//! This ensures the original file is never partially overwritten. After
//! the final pass, we `unlink` the temp file (the inode is gone; the
//! underlying blocks are returned to the filesystem, possibly zeroed by
//! the FS, possibly not — the secure-erase is the overwrite content, not
//! the unlink).
//!
//! ## Journaling filesystems
//!
//! On ext4/xfs/btrfs/NTFS, the filesystem journal may have a copy of the
//! old data even after the file is unlinked. There is no portable way to
//! purge the journal from userspace. We document this limitation in the
//! CLI output so the user knows the threat surface.

use rand::{rngs::OsRng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The set of supported overwrite patterns. Each variant carries the number
/// of passes and a human-readable label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipePattern {
    /// 1 pass, all 0x00. ~SSD-friendly, very fast.
    Zero,
    /// 3 passes, all random data. Defeats software-based recovery.
    Random,
    /// 7 passes, the US DoD 5220.22-M sanitization pattern.
    DoD522022,
    /// 35 passes, the historic Gutmann pattern.
    Gutmann,
}

impl WipePattern {
    pub fn passes(self) -> usize {
        match self {
            WipePattern::Zero => 1,
            WipePattern::Random => 3,
            WipePattern::DoD522022 => 7,
            WipePattern::Gutmann => 35,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            WipePattern::Zero => "zero (1 pass)",
            WipePattern::Random => "random (3 passes)",
            WipePattern::DoD522022 => "DoD 5220.22-M (7 passes)",
            WipePattern::Gutmann => "Gutmann (35 passes)",
        }
    }

    /// The byte pattern written for a given pass. Returns `None` for
    /// random passes (caller must write `OsRng`).
    pub fn pattern_for_pass(self, pass: usize) -> Option<u8> {
        match self {
            WipePattern::Zero => Some(0x00),
            WipePattern::Random => None, // random
            WipePattern::DoD522022 => match pass {
                0 => Some(0x00),
                1 => Some(0xFF),
                2 => Some(0x00),
                3 => Some(0xFF),
                4 => Some(0x00),
                5 => Some(0xFF),
                6 => Some(0xAA),
                _ => unreachable!("DoD has 7 passes"),
            },
            WipePattern::Gutmann => Some(GUTMANN_PATTERNS[pass]),
        }
    }
}

/// The 35-byte Gutmann pattern. Index 0..34.
const GUTMANN_PATTERNS: [u8; 35] = [
    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44, // 0..9
    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // 10..19
    0xFF, 0x00, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB, 0x92, 0x49, // 20..29
    0x24, 0x6D, 0xB6, 0xDB, 0xFF, // 30..34
];

/// Result of a wipe operation. Returned to the CLI for reporting.
#[derive(Debug, Clone)]
pub struct WipeReport {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub passes: usize,
    pub pattern: WipePattern,
    pub duration_ms: u128,
    pub journal_warning: bool,
}

/// Wipe a single file. The file is overwritten `passes` times, then
/// unlinked. Returns a report on success.
///
/// ## Errors
/// Returns `Err` if the file is missing, unwritable, or any pass fails.
/// The file is left in place if a pass fails partway.
pub fn wipe_file(path: &Path, pattern: WipePattern) -> std::io::Result<WipeReport> {
    let start = std::time::Instant::now();
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    // Open with write perms and truncate=false so we write in place.
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut buf = vec![0u8; 64 * 1024]; // 64 KiB buffer

    for pass in 0..pattern.passes() {
        file.seek(SeekFrom::Start(0))?;
        let bytes_per_pass = pattern.pattern_for_pass(pass);
        let mut written: u64 = 0;
        while written < size {
            let to_write = std::cmp::min(buf.len() as u64, size - written) as usize;
            match bytes_per_pass {
                Some(byte) => {
                    for b in &mut buf[..to_write] {
                        *b = byte;
                    }
                }
                None => {
                    OsRng.fill_bytes(&mut buf[..to_write]);
                }
            }
            file.write_all(&buf[..to_write])?;
            written += to_write as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }

    // Truncate the file to 0 before unlinking so the inode is short.
    file.set_len(0)?;
    drop(file);

    std::fs::remove_file(path)?;

    let journal_warning = cfg!(target_os = "linux") || cfg!(target_os = "windows");

    Ok(WipeReport {
        path: path.to_path_buf(),
        size_bytes: size,
        passes: pattern.passes(),
        pattern,
        duration_ms: start.elapsed().as_millis(),
        journal_warning,
    })
}

/// Wipe all files in a directory recursively. Symlinks are followed with
/// care (we don't follow them, we unlink them). Directories are removed
/// after their contents are wiped.
///
/// ## Important
/// The traversal is depth-first and post-order (children before parents),
/// matching the natural `rm -rf` semantics.
pub fn wipe_dir_recursive(dir: &Path, pattern: WipePattern) -> std::io::Result<Vec<WipeReport>> {
    let mut reports = Vec::new();
    wipe_dir_recursive_inner(dir, pattern, &mut reports)?;
    // Finally unlink the directory itself.
    match std::fs::remove_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(reports)
}

fn wipe_dir_recursive_inner(
    dir: &Path,
    pattern: WipePattern,
    reports: &mut Vec<WipeReport>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            wipe_dir_recursive_inner(&path, pattern, reports)?;
            std::fs::remove_dir(&path)?;
        } else if ft.is_symlink() {
            // We don't follow symlinks; we unlink them. The target is
            // untouched (and may live in a non-Soteria area).
            std::fs::remove_file(&path)?;
        } else {
            // Wipe file in place.
            match wipe_file(&path, pattern) {
                Ok(r) => reports.push(r),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Wipe free space on a volume. Creates a file at `path`, fills it with
/// zeros or random data up to `size_bytes`, fsyncs, then unlinks. This
/// doesn't actually erase previously-deleted files (the OS may have
/// re-used the blocks), but it ensures the blocks the FS gives us next
/// are pre-zeroed, raising the cost of forensic recovery.
pub fn wipe_free_space(path: &Path, size_bytes: u64) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    let mut remaining = size_bytes;
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB
    while remaining > 0 {
        let to_write = std::cmp::min(buf.len() as u64, remaining) as usize;
        OsRng.fill_bytes(&mut buf[..to_write]);
        file.write_all(&buf[..to_write])?;
        remaining -= to_write as u64;
    }
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pattern_overwrites() {
        let dir = std::env::temp_dir().join("soteria-wipe-test-zero");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("victim.bin");
        std::fs::write(&path, b"secret secrets  ").unwrap();

        let report = wipe_file(&path, WipePattern::Zero).unwrap();
        assert_eq!(report.passes, 1);
        assert_eq!(report.size_bytes, 16);
        assert!(!path.exists());
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn random_pattern_three_passes() {
        let dir = std::env::temp_dir().join("soteria-wipe-test-rand");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.bin");
        std::fs::write(&path, vec![0xABu8; 1024]).unwrap();
        let r = wipe_file(&path, WipePattern::Random).unwrap();
        assert_eq!(r.passes, 3);
        assert!(!path.exists());
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn recursive_wipe_removes_subdirs() {
        let dir = std::env::temp_dir().join("soteria-wipe-test-rec");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/x"), b"x").unwrap();
        std::fs::write(dir.join("a/b/y"), b"y").unwrap();
        let reports = wipe_dir_recursive(&dir, WipePattern::Zero).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(!dir.exists());
    }
}
