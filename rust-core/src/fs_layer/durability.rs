//! Cross-platform durability helpers.
//!
//! ## `fsync_dir`
//!
//! On POSIX filesystems, renaming or creating a file only updates the
//! directory entry in memory; the directory inode (and therefore the
//! existence of the file) is not durable until the directory itself is
//! `fsync`ed. Without this step, a crash between the rename and a power
//! loss can lose the new file even though its contents and inode are
//! already on disk.
//!
//! On Windows (NTFS), directory entry durability is handled differently:
//! `FlushFileBuffers` on the file handle is generally sufficient. Opening a
//! directory and calling `sync_all` either returns an error or is a no-op,
//! so this helper is best-effort: it never errors, and callers should treat
//! the absence of an error as "durable on POSIX" and "best effort on
//! Windows".
//!
//! This pattern is used at every atomic-rename boundary in the storage,
//! WAL, share-file, and KDF sidecar writers.

use std::path::Path;

/// Open the parent directory at `path` (if any) and `fsync` it.
///
/// Best-effort: any I/O error is silently ignored. Callers should not rely
/// on this for correctness on Windows; on POSIX it is required for
/// crash-safety after an atomic rename.
pub fn fsync_dir(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    if parent.as_os_str().is_empty() {
        return;
    }
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn fsync_dir_on_existing_dir_does_not_panic() {
        let tmp = std::env::temp_dir().join(format!(
            "soteria-fsync-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let probe = tmp.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        fsync_dir(&probe);
        // Cleanup.
        let _ = std::fs::remove_file(&probe);
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn fsync_dir_on_root_path_is_noop() {
        fsync_dir(&PathBuf::from("/"));
        fsync_dir(&PathBuf::from(""));
    }

    #[test]
    fn fsync_dir_on_missing_path_does_not_panic() {
        let missing = PathBuf::from("C:/this/path/should/not/exist/anywhere/fsync-probe");
        fsync_dir(&missing);
    }
}
