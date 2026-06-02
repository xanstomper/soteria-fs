//! D-8: Timestamp Virtualization (Linear Time Paradox)
//!
//! File timestamps returned by the virtual filesystem are randomized
//! per-mount. Two mounts of the same volume show completely different
//! timestamps. This defeats forensic timeline analysis.
//!
//! # How it works
//!
//! 1. On mount, a random "time warp" seed is generated.
//! 2. For each file, timestamps are derived from
//!    `BLAKE3("soteria:timestamp:v1" || warp_seed || file_id)`.
//! 3. The derived value is mapped to a plausible timestamp range
//!    (within the last 5 years).
//! 4. Different mounts → different warp seeds → different timestamps.
//!
//! # Forensic impact
//!
//! - Two forensic images of the same volume show different timestamps.
//! - Timeline analysis is impossible — timestamps are random per mount.
//! - `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps don't correlate.
//! - File "creation dates" are plausible but fictional.

use blake3;

/// A time warp seed generated on each mount.
pub type WarpSeed = [u8; 32];

/// Generate a new random warp seed for this mount.
pub fn generate_warp_seed() -> WarpSeed {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Derive a virtualized timestamp for a file.
/// Returns seconds since epoch, mapped to a plausible range.
pub fn virtualize_timestamp(warp_seed: &WarpSeed, file_id: &[u8; 32], field: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria:timestamp:v1");
    hasher.update(warp_seed);
    hasher.update(file_id);
    hasher.update(field.as_bytes());
    let hash = hasher.finalize();

    let raw = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());

    // Map to a plausible range: last 5 years.
    let five_years_secs = 5 * 365 * 24 * 3600;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Random offset within the last 5 years.
    let offset = raw % five_years_secs;
    now.saturating_sub(offset)
}

/// Derive all standard filesystem timestamps for a file.
pub struct VirtualTimestamps {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub changed: u64,
}

pub fn virtualize_all_timestamps(warp_seed: &WarpSeed, file_id: &[u8; 32]) -> VirtualTimestamps {
    VirtualTimestamps {
        created: virtualize_timestamp(warp_seed, file_id, "created"),
        modified: virtualize_timestamp(warp_seed, file_id, "modified"),
        accessed: virtualize_timestamp(warp_seed, file_id, "accessed"),
        changed: virtualize_timestamp(warp_seed, file_id, "changed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warp_seed_is_32_bytes() {
        let seed = generate_warp_seed();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn virtualize_is_deterministic_per_seed() {
        let seed = [0x42u8; 32];
        let file_id = [0x01u8; 32];
        let t1 = virtualize_timestamp(&seed, &file_id, "created");
        let t2 = virtualize_timestamp(&seed, &file_id, "created");
        assert_eq!(t1, t2);
    }

    #[test]
    fn virtualize_differs_by_seed() {
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        let file_id = [0x01u8; 32];
        let t1 = virtualize_timestamp(&seed1, &file_id, "created");
        let t2 = virtualize_timestamp(&seed2, &file_id, "created");
        assert_ne!(t1, t2);
    }

    #[test]
    fn virtualize_differs_by_file() {
        let seed = [0x42u8; 32];
        let f1 = [0x01u8; 32];
        let f2 = [0x02u8; 32];
        let t1 = virtualize_timestamp(&seed, &f1, "created");
        let t2 = virtualize_timestamp(&seed, &f2, "created");
        assert_ne!(t1, t2);
    }

    #[test]
    fn virtualize_is_plausible() {
        let seed = generate_warp_seed();
        let file_id = [0x01u8; 32];
        let ts = virtualize_timestamp(&seed, &file_id, "created");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Should be within the last 5 years.
        assert!(ts <= now);
        assert!(ts > now - 5 * 365 * 24 * 3600);
    }

    #[test]
    fn virtualize_all_timestamps_returns_four_fields() {
        let seed = generate_warp_seed();
        let file_id = [0x01u8; 32];
        let ts = virtualize_all_timestamps(&seed, &file_id);
        assert!(ts.created > 0);
        assert!(ts.modified > 0);
        assert!(ts.accessed > 0);
        assert!(ts.changed > 0);
    }
}
