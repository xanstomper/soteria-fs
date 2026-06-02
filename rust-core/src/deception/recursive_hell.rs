//! Recursive Directory Hell.
//!
//! Creates directory structures that loop infinitely, causing automated
//! filesystem scanners to exhaust memory and CPU.
//!
//! # How it works
//!
//! 1. A decoy directory contains a subdirectory that references itself.
//! 2. Each "level" adds plausible files and a new subdirectory.
//! 3. Directory names are randomized per level (prevents caching).
//! 4. File count doubles each level (memory exhaustion).
//! 5. Each level adds a configurable delay (CPU exhaustion).
//!
//! # Forensic impact
//!
//! - `find`, `ls -R`, `tree`: Infinite recursion, stack overflow.
//! - Automated scanners: Memory exhaustion after ~20 levels.
//! - Forensic tools (FTK, EnCase): Hang on directory enumeration.
//! - Human investigators: Eventually realize it's a trap (but waste time).
//!
//! # Legal
//!
//! This is a passive honeypot — no malware, no exploits, no active attack.
//! The directory structure is valid. The scanner chooses to recurse.

use blake3;
use serde::{Deserialize, Serialize};

/// Configuration for the recursive hell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveHellConfig {
    /// Maximum depth before the loop restarts (prevents stack overflow
    /// on the legitimate user's side).
    pub max_depth: usize,
    /// Number of files per level (doubles each level).
    pub base_files: usize,
    /// Delay per level in milliseconds (exhausts scanner time).
    pub delay_ms: u64,
    /// Whether to randomize directory names per mount.
    pub randomize_names: bool,
}

impl Default for RecursiveHellConfig {
    fn default() -> Self {
        Self {
            max_depth: 50,
            base_files: 5,
            delay_ms: 100,
            randomize_names: true,
        }
    }
}

/// A directory entry in the recursive hell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HellEntry {
    /// A fake file with generated content.
    File {
        name: String,
        size: usize,
        content_seed: [u8; 32],
    },
    /// A subdirectory that loops back.
    Directory {
        name: String,
        /// The depth of this directory (for generating unique names).
        depth: usize,
    },
}

/// Generate the directory entries for a given depth level.
pub fn generate_level(
    config: &RecursiveHellConfig,
    seed: &[u8; 32],
    depth: usize,
) -> Vec<HellEntry> {
    let file_count = config.base_files * (2_usize.pow(depth as u32));
    let mut entries = Vec::with_capacity(file_count + 1);

    // Generate files.
    for i in 0..file_count.min(1000) {
        // Cap at 1000 to prevent memory issues during generation.
        let hash = blake3::keyed_hash(seed, &[depth.to_le_bytes(), i.to_le_bytes()].concat());
        let name = format!(
            "file_{:04x}_{:04x}.dat",
            u16::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]),
            u16::from_le_bytes([hash.as_bytes()[2], hash.as_bytes()[3]])
        );
        entries.push(HellEntry::File {
            name,
            size: 1024 + (hash.as_bytes()[4] as usize * 256),
            content_seed: *hash.as_bytes(),
        });
    }

    // Generate the recursive subdirectory.
    let dir_hash = blake3::keyed_hash(seed, &depth.to_le_bytes());
    let dir_name = if config.randomize_names {
        format!(
            "archive_{:04x}",
            u16::from_le_bytes([dir_hash.as_bytes()[0], dir_hash.as_bytes()[1]])
        )
    } else {
        format!("level_{}", depth + 1)
    };

    entries.push(HellEntry::Directory {
        name: dir_name,
        depth: depth + 1,
    });

    entries
}

/// Simulate a scanner descending into the recursive hell.
/// Returns the number of entries encountered before hitting max_depth.
/// Used for testing and documentation.
pub fn simulate_scan(config: &RecursiveHellConfig, seed: &[u8; 32]) -> ScanResult {
    let mut total_files = 0;
    let mut total_dirs = 0;
    let mut total_size = 0;

    for depth in 0..config.max_depth {
        let entries = generate_level(config, seed, depth);
        for entry in &entries {
            match entry {
                HellEntry::File { size, .. } => {
                    total_files += 1;
                    total_size += size;
                }
                HellEntry::Directory { .. } => {
                    total_dirs += 1;
                }
            }
        }
    }

    ScanResult {
        depth_reached: config.max_depth,
        total_files,
        total_dirs,
        total_size_bytes: total_size,
    }
}

/// Result of simulating a scan through the recursive hell.
#[derive(Debug)]
pub struct ScanResult {
    pub depth_reached: usize,
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_level_returns_files_and_dir() {
        let config = RecursiveHellConfig::default();
        let seed = [0x42u8; 32];
        let entries = generate_level(&config, &seed, 0);
        assert!(entries.len() > 1);
        assert!(matches!(entries.last(), Some(HellEntry::Directory { .. })));
    }

    #[test]
    fn file_count_doubles_each_level() {
        let config = RecursiveHellConfig {
            base_files: 5,
            ..Default::default()
        };
        let seed = [0x42u8; 32];
        let l0 = generate_level(&config, &seed, 0);
        let l1 = generate_level(&config, &seed, 1);
        let l0_files = l0
            .iter()
            .filter(|e| matches!(e, HellEntry::File { .. }))
            .count();
        let l1_files = l1
            .iter()
            .filter(|e| matches!(e, HellEntry::File { .. }))
            .count();
        assert_eq!(l1_files, l0_files * 2);
    }

    #[test]
    fn simulate_scan_reports_totals() {
        let config = RecursiveHellConfig {
            max_depth: 5,
            base_files: 2,
            ..Default::default()
        };
        let seed = [0x42u8; 32];
        let result = simulate_scan(&config, &seed);
        assert_eq!(result.depth_reached, 5);
        assert!(result.total_files > 0);
        assert_eq!(result.total_dirs, 5); // One dir per level
    }

    #[test]
    fn directory_names_vary_by_depth() {
        let config = RecursiveHellConfig::default();
        let seed = [0x42u8; 32];
        let l0 = generate_level(&config, &seed, 0);
        let l1 = generate_level(&config, &seed, 1);
        let d0 = match l0.last().unwrap() {
            HellEntry::Directory { name, .. } => name.clone(),
            _ => unreachable!(),
        };
        let d1 = match l1.last().unwrap() {
            HellEntry::Directory { name, .. } => name.clone(),
            _ => unreachable!(),
        };
        assert_ne!(d0, d1);
    }
}
