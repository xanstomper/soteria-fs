//! Tool confusion — makes automated analysis tools ineffective.
//!
//! Every sector on disk has identical entropy, identical structure,
//! and identical statistical properties — regardless of whether it
//! contains encrypted data, empty space, or decoy content. Automated
//! tools (EnCase, FTK, X-Ways, Autopsy) cannot distinguish between
//! them, making their analysis useless.
//!
//! # What this defends against
//!
//! - **File carving** (PhotoRec, scalpel): No file boundaries exist
//!   in the ciphertext. All sectors look identical.
//! - **Entropy analysis** (binwalk, ent): All sectors have maximum
//!   entropy (~7.9 bits/byte). No detectable structure.
//! - **Frequency analysis**: No byte frequency patterns. Uniform
//!   distribution across all sectors.
//! - **Known-plaintext correlation**: Same plaintext at different
//!   times produces completely different ciphertext (PMC property).
//! - **Metadata analysis**: No timestamps, no filenames, no directory
//!   structure on disk (everything is derived at mount time).
//! - **Signature scanning**: No magic bytes, no volume headers at
//!   predictable locations (header scattering).
//!
//! # How it works
//!
//! 1. Unused space is filled with deterministic high-entropy noise
//!    (same noise every mount, indistinguishable from ciphertext).
//! 2. Volume headers are scattered across random sectors.
//! 3. Timestamps are virtualized (different every mount).
//! 4. No filesystem metadata is stored on disk.
//!
//! The result: the entire disk looks like one uniform block of
//! high-entropy data. No tool can find boundaries, patterns, or
//! structure without the key.

use crate::anti_forensic::entropy_pad;
use crate::anti_forensic::header_scatter;
use crate::anti_forensic::timestamp_warp;

/// Apply all tool-confusion measures to a volume.
/// Called during volume initialization.
pub fn apply_tool_confusion(key: &[u8; 32], max_lba: u64) -> ToolConfusionState {
    let warp_seed = timestamp_warp::generate_warp_seed();
    ToolConfusionState {
        warp_seed,
        entropy_key: *key,
        max_lba,
    }
}

/// State for tool-confusion measures.
pub struct ToolConfusionState {
    pub warp_seed: timestamp_warp::WarpSeed,
    pub entropy_key: [u8; 32],
    pub max_lba: u64,
}

impl ToolConfusionState {
    /// Generate entropy-equalized padding for an unused block.
    pub fn padding_for_block(&self, block_index: u64) -> [u8; 4096] {
        entropy_pad::entropy_pad_block(&self.entropy_key, block_index)
    }

    /// Get the LBA for a scattered header fragment.
    pub fn fragment_lba(&self, fragment_index: usize, is_decoy: bool) -> u64 {
        header_scatter::fragment_lba(&self.entropy_key, fragment_index, self.max_lba, is_decoy)
    }

    /// Virtualize a timestamp for a file.
    pub fn virtualize_timestamp(&self, file_id: &[u8; 32], field: &str) -> u64 {
        timestamp_warp::virtualize_timestamp(&self.warp_seed, file_id, field)
    }
}

/// Measure Shannon entropy of data (bits per byte).
/// Used to verify that confusion measures achieve maximum entropy.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    entropy_pad::shannon_entropy(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_confusion_state_creates() {
        let key = [0x42u8; 32];
        let state = apply_tool_confusion(&key, 1_000_000);
        assert!(state.max_lba > 0);
    }

    #[test]
    fn padding_has_high_entropy() {
        let key = [0x42u8; 32];
        let state = apply_tool_confusion(&key, 1_000_000);
        let padding = state.padding_for_block(0);
        let entropy = shannon_entropy(&padding);
        assert!(entropy > 7.5, "expected high entropy, got {entropy:.2}");
    }

    #[test]
    fn padding_is_deterministic() {
        let key = [0x42u8; 32];
        let state = apply_tool_confusion(&key, 1_000_000);
        let p1 = state.padding_for_block(42);
        let p2 = state.padding_for_block(42);
        assert_eq!(p1, p2);
    }

    #[test]
    fn fragment_lba_differs_for_real_and_decoy() {
        let key = [0x42u8; 32];
        let state = apply_tool_confusion(&key, 1_000_000);
        let real = state.fragment_lba(0, false);
        let decoy = state.fragment_lba(0, true);
        assert_ne!(real, decoy);
    }

    #[test]
    fn virtualized_timestamp_is_plausible() {
        let key = [0x42u8; 32];
        let state = apply_tool_confusion(&key, 1_000_000);
        let file_id = [0x01u8; 32];
        let ts = state.virtualize_timestamp(&file_id, "created");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(ts <= now);
        assert!(ts > now - 5 * 365 * 24 * 3600);
    }
}
