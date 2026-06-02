//! D-3: Entropy Deception Layer (EDL)
//!
//! Fills unused/unallocated space with high-entropy noise that is
//! indistinguishable from encrypted data. Forensic tools that analyze
//! sector entropy (EnCase, FTK, X-Ways) see uniform 7.9 bits/byte
//! across the entire volume — no detectable boundaries between used
//! and unused space.
//!
//! # How it works
//!
//! 1. Unused blocks are filled with `BLAKE3(key || block_index)` output.
//!    This is deterministic (same key + index = same noise) so the volume
//!    doesn't change between mounts.
//! 2. The output has maximum entropy (~7.99 bits/byte) and is
//!    indistinguishable from AES-256-GCM ciphertext.
//! 3. No forensic tool can distinguish unused blocks from encrypted blocks
//!    without the key.
//!
//! # Forensic impact
//!
//! - EnCase: "Full disk encryption detected — uniform entropy"
//! - FTK: No carveable file boundaries
//! - X-Ways: No distinguishable free space
//! - Autopsy: All sectors appear as encrypted data

use blake3;

/// Size of a single block in bytes.
pub const BLOCK_SIZE: usize = 4096;

/// Generate deterministic high-entropy noise for a given block index.
/// The noise is derived from `BLAKE3("soteria:entropy-pad:v1" || key || index)`,
/// repeated to fill the block. This is deterministic per (key, index) so
/// the volume looks the same on every mount.
pub fn entropy_pad_block(key: &[u8; 32], block_index: u64) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    let mut offset = 0;
    let mut counter = 0u64;

    while offset < BLOCK_SIZE {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:entropy-pad:v1");
        hasher.update(key);
        hasher.update(&block_index.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();

        let remaining = BLOCK_SIZE - offset;
        let copy_len = remaining.min(32);
        block[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);
        offset += copy_len;
        counter += 1;
    }

    block
}

/// Fill a range of unused blocks with entropy-equalized noise.
/// The caller writes these blocks to disk in the unused regions.
pub fn generate_padding_range(
    key: &[u8; 32],
    start_block: u64,
    count: u64,
) -> Vec<(u64, [u8; BLOCK_SIZE])> {
    (0..count)
        .map(|i| {
            let idx = start_block + i;
            (idx, entropy_pad_block(key, idx))
        })
        .collect()
}

/// Measure Shannon entropy of a byte slice (bits per byte).
/// Returns a value between 0.0 and 8.0.
/// Used to verify that padding achieves maximum entropy.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut histogram = [0u64; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }
    let len = data.len() as f64;
    histogram
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_pad_block_is_correct_size() {
        let key = [0x42u8; 32];
        let block = entropy_pad_block(&key, 0);
        assert_eq!(block.len(), BLOCK_SIZE);
    }

    #[test]
    fn entropy_pad_is_deterministic() {
        let key = [0x42u8; 32];
        let b1 = entropy_pad_block(&key, 42);
        let b2 = entropy_pad_block(&key, 42);
        assert_eq!(b1, b2);
    }

    #[test]
    fn entropy_pad_differs_by_index() {
        let key = [0x42u8; 32];
        let b0 = entropy_pad_block(&key, 0);
        let b1 = entropy_pad_block(&key, 1);
        assert_ne!(b0, b1);
    }

    #[test]
    fn entropy_pad_differs_by_key() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let b1 = entropy_pad_block(&k1, 0);
        let b2 = entropy_pad_block(&k2, 0);
        assert_ne!(b1, b2);
    }

    #[test]
    fn entropy_pad_has_high_entropy() {
        let key = [0x42u8; 32];
        let block = entropy_pad_block(&key, 0);
        let entropy = shannon_entropy(&block);
        // Should be close to 8.0 bits/byte (maximum).
        assert!(
            entropy > 7.5,
            "expected high entropy, got {entropy:.2} bits/byte"
        );
    }

    #[test]
    fn generate_padding_range_returns_correct_count() {
        let key = [0x42u8; 32];
        let pads = generate_padding_range(&key, 100, 5);
        assert_eq!(pads.len(), 5);
        assert_eq!(pads[0].0, 100);
        assert_eq!(pads[4].0, 104);
    }

    #[test]
    fn shannon_entropy_of_zeros_is_zero() {
        let data = [0u8; 1024];
        let entropy = shannon_entropy(&data);
        assert!(entropy < 0.01, "expected ~0, got {entropy:.4}");
    }

    #[test]
    fn shannon_entropy_of_random_is_high() {
        use rand::RngCore;
        let mut data = [0u8; 4096];
        rand::rngs::OsRng.fill_bytes(&mut data);
        let entropy = shannon_entropy(&data);
        assert!(entropy > 7.5, "expected high entropy, got {entropy:.2}");
    }
}
