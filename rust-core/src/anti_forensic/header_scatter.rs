//! D-9: Steganographic Header Scattering (SHS)
//!
//! The volume header (normally at a fixed location like LBA 0 or LBA 1024)
//! is split into fragments and scattered across random sectors on disk.
//! Only the correct key can compute the location of each fragment.
//!
//! # How it works
//!
//! 1. The volume header (256 bytes) is split into N fragments (default: 16).
//! 2. Each fragment is placed at a random LBA derived from
//!    `BLAKE3("soteria:header-fragment:v1" || key || fragment_index)`.
//! 3. M decoy fragments (default: 16) are placed at other random LBAs.
//! 4. Total fragments on disk: N + M (default: 32). Only N are real.
//! 5. To reconstruct the header, you need the key AND the knowledge that
//!    only fragments 0..N are real.
//!
//! # Forensic impact
//!
//! - Standard tools look at LBA 0, LBA 1024, etc. for volume headers.
//!   They find nothing (or decoy data).
//! - Even with a complete disk image, the header fragments are
//!   indistinguishable from random noise among the 32 candidates.
//! - Without the key, an attacker must try all C(32,16) combinations
//!   ≈ 601 million possibilities, each requiring a BLAKE3 computation.

use blake3;

/// Number of real header fragments.
pub const REAL_FRAGMENTS: usize = 16;

/// Number of decoy fragments.
pub const DECOY_FRAGMENTS: usize = 16;

/// Total fragments on disk.
pub const TOTAL_FRAGMENTS: usize = REAL_FRAGMENTS + DECOY_FRAGMENTS;

/// Size of each fragment in bytes (256 bytes / 16 fragments = 16 bytes each).
pub const FRAGMENT_SIZE: usize = 16;

/// Domain separator for fragment location derivation.
const DOMAIN: &[u8] = b"soteria:header-fragment:v1";

/// Domain separator for decoy fragment derivation.
const DECOY_DOMAIN: &[u8] = b"soteria:header-decoy:v1";

/// Compute the LBA where fragment `index` should be stored.
/// Works for both real and decoy fragments (different domain).
pub fn fragment_lba(key: &[u8; 32], index: usize, max_lba: u64, is_decoy: bool) -> u64 {
    let domain = if is_decoy { DECOY_DOMAIN } else { DOMAIN };
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(key);
    hasher.update(&index.to_le_bytes());
    let hash = hasher.finalize();
    let raw = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
    // Avoid LBA 0 (MBR) and ensure within bounds.
    (raw % (max_lba.saturating_sub(1))) + 1
}

/// Split a 256-byte header into 16 fragments.
pub fn split_header(header: &[u8; 256]) -> [[u8; FRAGMENT_SIZE]; REAL_FRAGMENTS] {
    let mut fragments = [[0u8; FRAGMENT_SIZE]; REAL_FRAGMENTS];
    for i in 0..REAL_FRAGMENTS {
        fragments[i].copy_from_slice(&header[i * FRAGMENT_SIZE..(i + 1) * FRAGMENT_SIZE]);
    }
    fragments
}

/// Reconstruct a 256-byte header from 16 fragments.
pub fn reassemble_header(fragments: &[[u8; FRAGMENT_SIZE]; REAL_FRAGMENTS]) -> [u8; 256] {
    let mut header = [0u8; 256];
    for i in 0..REAL_FRAGMENTS {
        header[i * FRAGMENT_SIZE..(i + 1) * FRAGMENT_SIZE].copy_from_slice(&fragments[i]);
    }
    header
}

/// Generate decoy fragment data that is indistinguishable from real fragments.
/// Uses a different domain separator so decoys don't collide with real fragments.
pub fn generate_decoy_fragment(key: &[u8; 32], index: usize) -> [u8; FRAGMENT_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DECOY_DOMAIN);
    hasher.update(key);
    hasher.update(&index.to_le_bytes());
    hasher.update(b"decoy");
    let hash = hasher.finalize();
    let mut fragment = [0u8; FRAGMENT_SIZE];
    fragment.copy_from_slice(&hash.as_bytes()[..FRAGMENT_SIZE]);
    fragment
}

/// A scattered header with fragment locations and data.
pub struct ScatteredHeader {
    /// Fragment index -> (LBA, data, is_real).
    pub fragments: Vec<ScatteredFragment>,
}

pub struct ScatteredFragment {
    pub lba: u64,
    pub data: [u8; FRAGMENT_SIZE],
    pub is_real: bool,
}

/// Create a scattered header from a 256-byte header and a key.
pub fn scatter_header(header: &[u8; 256], key: &[u8; 32], max_lba: u64) -> ScatteredHeader {
    let real_fragments = split_header(header);
    let mut fragments = Vec::with_capacity(TOTAL_FRAGMENTS);

    // Real fragments
    for (i, data) in real_fragments.iter().enumerate() {
        fragments.push(ScatteredFragment {
            lba: fragment_lba(key, i, max_lba, false),
            data: *data,
            is_real: true,
        });
    }

    // Decoy fragments
    for i in 0..DECOY_FRAGMENTS {
        fragments.push(ScatteredFragment {
            lba: fragment_lba(key, i, max_lba, true),
            data: generate_decoy_fragment(key, i),
            is_real: false,
        });
    }

    ScatteredHeader { fragments }
}

/// Reconstruct a header from scattered fragments on disk.
/// The `read_fn` is called with each fragment's LBA to read its data.
/// Returns the reconstructed header if all real fragments are found.
pub fn reconstruct_header<F>(key: &[u8; 32], max_lba: u64, read_fn: F) -> crate::Result<[u8; 256]>
where
    F: Fn(u64) -> crate::Result<[u8; FRAGMENT_SIZE]>,
{
    let mut fragments = [[0u8; FRAGMENT_SIZE]; REAL_FRAGMENTS];
    for i in 0..REAL_FRAGMENTS {
        let lba = fragment_lba(key, i, max_lba, false);
        fragments[i] = read_fn(lba)?;
    }
    Ok(reassemble_header(&fragments))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reassemble_roundtrip() {
        let mut header = [0u8; 256];
        for i in 0..256 {
            header[i] = i as u8;
        }
        let fragments = split_header(&header);
        let reassembled = reassemble_header(&fragments);
        assert_eq!(header, reassembled);
    }

    #[test]
    fn fragment_lba_is_within_bounds() {
        let key = [0x42u8; 32];
        let max_lba = 1_000_000;
        for i in 0..TOTAL_FRAGMENTS {
            let lba = fragment_lba(&key, i, max_lba, false);
            assert!(lba > 0 && lba < max_lba, "LBA {lba} out of bounds");
        }
    }

    #[test]
    fn fragment_lba_differs_by_index() {
        let key = [0x42u8; 32];
        let max_lba = 1_000_000;
        let lba0 = fragment_lba(&key, 0, max_lba, false);
        let lba1 = fragment_lba(&key, 1, max_lba, false);
        assert_ne!(lba0, lba1);
    }

    #[test]
    fn real_and_decoy_lbas_differ() {
        let key = [0x42u8; 32];
        let max_lba = 1_000_000;
        let real_lba = fragment_lba(&key, 0, max_lba, false);
        let decoy_lba = fragment_lba(&key, 0, max_lba, true);
        assert_ne!(real_lba, decoy_lba);
    }

    #[test]
    fn scatter_and_reconstruct_roundtrip() {
        let mut header = [0u8; 256];
        for i in 0..256 {
            header[i] = (i * 3) as u8;
        }
        let key = [0x42u8; 32];
        let max_lba = 10_000;

        let scattered = scatter_header(&header, &key, max_lba);
        assert_eq!(scattered.fragments.len(), TOTAL_FRAGMENTS);

        // Build a fake disk from scattered fragments.
        let mut disk: std::collections::HashMap<u64, [u8; FRAGMENT_SIZE]> =
            std::collections::HashMap::new();
        for frag in &scattered.fragments {
            disk.insert(frag.lba, frag.data);
        }

        // Reconstruct using only real fragment locations.
        let reconstructed = reconstruct_header(&key, max_lba, |lba| {
            disk.get(&lba)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("fragment not found at LBA {lba}"))
        })
        .unwrap();

        assert_eq!(header, reconstructed);
    }

    #[test]
    fn decoy_fragment_is_deterministic() {
        let key = [0x42u8; 32];
        let d1 = generate_decoy_fragment(&key, 0);
        let d2 = generate_decoy_fragment(&key, 0);
        assert_eq!(d1, d2);
    }
}
