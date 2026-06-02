use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Nonce96(pub [u8; 12]);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Nonce192(pub [u8; 24]);

impl Nonce96 {
    pub fn random() -> Self {
        let mut n = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut n);
        Self(n)
    }

    /// Derive a deterministic nonce from key + AAD.
    /// Nonce = BLAKE3(keyed_hash(key, aad))[..12].
    /// Safe because each block has unique AAD (block_index || lineage_prev).
    pub fn derive(key: &[u8; 32], aad: &[u8]) -> Self {
        let hash = blake3::keyed_hash(key, aad);
        let mut n = [0u8; 12];
        n.copy_from_slice(&hash.as_bytes()[..12]);
        Self(n)
    }
}

impl Nonce192 {
    pub fn random() -> Self {
        let mut n = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut n);
        Self(n)
    }

    /// Derive a deterministic nonce from key + AAD.
    pub fn derive(key: &[u8; 32], aad: &[u8]) -> Self {
        let hash = blake3::keyed_hash(key, aad);
        let mut n = [0u8; 24];
        n.copy_from_slice(&hash.as_bytes()[..24]);
        Self(n)
    }
}
