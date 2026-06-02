use blake3::Hash;
use serde::{Deserialize, Serialize};

/// Static canary value embedded in protected regions. The bytes are a known
/// marker; the hash binds them to the protection policy. Real canaries should
/// be unique per deployment.
pub const CANARY_MARKER: &[u8; 17] = b"SOTERIA::CANARY::";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CanaryToken {
    pub region_id: String,
    pub marker_hash: String,
    pub enabled: bool,
}

impl CanaryToken {
    pub fn new(region_id: impl Into<String>) -> Self {
        let region_id: String = region_id.into();
        let material = [CANARY_MARKER.as_slice(), region_id.as_bytes()].concat();
        Self {
            region_id,
            marker_hash: blake3::hash(&material).to_hex().to_string(),
            enabled: true,
        }
    }

    /// Verify that an observed byte slice still contains the unmodified canary
    /// marker and that the region identifier is the one the token was bound to.
    pub fn verify(&self, region_id: &str, observed: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        if region_id != self.region_id {
            return false;
        }
        observed
            .windows(CANARY_MARKER.len())
            .any(|w| w == CANARY_MARKER)
    }

    /// Compute the deterministic hash of the canary marker plus the region's
    /// identifier. Used to bind decoy metadata to the canary token.
    pub fn region_hash(&self) -> Hash {
        blake3::hash(self.region_id.as_bytes())
    }
}
