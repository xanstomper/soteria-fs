use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsMetadata {
    pub encrypted_name_blake3: String,
    pub region_id: String,
    pub version_chain_head: String,
}

impl FsMetadata {
    pub fn for_path(path: &Path, region_id: &str, head: &str) -> Self {
        Self {
            encrypted_name_blake3: blake3::hash(path.to_string_lossy().as_bytes())
                .to_hex()
                .to_string(),
            region_id: region_id.into(),
            version_chain_head: head.into(),
        }
    }
}
