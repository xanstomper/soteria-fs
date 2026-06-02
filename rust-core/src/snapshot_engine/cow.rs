use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub id: String,
    pub source: PathBuf,
    pub blake3: String,
}

pub fn snapshot_file(root: &Path, source: &Path) -> crate::Result<SnapshotManifest> {
    std::fs::create_dir_all(root)?;
    let data = std::fs::read(source)?;
    let hash = blake3::hash(&data).to_hex().to_string();
    let id = hash[..16].to_string();
    std::fs::write(root.join(&id), data)?;
    Ok(SnapshotManifest {
        id,
        source: source.into(),
        blake3: hash,
    })
}
