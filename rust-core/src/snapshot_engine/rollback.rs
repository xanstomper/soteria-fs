use super::cow::SnapshotManifest;
use std::path::Path;

pub fn rollback(root: &Path, manifest: &SnapshotManifest) -> crate::Result<()> {
    let data = std::fs::read(root.join(&manifest.id))?;
    anyhow::ensure!(
        blake3::hash(&data).to_hex().to_string() == manifest.blake3,
        "snapshot integrity check failed"
    );
    std::fs::write(&manifest.source, data)?;
    Ok(())
}
