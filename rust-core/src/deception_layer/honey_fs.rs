use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Cryptographically isolated deception surface. The honey filesystem never
/// holds real data; touching it produces high-confidence intrusion signals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoneyFileSystem {
    decoys: BTreeMap<String, HoneyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyEntry {
    pub logical_path: PathBuf,
    pub payload_blake3: String,
    pub canary_bound: bool,
}

impl HoneyEntry {
    pub fn new(logical_path: impl Into<PathBuf>, payload: &[u8], canary_bound: bool) -> Self {
        Self {
            logical_path: logical_path.into(),
            payload_blake3: blake3::hash(payload).to_hex().to_string(),
            canary_bound,
        }
    }
}

impl HoneyFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_decoy(&mut self, name: impl Into<String>, entry: HoneyEntry) {
        self.decoys.insert(name.into(), entry);
    }

    pub fn lookup(&self, name: &str) -> Option<&HoneyEntry> {
        self.decoys.get(name)
    }

    pub fn enumerate(&self) -> Vec<&HoneyEntry> {
        let mut out: Vec<&HoneyEntry> = self.decoys.values().collect();
        out.sort_by(|a, b| a.logical_path.cmp(&b.logical_path));
        out
    }

    pub fn touch(&self, name: &str) -> bool {
        self.decoys.contains_key(name)
    }

    pub fn touch_path(&self, path: &str) -> bool {
        self.decoys
            .values()
            .any(|e| e.logical_path.to_string_lossy() == path)
    }

    pub fn is_canary_bound(&self, name: &str) -> bool {
        self.decoys
            .get(name)
            .map(|e| e.canary_bound)
            .unwrap_or(false)
    }

    /// Create a default seed of believable decoy files. None of these contain
    /// real data; they exist solely to be interacted with by intruders.
    pub fn seed_default(root: &Path) -> Self {
        let mut fs = Self::new();
        let make = |logical: &str, payload: &[u8]| {
            let mut path = root.to_path_buf();
            for seg in logical.split('/').filter(|s| !s.is_empty()) {
                path.push(seg);
            }
            (path, payload.to_vec())
        };
        let (p1, d1) = make("finance/q4_forecast.xlsx", b"DECOY: not a real file");
        let (p2, d2) = make("backups/wallet_2026.dat", b"DECOY: no key material");
        let (p3, d3) = make("hr/employee_records.zip", b"DECOY: synthetic listing");
        fs.add_decoy("q4_forecast", HoneyEntry::new(p1, &d1, true));
        fs.add_decoy("wallet_backup", HoneyEntry::new(p2, &d2, true));
        fs.add_decoy("employee_records", HoneyEntry::new(p3, &d3, true));
        fs
    }
}
