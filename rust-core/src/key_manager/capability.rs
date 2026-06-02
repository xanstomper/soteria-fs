use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityScope {
    pub region_id: String,
    pub path_prefix: PathBuf,
    pub can_read: bool,
    pub can_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub process_id: u32,
    pub scope: CapabilityScope,
    pub issued_at: SystemTime,
    pub ttl_seconds: u64,
    pub token_blake3: String,
}

impl Capability {
    pub fn issue(process_id: u32, scope: CapabilityScope, ttl_seconds: u64) -> Self {
        let issued_at = SystemTime::now();
        let material = format!("{process_id}:{:?}:{ttl_seconds}:{issued_at:?}", scope);
        Self {
            process_id,
            scope,
            issued_at,
            ttl_seconds,
            token_blake3: blake3::hash(material.as_bytes()).to_hex().to_string(),
        }
    }
    pub fn valid(&self) -> bool {
        self.issued_at.elapsed().unwrap_or(Duration::MAX) <= Duration::from_secs(self.ttl_seconds)
    }
}
