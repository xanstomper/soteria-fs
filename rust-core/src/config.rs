use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoteriaConfig {
    pub crypto: CryptoConfig,
    pub key_lifecycle: KeyLifecycleConfig,
    pub event_bus: EventBusConfig,
    pub response: ResponseConfig,
    pub snapshot: SnapshotConfig,
    pub ai_observer: AiObserverConfig,
    pub deception: DeceptionConfig,
    #[serde(default)]
    pub fuse: FuseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub algorithm: String,
    pub block_size: usize,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycleConfig {
    pub session_ttl_seconds: u64,
    pub ratchet_every_events: u64,
    pub enforce_zeroize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBusConfig {
    pub append_only_log: PathBuf,
    pub chain_events_with_blake3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub entropy_spike_threshold: f64,
    pub write_rate_threshold_per_minute: u32,
    pub rename_rate_threshold_per_minute: u32,
    pub allowed_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    pub root: PathBuf,
    pub cow_enabled: bool,
    pub verify_blake3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiObserverConfig {
    pub enabled: bool,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionConfig {
    pub enabled: bool,
    pub decoy_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseConfig {
    /// Seconds between write-back cache flushes. Default: 30.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    /// Read cache size in MB. Default: 64.
    #[serde(default = "default_read_cache_mb")]
    pub read_cache_mb: usize,
}

impl Default for FuseConfig {
    fn default() -> Self {
        Self {
            flush_interval_secs: default_flush_interval(),
            read_cache_mb: default_read_cache_mb(),
        }
    }
}

fn default_flush_interval() -> u64 {
    30
}
fn default_read_cache_mb() -> usize {
    64
}

impl SoteriaConfig {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }
}
