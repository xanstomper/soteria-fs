//! Background daemon for Soteria.
//!
//! Runs as a long-lived process that handles:
//! - Auto-mount on startup
//! - Auto-lock on idle / screen lock
//! - Scheduled key rotation
//! - Real-time monitoring (anomaly detection)
//! - Periodic integrity checks
//! - Write-back cache flushing
//!
//! Started via `soteriad daemon` or by the systemd/launchd service.

use crate::config::SoteriaConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for the background daemon.
pub struct DaemonConfig {
    /// Path to the Soteria configuration file.
    pub config_path: PathBuf,
    /// How often to run integrity checks (seconds).
    pub integrity_check_interval: u64,
    /// How often to check for key rotation (seconds).
    pub key_rotation_check_interval: u64,
    /// How often to flush the write-back cache (seconds).
    pub cache_flush_interval: u64,
    /// Auto-lock after this many seconds of idle.
    pub auto_lock_idle_seconds: u64,
    /// Enable real-time anomaly monitoring.
    pub anomaly_monitoring: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("config/soteria.toml"),
            integrity_check_interval: 3600,     // 1 hour
            key_rotation_check_interval: 86400, // 24 hours
            cache_flush_interval: 30,           // 30 seconds
            auto_lock_idle_seconds: 900,        // 15 minutes
            anomaly_monitoring: true,
        }
    }
}

/// The background daemon. Runs tasks on configurable intervals.
pub struct Daemon {
    cfg: DaemonConfig,
    soteria_cfg: SoteriaConfig,
    running: Arc<AtomicBool>,
    last_integrity_check: Instant,
    last_rotation_check: Instant,
    last_cache_flush: Instant,
}

impl Daemon {
    pub fn new(cfg: DaemonConfig) -> crate::Result<Self> {
        let soteria_cfg = SoteriaConfig::load(&cfg.config_path)?;
        Ok(Self {
            cfg,
            soteria_cfg,
            running: Arc::new(AtomicBool::new(true)),
            last_integrity_check: Instant::now(),
            last_rotation_check: Instant::now(),
            last_cache_flush: Instant::now(),
        })
    }

    /// Run the daemon loop. Blocks until signaled to stop.
    pub fn run(&mut self) -> crate::Result<()> {
        tracing::info!("Soteria daemon starting");

        // Set up signal handlers.
        let running = self.running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| anyhow::anyhow!("failed to set signal handler: {e}"))?;

        while self.running.load(Ordering::SeqCst) {
            let now = Instant::now();

            // Integrity check
            if now.duration_since(self.last_integrity_check).as_secs()
                >= self.cfg.integrity_check_interval
            {
                self.run_integrity_check();
                self.last_integrity_check = now;
            }

            // Key rotation check
            if now.duration_since(self.last_rotation_check).as_secs()
                >= self.cfg.key_rotation_check_interval
            {
                self.check_key_rotation();
                self.last_rotation_check = now;
            }

            // Cache flush
            if now.duration_since(self.last_cache_flush).as_secs() >= self.cfg.cache_flush_interval
            {
                self.flush_cache();
                self.last_cache_flush = now;
            }

            // Anomaly monitoring
            if self.cfg.anomaly_monitoring {
                self.check_anomalies();
            }

            // Sleep for 1 second before next iteration.
            std::thread::sleep(Duration::from_secs(1));
        }

        tracing::info!("Soteria daemon shutting down");
        Ok(())
    }

    fn run_integrity_check(&self) {
        tracing::info!("Running periodic integrity check");
        // TODO: Walk all volumes and verify lineage chains.
        // Report any failures to the event bus.
    }

    fn check_key_rotation(&self) {
        tracing::info!("Checking key rotation schedule");
        // TODO: Check if any keys are overdue for rotation.
        // Auto-rotate if configured.
    }

    fn flush_cache(&self) {
        tracing::debug!("Flushing write-back cache");
        // TODO: Flush all dirty files in the FUSE layer.
    }

    fn check_anomalies(&self) {
        // TODO: Run the anomaly detector (entropy spikes, write patterns,
        // canary hits, etc.) and report to the event bus.
    }
}
