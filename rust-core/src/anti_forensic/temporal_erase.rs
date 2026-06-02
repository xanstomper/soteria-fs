//! D-1: Temporal Self-Erasing Blocks (TSEB)
//!
//! Blocks that haven't been accessed within a configurable TTL are
//! overwritten with random noise. This provides forward secrecy for
//! data at rest — even if the drive is imaged while powered, idle
//! blocks self-erase.
//!
//! # Limitations
//!
//! This is a software implementation. It only works while the system
//! is powered and the daemon is running. Once the drive is disconnected
//! or powered off, TTLs cannot be enforced. A firmware-level TSEB
//! would require custom SSD controller firmware.
//!
//! # Forensic impact
//!
//! - Drive imaged while powered: idle blocks may already be erased
//! - Drive imaged after power-off: TTLs freeze, blocks survive until
//!   next power-on when the daemon resumes erasing
//! - Drive imaged cold (no power): blocks survive until TTL check runs

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Configuration for temporal self-erasing blocks.
pub struct TsebConfig {
    /// Maximum time a block can go without access before erasure.
    pub max_idle: Duration,
    /// How often to scan for expired blocks.
    pub scan_interval: Duration,
    /// Maximum number of blocks to erase per scan (rate limiting).
    pub max_erases_per_scan: usize,
}

impl Default for TsebConfig {
    fn default() -> Self {
        Self {
            max_idle: Duration::from_secs(30 * 24 * 3600), // 30 days
            scan_interval: Duration::from_secs(3600),      // 1 hour
            max_erases_per_scan: 100,
        }
    }
}

/// Metadata for a tracked block.
struct BlockMeta {
    /// Last time this block was legitimately accessed.
    last_access: Instant,
    /// Block index on disk.
    index: u64,
}

/// The temporal erasure engine. Tracks block access times and erases
/// blocks that exceed their TTL.
pub struct TemporalEraser {
    /// Tracked blocks: index -> metadata.
    blocks: HashMap<u64, BlockMeta>,
    /// Configuration.
    config: TsebConfig,
    /// Whether the eraser is running.
    running: Arc<AtomicBool>,
    /// Total blocks erased since startup.
    erased_count: u64,
}

impl TemporalEraser {
    pub fn new(config: TsebConfig) -> Self {
        Self {
            blocks: HashMap::new(),
            config,
            running: Arc::new(AtomicBool::new(false)),
            erased_count: 0,
        }
    }

    /// Record a block access (resets its TTL).
    pub fn touch(&mut self, block_index: u64) {
        self.blocks.insert(
            block_index,
            BlockMeta {
                last_access: Instant::now(),
                index: block_index,
            },
        );
    }

    /// Remove a block from tracking (e.g., when the block is deleted).
    pub fn forget(&mut self, block_index: u64) {
        self.blocks.remove(&block_index);
    }

    /// Scan for expired blocks and return their indices.
    /// The caller is responsible for actually overwriting the blocks.
    pub fn scan_expired(&self) -> Vec<u64> {
        let now = Instant::now();
        let mut expired: Vec<u64> = self
            .blocks
            .iter()
            .filter(|(_, meta)| now.duration_since(meta.last_access) > self.config.max_idle)
            .map(|(idx, _)| *idx)
            .collect();
        expired.sort();
        expired.truncate(self.config.max_erases_per_scan);
        expired
    }

    /// Mark blocks as erased after overwriting.
    pub fn mark_erased(&mut self, indices: &[u64]) {
        for idx in indices {
            self.blocks.remove(idx);
            self.erased_count += 1;
        }
    }

    /// Total blocks erased.
    pub fn erased_count(&self) -> u64 {
        self.erased_count
    }

    /// Number of blocks currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.blocks.len()
    }

    /// Start a background scanner thread. Returns a handle and a stop flag.
    pub fn start_background(
        eraser: Arc<parking_lot::Mutex<Self>>,
        erase_fn: Box<dyn Fn(u64) + Send + Sync>,
    ) -> (std::thread::JoinHandle<()>, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let config = eraser.lock().config.scan_interval;

        let handle = std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                std::thread::sleep(config);
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let expired = {
                    let e = eraser.lock();
                    e.scan_expired()
                };
                for idx in &expired {
                    erase_fn(*idx);
                }
                if !expired.is_empty() {
                    let mut e = eraser.lock();
                    e.mark_erased(&expired);
                    tracing::info!(
                        count = expired.len(),
                        total = e.erased_count(),
                        "TSEB: erased expired blocks"
                    );
                }
            }
        });

        (handle, stop)
    }
}

/// Generate random noise for overwriting a block.
pub fn random_block(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Current time as nanoseconds since epoch (for TTL computation).
pub fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_and_scan_not_expired() {
        let mut eraser = TemporalEraser::new(TsebConfig {
            max_idle: Duration::from_secs(3600),
            ..Default::default()
        });
        eraser.touch(0);
        eraser.touch(1);
        assert_eq!(eraser.scan_expired().len(), 0);
    }

    #[test]
    fn expired_blocks_detected() {
        let mut eraser = TemporalEraser::new(TsebConfig {
            max_idle: Duration::from_millis(1),
            ..Default::default()
        });
        eraser.touch(0);
        eraser.touch(1);
        std::thread::sleep(Duration::from_millis(10));
        let expired = eraser.scan_expired();
        assert_eq!(expired.len(), 2);
        assert!(expired.contains(&0));
        assert!(expired.contains(&1));
    }

    #[test]
    fn mark_erased_removes_tracking() {
        let mut eraser = TemporalEraser::new(TsebConfig {
            max_idle: Duration::from_millis(1),
            ..Default::default()
        });
        eraser.touch(0);
        std::thread::sleep(Duration::from_millis(10));
        let expired = eraser.scan_expired();
        assert_eq!(expired.len(), 1);
        eraser.mark_erased(&expired);
        assert_eq!(eraser.tracked_count(), 0);
        assert_eq!(eraser.erased_count(), 1);
    }

    #[test]
    fn forget_removes_tracking() {
        let mut eraser = TemporalEraser::new(TsebConfig::default());
        eraser.touch(5);
        assert_eq!(eraser.tracked_count(), 1);
        eraser.forget(5);
        assert_eq!(eraser.tracked_count(), 0);
    }

    #[test]
    fn max_erases_per_scan_limits() {
        let mut eraser = TemporalEraser::new(TsebConfig {
            max_idle: Duration::from_millis(1),
            max_erases_per_scan: 2,
            ..Default::default()
        });
        for i in 0..10 {
            eraser.touch(i);
        }
        std::thread::sleep(Duration::from_millis(10));
        let expired = eraser.scan_expired();
        assert_eq!(expired.len(), 2);
    }

    #[test]
    fn random_block_has_correct_size() {
        let block = random_block(4096);
        assert_eq!(block.len(), 4096);
    }
}
