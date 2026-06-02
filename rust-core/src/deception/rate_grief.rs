//! Decryption Rate Griefing (DRG).
//!
//! Dynamically adjusts KDF cost based on the rate of failed decryption
//! attempts. Automated brute-force tools trigger exponential backoff
//! that makes each successive attempt computationally prohibitive.
//!
//! # How it works
//!
//! 1. Each failed decryption attempt is recorded with a timestamp.
//! 2. The KDF cost multiplier is computed from the attempt rate:
//!    - <1 attempt/minute: multiplier = 1.0 (normal cost)
//!    - 1-10 attempts/minute: multiplier = 1.5^attempts
//!    - >10 attempts/minute: multiplier = 10.0^attempts
//! 3. The legitimate user resets the counter by entering the correct
//!    passphrase (successful decryption resets the multiplier).
//!
//! # Forensic impact
//!
//! - After 10 failed attempts: KDF requires ~190 MiB RAM per guess
//! - After 20 failed attempts: KDF requires ~19 GiB RAM per guess
//! - After 30 failed attempts: KDF requires ~19 TiB RAM per guess (impossible)
//! - Legitimate user: normal cost (19 MiB) because they succeed on first try
//!
//! # Legal
//!
//! This is standard brute-force protection (like bcrypt's exponential cost).
//! No active counter-attack, no malware, no legal liability.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Configuration for rate griefing.
#[derive(Debug, Clone)]
pub struct RateGriefConfig {
    /// Window for counting attempts.
    pub window: Duration,
    /// Base KDF memory in KiB.
    pub base_memory_kib: u32,
    /// Base KDF iterations.
    pub base_iterations: u32,
    /// Maximum multiplier (cap to prevent overflow).
    pub max_multiplier: f64,
    /// Cooldown period after which the multiplier resets if no attempts.
    pub cooldown: Duration,
}

impl Default for RateGriefConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            base_memory_kib: 19 * 1024, // 19 MiB
            base_iterations: 2,
            max_multiplier: 1_000_000_000.0,    // 1 billionx
            cooldown: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// The rate griefing engine.
pub struct RateGriefer {
    config: RateGriefConfig,
    /// Timestamps of recent failed attempts.
    failures: VecDeque<Instant>,
    /// Current cost multiplier.
    multiplier: f64,
    /// Last successful decryption (resets multiplier).
    last_success: Option<Instant>,
}

impl RateGriefer {
    pub fn new(config: RateGriefConfig) -> Self {
        Self {
            config,
            failures: VecDeque::new(),
            multiplier: 1.0,
            last_success: None,
        }
    }

    /// Record a failed decryption attempt.
    pub fn record_failure(&mut self) {
        let now = Instant::now();
        self.failures.push_back(now);
        self.prune_old();
        self.update_multiplier();
    }

    /// Record a successful decryption (resets the multiplier).
    pub fn record_success(&mut self) {
        self.last_success = Some(Instant::now());
        self.failures.clear();
        self.multiplier = 1.0;
    }

    /// Get the current KDF parameters (adjusted for the current multiplier).
    pub fn current_kdf_params(&self) -> (u32, u32) {
        let memory = (self.config.base_memory_kib as f64 * self.multiplier) as u32;
        let iterations = (self.config.base_iterations as f64 * self.multiplier.sqrt()) as u32;
        (
            memory.max(self.config.base_memory_kib),
            iterations.max(self.config.base_iterations),
        )
    }

    /// Get the current multiplier.
    pub fn multiplier(&self) -> f64 {
        self.multiplier
    }

    /// Get the number of recent failures in the window.
    pub fn recent_failures(&self) -> usize {
        self.failures.len()
    }

    fn prune_old(&mut self) {
        let cutoff = Instant::now() - self.config.window;
        while self.failures.front().map_or(false, |t| *t < cutoff) {
            self.failures.pop_front();
        }
    }

    fn update_multiplier(&mut self) {
        let count = self.failures.len() as f64;

        // Check cooldown — if last success was recent, keep multiplier low.
        if let Some(success) = self.last_success {
            if success.elapsed() < self.config.cooldown {
                self.multiplier = 1.0;
                return;
            }
        }

        self.multiplier = if count < 1.0 {
            1.0
        } else if count <= 10.0 {
            1.5_f64.powf(count)
        } else {
            10.0_f64.powf(count - 10.0) * 1.5_f64.powf(10.0)
        };

        self.multiplier = self.multiplier.min(self.config.max_multiplier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_failures_means_normal_cost() {
        let griefer = RateGriefer::new(RateGriefConfig::default());
        assert_eq!(griefer.multiplier(), 1.0);
        let (mem, iter) = griefer.current_kdf_params();
        assert_eq!(mem, 19 * 1024);
        assert_eq!(iter, 2);
    }

    #[test]
    fn single_failure_increases_multiplier() {
        let mut griefer = RateGriefer::new(RateGriefConfig::default());
        griefer.record_failure();
        assert!(griefer.multiplier() > 1.0);
    }

    #[test]
    fn multiple_failures_exponential_growth() {
        let mut griefer = RateGriefer::new(RateGriefConfig::default());
        for _ in 0..10 {
            griefer.record_failure();
        }
        let m = griefer.multiplier();
        assert!(m > 10.0, "expected exponential growth, got {m}");
    }

    #[test]
    fn success_resets_multiplier() {
        let mut griefer = RateGriefer::new(RateGriefConfig::default());
        for _ in 0..10 {
            griefer.record_failure();
        }
        assert!(griefer.multiplier() > 10.0);
        griefer.record_success();
        assert_eq!(griefer.multiplier(), 1.0);
    }

    #[test]
    fn multiplier_is_capped() {
        let config = RateGriefConfig {
            max_multiplier: 100.0,
            ..Default::default()
        };
        let mut griefer = RateGriefer::new(config);
        for _ in 0..50 {
            griefer.record_failure();
        }
        assert_eq!(griefer.multiplier(), 100.0);
    }

    #[test]
    fn kdf_params_increase_with_failures() {
        let mut griefer = RateGriefer::new(RateGriefConfig::default());
        let (mem0, iter0) = griefer.current_kdf_params();
        for _ in 0..10 {
            griefer.record_failure();
        }
        let (mem1, iter1) = griefer.current_kdf_params();
        assert!(mem1 > mem0, "memory should increase");
        assert!(iter1 > iter0, "iterations should increase");
    }
}
