//! Threat Level Assessment Matrix (R-8).
//!
//! Scores every decryption event against a set of heuristics and
//! assigns a threat level from 0 (normal) to 5 (state-level APT).
//! Higher levels trigger more aggressive defensive responses.
//!
//! # Legal
//!
//! This is a passive monitoring and scoring system. No active
//! counter-measures are taken by this module — it only classifies.
//! The calling code decides what to do with the classification.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Threat levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Normal operation — legitimate user.
    Normal = 0,
    /// Suspicious activity — occasional wrong keys.
    Suspicious = 1,
    /// Active probing — systematic wrong-key attempts.
    Probing = 2,
    /// Brute-force attack — high rate of wrong keys.
    BruteForce = 3,
    /// State-level actor — tooling fingerprints, timing anomalies.
    StateLevel = 4,
    /// APT confirmed — persistent, sophisticated, targeted.
    AptConfirmed = 5,
}

impl ThreatLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=9 => Self::Normal,
            10..=24 => Self::Suspicious,
            25..=49 => Self::Probing,
            50..=79 => Self::BruteForce,
            80..=119 => Self::StateLevel,
            _ => Self::AptConfirmed,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// A single decryption event for scoring.
#[derive(Debug, Clone)]
pub struct DecryptionEvent {
    pub timestamp: Instant,
    pub block_index: u64,
    pub success: bool,
    pub duration: Duration,
    pub key_fingerprint: [u8; 32],
}

/// Configuration for the threat matrix.
#[derive(Debug, Clone)]
pub struct ThreatMatrixConfig {
    /// Window for counting events.
    pub window: Duration,
    /// Threshold for wrong-key rate (percentage).
    pub wrong_key_threshold: f64,
    /// Threshold for parallelism detection (max concurrent decryptions).
    pub parallelism_threshold: usize,
    /// Baseline decryption timing for the legitimate user.
    pub baseline_timing: Option<Duration>,
    /// Tolerance for timing deviation (percentage).
    pub timing_tolerance: f64,
}

impl Default for ThreatMatrixConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300), // 5 minutes
            wrong_key_threshold: 0.05,        // 5%
            parallelism_threshold: 2,
            baseline_timing: None,
            timing_tolerance: 0.5, // 50%
        }
    }
}

/// The threat assessment engine.
pub struct ThreatMatrix {
    config: ThreatMatrixConfig,
    events: VecDeque<DecryptionEvent>,
    current_level: ThreatLevel,
    score_history: Vec<u32>,
}

impl ThreatMatrix {
    pub fn new(config: ThreatMatrixConfig) -> Self {
        Self {
            config,
            events: VecDeque::new(),
            current_level: ThreatLevel::Normal,
            score_history: Vec::new(),
        }
    }

    /// Record a decryption event and re-evaluate the threat level.
    pub fn record(&mut self, event: DecryptionEvent) -> ThreatLevel {
        self.events.push_back(event);
        self.prune();
        let score = self.compute_score();
        self.score_history.push(score);
        self.current_level = ThreatLevel::from_score(score);
        self.current_level
    }

    /// Get the current threat level.
    pub fn level(&self) -> ThreatLevel {
        self.current_level
    }

    /// Get the current score.
    pub fn score(&self) -> u32 {
        self.score_history.last().copied().unwrap_or(0)
    }

    /// Get recent events.
    pub fn recent_events(&self) -> &VecDeque<DecryptionEvent> {
        &self.events
    }

    /// Set the baseline timing for the legitimate user.
    pub fn set_baseline_timing(&mut self, timing: Duration) {
        self.config.baseline_timing = Some(timing);
    }

    fn prune(&mut self) {
        let cutoff = Instant::now() - self.config.window;
        while self.events.front().map_or(false, |e| e.timestamp < cutoff) {
            self.events.pop_front();
        }
    }

    fn compute_score(&self) -> u32 {
        if self.events.is_empty() {
            return 0;
        }

        let mut score: u32 = 0;
        let total = self.events.len() as f64;
        let failures = self.events.iter().filter(|e| !e.success).count() as f64;
        let wrong_key_rate = failures / total;

        // Wrong-key rate scoring.
        if wrong_key_rate > self.config.wrong_key_threshold {
            score += 10;
        }
        if wrong_key_rate > 0.50 {
            score += 20;
        }
        if wrong_key_rate > 0.90 {
            score += 20;
        }

        // Timing anomaly detection.
        if let Some(baseline) = self.config.baseline_timing {
            let avg_duration: Duration =
                self.events.iter().map(|e| e.duration).sum::<Duration>() / self.events.len() as u32;
            let deviation = if baseline.as_nanos() > 0 {
                (avg_duration.as_nanos() as f64 - baseline.as_nanos() as f64).abs()
                    / baseline.as_nanos() as f64
            } else {
                0.0
            };
            if deviation > self.config.timing_tolerance {
                score += 15;
            }
        }

        // Sequential access pattern (automated scanning).
        let sequential = self.detect_sequential_access();
        if sequential {
            score += 15;
        }

        // Parallelism detection.
        let parallel = self.detect_parallelism();
        if parallel {
            score += 20;
        }

        // Uniform inter-arrival times (AI-like behavior).
        // Only check when there are failures — legitimate users don't have
        // uniform timing on wrong keys.
        if failures > 0.0 {
            let uniform = self.detect_uniform_timing();
            if uniform {
                score += 10;
            }
        }

        // High event rate (automated tool).
        let rate = total / self.config.window.as_secs_f64();
        if rate > 1.0 {
            score += 10;
        }
        if rate > 10.0 {
            score += 20;
        }

        score
    }

    fn detect_sequential_access(&self) -> bool {
        if self.events.len() < 5 {
            return false;
        }
        let mut sequential_count = 0;
        let mut prev_block = None;
        for event in &self.events {
            if let Some(prev) = prev_block {
                if event.block_index == prev + 1 {
                    sequential_count += 1;
                }
            }
            prev_block = Some(event.block_index);
        }
        sequential_count > self.events.len() / 2
    }

    fn detect_parallelism(&self) -> bool {
        if self.events.len() < 3 {
            return false;
        }
        // Check if any two events overlap in time.
        let events: Vec<_> = self.events.iter().collect();
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                let end_i = events[i].timestamp + events[i].duration;
                if events[j].timestamp < end_i {
                    return true;
                }
            }
        }
        false
    }

    fn detect_uniform_timing(&self) -> bool {
        if self.events.len() < 10 {
            return false;
        }
        // Check if inter-arrival times have very low variance (AI-like).
        let intervals: Vec<f64> = self
            .events
            .iter()
            .collect::<Vec<_>>()
            .windows(2)
            .map(|w| (w[1].timestamp - w[0].timestamp).as_secs_f64())
            .collect();
        if intervals.is_empty() {
            return false;
        }
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = if mean > 0.0 {
            variance.sqrt() / mean
        } else {
            0.0
        };
        // Coefficient of variation < 0.1 means very uniform timing.
        cv < 0.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(success: bool, block: u64, ms_ago: u64) -> DecryptionEvent {
        DecryptionEvent {
            timestamp: Instant::now() - Duration::from_millis(ms_ago),
            block_index: block,
            success,
            duration: Duration::from_millis(80 + (block % 5) * 10), // Varying durations
            key_fingerprint: [0u8; 32],
        }
    }

    #[test]
    fn no_events_is_normal() {
        let matrix = ThreatMatrix::new(ThreatMatrixConfig::default());
        assert_eq!(matrix.level(), ThreatLevel::Normal);
    }

    #[test]
    fn successful_decryptions_are_normal() {
        let config = ThreatMatrixConfig {
            window: Duration::from_secs(3600),
            ..Default::default()
        };
        let mut matrix = ThreatMatrix::new(config);
        // Use non-uniform timestamps and non-sequential block indices
        // (like a real user would have). Create events oldest-first.
        let delays = [11800, 10200, 9500, 8100, 7300, 6000, 4100, 3500, 1200, 0];
        let blocks = [5, 12, 3, 8, 1, 14, 7, 11, 2, 9];
        for (&delay, &block) in delays.iter().zip(blocks.iter()) {
            matrix.record(event(true, block, delay));
        }
        let score = matrix.score();
        assert_eq!(matrix.level(), ThreatLevel::Normal, "score={score}");
    }

    #[test]
    fn wrong_keys_increase_threat() {
        let config = ThreatMatrixConfig {
            window: Duration::from_secs(3600),
            ..Default::default()
        };
        let mut matrix = ThreatMatrix::new(config);
        for i in 0..20 {
            matrix.record(event(false, i, 0));
        }
        assert!(matrix.level() >= ThreatLevel::BruteForce);
    }

    #[test]
    fn sequential_access_detected() {
        let config = ThreatMatrixConfig {
            window: Duration::from_secs(3600),
            ..Default::default()
        };
        let mut matrix = ThreatMatrix::new(config);
        for i in 0..10 {
            matrix.record(event(false, i, 0));
        }
        assert!(matrix.detect_sequential_access());
    }

    #[test]
    fn threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(0), ThreatLevel::Normal);
        assert_eq!(ThreatLevel::from_score(15), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_score(30), ThreatLevel::Probing);
        assert_eq!(ThreatLevel::from_score(60), ThreatLevel::BruteForce);
        assert_eq!(ThreatLevel::from_score(100), ThreatLevel::StateLevel);
        assert_eq!(ThreatLevel::from_score(150), ThreatLevel::AptConfirmed);
    }
}
