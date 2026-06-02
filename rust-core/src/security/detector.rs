use super::canary::CanaryToken;
use crate::event_bus::{Severity, SoteriaEvent};
use crate::sensors::entropy_sensor::shannon_entropy;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

/// Detected alert categories produced by the canary/anomaly detector.
#[derive(Debug, Clone, PartialEq)]
pub enum Alert {
    CanaryTouched { region_id: String },
    EntropySpike { region_id: String, entropy: f64 },
    MassEnumeration { region_id: String, reads: u32 },
}

/// Sliding-window anomaly detector. Tracks per-region read counts, last
/// observed entropies, and emits structured immune events. Does not take
/// enforcement action — that is the responsibility of the policy engine.
pub struct AnomalyDetector {
    window: Duration,
    entropy_threshold: f64,
    read_window_threshold: u32,
    per_region_reads: BTreeMap<String, Vec<SystemTime>>,
    canaries: BTreeMap<String, CanaryToken>,
}

impl AnomalyDetector {
    pub fn new(entropy_threshold: f64, read_window_threshold: u32) -> Self {
        Self {
            window: Duration::from_secs(60),
            entropy_threshold,
            read_window_threshold,
            per_region_reads: BTreeMap::new(),
            canaries: BTreeMap::new(),
        }
    }

    pub fn register_canary(&mut self, token: CanaryToken) {
        self.canaries.insert(token.region_id.clone(), token);
    }

    pub fn region_canary_present(&self, region_id: &str) -> bool {
        self.canaries.contains_key(region_id)
    }

    pub fn observe_read(&mut self, region_id: &str) -> Vec<SoteriaEvent> {
        self.prune(region_id);
        let entry = self
            .per_region_reads
            .entry(region_id.to_string())
            .or_default();
        entry.push(SystemTime::now());
        let mut events = Vec::new();
        let count = entry.len() as u32;
        if count >= self.read_window_threshold {
            let event = SoteriaEvent::new(
                "MASS_ENUMERATION",
                "anomaly_detector",
                Severity::new(0.7),
                serde_json::json!({"region_id": region_id, "reads": count}),
            )
            .expect("timestamp never fails");
            events.push(event);
        }
        events
    }

    pub fn observe_write(&mut self, region_id: &str, payload: &[u8]) -> Vec<SoteriaEvent> {
        let mut events = Vec::new();
        let entropy = shannon_entropy(payload);
        if entropy >= self.entropy_threshold {
            let event = SoteriaEvent::new(
                "ENTROPY_SPIKE",
                "anomaly_detector",
                Severity::new((entropy / 8.0).min(1.0)),
                serde_json::json!({"region_id": region_id, "entropy": entropy}),
            )
            .expect("timestamp never fails");
            events.push(event);
        }
        events
    }

    pub fn verify_canary(&self, region_id: &str, observed: &[u8]) -> Option<SoteriaEvent> {
        let token = self.canaries.get(region_id)?;
        if !token.verify(region_id, observed) {
            return None;
        }
        // The presence of the canary in a read or modified region produces a
        // high-confidence alert.
        SoteriaEvent::new(
            "CANARY_TOUCHED",
            "anomaly_detector",
            Severity::new(0.95),
            serde_json::json!({"region_id": region_id}),
        )
        .ok()
    }

    pub fn alerts(&self) -> Vec<Alert> {
        let mut out = Vec::new();
        for (region, reads) in &self.per_region_reads {
            let count = reads.len() as u32;
            if count >= self.read_window_threshold {
                out.push(Alert::MassEnumeration {
                    region_id: region.clone(),
                    reads: count,
                });
            }
        }
        for region in self.canaries.keys() {
            out.push(Alert::CanaryTouched {
                region_id: region.clone(),
            });
        }
        out
    }

    fn prune(&mut self, region_id: &str) {
        let now = SystemTime::now();
        if let Some(reads) = self.per_region_reads.get_mut(region_id) {
            reads.retain(|t| now.duration_since(*t).unwrap_or_default() <= self.window);
        }
    }
}
