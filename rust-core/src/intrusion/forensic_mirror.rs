//! Forensic Mirror (R-7).
//!
//! Records all decryption events in an immutable, chain-hashed audit log
//! for post-incident prosecution. No active counter-measures — pure
//! passive evidence collection.
//!
//! # Legal
//!
//! This is standard audit logging. All data collected is from the
//! system's own operations (decryption attempts against the local
//! volume). No network scanning, no credential theft, no malware.

use blake3;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A single forensic event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvent {
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub block_index: Option<u64>,
    pub key_fingerprint: Option<[u8; 32]>,
    pub success: bool,
    pub duration_ns: u64,
    pub chain_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    DecryptionAttempt,
    KeyRotation,
    Mount,
    Unmount,
    ThreatEscalation { from: u8, to: u8 },
    CryptoErase,
}

/// The forensic mirror — immutable chain-hashed event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMirror {
    events: Vec<ForensicEvent>,
    chain_tip: [u8; 32],
}

impl ForensicMirror {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            chain_tip: [0u8; 32],
        }
    }

    pub fn record(
        &mut self,
        event_type: EventType,
        block_index: Option<u64>,
        key_fingerprint: Option<[u8; 32]>,
        success: bool,
        duration: Duration,
    ) {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let duration_ns = duration.as_nanos() as u64;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain_tip);
        hasher.update(&timestamp_ns.to_le_bytes());
        hasher.update(&(block_index.unwrap_or(u64::MAX)).to_le_bytes());
        hasher.update(&[success as u8]);
        hasher.update(&duration_ns.to_le_bytes());
        if let Some(kf) = &key_fingerprint {
            hasher.update(kf);
        }
        let chain_hash = *hasher.finalize().as_bytes();

        self.events.push(ForensicEvent {
            timestamp_ns,
            event_type,
            block_index,
            key_fingerprint,
            success,
            duration_ns,
            chain_hash,
        });
        self.chain_tip = chain_hash;
    }

    pub fn verify(&self) -> Option<usize> {
        let mut prev = [0u8; 32];
        for (i, event) in self.events.iter().enumerate() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&prev);
            hasher.update(&event.timestamp_ns.to_le_bytes());
            hasher.update(&(event.block_index.unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(&[event.success as u8]);
            hasher.update(&event.duration_ns.to_le_bytes());
            if let Some(kf) = &event.key_fingerprint {
                hasher.update(kf);
            }
            let expected = *hasher.finalize().as_bytes();
            if expected != event.chain_hash {
                eprintln!("verify: mismatch at index {i}");
                eprintln!("  expected: {:?}", &expected[..8]);
                eprintln!("  stored:   {:?}", &event.chain_hash[..8]);
                eprintln!("  success:  {}", event.success);
                eprintln!("  block:    {:?}", event.block_index);
                return Some(i);
            }
            prev = event.chain_hash;
        }
        None
    }

    pub fn events(&self) -> &[ForensicEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.events).unwrap_or_default()
    }
}

impl Default for ForensicMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mirror_is_valid() {
        let mirror = ForensicMirror::new();
        assert!(mirror.verify().is_none());
    }

    #[test]
    fn single_event_recorded() {
        let mut mirror = ForensicMirror::new();
        mirror.record(
            EventType::DecryptionAttempt,
            Some(0),
            None,
            true,
            Duration::from_millis(10),
        );
        assert_eq!(mirror.len(), 1);
    }

    #[test]
    fn multiple_events_recorded() {
        let mut mirror = ForensicMirror::new();
        for i in 0..10 {
            mirror.record(
                EventType::DecryptionAttempt,
                Some(i),
                None,
                true,
                Duration::from_millis(10),
            );
        }
        assert_eq!(mirror.len(), 10);
    }

    #[test]
    fn tampered_event_detected() {
        let mut mirror = ForensicMirror::new();
        for i in 0..5 {
            mirror.record(
                EventType::DecryptionAttempt,
                Some(i),
                None,
                true,
                Duration::from_millis(10),
            );
        }
        // Store original hash of event 2.
        let original_hash = mirror.events[2].chain_hash;
        // Tamper with event 2.
        mirror.events[2].success = false;
        // Verify should detect the tamper at index 2.
        let result = mirror.verify();
        assert!(result.is_some(), "verify should detect tamper");
        assert_eq!(result.unwrap(), 2, "tamper should be at index 2");
    }

    #[test]
    fn export_json_works() {
        let mut mirror = ForensicMirror::new();
        mirror.record(EventType::Mount, None, None, true, Duration::from_millis(0));
        let json = mirror.export_json();
        assert!(json.contains("Mount"));
    }
}
