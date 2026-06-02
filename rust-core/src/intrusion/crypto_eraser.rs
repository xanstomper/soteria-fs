//! Cryptographic Erasure (R-9).
//!
//! When triggered, destroys all key material, making encrypted data
//! permanently unreadable. This is the "nuclear option" — the data
//! is gone forever because the keys are gone.
//!
//! # Legal
//!
//! Cryptographic erasure is a recognized data sanitization technique
//! (NIST SP 800-88). Destroying your own keys is always legal.
//! It's the digital equivalent of shredding documents.

use blake3;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// What triggered the erasure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EraseTrigger {
    /// User requested erasure.
    UserRequested,
    /// Threat level exceeded threshold.
    ThreatLevelExceeded { level: u8 },
    /// Tamper detection triggered.
    TamperDetected,
    /// Dead man's switch (no heartbeat received).
    DeadMansSwitch,
    /// Remote wipe command received.
    RemoteWipe,
}

/// Record of a cryptographic erasure event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseRecord {
    pub timestamp: u64,
    pub trigger: EraseTrigger,
    pub keys_destroyed: Vec<String>,
    pub blake3_confirmation: [u8; 32],
}

/// The cryptographic eraser.
pub struct CryptoEraser {
    /// Registered key material to destroy on erase.
    keys: Vec<KeySlot>,
    /// Erasure history.
    history: Vec<EraseRecord>,
    /// Whether an erasure has occurred.
    erased: bool,
}

struct KeySlot {
    name: String,
    data: Vec<u8>,
}

impl CryptoEraser {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            history: Vec::new(),
            erased: false,
        }
    }

    /// Register key material for destruction on erase.
    pub fn register_key(&mut self, name: &str, data: &mut Vec<u8>) {
        self.keys.push(KeySlot {
            name: name.to_string(),
            data: std::mem::take(data),
        });
    }

    /// Execute cryptographic erasure. Destroys all registered keys.
    /// Returns an erase record for the forensic mirror.
    pub fn erase(&mut self, trigger: EraseTrigger) -> EraseRecord {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut keys_destroyed = Vec::new();

        // Destroy all registered key material.
        for slot in &mut self.keys {
            slot.data.zeroize();
            keys_destroyed.push(slot.name.clone());
        }

        // Generate confirmation hash (proves erasure occurred).
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:crypto-erase:v1");
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&(keys_destroyed.len() as u64).to_le_bytes());
        for name in &keys_destroyed {
            hasher.update(name.as_bytes());
        }
        let blake3_confirmation = *hasher.finalize().as_bytes();

        let record = EraseRecord {
            timestamp,
            trigger,
            keys_destroyed,
            blake3_confirmation,
        };

        self.history.push(record.clone());
        self.erased = true;

        record
    }

    /// Whether an erasure has occurred.
    pub fn is_erased(&self) -> bool {
        self.erased
    }

    /// Get the erasure history.
    pub fn history(&self) -> &[EraseRecord] {
        &self.history
    }

    /// Generate a zeroed-out block (for overwriting data sectors).
    pub fn zero_block(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    /// Generate a random block (for overwriting with noise).
    pub fn random_block(size: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut buf = vec![0u8; size];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    }
}

impl Default for CryptoEraser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_destroys_keys() {
        let mut eraser = CryptoEraser::new();
        let mut key1 = vec![0x42u8; 32];
        let mut key2 = vec![0x55u8; 32];
        eraser.register_key("volume_root", &mut key1);
        eraser.register_key("domain_key", &mut key2);

        let record = eraser.erase(EraseTrigger::UserRequested);

        assert!(eraser.is_erased());
        assert_eq!(record.keys_destroyed.len(), 2);
        assert!(record.keys_destroyed.contains(&"volume_root".to_string()));
        assert!(record.keys_destroyed.contains(&"domain_key".to_string()));
    }

    #[test]
    fn erase_is_idempotent() {
        let mut eraser = CryptoEraser::new();
        let mut key = vec![0x42u8; 32];
        eraser.register_key("key", &mut key);

        eraser.erase(EraseTrigger::UserRequested);
        eraser.erase(EraseTrigger::UserRequested);

        assert_eq!(eraser.history().len(), 2);
    }

    #[test]
    fn erase_record_has_confirmation() {
        let mut eraser = CryptoEraser::new();
        let mut key = vec![0x42u8; 32];
        eraser.register_key("key", &mut key);

        let record = eraser.erase(EraseTrigger::TamperDetected);
        // Confirmation hash should be non-zero.
        assert_ne!(record.blake3_confirmation, [0u8; 32]);
    }

    #[test]
    fn zero_block_is_correct_size() {
        let block = CryptoEraser::zero_block(4096);
        assert_eq!(block.len(), 4096);
        assert!(block.iter().all(|&b| b == 0));
    }

    #[test]
    fn random_block_is_correct_size() {
        let block = CryptoEraser::random_block(4096);
        assert_eq!(block.len(), 4096);
    }

    #[test]
    fn erased_keys_are_zeroed() {
        let mut eraser = CryptoEraser::new();
        let mut key = vec![0x42u8; 32];
        eraser.register_key("key", &mut key);

        eraser.erase(EraseTrigger::UserRequested);

        // The key slot's data should be zeroed.
        assert!(eraser.keys[0].data.iter().all(|&b| b == 0));
    }
}
