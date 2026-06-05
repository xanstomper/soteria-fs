//! SOTERIA-OMEGA Part 4 — COMSEC Key Custody Chain.
//!
//! In COMSEC (Communications Security) practice, every cryptographic
//! key has a documented life-cycle: it is generated, distributed,
//! stored, used, and finally destroyed. At every transition between
//! custodians, a `CustodyEvent` is recorded and countersigned.
//!
//! This module implements the Soteria-OMEGA COMSEC ledger. It is a
//! simple append-only structure (the underlying storage is
//! `policy::audit_log`; this module provides the COMSEC-specific
//! schema).
//!
//! ## Custody chain
//!
//! ```text
//! KeyGen(Alice) -> Distribute(Alice, Bob) -> Activate(Bob) ->
//!   Rotate(Bob, Carol) -> Destroy(Carol, Dave, witnessed)
//! ```
//!
//! Each transition has:
//! - `event_id`: BLAKE3 hash of the previous event + payload.
//! - `prev_event_hash`: BLAKE3 hash of the previous `CustodyEvent`.
//! - `actor`: the operator (or hardware token) performing the action.
//! - `counterparty`: the new custodian (for distribution/transfer).
//! - `witness`: optional third-party witness signature.
//! - `timestamp`: monotonic Unix ms.
//!
//! The chain is verified by hashing every event in order; a single
//! bit-flip in any event breaks the chain.
//!
//! ## DestroyCertificate
//!
//! A `DestroyCertificate` is the terminal event for a key. It
//! includes:
//! - The key's final custody event.
//! - The zeroization method used (e.g., "DoD 5220.22-M 3-pass",
//!   "NVMe Format SES=2", "ATA Secure Erase").
//! - A witness signature attesting to the destruction.
//! - A SHA-256 of the zeroized material (proving the operator
//!   destroyed *something* even if we can't prove what).

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Type of COMSEC event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyEventKind {
    /// Key was generated.
    KeyGen {
        algorithm: String,
        key_length_bits: usize,
    },
    /// Key was distributed from one custodian to another.
    Distribute { from: Custodian, to: Custodian },
    /// Key was activated (loaded into a crypto module for use).
    Activate { by: Custodian },
    /// Key was rotated to a successor.
    Rotate { to: Custodian, new_key_id: [u8; 32] },
    /// Key was suspended (taken out of active use without destruction).
    Suspend { by: Custodian, reason: String },
    /// Key was re-activated after suspension.
    Reactivate { by: Custodian },
    /// Key was compromised (zeroized and reported).
    Compromised {
        detected_by: Custodian,
        by: Custodian,
    },
    /// Key was destroyed (terminal event).
    Destroy {
        by: Custodian,
        method: DestructionMethod,
        sha256_of_zeroized: [u8; 32],
    },
}

/// A custodian is either a human operator, a hardware token, or a
/// sealed enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Custodian {
    Operator { id: [u8; 32], display_name: String },
    Hardware { token_id: String, model: String },
    Enclave { attestation_quote: Vec<u8> },
}

/// How the key was zeroized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructionMethod {
    /// Single-pass zero overwrite.
    Zero,
    /// 3-pass DoD 5220.22-M overwrite.
    Dod522022,
    /// 35-pass Gutmann overwrite.
    Gutmann,
    /// Random overwrite.
    Random,
    /// Cryptographic erase (key destroyed; data unreadable).
    CryptoErase,
    /// NVMe Format SES=2 (user-data erase).
    NvmeFormatUserData,
    /// NVMe Format SES=3 (cryptographic erase).
    NvmeFormatCrypto,
    /// ATA Security Erase.
    AtaSecureErase,
    /// ATA Enhanced Secure Erase.
    AtaEnhancedSecureErase,
    /// TPM2_NV_UndefineSpace.
    Tpm2Undefine,
    /// Software zeroize of RAM-resident material.
    SoftwareZeroize,
}

impl DestructionMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Dod522022 => "dod-5220-22-m",
            Self::Gutmann => "gutmann",
            Self::Random => "random",
            Self::CryptoErase => "crypto-erase",
            Self::NvmeFormatUserData => "nvme-format-ses-2",
            Self::NvmeFormatCrypto => "nvme-format-ses-3",
            Self::AtaSecureErase => "ata-secure-erase",
            Self::AtaEnhancedSecureErase => "ata-enhanced-secure-erase",
            Self::Tpm2Undefine => "tpm2-nv-undefine",
            Self::SoftwareZeroize => "software-zeroize",
        }
    }
}

/// A single custody event in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    pub event_id: [u8; 32],
    pub prev_event_hash: [u8; 32],
    pub key_id: [u8; 32],
    pub timestamp_ms: u64,
    pub kind: CustodyEventKind,
    pub witness: Option<WitnessSignature>,
}

/// Witness countersignature on a custody event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_kind: WitnessKind,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WitnessKind {
    HumanOperator {
        id: [u8; 32],
        name: String,
    },
    HardwareToken {
        token_id: String,
    },
    /// Auditor cryptographer (typically a designated third party).
    Auditor {
        id: [u8; 32],
        name: String,
    },
}

/// A `DestroyCertificate` is the terminal event for a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyCertificate {
    pub key_id: [u8; 32],
    pub method: DestructionMethod,
    pub sha256_of_zeroized: [u8; 32],
    pub timestamp_ms: u64,
    pub witnessed_by: WitnessSignature,
    pub rationale: String,
    /// A free-form attestation string (e.g. "per NISPOM 8-303" or
    /// "per NIST SP 800-88 Rev 1 purge").
    pub policy_reference: String,
}

/// A COMSEC key tracked by the inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComsecKey {
    pub key_id: [u8; 32],
    pub short_id: String,
    pub algorithm: String,
    pub key_length_bits: usize,
    pub classification: crate::omega::Classification,
    pub custodian: Custodian,
    pub created_ms: u64,
    pub destroyed: bool,
    pub last_event: Option<CustodyEvent>,
    pub event_chain: Vec<CustodyEvent>,
}

impl ComsecKey {
    pub fn new(
        short_id: impl Into<String>,
        algorithm: impl Into<String>,
        key_length_bits: usize,
        classification: crate::omega::Classification,
        custodian: Custodian,
    ) -> Self {
        let short_id_string: String = short_id.into();
        let key_id =
            *blake3::hash(format!("comsec-key-{}-{}", short_id_string, unix_ms_now()).as_bytes())
                .as_bytes();
        Self {
            key_id,
            short_id: short_id_string,
            algorithm: algorithm.into(),
            key_length_bits,
            classification,
            custodian,
            created_ms: unix_ms_now(),
            destroyed: false,
            last_event: None,
            event_chain: Vec::new(),
        }
    }

    /// Append a custody event to the chain. Returns the new event.
    pub fn append_event(
        &mut self,
        kind: CustodyEventKind,
        witness: Option<WitnessSignature>,
    ) -> OmegaResult<&CustodyEvent> {
        if self.destroyed {
            return Err(OmegaError::Comsec(
                "key already destroyed; no further events allowed".into(),
            ));
        }
        let prev_hash = self
            .last_event
            .as_ref()
            .map(|e| e.event_id)
            .unwrap_or([0u8; 32]);
        let mut payload = Vec::with_capacity(160);
        payload.extend_from_slice(&prev_hash);
        payload.extend_from_slice(&self.key_id);
        payload.extend_from_slice(&unix_ms_now().to_le_bytes());
        let kind_json = serde_json::to_vec(&kind)?;
        payload.extend_from_slice(&kind_json);
        let event_id = *blake3::hash(&payload).as_bytes();
        let event = CustodyEvent {
            event_id,
            prev_event_hash: prev_hash,
            key_id: self.key_id,
            timestamp_ms: unix_ms_now(),
            kind,
            witness,
        };
        self.event_chain.push(event.clone());
        self.last_event = Some(event);
        // If this was a destroy event, mark the key destroyed.
        if matches!(
            self.last_event.as_ref().unwrap().kind,
            CustodyEventKind::Destroy { .. }
        ) {
            self.destroyed = true;
        }
        Ok(self.event_chain.last().unwrap())
    }

    /// Issue a `DestroyCertificate` for this key. Marks the key as
    /// destroyed and returns the certificate.
    pub fn issue_destroy_certificate(
        &mut self,
        by: Custodian,
        method: DestructionMethod,
        sha256_of_zeroized: [u8; 32],
        witness: WitnessSignature,
        rationale: impl Into<String>,
        policy_reference: impl Into<String>,
    ) -> OmegaResult<DestroyCertificate> {
        let kind = CustodyEventKind::Destroy {
            by,
            method: method.clone(),
            sha256_of_zeroized,
        };
        self.append_event(kind, Some(witness.clone()))?;
        Ok(DestroyCertificate {
            key_id: self.key_id,
            method,
            sha256_of_zeroized,
            timestamp_ms: unix_ms_now(),
            witnessed_by: witness,
            rationale: rationale.into(),
            policy_reference: policy_reference.into(),
        })
    }

    /// Verify the custody chain. Returns the index of the first
    /// broken event, or None if all events are valid.
    pub fn verify_chain(&self) -> Option<usize> {
        let mut prev = [0u8; 32];
        for (i, e) in self.event_chain.iter().enumerate() {
            if e.prev_event_hash != prev {
                return Some(i);
            }
            let mut payload = Vec::with_capacity(160);
            payload.extend_from_slice(&prev);
            payload.extend_from_slice(&self.key_id);
            payload.extend_from_slice(&e.timestamp_ms.to_le_bytes());
            let kind_json = match serde_json::to_vec(&e.kind) {
                Ok(v) => v,
                Err(_) => return Some(i),
            };
            payload.extend_from_slice(&kind_json);
            let computed = *blake3::hash(&payload).as_bytes();
            if computed != e.event_id {
                return Some(i);
            }
            prev = e.event_id;
        }
        None
    }
}

/// The COMSEC inventory: a map from key_id to ComsecKey.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyInventory {
    keys: BTreeMap<[u8; 32], ComsecKey>,
    /// Append-only list of `DestroyCertificate`s, indexed by key_id.
    destroyed: BTreeMap<[u8; 32], DestroyCertificate>,
}

impl KeyInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: ComsecKey) {
        self.keys.insert(key.key_id, key);
    }

    pub fn get(&self, key_id: &[u8; 32]) -> Option<&ComsecKey> {
        self.keys.get(key_id)
    }

    pub fn get_mut(&mut self, key_id: &[u8; 32]) -> Option<&mut ComsecKey> {
        self.keys.get_mut(key_id)
    }

    pub fn active(&self) -> impl Iterator<Item = &ComsecKey> {
        self.keys.values().filter(|k| !k.destroyed)
    }

    pub fn destroyed(&self) -> impl Iterator<Item = &ComsecKey> {
        self.keys.values().filter(|k| k.destroyed)
    }

    pub fn destroy_certificate(&self, key_id: &[u8; 32]) -> Option<&DestroyCertificate> {
        self.destroyed.get(key_id)
    }

    /// Verify every key's custody chain. Returns the key_id of the
    /// first broken chain, or None if all chains are valid.
    pub fn verify_all(&self) -> Option<[u8; 32]> {
        for (kid, k) in &self.keys {
            if k.verify_chain().is_some() {
                return Some(*kid);
            }
        }
        None
    }

    pub fn total_keys(&self) -> usize {
        self.keys.len()
    }

    pub fn total_destroyed(&self) -> usize {
        self.destroyed.len()
    }

    /// Record a `DestroyCertificate` and remove the live key from the
    /// active inventory.
    pub fn record_destroy(&mut self, cert: DestroyCertificate) -> OmegaResult<()> {
        let key_id = cert.key_id;
        if let Some(k) = self.keys.get_mut(&key_id) {
            k.destroyed = true;
        }
        if self.destroyed.insert(key_id, cert).is_some() {
            return Err(OmegaError::Comsec(
                "duplicate destroy certificate for key".into(),
            ));
        }
        Ok(())
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Custodian {
        Custodian::Operator {
            id: [1u8; 32],
            display_name: "Alice".into(),
        }
    }

    fn bob() -> Custodian {
        Custodian::Operator {
            id: [2u8; 32],
            display_name: "Bob".into(),
        }
    }

    fn carol() -> Custodian {
        Custodian::Operator {
            id: [3u8; 32],
            display_name: "Carol".into(),
        }
    }

    fn witness() -> WitnessSignature {
        WitnessSignature {
            witness_kind: WitnessKind::Auditor {
                id: [9u8; 32],
                name: "Auditor".into(),
            },
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn keygen_event_chain() {
        let mut k = ComsecKey::new(
            "K-001",
            "ML-KEM-768",
            768,
            crate::omega::Classification::Secret,
            alice(),
        );
        let kgen = CustodyEventKind::KeyGen {
            algorithm: "ML-KEM-768".into(),
            key_length_bits: 768,
        };
        k.append_event(kgen, None).unwrap();
        assert_eq!(k.event_chain.len(), 1);
        assert!(k.verify_chain().is_none());
    }

    #[test]
    fn full_lifecycle() {
        let mut k = ComsecKey::new(
            "K-002",
            "AES-256",
            256,
            crate::omega::Classification::TopSecret,
            alice(),
        );
        k.append_event(
            CustodyEventKind::KeyGen {
                algorithm: "AES-256".into(),
                key_length_bits: 256,
            },
            None,
        )
        .unwrap();
        k.append_event(
            CustodyEventKind::Distribute {
                from: alice(),
                to: bob(),
            },
            Some(witness()),
        )
        .unwrap();
        k.append_event(CustodyEventKind::Activate { by: bob() }, None)
            .unwrap();
        let cert = k
            .issue_destroy_certificate(
                bob(),
                DestructionMethod::CryptoErase,
                [0u8; 32],
                witness(),
                "scheduled rotation",
                "NISPOM 8-303",
            )
            .unwrap();
        assert!(k.destroyed);
        assert_eq!(k.event_chain.len(), 4);
        assert!(k.verify_chain().is_none());
        assert_eq!(cert.method, DestructionMethod::CryptoErase);
    }

    #[test]
    fn no_events_after_destroy() {
        let mut k = ComsecKey::new(
            "K-003",
            "AES-256",
            256,
            crate::omega::Classification::Secret,
            alice(),
        );
        k.append_event(
            CustodyEventKind::KeyGen {
                algorithm: "AES-256".into(),
                key_length_bits: 256,
            },
            None,
        )
        .unwrap();
        k.issue_destroy_certificate(
            alice(),
            DestructionMethod::Zero,
            [0u8; 32],
            witness(),
            "test",
            "test",
        )
        .unwrap();
        let err = k
            .append_event(CustodyEventKind::Activate { by: bob() }, None)
            .unwrap_err();
        assert!(matches!(err, OmegaError::Comsec(_)));
    }

    #[test]
    fn inventory_record_destroy() {
        let mut inv = KeyInventory::new();
        let mut k = ComsecKey::new(
            "K-004",
            "AES-256",
            256,
            crate::omega::Classification::Secret,
            alice(),
        );
        k.append_event(
            CustodyEventKind::KeyGen {
                algorithm: "AES-256".into(),
                key_length_bits: 256,
            },
            None,
        )
        .unwrap();
        let cert = k
            .issue_destroy_certificate(
                alice(),
                DestructionMethod::SoftwareZeroize,
                [0u8; 32],
                witness(),
                "test",
                "test",
            )
            .unwrap();
        let kid = k.key_id;
        inv.insert(k);
        inv.record_destroy(cert).unwrap();
        assert!(inv.destroy_certificate(&kid).is_some());
    }

    #[test]
    fn tampered_event_detected() {
        let mut k = ComsecKey::new(
            "K-005",
            "AES-256",
            256,
            crate::omega::Classification::Secret,
            alice(),
        );
        k.append_event(
            CustodyEventKind::KeyGen {
                algorithm: "AES-256".into(),
                key_length_bits: 256,
            },
            None,
        )
        .unwrap();
        // No tampering yet
        assert!(k.verify_chain().is_none());
        // Now corrupt the kind field of the first event in memory and re-verify
        if let CustodyEventKind::KeyGen {
            key_length_bits, ..
        } = &mut k.event_chain[0].kind
        {
            *key_length_bits = 999;
        }
        assert!(k.verify_chain().is_some());
    }

    #[test]
    fn destruction_method_labels_unique() {
        let methods = [
            DestructionMethod::Zero,
            DestructionMethod::Dod522022,
            DestructionMethod::Gutmann,
            DestructionMethod::Random,
            DestructionMethod::CryptoErase,
            DestructionMethod::NvmeFormatUserData,
            DestructionMethod::NvmeFormatCrypto,
            DestructionMethod::AtaSecureErase,
            DestructionMethod::AtaEnhancedSecureErase,
            DestructionMethod::Tpm2Undefine,
            DestructionMethod::SoftwareZeroize,
        ];
        let labels: std::collections::HashSet<_> =
            methods.iter().map(|m| m.label().to_string()).collect();
        assert_eq!(labels.len(), methods.len());
    }
}
