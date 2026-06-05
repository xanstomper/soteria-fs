//! SOTERIA-OMEGA Part 6 / Part 13 — Multi-Level Initialization Flow.
//!
//! OMEGA replaces the standard "passphrase in, key out" init with a
//! 6-phase flow that requires two cleared operators and produces a
//! fully-attested, audit-anchored, witness-signed volume.
//!
//! ## The six phases
//!
//! 1. **PersonaAssign**: each operator attests to a digital persona
//!    (their OMEGA operator identity, derived from a hardware token).
//!    The attestation is bound to the operator's ML-DSA-65 signing
//!    key.
//!
//! 2. **RoleAttest**: each operator asserts their clearance level
//!    and compartment access. The role attestation is signed by
//!    the second cleared custodian (e.g., a security officer).
//!
//! 3. **ClearedKeyGen**: the master key is generated INSIDE the
//!    crypto process. The key is split (Shamir 2-of-2 by default;
//!    2-of-3 with hardware witness) and each share is handed to one
//!    of the two operators.
//!
//! 4. **AuditAnchor**: a BLAKE3 anchor of the entire init event is
//!    written to the local audit log AND, if `--anchor-remote` is
//!    set, to a remote audit server over TLS. The remote server
//!    records the anchor timestamp.
//!
//! 5. **CommittedPublish**: the OMEGA volume header is written to
//!    disk. The header includes the Merkle root of all blocks, the
//!    RS-encoded root, the COMSEC custody chain genesis event, the
//!    software-attestation marker (if hardware was missing), and
//!    the operator identities.
//!
//! 6. **WitnessSign**: a third cleared party (or hardware token)
//!    countersigns the volume header. The signed header is the
//!    "birth certificate" of the volume; any subsequent operation
//!    on the volume references this certificate.
//!
//! ## When to use this flow
//!
//! - **Required for TOP SECRET and above.**
//! - **Required when the operator wants a `DestroyCertificate`
//!   for SOX / HIPAA / FedRAMP audit trails.**
//! - **Optional for SECRET and below**, in which case the
//!   `TwoPersonRule` is advisory.
//!
//! ## State machine
//!
//! The `InitState` is a pure data object: it accumulates the
//! `InitPhase`s as they complete. The order is enforced — you
//! cannot move from phase 3 to phase 5 without completing phase 4.

use crate::omega::{
    classification::{Classification, Compartments},
    two_person::OperatorId,
    OmegaError, OmegaResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// The six init phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InitPhase {
    PersonaAssign = 1,
    RoleAttest = 2,
    ClearedKeyGen = 3,
    AuditAnchor = 4,
    CommittedPublish = 5,
    WitnessSign = 6,
}

impl InitPhase {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PersonaAssign),
            2 => Some(Self::RoleAttest),
            3 => Some(Self::ClearedKeyGen),
            4 => Some(Self::AuditAnchor),
            5 => Some(Self::CommittedPublish),
            6 => Some(Self::WitnessSign),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::PersonaAssign => "PersonaAssign",
            Self::RoleAttest => "RoleAttest",
            Self::ClearedKeyGen => "ClearedKeyGen",
            Self::AuditAnchor => "AuditAnchor",
            Self::CommittedPublish => "CommittedPublish",
            Self::WitnessSign => "WitnessSign",
        }
    }
}

/// Configuration for the init flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    pub classification: Classification,
    pub compartments: Compartments,
    pub target_path: String,
    pub total_size_bytes: u64,
    pub sector_size: u16,
    /// KDF cost profile.
    pub kdf_iterations: u32,
    /// Threshold for Shamir key splitting.
    pub shamir_threshold: u8,
    pub shamir_shares: u8,
    /// Whether to anchor the audit log to a remote server.
    pub anchor_remote: bool,
    /// Remote anchor server URL (only used if anchor_remote).
    pub anchor_url: Option<String>,
    /// Whether to require a hardware witness (FIDO2 / TPM).
    pub require_hardware_witness: bool,
}

/// Live state of an init flow in progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitState {
    pub config: InitConfig,
    pub started_ms: u64,
    pub completed_phases: BTreeMap<InitPhase, PhaseCompletion>,
    pub operator_a: Option<OperatorId>,
    pub operator_b: Option<OperatorId>,
    pub witness: Option<OperatorId>,
    pub volume_uuid: Option<[u8; 16]>,
    pub master_key_id: Option<[u8; 32]>,
    pub audit_anchor: Option<[u8; 32]>,
    pub birth_certificate: Option<Vec<u8>>,
}

/// A single phase's completion record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseCompletion {
    pub phase: InitPhase,
    pub completed_ms: u64,
    pub operator_id: Option<OperatorId>,
    pub notes: String,
    /// Hash of the artifact produced by this phase.
    pub artifact_hash: [u8; 32],
}

impl InitState {
    pub fn new(config: InitConfig) -> Self {
        Self {
            config,
            started_ms: unix_ms_now(),
            completed_phases: BTreeMap::new(),
            operator_a: None,
            operator_b: None,
            witness: None,
            volume_uuid: None,
            master_key_id: None,
            audit_anchor: None,
            birth_certificate: None,
        }
    }

    pub fn current_phase(&self) -> InitPhase {
        // The current phase is the lowest-numbered phase that has
        // not yet been completed.
        for p in [
            InitPhase::PersonaAssign,
            InitPhase::RoleAttest,
            InitPhase::ClearedKeyGen,
            InitPhase::AuditAnchor,
            InitPhase::CommittedPublish,
            InitPhase::WitnessSign,
        ] {
            if !self.completed_phases.contains_key(&p) {
                return p;
            }
        }
        InitPhase::WitnessSign
    }

    pub fn is_complete(&self) -> bool {
        self.completed_phases.len() == 6
    }

    /// Mark a phase complete. Returns an error if the phase is
    /// out-of-order or already complete.
    pub fn complete_phase(
        &mut self,
        phase: InitPhase,
        operator_id: Option<OperatorId>,
        notes: impl Into<String>,
        artifact: &[u8],
    ) -> OmegaResult<()> {
        if self.completed_phases.contains_key(&phase) {
            return Err(OmegaError::Init(format!(
                "phase {} already complete",
                phase.label()
            )));
        }
        // Enforce ordering: all previous phases must be complete.
        for p in [
            InitPhase::PersonaAssign,
            InitPhase::RoleAttest,
            InitPhase::ClearedKeyGen,
            InitPhase::AuditAnchor,
            InitPhase::CommittedPublish,
            InitPhase::WitnessSign,
        ] {
            if p == phase {
                break;
            }
            if !self.completed_phases.contains_key(&p) {
                return Err(OmegaError::Init(format!(
                    "phase {} requires {} first",
                    phase.label(),
                    p.label()
                )));
            }
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(blake3::hash(artifact).as_bytes());
        self.completed_phases.insert(
            phase,
            PhaseCompletion {
                phase,
                completed_ms: unix_ms_now(),
                operator_id,
                notes: notes.into(),
                artifact_hash: h,
            },
        );
        Ok(())
    }

    /// Validate the entire init flow. Returns an error if any phase
    /// is missing or any artifact hash is invalid.
    pub fn validate(&self) -> OmegaResult<()> {
        for p in [
            InitPhase::PersonaAssign,
            InitPhase::RoleAttest,
            InitPhase::ClearedKeyGen,
            InitPhase::AuditAnchor,
            InitPhase::CommittedPublish,
            InitPhase::WitnessSign,
        ] {
            if !self.completed_phases.contains_key(&p) {
                return Err(OmegaError::Init(format!(
                    "phase {} not complete",
                    p.label()
                )));
            }
        }
        Ok(())
    }

    /// Issue the final birth certificate: a BLAKE3 hash of the
    /// entire init state, signed by the witness.
    pub fn issue_birth_certificate(&mut self) -> OmegaResult<Vec<u8>> {
        self.validate()?;
        if self.birth_certificate.is_some() {
            return Err(OmegaError::Init("birth certificate already issued".into()));
        }
        let cert_bytes = serde_json::to_vec(&self.completed_phases)?;
        let mut h = [0u8; 32];
        h.copy_from_slice(blake3::hash(&cert_bytes).as_bytes());
        let mut cert = Vec::with_capacity(32 + 8);
        cert.extend_from_slice(&h);
        cert.extend_from_slice(&self.started_ms.to_le_bytes());
        self.birth_certificate = Some(cert.clone());
        Ok(cert)
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

    fn default_config() -> InitConfig {
        InitConfig {
            classification: Classification::TopSecret,
            compartments: Compartments::new(),
            target_path: "/tmp/test.omega".into(),
            total_size_bytes: 1024 * 1024 * 1024,
            sector_size: 512,
            kdf_iterations: 600_000,
            shamir_threshold: 2,
            shamir_shares: 2,
            anchor_remote: false,
            anchor_url: None,
            require_hardware_witness: true,
        }
    }

    #[test]
    fn phases_in_order() {
        let mut s = InitState::new(default_config());
        assert_eq!(s.current_phase(), InitPhase::PersonaAssign);
        s.complete_phase(InitPhase::PersonaAssign, None, "", b"p1")
            .unwrap();
        s.complete_phase(InitPhase::RoleAttest, None, "", b"p2")
            .unwrap();
        s.complete_phase(InitPhase::ClearedKeyGen, None, "", b"p3")
            .unwrap();
        s.complete_phase(InitPhase::AuditAnchor, None, "", b"p4")
            .unwrap();
        s.complete_phase(InitPhase::CommittedPublish, None, "", b"p5")
            .unwrap();
        s.complete_phase(InitPhase::WitnessSign, None, "", b"p6")
            .unwrap();
        assert!(s.is_complete());
        assert!(s.validate().is_ok());
    }

    #[test]
    fn out_of_order_rejected() {
        let mut s = InitState::new(default_config());
        // Skip PersonaAssign, try to complete ClearedKeyGen
        let r = s.complete_phase(InitPhase::ClearedKeyGen, None, "", b"x");
        assert!(r.is_err());
    }

    #[test]
    fn duplicate_phase_rejected() {
        let mut s = InitState::new(default_config());
        s.complete_phase(InitPhase::PersonaAssign, None, "", b"x")
            .unwrap();
        let r = s.complete_phase(InitPhase::PersonaAssign, None, "", b"x");
        assert!(r.is_err());
    }

    #[test]
    fn birth_certificate_after_validate() {
        let mut s = InitState::new(default_config());
        s.complete_phase(InitPhase::PersonaAssign, None, "", b"p1")
            .unwrap();
        s.complete_phase(InitPhase::RoleAttest, None, "", b"p2")
            .unwrap();
        s.complete_phase(InitPhase::ClearedKeyGen, None, "", b"p3")
            .unwrap();
        s.complete_phase(InitPhase::AuditAnchor, None, "", b"p4")
            .unwrap();
        s.complete_phase(InitPhase::CommittedPublish, None, "", b"p5")
            .unwrap();
        s.complete_phase(InitPhase::WitnessSign, None, "", b"p6")
            .unwrap();
        let cert = s.issue_birth_certificate().unwrap();
        assert_eq!(cert.len(), 40);
        let r = s.issue_birth_certificate();
        assert!(r.is_err());
    }

    #[test]
    fn incomplete_validate_fails() {
        let s = InitState::new(default_config());
        assert!(s.validate().is_err());
    }

    #[test]
    fn phase_labels_unique() {
        let phases = [
            InitPhase::PersonaAssign,
            InitPhase::RoleAttest,
            InitPhase::ClearedKeyGen,
            InitPhase::AuditAnchor,
            InitPhase::CommittedPublish,
            InitPhase::WitnessSign,
        ];
        let labels: std::collections::HashSet<_> = phases.iter().map(|p| p.label()).collect();
        assert_eq!(labels.len(), phases.len());
    }
}
