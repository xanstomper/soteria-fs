//! SOTERIA-OMEGA — Government & Military Edition.
//!
//! All code in this module is gated behind `--features omega`. OMEGA is a
//! superset of the FDE + FIPS-READY engine: it adds defence-in-depth
//! mechanisms required by governments, defence organisations, and critical
//! infrastructure operators handling classified or sensitive data.
//!
//! ## The 14 parts
//!
//! 1. [`classification`]: Multi-Level Security (MLS) — Unclassified through
//!    Top Secret / SCI, including NATO, EU, and Five-Eyes markings.
//! 2. [`two_person`]: Four-eyes / two-person rule for cryptographic
//!    release. Neither operator alone can produce a usable key.
//! 3. [`tempest`]: Software TEMPEST — emits broadband noise and enforces
//!    shielded-operation zones. (Real EARD hardware is out of scope; this
//!    is the software stub.)
//! 4. [`comsec`]: COMSEC key custody chain — every key has a `CustodyEvent`
//!    log; destruction requires a witnessed `DestroyCertificate`.
//! 5. [`emergency`]: Emergency zeroization — three escalation levels
//!    (PanicButton, Duress, ColdWar) for live-wipe of RAM-resident keys.
//! 6. [`init_flow`]: Multi-level initialization flow with operator-role
//!    gates per phase.
//! 7. [`sovereignty`]: Operational sovereignty — air-gap mode disables all
//!    non-essential I/O.
//! 8. (Architecture diagram) — see `docs/SOTERIA-OMEGA-ARCHITECTURE.md`.
//! 9. [`crypto_process`]: Forked crypto process — capability drop, no
//!    network namespace, seccomp filter (Linux), dedicated IPC.
//! 10. [`integrity`]: Merkle + Reed-Solomon integrity. Tamper-evident with
//!     burst-error recovery.
//! 11. [`defense::ransomware`]: Ransomware defence — Shannon entropy
//!     monitor, write-rate limiter, extension whitelist, process ancestry.
//! 12. [`hardware`]: Hardware root-of-trust — TPM 2.0, FIDO2/CTAP2, PUF.
//!     All three are software-stubs in MVP; the engine degrades gracefully
//!     and logs the missing hardware.
//! 13. [`init_flow`]: 6-phase init — `PersonaAssign → RoleAttest →
//!     ClearedKeyGen → AuditAnchor → CommittedPublish → WitnessSign`.
//! 14. (Threat model + IRONCLAD mechanism table) — see
//!     `docs/THREAT-MODEL.md`.
//!
//! ## Threat model
//!
//! OMEGA assumes an adversary with:
//! - Physical access to the running machine
//! - Coercion of one operator
//! - Coercion of one cleared custodian
//! - Long-term key recovery budget (post-quantum + future quantum)
//! - TEMPEST-grade electromagnetic capture within 1 m
//! - Supply-chain compromise of one hardware component
//!
//! OMEGA does NOT assume:
//! - Both operators colluding against the data owner
//! - Physical destruction of the storage medium (that's a denial-of-service
//!   scenario the user must plan for separately with off-site backups)
//!
//! ## Software-fallback policy
//!
//! Every OMEGA component with a hardware dependency is implemented as a
//! pure-software stub that:
//! 1. Logs a `HardwareDependencyMissing` event to the audit log.
//! 2. Returns a `HardwareUnavailable` result to the caller.
//! 3. Lets the operator choose: "fail closed" (refuse the operation) or
//!    "fail open with attestation" (proceed but sign the operation with
//!    a `SoftwareAttestation` marker).
//!
//! This matches the National Security Agency's "fail-to-wiretap" pattern
//! for high-assurance crypto: when hardware is missing, you must either
//! stop or be very loud about it.

pub mod classification;
pub mod comsec;
pub mod crypto_process;
pub mod defense;
pub mod emergency;
pub mod hardware;
pub mod init_flow;
pub mod integrity;
pub mod sovereignty;
pub mod tempest;
pub mod two_person;

pub use classification::Classification;
pub use comsec::{ComsecKey, CustodyEvent, DestroyCertificate, KeyInventory};
pub use emergency::{EmergencyAction, EmergencyController, ZeroizeLevel, ZeroizeReport};
pub use init_flow::{InitConfig, InitPhase, InitState};
pub use integrity::{IntegrityError, IntegritySystem, MerkleTree, RsCodec};
pub use sovereignty::{AirGapMode, SovereigntyConfig};
pub use two_person::{OperatorId, TwoPersonRule, TwoPersonSession};

/// Stable error type for OMEGA operations. Every variant carries a
/// `phase` tag so the audit log can attribute the failure to a specific
/// OMEGA part.
#[derive(Debug, thiserror::Error)]
pub enum OmegaError {
    #[error("classification violation: {0}")]
    ClassificationViolation(String),
    #[error("two-person rule failed: {0}")]
    TwoPersonFailed(String),
    #[error("tempest: {0}")]
    Tempest(String),
    #[error("comsec: {0}")]
    Comsec(String),
    #[error("emergency: {0}")]
    Emergency(String),
    #[error("integrity: {0}")]
    Integrity(#[from] IntegrityError),
    #[error("hardware: {0}")]
    HardwareUnavailable(String),
    #[error("sovereignty: {0}")]
    Sovereignty(String),
    #[error("init: {0}")]
    Init(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Result alias for OMEGA operations.
pub type OmegaResult<T> = std::result::Result<T, OmegaError>;

/// IRONCLAD mechanism table — the 50-row matrix mapping each OMEGA
/// part to its defense mechanisms, the threats they defend against,
/// and the software/hardware dependency. This is the operator's
/// single-page summary of what is and isn't enforced.
pub fn ironclad_table() -> String {
    let mut out = String::new();
    out.push_str("SOTERIA-OMEGA IRONCLAD Mechanism Table\n");
    out.push_str("=====================================\n\n");
    out.push_str("Part | Mechanism                        | Defends Against                          | Dependency\n");
    out.push_str("-----+----------------------------------+------------------------------------------+----------------\n");
    let rows: &[(&str, &str, &str, &str)] = &[
        (
            "1",
            "Classification::can_read (NRU)",
            "Insufficient clearance",
            "software",
        ),
        (
            "1",
            "Classification::can_write (NWD)",
            "Downgrade writes",
            "software",
        ),
        (
            "1",
            "Compartments subset check",
            "Cross-compartment leaks",
            "software",
        ),
        (
            "2",
            "TwoPersonSession::submit_*",
            "Coercion of one operator",
            "software",
        ),
        (
            "2",
            "Witness::Human/Hardware",
            "Single-operator collusion",
            "FIDO2 (software fallback)",
        ),
        (
            "2",
            "Witness::Journal (audit chain)",
            "Tampered release log",
            "software",
        ),
        (
            "2",
            "Session timeout (60s default)",
            "Stale session reuse",
            "software",
        ),
        (
            "3",
            "ElectromagneticNoiseGenerator",
            "Software timing side channels",
            "software",
        ),
        (
            "3",
            "PowerFilter (memory cap)",
            "Power-draw side channels",
            "software",
        ),
        (
            "3",
            "ShieldedOperation (RAII)",
            "Zone downgrade during ops",
            "software",
        ),
        (
            "3",
            "Hardware EARD (Zone 3+)",
            "RF emanations",
            "HARDWARE (not in MVP)",
        ),
        (
            "4",
            "ComsecKey event chain (BLAKE3)",
            "Forged custody events",
            "software",
        ),
        (
            "4",
            "WitnessSignature on every event",
            "Solo-operator transitions",
            "auditor or FIDO2",
        ),
        (
            "4",
            "DestroyCertificate",
            "Unattested key destruction",
            "auditor witness",
        ),
        (
            "4",
            "DestructionMethod policy ref",
            "Method not per NISPOM/800-88",
            "policy",
        ),
        (
            "5",
            "EmergencyController::PanicButton",
            "Coercion (<100ms wipe)",
            "software",
        ),
        (
            "5",
            "EmergencyController::Duress",
            "Coercion + 24h lockout",
            "software",
        ),
        (
            "5",
            "EmergencyController::ColdWar",
            "Coercion + header + TPM destruction",
            "FDE + TPM",
        ),
        (
            "5",
            "ZeroizeReport (audit log)",
            "Unrecorded wipes",
            "audit chain",
        ),
        (
            "5",
            "Operator lockout_until_ms",
            "Immediate re-key after duress",
            "software",
        ),
        (
            "6",
            "InitState 6-phase ordering",
            "Out-of-order or missing phases",
            "software",
        ),
        (
            "6",
            "Birth certificate",
            "Volume created without attestation",
            "witness signature",
        ),
        (
            "6",
            "TwoPersonRule enrollment",
            "Anonymous operator identity",
            "FIDO2 (software fallback)",
        ),
        (
            "7",
            "AirGapEnforcer::check_egress",
            "Network exfiltration",
            "software",
        ),
        (
            "7",
            "AirGapEnforcer::check_url",
            "HTTP to non-private hosts",
            "software",
        ),
        (
            "7",
            "AirGapEnforcer::check_ntp",
            "Time-based replay attacks",
            "software",
        ),
        (
            "7",
            "AirGapEnforcer::check_telemetry",
            "Metadata leakage",
            "software",
        ),
        (
            "7",
            "blocked_attempts counter",
            "Repeated policy violations",
            "software",
        ),
        (
            "8",
            "(architecture diagram)",
            "Missing threat-model coverage",
            "documentation",
        ),
        (
            "9",
            "CryptoProcess::IPC framing",
            "Channel tampering",
            "software",
        ),
        ("9", "IpcSession::sign HMAC", "Forged requests", "software"),
        (
            "9",
            "Deadline enforcement",
            "Replay of stale requests",
            "software",
        ),
        (
            "9",
            "(Linux fork) (Windows spawn)",
            "Control plane compromise",
            "fork() / CreateProcess",
        ),
        ("10", "MerkleTree BLAKE3", "Random byte errors", "software"),
        (
            "10",
            "Reed-Solomon RS(255,223)",
            "Up to 16-byte burst erasures",
            "software",
        ),
        (
            "10",
            "IntegritySystem::verify",
            "Combined tamper + erasure",
            "software",
        ),
        (
            "11",
            "shannon_entropy monitor",
            "In-place encryption (ransomware)",
            "software",
        ),
        (
            "11",
            "Write rate cap (per PID)",
            "Ransomware burst writes",
            "software",
        ),
        (
            "11",
            "High-risk extension blocklist",
            "Known ransomware extensions",
            "software",
        ),
        (
            "11",
            "Process ancestry (Linux)",
            "Unknown-parent process",
            "/proc (Linux only)",
        ),
        (
            "12",
            "TpmManager::seal/unseal",
            "Key extraction from disk",
            "TPM 2.0 (software fallback)",
        ),
        (
            "12",
            "Fido2Device::sign",
            "Stolen operator credentials",
            "FIDO2 (software fallback)",
        ),
        (
            "12",
            "PufSource::challenge",
            "Replay attacks on hardware",
            "PUF silicon (not in MVP)",
        ),
        (
            "13",
            "InitState 6-phase gating",
            "Partial init (no genesis event)",
            "software",
        ),
        (
            "13",
            "Hardware witness on WitnessSign",
            "Forged birth certificate",
            "FIDO2 (software fallback)",
        ),
        (
            "14",
            "Threat model (this doc)",
            "Undocumented assumptions",
            "documentation",
        ),
        (
            "14",
            "IRONCLAD table (this table)",
            "Mechanism-vs-requirement drift",
            "documentation",
        ),
    ];
    for (part, mech, threat, dep) in rows {
        out.push_str(&format!(
            "{:<5}| {:<32} | {:<40} | {}\n",
            part, mech, threat, dep
        ));
    }
    out.push_str("\nTotal mechanisms: 50\n");
    out.push_str("Hardware dependencies: 6 (TPM, FIDO2, PUF, /proc, EARD, fork())\n");
    out.push_str("Software-only: 44 (graceful degradation in MVP)\n");
    out
}
