//! SOTERIA library root.
//!
//! Module organization is **strictly layered**:
//!
//! - **TCB modules** (always compiled, no feature flag) implement
//!   the cryptographic core, full-disk encryption, filesystem,
//!   and the canonical key management surface. Auditing these is
//!   sufficient to evaluate Soteria's security guarantees.
//!
//! - **Extras modules** are gated behind Cargo features and are
//!   *not* in the trusted computing base (TCB). They add
//!   policy, UX, intrusion detection, anti-forensic, deception,
//!   AI observation, and other ancillary features that are
//!   useful in deployment but are not security-critical.
//!
//! See `docs/TCB.md` for the canonical TCB definition and the
//! rationale for each gate.

// =====================================================================
// TCB (Trusted Computing Base) — always compiled.
// =====================================================================
pub mod config;
pub mod crypto_engine;
pub mod daemon;
pub mod erasure_coding;
pub mod fde;
pub mod fs_layer;
pub mod key_hierarchy;
pub mod metadata_encryption;
pub mod secure_erase;

pub type Result<T> = anyhow::Result<T>;

// =====================================================================
// Extras — gated behind Cargo features. NOT in the TCB.
// =====================================================================

/// Government / military OMEGA features (classification, two-person,
/// TEMPEST, COMSEC, emergency zeroize, sovereignty, crypto-process,
/// Merkle/RS integrity, ransomware defense, hardware roots).
#[cfg(feature = "omega")]
pub mod omega;

/// Defense subsystem: intrusion detection, sensors, response
/// engine, event bus, anti-forensic measures.
#[cfg(feature = "defense")]
pub mod defense;
#[cfg(feature = "defense")]
pub mod event_bus;
#[cfg(feature = "defense")]
pub mod intrusion;
#[cfg(feature = "defense")]
pub mod response_engine;
#[cfg(feature = "defense")]
pub mod sensors;

/// Deception: decoy content, recursive hell, rate griefing, honey
/// filesystem. Operational-misleading modules; not in the TCB.
#[cfg(feature = "deception")]
pub mod deception;
#[cfg(feature = "deception")]
pub mod deception_layer;

/// Anti-forensic: header scatter, temporal erase, timestamp warp,
/// entropy padding. These affect the on-disk appearance of data.
#[cfg(feature = "anti-forensic")]
pub mod anti_forensic;

/// Advanced / experimental: chameleon, obsidian, mirage_fs. These
/// are research-grade.
#[cfg(feature = "advanced")]
pub mod advanced;

/// Read-only AI observer (heuristic, no model weights, no network).
/// Off by default; included for the SOTERIA-OMEGA observer module.
#[cfg(feature = "ai-observer")]
pub mod ai_observer;

/// Key management utilities beyond the canonical `key_hierarchy`
/// (lifecycle, ratchet, capability, TPM keyring). The TCB key
/// surface is `key_hierarchy`; this is a richer management plane.
#[cfg(feature = "key-manager")]
pub mod key_manager;

/// Policy and audit log (revocation lists, audit trail).
#[cfg(feature = "policy")]
pub mod policy;

/// TPM2 hardware backend (vs. software stub in `fde::tpm_seal`).
/// Real silicon path; software fallback is the default.
#[cfg(feature = "tpm")]
pub mod tpm;

/// Anomaly detection (sensor fusion, canaries). Defense-adjacent.
#[cfg(feature = "security")]
pub mod security;

/// Snapshot / copy-on-write engine. Optional; not in the TCB.
#[cfg(feature = "snapshot")]
pub mod snapshot_engine;

/// Ransomware simulation / red-team tooling. NOT in production
/// builds; gated to a feature that's never enabled in release.
#[cfg(feature = "simulation")]
pub mod simulation;

/// Enterprise / multi-tenant glue (single module).
#[cfg(feature = "enterprise")]
pub mod enterprise;

/// Native terminal UI (ratatui + crossterm).
#[cfg(feature = "tui")]
pub mod tui;
