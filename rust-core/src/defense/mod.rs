//! Defensive hardening layer.
//!
//! These modules make Soteria resistant to automated analysis tools,
//! side-channel attacks, and forensic examination. Every feature is
//! passive and defensive — no malware, no active counter-attacks.

pub mod constant_time;
pub mod shamir_recovery;
pub mod tool_confusion;
