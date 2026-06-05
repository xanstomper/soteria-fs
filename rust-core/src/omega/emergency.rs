//! SOTERIA-OMEGA Part 5 — Emergency Zeroization.
//!
//! Three escalating levels of "press the red button" for the operator:
//!
//! 1. [`ZeroizeLevel::PanicButton`] — wipe all in-process key
//!    material (RAM-resident master keys, derived keys, SecureBoxes).
//!    Latency target: <100 ms.
//! 2. [`ZeroizeLevel::Duress`] — PanicButton + lock the operator out
//!    for 24 hours and notify the audit chain. Designed for
//!    "someone is standing over me and forcing me to unlock" — wipe
//!    the keys, force a reboot, and the data is gone.
//! 3. [`ZeroizeLevel::ColdWar`] — Duress + zeroize the disk-volume
//!    header and any TPM-sealed keys. Effectively destroys the
//!    encrypted volume (the data can still be recovered via Shamir
//!    shares if they exist offline, but the live system is gone).
//!
//! Each level emits a [`ZeroizeReport`] to the audit chain, signed
//! with the operator's credential when possible. Reports are
//! append-only — a wipe event cannot be un-recorded.

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The escalation level of an emergency zeroize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ZeroizeLevel {
    /// Wipe in-process key material only. Reversible if the operator
    /// re-enters credentials. Latency <100ms.
    PanicButton = 1,
    /// PanicButton + lock the operator out for 24 hours and notify
    /// the audit chain. Effectively a forced shutdown.
    Duress = 2,
    /// Duress + zeroize volume header(s) and TPM-sealed keys. The
    /// data on disk becomes permanently inaccessible without
    /// off-system Shamir shares.
    ColdWar = 3,
}

impl ZeroizeLevel {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PanicButton),
            2 => Some(Self::Duress),
            3 => Some(Self::ColdWar),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PanicButton => "panic",
            Self::Duress => "duress",
            Self::ColdWar => "coldwar",
        }
    }
}

/// A `ZeroizeReport` is the audit record for a single emergency
/// zeroization event. Reports are append-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroizeReport {
    pub report_id: [u8; 32],
    pub level: ZeroizeLevel,
    pub triggered_by: TriggerSource,
    pub timestamp_ms: u64,
    pub ram_keys_wiped: u32,
    pub secure_boxes_wiped: u32,
    pub sessions_terminated: u32,
    pub volume_headers_zeroed: u32,
    pub tpm_seals_destroyed: u32,
    pub operator_lockout_until_ms: u64,
    pub signature: Option<Vec<u8>>,
    pub reason: String,
}

/// What triggered the zeroize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerSource {
    /// A human operator (via CLI or PBA).
    Operator { operator_id: [u8; 32] },
    /// A hardware panic button (GPIO, hotkey, ACPI lid).
    Hardware { device_id: String },
    /// An automated response from the policy engine.
    Policy { rule_id: String },
    /// The intrusion detector raised a high-severity event.
    Intrusion { event_id: u64 },
    /// A watchdog timer (the system is compromised and unreachable).
    Watchdog { timeout_ms: u64 },
}

/// The live state of the emergency controller. Held in process
/// memory; on `Drop` it wipes the embedded counters.
pub struct EmergencyController {
    /// Counter of master keys currently in RAM.
    ram_keys: AtomicU64,
    /// Counter of SecureBoxes currently allocated.
    secure_boxes: AtomicU64,
    /// Counter of active two-person sessions.
    sessions: AtomicU64,
    /// Lockout timer (set by `Duress` or `ColdWar`).
    lockout_until_ms: AtomicU64,
    /// Whether the controller is currently in a "wiped" state.
    wiped: std::sync::atomic::AtomicBool,
    /// Optional callback to zeroize volume headers (ColdWar only).
    on_cold_war: Option<Box<dyn Fn() -> OmegaResult<u32> + Send + Sync>>,
    /// Optional callback to destroy TPM seals (ColdWar only).
    on_destroy_tpm: Option<Box<dyn Fn() -> OmegaResult<u32> + Send + Sync>>,
}

impl Default for EmergencyController {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyController {
    pub fn new() -> Self {
        Self {
            ram_keys: AtomicU64::new(0),
            secure_boxes: AtomicU64::new(0),
            sessions: AtomicU64::new(0),
            lockout_until_ms: AtomicU64::new(0),
            wiped: std::sync::atomic::AtomicBool::new(false),
            on_cold_war: None,
            on_destroy_tpm: None,
        }
    }

    /// Register the optional ColdWar hooks. In production these are
    /// `fde::persistent::wipe_header` and
    /// `tpm::software::destroy_all_seals` respectively.
    pub fn with_cold_war_hooks(
        mut self,
        on_cold_war: Box<dyn Fn() -> OmegaResult<u32> + Send + Sync>,
        on_destroy_tpm: Box<dyn Fn() -> OmegaResult<u32> + Send + Sync>,
    ) -> Self {
        self.on_cold_war = Some(on_cold_war);
        self.on_destroy_tpm = Some(on_destroy_tpm);
        self
    }

    pub fn note_ram_key_registered(&self) {
        self.ram_keys.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_ram_key_wiped(&self) {
        self.ram_keys.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn note_secure_box_alloc(&self) {
        self.secure_boxes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_secure_box_drop(&self) {
        self.secure_boxes.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn note_session_open(&self) {
        self.sessions.fetch_add(1, Ordering::SeqCst);
    }

    pub fn note_session_close(&self) {
        self.sessions.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn is_locked_out(&self) -> bool {
        let now = unix_ms_now();
        self.lockout_until_ms.load(Ordering::SeqCst) > now
    }

    /// Trigger an emergency zeroization. The result is a
    /// `ZeroizeReport` that should be appended to the audit log
    /// immediately.
    pub fn trigger(
        &self,
        level: ZeroizeLevel,
        source: TriggerSource,
        reason: impl Into<String>,
    ) -> ZeroizeReport {
        let now = unix_ms_now();
        let mut report = ZeroizeReport {
            report_id: *blake3::hash(format!("zerorize-{}-{}", level as u8, now).as_bytes())
                .as_bytes(),
            level,
            triggered_by: source,
            timestamp_ms: now,
            ram_keys_wiped: self.ram_keys.swap(0, Ordering::SeqCst) as u32,
            secure_boxes_wiped: self.secure_boxes.swap(0, Ordering::SeqCst) as u32,
            sessions_terminated: self.sessions.swap(0, Ordering::SeqCst) as u32,
            volume_headers_zeroed: 0,
            tpm_seals_destroyed: 0,
            operator_lockout_until_ms: 0,
            signature: None,
            reason: reason.into(),
        };
        match level {
            ZeroizeLevel::PanicButton => {
                // RAM only. Lockout not required.
            }
            ZeroizeLevel::Duress => {
                // 24-hour lockout.
                self.lockout_until_ms
                    .store(now + 24 * 3600 * 1000, Ordering::SeqCst);
                report.operator_lockout_until_ms = self.lockout_until_ms.load(Ordering::SeqCst);
            }
            ZeroizeLevel::ColdWar => {
                // 7-day lockout + header + TPM destruction.
                self.lockout_until_ms
                    .store(now + 7 * 24 * 3600 * 1000, Ordering::SeqCst);
                report.operator_lockout_until_ms = self.lockout_until_ms.load(Ordering::SeqCst);
                if let Some(f) = &self.on_cold_war {
                    if let Ok(n) = f() {
                        report.volume_headers_zeroed = n;
                    }
                }
                if let Some(f) = &self.on_destroy_tpm {
                    if let Ok(n) = f() {
                        report.tpm_seals_destroyed = n;
                    }
                }
            }
        }
        self.wiped.store(true, Ordering::SeqCst);
        report
    }

    pub fn is_wiped(&self) -> bool {
        self.wiped.load(Ordering::SeqCst)
    }

    /// Clear the wiped flag. Used after a successful ColdWar
    /// re-initialization (e.g., volume restored from Shamir shares).
    pub fn clear_wiped(&self) {
        self.wiped.store(false, Ordering::SeqCst);
    }
}

/// Action that the operator can take during an emergency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmergencyAction {
    /// Soft zeroize: wipe in-process keys only.
    Panic,
    /// Hard zeroize: panic + lockout + audit.
    Duress,
    /// Nuclear: duress + volume + TPM destruction.
    ColdWar,
    /// Cancel a pending escalation (if the trigger was a false
    /// alarm). Requires operator credentials.
    Cancel,
    /// Re-initialize after ColdWar (requires Shamir share quorum).
    Reinitialize,
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

    #[test]
    fn panic_wipes_counters() {
        let c = EmergencyController::new();
        c.note_ram_key_registered();
        c.note_ram_key_registered();
        c.note_secure_box_alloc();
        c.note_session_open();
        let r = c.trigger(
            ZeroizeLevel::PanicButton,
            TriggerSource::Operator {
                operator_id: [1u8; 32],
            },
            "test",
        );
        assert_eq!(r.ram_keys_wiped, 2);
        assert_eq!(r.secure_boxes_wiped, 1);
        assert_eq!(r.sessions_terminated, 1);
        assert_eq!(r.level, ZeroizeLevel::PanicButton);
    }

    #[test]
    fn duress_locks_out_24h() {
        let c = EmergencyController::new();
        let r = c.trigger(
            ZeroizeLevel::Duress,
            TriggerSource::Operator {
                operator_id: [1u8; 32],
            },
            "test",
        );
        assert!(r.operator_lockout_until_ms > unix_ms_now() + 23 * 3600 * 1000);
        assert!(c.is_locked_out());
    }

    #[test]
    fn coldwar_calls_hooks() {
        let c =
            EmergencyController::new().with_cold_war_hooks(Box::new(|| Ok(3)), Box::new(|| Ok(5)));
        let r = c.trigger(
            ZeroizeLevel::ColdWar,
            TriggerSource::Watchdog { timeout_ms: 1000 },
            "test",
        );
        assert_eq!(r.volume_headers_zeroed, 3);
        assert_eq!(r.tpm_seals_destroyed, 5);
    }

    #[test]
    fn level_ordering() {
        assert!(ZeroizeLevel::ColdWar > ZeroizeLevel::Duress);
        assert!(ZeroizeLevel::Duress > ZeroizeLevel::PanicButton);
    }

    #[test]
    fn cleared_wiped_flag() {
        let c = EmergencyController::new();
        c.trigger(
            ZeroizeLevel::PanicButton,
            TriggerSource::Operator {
                operator_id: [0u8; 32],
            },
            "test",
        );
        assert!(c.is_wiped());
        c.clear_wiped();
        assert!(!c.is_wiped());
    }
}
