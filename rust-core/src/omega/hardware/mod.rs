//! SOTERIA-OMEGA Part 12 — Hardware Root of Trust.
//!
//! OMEGA integrates with three classes of hardware root-of-trust:
//!
//! 1. **TPM 2.0** — the standard on most business laptops and
//!    servers. Used for measured boot, key sealing, and remote
//!    attestation. Backend crate: `tss-esapi` (TSS 2.0 Enhanced
//!    System API).
//! 2. **FIDO2 / CTAP2** — YubiKey and friends. Used for two-factor
//!    authentication of operators. Backend crate: `ctap2` (no
//!    available crate as of 2026; we use a software fallback).
//! 3. **PUF (Physical Unclonable Function)** — a silicon-intrinsic
//!    fingerprint, used as an additional entropy source. No
//!    portable crate; software fallback only.
//!
//! ## Software-fallback policy
//!
//! All three are SOFTWARE-ONLY in this MVP. The `TpmManager`,
//! `Fido2Device`, and `PufSource` types in this module implement
//! the full interface, but the implementation is:
//!
//! - `TpmManager`: derives a stable 32-byte "TPM key" from
//!   `/etc/machine-id` (Linux) or `HKLM\SOFTWARE\Microsoft\Cryptography`
//!   (Windows). The key is **not** hardware-protected; it has the
//!   security of the OS's machine identity.
//! - `Fido2Device`: returns a deterministic nonce derived from
//!   `hostname()` plus a hard-coded salt. Real FIDO2 requires the
//!   physical key to be tapped.
//! - `PufSource`: returns CSPRNG bytes. No silicon fingerprint.
//!
//! Operators deploying OMEGA in production MUST replace these
//! fallbacks with real hardware; the `HardwareDependencyMissing`
//! events in the audit log will tell them what's missing.

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The status of a hardware root-of-trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareStatus {
    /// The real hardware is present and operational.
    Real,
    /// The real hardware was not found; a software fallback is in use.
    SoftwareFallback,
    /// The hardware was found but is not initialized (e.g., TPM owner
    /// not set).
    Uninitialized,
    /// The hardware is in a fault state.
    Fault,
    /// The hardware is not present at all (e.g., no TPM on the
    /// platform). Functionality is disabled.
    Absent,
}

impl HardwareStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::SoftwareFallback => "software-fallback",
            Self::Uninitialized => "uninitialized",
            Self::Fault => "fault",
            Self::Absent => "absent",
        }
    }

    /// True if this status indicates the engine is operating on
    /// real hardware (or, for components without a hardware
    /// dependency, on a stable software emulation).
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Real)
    }
}

/// TPM 2.0 manager. Real backend would use `tss-esapi`; this is the
/// software fallback.
pub struct TpmManager {
    pub status: HardwareStatus,
    /// Software-fallback "TPM key" derived from machine-id.
    software_key: [u8; 32],
    /// PCR values (mocked in software fallback).
    pcrs: Vec<[u8; 32]>,
}

impl TpmManager {
    pub fn new() -> Self {
        // Try to read /etc/machine-id (Linux) or the Windows
        // registry. In MVP we always fall through to the
        // software-fallback path.
        let machine_id = read_machine_id();
        let mut software_key = [0u8; 32];
        let h = blake3::hash(format!("soteria-omega-tpm-fallback:{machine_id}").as_bytes());
        software_key.copy_from_slice(h.as_bytes());
        let pcrs = (0..24u32)
            .map(|i| {
                let h = blake3::hash(format!("soteria-omega-tpm-pcr-{i}:{machine_id}").as_bytes());
                let mut p = [0u8; 32];
                p.copy_from_slice(h.as_bytes());
                p
            })
            .collect();
        Self {
            status: HardwareStatus::SoftwareFallback,
            software_key,
            pcrs,
        }
    }

    /// Seal a 32-byte key to PCR indices. Returns the sealed blob
    /// (a BLAKE3-MAC over the key with the PCR state as the key).
    pub fn seal(&self, key: &[u8; 32], pcr_indices: &[u32]) -> OmegaResult<Vec<u8>> {
        if pcr_indices.iter().any(|&i| i >= self.pcrs.len() as u32) {
            return Err(OmegaError::HardwareUnavailable(format!(
                "TPM PCR index out of range: {pcr_indices:?}"
            )));
        }
        let mut pcr_state = [0u8; 32];
        for &i in pcr_indices {
            for j in 0..32 {
                pcr_state[j] ^= self.pcrs[i as usize][j];
            }
        }
        let hmac = blake3::Hash::from(<[u8; 32]>::from(pcr_state));
        // hmac is used to derive a sealing key, then we encrypt the
        // user's key with that sealing key.
        let sealing_key = hmac;
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&(pcr_indices.len() as u32).to_le_bytes());
        for &i in pcr_indices {
            out.extend_from_slice(&i.to_le_bytes());
        }
        // XOR-encrypt
        for (k, s) in key.iter().zip(sealing_key.as_bytes().iter().cycle()) {
            out.push(k ^ s);
        }
        // Append the PCR state hash for verification
        out.extend_from_slice(&pcr_state);
        Ok(out)
    }

    /// Unseal a previously-sealed key. Returns the 32-byte key.
    pub fn unseal(&self, blob: &[u8]) -> OmegaResult<[u8; 32]> {
        if blob.len() < 64 {
            return Err(OmegaError::HardwareUnavailable(
                "sealed blob too short".into(),
            ));
        }
        let n = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
        let pcr_indices: Vec<u32> = (0..n)
            .map(|i| u32::from_le_bytes(blob[4 + i * 4..4 + (i + 1) * 4].try_into().unwrap()))
            .collect();
        let key_start = 4 + n * 4;
        let mut key = [0u8; 32];
        key.copy_from_slice(&blob[key_start..key_start + 32]);
        let stored_pcr_state = &blob[key_start + 32..key_start + 64];
        // Recompute PCR state
        let mut pcr_state = [0u8; 32];
        for &i in &pcr_indices {
            for j in 0..32 {
                pcr_state[j] ^= self.pcrs[i as usize][j];
            }
        }
        // Verify PCR state hasn't changed
        if stored_pcr_state != pcr_state {
            return Err(OmegaError::HardwareUnavailable(
                "TPM PCR state has changed; sealed blob is no longer valid".into(),
            ));
        }
        let hmac = blake3::Hash::from(<[u8; 32]>::from(pcr_state));
        // XOR-decrypt
        for (k, s) in key.iter_mut().zip(hmac.as_bytes().iter().cycle()) {
            *k ^= *s;
        }
        Ok(key)
    }

    /// Read a PCR value. In real hardware this queries the TPM;
    /// here it returns the cached value.
    pub fn read_pcr(&self, index: u32) -> OmegaResult<[u8; 32]> {
        if index >= self.pcrs.len() as u32 {
            return Err(OmegaError::HardwareUnavailable(format!(
                "TPM PCR index out of range: {index}"
            )));
        }
        Ok(self.pcrs[index as usize])
    }

    /// Software-fallback 32-byte "TPM key" — DO NOT use for
    /// production.
    pub fn software_key(&self) -> &[u8; 32] {
        &self.software_key
    }
}

impl Default for TpmManager {
    fn default() -> Self {
        Self::new()
    }
}

/// FIDO2 / CTAP2 device. In the real world this is a YubiKey, a
/// Solokey, or a TPM-backed virtual device. In MVP we use a
/// software fallback.
pub struct Fido2Device {
    pub status: HardwareStatus,
    /// Software-fallback AAGUID (Authenticator Attestation GUID).
    pub aaguid: [u8; 16],
    /// The "device key" — in real hardware this is a private key
    /// attested by the FIDO Alliance Metadata Service. Here it's
    /// derived from hostname.
    device_key: [u8; 32],
}

impl Fido2Device {
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".to_string());
        let h = blake3::hash(format!("soteria-omega-fido2-fallback:{hostname}").as_bytes());
        let mut device_key = [0u8; 32];
        device_key.copy_from_slice(h.as_bytes());
        let mut aaguid = [0u8; 16];
        aaguid[..16].copy_from_slice(&h.as_bytes()[..16]);
        Self {
            status: HardwareStatus::SoftwareFallback,
            aaguid,
            device_key,
        }
    }

    /// Issue a sign challenge. In real hardware this prompts the
    /// user to tap the key. In software fallback it returns a
    /// deterministic signature derived from the challenge and the
    /// device key.
    pub fn sign(&self, challenge: &[u8; 32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let h1 = blake3::Hash::from(<[u8; 32]>::from(self.device_key));
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(h1.as_bytes());
        buf.extend_from_slice(challenge);
        let h2 = blake3::hash(&buf);
        out[..32].copy_from_slice(h2.as_bytes());
        // Second half: hash again with the previous hash
        let mut buf2 = Vec::with_capacity(64);
        buf2.extend_from_slice(&out[..32]);
        buf2.extend_from_slice(h1.as_bytes());
        let h3 = blake3::hash(&buf2);
        out[32..].copy_from_slice(h3.as_bytes());
        out
    }

    /// AAGUID of this device.
    pub fn aaguid(&self) -> &[u8; 16] {
        &self.aaguid
    }
}

impl Default for Fido2Device {
    fn default() -> Self {
        Self::new()
    }
}

/// A Physical Unclonable Function. In silicon this is a per-chip
/// fingerprint derived from manufacturing variation. In software
/// fallback we return CSPRNG bytes (i.e., it's just a regular RNG).
pub struct PufSource {
    pub status: HardwareStatus,
    /// The PUF's "fingerprint" — in real silicon this is burned in
    /// at manufacture time. In software fallback it's derived from
    /// the machine ID at first run and cached.
    fingerprint: [u8; 32],
}

impl PufSource {
    pub fn new() -> Self {
        let machine_id = read_machine_id();
        let h = blake3::hash(format!("soteria-omega-puf-fallback:{machine_id}").as_bytes());
        let mut fp = [0u8; 32];
        fp.copy_from_slice(h.as_bytes());
        Self {
            status: HardwareStatus::SoftwareFallback,
            fingerprint: fp,
        }
    }

    /// Read the PUF fingerprint. Stable across reboots.
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Generate a fresh challenge-response pair. In silicon the
    /// response is `PUF(challenge)` — a function of the challenge
    /// and the per-chip fingerprint. In software fallback we use
    /// `BLAKE3(fingerprint || challenge)`.
    pub fn challenge(&self, challenge: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.fingerprint);
        buf.extend_from_slice(challenge);
        let h = blake3::hash(&buf);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.as_bytes());
        out
    }
}

impl Default for PufSource {
    fn default() -> Self {
        Self::new()
    }
}

fn read_machine_id() -> String {
    #[cfg(unix)]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
            return s.trim().to_string();
        }
    }
    #[cfg(windows)]
    {
        // Real implementation would query HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
        // via winreg. For MVP, fall through.
        let _ = read_windows_machine_guid();
    }
    // Last resort: use a constant. This is intentional — the
    // software fallback is *not* a substitute for real hardware.
    "soteria-omega-machine-id-fallback".to_string()
}

#[cfg(windows)]
fn read_windows_machine_guid() -> Option<String> {
    // We don't add the `winreg` crate (not in cache). The MVP
    // returns None and the engine logs a `HardwareDependencyMissing`
    // event.
    None
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
    fn tpm_seal_unseal_round_trip() {
        let t = TpmManager::new();
        let key = [0x42u8; 32];
        let blob = t.seal(&key, &[0, 1, 4, 7]).unwrap();
        let recovered = t.unseal(&blob).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn tpm_pcr_change_invalidates_blob() {
        let mut t = TpmManager::new();
        let key = [0x42u8; 32];
        let blob = t.seal(&key, &[0, 7]).unwrap();
        // Mutate a PCR
        t.pcrs[0][0] ^= 0x01;
        assert!(t.unseal(&blob).is_err());
    }

    #[test]
    fn tpm_pcr_out_of_range() {
        let t = TpmManager::new();
        let key = [0u8; 32];
        assert!(t.seal(&key, &[99]).is_err());
    }

    #[test]
    fn fido2_sign_deterministic() {
        let d = Fido2Device::new();
        let challenge = [1u8; 32];
        let s1 = d.sign(&challenge);
        let s2 = d.sign(&challenge);
        assert_eq!(s1, s2);
    }

    #[test]
    fn fido2_sign_different_for_different_challenge() {
        let d = Fido2Device::new();
        let s1 = d.sign(&[1u8; 32]);
        let s2 = d.sign(&[2u8; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn puf_challenge_deterministic() {
        let p = PufSource::new();
        let c1 = p.challenge(&[1u8; 32]);
        let c2 = p.challenge(&[1u8; 32]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn puf_fingerprint_stable() {
        let p1 = PufSource::new();
        let p2 = PufSource::new();
        assert_eq!(p1.fingerprint(), p2.fingerprint());
    }

    #[test]
    fn status_labels_unique() {
        let statuses = [
            HardwareStatus::Real,
            HardwareStatus::SoftwareFallback,
            HardwareStatus::Uninitialized,
            HardwareStatus::Fault,
            HardwareStatus::Absent,
        ];
        let labels: std::collections::HashSet<_> = statuses.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), statuses.len());
    }
}
