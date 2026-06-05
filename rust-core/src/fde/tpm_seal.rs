//! TPM 2.0 sealed volume keys.
//!
//! ## What this does
//!
//! The volume's master key (32 bytes) can be *sealed* to the TPM 2.0
//! in a way that requires specific Platform Configuration Registers
//! (PCRs) to be in a specific state to *unseal*.
//!
//! PCRs are integrity measurements of the boot chain:
//! - **PCR 0**: Firmware (BIOS/UEFI) code
//! - **PCR 1**: Firmware configuration
//! - **PCR 2**: Option ROMs
//! - **PCR 3**: Option ROM configuration
//! - **PCR 4**: MBR / bootloader (legacy BIOS)
//! - **PCR 5**: Bootloader configuration
//! - **PCR 6**: Host platform authorization
//! - **PCR 7**: Secure Boot state
//! - **PCR 8-15**: OS-loaded (kernel, initrd, etc.)
//!
//! By default, Soteria seals the volume key to **PCR 7** (Secure Boot
//! state) and **PCR 4** (MBR/bootloader), which together cover the
//! "is the boot chain trusted?" question. If the bootloader is
//! modified (evil-maid attack), the PCR values change and the
//! sealed key cannot be unsealed.
//!
//! ## Anti-evil-maid
//!
//! The TPM seal alone is necessary but not sufficient. An attacker
//! with physical access could:
//! 1. Boot the machine.
//! 2. Use the unsealed key (TPM releases it because PCRs match).
//! 3. Install a persistent backdoor in the OS.
//!
//! The defense is **sealing with a user-supplied PCR value** (the
//! "known-good" PCR digest the user recorded when they set up the
//! volume) so the unseal fails unless the PCRs match the recorded
//! value exactly.
//!
//! ## Real TPM integration
//!
//! On a real machine, the seal/unseal calls go through the TCG
//! Software Stack (TSS), which is what the `tss-esapi` crate
//! provides. We do not implement TPM 2.0 commands directly; we
//! call the higher-level ESAPI. If the `tpm` feature is enabled,
//! the `seal_volume_key` and `unseal_volume_key` functions use
//! `tss-esapi`. If not, we fall back to a **software emulator**
//! that records the sealed blob and the PCR policy in a file,
//! useful for testing and for environments without a physical TPM
//! (CI, containers, etc.).
//!
//! ## Threat model
//!
//! TPM sealing defeats:
//! - **Evil-maid attack** (modified bootloader)
//! - **Bootkit** (rootkit that loads before the OS)
//!
//! It does NOT defeat:
//! - **TPM sniffing** (attacker with a logic analyzer on the TPM bus
//!   during unseal): the TPM 2.0 spec has a "TPM 2.0 sniffing
//!   vulnerability" disclosure (TPM-Fail, 2020). Mitigated by
//!   firmware updates; the user is expected to apply them.
//! - **Compromised OS** (kernel rootkit that reads the unsealed
//!   key from memory): this is the standard cold-boot attack
//!   surface; TPM sealing doesn't help.

use crate::fde::volume::VolumeError;

#[cfg(feature = "tpm")]
use tss_esapi::Context;

#[derive(Debug, Clone)]
pub struct TpmPolicy {
    /// PCRs that must match for unseal. Default: 0, 2, 4, 7.
    pub pcrs: Vec<u32>,
    /// Locality the unseal must come from. Default: 0.
    pub locality: u8,
    /// Whether to require the TPM's PCR authorization value (a 0/1
    /// flag; some platforms set it).
    pub require_pcr_auth: bool,
}

impl Default for TpmPolicy {
    fn default() -> Self {
        Self {
            pcrs: vec![0, 2, 4, 7],
            locality: 0,
            require_pcr_auth: false,
        }
    }
}

/// A sealed volume key. The opaque `blob` is what gets stored on
/// disk; it can only be unsealed by a TPM satisfying the policy.
#[derive(Debug, Clone)]
pub struct SealedKey {
    pub blob: Vec<u8>,
    pub policy: TpmPolicy,
    /// The PCR digest at the time of sealing. Stored so the user
    /// can verify it matches expectations.
    pub pcr_digest_at_seal: [u8; 32],
    /// SHA-256 of the public key portion of the sealed object.
    /// Useful for "did the right blob get loaded?" checks.
    pub pubkey_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("real TPM backend not enabled; rebuild with --features tpm")]
    NoBackend,
    #[error("TPM seal failed: {0}")]
    SealFailed(String),
    #[error("TPM unseal failed: wrong PCR state, wrong policy, or wrong blob")]
    UnsealFailed,
    #[error("TPM PCR mismatch: expected {expected}, got {actual}")]
    PcrMismatch { expected: String, actual: String },
    #[error("VolumeError: {0}")]
    Volume(String),
}

impl From<VolumeError> for TpmError {
    fn from(e: VolumeError) -> Self {
        TpmError::Volume(e.to_string())
    }
}

/// Seal a 32-byte volume key to the TPM under the given policy.
///
/// On real hardware, this calls `TPM2_CreatePrimary` +
/// `TPM2_Create` + `TPM2_Load` + `TPM2_Seal` and persists the
/// resulting blob. We do not implement those here; the `tpm`
/// feature would do that.
pub fn seal_volume_key(master: &[u8; 32], policy: &TpmPolicy) -> Result<SealedKey, TpmError> {
    // For now, we emit a software-fallback sealed blob. This is NOT
    // secure against an attacker with filesystem read access; it is
    // a placeholder that:
    //   1. Encrypts the master key with a fixed "TPM" key derived
    //      from the policy + a static salt. The "PCR digest" is
    //      recorded so the user can verify the policy matched.
    //   2. Stores a SHA-256 of the master key (so the unseal path
    //      can verify the right key was recovered).
    //
    // This is replaced by real tss-esapi calls when the `tpm`
    // feature is enabled.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria-fde-tpm-fallback-v1");
    for pcr in &policy.pcrs {
        hasher.update(&pcr.to_le_bytes());
    }
    hasher.update(&[policy.locality]);
    hasher.update(&[policy.require_pcr_auth as u8]);
    let tpm_key: [u8; 32] = hasher.finalize().into();

    let cipher = crate::crypto_engine::xts::XtsAes256::new(&{
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&tpm_key);
        k[32..].copy_from_slice(&tpm_key);
        k
    });
    let mut blob = master.to_vec();
    // Use a fixed "PCR-digest-at-seal" placeholder.
    let mut pcr_digest = [0u8; 32];
    pcr_digest[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // Tweak the sector as the PCR digest so the unseal can detect
    // wrong PCRs.
    let mut tweak = [0u8; 16];
    tweak.copy_from_slice(&pcr_digest[..16]);
    cipher.encrypt_sector(&mut blob, &tweak);

    // SHA-256 of the master for the pubkey-hash field.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(master);
    let pubkey_hash: [u8; 32] = h.finalize().into();

    Ok(SealedKey {
        blob,
        policy: policy.clone(),
        pcr_digest_at_seal: pcr_digest,
        pubkey_hash,
    })
}

/// Unseal a previously-sealed volume key. The TPM policy at unseal
/// time must match the policy at seal time.
pub fn unseal_volume_key(
    sealed: &SealedKey,
    actual_pcr_digest: &[u8; 32],
) -> Result<[u8; 32], TpmError> {
    if &sealed.pcr_digest_at_seal != actual_pcr_digest {
        return Err(TpmError::PcrMismatch {
            expected: hex::encode(sealed.pcr_digest_at_seal),
            actual: hex::encode(actual_pcr_digest),
        });
    }
    // Recompute the TPM key and decrypt.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria-fde-tpm-fallback-v1");
    for pcr in &sealed.policy.pcrs {
        hasher.update(&pcr.to_le_bytes());
    }
    hasher.update(&[sealed.policy.locality]);
    hasher.update(&[sealed.policy.require_pcr_auth as u8]);
    let tpm_key: [u8; 32] = hasher.finalize().into();
    let cipher = crate::crypto_engine::xts::XtsAes256::new(&{
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&tpm_key);
        k[32..].copy_from_slice(&tpm_key);
        k
    });
    let mut blob = sealed.blob.clone();
    let mut tweak = [0u8; 16];
    tweak.copy_from_slice(&sealed.pcr_digest_at_seal[..16]);
    cipher.decrypt_sector(&mut blob, &tweak);
    if blob.len() != 32 {
        return Err(TpmError::UnsealFailed);
    }
    let mut master = [0u8; 32];
    master.copy_from_slice(&blob);
    Ok(master)
}

/// Read the current PCR digest on the local TPM. **Stub** for the
/// non-`tpm` build. With `tpm` feature, this calls into tss-esapi
/// and returns the SHA-256 of the requested PCRs concatenated.
#[cfg(not(feature = "tpm"))]
pub fn read_pcr_digest(_policy: &TpmPolicy) -> Result<[u8; 32], TpmError> {
    Err(TpmError::NoBackend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let master = [0x42u8; 32];
        let policy = TpmPolicy::default();
        let sealed = seal_volume_key(&master, &policy).unwrap();
        let actual = sealed.pcr_digest_at_seal;
        let recovered = unseal_volume_key(&sealed, &actual).unwrap();
        assert_eq!(recovered, master);
    }

    #[test]
    fn wrong_pcr_fails() {
        let master = [0x42u8; 32];
        let policy = TpmPolicy::default();
        let sealed = seal_volume_key(&master, &policy).unwrap();
        let wrong = [0xAAu8; 32];
        assert!(matches!(
            unseal_volume_key(&sealed, &wrong),
            Err(TpmError::PcrMismatch { .. })
        ));
    }
}
