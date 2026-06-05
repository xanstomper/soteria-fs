//! Pre-Boot Authentication (PBA) design.
//!
//! ## What PBA is
//!
//! PBA is a small bootloader that runs **before** the OS. It:
//! 1. Prompts the user for a passphrase.
//! 2. Derives the volume key via Argon2id.
//! 3. Decrypts the OS partition's volume header.
//! 4. Sets up the OS's encrypted-volume driver (Linux: `dm-crypt`;
//!    Windows: `BitLocker`-equivalent; macOS: `CoreStorage`).
//! 5. Chains to the OS bootloader (GRUB, Windows Boot Manager,
//!    `boot.efi`).
//!
//! This is what BitLocker, FileVault, LUKS, and VeraCrypt all do.
//!
//! ## PBA architecture for Soteria
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  UEFI firmware                               │
//! │  - Verifies Secure Boot signatures           │
//! │  - Loads Soteria PBA from ESP                │
//! └─────────────────────────────────────────────┘
//!                      ↓
//! ┌─────────────────────────────────────────────┐
//! │  Soteria PBA (this module's reference impl)  │
//! │  - Prompts passphrase via console            │
//! │  - Derives XTS key via Argon2id              │
//! │  - Decrypts OS volume header                 │
//! │  - Extends TPM PCR 5 with the new state      │
//! │  - Loads OS bootloader                       │
//! └─────────────────────────────────────────────┘
//!                      ↓
//! ┌─────────────────────────────────────────────┐
//! │  OS Bootloader (GRUB, Windows BootMgr, etc.) │
//! │  - Loads the OS                              │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Implementation status
//!
//! This module is a **design + configuration** module. The actual
//! PBA EFI binary is a separate Rust crate (`soteria-pba`) built with
//! the `uefi` target and is not part of this MVP. The CLI exposes
//! the configuration and a build helper, but the binary is expected
//! to be built and signed by the user (or by the system integrator).
//!
//! ## TPM-sealed PBA
//!
//! In the TPM-sealed flow, the PBA does NOT prompt for a passphrase.
//! Instead, it asks the TPM to unseal the volume key, and the TPM
//! releases the key only if the boot chain is intact (PCRs match).
//! This is the BitLocker "TPM-only" mode. It is less secure than
//! passphrase+PBA (an attacker who boots the machine can unseal),
//! but it is convenient and defends against offline disk theft.
//!
//! ## Attack surface
//!
//! The PBA is the highest-value attack target:
//! - **Cold-boot** between PBA and OS load: an attacker with a
//!   memory freeze spray can read the derived key from RAM.
//!   Mitigations: zeroize the key in memory after passing it to
//!   the OS driver; use a key-encryption-key (KEK) pattern where
//!   the PBA only ever sees a short-lived wrapping key.
//! - **Evil-maid** (modified PBA itself): if the attacker can
//!   replace the PBA binary, they can capture the passphrase.
//!   Mitigations: Secure Boot signature verification, full-disk
//!   encryption of the PBA partition, TPM measurement of the PBA
//!   binary into PCR 4.

use serde::{Deserialize, Serialize};

/// PBA configuration. The CLI writes this to a `pba.toml` file in
/// the EFI System Partition; the PBA binary reads it at boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbaConfig {
    /// Path to the OS volume (the encrypted disk the PBA unlocks).
    pub os_volume: String,
    /// KDF parameters. Must match the OS volume's KDF params.
    pub kdf_m_cost_kib: u32,
    pub kdf_t_cost: u32,
    pub kdf_p: u32,
    /// Whether to require TPM unseal (in addition to or instead of
    /// passphrase). "tpm_only" is convenient but less secure.
    pub auth_mode: AuthMode,
    /// PCRs to seal/unseal against. Default: [0, 2, 4, 7].
    pub pcrs: Vec<u32>,
    /// Locale of the PBA UI (BCP-47, e.g., "en-US", "de-DE").
    pub locale: String,
    /// Number of failed-attempt lockouts before the PBA wipes
    /// the OS volume's header. 0 disables the feature.
    pub max_failed_attempts: u32,
    /// Whether to display a custom banner (e.g., legal warning).
    pub banner: Option<String>,
    /// Path to the OS bootloader to chain-load after success.
    pub chain_load: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMode {
    /// Passphrase only. Most secure; user must type every boot.
    Passphrase,
    /// TPM unseal only. Convenient; vulnerable to evil-maid.
    TpmOnly,
    /// Both: TPM unseal AND passphrase. Maximum security.
    TpmAndPassphrase,
}

impl Default for PbaConfig {
    fn default() -> Self {
        Self {
            os_volume: "/dev/sda2".to_string(),
            kdf_m_cost_kib: 1 << 16, // 64 MiB
            kdf_t_cost: 3,
            kdf_p: 1,
            auth_mode: AuthMode::TpmAndPassphrase,
            pcrs: vec![0, 2, 4, 7],
            locale: "en-US".to_string(),
            max_failed_attempts: 10,
            banner: Some(
                "SOTERIA PRE-BOOT AUTHENTICATION\nAuthorized access only. \
                 All access is logged."
                    .to_string(),
            ),
            chain_load: "/EFI/systemd/systemd-bootx64.efi".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PbaError {
    #[error("invalid PCR list: must be 0..=23, got {0}")]
    InvalidPcr(u32),
    #[error("invalid locale: {0}")]
    InvalidLocale(String),
    #[error("io: {0}")]
    Io(String),
}

impl PbaConfig {
    /// Validate the configuration. Returns `Err` on bad PCR indices,
    /// out-of-range KDF params, etc.
    pub fn validate(&self) -> Result<(), PbaError> {
        for p in &self.pcrs {
            if *p > 23 {
                return Err(PbaError::InvalidPcr(*p));
            }
        }
        if self.kdf_m_cost_kib < 8192 {
            return Err(PbaError::Io(format!(
                "kdf_m_cost_kib {} below minimum 8192",
                self.kdf_m_cost_kib
            )));
        }
        if self.kdf_t_cost < 1 {
            return Err(PbaError::Io(format!(
                "kdf_t_cost {} below minimum 1",
                self.kdf_t_cost
            )));
        }
        if self.kdf_p < 1 {
            return Err(PbaError::Io(format!(
                "kdf_p {} below minimum 1",
                self.kdf_p
            )));
        }
        if self.locale.len() > 16 {
            return Err(PbaError::InvalidLocale(self.locale.clone()));
        }
        Ok(())
    }

    /// Serialize to TOML for writing into the EFI System Partition.
    pub fn to_toml(&self) -> Result<String, PbaError> {
        toml::to_string_pretty(self).map_err(|e| PbaError::Io(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        PbaConfig::default().validate().unwrap();
    }

    #[test]
    fn invalid_pcr_rejected() {
        let mut c = PbaConfig::default();
        c.pcrs = vec![0, 99];
        assert!(matches!(c.validate(), Err(PbaError::InvalidPcr(99))));
    }

    #[test]
    fn weak_kdf_rejected() {
        let mut c = PbaConfig::default();
        c.kdf_m_cost_kib = 1024;
        assert!(c.validate().is_err());
    }
}
