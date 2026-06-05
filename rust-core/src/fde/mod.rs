//! Full-Disk Encryption (FDE) module.
//!
//! This module implements the production-grade disk encryption stack:
//! - **AES-256-XTS** sector cipher (FIPS-approved for FDE; NIST SP 800-38E)
//! - **Argon2id** KDF (RFC 9106) with tunable cost parameters
//! - **Header integrity** with BLAKE3, constant-time verified
//! - **LUKS2-style header backup** at the end of the device
//! - **Hidden volume** support (VeraCrypt-style plausible deniability)
//! - **TPM 2.0 seal/unseal** of the volume key to PCR 0–7
//! - **Anti-forensic key splitting** (Shamir M-of-N)
//! - **Persistent NVRAM-equivalent** tamper-evident state
//! - **Hardware secure erase** (NVMe Format / ATA SECURE ERASE)
//!
//! ## Threat model
//!
//! This module defends against:
//! - **Lost / stolen device**: device is encrypted at rest. With the
//!   device powered off, no key material is in memory; XTS-encrypted
//!   sectors are indistinguishable from random.
//! - **Evil-maid attack** (modified boot chain): volume key can be
//!   sealed to TPM PCRs; an attacker who swaps the bootloader cannot
//!   unseal the key without the original PCR values.
//! - **Coercion / rubber-hose** (forced to reveal passphrase): a hidden
//!   volume can be created inside the "free space" of an outer volume.
//!   The outer passphrase decrypts to plausible decoy data; the hidden
//!   passphrase reveals the real data. The user can plausibly deny the
//!   existence of the hidden volume.
//! - **Disk theft + forensic recovery**: multi-pass overwrite before
//!   format (best-effort on HDD) plus NVMe/ATA hardware secure erase
//!   (definitive on SSD).
//!
//! This module does NOT defend against:
//! - **Cold-boot attack**: an attacker with physical access to a
//!   *running* machine can DMA-attack memory to recover the live
//!   volume key. Mitigations: DRAM scrambling, full-memory encryption
//!   (AMD SME/SEV, Intel TME), and short idle timeouts.
//! - **Compromised OS kernel**: if the running kernel is malicious,
//!   the volume key can be exfiltrated. Mitigations: measured boot,
//!   TPM sealing, and never booting untrusted kernels.

pub mod block_device;
pub mod gcm_sector;
pub mod hidden;
pub mod hw_erase;
pub mod pba;
pub mod persistent;
pub mod shamir;
pub mod tpm_seal;
pub mod volume;

pub use block_device::{BlockDevice, BlockError, FileBackedDevice};
pub use hidden::{hidden_header_lba, HiddenHeader};
pub use hw_erase::{secure_erase_ata, secure_erase_nvme, HwEraseResult};
pub use pba::{PbaConfig, PbaError};
pub use persistent::{NvramError, NvramState};
pub use shamir::{combine_shares, split_secret, Share};
pub use tpm_seal::{SealedKey, TpmError, TpmPolicy};
pub use volume::{
    build_xts_key_check, derive_xts_key, format_volume, init_volume, open_volume, verify_xts_key,
    MountedVolume, VolumeHeader, FEATURE_ANTI_FORENSIC, FEATURE_HIDDEN, FEATURE_TPM_SEALED,
    HEADER_MAGIC, HEADER_SECTORS, HEADER_SIZE, HEADER_VERSION,
};
