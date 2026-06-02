//! Software-based key sealing for platforms without TPM hardware.
//!
//! Uses AES-256-GCM with a device-specific key derived from
//! BLAKE3(machine-id || hostname). This is NOT equivalent to TPM
//! hardware binding but provides encryption-at-rest.

use crate::tpm::interface::TpmProvider;
use zeroize::Zeroizing;

/// Software-based key sealing provider.
pub struct SoftwareSealingProvider {
    device_key: [u8; 32],
}

impl SoftwareSealingProvider {
    pub fn new() -> crate::Result<Self> {
        let device_key = Self::derive_device_key()?;
        Ok(Self { device_key })
    }

    fn derive_device_key() -> crate::Result<[u8; 32]> {
        let mut material = Vec::new();
        material.extend_from_slice(b"soteria:device-key:v1");

        let machine_id = Self::read_machine_id();
        material.extend_from_slice(machine_id.as_bytes());

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        material.extend_from_slice(hostname.as_bytes());

        Ok(*blake3::hash(&material).as_bytes())
    }

    fn read_machine_id() -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/etc/machine-id")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "linux-unknown".to_string())
        }

        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("wmic")
                .args(["csproduct", "get", "UUID"])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .nth(1)
                        .unwrap_or("windows-unknown")
                        .trim()
                        .to_string()
                })
                .unwrap_or_else(|_| "windows-unknown".to_string())
        }

        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("ioreg")
                .args(["-rd1", "-c", "IOPlatformExpertDevice"])
                .output()
                .map(|o| {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    stdout
                        .lines()
                        .find(|l| l.contains("IOPlatformUUID"))
                        .and_then(|l| l.split('"').nth(3))
                        .unwrap_or("macos-unknown")
                        .to_string()
                })
                .unwrap_or_else(|_| "macos-unknown".to_string())
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            "unknown-platform".to_string()
        }
    }
}

impl TpmProvider for SoftwareSealingProvider {
    fn seal(&self, plaintext_key: &[u8; 32]) -> crate::Result<Vec<u8>> {
        use crate::crypto_engine::aead::CryptoEngine;
        use crate::crypto_engine::AeadAlgorithm;

        let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, self.device_key);
        let envelope = engine.encrypt(plaintext_key, b"soteria:software-seal:v1")?;
        serde_json::to_vec(&envelope).map_err(|e| anyhow::anyhow!("seal: serialize: {e}"))
    }

    fn unseal(&self, sealed_blob: &[u8]) -> crate::Result<Zeroizing<[u8; 32]>> {
        use crate::crypto_engine::aead::{AeadEnvelope, CryptoEngine};
        use crate::crypto_engine::AeadAlgorithm;

        let envelope: AeadEnvelope = serde_json::from_slice(sealed_blob)
            .map_err(|e| anyhow::anyhow!("unseal: deserialize: {e}"))?;
        let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, self.device_key);
        let plaintext = engine.decrypt(&envelope, b"soteria:software-seal:v1")?;

        anyhow::ensure!(plaintext.len() == 32, "software unseal: expected 32 bytes");

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&plaintext);
        Ok(out)
    }

    fn boot_measurement(&self) -> crate::Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:software-boot-measurement:v1");
        hasher.update(&self.device_key);
        hasher.update(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_le_bytes(),
        );
        Ok(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let provider = SoftwareSealingProvider::new().unwrap();
        let key = [0x42u8; 32];
        let sealed = provider.seal(&key).unwrap();
        let unsealed = provider.unseal(&sealed).unwrap();
        assert_eq!(*unsealed, key);
    }

    #[test]
    fn seal_different_nonces() {
        let provider = SoftwareSealingProvider::new().unwrap();
        let key = [0x42u8; 32];
        let s1 = provider.seal(&key).unwrap();
        let s2 = provider.seal(&key).unwrap();
        // Same plaintext, different nonces → different ciphertext.
        assert_ne!(s1, s2);
    }

    #[test]
    fn unseal_rejects_tampered() {
        let provider = SoftwareSealingProvider::new().unwrap();
        let key = [0x42u8; 32];
        let mut sealed = provider.seal(&key).unwrap();
        sealed[15] ^= 0xFF;
        assert!(provider.unseal(&sealed).is_err());
    }

    #[test]
    fn unseal_rejects_truncated() {
        let provider = SoftwareSealingProvider::new().unwrap();
        assert!(provider.unseal(&[0u8; 10]).is_err());
    }

    #[test]
    fn boot_measurement_is_32_bytes() {
        let provider = SoftwareSealingProvider::new().unwrap();
        let m = provider.boot_measurement().unwrap();
        assert_eq!(m.len(), 32);
    }
}
