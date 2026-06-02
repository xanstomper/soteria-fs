use crate::crypto_engine::nonce::{Nonce192, Nonce96};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEnvelope {
    pub algorithm: AeadAlgorithm,
    pub nonce: Vec<u8>,
    pub aad_blake3: String,
    pub ciphertext: Vec<u8>,
}

pub struct CryptoEngine {
    algorithm: AeadAlgorithm,
    key: Zeroizing<[u8; 32]>,
}

impl CryptoEngine {
    pub fn new(algorithm: AeadAlgorithm, key: [u8; 32]) -> Self {
        Self {
            algorithm,
            key: Zeroizing::new(key),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> crate::Result<AeadEnvelope> {
        let (nonce, ciphertext) = match self.algorithm {
            AeadAlgorithm::Aes256Gcm => {
                // V-01 fix: derive nonce deterministically from key + AAD.
                // Each block has unique AAD (block_index || lineage_prev),
                // so nonce is unique per block per key. No birthday bound risk.
                let n = Nonce96::derive(&self.key, aad);
                let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid AES key"))?;
                let ct = cipher
                    .encrypt(
                        AesNonce::from_slice(&n.0),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("AES-GCM encrypt failed"))?;
                (n.0.to_vec(), ct)
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                let n = Nonce192::random();
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid XChaCha key"))?;
                let ct = cipher
                    .encrypt(
                        XNonce::from_slice(&n.0),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 encrypt failed"))?;
                (n.0.to_vec(), ct)
            }
        };
        Ok(AeadEnvelope {
            algorithm: self.algorithm,
            nonce,
            aad_blake3: blake3::hash(aad).to_hex().to_string(),
            ciphertext,
        })
    }

    pub fn decrypt(&self, envelope: &AeadEnvelope, aad: &[u8]) -> crate::Result<Vec<u8>> {
        anyhow::ensure!(
            envelope.aad_blake3 == blake3::hash(aad).to_hex().to_string(),
            "AAD hash mismatch"
        );
        match envelope.algorithm {
            AeadAlgorithm::Aes256Gcm => {
                anyhow::ensure!(envelope.nonce.len() == 12, "invalid AES-GCM nonce length");
                let cipher = Aes256Gcm::new_from_slice(self.key.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid AES key"))?;
                cipher
                    .decrypt(
                        AesNonce::from_slice(&envelope.nonce),
                        Payload {
                            msg: &envelope.ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("AES-GCM decrypt/auth failed"))
            }
            AeadAlgorithm::XChaCha20Poly1305 => {
                anyhow::ensure!(envelope.nonce.len() == 24, "invalid XChaCha nonce length");
                let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
                    .map_err(|_| anyhow::anyhow!("invalid XChaCha key"))?;
                cipher
                    .decrypt(
                        XNonce::from_slice(&envelope.nonce),
                        Payload {
                            msg: &envelope.ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("XChaCha decrypt/auth failed"))
            }
        }
    }
}
