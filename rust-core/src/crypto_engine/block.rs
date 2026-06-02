use super::{AeadAlgorithm, CryptoEngine};
use crate::crypto_engine::kdf::hkdf_derive;
use serde::{Deserialize, Serialize};

/// HKDF info string for per-block key derivation. Domain separator; includes
/// product name and version so a key derived for Soteria can never collide
/// with a key derived under a different design or version.
pub const BLOCK_KEY_INFO: &[u8] = b"SOTERIA per-block key v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCiphertext {
    pub block_index: u64,
    pub lineage_prev: String,
    pub lineage_new: String,
    pub envelope: super::aead::AeadEnvelope,
}

pub struct BlockCrypto {
    algorithm: AeadAlgorithm,
    domain_key: [u8; 32],
}

impl BlockCrypto {
    pub fn new(algorithm: AeadAlgorithm, domain_key: [u8; 32]) -> Self {
        Self {
            algorithm,
            domain_key,
        }
    }

    pub fn encrypt_block(
        &self,
        block_index: u64,
        plaintext: &[u8],
        previous_lineage: &str,
    ) -> crate::Result<BlockCiphertext> {
        let salt = build_block_salt(block_index, previous_lineage);
        let key = hkdf_derive(&self.domain_key, &salt, BLOCK_KEY_INFO)?;
        let aad = Self::aad(block_index, previous_lineage);
        let envelope = CryptoEngine::new(self.algorithm, key).encrypt(plaintext, &aad)?;
        let mut lineage_material = previous_lineage.as_bytes().to_vec();
        lineage_material.extend_from_slice(&envelope.ciphertext);
        let lineage_new = blake3::hash(&lineage_material).to_hex().to_string();
        Ok(BlockCiphertext {
            block_index,
            lineage_prev: previous_lineage.to_string(),
            lineage_new,
            envelope,
        })
    }

    pub fn decrypt_block(&self, block: &BlockCiphertext) -> crate::Result<Vec<u8>> {
        let salt = build_block_salt(block.block_index, &block.lineage_prev);
        let key = hkdf_derive(&self.domain_key, &salt, BLOCK_KEY_INFO)?;
        CryptoEngine::new(block.envelope.algorithm, key).decrypt(
            &block.envelope,
            &Self::aad(block.block_index, &block.lineage_prev),
        )
    }

    fn aad(block_index: u64, lineage_prev: &str) -> Vec<u8> {
        format!("soteria:block:{block_index}:prev:{lineage_prev}").into_bytes()
    }
}

/// Build the HKDF salt for a per-block key: `LE-u64(block_index) || lineage_prev_hash`.
/// Including the lineage hash in the salt means tampering with a prior block's
/// ciphertext (which changes its `lineage_new`, which is then the
/// `lineage_prev` of every subsequent block) forces re-derivation of all
/// downstream block keys, and any tamper fails the AEAD auth tag check.
pub fn build_block_salt(block_index: u64, lineage_prev: &str) -> [u8; 40] {
    let mut salt = [0u8; 40];
    salt[..8].copy_from_slice(&block_index.to_le_bytes());
    salt[8..].copy_from_slice(&lineage_prev_salt(lineage_prev));
    salt
}

/// Reduce a lineage_prev string (either the literal "GENESIS" or a 64-char
/// hex BLAKE3 digest) to the 32 bytes used in the HKDF salt.
pub fn lineage_prev_salt(lineage_prev: &str) -> [u8; 32] {
    if lineage_prev == "GENESIS" {
        *blake3::hash(b"GENESIS").as_bytes()
    } else {
        let mut out = [0u8; 32];
        let bytes = lineage_prev.as_bytes();
        let mut i = 0;
        let mut j = 0;
        while i + 1 < bytes.len() && j < 32 {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("00"), 16)
            {
                out[j] = b;
            }
            i += 2;
            j += 1;
        }
        out
    }
}
