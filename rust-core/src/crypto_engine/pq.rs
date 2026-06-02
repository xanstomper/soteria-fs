//! Post-quantum file sharing via ML-KEM-768 (FIPS 203).
//!
//! ## Threat model
//!
//! A sender wants to share an encrypted file with a recipient without
//! revealing the volume key. We use the standard "hybrid" KEM pattern:
//!
//! 1. Sender generates a random 32-byte data-encryption key (DEK) for the
//!    file. The file is encrypted with this DEK (the existing AEAD path).
//! 2. Sender encapsulates a 32-byte shared secret to the recipient's ML-KEM
//!    public key, derives a key-encryption key (KEK) from it via HKDF, and
//!    encrypts the DEK under the KEK with AES-256-GCM.
//! 3. The recipient decapsulates the ML-KEM ciphertext with their secret key,
//!    re-derives the same KEK, and decrypts the DEK.
//!
//! The DEK never leaves the sender's trust boundary unencrypted; only the
//! KEK-wrapped DEK is transmitted. A future-quantum attacker who later
//! records the ML-KEM ciphertext cannot recover the KEK, and a classical
//! attacker cannot break the ML-KEM-768 encapsulation.
//!
//! ## Key serialization
//!
//! - Public key: 1184 bytes (the FIPS 203 encapsulation key).
//! - Secret key: 64-byte seed (the FIPS 203 preferred form; the full 2400-byte
//!   expanded form is reconstructed on demand).
//! - Ciphertext: 1088 bytes.
//! - Shared secret: 32 bytes.
//!
//! The ml-kem crate is a pure-Rust FIPS 203 implementation with no C
//! dependencies. A future `pqc-oqs` feature can swap the implementation for
//! liboqs without changing this module's public API.

use crate::crypto_engine::kdf::hkdf_derive;
use crate::crypto_engine::{AeadAlgorithm, CryptoEngine};
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::{KeyExport, MlKem768, SharedKey as MlKemSharedKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const ML_KEM_768_PK_LEN: usize = 1184;
pub const ML_KEM_768_SK_SEED_LEN: usize = 64;
pub const ML_KEM_768_CT_LEN: usize = 1088;
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;

const HKDF_INFO: &[u8] = b"SOTERIA pq-wrap v1";
const HKDF_SALT: &[u8] = b"soteria-pq-kek-salt-v1";
const WRAP_AAD: &[u8] = b"soteria:pq:data-key:v1";

/// Post-quantum encapsulation key (the recipient's "address").
#[derive(Clone, Zeroize, Serialize, Deserialize)]
pub struct PublicKey {
    /// Raw FIPS 203 encapsulation key bytes.
    pub bytes: Vec<u8>,
}

/// Post-quantum decapsulation key (the recipient's secret).
#[derive(Clone, Zeroize, Serialize, Deserialize)]
pub struct SecretKey {
    /// 64-byte FIPS 203 seed; the expanded form is reconstructed on demand.
    pub bytes: Vec<u8>,
}

/// A recipient's keypair. The secret key is zeroized on drop.
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    pub fn public(&self) -> &PublicKey {
        &self.public
    }
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // The Vec<u8> already drops, but be explicit.
        self.public.bytes.zeroize();
        self.secret.bytes.zeroize();
    }
}

/// Generate a fresh ML-KEM-768 keypair.
pub fn generate_keypair() -> KeyPair {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes();
    let dk_seed = dk
        .to_seed()
        .expect("ml-kem decapsulation key supports seed export");
    KeyPair {
        public: PublicKey {
            bytes: ek_bytes.to_vec(),
        },
        secret: SecretKey {
            bytes: dk_seed.to_vec(),
        },
    }
}

/// A data key wrapped for a specific recipient.
///
/// Stored alongside the file. The recipient finds their envelope by
/// matching `recipient_key_id` to `BLAKE3(recipient_public_key)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    #[serde(with = "hex_32")]
    pub recipient_key_id: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    #[serde(with = "hex_vec")]
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM nonce for the wrapped key (12 bytes).
    #[serde(with = "hex_12")]
    pub wrap_nonce: [u8; 12],
    /// AES-256-GCM ciphertext + tag for the wrapped data key (48 bytes).
    #[serde(with = "hex_vec")]
    pub wrapped_key: Vec<u8>,
}

impl KeyEnvelope {
    /// 32-byte BLAKE3 fingerprint of the recipient's public key. Use to
    /// identify which envelope belongs to which recipient when a file has
    /// multiple envelopes (multi-recipient sharing).
    pub fn recipient_key_id(public_key: &PublicKey) -> [u8; 32] {
        *blake3::hash(&public_key.bytes).as_bytes()
    }
}

/// Wrap a 32-byte data key for a recipient.
pub fn wrap_key(data_key: &[u8; 32], recipient_pk: &PublicKey) -> crate::Result<KeyEnvelope> {
    if recipient_pk.bytes.len() != ML_KEM_768_PK_LEN {
        anyhow::bail!(
            "invalid ML-KEM-768 public key length: got {}, expected {}",
            recipient_pk.bytes.len(),
            ML_KEM_768_PK_LEN
        );
    }
    let mut pk_arr = [0u8; ML_KEM_768_PK_LEN];
    pk_arr.copy_from_slice(&recipient_pk.bytes);
    let ek = <MlKem768 as Kem>::EncapsulationKey::new(&Array(pk_arr))
        .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 public key bytes"))?;
    let (ct, ss) = ek.encapsulate();

    // Derive a 32-byte key-encryption key from the shared secret via HKDF.
    let kek: [u8; 32] = hkdf_derive(ss.as_slice(), HKDF_SALT, HKDF_INFO)?;

    // Encrypt the data key with AES-256-GCM. The envelope embeds a fresh
    // random nonce and the 16-byte auth tag in the ciphertext.
    let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, kek);
    let aead = engine.encrypt(data_key, WRAP_AAD)?;
    anyhow::ensure!(aead.nonce.len() == 12, "unexpected AES-GCM nonce length");
    anyhow::ensure!(
        aead.ciphertext.len() == 32 + 16,
        "unexpected wrapped_key length"
    );
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&aead.nonce);

    Ok(KeyEnvelope {
        recipient_key_id: KeyEnvelope::recipient_key_id(recipient_pk),
        kem_ciphertext: ct.to_vec(),
        wrap_nonce: nonce,
        wrapped_key: aead.ciphertext,
    })
}

/// Unwrap a 32-byte data key from a `KeyEnvelope` using the recipient's
/// secret key. Returns `Err` on AEAD auth failure, malformed key, or
/// malformed envelope.
pub fn unwrap_key(envelope: &KeyEnvelope, recipient_sk: &SecretKey) -> crate::Result<[u8; 32]> {
    if recipient_sk.bytes.len() != ML_KEM_768_SK_SEED_LEN {
        anyhow::bail!(
            "invalid ML-KEM-768 secret seed length: got {}, expected {}",
            recipient_sk.bytes.len(),
            ML_KEM_768_SK_SEED_LEN
        );
    }
    if envelope.kem_ciphertext.len() != ML_KEM_768_CT_LEN {
        anyhow::bail!(
            "invalid ML-KEM-768 ciphertext length: got {}, expected {}",
            envelope.kem_ciphertext.len(),
            ML_KEM_768_CT_LEN
        );
    }
    if envelope.wrap_nonce.len() != 12 {
        anyhow::bail!(
            "invalid wrap nonce length: got {}, expected 12",
            envelope.wrap_nonce.len()
        );
    }
    if envelope.wrapped_key.len() != 32 + 16 {
        anyhow::bail!(
            "invalid wrapped_key length: got {}, expected 48",
            envelope.wrapped_key.len()
        );
    }

    let mut sk_seed = [0u8; ML_KEM_768_SK_SEED_LEN];
    sk_seed.copy_from_slice(&recipient_sk.bytes);
    let dk = <MlKem768 as Kem>::DecapsulationKey::from_seed(Array(sk_seed));
    let mut ct_arr = [0u8; ML_KEM_768_CT_LEN];
    ct_arr.copy_from_slice(&envelope.kem_ciphertext);
    let ss: MlKemSharedKey = dk.decapsulate(&Array(ct_arr));

    let kek: [u8; 32] = hkdf_derive(ss.as_slice(), HKDF_SALT, HKDF_INFO)?;
    let engine = CryptoEngine::new(AeadAlgorithm::Aes256Gcm, kek);
    let aead = crate::crypto_engine::aead::AeadEnvelope {
        algorithm: AeadAlgorithm::Aes256Gcm,
        nonce: envelope.wrap_nonce.to_vec(),
        aad_blake3: blake3::hash(WRAP_AAD).to_hex().to_string(),
        ciphertext: envelope.wrapped_key.clone(),
    };
    let pt = engine.decrypt(&aead, WRAP_AAD)?;
    anyhow::ensure!(pt.len() == 32, "decrypted data key has wrong length");
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Hex serde helpers for the on-disk KeyEnvelope JSON.
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex char at index {i}"))?;
        let l = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("bad hex char at index {}", i + 1))?;
        out.push(((h << 4) | l) as u8);
        i += 2;
    }
    Ok(out)
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = super::hex_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod hex_12 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = super::hex_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 12 {
            return Err(serde::de::Error::custom("expected 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::hex_decode(&s).map_err(serde::de::Error::custom)
    }
}
