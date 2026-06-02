//! Post-quantum signatures via ML-DSA-65 (FIPS 204).
//!
//! Used to authenticate the owner of a share file. The owner generates a
//! keypair once, keeps the secret key offline, and distributes the public
//! key out-of-band to recipients. When the owner adds a recipient to a
//! volume, the owner signs the resulting ML-KEM envelope with their
//! ML-DSA-65 secret key; the recipient verifies the signature with the
//! owner's ML-DSA-65 public key before unwrapping the volume root key.
//!
//! ## Security properties
//!
//! - **Post-quantum** — ML-DSA-65 is IND-CCA2-secure under standard lattice
//!   assumptions (module-LWE / module-SIS). A future-quantum adversary
//!   cannot forge a signature on a modified envelope.
//! - **EUF-CMA** — existential unforgeability under chosen-message attack.
//!   An attacker who can request signatures on chosen envelopes still
//!   cannot produce a valid signature on a new envelope.
//! - **Deterministic** — the crate's `Signer` impl uses the optional
//!   deterministic variant of ML-DSA.Sign, so the same `(sk, message)`
//!   pair always produces the same signature. This is what we want for
//!   the share-file audit trail.
//!
//! ## Key serialization
//!
//! - Public key: 1952 bytes (the FIPS 204 verifying key).
//! - Secret key: 32-byte seed (FIPS 204 preferred form; the 4032-byte
//!   expanded form is reconstructed on demand).
//! - Signature: 3309 bytes.
//!
//! The `ml-dsa` crate is a pure-Rust FIPS 204 implementation with no C
//! dependencies. A future `pqc-oqs` feature can swap the implementation
//! for liboqs without changing this module's public API.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::MlDsa65;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const ML_DSA_65_PK_LEN: usize = 1952;
pub const ML_DSA_65_SK_SEED_LEN: usize = 32;
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// Owner's post-quantum verifying key. Distributed out-of-band to
/// recipients so they can verify the owner signed each share envelope.
#[derive(Clone, Zeroize, Serialize, Deserialize)]
pub struct OwnerPublicKey {
    /// Raw FIPS 204 verifying key bytes.
    #[serde(with = "hex_vec")]
    pub bytes: Vec<u8>,
}

/// Owner's post-quantum signing key. Kept secret by the owner. The
/// 32-byte seed form is preferred; the expanded form is reconstructed
/// on demand.
#[derive(Clone, Zeroize, Serialize, Deserialize)]
pub struct OwnerSecretKey {
    /// 32-byte FIPS 204 seed.
    #[serde(with = "hex_vec")]
    pub bytes: Vec<u8>,
}

/// Owner's keypair. The secret key is zeroized on drop.
pub struct OwnerKeyPair {
    pub public: OwnerPublicKey,
    pub secret: OwnerSecretKey,
}

impl Drop for OwnerKeyPair {
    fn drop(&mut self) {
        self.public.bytes.zeroize();
        self.secret.bytes.zeroize();
    }
}

/// Generate a fresh ML-DSA-65 keypair. The secret key is stored as a
/// 32-byte seed; the verifying key is stored as 1952 raw bytes.
pub fn generate_keypair() -> OwnerKeyPair {
    let mut seed_bytes = [0u8; ML_DSA_65_SK_SEED_LEN];
    OsRng.fill_bytes(&mut seed_bytes);
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_bytes.into());
    let vk = sk.verifying_key();
    OwnerKeyPair {
        public: OwnerPublicKey {
            bytes: vk.encode().to_vec(),
        },
        secret: OwnerSecretKey {
            bytes: seed_bytes.to_vec(),
        },
    }
}

/// A 32-byte BLAKE3 fingerprint of the owner's public key. Used in the
/// share file to identify which owner key signed each event.
pub fn owner_key_id(public_key: &OwnerPublicKey) -> [u8; 32] {
    *blake3::hash(&public_key.bytes).as_bytes()
}

/// Sign `message` with the owner's secret key. Returns the raw signature
/// bytes. Uses ML-DSA-65's deterministic Sign variant.
pub fn sign(message: &[u8], secret_key: &OwnerSecretKey) -> crate::Result<Vec<u8>> {
    if secret_key.bytes.len() != ML_DSA_65_SK_SEED_LEN {
        anyhow::bail!(
            "invalid ML-DSA-65 secret seed length: got {}, expected {}",
            secret_key.bytes.len(),
            ML_DSA_65_SK_SEED_LEN
        );
    }
    let mut seed_arr = [0u8; ML_DSA_65_SK_SEED_LEN];
    seed_arr.copy_from_slice(&secret_key.bytes);
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed_arr.into());
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

/// Verify `signature` over `message` with the owner's public key.
pub fn verify(message: &[u8], signature: &[u8], public_key: &OwnerPublicKey) -> crate::Result<()> {
    if public_key.bytes.len() != ML_DSA_65_PK_LEN {
        anyhow::bail!(
            "invalid ML-DSA-65 public key length: got {}, expected {}",
            public_key.bytes.len(),
            ML_DSA_65_PK_LEN
        );
    }
    if signature.len() != ML_DSA_65_SIG_LEN {
        anyhow::bail!(
            "invalid ML-DSA-65 signature length: got {}, expected {}",
            signature.len(),
            ML_DSA_65_SIG_LEN
        );
    }
    let pk_enc: ml_dsa::EncodedVerifyingKey<MlDsa65> = public_key
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 public key bytes"))?;
    let pk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pk_enc);
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 signature bytes"))?;
    pk.verify(message, &sig)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signature verification failed: {e:?}"))?;
    Ok(())
}

mod hex_vec {
    use super::hex_decode;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex_decode(&s).map_err(serde::de::Error::custom)?;
        Ok(bytes)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = generate_keypair();
        let msg = b"soteria:share:envelope:v1:roundtrip";
        let sig = sign(msg, &kp.secret).unwrap();
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
        verify(msg, &sig, &kp.public).unwrap();
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let kp = generate_keypair();
        let msg = b"original message";
        let sig = sign(msg, &kp.secret).unwrap();
        let tampered = b"tampered message";
        let result = verify(tampered, &sig, &kp.public);
        assert!(result.is_err(), "verify must fail on tampered message");
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let msg = b"hello";
        let sig = sign(msg, &kp1.secret).unwrap();
        let result = verify(msg, &sig, &kp2.public);
        assert!(
            result.is_err(),
            "verify must fail when using a different owner's PK"
        );
    }

    #[test]
    fn owner_key_id_is_32_bytes() {
        let kp = generate_keypair();
        let id = owner_key_id(&kp.public);
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn sign_rejects_wrong_size_key() {
        let bogus = OwnerSecretKey {
            bytes: vec![0u8; 16],
        };
        let result = sign(b"msg", &bogus);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_size_signature() {
        let kp = generate_keypair();
        let result = verify(b"msg", &[0u8; 100], &kp.public);
        assert!(result.is_err());
    }

    #[test]
    fn public_key_size_is_1952() {
        let kp = generate_keypair();
        assert_eq!(kp.public.bytes.len(), ML_DSA_65_PK_LEN);
    }

    #[test]
    fn secret_key_size_is_32() {
        let kp = generate_keypair();
        assert_eq!(kp.secret.bytes.len(), ML_DSA_65_SK_SEED_LEN);
    }

    #[test]
    fn deterministic_signing_produces_same_signature() {
        let kp = generate_keypair();
        let msg = b"deterministic test message";
        let sig1 = sign(msg, &kp.secret).unwrap();
        let sig2 = sign(msg, &kp.secret).unwrap();
        assert_eq!(
            sig1, sig2,
            "ML-DSA-65 deterministic Sign variant must produce the same bytes for the same (sk, msg)"
        );
    }
}
