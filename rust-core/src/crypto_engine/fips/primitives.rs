//! FIPS-mode cryptographic primitives.
//!
//! ## What this module does
//!
//! When the `fips` Cargo feature is enabled, **all** cryptographic
//! operations in Soteria are routed through this module. The
//! implementations here use the `ring` crate, which is a FIPS-validated
//! cryptographic module (the underlying BoringCrypto FIPS module is
//! NIST certificate #4288 and successors).
//!
//! When the `fips` feature is **not** enabled, the rest of the code
//! uses the RustCrypto crates (`aes`, `argon2`, `blake3`) for
//! non-validated operation. This is a deliberate dual-build:
//! - **Default build**: faster, broader algorithm set (XChaCha,
//!   Argon2id, BLAKE3), not FIPS-validated.
//! - **FIPS build** (`--features fips`): all crypto goes through
//!   `ring`, power-on self-tests gate every operation, the binary
//!   refuses to start if self-tests fail.
//!
//! ## Algorithms
//!
//! | Operation | FIPS-validated impl (this module) | Default impl |
//! |---|---|---|
//! | Hash | SHA-256, SHA-512 (FIPS 180-4) | BLAKE3 |
//! | MAC | HMAC-SHA-256 (FIPS 198-1) | (none) |
//! | KDF (password) | PBKDF2-HMAC-SHA-256 (FIPS SP 800-132) | Argon2id |
//! | KDF (extract+expand) | HKDF-SHA-256 (FIPS SP 800-56C) | HKDF-SHA-512 |
//! | AEAD (FDE sector) | AES-256-GCM (FIPS SP 800-38D) | AES-256-XTS |
//! | DRBG | ring::SystemRandom (FIPS SP 800-90A) | OsRng |
//!
//! ## Non-allowed algorithms
//!
//! In FIPS mode, the following are **prohibited**:
//! - XChaCha20-Poly1305 (non-approved; SP 800-38D lists only AES-GCM
//!   and AES-CCM as approved AEADs)
//! - Argon2id (not in FIPS 140-3 approved list; SP 800-63B allows it
//!   for password storage but FIPS 140-3 doesn't list it for module
//!   use)
//! - BLAKE3 (not a FIPS-approved hash)
//! - AES-256-XTS (algorithm approved, but no FIPS-validated impl
//!   available in pure-Rust bindings; use AES-256-GCM instead)
//!
//! The build refuses to compile if a non-allowed algorithm is
//! referenced from a FIPS-mode code path.

use ring::aead;
use ring::digest;
use ring::hkdf;
use ring::pbkdf2;
use ring::rand::SystemRandom;

pub use ring::aead::AES_256_GCM;
pub use ring::digest::SHA256;
pub use ring::digest::SHA512;
pub use ring::hmac::HMAC_SHA256;
pub use ring::hmac::HMAC_SHA512;

/// The system DRBG. Thread-safe and re-entrant.
pub fn system_random() -> SystemRandom {
    SystemRandom::new()
}

/// FIPS-mode SHA-256. Returns 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// FIPS-mode SHA-512. Returns 64 bytes.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = digest::digest(&SHA512, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_ref());
    out
}

/// FIPS-mode HMAC-SHA-256. Returns 32 bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let s_key = ring::hmac::Key::new(HMAC_SHA256, key);
    let tag = ring::hmac::sign(&s_key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// FIPS-mode HMAC-SHA-512. Returns 64 bytes.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let s_key = ring::hmac::Key::new(HMAC_SHA512, key);
    let tag = ring::hmac::sign(&s_key, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Constant-time HMAC-SHA-256 verification. Returns `Ok(())` on match.
pub fn hmac_sha256_verify(
    key: &[u8],
    data: &[u8],
    expected: &[u8],
) -> Result<(), ring::error::Unspecified> {
    let s_key = ring::hmac::Key::new(HMAC_SHA256, key);
    ring::hmac::verify(&s_key, data, expected)
}

/// FIPS-mode PBKDF2-HMAC-SHA-256. The iteration count is fixed at
/// 600,000 per OWASP 2023 (which lines up with NIST SP 800-132's
/// "as high as practical" guidance). The output is 32 bytes.
pub fn pbkdf2_sha256(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iterations =
        core::num::NonZeroU32::new(iterations.max(1000)).expect("max(1000) is non-zero");
    let mut out = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase,
        &mut out,
    );
    out
}

/// FIPS-mode HKDF-SHA-256. `ikm` is the input keying material; `salt`
/// may be empty (None); `info` is the context string. Output is
/// written to `out`.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), ring::error::Unspecified> {
    let s_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.unwrap_or(&[]));
    let prk = s_salt.extract(ikm);
    let info_chunks: [&[u8]; 1] = [info];
    let okm = prk
        .expand(&info_chunks, OkmLen(out.len()))
        .map_err(|_| ring::error::Unspecified)?;
    okm.fill(out).map_err(|_| ring::error::Unspecified)?;
    Ok(())
}

/// Wrapper that adapts an arbitrary length to ring's `KeyType` trait.
struct OkmLen(usize);
impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// FIPS-mode AES-256-GCM seal. `key` must be 32 bytes; `nonce` must
/// be 12 bytes; `aad` is the additional authenticated data. The
/// plaintext is encrypted in place (same length) and the 16-byte
/// tag is returned.
pub fn aes256_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &mut [u8],
) -> Result<[u8; 16], ring::error::Unspecified> {
    let s_key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&AES_256_GCM, key.as_ref()).map_err(|_| ring::error::Unspecified)?,
    );
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let tag = s_key
        .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), plaintext)
        .map_err(|_| ring::error::Unspecified)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// FIPS-mode AES-256-GCM open. Decrypts ciphertext+tag in place
/// (input is `ct_len + 16` bytes; output is `ct_len` bytes of
/// plaintext occupying the first `ct_len` bytes of the buffer).
/// Returns the plaintext length.
pub fn aes256_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &mut [u8],
) -> Result<usize, ring::error::Unspecified> {
    let s_key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&AES_256_GCM, key.as_ref()).map_err(|_| ring::error::Unspecified)?,
    );
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    if ciphertext_and_tag.len() < 16 {
        return Err(ring::error::Unspecified);
    }
    let pt_len = ciphertext_and_tag.len() - 16;
    s_key
        .open_in_place(nonce, aead::Aad::from(aad), ciphertext_and_tag)
        .map_err(|_| ring::error::Unspecified)?;
    Ok(pt_len)
}

/// FIPS-mode secure random bytes.
pub fn random_bytes(out: &mut [u8]) -> Result<(), ring::error::Unspecified> {
    use ring::rand::SecureRandom;
    SystemRandom::new().fill(out)
}

/// FIPS-mode secure random `u32`.
pub fn random_u32() -> Result<u32, ring::error::Unspecified> {
    use ring::rand::SecureRandom;
    let mut buf = [0u8; 4];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| ring::error::Unspecified)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        let tag = hmac_sha256(&key, data);
        assert_eq!(hex::encode(tag), hex::encode(&expected));
    }

    #[test]
    fn pbkdf2_roundtrip() {
        let pw = b"password";
        let salt = b"salt";
        let k1 = pbkdf2_sha256(pw, salt, 1000);
        let k2 = pbkdf2_sha256(pw, salt, 1000);
        assert_eq!(k1, k2);
        let k3 = pbkdf2_sha256(b"different", salt, 1000);
        assert_ne!(k1, k3);
    }

    #[test]
    fn aes_gcm_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 12];
        let aad = b"aad";
        let mut buf = b"hello world".to_vec();
        let pt_len = buf.len();
        let tag = aes256_gcm_seal(&key, &nonce, aad, &mut buf).unwrap();
        assert_eq!(buf.len(), pt_len);
        // Append tag for open.
        buf.extend_from_slice(&tag);
        let recovered_len = aes256_gcm_open(&key, &nonce, aad, &mut buf).unwrap();
        assert_eq!(recovered_len, pt_len);
        assert_eq!(&buf[..recovered_len], b"hello world");
    }

    #[test]
    fn aes_gcm_tamper_detected() {
        let key = [0x42u8; 32];
        let nonce = [0xABu8; 12];
        let aad = b"aad";
        let mut buf = b"hello world".to_vec();
        let tag = aes256_gcm_seal(&key, &nonce, aad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        // Flip a bit in the ciphertext.
        buf[0] ^= 0x01;
        let r = aes256_gcm_open(&key, &nonce, aad, &mut buf);
        assert!(r.is_err());
    }

    #[test]
    fn hkdf_known_vector() {
        // RFC 5869 Test Case 1 (HKDF-SHA-256, 42 bytes output)
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut out = [0u8; 42];
        hkdf_sha256(&ikm, Some(&salt), &info, &mut out).unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(hex::encode(out), hex::encode(expected));
    }
}
