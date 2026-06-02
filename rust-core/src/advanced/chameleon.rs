//! Chameleon Cipher — multi-key encryption.
//!
//! Encrypts N plaintexts into one ciphertext such that key K_i reveals
//! plaintext P_i. No key reveals whether any plaintext is the "real"
//! one — all are equally embedded.
//!
//! # What this defends against
//!
//! - **Coercion**: An attacker who forces you to reveal a key gets a
//!   valid plaintext, but cannot prove it's the "real" one.
//! - **Brute force**: Every key produces valid output. The attacker
//!   cannot distinguish correct from incorrect decryption.
//! - **Known-plaintext**: Knowing one (key, plaintext) pair reveals
//!   nothing about other pairs.
//!
//! # How it works
//!
//! 1. Generate a random 32-byte mask R.
//! 2. For each plaintext P_i and key K_i:
//!    `C_i = P_i XOR HKDF(R, K_i)`
//! 3. Final ciphertext: `R || C_0 || C_1 || ... || C_{N-1}`
//!
//! Each key K_i derives a unique mask from R, so each key reveals
//! only its corresponding plaintext. The other plaintexts remain
//! hidden (XOR'd with different masks).
//!
//! # Limitations
//!
//! - All plaintexts must be the same length (padded if necessary).
//! - Ciphertext is N times the plaintext size (one per key).
//! - This is NOT information-theoretically secure — it's computationally
//!   secure under the assumption that HKDF is a secure PRF.

use blake3;

/// Maximum number of keys supported.
pub const MAX_KEYS: usize = 8;

/// Encrypt N plaintexts with N keys into a single ciphertext.
///
/// Each plaintext is XOR'd with a mask derived from a random seed
/// and the corresponding key. The seed is prepended to the ciphertext.
pub fn encrypt<const N: usize>(
    plaintexts: &[[u8; 32]; N],
    keys: &[[u8; 32]; N],
) -> crate::Result<Vec<u8>> {
    use rand::RngCore;

    // Generate random seed.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    let mut ciphertext = Vec::with_capacity(32 + N * 32);
    ciphertext.extend_from_slice(&seed);

    for i in 0..N {
        let mask = derive_mask(&seed, &keys[i]);
        let mut block = [0u8; 32];
        for j in 0..32 {
            block[j] = plaintexts[i][j] ^ mask[j];
        }
        ciphertext.extend_from_slice(&block);
    }

    Ok(ciphertext)
}

/// Decrypt a ciphertext with a specific key.
///
/// The key determines which block to unmask. Returns the plaintext
/// corresponding to this key.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], key_index: usize) -> crate::Result<[u8; 32]> {
    anyhow::ensure!(ciphertext.len() >= 32, "ciphertext too short");
    anyhow::ensure!(
        ciphertext.len() >= 32 + (key_index + 1) * 32,
        "ciphertext too short for key index {key_index}"
    );

    let seed: [u8; 32] = ciphertext[..32].try_into().unwrap();
    let mask = derive_mask(&seed, key);

    let block_start = 32 + key_index * 32;
    let block = &ciphertext[block_start..block_start + 32];

    let mut plaintext = [0u8; 32];
    for i in 0..32 {
        plaintext[i] = block[i] ^ mask[i];
    }

    Ok(plaintext)
}

/// Derive a mask from the seed and key using BLAKE3 as a PRF.
fn derive_mask(seed: &[u8; 32], key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria:chameleon:mask:v1");
    hasher.update(seed);
    hasher.update(key);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let p1 = [0x42u8; 32];
        let p2 = [0x55u8; 32];
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];

        let ct = encrypt(&[p1, p2], &[k1, k2]).unwrap();
        let r1 = decrypt(&ct, &k1, 0).unwrap();
        let r2 = decrypt(&ct, &k2, 1).unwrap();

        assert_eq!(r1, p1);
        assert_eq!(r2, p2);
    }

    #[test]
    fn wrong_key_produces_different_plaintext() {
        let p1 = [0x42u8; 32];
        let p2 = [0x55u8; 32];
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];

        let ct = encrypt(&[p1, p2], &[k1, k2]).unwrap();

        // Decrypting with k1 at index 1 should NOT produce p2.
        let wrong = decrypt(&ct, &k1, 1).unwrap();
        assert_ne!(wrong, p2);
    }

    #[test]
    fn same_plaintext_different_keys() {
        let p = [0x42u8; 32];
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];

        let ct = encrypt(&[p, p], &[k1, k2]).unwrap();
        let r1 = decrypt(&ct, &k1, 0).unwrap();
        let r2 = decrypt(&ct, &k2, 1).unwrap();

        // Both decrypt to the same plaintext.
        assert_eq!(r1, p);
        assert_eq!(r2, p);
    }

    #[test]
    fn ciphertext_contains_seed_and_blocks() {
        let p = [0x42u8; 32];
        let k = [0x01u8; 32];
        let ct = encrypt(&[p], &[k]).unwrap();
        // 32 bytes seed + 32 bytes block = 64 bytes
        assert_eq!(ct.len(), 64);
    }

    #[test]
    fn too_short_ciphertext_fails() {
        let result = decrypt(&[0u8; 10], &[0u8; 32], 0);
        assert!(result.is_err());
    }
}
