use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub fn argon2id_root_from_password(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
) -> crate::Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(memory_kib, iterations, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2id params: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2id failed: {e:?}"))?;
    Ok(out)
}

pub fn hkdf_derive(input_key_material: &[u8], salt: &[u8], info: &[u8]) -> crate::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

pub fn ratchet_key(
    current: &mut Zeroizing<[u8; 32]>,
    entropy: &[u8],
    counter: u64,
) -> crate::Result<[u8; 32]> {
    let mut info = b"SOTERIA key ratchet v1".to_vec();
    info.extend_from_slice(&counter.to_le_bytes());
    let next = hkdf_derive(current.as_slice(), entropy, &info)?;
    current.zeroize();
    **current = next;
    Ok(next)
}
