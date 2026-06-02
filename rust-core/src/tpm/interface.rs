use zeroize::Zeroizing;

pub trait TpmProvider: Send + Sync + 'static {
    fn seal(&self, plaintext_key: &[u8; 32]) -> crate::Result<Vec<u8>>;
    fn unseal(&self, sealed_blob: &[u8]) -> crate::Result<Zeroizing<[u8; 32]>>;
    fn boot_measurement(&self) -> crate::Result<[u8; 32]>;
}

pub struct MockTpmProvider;

impl TpmProvider for MockTpmProvider {
    fn seal(&self, plaintext_key: &[u8; 32]) -> crate::Result<Vec<u8>> {
        Ok(plaintext_key.to_vec())
    }
    fn unseal(&self, sealed_blob: &[u8]) -> crate::Result<Zeroizing<[u8; 32]>> {
        anyhow::ensure!(sealed_blob.len() == 32, "invalid mock sealed blob");
        let mut out = [0u8; 32];
        out.copy_from_slice(sealed_blob);
        Ok(Zeroizing::new(out))
    }
    fn boot_measurement(&self) -> crate::Result<[u8; 32]> {
        Ok(blake3::hash(b"mock-secure-boot-measurement").into())
    }
}
