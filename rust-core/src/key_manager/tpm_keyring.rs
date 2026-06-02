use crate::tpm::interface::TpmProvider;
use zeroize::Zeroizing;

pub struct TpmKeyring<T: TpmProvider> {
    provider: T,
}

impl<T: TpmProvider> TpmKeyring<T> {
    pub fn new(provider: T) -> Self {
        Self { provider }
    }
    pub fn seal_root(&self, root: &[u8; 32]) -> crate::Result<Vec<u8>> {
        self.provider.seal(root)
    }
    pub fn unseal_root(&self, blob: &[u8]) -> crate::Result<Zeroizing<[u8; 32]>> {
        self.provider.unseal(blob)
    }
}
