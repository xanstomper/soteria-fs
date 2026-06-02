use crate::crypto_engine::kdf::ratchet_key;
use zeroize::Zeroizing;

pub struct KeyRatchet {
    current: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl KeyRatchet {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            current: Zeroizing::new(seed),
            counter: 0,
        }
    }
    pub fn current_key(&self) -> [u8; 32] {
        *self.current
    }
    pub fn advance(&mut self, entropy: &[u8]) -> crate::Result<[u8; 32]> {
        self.counter += 1;
        ratchet_key(&mut self.current, entropy, self.counter)
    }
}
