use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum KeyState {
    Generated,
    Sealed,
    Active,
    Rotating,
    Revoked,
    Zeroized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycle {
    pub state: KeyState,
    pub generation: u64,
}

impl KeyLifecycle {
    pub fn new() -> Self {
        Self {
            state: KeyState::Generated,
            generation: 0,
        }
    }
    pub fn transition(&mut self, next: KeyState) {
        self.state = next;
        if matches!(next, KeyState::Rotating) {
            self.generation += 1;
        }
    }
    pub fn zeroize_key(key: &mut [u8; 32]) {
        key.zeroize();
    }
}

impl Default for KeyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}
