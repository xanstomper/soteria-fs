use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Nonce96(pub [u8; 12]);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct Nonce192(pub [u8; 24]);

impl Nonce96 {
    pub fn random() -> Self {
        let mut n = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut n);
        Self(n)
    }
}

impl Nonce192 {
    pub fn random() -> Self {
        let mut n = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut n);
        Self(n)
    }
}
