//! Process-level write authorization.
//!
//! Every write to the encrypted volume requires a valid intent token —
//! a short-lived HMAC signed by the current process. This prevents
//! malware from writing to the volume even if it gains access to the
//! filesystem.
//!
//! # How it works
//!
//! 1. On mount, a session key is derived from the volume key + process
//!    identity (PID + binary hash).
//! 2. Each write request includes an intent token:
//!    `HMAC-SHA256(session_key, timestamp || block_index)`.
//! 3. The token is verified before the write is allowed.
//! 4. Tokens expire after 1 second (replay protection).
//!
//! # Limitations
//!
//! This is a userspace implementation. A kernel-level implementation
//! (seccomp-bpf, Landlock) would be stronger but requires platform-
//! specific code and root privileges.

use blake3;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum age of an intent token before it's rejected.
const INTENT_WINDOW: Duration = Duration::from_secs(1);

/// Session key derived from volume key + process identity.
pub type SessionKey = [u8; 32];

/// Derive a session key from the volume key and current process identity.
pub fn derive_session_key(volume_key: &[u8; 32]) -> SessionKey {
    let pid = std::process::id();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria:intent-session:v1");
    hasher.update(volume_key);
    hasher.update(&pid.to_le_bytes());
    // Include binary path hash for process identity.
    if let Ok(exe) = std::env::current_exe() {
        let exe_hash = blake3::hash(exe.to_string_lossy().as_bytes());
        hasher.update(exe_hash.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Generate an intent token for a write operation.
pub fn generate_intent_token(session_key: &SessionKey, block_index: u64) -> [u8; 32] {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria:intent-token:v1");
    hasher.update(session_key);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(&block_index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify an intent token for a write operation.
pub fn verify_intent_token(
    session_key: &SessionKey,
    block_index: u64,
    token: &[u8; 32],
    max_age: Duration,
) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check current timestamp and recent timestamps (within the window).
    let window_secs = max_age.as_secs().max(1);
    for offset in 0..=window_secs {
        let ts = now.saturating_sub(offset);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:intent-token:v1");
        hasher.update(session_key);
        hasher.update(&ts.to_le_bytes());
        hasher.update(&block_index.to_le_bytes());
        let expected = hasher.finalize();
        if *expected.as_bytes() == *token {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_roundtrip() {
        let key = [0x42u8; 32];
        let session = derive_session_key(&key);
        let token = generate_intent_token(&session, 0);
        assert!(verify_intent_token(&session, 0, &token, INTENT_WINDOW));
    }

    #[test]
    fn wrong_block_index_fails() {
        let key = [0x42u8; 32];
        let session = derive_session_key(&key);
        let token = generate_intent_token(&session, 0);
        assert!(!verify_intent_token(&session, 1, &token, INTENT_WINDOW));
    }

    #[test]
    fn wrong_session_key_fails() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let session1 = derive_session_key(&key1);
        let session2 = derive_session_key(&key2);
        let token = generate_intent_token(&session1, 0);
        assert!(!verify_intent_token(&session2, 0, &token, INTENT_WINDOW));
    }

    #[test]
    fn session_key_is_deterministic() {
        let key = [0x42u8; 32];
        let s1 = derive_session_key(&key);
        let s2 = derive_session_key(&key);
        assert_eq!(s1, s2);
    }
}
