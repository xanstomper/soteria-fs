//! ML-KEM-768 file sharing — multi-recipient volume key distribution.
//!
//! ## Threat model
//!
//! A volume owner wants to share an encrypted file with one or more
//! recipients. The owner holds the volume's 32-byte root key (derived from a
//! passphrase via Argon2id, or supplied directly). For each recipient:
//!
//! 1. The owner encapsulates a 32-byte shared secret to the recipient's
//!    ML-KEM-768 public key.
//! 2. The owner derives a 32-byte key-encryption key (KEK) from the shared
//!    secret via HKDF.
//! 3. The owner AES-256-GCM-encrypts the volume root key under the KEK.
//! 4. The owner signs the resulting envelope with their ML-DSA-65 secret
//!    key so recipients can cryptographically verify that the volume owner
//!    added them to the share file.
//! 5. The envelope + signature is stored in the share file.
//!
//! A recipient reverses the process using their ML-KEM secret key. If the
//! recipient also holds the owner's ML-DSA-65 public key, they verify the
//! signature before unwrapping the volume root key. The root key never
//! appears in cleartext outside the owner's and recipient's trust boundaries.
//!
//! ## On-disk format
//!
//! The share file is a JSON sidecar at `<volume>.sot.shares`. It is
//! append-only: every `Added` and `Revoked` event is recorded. The currently
//! active set is derived by walking the events in reverse and taking each
//! recipient's latest state. The volume root key fingerprint (`BLAKE3(root_key)`)
//! is stored in the header to detect cross-volume graft attacks.
//!
//! ```text
//! {
//!   "version": 2,
//!   "volume_root_key_fingerprint": "<32 B BLAKE3, hex>",
//!   "events": [
//!     { "action": "added",
//!       "recipient_key_id": "...",
//!       "recipient_pk_bytes": "...",
//!       "envelope": {...},
//!       "owner_sig_pk_id": "<32 B BLAKE3 of owner PK, hex>",
//!       "owner_signature": "<3309 B ML-DSA-65 sig, hex>",
//!       "at_unix_ms": ... },
//!     { "action": "revoked", "recipient_key_id": "...", "reason": "...", "at_unix_ms": ... },
//!     ...
//!   ]
//! }
//! ```
//!
//! `owner_sig_pk_id` is a 32-byte BLAKE3 fingerprint of the owner's ML-DSA-65
//! public key; `owner_signature` is the ML-DSA-65 signature over the
//! canonical envelope bytes (see [`envelope_signing_payload`]).

use crate::crypto_engine::dsa::{self, OwnerPublicKey, OwnerSecretKey};
use crate::crypto_engine::pq::{
    unwrap_key, wrap_key, KeyEnvelope, PublicKey, SecretKey, ML_KEM_768_PK_LEN,
};
use crate::fs_layer::durability::fsync_dir;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const SHARES_SIDECAR_SUFFIX: &str = ".sot.shares";
pub const SHARES_VERSION: u32 = 2;

/// Domain separation tag prefixed to every envelope signature payload. Pins
/// the signature to the share-envelope protocol so an ML-DSA-65 signature
/// minted for any other context (e.g. a future "policy update" protocol)
/// cannot be replayed against a share envelope.
pub const ENVELOPE_SIGN_DOMAIN: &[u8] = b"soteria:share:envelope:v1";

/// Resolve `<volume>` to `<volume>.sot.shares`.
pub fn shares_path_for(volume_path: &Path) -> PathBuf {
    let mut s = volume_path.as_os_str().to_owned();
    s.push(SHARES_SIDECAR_SUFFIX);
    PathBuf::from(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ShareEvent {
    Added {
        #[serde(with = "hex_32")]
        recipient_key_id: [u8; 32],
        #[serde(with = "hex_pk")]
        recipient_pk_bytes: Vec<u8>,
        envelope: KeyEnvelope,
        /// 32-byte BLAKE3 fingerprint of the owner's ML-DSA-65 public key.
        /// Recipients can use this to select the correct owner PK from a
        /// keyring before verifying the signature.
        #[serde(with = "hex_32")]
        owner_sig_pk_id: [u8; 32],
        /// ML-DSA-65 signature over the canonical envelope bytes
        /// (see [`envelope_signing_payload`]). 3309 bytes.
        #[serde(with = "hex_pk")]
        owner_signature: Vec<u8>,
        at_unix_ms: u64,
    },
    Revoked {
        #[serde(with = "hex_32")]
        recipient_key_id: [u8; 32],
        at_unix_ms: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFile {
    pub version: u32,
    #[serde(with = "hex_32")]
    pub volume_root_key_fingerprint: [u8; 32],
    pub events: Vec<ShareEvent>,
    /// PATCH-06: BLAKE3 chain hash per event. Prevents event reordering
    /// and rollback. Each entry is `BLAKE3(prev_chain || event_bytes)`.
    /// The chain protects against an attacker who has write access to
    /// the share file reordering, removing, or replaying events.
    #[serde(default)]
    pub chain: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveRecipient {
    #[serde(with = "hex_32")]
    pub recipient_key_id: [u8; 32],
    pub recipient_pk_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevokedRecipient {
    #[serde(with = "hex_32")]
    pub recipient_key_id: [u8; 32],
    pub revoked_at_unix_ms: u64,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct DecryptedShare {
    pub recipient_key_id: [u8; 32],
    pub root_key: [u8; 32],
}

/// A single active envelope together with its ML-DSA-65 signature metadata.
/// Tuple layout: `(PublicKey, key_id, KeyEnvelope, owner_sig_pk_id, owner_signature, at_unix_ms, event_index)`.
pub type SignedEnvelope = (
    PublicKey,
    [u8; 32],
    KeyEnvelope,
    [u8; 32],
    Vec<u8>,
    u64,
    u64,
);

impl ShareFile {
    /// Build a fresh, empty share file for a volume with the given root key.
    pub fn new(root_key: &[u8; 32]) -> Self {
        Self {
            version: SHARES_VERSION,
            volume_root_key_fingerprint: *blake3::hash(root_key).as_bytes(),
            events: Vec::new(),
            chain: Vec::new(),
        }
    }

    /// Open the share file for the given volume, validating that its
    /// `volume_root_key_fingerprint` matches the supplied root key. Missing
    /// file is treated as a valid empty share file (the owner is setting up
    /// sharing for the first time).
    ///
    /// V-AUDIT-9: Validates the BLAKE3 chain on load. An attacker who has
    /// file-write access to the share file can rewrite events without
    /// updating the chain; we detect that here.
    pub fn open(volume_path: &Path, root_key: &[u8; 32]) -> crate::Result<Self> {
        let path = shares_path_for(volume_path);
        let expected_fp: [u8; 32] = *blake3::hash(root_key).as_bytes();
        if !path.exists() {
            return Ok(Self::new(root_key));
        }
        let raw = std::fs::read(&path)?;
        let sf: ShareFile = serde_json::from_slice(&raw)
            .map_err(|e| anyhow::anyhow!("share file: malformed JSON: {e}"))?;
        if sf.version != SHARES_VERSION {
            anyhow::bail!("share file: unsupported version {}", sf.version);
        }
        if sf.volume_root_key_fingerprint != expected_fp {
            anyhow::bail!(
                "share file: volume key fingerprint mismatch (wrong volume or wrong key)"
            );
        }
        // V-AUDIT-9: Verify chain on load. Refuse to use a tampered share file.
        if let Some(bad) = sf.verify_chain() {
            anyhow::bail!("share file: chain broken at event index {bad}");
        }
        Ok(sf)
    }

    /// Persist this share file to disk (atomic rename + parent dir fsync).
    pub fn save(&self, volume_path: &Path) -> crate::Result<()> {
        let path = shares_path_for(volume_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("share file: serialize: {e}"))?;
        let tmp = path.with_extension("shares.tmp");
        std::fs::write(&tmp, &bytes)?;
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, &path)?;
        if let Ok(f) = std::fs::File::open(&path) {
            let _ = f.sync_all();
        }
        fsync_dir(&path);
        Ok(())
    }

    /// Add a new recipient. Errors if the recipient is already active or has
    /// been previously revoked (use a fresh keypair to re-share).
    ///
    /// The owner must sign the resulting envelope with their ML-DSA-65
    /// secret key. Recipients can later verify the signature with the
    /// owner's ML-DSA-65 public key.
    pub fn add_recipient(
        &mut self,
        recipient_pk: &PublicKey,
        root_key: &[u8; 32],
        owner_sk: &OwnerSecretKey,
        now_unix_ms: u64,
    ) -> crate::Result<[u8; 32]> {
        let key_id = KeyEnvelope::recipient_key_id(recipient_pk);
        if self.events.iter().any(|e| event_key_id(e) == Some(key_id)) {
            anyhow::bail!(
                "share: recipient already has history (active or revoked); use a fresh keypair"
            );
        }
        let envelope = wrap_key(root_key, recipient_pk)?;
        // PATCH-07: Full signature scope includes timestamp and event index.
        let event_index = self.events.len() as u64;
        let payload = envelope_signing_payload(
            &key_id,
            &recipient_pk.bytes,
            &envelope,
            now_unix_ms,
            event_index,
        );
        let signature = dsa::sign(&payload, owner_sk)?;
        // Derive the owner key id from the secret key's corresponding public
        // key. The dsa module doesn't expose the public key derived from a
        // secret seed directly, so we reconstruct it.
        let owner_pk_bytes = owner_public_key_bytes_from_secret(owner_sk)?;
        let owner_sig_pk_id = dsa::owner_key_id(&OwnerPublicKey {
            bytes: owner_pk_bytes,
        });
        self.events.push(ShareEvent::Added {
            recipient_key_id: key_id,
            recipient_pk_bytes: recipient_pk.bytes.clone(),
            envelope,
            owner_sig_pk_id,
            owner_signature: signature,
            at_unix_ms: now_unix_ms,
        });
        // PATCH-06: Append chain hash for this event.
        self.append_chain_hash();
        Ok(key_id)
    }

    /// Revoke a recipient. Returns `Ok(true)` if the recipient was active
    /// and is now revoked; `Ok(false)` if the recipient is not currently
    /// active. Errors if the recipient is already revoked.
    pub fn revoke_recipient(
        &mut self,
        recipient_pk: &PublicKey,
        reason: &str,
        now_unix_ms: u64,
    ) -> crate::Result<bool> {
        let key_id = KeyEnvelope::recipient_key_id(recipient_pk);
        let active_keys: std::collections::HashSet<[u8; 32]> = self
            .active_envelopes()
            .into_iter()
            .map(|(_, kid, _)| kid)
            .collect();
        if active_keys.contains(&key_id) {
            self.events.push(ShareEvent::Revoked {
                recipient_key_id: key_id,
                at_unix_ms: now_unix_ms,
                reason: reason.to_string(),
            });
            // PATCH-06: Append chain hash for this event.
            self.append_chain_hash();
            return Ok(true);
        }
        let was_revoked = self.events.iter().any(
            |e| matches!(e, ShareEvent::Revoked { recipient_key_id: kid, .. } if *kid == key_id),
        );
        if was_revoked {
            anyhow::bail!("share: recipient is already revoked");
        }
        Ok(false)
    }

    /// Append a chain hash for the latest event (PATCH-06).
    ///
    /// V-AUDIT-8: Serialization of a `ShareEvent` cannot fail for any input.
    /// We use `expect` rather than `unwrap_or_default` so a failure surfaces
    /// as a panic during development instead of a silent fallback to empty
    /// bytes (which an attacker could predict and forge).
    fn append_chain_hash(&mut self) {
        let prev = self.chain.last().copied().unwrap_or([0u8; 32]);
        let event = self
            .events
            .last()
            .expect("events vec is non-empty when appending chain");
        let event_bytes =
            serde_json::to_vec(event).expect("ShareEvent serialization is total and cannot fail");
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:share-chain:v1");
        hasher.update(&prev);
        hasher.update(&event_bytes);
        self.chain.push(*hasher.finalize().as_bytes());
    }

    /// Verify the chain integrity. Returns the index of the first bad
    /// event, or None if the chain is valid.
    ///
    /// V-AUDIT-7: Strict validation. The chain MUST be the same length as
    /// the events list, and every entry MUST match the recomputed hash.
    /// An attacker who deletes chain entries will be caught here.
    pub fn verify_chain(&self) -> Option<usize> {
        if self.chain.len() != self.events.len() {
            return Some(self.chain.len().min(self.events.len()));
        }
        let mut prev = [0u8; 32];
        for (i, event) in self.events.iter().enumerate() {
            let event_bytes = serde_json::to_vec(event)
                .expect("ShareEvent serialization is total and cannot fail");
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"soteria:share-chain:v1");
            hasher.update(&prev);
            hasher.update(&event_bytes);
            let expected = *hasher.finalize().as_bytes();
            if self.chain[i] != expected {
                return Some(i);
            }
            prev = expected;
        }
        None
    }

    /// Unwrap the volume root key using the recipient's secret key. Tries
    /// each active envelope; the AEAD auth check rejects the wrong ones.
    ///
    /// If `owner_pk` is provided, the signature on each candidate envelope
    /// is verified before the unwrap. If verification fails, the envelope
    /// is rejected and the next candidate is tried. The function returns
    /// the first envelope that passes BOTH the signature check (if
    /// `owner_pk` is `Some`) and the AEAD unwrap.
    pub fn unlock(
        &self,
        recipient_sk: &SecretKey,
        owner_pk: Option<&OwnerPublicKey>,
    ) -> crate::Result<DecryptedShare> {
        let mut owner_id_checked = false;
        for (pk, kid, env, sig_pk_id, signature, at_unix_ms, event_idx) in
            self.active_envelopes_with_signatures()
        {
            // Signature verification is only attempted when the caller
            // supplied an owner PK. Otherwise the signature is recorded in
            // the event but not checked (caller opted out).
            if let Some(opk) = owner_pk {
                let expected_kid = dsa::owner_key_id(opk);
                if expected_kid != sig_pk_id {
                    // Owner key fingerprint doesn't match the signer of
                    // this envelope; skip rather than fail outright, in
                    // case the recipient's owner is key-rotated and some
                    // older envelopes are signed by a predecessor key.
                    continue;
                }
                owner_id_checked = true;
                // PATCH-07: Full signature scope includes timestamp and event index.
                let payload =
                    envelope_signing_payload(&kid, &pk.bytes, &env, at_unix_ms, event_idx);
                if dsa::verify(&payload, &signature, opk).is_err() {
                    anyhow::bail!(
                        "share unlock: envelope signature failed verification for recipient key {}",
                        hex_encode(&kid)
                    );
                }
            }
            if let Ok(root_key) = unwrap_key(&env, recipient_sk) {
                let _ = pk; // pk is metadata only
                return Ok(DecryptedShare {
                    recipient_key_id: kid,
                    root_key,
                });
            }
        }
        // If the caller provided an owner PK but no envelope's
        // `owner_sig_pk_id` matched it, the owner key is wrong for this
        // share file — give a specific error rather than the generic
        // "no envelope" message.
        if owner_pk.is_some() && !owner_id_checked {
            anyhow::bail!(
                "share unlock: the supplied owner public key does not match \
                 any envelope's signer (no envelope was signed by this owner)"
            );
        }
        anyhow::bail!("share unlock: no envelope matches this secret key");
    }

    /// The set of currently-active envelopes. Returns `(PublicKey, key_id,
    /// KeyEnvelope)` tuples in chronological insertion order.
    pub fn active_envelopes(&self) -> Vec<(PublicKey, [u8; 32], KeyEnvelope)> {
        self.active_envelopes_with_signatures()
            .into_iter()
            .map(|(pk, kid, env, _, _, _, _)| (pk, kid, env))
            .collect()
    }

    /// The set of currently-active envelopes, including the owner's signature
    /// metadata. Returns `(PublicKey, key_id, KeyEnvelope, owner_sig_pk_id,
    /// owner_signature)` tuples in chronological insertion order.
    pub fn active_envelopes_with_signatures(&self) -> Vec<SignedEnvelope> {
        let latest = latest_state_per_recipient(&self.events);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (event_idx, ev) in self.events.iter().enumerate() {
            let kid = match ev {
                ShareEvent::Added {
                    recipient_key_id, ..
                } => *recipient_key_id,
                ShareEvent::Revoked {
                    recipient_key_id, ..
                } => *recipient_key_id,
            };
            if seen.contains(&kid) {
                continue;
            }
            let candidate = latest.get(&kid);
            if let Some(ShareEvent::Added {
                recipient_pk_bytes,
                envelope,
                owner_sig_pk_id,
                owner_signature,
                at_unix_ms,
                ..
            }) = candidate
            {
                if recipient_pk_bytes.len() != ML_KEM_768_PK_LEN {
                    continue;
                }
                let mut bytes = vec![0u8; ML_KEM_768_PK_LEN];
                bytes.copy_from_slice(recipient_pk_bytes);
                out.push((
                    PublicKey { bytes },
                    kid,
                    KeyEnvelope::clone(envelope),
                    *owner_sig_pk_id,
                    owner_signature.clone(),
                    *at_unix_ms,
                    event_idx as u64,
                ));
                seen.insert(kid);
            }
        }
        out
    }

    /// Active recipients in insertion order.
    pub fn list_active(&self) -> Vec<ActiveRecipient> {
        self.active_envelopes()
            .into_iter()
            .map(|(pk, kid, _)| ActiveRecipient {
                recipient_key_id: kid,
                recipient_pk_hex: pk.bytes.iter().map(|b| format!("{b:02x}")).collect(),
            })
            .collect()
    }

    /// All currently-revoked recipients (one entry per kid, with the most
    /// recent revocation timestamp).
    pub fn list_revoked(&self) -> Vec<RevokedRecipient> {
        let latest = latest_state_per_recipient(&self.events);
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for ev in &self.events {
            let kid = match ev {
                ShareEvent::Added {
                    recipient_key_id, ..
                } => *recipient_key_id,
                ShareEvent::Revoked {
                    recipient_key_id, ..
                } => *recipient_key_id,
            };
            if seen.contains(&kid) {
                continue;
            }
            if let Some(ShareEvent::Revoked {
                at_unix_ms, reason, ..
            }) = latest.get(&kid)
            {
                out.push(RevokedRecipient {
                    recipient_key_id: kid,
                    revoked_at_unix_ms: *at_unix_ms,
                    reason: reason.clone(),
                });
                seen.insert(kid);
            }
        }
        out
    }
}

fn event_key_id(ev: &ShareEvent) -> Option<[u8; 32]> {
    match ev {
        ShareEvent::Added {
            recipient_key_id, ..
        } => Some(*recipient_key_id),
        ShareEvent::Revoked {
            recipient_key_id, ..
        } => Some(*recipient_key_id),
    }
}

/// Canonical signing payload for an envelope. The owner signs these bytes
/// with their ML-DSA-65 secret key; recipients verify the signature with the
/// owner's ML-DSA-65 public key.
///
/// Format: `domain || recipient_key_id || recipient_ml_kem_pk || wrap_nonce
/// || kem_ciphertext || wrapped_key || at_unix_ms || event_index`.
///
/// Every field of the envelope is bound to the signature, so any tampering
/// (key id swap, KEM ciphertext modification, wrapped key swap, nonce
/// modification) is detected.
pub fn envelope_signing_payload(
    recipient_key_id: &[u8; 32],
    recipient_pk_bytes: &[u8],
    envelope: &KeyEnvelope,
    at_unix_ms: u64,
    event_index: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        ENVELOPE_SIGN_DOMAIN.len()
            + 32
            + recipient_pk_bytes.len()
            + envelope.wrap_nonce.len()
            + envelope.kem_ciphertext.len()
            + envelope.wrapped_key.len()
            + 8
            + 8,
    );
    buf.extend_from_slice(ENVELOPE_SIGN_DOMAIN);
    buf.extend_from_slice(recipient_key_id);
    buf.extend_from_slice(recipient_pk_bytes);
    buf.extend_from_slice(&envelope.wrap_nonce);
    buf.extend_from_slice(&envelope.kem_ciphertext);
    buf.extend_from_slice(&envelope.wrapped_key);
    // PATCH-07: Bind timestamp and event index to the signature.
    buf.extend_from_slice(&at_unix_ms.to_le_bytes());
    buf.extend_from_slice(&event_index.to_le_bytes());
    buf
}

/// Reconstruct the owner's ML-DSA-65 public key bytes from their secret
/// seed. The `dsa` module doesn't currently expose this directly, so we
/// derive it here via the same code path as `dsa::generate_keypair`.
fn owner_public_key_bytes_from_secret(sk: &OwnerSecretKey) -> crate::Result<Vec<u8>> {
    use ml_dsa::signature::Keypair;
    if sk.bytes.len() != dsa::ML_DSA_65_SK_SEED_LEN {
        anyhow::bail!(
            "invalid ML-DSA-65 secret seed length: got {}, expected {}",
            sk.bytes.len(),
            dsa::ML_DSA_65_SK_SEED_LEN
        );
    }
    let mut seed_arr = [0u8; dsa::ML_DSA_65_SK_SEED_LEN];
    seed_arr.copy_from_slice(&sk.bytes);
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_arr.into());
    let vk = ml_sk.verifying_key();
    Ok(vk.encode().to_vec())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// For each recipient key id, find the latest event (most recent in the
/// events list). The latest event is the recipient's current state.
fn latest_state_per_recipient(
    events: &[ShareEvent],
) -> std::collections::HashMap<[u8; 32], &ShareEvent> {
    let mut latest: std::collections::HashMap<[u8; 32], &ShareEvent> =
        std::collections::HashMap::new();
    for ev in events.iter().rev() {
        let kid = event_key_id(ev).expect("every event has a recipient_key_id");
        latest.entry(kid).or_insert(ev);
    }
    latest
}

// ---------------------------------------------------------------------------
// Hex serde helpers (mirrors the format used by the existing modules).
// ---------------------------------------------------------------------------

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

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = super::hex_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod hex_pk {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::hex_decode(&s).map_err(serde::de::Error::custom)
    }
}
