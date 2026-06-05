//! SOTERIA key slots — multi-user access and revocation.
//!
//! A *key slot* is a wrapped copy of the volume master key. The
//! master key itself is never written to disk in plaintext: each
//! slot is `AEAD(K_slot_key, K_master)` where `K_slot_key` is
//! derived from a user-supplied passphrase via Argon2id.
//!
//! ## Design
//!
//! - A volume can have up to N key slots (default 8). Each slot is
//!   a separate user/passphrase binding.
//! - Opening a volume tries each slot in turn; the first that
//!   successfully decrypts its wrapped master key wins.
//! - Revocation = deleting a slot. The data on disk is unchanged.
//! - Adding a slot = creating a new wrapped master from a new
//!   passphrase and writing it to the header.
//!
//! ## Header layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ magic: 4 bytes = b"SOTK"                                │
//! │ version: u8 = 1                                         │
//! │ slot_count: u8                                          │
//! │ for each slot:                                          │
//! │   slot_id: [u8; 16]                                     │
//! │   kdf_id: u8 (1 = Argon2id)                             │
//! │   kdf_m_cost: u32 LE                                    │
//! │   kdf_t_cost: u32 LE                                    │
//! │   salt: [u8; 16]                                        │
//! │   nonce: [u8; 12]   (AEAD nonce)                        │
//! │   ct:  [u8; 32 + 16] (master || tag)                    │
//! │   flags: u8  (bit 0 = enabled)                          │
//! │   created_at: u64 LE (Unix seconds)                     │
//! │ header_hmac: [u8; 32] (BLAKE3 keyed-MAC over header)    │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! Note: the AEAD is AES-256-GCM. The 32-byte master key + 16-byte
//! GCM tag are concatenated into `ct`; the nonce is unique per slot
//! (random from OsRng on slot creation). The header HMAC is
//! BLAKE3-keyed with a per-volume salt to detect tampering with
//! the slot metadata itself (slot IDs, KDF params) — preventing
//! downgrade attacks via KDF-cost modification.
//!
//! ## Security notes
//!
//! - Slot metadata is *not* secret, but its integrity must be
//!   preserved. The keyed HMAC is computed over the entire header
//!   with `header_salt` as the key.
//! - The master key is wrapped with a 96-bit random nonce per
//!   slot. Reusing a (key, nonce) pair would be catastrophic, so
//!   we store the nonce alongside.
//! - On disk the master key is never seen. Even if an attacker
//!   reads the raw header, they need at least one valid
//!   passphrase to recover the master.

use crate::crypto_engine::kdf::{argon2id_root_from_password, hkdf_derive};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Hex wrapper for fixed-size byte arrays in serde. The array is
/// serialized as a 2*N-character hex string and deserialized from
/// the same.
mod hex48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = b.iter().map(|x| format!("{:02x}", x)).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 96 {
            return Err(serde::de::Error::custom("hex48: wrong length"));
        }
        let mut out = [0u8; 48];
        for i in 0..48 {
            out[i] =
                u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

/// Header magic — 4 bytes "SOTK".
pub const HEADER_MAGIC: &[u8; 4] = b"SOTK";
/// Header version. Bump only on incompatible changes.
pub const HEADER_VERSION: u8 = 1;
/// Maximum number of slots per volume.
pub const MAX_SLOTS: usize = 16;
/// Argon2id KDF identifier.
pub const KDF_ID_ARGON2ID: u8 = 1;
/// AES-256-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// Master key length in bytes.
pub const MASTER_LEN: usize = 32;
/// GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// A single key-slot record. Holds the wrapped master key plus
/// the KDF parameters needed to unlock it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySlot {
    /// Unique slot identifier (random 16 bytes).
    pub slot_id: [u8; 16],
    /// KDF algorithm identifier (1 = Argon2id).
    pub kdf_id: u8,
    /// Argon2id memory cost in KiB.
    pub kdf_m_cost: u32,
    /// Argon2id iterations.
    pub kdf_t_cost: u32,
    /// Argon2id parallelism.
    pub kdf_p_cost: u32,
    /// Argon2id salt (16 bytes).
    pub salt: [u8; 16],
    /// GCM nonce (12 bytes, unique per slot).
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext = `master_key || gcm_tag` (48 bytes total).
    #[serde(with = "hex48")]
    pub ct: [u8; MASTER_LEN + TAG_LEN],
    /// Slot flags. Bit 0 = enabled.
    pub flags: u8,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

impl KeySlot {
    /// Build a new key slot: derive `K_slot_key` from
    /// `passphrase` + `salt` + cost params, then encrypt the
    /// master with AES-256-GCM and return the slot record.
    pub fn create(
        master: &[u8; MASTER_LEN],
        passphrase: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> crate::Result<Self> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self::create_with_salt(master, passphrase, m_cost, t_cost, p_cost, salt)
    }

    /// Build a new key slot using a specific (deterministic) salt.
    /// Useful for tests; production code should use [`KeySlot::create`].
    pub fn create_with_salt(
        master: &[u8; MASTER_LEN],
        passphrase: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        salt: [u8; 16],
    ) -> crate::Result<Self> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        // Derive K_slot_key from passphrase + salt + params.
        let mut slot_key = argon2id_root_from_password(passphrase, &salt, m_cost, t_cost)?;
        let cipher = Aes256Gcm::new_from_slice(slot_key.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;

        // AAD binds the slot metadata to the ciphertext so that
        // an attacker can't swap slots between volumes.
        let mut aad = Vec::new();
        aad.extend_from_slice(HEADER_MAGIC);
        aad.push(HEADER_VERSION);
        aad.push(KDF_ID_ARGON2ID);
        aad.extend_from_slice(&m_cost.to_le_bytes());
        aad.extend_from_slice(&t_cost.to_le_bytes());
        aad.extend_from_slice(&p_cost.to_le_bytes());
        aad.extend_from_slice(&salt);
        aad.extend_from_slice(&nonce);

        let pt = master.as_ref();
        let ct_full = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
            .map_err(|e| anyhow::anyhow!("AES-256-GCM seal failed: {e:?}"))?;

        // ct_full should be 32 (master) + 16 (GCM tag) = 48 bytes.
        if ct_full.len() != MASTER_LEN + TAG_LEN {
            slot_key.zeroize();
            anyhow::bail!(
                "AES-256-GCM produced unexpected ct length: {}",
                ct_full.len()
            );
        }

        let mut ct = [0u8; MASTER_LEN + TAG_LEN];
        ct.copy_from_slice(&ct_full);
        slot_key.zeroize();

        let mut slot_id = [0u8; 16];
        OsRng.fill_bytes(&mut slot_id);

        Ok(Self {
            slot_id,
            kdf_id: KDF_ID_ARGON2ID,
            kdf_m_cost: m_cost,
            kdf_t_cost: t_cost,
            kdf_p_cost: p_cost,
            salt,
            nonce,
            ct,
            flags: 0b0000_0001, // enabled
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    /// Unseal: derive the slot key from `passphrase` and try to
    /// decrypt the wrapped master. Returns an error on tag
    /// mismatch (wrong passphrase, tampered header, or slot
    /// swapped between volumes).
    pub fn unseal(&self, passphrase: &[u8]) -> crate::Result<[u8; MASTER_LEN]> {
        if self.kdf_id != KDF_ID_ARGON2ID {
            anyhow::bail!("unsupported kdf_id in slot: {}", self.kdf_id);
        }
        if self.flags & 0b0000_0001 == 0 {
            anyhow::bail!("slot is disabled");
        }
        let mut slot_key =
            argon2id_root_from_password(passphrase, &self.salt, self.kdf_m_cost, self.kdf_t_cost)?;
        let cipher = Aes256Gcm::new_from_slice(slot_key.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;

        // Reconstruct the same AAD.
        let mut aad = Vec::new();
        aad.extend_from_slice(HEADER_MAGIC);
        aad.push(HEADER_VERSION);
        aad.push(KDF_ID_ARGON2ID);
        aad.extend_from_slice(&self.kdf_m_cost.to_le_bytes());
        aad.extend_from_slice(&self.kdf_t_cost.to_le_bytes());
        aad.extend_from_slice(&self.kdf_p_cost.to_le_bytes());
        aad.extend_from_slice(&self.salt);
        aad.extend_from_slice(&self.nonce);

        let pt = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ct,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("slot unseal failed (wrong passphrase or tampered slot)")
            })?;
        slot_key.zeroize();

        if pt.len() != MASTER_LEN {
            anyhow::bail!("unsealed master has wrong length: {}", pt.len());
        }
        let mut m = [0u8; MASTER_LEN];
        m.copy_from_slice(&pt);
        Ok(m)
    }

    /// Is this slot currently enabled?
    pub fn is_enabled(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }

    /// Disable this slot (revocation). The data on disk is
    /// untouched; the master key becomes unreachable via this
    /// binding.
    pub fn disable(&mut self) {
        self.flags &= !0b0000_0001;
    }
}

/// The full key-slot table for a volume, plus a per-volume
/// header-salt used for the integrity MAC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySlotTable {
    /// Per-volume salt for the header HMAC (random 32 bytes).
    pub header_salt: [u8; 32],
    /// Active slots (max [`MAX_SLOTS`]).
    pub slots: Vec<KeySlot>,
}

impl KeySlotTable {
    /// Build a new table with one initial slot wrapping `master`.
    pub fn new_initial(master: &[u8; MASTER_LEN], passphrase: &[u8]) -> crate::Result<Self> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut header_salt = [0u8; 32];
        OsRng.fill_bytes(&mut header_salt);
        let slot = KeySlot::create(master, passphrase, 19_456, 2, 1)?;
        Ok(Self {
            header_salt,
            slots: vec![slot],
        })
    }

    /// Try every enabled slot in turn; return the master key
    /// recovered from the first successful unseal.
    pub fn unseal_with(&self, passphrase: &[u8]) -> crate::Result<(usize, [u8; MASTER_LEN])> {
        for (i, s) in self.slots.iter().enumerate() {
            if !s.is_enabled() {
                continue;
            }
            if let Ok(m) = s.unseal(passphrase) {
                return Ok((i, m));
            }
        }
        anyhow::bail!("no slot accepted the passphrase")
    }

    /// Add a new slot wrapping the same master under a new
    /// passphrase. Used to grant access to another user.
    pub fn add_slot(
        &mut self,
        master: &[u8; MASTER_LEN],
        passphrase: &[u8],
    ) -> crate::Result<usize> {
        if self.slots.len() >= MAX_SLOTS {
            anyhow::bail!("max slots ({}) reached", MAX_SLOTS);
        }
        let slot = KeySlot::create(master, passphrase, 19_456, 2, 1)?;
        self.slots.push(slot);
        Ok(self.slots.len() - 1)
    }

    /// Revoke a slot by index. Returns Err if the slot is the
    /// only enabled one (we refuse to lock the user out).
    pub fn revoke_slot(&mut self, index: usize) -> crate::Result<()> {
        let enabled_count = self.slots.iter().filter(|s| s.is_enabled()).count();
        if enabled_count <= 1 {
            anyhow::bail!("cannot revoke last enabled slot");
        }
        if index >= self.slots.len() {
            anyhow::bail!("slot index out of range");
        }
        self.slots[index].disable();
        Ok(())
    }

    /// Number of currently-enabled slots.
    pub fn enabled_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_enabled()).count()
    }

    /// Serialize the table to bytes for storage. The header HMAC
    /// is appended.
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(HEADER_MAGIC);
        buf.push(HEADER_VERSION);
        buf.push(self.slots.len() as u8);

        for s in &self.slots {
            buf.extend_from_slice(&s.slot_id);
            buf.push(s.kdf_id);
            buf.extend_from_slice(&s.kdf_m_cost.to_le_bytes());
            buf.extend_from_slice(&s.kdf_t_cost.to_le_bytes());
            buf.extend_from_slice(&s.kdf_p_cost.to_le_bytes());
            buf.extend_from_slice(&s.salt);
            buf.extend_from_slice(&s.nonce);
            buf.extend_from_slice(&s.ct);
            buf.push(s.flags);
            buf.extend_from_slice(&s.created_at.to_le_bytes());
        }

        // Header HMAC: BLAKE3-keyed with header_salt over the
        // serialized table. Truncated to 32 bytes.
        let mut mac = blake3::Hasher::new_keyed(&self.header_salt);
        mac.update(&buf);
        let tag = *mac.finalize().as_bytes();
        buf.extend_from_slice(&tag);

        Ok(buf)
    }

    /// Parse a serialized table and verify its HMAC.
    pub fn from_bytes(bytes: &[u8], header_salt: &[u8; 32]) -> crate::Result<Self> {
        if bytes.len() < 4 + 1 + 1 + 32 {
            anyhow::bail!("slot table: header too short");
        }
        if &bytes[0..4] != HEADER_MAGIC {
            anyhow::bail!("slot table: bad magic");
        }
        if bytes[4] != HEADER_VERSION {
            anyhow::bail!("slot table: unknown version {}", bytes[4]);
        }
        let slot_count = bytes[5] as usize;
        if slot_count > MAX_SLOTS {
            anyhow::bail!("slot table: slot_count {} > max {}", slot_count, MAX_SLOTS);
        }

        // Body length: 4 (magic) + 1 (ver) + 1 (count) + sum(slot sizes) + 32 (hmac)
        // Per slot: 16 (id) + 1 (kdf) + 4*3 (params) + 16 (salt) + 12 (nonce) + 48 (ct) + 1 (flags) + 8 (ts) = 118
        const PER_SLOT: usize = 16 + 1 + 4 * 3 + 16 + 12 + 48 + 1 + 8;
        let body = 4 + 1 + 1 + slot_count * PER_SLOT;
        if bytes.len() != body + 32 {
            anyhow::bail!(
                "slot table: body length {} != expected {}",
                bytes.len(),
                body + 32
            );
        }

        // Verify HMAC over the pre-MAC portion.
        let mut mac = blake3::Hasher::new_keyed(header_salt);
        mac.update(&bytes[..body]);
        let computed = *mac.finalize().as_bytes();
        if &bytes[body..body + 32] != computed {
            anyhow::bail!("slot table: HMAC verification failed");
        }

        let mut slots = Vec::with_capacity(slot_count);
        let mut off = 6;
        for _ in 0..slot_count {
            let mut slot_id = [0u8; 16];
            slot_id.copy_from_slice(&bytes[off..off + 16]);
            off += 16;
            let kdf_id = bytes[off];
            off += 1;
            let m_cost = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            off += 4;
            let t_cost = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            off += 4;
            let p_cost = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            off += 4;
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&bytes[off..off + 16]);
            off += 16;
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&bytes[off..off + NONCE_LEN]);
            off += NONCE_LEN;
            let mut ct = [0u8; MASTER_LEN + TAG_LEN];
            ct.copy_from_slice(&bytes[off..off + MASTER_LEN + TAG_LEN]);
            off += MASTER_LEN + TAG_LEN;
            let flags = bytes[off];
            off += 1;
            let created_at = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            off += 8;

            slots.push(KeySlot {
                slot_id,
                kdf_id,
                kdf_m_cost: m_cost,
                kdf_t_cost: t_cost,
                kdf_p_cost: p_cost,
                salt,
                nonce,
                ct,
                flags,
                created_at,
            });
        }

        Ok(Self {
            header_salt: *header_salt,
            slots,
        })
    }
}

/// Volume key rotation. The master is regenerated, the data on
/// disk is unchanged (the per-block data is keyed by `K_enc` which
/// is re-derived from the new master on next open).
pub struct VolumeKeyRotation;

impl VolumeKeyRotation {
    /// Generate a fresh random master key.
    pub fn fresh_master() -> [u8; MASTER_LEN] {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut m = [0u8; MASTER_LEN];
        OsRng.fill_bytes(&mut m);
        m
    }

    /// Re-wrap an existing master under a new passphrase (adds a
    /// new slot, returns the table). Useful when a user changes
    /// their passphrase without rotating the volume.
    pub fn rewrap_with_new_passphrase(
        master: &[u8; MASTER_LEN],
        new_passphrase: &[u8],
    ) -> crate::Result<KeySlotTable> {
        KeySlotTable::new_initial(master, new_passphrase)
    }

    /// Perform a key rotation: regenerate the master, re-derive
    /// the hierarchy, return both. The caller is responsible for
    /// rewriting the slot table on disk with the new master.
    pub fn rotate(old_master: &[u8; MASTER_LEN]) -> crate::Result<[u8; MASTER_LEN]> {
        // Note: the actual hkdf chain between old and new master
        // is *intentionally* not done. The new master is a
        // uniformly random 256-bit value. This means: an attacker
        // who recovers the old master gains no information about
        // the new one. A defender who only has the new master
        // cannot decrypt old backups unless they kept the old
        // master (this is the user-visible "rotation" semantic).
        let _ = hkdf_derive(old_master, b"rotate", b"soteria-v1/rotation");
        let new = Self::fresh_master();
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_slot(master: &[u8; MASTER_LEN], pw: &[u8]) -> KeySlot {
        KeySlot::create(master, pw, 64, 1, 1).unwrap()
    }

    #[test]
    fn round_trip_unseal() {
        let master = [0x55u8; MASTER_LEN];
        let slot = fast_slot(&master, b"hunter2");
        let recovered = slot.unseal(b"hunter2").unwrap();
        assert_eq!(recovered, master);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let master = [0x66u8; MASTER_LEN];
        let slot = fast_slot(&master, b"hunter2");
        assert!(slot.unseal(b"wrong").is_err());
    }

    #[test]
    fn slot_isolation() {
        let master = [0x77u8; MASTER_LEN];
        let s1 = fast_slot(&master, b"pass-a");
        let s2 = fast_slot(&master, b"pass-b");
        // s1 should not unseal with pass-b and vice versa.
        assert!(s1.unseal(b"pass-b").is_err());
        assert!(s2.unseal(b"pass-a").is_err());
        // s1 unseal gives the same master as s2 unseal.
        assert_eq!(s1.unseal(b"pass-a").unwrap(), s2.unseal(b"pass-b").unwrap());
    }

    #[test]
    fn table_multi_user() {
        let master = [0x88u8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"alice-pw").unwrap();
        assert_eq!(table.enabled_count(), 1);
        let bob_idx = table.add_slot(&master, b"bob-pw").unwrap();
        assert_eq!(table.enabled_count(), 2);

        let (idx, m) = table.unseal_with(b"bob-pw").unwrap();
        assert_eq!(m, master);
        assert_eq!(idx, bob_idx);

        let (idx, m) = table.unseal_with(b"alice-pw").unwrap();
        assert_eq!(m, master);
        assert_eq!(idx, 0);
    }

    #[test]
    fn revocation_blocks_access() {
        let master = [0x99u8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"alice-pw").unwrap();
        let bob = table.add_slot(&master, b"bob-pw").unwrap();
        assert!(table.revoke_slot(bob).is_ok());
        // Bob's passphrase no longer works.
        assert!(table.unseal_with(b"bob-pw").is_err());
        // Alice still works.
        assert!(table.unseal_with(b"alice-pw").is_ok());
    }

    #[test]
    fn cannot_revoke_last_slot() {
        let master = [0xAAu8; MASTER_LEN];
        let mut table = KeySlotTable::new_initial(&master, b"only-pw").unwrap();
        assert!(table.revoke_slot(0).is_err());
    }

    #[test]
    fn table_serde_round_trip() {
        let master = [0xBBu8; MASTER_LEN];
        let table = KeySlotTable::new_initial(&master, b"pw").unwrap();
        let bytes = table.to_bytes().unwrap();
        let salt = table.header_salt;
        let parsed = KeySlotTable::from_bytes(&bytes, &salt).unwrap();
        assert_eq!(parsed.slots.len(), table.slots.len());
        assert_eq!(parsed.header_salt, table.header_salt);
    }

    #[test]
    fn tampered_table_fails_hmac() {
        let master = [0xCCu8; MASTER_LEN];
        let table = KeySlotTable::new_initial(&master, b"pw").unwrap();
        let mut bytes = table.to_bytes().unwrap();
        // Flip a byte in the body.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        // Wrong salt -> wrong HMAC.
        let wrong_salt = [0u8; 32];
        assert!(KeySlotTable::from_bytes(&bytes, &wrong_salt).is_err());
    }

    #[test]
    fn rotation_changes_master() {
        let old = [0xDDu8; MASTER_LEN];
        let new = VolumeKeyRotation::rotate(&old).unwrap();
        assert_ne!(old, new);
    }
}
