//! SOTERIA key hierarchy — domain-separated key derivation.
//!
//! Every Soteria key slot derives its full key hierarchy from a single
//! 256-bit master key via HKDF-SHA256 with a *distinct* `info` string
//! for each domain. This gives us:
//!
//! - **Blast-radius isolation**: compromising `K_meta` does not let
//!   the attacker decrypt data blocks. The domains are
//!   cryptographically independent under the HKDF assumption.
//! - **No cross-protocol key reuse**: e.g., the AEAD authentication
//!   tag key is not the same byte string as the XTS data key.
//! - **Auditable composition**: every key has a single documented
//!   source (`K_master`) and a single documented purpose (`info`).
//!
//! ## Hierarchy
//!
//! ```text
//!                          ┌──────────────────────┐
//!                          │  K_master (256 bits) │  (root, never logged, never written to disk in plaintext)
//!                          └──────────┬───────────┘
//!                                     │ HKDF-SHA256
//!              ┌───────────┬──────────┼──────────┬────────────┬──────────────┐
//!              ▼           ▼          ▼          ▼            ▼              ▼
//!         K_enc (data)  K_auth   K_meta    K_shard       K_xts        K_handle
//!         (AEAD bulk)   (MACs)  (metadata) (shard AEAD)  (FDE sector)  (file handles)
//! ```
//!
//! `K_hand` is reserved for filesystem handle derivation (e.g., inode-
//! to-key mapping in a FUSE-style mount).
//!
//! ## Key rotation
//!
//! A new master key is generated, and a key-slot record is re-wrapped:
//! the *data* on disk is not re-encrypted. Each block is keyed by
//! `K_enc`, which is derived per session from `K_master`. When
//! `K_master` is rotated, all five domain keys are re-derived on
//! next open. The plaintext data is untouched.
//!
//! ## Backwards compatibility
//!
//! The `legacy_single_key` constructor builds a hierarchy where
//! `K_enc == K_master` (no HKDF separation). It is provided so that
//! volumes created before the hierarchy refactor can still be
//! opened. New volumes should use [`KeyHierarchy::from_master`].

use crate::crypto_engine::kdf::hkdf_derive;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Domain-separation info strings for HKDF. These are *content*, not
/// configuration: changing them silently breaks every existing
/// volume. The values are versioned (v1, v2, ...) so a future
/// migration to a new KDF can co-exist with old volumes.
pub mod info {
    /// Domain-separation tag for the bulk data-encryption key (AEAD).
    pub const K_ENC: &[u8] = b"soteria-kh-v1/k-enc/aead-bulk";
    /// Domain-separation tag for the authentication key (per-block MAC).
    pub const K_AUTH: &[u8] = b"soteria-kh-v1/k-auth/block-mac";
    /// Domain-separation tag for the metadata encryption key
    /// (file names, paths, indices, journal).
    pub const K_META: &[u8] = b"soteria-kh-v1/k-meta/metadata";
    /// Domain-separation tag for the shard encryption key (used
    /// by the erasure-coding layer before placing shards on
    /// distinct storage nodes).
    pub const K_SHARD: &[u8] = b"soteria-kh-v1/k-shard/erasure-coding";
    /// Domain-separation tag for the FDE XTS sector key (whole-
    /// disk encryption). Split into data + tweak halves.
    pub const K_XTS: &[u8] = b"soteria-kh-v1/k-xts/fde-sector";
    /// Domain-separation tag for the file-handle / inode key.
    pub const K_HANDLE: &[u8] = b"soteria-kh-v1/k-handle/identity";
}

/// The full key hierarchy. All five domain keys are derived from
/// the same master via HKDF-SHA256 with distinct `info` tags.
#[derive(Clone)]
pub struct KeyHierarchy {
    /// 32-byte AEAD bulk-encryption key.
    pub k_enc: [u8; 32],
    /// 32-byte block-MAC key.
    pub k_auth: [u8; 32],
    /// 32-byte metadata-encryption key.
    pub k_meta: [u8; 32],
    /// 32-byte shard-encryption key (erasure coding layer).
    pub k_shard: [u8; 32],
    /// 32-byte FDE XTS data-key (combine with a separate tweak key
    /// derived from this same key for AES-256-XTS).
    pub k_xts: [u8; 32],
    /// 32-byte file-handle / inode key.
    pub k_handle: [u8; 32],
}

impl Drop for KeyHierarchy {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.k_enc.zeroize();
        self.k_auth.zeroize();
        self.k_meta.zeroize();
        self.k_shard.zeroize();
        self.k_xts.zeroize();
        self.k_handle.zeroize();
    }
}

impl KeyHierarchy {
    /// Build a hierarchy from a 32-byte master key. The master is
    /// HKDF-expanded five times with distinct `info` tags.
    pub fn from_master(master: &[u8; 32]) -> crate::Result<Self> {
        let salt = b"soteria-kh-v1/master-salt";
        Ok(Self {
            k_enc: hkdf_derive(master, salt, info::K_ENC)?,
            k_auth: hkdf_derive(master, salt, info::K_AUTH)?,
            k_meta: hkdf_derive(master, salt, info::K_META)?,
            k_shard: hkdf_derive(master, salt, info::K_SHARD)?,
            k_xts: hkdf_derive(master, salt, info::K_XTS)?,
            k_handle: hkdf_derive(master, salt, info::K_HANDLE)?,
        })
    }

    /// Build a hierarchy from a passphrase + salt + cost params
    /// (Argon2id -> 32-byte master -> HKDF -> 5 domain keys).
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8],
        memory_kib: u32,
        iterations: u32,
    ) -> crate::Result<Self> {
        let master = crate::crypto_engine::kdf::argon2id_root_from_password(
            passphrase, salt, memory_kib, iterations,
        )?;
        let mut m = Zeroizing::new([0u8; 32]);
        m.copy_from_slice(master.as_ref());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(m.as_ref());
        let h = Self::from_master(&arr)?;
        Ok(h)
    }

    /// Legacy mode: a hierarchy where every domain key equals the
    /// master. Used to open volumes created before the hierarchy
    /// refactor.
    pub fn legacy_single_key(master: &[u8; 32]) -> Self {
        Self {
            k_enc: *master,
            k_auth: *master,
            k_meta: *master,
            k_shard: *master,
            k_xts: *master,
            k_handle: *master,
        }
    }

    /// Compute a 32-byte sub-key from a domain key. Used to derive
    /// per-file / per-block keys without re-deriving the master.
    pub fn subkey(domain: &[u8; 32], context: &[u8]) -> crate::Result<[u8; 32]> {
        hkdf_derive(domain, b"soteria-kh-v1/subkey-salt", context)
    }
}

/// Identifies which domain key to use for a sub-key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Domain {
    Enc,
    Auth,
    Meta,
    Shard,
    Xts,
    Handle,
}

impl Domain {
    pub fn info_tag(self) -> &'static [u8] {
        match self {
            Self::Enc => info::K_ENC,
            Self::Auth => info::K_AUTH,
            Self::Meta => info::K_META,
            Self::Shard => info::K_SHARD,
            Self::Xts => info::K_XTS,
            Self::Handle => info::K_HANDLE,
        }
    }
}

pub mod slots;

pub use slots::{
    KeySlot, KeySlotTable, VolumeKeyRotation, HEADER_MAGIC, HEADER_VERSION, KDF_ID_ARGON2ID,
    MASTER_LEN, MAX_SLOTS, NONCE_LEN, TAG_LEN,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_separates_domains() {
        let master = [0x42u8; 32];
        let h = KeyHierarchy::from_master(&master).unwrap();
        // All five must differ.
        assert_ne!(h.k_enc, h.k_auth);
        assert_ne!(h.k_enc, h.k_meta);
        assert_ne!(h.k_enc, h.k_shard);
        assert_ne!(h.k_enc, h.k_xts);
        assert_ne!(h.k_enc, h.k_handle);
    }

    #[test]
    fn hierarchy_deterministic() {
        let master = [7u8; 32];
        let h1 = KeyHierarchy::from_master(&master).unwrap();
        let h2 = KeyHierarchy::from_master(&master).unwrap();
        assert_eq!(h1.k_enc, h2.k_enc);
        assert_eq!(h1.k_meta, h2.k_meta);
    }

    #[test]
    fn legacy_mode_uses_master_directly() {
        let master = [9u8; 32];
        let h = KeyHierarchy::legacy_single_key(&master);
        assert_eq!(h.k_enc, master);
        assert_eq!(h.k_auth, master);
    }

    #[test]
    fn subkey_derivation() {
        let h = KeyHierarchy::from_master(&[1u8; 32]).unwrap();
        let k1 = KeyHierarchy::subkey(&h.k_enc, b"file:foo").unwrap();
        let k2 = KeyHierarchy::subkey(&h.k_enc, b"file:foo").unwrap();
        assert_eq!(k1, k2);
        let k3 = KeyHierarchy::subkey(&h.k_enc, b"file:bar").unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn domain_info_tags_unique() {
        let tags = [
            Domain::Enc.info_tag(),
            Domain::Auth.info_tag(),
            Domain::Meta.info_tag(),
            Domain::Shard.info_tag(),
            Domain::Xts.info_tag(),
            Domain::Handle.info_tag(),
        ];
        let unique: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len());
    }
}
