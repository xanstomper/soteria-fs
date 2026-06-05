//! SOTERIA metadata encryption — AEAD for filesystem metadata.
//!
//! All filesystem metadata (file names, paths, indices, journal
//! entries, inodes) is encrypted at rest with AES-256-GCM under
//! the [`KeyHierarchy::k_meta`] domain key. This is the
//! confidentiality layer for the directory tree.
//!
//! ## Why a separate domain key?
//!
//! - **Blast-radius isolation**: a `K_meta` leak does not expose
//!   file *contents*; a `K_enc` leak does not expose file *names*.
//! - **Performance**: most metadata reads are tiny (a single name
//!   or inode). Using a separate key allows future work to
//!   experiment with lighter-weight schemes for metadata
//!   (e.g., AES-GCM-SIV) without affecting bulk data encryption.
//! - **Auditability**: the chain `K_master -> K_meta` is
//!   explicit. A new key hierarchy version can rotate
//!   `K_meta` without touching `K_enc`.
//!
//! ## AEAD AAD
//!
//! Every metadata ciphertext is sealed with a 12-byte random
//! nonce and an AAD that includes:
//! - the metadata kind tag (so a name can't be replayed as a
//!   journal entry),
//! - a per-volume context string (so metadata from one volume
//!   can't be replayed in another).
//!
//! ## Stream vs. single-shot
//!
//! For simplicity, all metadata items are encrypted as a single
//! AEAD shot. The on-disk overhead is 12 (nonce) + 16 (tag) = 28
//! bytes per metadata record. Streaming encryption is a future
//! optimization.

use crate::key_hierarchy::KeyHierarchy;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

/// AEAD version byte for metadata. Bump on incompatible changes.
pub const META_AEAD_VERSION: u8 = 1;
/// 12-byte AES-GCM nonce.
pub const META_NONCE_LEN: usize = 12;
/// 16-byte GCM tag.
pub const META_TAG_LEN: usize = 16;

/// Kinds of metadata. Used to bind ciphertexts to their semantic
/// type via the AAD. A name-ciphertext cannot be replayed as a
/// journal entry because the kinds differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MetaKind {
    FileName = 0x01,
    DirectoryEntry = 0x02,
    Inode = 0x03,
    JournalEntry = 0x04,
    SymlinkTarget = 0x05,
    ExtendedAttribute = 0x06,
    XattrValue = 0x07,
}

impl MetaKind {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// A sealed metadata record. The plaintext can be any bytes
/// (UTF-8 file name, binary journal entry, etc.) and is bound
/// to the metadata kind and a per-volume context string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedMeta {
    pub kind: MetaKind,
    pub nonce: [u8; META_NONCE_LEN],
    /// 12-byte nonce + ciphertext + 16-byte GCM tag.
    pub ct: Vec<u8>,
}

/// Per-volume context for metadata AEAD. Set at volume
/// creation; never rotated. This binds metadata to a specific
/// volume so that ciphertexts cannot be replayed between volumes
/// even if the same `K_meta` is reused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeContext {
    pub volume_id: [u8; 16],
    pub label: String,
}

impl VolumeContext {
    /// Serialize to a stable byte string for use in AAD.
    pub fn context_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 4 + self.label.len());
        v.extend_from_slice(&self.volume_id);
        v.extend_from_slice(&(self.label.len() as u32).to_le_bytes());
        v.extend_from_slice(self.label.as_bytes());
        v
    }
}

fn build_aad(version: u8, kind: MetaKind, ctx: &VolumeContext) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.push(version);
    aad.push(kind.as_byte());
    aad.extend_from_slice(&ctx.context_bytes());
    aad
}

/// Seal a metadata record.
pub fn seal_meta(
    kind: MetaKind,
    plaintext: &[u8],
    ctx: &VolumeContext,
    k_meta: &[u8; 32],
) -> crate::Result<SealedMeta> {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut nonce = [0u8; META_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new_from_slice(k_meta.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;

    let aad = build_aad(META_AEAD_VERSION, kind, ctx);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-256-GCM seal failed: {e:?}"))?;

    Ok(SealedMeta { kind, nonce, ct })
}

/// Open a sealed metadata record. Verifies kind matches the
/// expected kind.
pub fn open_meta(
    sealed: &SealedMeta,
    expected_kind: MetaKind,
    ctx: &VolumeContext,
    k_meta: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if sealed.kind != expected_kind {
        anyhow::bail!(
            "metadata kind mismatch: expected {:?}, got {:?}",
            expected_kind,
            sealed.kind
        );
    }
    let cipher = Aes256Gcm::new_from_slice(k_meta.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e:?}"))?;
    let aad = build_aad(META_AEAD_VERSION, sealed.kind, ctx);
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("metadata AEAD open failed (wrong key or tampered)"))?;
    Ok(pt)
}

/// Convenience wrappers using a `KeyHierarchy`.
pub fn seal_meta_with_h(
    kind: MetaKind,
    plaintext: &[u8],
    ctx: &VolumeContext,
    kh: &KeyHierarchy,
) -> crate::Result<SealedMeta> {
    seal_meta(kind, plaintext, ctx, &kh.k_meta)
}

pub fn open_meta_with_h(
    sealed: &SealedMeta,
    expected_kind: MetaKind,
    ctx: &VolumeContext,
    kh: &KeyHierarchy,
) -> crate::Result<Vec<u8>> {
    open_meta(sealed, expected_kind, ctx, &kh.k_meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> VolumeContext {
        VolumeContext {
            volume_id: [7u8; 16],
            label: "test-volume".to_string(),
        }
    }

    fn test_kh() -> KeyHierarchy {
        KeyHierarchy::from_master(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn round_trip_filename() {
        let kh = test_kh();
        let ctx = test_ctx();
        let name = "secret-document.txt";
        let sealed = seal_meta_with_h(MetaKind::FileName, name.as_bytes(), &ctx, &kh).unwrap();
        let pt = open_meta_with_h(&sealed, MetaKind::FileName, &ctx, &kh).unwrap();
        assert_eq!(pt, name.as_bytes());
    }

    #[test]
    fn kind_mismatch_rejected() {
        let kh = test_kh();
        let ctx = test_ctx();
        let sealed = seal_meta_with_h(MetaKind::FileName, b"foo", &ctx, &kh).unwrap();
        // Try to open as a different kind.
        assert!(open_meta_with_h(&sealed, MetaKind::JournalEntry, &ctx, &kh).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kh = test_kh();
        let ctx = test_ctx();
        let sealed = seal_meta_with_h(MetaKind::Inode, &[0u8; 64], &ctx, &kh).unwrap();
        let wrong = KeyHierarchy::from_master(&[0x99u8; 32]).unwrap();
        assert!(open_meta_with_h(&sealed, MetaKind::Inode, &ctx, &wrong).is_err());
    }

    #[test]
    fn wrong_volume_context_fails() {
        let kh = test_kh();
        let ctx1 = test_ctx();
        let ctx2 = VolumeContext {
            volume_id: [8u8; 16],
            label: "other-volume".to_string(),
        };
        let sealed = seal_meta_with_h(MetaKind::SymlinkTarget, b"/target", &ctx1, &kh).unwrap();
        assert!(open_meta_with_h(&sealed, MetaKind::SymlinkTarget, &ctx2, &kh).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kh = test_kh();
        let ctx = test_ctx();
        let mut sealed =
            seal_meta_with_h(MetaKind::XattrValue, b"user.foo=bar", &ctx, &kh).unwrap();
        sealed.ct[0] ^= 0x01;
        assert!(open_meta_with_h(&sealed, MetaKind::XattrValue, &ctx, &kh).is_err());
    }

    #[test]
    fn different_kinds_use_different_aad() {
        let kh = test_kh();
        let ctx = test_ctx();
        let s_name = seal_meta_with_h(MetaKind::FileName, b"x", &ctx, &kh).unwrap();
        let s_ino = seal_meta_with_h(MetaKind::Inode, b"x", &ctx, &kh).unwrap();
        // Same plaintext, same key, same volume, but different
        // kind -> different ct. (Probability of equal random
        // 28-byte suffix is 2^{-224}; treat as zero.)
        assert_ne!(s_name.ct, s_ino.ct);
    }
}
