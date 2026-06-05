//! AES-256-GCM sector encryption for FIPS-mode FDE.
//!
//! In FIPS mode, the sector cipher is AES-256-GCM (FIPS SP 800-38D)
//! instead of AES-256-XTS (FIPS SP 800-38E, but no FIPS-validated
//! Rust binding available). GCM has slightly different properties:
//!
//! - **Per-sector authentication**: a 16-byte GCM tag is stored
//!   with each sector, allowing detection of any sector-level
//!   tampering. The XTS construction does not authenticate.
//! - **Nonce = LBA**: each sector uses a 12-byte nonce derived
//!   from its LBA. Since LBAs are unique, the (key, nonce) pair
//!   is never reused. GCM is catastrophically broken if a
//!   nonce is reused; we use a 96-bit LBA (8 bytes of LBA + 4
//!   bytes zero) to ensure uniqueness.
//! - **6.25% overhead**: 32 bytes per 512-byte sector is lost
//!   to the GCM nonce (12 bytes stored) + tag (16 bytes). The
//!   plaintext area is 480 bytes per 512-byte sector.
//!
//! ## On-disk sector layout (FIPS mode)
//!
//! ```text
//! Offset  Size  Field
//! 0       12    nonce (8 bytes LBA in LE + 4 bytes reserved)
//! 12      480   ciphertext
//! 492     16    GCM tag
//! 508     4     reserved
//! = 512 bytes total
//! ```
//!
//! In non-FIPS mode, the on-disk layout is the original XTS layout
//! (512 bytes plaintext-ciphertext, no nonce or tag stored on disk).

#[cfg(feature = "fips")]
use crate::crypto_engine::fips::primitives;

pub const GCM_SECTOR_SIZE: usize = 512;
pub const GCM_NONCE_SIZE: usize = 12;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_PLAINTEXT_SIZE: usize = GCM_SECTOR_SIZE - GCM_NONCE_SIZE - GCM_TAG_SIZE;

/// Build the per-sector nonce: 8 bytes of LBA in little-endian,
/// 4 bytes of zero. Two sectors with the same LBA but different
/// volume keys would still have unique nonces because the LBA
/// is unique per device.
pub fn sector_nonce(lba: u64) -> [u8; GCM_NONCE_SIZE] {
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    nonce[0..8].copy_from_slice(&lba.to_le_bytes());
    nonce
}

/// A mounted FDE volume in FIPS mode. Holds the AES-256-GCM key.
pub struct GcmSectorCipher {
    key: [u8; 32],
}

impl GcmSectorCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Encrypt a sector. `lba` is the sector number. `buf` is
    /// `GCM_PLAINTEXT_SIZE` bytes of plaintext. The function writes
    /// the encrypted sector (nonce || ciphertext || tag) into `out`,
    /// which must be `GCM_SECTOR_SIZE` bytes.
    #[cfg(feature = "fips")]
    pub fn encrypt_sector(&self, lba: u64, buf: &[u8], out: &mut [u8; GCM_SECTOR_SIZE]) {
        assert_eq!(buf.len(), GCM_PLAINTEXT_SIZE);
        let nonce = sector_nonce(lba);
        // AAD = the nonce itself (authenticate the sector index)
        out[..GCM_NONCE_SIZE].copy_from_slice(&nonce);
        let mut ct = [0u8; GCM_PLAINTEXT_SIZE];
        ct.copy_from_slice(buf);
        let tag = primitives::aes256_gcm_seal(&self.key, &nonce, &nonce, &mut ct)
            .expect("GCM seal with valid key and nonce should not fail");
        out[GCM_NONCE_SIZE..GCM_NONCE_SIZE + GCM_PLAINTEXT_SIZE]
            .copy_from_slice(&ct[..GCM_PLAINTEXT_SIZE]);
        out[GCM_NONCE_SIZE + GCM_PLAINTEXT_SIZE..GCM_SECTOR_SIZE].copy_from_slice(&tag);
    }

    /// Decrypt a sector. Inverse of `encrypt_sector`.
    #[cfg(feature = "fips")]
    pub fn decrypt_sector(
        &self,
        lba: u64,
        sector: &[u8; GCM_SECTOR_SIZE],
        out: &mut [u8],
    ) -> Result<(), &'static str> {
        assert_eq!(out.len(), GCM_PLAINTEXT_SIZE);
        let nonce = sector_nonce(lba);
        // Verify the stored nonce matches what we expect for this LBA.
        if &sector[..GCM_NONCE_SIZE] != &nonce[..] {
            return Err("nonce mismatch (sector moved or wrong key)");
        }
        let mut ct = [0u8; GCM_PLAINTEXT_SIZE + GCM_TAG_SIZE];
        ct.copy_from_slice(
            &sector[GCM_NONCE_SIZE..GCM_NONCE_SIZE + GCM_PLAINTEXT_SIZE + GCM_TAG_SIZE],
        );
        let pt_len = primitives::aes256_gcm_open(&self.key, &nonce, &nonce, &mut ct)
            .map_err(|_| "GCM tag verification failed (tamper detected)")?;
        out.copy_from_slice(&ct[..pt_len]);
        Ok(())
    }
}

#[cfg(all(test, feature = "fips"))]
mod tests {
    use super::*;

    #[test]
    fn gcm_sector_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = GcmSectorCipher::new(&key);
        let plaintext = vec![0xABu8; GCM_PLAINTEXT_SIZE];
        let mut sector = [0u8; GCM_SECTOR_SIZE];
        cipher.encrypt_sector(7, &plaintext, &mut sector);

        let mut recovered = vec![0u8; GCM_PLAINTEXT_SIZE];
        cipher.decrypt_sector(7, &sector, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn gcm_sector_tamper_detected() {
        let key = [0x42u8; 32];
        let cipher = GcmSectorCipher::new(&key);
        let plaintext = vec![0xCDu8; GCM_PLAINTEXT_SIZE];
        let mut sector = [0u8; GCM_SECTOR_SIZE];
        cipher.encrypt_sector(7, &plaintext, &mut sector);
        // Flip a bit in the ciphertext.
        sector[20] ^= 0x01;
        let mut recovered = vec![0u8; GCM_PLAINTEXT_SIZE];
        let r = cipher.decrypt_sector(7, &sector, &mut recovered);
        assert!(r.is_err(), "GCM should reject tampered ciphertext");
    }

    #[test]
    fn gcm_sectors_independent() {
        let key = [0x42u8; 32];
        let cipher = GcmSectorCipher::new(&key);
        let plaintext = vec![0u8; GCM_PLAINTEXT_SIZE];
        let mut s1 = [0u8; GCM_SECTOR_SIZE];
        let mut s2 = [0u8; GCM_SECTOR_SIZE];
        cipher.encrypt_sector(0, &plaintext, &mut s1);
        cipher.encrypt_sector(1, &plaintext, &mut s2);
        assert_ne!(
            s1, s2,
            "different LBAs should produce different ciphertexts"
        );
    }
}
