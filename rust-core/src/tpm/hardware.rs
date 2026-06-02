//! Real TPM2 hardware backend using tss-esapi.
//!
//! Requires the `tpm` feature flag and a TPM2-capable system.

use crate::tpm::interface::TpmProvider;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    context::TctiName,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        PcrSelectionList, PcrSlot, PublicBuilder, PublicRsaParametersBuilder, RsaExponent,
        SymmetricDefinition,
    },
    Context,
};
use zeroize::Zeroizing;

pub struct Tpm2HardwareProvider {
    ctx: parking_lot::Mutex<Context>,
}

impl Tpm2HardwareProvider {
    pub fn new() -> crate::Result<Self> {
        let ctx = Context::new(TctiName::Device)
            .map_err(|e| anyhow::anyhow!("TPM2: failed to connect: {e}"))?;
        Ok(Self {
            ctx: parking_lot::Mutex::new(ctx),
        })
    }

    fn primary_template() -> tss_esapi::structures::Public {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()
            .expect("TPM2: primary key attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinition::AesCbc(
                        SymmetricDefinition::AES_128_CBC,
                    ))
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .build()
                    .expect("TPM2: RSA parameters"),
            )
            .build()
            .expect("TPM2: primary key template")
    }

    fn sealed_template() -> tss_esapi::structures::Public {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(false)
            .with_user_with_auth(true)
            .build()
            .expect("TPM2: sealed object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .build()
            .expect("TPM2: sealed object template")
    }
}

impl TpmProvider for Tpm2HardwareProvider {
    fn seal(&self, plaintext_key: &[u8; 32]) -> crate::Result<Vec<u8>> {
        let mut ctx = self.ctx.lock();

        let primary = ctx
            .create_primary_key(
                Hierarchy::Owner,
                &Self::primary_template(),
                None,
                None,
                None,
                None,
            )
            .map_err(|e| anyhow::anyhow!("TPM2 seal: primary key: {e}"))?;

        let sealed = ctx
            .create(primary, &Self::sealed_template(), None, None, None, None)
            .map_err(|e| anyhow::anyhow!("TPM2 seal: create: {e}"))?;

        let priv_bytes = sealed
            .out_private
            .marshal()
            .map_err(|e| anyhow::anyhow!("TPM2 seal: marshal private: {e}"))?;
        let pub_bytes = sealed
            .out_public
            .marshal()
            .map_err(|e| anyhow::anyhow!("TPM2 seal: marshal public: {e}"))?;

        let mut result = Vec::with_capacity(4 + priv_bytes.len() + pub_bytes.len());
        result.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&priv_bytes);
        result.extend_from_slice(&pub_bytes);

        let _ = ctx.flush_context(primary.into());
        Ok(result)
    }

    fn unseal(&self, sealed_blob: &[u8]) -> crate::Result<Zeroizing<[u8; 32]>> {
        anyhow::ensure!(sealed_blob.len() > 4, "TPM2 unseal: blob too short");

        let priv_len = u32::from_le_bytes([
            sealed_blob[0],
            sealed_blob[1],
            sealed_blob[2],
            sealed_blob[3],
        ]) as usize;

        anyhow::ensure!(
            sealed_blob.len() >= 4 + priv_len,
            "TPM2 unseal: blob truncated"
        );

        let priv_bytes = &sealed_blob[4..4 + priv_len];
        let pub_bytes = &sealed_blob[4 + priv_len..];

        let mut ctx = self.ctx.lock();

        let primary = ctx
            .create_primary_key(
                Hierarchy::Owner,
                &Self::primary_template(),
                None,
                None,
                None,
                None,
            )
            .map_err(|e| anyhow::anyhow!("TPM2 unseal: primary key: {e}"))?;

        let private = tss_esapi::structures::Private::try_from(priv_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("TPM2 unseal: parse private: {e}"))?;
        let public = tss_esapi::structures::Public::try_from(pub_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("TPM2 unseal: parse public: {e}"))?;

        let handle = ctx
            .load(primary, private, public)
            .map_err(|e| anyhow::anyhow!("TPM2 unseal: load: {e}"))?;

        let unsealed = ctx
            .unseal(handle, None)
            .map_err(|e| anyhow::anyhow!("TPM2 unseal: unseal: {e}"))?;

        anyhow::ensure!(unsealed.len() == 32, "TPM2 unseal: expected 32 bytes");

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&unsealed);

        let _ = ctx.flush_context(handle.into());
        let _ = ctx.flush_context(primary.into());
        Ok(out)
    }

    fn boot_measurement(&self) -> crate::Result<[u8; 32]> {
        let mut ctx = self.ctx.lock();

        let selection = PcrSelectionList::builder()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot4,
                    PcrSlot::Slot7,
                ],
            )
            .build()
            .map_err(|e| anyhow::anyhow!("TPM2: PCR selection: {e}"))?;

        let (pcr_values, _) = ctx
            .pcr_read(&selection)
            .map_err(|e| anyhow::anyhow!("TPM2: PCR read: {e}"))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"soteria:boot-measurement:v1");
        for digest in pcr_values.digests() {
            hasher.update(digest.as_bytes());
        }

        Ok(*hasher.finalize().as_bytes())
    }
}
