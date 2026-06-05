//! Core bridge — calls soteria-core directly.
//!
//! Every UI action goes through this module. No CLI, no HTTP, no
//! subprocess. Direct function calls into the Rust library.

use soteria_core::crypto_engine::shares::{shares_path_for, ShareFile};
use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::fs_layer::kdf::{KdfParams, VolumeKeyFile};
use soteria_core::fs_layer::storage::{
    backing_path_for, decrypt_from_disk_with_passphrase, encrypt_to_disk_with_passphrase,
    list_files, OnDiskFile,
};
use std::path::{Path, PathBuf};

#[cfg(feature = "tpm")]
use soteria_core::tpm;

/// Result of a core operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoreResult {
    pub ok: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl CoreResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            data: None,
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            data: None,
        }
    }
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Encrypt a file into a volume.
pub fn encrypt_file(
    src: &Path,
    into: &Path,
    name: &str,
    passphrase: &str,
    fast_kdf: bool,
) -> CoreResult {
    let plaintext = match std::fs::read(src) {
        Ok(p) => p,
        Err(e) => return CoreResult::err(format!("read failed: {e}")),
    };
    if let Err(e) = std::fs::create_dir_all(into) {
        return CoreResult::err(format!("mkdir failed: {e}"));
    }
    let path = backing_path_for(into, name);
    let params = if fast_kdf {
        KdfParams::fast_test()
    } else {
        KdfParams::production()
    };
    match encrypt_to_disk_with_passphrase(
        &path,
        AeadAlgorithm::XChaCha20Poly1305,
        params,
        65536,
        passphrase.as_bytes(),
        &plaintext,
    ) {
        Ok(vol) => {
            CoreResult::ok(format!("Encrypted: {}", path.display())).with_data(serde_json::json!({
                "path": path.to_string_lossy(),
                "size": vol.plaintext_size,
                "blocks": vol.index.len(),
            }))
        }
        Err(e) => CoreResult::err(format!("encrypt failed: {e}")),
    }
}

/// Decrypt a volume to a file.
pub fn decrypt_file(from: &Path, name: &str, passphrase: &str, output: &Path) -> CoreResult {
    let volume_path = backing_path_for(from, name);
    let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(&volume_path);
    let kdf_file = match VolumeKeyFile::load(&kdf_path) {
        Ok(f) => f,
        Err(e) => return CoreResult::err(format!("KDF load failed: {e}")),
    };
    let key = match soteria_core::fs_layer::kdf::derive_volume_key(passphrase.as_bytes(), &kdf_file)
    {
        Ok(k) => k,
        Err(e) => return CoreResult::err(format!("KDF derive failed: {e}")),
    };
    let vol = match OnDiskFile::load(&volume_path) {
        Ok(v) => v,
        Err(e) => return CoreResult::err(format!("volume load failed: {e}")),
    };
    let crypto = soteria_core::crypto_engine::block::BlockCrypto::new(
        AeadAlgorithm::XChaCha20Poly1305,
        *key,
    );
    let plaintext = match vol.plaintext(&crypto) {
        Ok(p) => p,
        Err(e) => return CoreResult::err(format!("decrypt failed: {e}")),
    };
    if let Some(parent) = output.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(output, &plaintext) {
        Ok(()) => CoreResult::ok(format!("Decrypted: {}", output.display()))
            .with_data(serde_json::json!({"size": plaintext.len()})),
        Err(e) => CoreResult::err(format!("write failed: {e}")),
    }
}

/// Generate an ML-KEM-768 keypair.
pub fn generate_kem_keypair(out: &Path) -> CoreResult {
    let kp = soteria_core::crypto_engine::pq::generate_keypair();
    let pk_hex: String = kp
        .public()
        .bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sk_hex: String = kp
        .secret()
        .bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pk_path = out.with_extension("pk");
    let sk_path = out.with_extension("sk");
    if let Err(e) = std::fs::write(&pk_path, &pk_hex) {
        return CoreResult::err(format!("write pk: {e}"));
    }
    if let Err(e) = std::fs::write(&sk_path, &sk_hex) {
        return CoreResult::err(format!("write sk: {e}"));
    }
    CoreResult::ok(format!("Generated: {}", pk_path.display())).with_data(
        serde_json::json!({"pk": pk_path.to_string_lossy(), "sk": sk_path.to_string_lossy()}),
    )
}

/// Generate an ML-DSA-65 keypair.
pub fn generate_dsa_keypair(out: &Path) -> CoreResult {
    let kp = soteria_core::crypto_engine::dsa::generate_keypair();
    let pk_hex: String = kp.public.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let sk_hex: String = kp.secret.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let pk_path = out.with_extension("dsa.pk");
    let sk_path = out.with_extension("dsa.sk");
    if let Err(e) = std::fs::write(&pk_path, &pk_hex) {
        return CoreResult::err(format!("write pk: {e}"));
    }
    if let Err(e) = std::fs::write(&sk_path, &sk_hex) {
        return CoreResult::err(format!("write sk: {e}"));
    }
    CoreResult::ok(format!("Generated: {}", pk_path.display())).with_data(
        serde_json::json!({"pk": pk_path.to_string_lossy(), "sk": sk_path.to_string_lossy()}),
    )
}

/// Add a recipient to a volume's share file.
pub fn share_add(
    volume: &Path,
    passphrase: &str,
    recipient_pk: &Path,
    owner_sk: &Path,
) -> CoreResult {
    let root_key = match derive_root_key(volume, passphrase) {
        Ok(k) => k,
        Err(e) => return CoreResult::err(e),
    };
    let mut sf = match ShareFile::open(volume, &root_key) {
        Ok(f) => f,
        Err(e) => return CoreResult::err(format!("open share file: {e}")),
    };
    let pk = match load_pk(recipient_pk) {
        Ok(p) => p,
        Err(e) => return CoreResult::err(e),
    };
    let osk = match load_owner_sk(owner_sk) {
        Ok(s) => s,
        Err(e) => return CoreResult::err(e),
    };
    let now = now_ms();
    match sf.add_recipient(&pk, &root_key, &osk, now) {
        Ok(kid) => {
            if let Err(e) = sf.save(volume) {
                return CoreResult::err(format!("save share file: {e}"));
            }
            let kid_hex: String = kid.iter().map(|b| format!("{b:02x}")).collect();
            CoreResult::ok("Recipient added")
                .with_data(serde_json::json!({"recipient_key_id_hex": kid_hex}))
        }
        Err(e) => CoreResult::err(format!("add_recipient failed: {e}")),
    }
}

/// List recipients in a volume's share file.
pub fn share_list(volume: &Path, passphrase: &str) -> CoreResult {
    let root_key = match derive_root_key(volume, passphrase) {
        Ok(k) => k,
        Err(e) => return CoreResult::err(e),
    };
    match ShareFile::open(volume, &root_key) {
        Ok(sf) => {
            let active = sf.list_active();
            let revoked = sf.list_revoked();
            CoreResult::ok(format!(
                "{} active, {} revoked",
                active.len(),
                revoked.len()
            ))
            .with_data(serde_json::json!({
                "active_count": active.len(),
                "revoked_count": revoked.len(),
                "active": active.iter().map(|r| r.recipient_key_id).collect::<Vec<_>>(),
            }))
        }
        Err(e) => CoreResult::err(format!("open share file: {e}")),
    }
}

/// Verify volume integrity.
pub fn verify_volume(dir: &Path) -> CoreResult {
    match list_files(dir) {
        Ok(files) => {
            let mut ok_count = 0;
            let mut err_count = 0;
            for name in &files {
                let path = backing_path_for(dir, name);
                match OnDiskFile::load(&path) {
                    Ok(vol) => {
                        let crypto = soteria_core::crypto_engine::block::BlockCrypto::new(
                            vol.algorithm,
                            [0u8; 32], // dummy key — only checking header integrity
                        );
                        // Header integrity is checked in load()
                        ok_count += 1;
                    }
                    Err(_) => err_count += 1,
                }
            }
            CoreResult::ok(format!("{ok_count} volumes verified, {err_count} errors"))
                .with_data(serde_json::json!({"ok": ok_count, "err": err_count}))
        }
        Err(e) => CoreResult::err(format!("list failed: {e}")),
    }
}

/// List volumes in a directory.
pub fn list_volumes(dir: &Path) -> Vec<(String, u64)> {
    match list_files(dir) {
        Ok(files) => files
            .iter()
            .map(|name| {
                let path = backing_path_for(dir, name);
                let size = OnDiskFile::load(&path)
                    .map(|v| v.plaintext_size)
                    .unwrap_or(0);
                (name.clone(), size)
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Check if TPM is available.
pub fn tpm_available() -> bool {
    #[cfg(feature = "tpm")]
    {
        tpm::tpm_available()
    }
    #[cfg(not(feature = "tpm"))]
    {
        false
    }
}

/// Get the KDF params (production vs fast).
pub fn kdf_params(fast: bool) -> KdfParams {
    if fast {
        KdfParams::fast_test()
    } else {
        KdfParams::production()
    }
}

/// Create a new empty volume at `data_path` by generating random plaintext of
/// `size_mb` megabytes, then encrypting with `passphrase`.
///
/// Returns the size in bytes of the created volume.
pub fn create_volume(
    data_path: &Path,
    passphrase: &str,
    size_mb: u64,
    fast_kdf: bool,
) -> CoreResult {
    let size_bytes = size_mb * 1024 * 1024;
    let plaintext = vec![0u8; size_bytes as usize];
    let params = if fast_kdf {
        KdfParams::fast_test()
    } else {
        KdfParams::production()
    };
    match encrypt_to_disk_with_passphrase(
        data_path,
        AeadAlgorithm::XChaCha20Poly1305,
        params,
        65536,
        passphrase.as_bytes(),
        &plaintext,
    ) {
        Ok(vol) => CoreResult::ok(format!(
            "Created volume: {:?}",
            data_path.file_name().unwrap_or_default()
        ))
        .with_data(serde_json::json!({
            "path": data_path.to_string_lossy(),
            "size_bytes": size_bytes,
            "block_count": vol.index.len(),
        })),
        Err(e) => CoreResult::err(format!("create volume failed: {e}")),
    }
}

/// Open a volume at `data_path` using `passphrase`.
/// Returns plaintext size on success but does NOT expose the plaintext.
pub fn open_volume(data_path: &Path, passphrase: &str) -> CoreResult {
    match decrypt_from_disk_with_passphrase(data_path, passphrase.as_bytes()) {
        Ok((vol, plaintext)) => {
            let size = vol.plaintext_size;
            let blocks = vol.index.len();
            let algorithm = match vol.algorithm {
                AeadAlgorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
                AeadAlgorithm::Aes256Gcm => "AES-256-GCM",
            };
            CoreResult::ok(format!(
                "Volume opened: {} ({algorithm}, {blocks} blocks, {size} bytes)",
                data_path.display()
            ))
            .with_data(serde_json::json!({
                "path": data_path.to_string_lossy(),
                "size": size,
                "blocks": blocks,
                "algorithm": algorithm,
            }))
        }
        Err(e) => CoreResult::err(format!("open volume failed: {e}")),
    }
}

/// Close / dismount an opened volume.
pub fn close_volume(data_path: &Path) -> CoreResult {
    match std::fs::remove_file(data_path) {
        Ok(()) => CoreResult::ok(format!("Dismounted: {}", data_path.display())),
        Err(e) => CoreResult::err(format!("dismount failed: {e}")),
    }
}

/// Return the total capacity of a volume file on disk (raw bytes).
pub fn volume_file_size(data_path: &Path) -> u64 {
    std::fs::metadata(data_path).map(|m| m.len()).unwrap_or(0)
}

// ── Helpers ─────────────────────────────────────────────────────────
fn derive_root_key(volume: &Path, passphrase: &str) -> Result<[u8; 32], String> {
    let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(volume);
    let kdf_file = VolumeKeyFile::load(&kdf_path).map_err(|e| format!("KDF load: {e}"))?;
    let key = soteria_core::fs_layer::kdf::derive_volume_key(passphrase.as_bytes(), &kdf_file)
        .map_err(|e| format!("KDF derive: {e}"))?;
    Ok(*key)
}

fn load_pk(path: &Path) -> Result<soteria_core::crypto_engine::pq::PublicKey, String> {
    let hex = std::fs::read_to_string(path).map_err(|e| format!("read pk: {e}"))?;
    let bytes = hex::decode(hex.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 1184 {
        return Err(format!("pk must be 1184 bytes, got {}", bytes.len()));
    }
    Ok(soteria_core::crypto_engine::pq::PublicKey { bytes })
}

fn load_owner_sk(path: &Path) -> Result<soteria_core::crypto_engine::dsa::OwnerSecretKey, String> {
    let hex = std::fs::read_to_string(path).map_err(|e| format!("read sk: {e}"))?;
    let bytes = hex::decode(hex.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("sk must be 32 bytes, got {}", bytes.len()));
    }
    Ok(soteria_core::crypto_engine::dsa::OwnerSecretKey { bytes })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
