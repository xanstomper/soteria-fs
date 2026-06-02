use clap::{Parser, Subcommand};
use soteria_core::config::SoteriaConfig;
use soteria_core::crypto_engine::dsa::{self, OwnerPublicKey, OwnerSecretKey};
use soteria_core::crypto_engine::pq::{generate_keypair, PublicKey, SecretKey};
use soteria_core::crypto_engine::shares::{shares_path_for, ShareFile};
use soteria_core::crypto_engine::AeadAlgorithm;
use soteria_core::event_bus::{EventBus, Severity, SoteriaEvent};
use soteria_core::fs_layer::kdf::{KdfParams, VolumeKeyFile};
use soteria_core::fs_layer::storage::{
    backing_path_for, decrypt_from_disk_with_key, decrypt_from_disk_with_passphrase,
    encrypt_to_disk_with_passphrase, list_files, OnDiskFile,
};
use soteria_core::response_engine::{PolicyEngine, ResponseContext};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(name = "soteriad", about = "Soteria FS deterministic security daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print the loaded configuration as JSON.
    Status {
        #[arg(long, default_value = "../config/soteria.toml")]
        config: PathBuf,
    },
    /// Append a synthetic event to the in-memory event bus and run the
    /// policy engine over it. Useful for testing the response pipeline.
    SimulateEvent {
        #[arg(long, default_value = "../config/soteria.toml")]
        config: PathBuf,
        #[arg(long, default_value = "ENTROPY_SPIKE")]
        event_type: String,
        #[arg(long, default_value_t = 0.91)]
        severity: f64,
    },
    /// Mount the FUSE filesystem. Linux/macOS only.
    Mount {
        #[arg(long)]
        mountpoint: PathBuf,
        #[arg(long)]
        backing: PathBuf,
        #[arg(long, default_value = "../config/soteria.toml")]
        config: PathBuf,
    },
    /// Encrypt a file into a Soteria volume directory using a passphrase.
    /// Writes `<dir>/<name>.sot` and a `.sot.kdf` sidecar.
    Encrypt {
        #[arg(long)]
        src: PathBuf,
        #[arg(long)]
        into: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: String,
        #[arg(long, value_enum, default_value_t = AlgoArg::XChaCha)]
        algorithm: AlgoArg,
        #[arg(long, default_value_t = 65536)]
        block_size: usize,
        #[arg(long, default_value_t = false)]
        fast_kdf: bool,
    },
    /// Decrypt a Soteria volume back to plaintext. Use either `--passphrase`
    /// or `--key-file` (a 32-byte raw key, e.g. produced by `share unlock`).
    Decrypt {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, conflicts_with = "key_file")]
        passphrase: Option<String>,
        #[arg(long, conflicts_with = "passphrase")]
        key_file: Option<PathBuf>,
    },
    /// List all volumes in a directory and their sizes.
    List {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Verify every volume in a directory (header integrity + lineage chain).
    /// Exits with non-zero status if any volume fails verification.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Generate a fresh keypair. Default is ML-KEM-768 (used for share
    /// recipients). Use `--scheme ml-dsa-65` to generate an ML-DSA-65
    /// keypair for the volume owner. Writes `<prefix>.pk` and `<prefix>.sk`
    /// as hex files.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// Cryptographic scheme: `ml-kem-768` (default) for share recipients,
        /// `ml-dsa-65` for the volume owner's signing key.
        #[arg(long, value_enum, default_value_t = KeygenSchemeArg::MlKem768)]
        scheme: KeygenSchemeArg,
    },
    /// Inspect an audit log. Dumps all entries, verifies the BLAKE3 chain,
    /// and exits non-zero on tamper.
    Audit {
        #[arg(long)]
        log: PathBuf,
        #[arg(long, default_value_t = false)]
        verify_only: bool,
    },
    /// Start the native terminal UI dashboard. Runs as a full-screen
    /// TUI that communicates directly with the Soteria runtime.
    /// No HTTP, no browser, no external process.
    Tui,
    /// Manage ML-KEM-768 sharing of a volume's root key.
    #[command(subcommand)]
    Share(ShareCommands),
}

#[derive(Subcommand, Debug)]
enum ShareCommands {
    /// Add a new recipient to a volume. Wraps the volume root key with the
    /// recipient's ML-KEM-768 public key, signs the envelope with the
    /// owner's ML-DSA-65 secret key, and writes it to the share file.
    Add {
        /// Path to the volume file (the `.sot` file).
        #[arg(long)]
        volume: PathBuf,
        /// Passphrase the volume was encrypted with.
        #[arg(long)]
        passphrase: String,
        /// Path to the recipient's `.pk` file.
        #[arg(long)]
        recipient_pk: PathBuf,
        /// Path to the volume owner's ML-DSA-65 secret key (`.dsa.sk`).
        /// The owner signs the resulting envelope so recipients can
        /// cryptographically verify the addition.
        #[arg(long)]
        owner_sk: PathBuf,
    },
    /// Revoke a recipient. The recipient's envelope stays in the share
    /// file's history but is no longer active.
    Remove {
        #[arg(long)]
        volume: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        recipient_pk: PathBuf,
        #[arg(long, default_value = "manual revocation")]
        reason: String,
    },
    /// List active and revoked recipients for a volume.
    List {
        #[arg(long)]
        volume: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    /// Recover the volume root key using the recipient's secret key. Writes
    /// 32 raw bytes to `--out`. The key can then unlock the volume via
    /// `decrypt --key-file`.
    Unlock {
        #[arg(long)]
        volume: PathBuf,
        /// Path to the recipient's `.sk` file.
        #[arg(long)]
        sk: PathBuf,
        /// Path to write the 32-byte raw root key to.
        #[arg(long)]
        out: PathBuf,
        /// Skip share-file fingerprint validation. The recipient normally
        /// does not hold the volume passphrase, so this is the default. Set
        /// `--verify-fingerprint` to validate that the share file matches
        /// the volume's root key (requires `--passphrase`).
        #[arg(long, default_value_t = false)]
        verify_fingerprint: bool,
        /// Passphrase the volume was encrypted with. Required when
        /// `--verify-fingerprint` is set; ignored otherwise.
        #[arg(long)]
        passphrase: Option<String>,
        /// Path to the volume owner's ML-DSA-65 public key (`.dsa.pk`).
        /// When supplied, the signature on each candidate envelope is
        /// verified before unwrapping. Use `--no-verify-signature` to
        /// opt out.
        #[arg(long)]
        owner_pk: Option<PathBuf>,
        /// Skip envelope signature verification even if `--owner-pk` is
        /// supplied. The AEAD auth check on the envelope still applies.
        #[arg(long, default_value_t = false)]
        no_verify_signature: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Debug, Eq, PartialEq)]
enum AlgoArg {
    XChaCha,
    AesGcm,
}

impl From<AlgoArg> for AeadAlgorithm {
    fn from(a: AlgoArg) -> Self {
        match a {
            AlgoArg::XChaCha => AeadAlgorithm::XChaCha20Poly1305,
            AlgoArg::AesGcm => AeadAlgorithm::Aes256Gcm,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug, Eq, PartialEq)]
enum KeygenSchemeArg {
    /// ML-KEM-768 (default) — used by share recipients.
    MlKem768,
    /// ML-DSA-65 — used by the volume owner to sign share envelopes.
    MlDsa65,
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn derive_root_key_from_volume(volume_path: &Path, passphrase: &str) -> anyhow::Result<[u8; 32]> {
    let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(volume_path);
    let kdf_file = VolumeKeyFile::load(&kdf_path)
        .map_err(|e| anyhow::anyhow!("KDF sidecar load failed: {e}"))?;
    let key = soteria_core::fs_layer::kdf::derive_volume_key(passphrase.as_bytes(), &kdf_file)
        .map_err(|e| anyhow::anyhow!("KDF derive failed: {e}"))?;
    // Verify the derived key actually decrypts the volume's first block.
    // This defends share-sidecar creation against wrong-passphrase attacks
    // (a wrong passphrase would otherwise let an attacker plant a share
    // file with a fingerprint of the wrong key).
    soteria_core::fs_layer::storage::verify_key_for_volume(volume_path, &key)
        .map_err(|_| anyhow::anyhow!("passphrase does not unlock this volume"))?;
    Ok(*key)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("info")
        .init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Status { config } => {
            let cfg = SoteriaConfig::load(&config)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Commands::SimulateEvent {
            config,
            event_type,
            severity,
        } => {
            let cfg = SoteriaConfig::load(&config)?;
            let mut bus = EventBus::new();
            let mut policy = PolicyEngine::from_config(&cfg.response);
            let event = SoteriaEvent::new(
                event_type,
                "cli_simulator",
                Severity::new(severity),
                serde_json::json!({"deterministic": true}),
            )?;
            let record = bus.append(event.clone())?;
            let decision = policy.evaluate(&event, &mut ResponseContext::default());
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"event_record": *record, "decision": decision})
                )?
            );
        }
        Commands::Mount {
            mountpoint,
            backing,
            config,
        } => {
            #[cfg(not(feature = "fuse"))]
            {
                let _ = (mountpoint, backing, config);
                anyhow::bail!("built without FUSE support; rebuild with --features fuse");
            }
            #[cfg(feature = "fuse")]
            {
                use fuser::MountOption;
                use soteria_core::fs_layer::fuse_fs::SoteriaFs;
                let cfg = SoteriaConfig::load(&config)?;
                std::fs::create_dir_all(&backing)?;
                let fs = SoteriaFs::new(backing, cfg)?;
                fuser::mount2(
                    fs,
                    mountpoint,
                    &[
                        MountOption::FSName("soteria-fs".into()),
                        MountOption::AutoUnmount,
                    ],
                )?;
            }
        }
        Commands::Encrypt {
            src,
            into,
            name,
            passphrase,
            algorithm,
            block_size,
            fast_kdf,
        } => {
            let plaintext = std::fs::read(&src)?;
            std::fs::create_dir_all(&into)?;
            let path = backing_path_for(&into, &name);
            let params = if fast_kdf {
                KdfParams::fast_test()
            } else {
                KdfParams::production()
            };
            let vol = encrypt_to_disk_with_passphrase(
                &path,
                algorithm.clone().into(),
                params,
                block_size,
                passphrase.as_bytes(),
                &plaintext,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "path": path,
                    "name": name,
                    "plaintext_size": vol.plaintext_size,
                    "block_count": vol.index.len(),
                    "block_size": vol.block_size,
                    "algorithm": match algorithm {
                        AlgoArg::XChaCha => "XChaCha20Poly1305",
                        AlgoArg::AesGcm => "Aes256Gcm",
                    },
                }))?
            );
        }
        Commands::Decrypt {
            from,
            name,
            output,
            passphrase,
            key_file,
        } => {
            let path = backing_path_for(&from, &name);
            let (vol, plaintext) = match (passphrase, key_file) {
                (Some(pw), None) => decrypt_from_disk_with_passphrase(&path, pw.as_bytes())?,
                (None, Some(kf)) => {
                    let key_bytes = std::fs::read(&kf)?;
                    anyhow::ensure!(
                        key_bytes.len() == 32,
                        "key file must be exactly 32 raw bytes (got {})",
                        key_bytes.len()
                    );
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);
                    decrypt_from_disk_with_key(&path, &key)?
                }
                _ => anyhow::bail!("decrypt: provide exactly one of --passphrase or --key-file"),
            };
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&output, &plaintext)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "path": path,
                    "output": output,
                    "plaintext_size": vol.plaintext_size,
                    "recovered_size": plaintext.len(),
                }))?
            );
        }
        Commands::List { dir } => {
            let names = list_files(&dir)?;
            let mut rows = Vec::new();
            for name in &names {
                let path = backing_path_for(&dir, name);
                let vol = OnDiskFile::load(&path)?;
                let lineage_ok = vol.verify_lineage().is_none();
                rows.push(serde_json::json!({
                    "name": name,
                    "plaintext_size": vol.plaintext_size,
                    "block_count": vol.index.len(),
                    "lineage_ok": lineage_ok,
                }));
            }
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        Commands::Verify { dir } => {
            let names = list_files(&dir)?;
            let mut all_ok = true;
            let mut results = Vec::new();
            for name in &names {
                let path = backing_path_for(&dir, name);
                let vol = match OnDiskFile::load(&path) {
                    Ok(v) => v,
                    Err(e) => {
                        all_ok = false;
                        results.push(serde_json::json!({
                            "name": name,
                            "ok": false,
                            "error": e.to_string(),
                        }));
                        continue;
                    }
                };
                match vol.verify_lineage() {
                    None => results.push(serde_json::json!({
                        "name": name,
                        "ok": true,
                        "blocks": vol.index.len(),
                    })),
                    Some(i) => {
                        all_ok = false;
                        results.push(serde_json::json!({
                            "name": name,
                            "ok": false,
                            "first_bad_block": i,
                        }));
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&results)?);
            if !all_ok {
                std::process::exit(1);
            }
        }
        Commands::Keygen { out, scheme } => match scheme {
            KeygenSchemeArg::MlKem768 => {
                let kp = generate_keypair();
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
                std::fs::write(&pk_path, &pk_hex)?;
                std::fs::write(&sk_path, &sk_hex)?;
                let pk = PublicKey {
                    bytes: hex_decode(&pk_hex)?,
                };
                assert_eq!(pk.bytes.len(), 1184);
                let fp = soteria_core::crypto_engine::pq::KeyEnvelope::recipient_key_id(&pk);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "scheme": "ml-kem-768",
                        "public_key": pk_path,
                        "secret_key": sk_path,
                        "recipient_key_id_hex": fp.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    }))?
                );
            }
            KeygenSchemeArg::MlDsa65 => {
                let kp = dsa::generate_keypair();
                let pk_hex: String = kp.public.bytes.iter().map(|b| format!("{b:02x}")).collect();
                let sk_hex: String = kp.secret.bytes.iter().map(|b| format!("{b:02x}")).collect();
                let pk_path = out.with_extension("dsa.pk");
                let sk_path = out.with_extension("dsa.sk");
                std::fs::write(&pk_path, &pk_hex)?;
                std::fs::write(&sk_path, &sk_hex)?;
                let kid = dsa::owner_key_id(&kp.public);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "scheme": "ml-dsa-65",
                        "public_key": pk_path,
                        "secret_key": sk_path,
                        "owner_key_id_hex": kid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    }))?
                );
            }
        },
        Commands::Audit { log, verify_only } => {
            use soteria_core::policy::audit_log::{read_entries, verify_bytes, VerifyResult};
            let raw = match std::fs::read(&log) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "entries": 0,
                            "log": log,
                            "note": "log does not exist yet",
                        }))?
                    );
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };
            let verify = verify_bytes(&raw).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            match &verify {
                VerifyResult::Ok { entries } => {
                    if verify_only {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": true,
                                "entries": entries,
                            }))?
                        );
                    } else {
                        let entries = read_entries(&log)?;
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "ok": true,
                                "entries": entries,
                            }))?
                        );
                    }
                }
                VerifyResult::Tampered { first_bad_index } => {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "reason": "tampered",
                            "first_bad_index": first_bad_index,
                        }))?
                    );
                    std::process::exit(1);
                }
                VerifyResult::Malformed { first_bad_index } => {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": false,
                            "reason": "malformed",
                            "first_bad_index": first_bad_index,
                        }))?
                    );
                    std::process::exit(2);
                }
            }
        }
        Commands::Share(sub) => match sub {
            ShareCommands::Add {
                volume,
                passphrase,
                recipient_pk,
                owner_sk,
            } => {
                let root_key = derive_root_key_from_volume(&volume, &passphrase)?;
                let mut sf = ShareFile::open(&volume, &root_key)?;
                let pk = load_public_key(&recipient_pk)?;
                let osk = load_owner_secret_key(&owner_sk)?;
                let kid = sf.add_recipient(&pk, &root_key, &osk, unix_ms_now())?;
                sf.save(&volume)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "added",
                        "volume": volume,
                        "share_file": shares_path_for(&volume),
                        "recipient_key_id_hex": kid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    }))?
                );
            }
            ShareCommands::Remove {
                volume,
                passphrase,
                recipient_pk,
                reason,
            } => {
                let root_key = derive_root_key_from_volume(&volume, &passphrase)?;
                let mut sf = ShareFile::open(&volume, &root_key)?;
                let pk = load_public_key(&recipient_pk)?;
                let revoked = sf.revoke_recipient(&pk, &reason, unix_ms_now())?;
                sf.save(&volume)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": if revoked { "revoked" } else { "noop" },
                        "volume": volume,
                        "revoked": revoked,
                    }))?
                );
            }
            ShareCommands::List { volume, passphrase } => {
                let root_key = derive_root_key_from_volume(&volume, &passphrase)?;
                let sf = ShareFile::open(&volume, &root_key)?;
                let active = sf.list_active();
                let revoked = sf.list_revoked();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "volume": volume,
                        "share_file": shares_path_for(&volume),
                        "active_count": active.len(),
                        "revoked_count": revoked.len(),
                        "active": active,
                        "revoked": revoked,
                    }))?
                );
            }
            ShareCommands::Unlock {
                volume,
                sk,
                out,
                verify_fingerprint,
                passphrase,
                owner_pk,
                no_verify_signature,
            } => {
                let recipient_sk = load_secret_key(&sk)?;
                let root_key = if verify_fingerprint {
                    let pw = passphrase.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("--verify-fingerprint requires --passphrase")
                    })?;
                    Some(derive_root_key_from_volume(&volume, pw)?)
                } else {
                    None
                };
                // Load the owner PK for signature verification, if provided.
                let owner_pk_loaded = match &owner_pk {
                    Some(path) => {
                        let opk = load_owner_public_key(path)?;
                        Some(opk)
                    }
                    None => None,
                };
                // When fingerprint checking is requested, `open` will validate
                // that the share file matches. When skipped, we still need a
                // root_key to pass into `open`, so use a sentinel of all zeros
                // and bypass the check by reading the file directly. The
                // zero-key path is only used for parsing, not for crypto.
                let sf = if let Some(rk) = root_key.as_ref() {
                    ShareFile::open(&volume, rk)?
                } else {
                    let raw = std::fs::read(shares_path_for(&volume))?;
                    serde_json::from_slice::<ShareFile>(&raw)
                        .map_err(|e| anyhow::anyhow!("share file: malformed JSON: {e}"))?
                };
                // If the caller supplied an owner PK and did NOT opt out of
                // verification, pass the PK to unlock for signature checking.
                // Otherwise pass None (no check).
                let verify_pk = if no_verify_signature {
                    if owner_pk.is_some() {
                        eprintln!("warning: --owner-pk supplied but --no-verify-signature was also set; skipping signature check");
                    }
                    None
                } else {
                    owner_pk_loaded.as_ref()
                };
                let decrypted = sf.unlock(&recipient_sk, verify_pk)?;
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&out, decrypted.root_key)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "unlocked",
                        "volume": volume,
                        "out": out,
                        "recipient_key_id_hex": decrypted.recipient_key_id.iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>(),
                        "fingerprint_verified": root_key.is_some(),
                        "signature_verified": verify_pk.is_some(),
                    }))?
                );
            }
        },
        Commands::Tui => {
            let bus = std::sync::Arc::new(soteria_core::event_bus::bus::EventBus::new());
            // Publish a startup event.
            bus.publish(
                soteria_core::event_bus::bus::EventCategory::System,
                soteria_core::event_bus::bus::Severity::Info,
                "soteriad",
                "Soteria runtime started",
                soteria_core::event_bus::bus::EventData::None,
            );
            soteria_core::tui::app::run(bus)?;
        }
    }
    Ok(())
}

fn load_public_key(path: &PathBuf) -> anyhow::Result<PublicKey> {
    let hex = std::fs::read_to_string(path)?;
    let bytes = hex_decode(hex.trim())?;
    anyhow::ensure!(
        bytes.len() == 1184,
        "public key must be 1184 bytes (got {})",
        bytes.len()
    );
    Ok(PublicKey { bytes })
}

fn load_secret_key(path: &PathBuf) -> anyhow::Result<SecretKey> {
    let hex = std::fs::read_to_string(path)?;
    let bytes = hex_decode(hex.trim())?;
    anyhow::ensure!(
        bytes.len() == 64,
        "secret key seed must be 64 bytes (got {})",
        bytes.len()
    );
    Ok(SecretKey { bytes })
}

fn load_owner_public_key(path: &PathBuf) -> anyhow::Result<OwnerPublicKey> {
    let hex = std::fs::read_to_string(path)?;
    let bytes = hex_decode(hex.trim())?;
    anyhow::ensure!(
        bytes.len() == dsa::ML_DSA_65_PK_LEN,
        "owner public key must be {} bytes (got {})",
        dsa::ML_DSA_65_PK_LEN,
        bytes.len()
    );
    Ok(OwnerPublicKey { bytes })
}

fn load_owner_secret_key(path: &PathBuf) -> anyhow::Result<OwnerSecretKey> {
    let hex = std::fs::read_to_string(path)?;
    let bytes = hex_decode(hex.trim())?;
    anyhow::ensure!(
        bytes.len() == dsa::ML_DSA_65_SK_SEED_LEN,
        "owner secret key seed must be {} bytes (got {})",
        dsa::ML_DSA_65_SK_SEED_LEN,
        bytes.len()
    );
    Ok(OwnerSecretKey { bytes })
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("bad hex"))?;
        let l = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("bad hex"))?;
        out.push(((h << 4) | l) as u8);
        i += 2;
    }
    Ok(out)
}
