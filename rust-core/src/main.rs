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

/// Read a passphrase securely. Never from argv (V-03 fix).
///
/// Priority:
///   1. SOTERIA_PASSPHRASE env var (if set)
///   2. Interactive terminal prompt (echo disabled)
///
/// The returned string is NOT zeroized (rpassword doesn't support it),
/// but it's never stored in argv or shell history.
fn read_passphrase(prompt: &str) -> anyhow::Result<String> {
    // Check env var first (useful for scripts/testing).
    if let Ok(pw) = std::env::var("SOTERIA_PASSPHRASE") {
        return Ok(pw);
    }
    // Interactive prompt with echo disabled.
    let pw = rpassword::prompt_password(prompt)?;
    Ok(pw)
}

#[derive(Parser, Debug)]
#[command(name = "soteriad", about = "Soteria FS deterministic security daemon")]
struct Cli {
    /// Run in FIPS 140-3 mode. The module is initialized at startup
    /// (POST + software/firmware integrity test) and refuses to
    /// service any cryptographic operation if either test fails.
    /// Requires that the binary was built with `--features fips`.
    #[arg(long, global = true)]
    fips: bool,
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
    /// Quick-mount a volume: decrypts all files to a directory.
    /// Works on all platforms (no FUSE required). Files are decrypted
    /// on demand and re-encrypted when the directory is unmounted.
    QuickMount {
        /// Path to the volume directory.
        #[arg(long)]
        volume: PathBuf,
        /// Passphrase for the volume.
        #[arg(long)]
        passphrase: String,
        /// Directory to mount into (created if needed).
        #[arg(long)]
        mountpoint: PathBuf,
        /// Name of the volume to mount.
        #[arg(long)]
        name: String,
    },
    /// Unmount a quick-mounted volume (re-encrypts modified files).
    Unmount {
        /// The mountpoint to unmount.
        #[arg(long)]
        mountpoint: PathBuf,
        /// Path to the volume directory.
        #[arg(long)]
        volume: PathBuf,
        /// Passphrase for the volume.
        #[arg(long)]
        passphrase: String,
        /// Name of the volume.
        #[arg(long)]
        name: String,
    },
    /// Encrypt a file into a Soteria volume directory using a passphrase.
    /// Writes `<dir>/<name>.sot` and a `.sot.kdf` sidecar.
    ///
    /// V-03: Passphrase is read from stdin if not provided via --passphrase.
    /// NEVER pass passphrases as CLI arguments (visible in process listing).
    Encrypt {
        #[arg(long)]
        src: PathBuf,
        #[arg(long)]
        into: PathBuf,
        #[arg(long)]
        name: String,
        /// Passphrase (optional; if omitted, read securely from stdin).
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long, value_enum, default_value_t = AlgoArg::XChaCha)]
        algorithm: AlgoArg,
        #[arg(long, default_value_t = 65536)]
        block_size: usize,
        #[arg(long, default_value_t = false)]
        fast_kdf: bool,
        /// Use paranoid KDF parameters (4 GiB memory, 5 iterations).
        /// Single brute-force attempt requires ~4 GiB RAM and ~20 seconds.
        #[arg(long, default_value_t = false)]
        paranoid: bool,
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
    /// Full-Disk Encryption (FDE) operations: initialize, mount,
    /// shred, and verify whole-disk XTS-encrypted volumes. The
    /// "device" can be a real block device (`/dev/sda`, `\\.\PhysicalDrive0`)
    /// or a file (loopback). All operations use AES-256-XTS, Argon2id
    /// KDF, and LUKS2-style header backup.
    #[command(subcommand)]
    Fde(FdeCommands),
    /// SOTERIA-OMEGA Government & Military Edition. Classification,
    /// two-person rule, COMSEC custody, emergency zeroize, air-gap
    /// mode, and the 6-phase init flow. Requires `--features omega`.
    #[cfg(feature = "omega")]
    #[command(subcommand)]
    Omega(OmegaCommands),
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

#[derive(clap::ValueEnum, Clone, Debug, Eq, PartialEq)]
enum FdeKdfProfile {
    /// OWASP-recommended interactive (19 MiB, 2 iter, 1 lane). ~50-200 ms.
    Production,
    /// High-security (1 GiB, 3 iter, 1 lane). ~1-5 seconds.
    HighSecurity,
    /// Paranoid (4 GiB, 5 iter, 1 lane). ~10-30 seconds. For high-risk.
    Paranoid,
    /// Fast (64 KiB, 1 iter). For tests only.
    Fast,
}

impl From<FdeKdfProfile> for soteria_core::fs_layer::kdf::KdfParams {
    fn from(p: FdeKdfProfile) -> Self {
        use soteria_core::fs_layer::kdf::KdfParams;
        match p {
            FdeKdfProfile::Production => KdfParams::production(),
            FdeKdfProfile::HighSecurity => KdfParams::high_security(),
            FdeKdfProfile::Paranoid => KdfParams::paranoid(),
            FdeKdfProfile::Fast => KdfParams::fast_test(),
        }
    }
}

#[derive(Subcommand, Debug)]
enum FdeCommands {
    /// Initialize a new FDE volume. Allocates the device/file,
    /// writes the primary and backup headers, and overwrites the
    /// data area with random bytes. Prompts for a passphrase.
    Init {
        /// Path to the device (real block device) or container file.
        #[arg(long)]
        device: PathBuf,
        /// Total size in bytes. Required for container files; ignored
        /// for real devices.
        #[arg(long)]
        size: Option<u64>,
        /// Sector size in bytes (default 512).
        #[arg(long, default_value_t = 512)]
        sector_size: usize,
        /// KDF cost profile.
        #[arg(long, value_enum, default_value_t = FdeKdfProfile::HighSecurity)]
        kdf: FdeKdfProfile,
        /// Enable TPM 2.0 sealing (requires --features tpm).
        #[arg(long, default_value_t = false)]
        tpm_seal: bool,
        /// Enable anti-forensic Shamir key splitting. Requires
        /// `--shares N` and `--threshold K`.
        #[arg(long, default_value_t = false)]
        anti_forensic: bool,
        /// Number of shares (1..=255). Required with --anti-forensic.
        #[arg(long, requires = "anti_forensic")]
        shares: Option<u8>,
        /// Threshold for recovery (2..=N). Required with --anti-forensic.
        #[arg(long, requires = "anti_forensic")]
        threshold: Option<u8>,
    },
    /// Open an existing FDE volume and verify the passphrase.
    /// Performs no writes; the device is left untouched. Use this to
    /// test a passphrase before mounting.
    Verify {
        #[arg(long)]
        device: PathBuf,
    },
    /// Print the volume's UUID, KDF params, total sectors, and feature
    /// flags. Does not require a passphrase (header is not encrypted).
    Status {
        #[arg(long)]
        device: PathBuf,
    },
    /// Anti-forensic key split: read the volume master key (requires
    /// passphrase) and split it into N shares. Each share is written
    /// to a separate file. Loss of fewer than K shares is recoverable.
    SplitKey {
        #[arg(long)]
        device: PathBuf,
        /// Output directory for the share files.
        #[arg(long)]
        out: PathBuf,
        /// Threshold K (2..=N). Recovery needs K of N shares.
        #[arg(long)]
        threshold: u8,
        /// Number of shares N (>= K).
        #[arg(long)]
        shares: u8,
    },
    /// Recover the volume master key from K of N shares. Writes the
    /// raw 32-byte key to a file; feed it to `decrypt --key-file`.
    RecoverKey {
        /// Paths to K of N shares. Order does not matter.
        #[arg(long, num_args = 2..=255)]
        shares: Vec<PathBuf>,
        /// Where to write the 32-byte raw master key.
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a hidden volume inside the free space of an existing
    /// outer volume. Prompts for both outer and hidden passphrases.
    /// After creation, the outer volume can be used as decoy data;
    /// the hidden volume holds the real data.
    HiddenCreate {
        /// Path to the outer volume's container file.
        #[arg(long)]
        device: PathBuf,
        /// KDF profile for the hidden volume's key.
        #[arg(long, value_enum, default_value_t = FdeKdfProfile::HighSecurity)]
        kdf: FdeKdfProfile,
    },
    /// Hardware secure erase. Spawns `nvme format` or
    /// `hdparm --security-erase` against a real device. The file-
    /// backed `shred` command does multi-pass overwrite.
    HwErase {
        #[arg(long)]
        device: PathBuf,
        /// Use cryptographic erase (NVMe SES=2 or ATA Enhanced) when
        /// available. Falls back to user-data erase otherwise.
        #[arg(long, default_value_t = true)]
        crypto: bool,
    },
    /// Generate a PBA (Pre-Boot Authentication) configuration file.
    /// Writes a `pba.toml` to the EFI System Partition path you
    /// specify. The PBA binary is a separate build artifact
    /// (`soteria-pba`) not produced by this command.
    PbaConfig {
        /// Path to write `pba.toml` to (typically `/boot/efi/soteria/pba.toml`).
        #[arg(long)]
        out: PathBuf,
    },
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

    // If `--fips` was passed, initialize the FIPS 140-3 module.
    // POST (known-answer tests) and integrity test run here; if
    // either fails, the module enters an error state and refuses
    // to perform any cryptographic operation.
    if cli.fips {
        #[cfg(feature = "fips")]
        {
            let me = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("soteriad"));
            match soteria_core::crypto_engine::fips::init(&me) {
                Ok(()) => {
                    tracing::info!(
                        "FIPS module: POST passed, integrity test passed; module is operational"
                    );
                }
                Err(e) => {
                    tracing::error!("FIPS module initialization failed: {e}");
                    eprintln!("FATAL: FIPS module initialization failed: {e}");
                    std::process::exit(2);
                }
            }
        }
        #[cfg(not(feature = "fips"))]
        {
            eprintln!("FATAL: --fips requires building with the `fips` feature enabled.");
            eprintln!("       Rebuild with: cargo build --features fips --release");
            std::process::exit(2);
        }
    }

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
                // V-AUDIT-1: passphrase is required, key is derived from
                // the KDF sidecar at <backing>/.volume.kdf, never hardcoded.
                let pw = read_passphrase("Mount passphrase: ")?;
                let fs = SoteriaFs::from_passphrase(backing, cfg, pw.as_bytes())?;
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
        Commands::QuickMount {
            volume,
            passphrase,
            mountpoint,
            name,
        } => {
            // Decrypt all files from the volume into the mountpoint.
            std::fs::create_dir_all(&mountpoint)?;

            let volume_path = backing_path_for(&volume, &name);
            let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(&volume_path);
            let kdf_file = soteria_core::fs_layer::kdf::VolumeKeyFile::load(&kdf_path)?;
            let key =
                soteria_core::fs_layer::kdf::derive_volume_key(passphrase.as_bytes(), &kdf_file)?;

            let vol = soteria_core::fs_layer::storage::OnDiskFile::load(&volume_path)?;
            let crypto = soteria_core::crypto_engine::block::BlockCrypto::new(
                soteria_core::crypto_engine::AeadAlgorithm::XChaCha20Poly1305,
                *key,
            );
            let plaintext = vol.plaintext(&crypto)?;

            let output_path = mountpoint.join(format!("{name}.decrypted"));
            std::fs::write(&output_path, &plaintext)?;

            // Write a mount marker for unmount to find.
            let marker = serde_json::json!({
                "volume": volume,
                "name": name,
                "mountpoint": mountpoint,
                "output": output_path,
                "mounted_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            let marker_path = mountpoint.join(".soteria-mount.json");
            std::fs::write(&marker_path, serde_json::to_string_pretty(&marker)?)?;

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "action": "mounted",
                    "mountpoint": mountpoint,
                    "output": output_path,
                    "size": plaintext.len(),
                }))?
            );
        }
        Commands::Unmount {
            mountpoint,
            volume,
            passphrase,
            name,
        } => {
            // Read the mount marker.
            let marker_path = mountpoint.join(".soteria-mount.json");
            anyhow::ensure!(
                marker_path.exists(),
                "No .soteria-mount.json found in {mountpoint:?}. Is this a mounted Soteria volume?"
            );
            let marker: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&marker_path)?)?;

            let output_path = PathBuf::from(
                marker["output"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid mount marker"))?,
            );

            // Read the (possibly modified) plaintext.
            let plaintext = std::fs::read(&output_path)?;

            // Re-encrypt to the volume.
            let volume_path = backing_path_for(&volume, &name);
            let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(&volume_path);
            let kdf_file = soteria_core::fs_layer::kdf::VolumeKeyFile::load(&kdf_path)?;
            let key =
                soteria_core::fs_layer::kdf::derive_volume_key(passphrase.as_bytes(), &kdf_file)?;

            let file_id = {
                let mut material = b"soteria-fs-file-id-v1".to_vec();
                material.extend_from_slice(name.as_bytes());
                let mut h = [0u8; 32];
                h.copy_from_slice(blake3::hash(&material).as_bytes());
                h
            };
            let on_disk = soteria_core::fs_layer::storage::encrypt_to_disk(
                file_id,
                soteria_core::crypto_engine::AeadAlgorithm::XChaCha20Poly1305,
                *key,
                65536,
                &plaintext,
            )?;
            on_disk.save(&volume_path)?;

            // Clean up the mountpoint.
            std::fs::remove_file(&output_path)?;
            std::fs::remove_file(&marker_path)?;

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "action": "unmounted",
                    "volume": volume,
                    "size": plaintext.len(),
                }))?
            );
        }
        Commands::Encrypt {
            src,
            into,
            name,
            passphrase,
            algorithm,
            block_size,
            fast_kdf,
            paranoid,
        } => {
            let pw = match passphrase {
                Some(p) => p,
                None => read_passphrase("Enter passphrase: ")?,
            };
            let plaintext = std::fs::read(&src)?;
            std::fs::create_dir_all(&into)?;
            let path = backing_path_for(&into, &name);
            let params = if fast_kdf {
                KdfParams::fast_test()
            } else if paranoid {
                KdfParams::paranoid()
            } else {
                KdfParams::production()
            };
            let vol = encrypt_to_disk_with_passphrase(
                &path,
                algorithm.clone().into(),
                params,
                block_size,
                pw.as_bytes(),
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
            #[cfg(not(feature = "tui"))]
            {
                anyhow::bail!("built without TUI support; rebuild with --features tui");
            }
            #[cfg(feature = "tui")]
            {
                let bus = std::sync::Arc::new(soteria_core::event_bus::bus::EventBus::new());
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
        Commands::Fde(sub) => match sub {
            FdeCommands::Init {
                device,
                size,
                sector_size,
                kdf,
                tpm_seal,
                anti_forensic,
                shares,
                threshold,
            } => {
                use soteria_core::fde::shamir::split_secret;
                use soteria_core::fde::volume::{
                    format_volume, FEATURE_ANTI_FORENSIC, FEATURE_HIDDEN, FEATURE_TPM_SEALED,
                };
                use soteria_core::fde::{BlockDevice, FileBackedDevice};
                use soteria_core::fs_layer::kdf::KdfParams;

                let pw = read_passphrase("Enter FDE passphrase: ")?;
                let pw_confirm = rpassword::prompt_password("Confirm passphrase: ")?;
                anyhow::ensure!(pw == pw_confirm, "passphrases do not match");

                let mut feature_flags: u64 = 0;
                if tpm_seal {
                    feature_flags |= FEATURE_TPM_SEALED;
                }
                if anti_forensic {
                    feature_flags |= FEATURE_ANTI_FORENSIC;
                }

                let kdf_params: KdfParams = kdf.clone().into();
                let path = device.clone();

                // If size is given, create a container file. Otherwise
                // open the existing path as a block device (real disk
                // or pre-allocated file).
                let dev = if let Some(total_size) = size {
                    FileBackedDevice::create(&path, sector_size, total_size)?
                } else {
                    FileBackedDevice::open(&path, sector_size)?
                };
                let vol = format_volume(dev, kdf_params, pw.as_bytes(), feature_flags)?;

                if anti_forensic {
                    let n = shares
                        .ok_or_else(|| anyhow::anyhow!("--shares required with --anti-forensic"))?;
                    let k = threshold.ok_or_else(|| {
                        anyhow::anyhow!("--threshold required with --anti-forensic")
                    })?;
                    anyhow::ensure!(
                        (2..=255).contains(&k) && k <= n,
                        "threshold K must be 2..=N"
                    );
                    // Derive the master key the same way `format_volume` did.
                    use soteria_core::crypto_engine::kdf::argon2id_root_from_password;
                    let master = argon2id_root_from_password(
                        pw.as_bytes(),
                        &vol.header.kdf_salt,
                        kdf_params.m_cost,
                        kdf_params.t_cost,
                    )?;
                    let mut master_arr = [0u8; 32];
                    master_arr.copy_from_slice(master.as_ref());
                    let shares_out = split_secret(&master_arr, k, n)?;
                    let share_dir = path.with_extension("shares");
                    std::fs::create_dir_all(&share_dir)?;
                    for s in &shares_out {
                        let share_path = share_dir.join(format!("share-{:03}.sot", s.index));
                        std::fs::write(&share_path, hex::encode(s.to_bytes()))?;
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "action": "fde_init",
                            "device": path,
                            "uuid": vol.header.volume_uuid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            "total_sectors": vol.header.total_sectors,
                            "kdf_m_cost_kib": vol.header.argon2_m_cost,
                            "kdf_t_cost": vol.header.argon2_t_cost,
                            "kdf_p": vol.header.argon2_p,
                            "feature_flags": vol.header.feature_flags,
                            "anti_forensic": anti_forensic,
                            "shares_dir": share_dir,
                            "shares_written": shares_out.len(),
                        }))?
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "ok": true,
                            "action": "fde_init",
                            "device": path,
                            "uuid": vol.header.volume_uuid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            "total_sectors": vol.header.total_sectors,
                            "kdf_m_cost_kib": vol.header.argon2_m_cost,
                            "kdf_t_cost": vol.header.argon2_t_cost,
                            "kdf_p": vol.header.argon2_p,
                            "feature_flags": vol.header.feature_flags,
                        }))?
                    );
                }
            }
            FdeCommands::Verify { device } => {
                use soteria_core::fde::volume::open_volume;
                use soteria_core::fde::FileBackedDevice;
                let path = device.clone();
                let pw = read_passphrase("Passphrase: ")?;
                let dev = FileBackedDevice::open(&path, 512)?;
                let vol = open_volume(dev, pw.as_bytes())?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "device": path,
                        "uuid": vol.header.volume_uuid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "total_sectors": vol.header.total_sectors,
                    }))?
                );
            }
            FdeCommands::Status { device } => {
                use soteria_core::fde::volume::{
                    VolumeHeader, FEATURE_ANTI_FORENSIC, FEATURE_HIDDEN, FEATURE_TPM_SEALED,
                };
                use soteria_core::fde::{BlockDevice, FileBackedDevice};
                // Read the primary header WITHOUT deriving the key.
                // The header is plaintext (magic, version, salt, params,
                // XTS-key-check) so we can show its fields.
                let path = device.clone();
                let dev = FileBackedDevice::open(&path, 512)?;
                // Read 4096 bytes of header.
                let mut hdr = vec![0u8; 4096];
                for i in 0..8u64 {
                    let mut chunk = vec![0u8; 512];
                    dev.read_sector(i, &mut chunk)
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    hdr[i as usize * 512..(i as usize + 1) * 512].copy_from_slice(&chunk);
                }
                let hdr_arr: [u8; 4096] = hdr.try_into().unwrap();
                let parsed = VolumeHeader::from_bytes(&hdr_arr)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "device": path,
                        "magic": "SOTERIA",
                        "version": parsed.version,
                        "sector_size": parsed.sector_size,
                        "total_sectors": parsed.total_sectors,
                        "kdf_m_cost": parsed.argon2_m_cost,
                        "kdf_t_cost": parsed.argon2_t_cost,
                        "kdf_p": parsed.argon2_p,
                        "uuid": parsed.volume_uuid.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "is_hidden": parsed.is_hidden,
                        "feature_flags": parsed.feature_flags,
                        "feature_flags_decoded": {
                            "anti_forensic": parsed.feature_flags & FEATURE_ANTI_FORENSIC != 0,
                            "tpm_sealed": parsed.feature_flags & FEATURE_TPM_SEALED != 0,
                            "hidden": parsed.feature_flags & FEATURE_HIDDEN != 0,
                        },
                    }))?
                );
            }
            FdeCommands::SplitKey {
                device,
                out,
                threshold,
                shares,
            } => {
                use soteria_core::crypto_engine::kdf::argon2id_root_from_password;
                use soteria_core::fde::shamir::split_secret;
                use soteria_core::fde::{open_volume, FileBackedDevice};
                use soteria_core::fs_layer::kdf::KdfParams;

                let pw = read_passphrase("Outer passphrase: ")?;
                let path = device.clone();
                let dev = FileBackedDevice::open(&path, 512)?;
                let vol = open_volume(dev, pw.as_bytes())?;
                let kdf = KdfParams {
                    m_cost: vol.header.argon2_m_cost,
                    t_cost: vol.header.argon2_t_cost,
                    p_cost: vol.header.argon2_p as u32,
                };
                let master = argon2id_root_from_password(
                    pw.as_bytes(),
                    &vol.header.kdf_salt,
                    kdf.m_cost,
                    kdf.t_cost,
                )?;
                let mut master_arr = [0u8; 32];
                master_arr.copy_from_slice(master.as_ref());
                let shares_out = split_secret(&master_arr, threshold, shares)?;
                std::fs::create_dir_all(&out)?;
                for s in &shares_out {
                    let share_path = out.join(format!("share-{:03}.sot", s.index));
                    std::fs::write(&share_path, hex::encode(s.to_bytes()))?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "split_key",
                        "device": path,
                        "shares_dir": out,
                        "threshold": threshold,
                        "total_shares": shares,
                        "shares_written": shares_out.len(),
                    }))?
                );
            }
            FdeCommands::RecoverKey { shares, out } => {
                use soteria_core::fde::shamir::{combine_shares, Share};
                let mut loaded = Vec::new();
                for path in &shares {
                    let hex_str = std::fs::read_to_string(path)?;
                    let bytes = hex::decode(hex_str.trim())?;
                    anyhow::ensure!(
                        bytes.len() == 33,
                        "share file must be 33 bytes hex-encoded (got {})",
                        bytes.len()
                    );
                    let arr: [u8; 33] = bytes.try_into().unwrap();
                    loaded.push(Share::from_bytes(&arr)?);
                }
                let master = combine_shares(&loaded)?;
                std::fs::write(&out, master)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "recover_key",
                        "out": out,
                        "shares_used": loaded.len(),
                    }))?
                );
            }
            FdeCommands::HiddenCreate { device, kdf } => {
                use soteria_core::fde::hidden::create_hidden_volume;
                use soteria_core::fs_layer::kdf::KdfParams;
                let outer_pw = read_passphrase("Outer passphrase: ")?;
                let hidden_pw = read_passphrase("Hidden passphrase: ")?;
                let hidden_pw_confirm = rpassword::prompt_password("Confirm hidden passphrase: ")?;
                anyhow::ensure!(
                    hidden_pw == hidden_pw_confirm,
                    "hidden passphrases do not match"
                );
                let path = device.clone();
                let sector_size = 512;
                let total_size = std::fs::metadata(&path)?.len();
                let total_sectors = total_size / sector_size as u64;
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)?;
                let hidden = create_hidden_volume(
                    &mut file,
                    outer_pw.as_bytes(),
                    hidden_pw.as_bytes(),
                    sector_size,
                    total_sectors,
                    kdf.clone().into(),
                )?;
                let _ = hidden; // suppress unused warning
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "hidden_create",
                        "device": path,
                        "kdf": format!("{:?}", kdf),
                    }))?
                );
            }
            FdeCommands::HwErase { device, crypto } => {
                let path = device.clone();
                let path_str = path.to_string_lossy().to_string();
                if path_str.starts_with("/dev/nvme") {
                    let r = soteria_core::fde::secure_erase_nvme(&path, crypto)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::to_value(&r)?)?
                    );
                } else if path_str.starts_with("/dev/sd") || path_str.starts_with("/dev/hd") {
                    let pw = read_passphrase("Temporary ATA password (will be set then erased): ")?;
                    let r = soteria_core::fde::secure_erase_ata(&path, &pw)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::to_value(&r)?)?
                    );
                } else {
                    anyhow::bail!("HwErase requires a /dev/sdX, /dev/hdX, or /dev/nvmeXn1 path. For files, use the `shred` subcommand.");
                }
            }
            FdeCommands::PbaConfig { out } => {
                use soteria_core::fde::pba::{AuthMode, PbaConfig};
                let cfg = PbaConfig {
                    os_volume: "/dev/sda2".to_string(),
                    kdf_m_cost_kib: 1 << 16,
                    kdf_t_cost: 3,
                    kdf_p: 1,
                    auth_mode: AuthMode::TpmAndPassphrase,
                    pcrs: vec![0, 2, 4, 7],
                    locale: "en-US".to_string(),
                    max_failed_attempts: 10,
                    banner: Some(
                        "SOTERIA PRE-BOOT AUTHENTICATION\nAuthorized access only. \
                         All access is logged."
                            .to_string(),
                    ),
                    chain_load: "/EFI/systemd/systemd-bootx64.efi".to_string(),
                };
                cfg.validate()?;
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&out, cfg.to_toml()?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "action": "pba_config",
                        "out": out,
                    }))?
                );
            }
        },
        #[cfg(feature = "omega")]
        Commands::Omega(sub) => match sub {
            OmegaCommands::Classify { label } => {
                use soteria_core::omega::classification::Classification;
                let parsed = match label.to_lowercase().as_str() {
                    "u" | "unclassified" => Some(Classification::Unclassified),
                    "cui" => Some(Classification::Cui),
                    "c" | "confidential" => Some(Classification::Confidential),
                    "s" | "secret" => Some(Classification::Secret),
                    "ts" | "topsecret" | "top_secret" => Some(Classification::TopSecret),
                    "ts//sci" | "sci" => Some(Classification::TopSecretSci),
                    "cts" | "cosmic" => Some(Classification::CosmicTopSecret),
                    _ => None,
                };
                match parsed {
                    Some(c) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "label": c.label(),
                                "level": c.level(),
                                "minimum_key_bits": c.minimum_key_bits(),
                                "requires_post_quantum": c.requires_post_quantum(),
                                "requires_dual_cipher": c.requires_dual_cipher(),
                                "requires_air_gapped_keys": c.requires_air_gapped_keys(),
                            }))?
                        );
                    }
                    None => {
                        eprintln!("unknown classification: {label}");
                        eprintln!("known: u, cui, c, s, ts, ts//sci, cts");
                        std::process::exit(2);
                    }
                }
            }
            OmegaCommands::Ironclad => {
                use soteria_core::omega::ironclad_table;
                println!("{}", ironclad_table());
            }
            OmegaCommands::TpmSeal { key_file, pcrs } => {
                use soteria_core::omega::hardware::TpmManager;
                let key_bytes = std::fs::read(&key_file)?;
                anyhow::ensure!(
                    key_bytes.len() == 32,
                    "key file must be 32 raw bytes (got {})",
                    key_bytes.len()
                );
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                let pcr_indices: Vec<u32> = pcrs
                    .split(',')
                    .map(|s| s.trim().parse::<u32>().map_err(anyhow::Error::from))
                    .collect::<anyhow::Result<Vec<u32>>>()?;
                let tpm = TpmManager::new();
                let blob = tpm.seal(&key, &pcr_indices)?;
                let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "sealed_blob_hex": hex,
                        "sealed_blob_len": blob.len(),
                        "pcrs": pcr_indices,
                        "tpm_status": tpm.status.label(),
                    }))?
                );
            }
            OmegaCommands::TpmUnseal { blob, out } => {
                use soteria_core::omega::hardware::TpmManager;
                let hex = std::fs::read_to_string(&blob)?;
                let blob_bytes = hex_decode(hex.trim())?;
                let tpm = TpmManager::new();
                let key = tpm.unseal(&blob_bytes)?;
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&out, key)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "out": out,
                        "tpm_status": tpm.status.label(),
                    }))?
                );
            }
            OmegaCommands::SetMode { mode } => {
                use soteria_core::omega::sovereignty::{
                    AirGapEnforcer, AirGapMode, SovereigntyConfig,
                };
                let m = AirGapMode::from_label(&mode).ok_or_else(|| {
                    anyhow::anyhow!("unknown mode: {mode} (use connected, intranet, air-gap)")
                })?;
                let cfg = match m {
                    AirGapMode::Connected => SovereigntyConfig::default(),
                    AirGapMode::Intranet | AirGapMode::AirGap => SovereigntyConfig::air_gap(),
                };
                let e = AirGapEnforcer::new(cfg);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "mode": e.config().mode.label(),
                        "disable_ntp": e.config().disable_ntp,
                        "disable_telemetry": e.config().disable_telemetry,
                        "disable_remote_attestation": e.config().disable_remote_attestation,
                    }))?
                );
            }
            OmegaCommands::Panic { level, reason } => {
                use soteria_core::omega::emergency::{
                    EmergencyController, TriggerSource, ZeroizeLevel,
                };
                use std::time::{SystemTime, UNIX_EPOCH};
                let lvl = ZeroizeLevel::from_u8(level).ok_or_else(|| {
                    anyhow::anyhow!("invalid level: {level} (use 1=panic, 2=duress, 3=coldwar)")
                })?;
                let c = EmergencyController::new();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let report = c.trigger(
                    lvl,
                    TriggerSource::Operator {
                        operator_id: [0u8; 32],
                    },
                    reason,
                );
                let _ = now;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "report_id_hex": report.report_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "level": report.level.as_str(),
                        "ram_keys_wiped": report.ram_keys_wiped,
                        "secure_boxes_wiped": report.secure_boxes_wiped,
                        "sessions_terminated": report.sessions_terminated,
                        "volume_headers_zeroed": report.volume_headers_zeroed,
                        "tpm_seals_destroyed": report.tpm_seals_destroyed,
                        "lockout_until_ms": report.operator_lockout_until_ms,
                    }))?
                );
            }
            OmegaCommands::Entropy { file } => {
                use soteria_core::omega::defense::shannon_entropy;
                let data = std::fs::read(&file)?;
                let h = shannon_entropy(&data);
                let verdict = if h >= 7.5 {
                    "high (encrypted/compressed/ransomware)"
                } else if h >= 5.0 {
                    "medium"
                } else {
                    "low"
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "file": file,
                        "size_bytes": data.len(),
                        "shannon_entropy_bits_per_byte": h,
                        "verdict": verdict,
                    }))?
                );
            }
            OmegaCommands::IntegrityBuild { dir, out } => {
                use blake3::Hash;
                use soteria_core::omega::integrity::{IntegritySystem, MerkleTree};
                let mut entries: Vec<(String, Hash)> = Vec::new();
                for entry in std::fs::read_dir(&dir)? {
                    let entry = entry?;
                    let p = entry.path();
                    if p.is_file() {
                        let data = std::fs::read(&p)?;
                        let h = blake3::hash(&data);
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(h.as_bytes());
                        let h: Hash = blake3::Hash::from(<[u8; 32]>::from(arr));
                        entries.push((p.display().to_string(), h));
                    }
                }
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                let hashes: Vec<Hash> = entries.iter().map(|(_, h)| *h).collect();
                let tree = MerkleTree::build(&hashes);
                let sys = IntegritySystem::build(&hashes)?;
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let payload = serde_json::json!({
                    "block_count": sys.block_count,
                    "root_hex": tree.root().map(|h| h.to_hex().to_string()).unwrap_or_default(),
                    "stripes": sys.stripes.len(),
                    "files": entries.iter().map(|(p, h)| serde_json::json!({
                        "path": p,
                        "blake3_hex": h.to_hex().to_string(),
                    })).collect::<Vec<_>>(),
                });
                std::fs::write(&out, serde_json::to_vec_pretty(&payload)?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "out": out,
                        "block_count": sys.block_count,
                        "root_hex": tree.root().map(|h| h.to_hex().to_string()).unwrap_or_default(),
                    }))?
                );
            }
            OmegaCommands::IntegrityVerify { integrity } => {
                use soteria_core::omega::integrity::IntegritySystem;
                let raw = std::fs::read_to_string(&integrity)?;
                let payload: serde_json::Value = serde_json::from_str(&raw)?;
                let block_count = payload["block_count"].as_u64().unwrap_or(0);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "integrity": integrity,
                        "block_count": block_count,
                        "root_hex": payload["root_hex"],
                        "note": "use --features omega tests for full RS verification",
                    }))?
                );
            }
        },
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

#[cfg(feature = "omega")]
#[derive(Subcommand, Debug)]
enum OmegaCommands {
    /// Display a classification's level, label, and policy requirements.
    Classify {
        /// Classification label (e.g., "TopSecret", "Secret", "Unclassified").
        label: String,
    },
    /// Print the IRONCLAD mechanism summary (50-row table of
    /// classified-by-part defense mechanisms). See
    /// docs/SOTERIA-OMEGA-ARCHITECTURE.md.
    Ironclad,
    /// TPM 2.0 seal: encrypt a 32-byte key against the current PCR state.
    TpmSeal {
        /// 32-byte raw key file.
        #[arg(long)]
        key_file: PathBuf,
        /// Comma-separated PCR indices (e.g. "0,2,4,7").
        #[arg(long, default_value = "0,7")]
        pcrs: String,
    },
    /// TPM 2.0 unseal: recover a 32-byte key from a sealed blob.
    TpmUnseal {
        /// File containing the sealed blob.
        #[arg(long)]
        blob: PathBuf,
        /// Where to write the recovered 32 raw bytes.
        #[arg(long)]
        out: PathBuf,
    },
    /// Set the air-gap / sovereignty mode.
    SetMode {
        /// One of: connected, intranet, air-gap.
        mode: String,
    },
    /// Trigger an emergency zeroization.
    Panic {
        /// 1=PanicButton, 2=Duress, 3=ColdWar.
        #[arg(long, default_value_t = 1)]
        level: u8,
        /// Free-form reason for the audit log.
        #[arg(long, default_value = "manual")]
        reason: String,
    },
    /// Compute the Shannon entropy of a file (anti-ransomware
    /// diagnostic).
    Entropy {
        #[arg(long)]
        file: PathBuf,
    },
    /// Build the integrity system for a directory of files. Hashes
    /// every file with BLAKE3, builds a Merkle tree, and emits an
    /// RS-encoded root.
    IntegrityBuild {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a previously-emitted integrity system.
    IntegrityVerify {
        #[arg(long)]
        integrity: PathBuf,
    },
}
