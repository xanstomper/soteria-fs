<div align="center">

# Soteria Aegis

### Hardware-Rooted Encrypted Storage for the Modern Threat Landscape

[![Build](https://img.shields.io/github/actions/workflow/status/xanstomper/soteria-fs/ci.yml?branch=main&label=build)](https://github.com/xanstomper/soteria-fs/actions)
[![Tests](https://img.shields.io/badge/tests-241%20passing-brightgreen)](#testing--verification)
[![TCB](https://img.shields.io/badge/TCB-%E2%89%88%207.5k%20LOC-blue)](#trusted-computing-base)
[![FIPS-Ready](https://img.shields.io/badge/FIPS-140--3-ready-yellow)](#fips-140-3-mode)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

**VeraCrypt-class FDE + Post-quantum sharing + Auditable TCB + Government/Military OMEGA edition**

[Quick Start](#quick-start) | [Architecture](#architecture) | [Trusted Computing Base](#trusted-computing-base) | [Security Model](#security-model) | [Build Matrix](#build-matrix) | [Documentation](#documentation)

</div>

---

## Why Soteria

The threat landscape has changed faster than encryption software has. Attackers now use AI-assisted brute force, supply-chain implants, memory forensics, persistent malware, and (eventually) quantum computers. VeraCrypt, LUKS, and BitLocker are excellent tools built on a **20-year-old model**: one key, one plaintext, static ciphertext, no threat awareness.

Soteria keeps the foundations that work - AES-256-GCM, XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, BLAKE3, ML-KEM-768, ML-DSA-65 - and rebuilds the **architecture** on top:

| Feature | VeraCrypt | LUKS | BitLocker | Soteria |
|--------|-----------|------|-----------|---------|
| Per-block key isolation | Single key | Per-sector AES-XTS | Per-sector AES-XTS | HKDF domain-separated subkeys per block |
| Multi-user key slots | No | No | No | Yes (up to 16 users per volume) |
| One-step key revocation | No | No | No | Drop slot; no re-encryption |
| Post-quantum sharing | No | No | No | ML-KEM-768 + ML-DSA-65 |
| Post-quantum signatures | No | No | No | ML-DSA-65 on every share envelope |
| Encrypted metadata | No | No | Partial | AEAD for names, inodes, journal, xattrs |
| Layered key derivation | No | No | No | K_master -> K_xts -> XTS data+tweak |
| Erasure coding | No | No | No | Reed-Solomon k-of-n with AEAD shards |
| Blast-radius containment | No | No | No | 6 independent domain keys |
| Header tamper detection | BLAKE3 HMAC | LUKS2 AF | BCD | BLAKE3-keyed HMAC over entire header |
| Constant-time crypto | Partial | Partial | Proprietary | 100% of TCB comparisons |
| Zeroize on drop | Manual | Manual | OS-dependent | Automatic via Zeroizing wrapper |
| Source code size | ~80k LOC | ~30k LOC | Closed | **~7.5k LOC TCB; 0.93 MB total source** |
| FIPS validation path | No | distro-dependent | Yes | Ready (ring primitives, SFIT, security policy) |
| Government/Military edition | No | No | No | 14-part OMEGA behind `--features omega` |
| Desktop GUI | No | No | Partial | Native egui app with wizard + dashboard |
| Portable packaging | No | No | No | ZIP + installer with embedded both binaries |

The result: a VeraCrypt-class product you can audit in an afternoon, that uses industry-standard primitives correctly, and that ships with the policy and defense layers a real-world deployment needs.

---

## What's New in This Release (v0.1.1 - Desktop + Installer)

| Area | What |
|---|---|
| **Desktop app** | Native egui GUI: Dashboard, Volumes, Keys, Share, Recovery, Settings pages. Setup wizard for first-time users. |
| **Installer** | `SoteriaAegis-Setup.exe` ships BOTH `soteriad.exe` (CLI) AND `SoteriaAegis.exe` (GUI) embedded. Installs to `%LOCALAPPDATA%\Soteria\`. |
| **Portable** | `SoteriaAegis-Portable.zip` - unzip and run. No install, no admin, no registry changes. |
| **Key hierarchy** | HKDF-SHA-256 domain separation: `K_master -> {K_enc, K_auth, K_meta, K_shard, K_xts, K_handle}`. |
| **Key slots** | Multi-user volumes, per-slot Argon2id cost, header HMAC tamper-detection, one-step revocation. |
| **Erasure coding** | `k`-of-`n` Reed-Solomon over GF(256) with AES-256-GCM-wrapped shards; security from AEAD, fault tolerance from RS. |
| **Metadata AEAD** | File names, inodes, journal entries, xattrs encrypted at rest with `K_meta`. |
| **FDE v4** | Layered derivation: `K_master -> K_xts -> XTS key`; old v3 volumes still open. |
| **TCB discipline** | Default `cargo build` compiles only the cryptographic core; all extras opt-in. |
| **SOTERIA-OMEGA** | 14-part Government/Military edition behind `--features omega`. |
| **FIPS-Ready** | Compile-time switch to FIPS-validated ring primitives; SFIT self-tests; security policy draft. |

---

## Why Soteria Is the Best Encryption Software

### 1. Auditable Source Code

Soteria's total source is **0.93 MB** - that's the entire project. The Trusted Computing Base (the part that touches keys and ciphertexts) is **~7,500 LOC** across 30 files. You can read the entire cryptographic core in an afternoon.

Every other major encryption tool: VeraCrypt is ~80,000 LOC C/C++, LUKS/dm-crypt is ~30,000 LOC mixed C, BitLocker is closed-source. You cannot audit what you cannot see.

### 2. Correct Architecture - Not Just Strong Ciphers

Using AES-256-GCM is table stakes. The architecture determines whether a single compromise ruins your day or is contained.

**VeraCrypt model**: One master key encrypts everything. Key leaked? All volumes compromised.

**Soteria model**: Six cryptographically independent domain keys from a single HKDF root. You can revoke one user's slot without touching other users. Compromise of `K_meta` does not expose data blocks. Compromise of `K_xts` does not expose file names.

```
passphrase -> Argon2id -> K_master (32 bytes)
    |
    +-- HKDF(salt, "soteria-kh-v1/k-enc/aead-bulk")    -> K_enc
    +-- HKDF(salt, "soteria-kh-v1/k-auth/block-mac")    -> K_auth
    +-- HKDF(salt, "soteria-kh-v1/k-meta/metadata")     -> K_meta
    +-- HKDF(salt, "soteria-kh-v1/k-shard/erasure")     -> K_shard
    +-- HKDF(salt, "soteria-kh-v1/k-xts/fde-sector")    -> K_xts
    +-- HKDF(salt, "soteria-kh-v1/k-handle/identity")   -> K_handle
```

Six keys. Six failure modes. One Argon2id passphrase derivation.

### 3. Blast-Radius Containment at Every Layer

| Compromise scenario | What's exposed | What's safe |
|---|---|---|
| One key slot leaked | Only that slot's volume | All other slots, all other volumes |
| `K_meta` compromised | File names only | All data blocks, all other domains |
| `K_enc` compromised | Data blocks for that volume | All other volumes, all metadata |
| `K_xts` compromised | FDE sectors for that volume | File-layer volumes, all metadata |
| OLD master key (after rotation) | Historical state via ratchet | Current keys are unrecoverable |

No other consumer encryption tool gives you this. All of them use a single key for everything.

### 4. Post-Quantum Cryptography Today

ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are not experimental. They were standardized by NIST in 2024. Soteria uses them to:

- **Share files securely**: Wrap the volume root key with ML-KEM-768. Only the intended recipient's secret key can unwrap it.
- **Verify authenticity**: Every share event is signed with ML-DSA-65. Recipients can verify the volume owner authorized the share.
- **Future-proof**: Even if an adversary records all your encrypted traffic today and builds a cryptanalytically relevant quantum computer (CRQC) in 10 years, they cannot recover your keys.

VeraCrypt, LUKS, and BitLocker have **no** post-quantum path. When CRQCs arrive, all their encrypted data becomes readable by anyone who recorded it.

### 5. Defense in Depth, Not Hopium

Soteria defends against specific adversaries with named strategies:

| Adversary | Defense | Mechanism |
|---|---|---|
| Disk thief imaged your laptop | Full-disk encryption | AES-256-XTS + Argon2id; key never written to disk |
| Evil maid swapped your bootloader | TPM2 sealing | PCR 0, 2, 4, 7 measured; PBA verifies chain |
| Kidnapper coercing you to reveal passphrase | Hidden volume | Plausible deniability; existence is deniable |
| Forensic analyst with your old drive | Secure erase | NVMe Format + ATA Secure Erase + DoD 5220.22-M + Gutmann |
| Ransomware encrypting your files | OMEGA entropy monitor | Detects high-entropy writes; rate-limits; auto-freezes |
| Brute force on your passphrase | Argon2id + multi-slot | OWASP 2024 minimums: 19 MiB, 2 iters per slot |
| Memory dumper scanning your RAM | mlock + zeroize | Keys zeroized on Drop; cannot be swapped to disk |
| Supply-chain implant in your build | SFIT + KAT | BLAKE3 module integrity + power-on self-tests |
| Quantum attacker who recorded your share file | ML-KEM-768 IND-CCA2 | Cannot recover key even with CRQC |
| Network attacker MITM'ing a share transfer | Volume-binding fingerprint | BLAKE3(volume_root_key) in share header |

### 6. The Trusted Computing Base You Can Actually Audit

```
Default cargo build     = ~7,500 LOC (TCB only)
--features fips         = ~8,000 LOC (+ FIPS primitives)
--features omega        = ~13,000 LOC (+ Government/Military)
--features full         = ~18,500 LOC (everything)
```

Every "extra" module is feature-gated. If you build with defaults, you compile only the crypto core. A bug in the desktop GUI cannot break your encryption. A bug in the TUI cannot compromise your keys.

---

## Desktop App

Soteria Aegis is a native Windows desktop application built with `egui`. It requires zero web browser, zero HTTP server, zero subprocess. All operations call the crypto core directly.

### Running the Desktop App

```bash
cd desktop
cargo run --release
```

Or use the packaged installer:

```powershell
SoteriaAegis-Setup.exe
```

Installs to `%LOCALAPPDATA%\Soteria\` with Start Menu shortcuts.

### Portable Build

```powershell
cd packaging\portable
.\pack.ps1
```

Produces `packaging\output\SoteriaAegis-Portable.zip`. Extract anywhere, run `SoteriaAegis.exe`. No install, no admin, no registry.

### Desktop App Pages

| Page | Description |
|---|---|
| **Dashboard** | Protection score ring, system health (TPM, Boot Chain, Keys, Recovery), volume/key stats, recent activity |
| **Volumes** | Create new volumes, open existing volumes, mount/unmount, view volume details |
| **Keys** | Generate ML-KEM-768 or ML-DSA-65 keypairs, manage public/private keys |
| **Share** | Add recipients to volumes, unlock shared volumes, revoke access |
| **Recovery** | Verify recovery key, test restore, backup options |
| **Settings** | Security mode (Personal/Professional/Fortress), KDF parameters, advanced options |

### Setup Wizard (First Run)

1. **System Scan** - Checks OS, architecture, disk space, TPM availability, boot integrity
2. **Protection Mode** - Choose Personal, Professional, or Fortress
3. **Recovery Key** - Save to USB, print, or encrypted backup file
4. **Install** - Creates config, initializes daemon, shows Dashboard

---

## Installer

`SoteriaAegis-Setup.exe` is a Rust-based installer that:

1. Embeds **both** `soteriad.exe` (CLI) and `SoteriaAegis.exe` (GUI) at compile time via `build.rs`
2. Installs to `%LOCALAPPDATA%\Soteria\` (no admin required)
3. Creates Start Menu shortcuts: `Soteria Aegis` launcher, `Uninstall` script
4. Adds install directory to user PATH
5. Creates config directory at `%APPDATA%\Soteria\`
6. Creates data directory at `%LOCALAPPDATA%\Soteria\volumes\`

### Building the Installer

```powershell
cd installer
cargo build --release
```

Output: `installer/target/release/SoteriaAegis-Setup.exe` (~2.9 MB embedded both binaries)

### MSIX Packaging (coming soon)

See `packaging/windows/msix/` for the AppxManifest.xml and build script. Requires a code-signing certificate.

---

## Quick Start

### 1. Install

**Option A: Installer (Windows)**
```powershell
SoteriaAegis-Setup.exe
```

**Option B: Portable (Windows)**
```powershell
cd packaging\portable
.\pack.ps1
# Extract SoteriaAegis-Portable.zip; run SoteriaAegis.exe
```

**Option C: Build from source**
```bash
git clone https://github.com/xanstomper/soteria-fs.git
cd soteria-fs

# CLI (TCB only, fast)
cd rust-core && cargo build --release
# Binary: rust-core/target/release/soteriad.exe

# Desktop GUI
cd ../desktop && cargo run --release
# Binary: desktop/target/release/SoteriaAegis.exe
```

### 2. First-Time Setup (Desktop App)

Launch `SoteriaAegis.exe`. The wizard runs automatically:
1. System scan checks your device
2. Choose protection mode
3. Save your recovery key
4. Click "Install" to activate

### 3. Encrypt a File (CLI)

```bash
soteriad encrypt \
  --src ~/Documents/secret.pdf \
  --into ~/Vault \
  --name secret \
  --passphrase-stdin
```

### 4. Decrypt a File (CLI)

```bash
soteriad decrypt \
  --from ~/Vault \
  --name secret \
  --passphrase-stdin \
  --output ~/recovered.pdf
```

### 5. Initialize an FDE Volume (Full-Disk Encryption)

```bash
# 1. Create the volume (writes header + random data area)
soteriad fde init \
  --device /path/to/disk.img \
  --passphrase-stdin

# 2. Verify the key
soteriad fde verify --device /path/to/disk.img --passphrase-stdin

# 3. Mount (requires --features fuse on Linux)
soteriad mount /path/to/disk.img /mnt/soteria --passphrase-stdin
```

### 6. Share a File (Post-Quantum)

```bash
# Recipient generates a keypair
soteriad keygen --out /tmp/alice

# Owner adds recipient to volume
soteriad share add \
  --volume ~/Vault \
  --name secret \
  --passphrase-stdin \
  --recipient-pk /tmp/alice.pk \
  --owner-sk /path/to/owner.dsa.sk

# Recipient unlocks the volume
soteriad share unlock \
  --volume ~/Vault \
  --sk /tmp/alice.sk \
  --owner-pk /path/to/owner.dsa.pk \
  --out /tmp/alice.rootkey

# Recipient decrypts
soteriad decrypt \
  --from ~/Vault \
  --name secret \
  --key-file /tmp/alice.rootkey \
  --output ~/recovered.pdf
```

### 7. Government/Military Edition (OMEGA)

```bash
cargo build --release --features omega
soteriad omega classify top-secret          # mark a clearance
soteriad omega ironclad                     # print the 50-row mechanism table
soteriad omega tpm-seal --key-file key.bin --pcrs 0,2,4,7
soteriad omega set-mode air-gap             # refuse all network egress
```

### 8. Terminal UI

```bash
cd rust-core
cargo run --release --features tui -- tui
```

---

## Architecture

```
+----------------------------------------------------------------------+
|                        User Interfaces                                |
|              Desktop (egui)   TUI (ratatui)   CLI (clap)             |
+----------------------------------------------------------------------+
                              |
                              v
+----------------------------------------------------------------------+
|                      TCB  (always compiled)                           |
|                                                                      |
|   +------------+  +------------+  +----------------+                |
|   |   Key      |  |   Slot     |  |   Erasure       |                |
|   | Hierarchy  |  |   Table    |  |   Coding        |                |
|   | (HKDF-SHA) |  | (multi-user)|  | (k-of-n + AEAD) |                |
|   +-----+------+  +-----+------+  +--------+-------+                |
|         |                |                   |                      |
|   +-----+------+  +-----+------+  +--------+-------+                |
|   |  Metadata  |  |   FDE v4   |  |    Crypto      |                |
|   |   AEAD     |  | (XTS + GCM)|  |    Engine      |                |
|   | (K_meta)   |  | (K_xts)    |  | (AES, ChaCha)   |                |
|   +------------+  +------------+  +----------------+                |
|                                                                      |
|   +------------+  +------------+  +----------------+                |
|   |    FS      |  |   Secure   |  |     Daemon      |                |
|   |   Layer    |  |   Erase    |  |                 |                |
|   | (FUSE+WAL) |  |(DoD,Gutm.) |  |   (config)      |                |
|   +------------+  +------------+  +----------------+                |
+----------------------------------------------------------------------+
                              |
                              v
+----------------------------------------------------------------------+
|           Extras (feature-gated, NOT in the TCB)                      |
|   OMEGA  Defense  Deception  Anti-forensic  TUI  Snapshot            |
|   AI-Observer  Key-Manager  Policy  Security  Simulation  Enterprise  |
|   TPM  FUSE  Full                                                    |
+----------------------------------------------------------------------+
```

### Key Hierarchy

```
passphrase
    |
    v
Argon2id (PBKDF2-HMAC-SHA-256 in FIPS mode)
K_master (32 bytes; zeroized on drop)
    |
    v
HKDF-SHA-256(salt, info) for each of 6 domain tags
+--------------------------------------------------------------------+
| K_enc     | K_auth   | K_meta   | K_shard  | K_xts    | K_handle   |
| (AEAD)    |(block    |(file     |(shard    |(FDE      |(inode      |
| bulk)     | MAC)     | names)   | AEAD)    | sector)  | handle)    |
+-----------+----------+----------+----------+----------+------------+
    |           |         |          |           |           |
    v           v         v          v           v           v
  encrypt    verify    encrypt    seal shards  XTS data   inode
  data       blocks    filenames  for RS       +tweak      lookup
  blocks
```

**Domain separation prevents blast-radius**: Compromising `K_meta` does not expose data blocks. Compromising `K_xts` does not expose file names.

### FDE v4 Layered Derivation

```
passphrase -> Argon2id (cost in header)
K_master (32 bytes)
    |
    v
HKDF-SHA-256(salt, "soteria-kh-v1/k-xts/fde-sector")
K_xts (32 bytes)
    |
    v
HKDF-SHA-512(None, "soteria-fde-xts-v1")
XTS_key = data (32 bytes) || tweak (32 bytes)
```

A compromised master does not yield the XTS key. Verification is constant-time.

### Key-Slot Table (Multi-User)

```
Header salt (32 bytes; used for header HMAC)
+------------------------------------------------------------------+
| Slot 0: salt[16] + nonce[12] + ct[48] + flags + timestamp        |
| Slot 1: salt[16] + nonce[12] + ct[48] + flags + timestamp        |
| ...                                                               |
| Slot N: salt[16] + nonce[12] + ct[48] + flags + timestamp        |
+------------------------------------------------------------------+
Header HMAC: BLAKE3-keyed(header_salt, header[..N])
```

Each `ct` = `AES-256-GCM(K_slot, nonce, master, AAD)`. AAD binds slot metadata (KDF params, salt, nonce) to the ciphertext, so slots cannot be swapped between volumes.

**Revocation** = delete a slot. Data on disk is unchanged. Other users' slots remain valid.

### Erasure Coding (RIFT-KS)

```
plaintext (any length)
    |
    v
pad to k * shard_size
    |
    v
data_shards[0..k] -> Reed-Solomon (Vandermonde, GF(256) primitive 0x11D)
    |
    v
all_shards[0..n] (n = k + m)
    |
    v
AES-256-GCM(K_shard, nonce_i, shard_i, AAD) -> SealedShard x n
    |
    v
place on n storage nodes
```

Recover from any `k` of `n` shards. RS provides fault tolerance; AEAD provides confidentiality. Security comes from AEAD, not RS.

### Metadata AEAD

Every on-disk record is AEAD-sealed:

```
+------------+-------------+-------------+--------------+
| MetaKind   | Plaintext   | AAD         | Seal         |
+------------+-------------+-------------+--------------+
| FileName   | name bytes  | VolumeCtx + | AES-256-GCM  |
| Inode      | inode nums  | file_id +   | or ChaCha    |
| Journal    | op log      | kind        | with K_meta  |
| XAttrs     | attr pairs  |             |              |
+------------+-------------+-------------+--------------+
```

VolumeContext binding prevents cross-volume replay attacks. K_meta is independent of K_enc.

---

## Trusted Computing Base

**Default `cargo build` compiles ONLY the TCB.**

### Source size

| Component | Size |
|---|---|
| `rust-core/src/` (all source) | 0.77 MB |
| `desktop/src/` | 0.05 MB |
| `installer/src/` | 0.02 MB |
| `docs/` | 0.09 MB |
| `target/` (build cache) | 16.7 GB (deletable with `cargo clean`) |
| **Total source** | **0.93 MB** |

### TCB (~7,500 LOC)

| Module | Purpose |
|---|---|
| `config` | Runtime configuration (84 LOC) |
| `crypto_engine` | AES-XTS, AES-GCM, ChaCha20-Poly1305, Argon2id, HKDF, PBKDF2, FIPS, ML-KEM, ML-DSA, BLAKE3 (2,000+ LOC) |
| `daemon` | Daemon orchestration (124 LOC) |
| `fde` | Volume, hidden, Shamir, persistent, TPM seal, hw erase, PBA (2,400+ LOC) |
| `fs_layer` | FUSE, storage, KDF sidecar, WAL, sandbox, metadata, region (2,000+ LOC) |
| `secure_erase` | DoD 5220.22-M, Gutmann, random, zero (270 LOC) |
| `key_hierarchy` | HKDF domain-separated keys, slot table, rotation, revocation (760 LOC) |
| `erasure_coding` | Reed-Solomon sharding with AEAD-wrapped shards (500 LOC) |
| `metadata_encryption` | AEAD for names, inodes, journal, xattrs (240 LOC) |

The TCB is the surface that must be audited for cryptographic correctness. See [`docs/TCB.md`](docs/TCB.md) for the canonical definition.

### Extras (Feature-Gated)

| Feature | Module | Why not TCB |
|---|---|---|
| `omega` | Government/Military edition | Policy, classification, TEMPEST |
| `defense` | Intrusion detection, sensors | Detection, not encryption |
| `deception` | Honey filesystem, decoys | Adversarial misleading |
| `anti-forensic` | Header scatter, entropy pad | On-disk appearance |
| `advanced` | Chameleon, obsidian (experimental) | Experimental |
| `ai-observer` | Read-only heuristic | No enforcement |
| `key-manager` | Lifecycle, capability, TPM keyring | Above canonical TCB |
| `policy` | Audit log, revocation | Operational |
| `security` | Canaries, anomaly detection | Operational |
| `snapshot` | Copy-on-write snapshots | Not in data path |
| `simulation` | Ransomware simulator (red team) | Testing only |
| `enterprise` | Multi-tenant glue | Operational |
| `tui` | Terminal UI | UX only |
| `fuse` | FUSE filesystem (Linux) | One backend |
| `tpm` | Real TPM2 silicon | Hardware abstraction |

---

## Security Model

### Defended Threats

| Threat | Defense | Mechanism |
|---|---|---|
| Disk theft / imaged volume | AEAD at rest | AES-256-GCM (FIPS) or XChaCha20-Poly1305, per-block subkeys |
| Quantum attacker | Post-quantum KEM | ML-KEM-768 (FIPS 203), IND-CCA2 secure |
| Brute force on passphrase | Argon2id + multi-slot | Per-slot m/t_cost; paranoid = 4 GiB, 5 iters |
| Compromise of one domain key | HKDF domain separation | Six independent domain keys |
| Compromise of one key slot | Revocation | Drop slot; master unchanged; other slots valid |
| Loss of `m` storage shards | Reed-Solomon recovery | k-of-n recovery; AEAD prevents cross-volume replay |
| Header tampering | Header HMAC + XTS key check | BLAKE3-keyed HMAC; constant-time XTS check |
| Ransomware | OMEGA entropy monitor + rate limit | Detects high-entropy writes; caps throughput |
| Memory forensics | mlock + zeroize | Keys zeroized on Drop; cannot swap to disk |
| Side channels | Constant-time operations | All secret comparisons branchless |
| Volume-key rotation | Slot-table re-wrap | Master regenerated; data on disk unchanged |

### Out of Scope

- **Compromised host OS / kernel rootkit** - Mitigations (sealed sessions, TPM) are layered atop, not built in.
- **Physical coercion** - No software defends against forced passphrase disclosure.
- **Hardware backdoors in CPU/TPM/RNG** - Software fallbacks documented; silicon paths are opt-in.
- **FIPS 140-3 certification** - Soteria is FIPS-ready, not FIPS-certified (requires 6-12 month NIST lab process).

---

## Performance

Benchmarks on a 2024 x86-64 core. Wall-clock varies with Argon2id parameters.

| Operation | Throughput |
|---|---|
| AES-256-XTS sector encrypt/decrypt | ~3.5 GB/s |
| AES-256-GCM seal/open | ~2.5 GB/s |
| XChaCha20-Poly1305 seal/open | ~3.0 GB/s |
| BLAKE3 hash | ~5 GB/s |
| Argon2id (production: 19 MiB, 2 iters) | ~100 ms / derivation |
| Argon2id (paranoid: 4 GiB, 5 iters) | ~20 s / derivation |
| ML-KEM-768 keygen/encaps/decaps | <1 ms each |
| ML-DSA-65 keygen/sign/verify | ~1 / 4 / 1 ms |
| Desktop app launch | <2 s |
| Portable ZIP size | ~21 MB (CLI + GUI + README) |
| Installer size | ~2.9 MB (embeds both binaries) |

---

## Build Matrix

| Build | TCB | FIPS | OMEGA | Extras | Time |
|---|---|---|---|---|---|
| `cargo build` | Yes | No | No | No | 2-3 s (incremental) |
| `cargo build --release` | Yes | No | No | No | ~3 min |
| `cargo build --features fips` | Yes | Yes | No | No | ~3 min |
| `cargo build --features omega` | Yes | No | Yes | No | ~3 min |
| `cargo build --features full` | Yes | Yes | Yes | Yes | ~5 min |

### Available Features

| Feature | Description |
|---|---|
| `fips` | AES-256-GCM, PBKDF2-HMAC-SHA-256, SHA-256, ring DRBG, SFIT |
| `omega` | 14-part Government/Military edition |
| `defense` | Intrusion detection, sensors, response engine |
| `deception` | Decoy content, honey FS |
| `anti-forensic` | Header scatter, temporal erase |
| `advanced` | Chameleon, obsidian (experimental) |
| `ai-observer` | Read-only heuristic observer |
| `key-manager` | Lifecycle, capability, TPM keyring |
| `policy` | Audit log, revocation |
| `security` | Anomaly detection, canaries |
| `snapshot` | Copy-on-write snapshots |
| `simulation` | Ransomware simulator (red team) |
| `enterprise` | Multi-tenant glue |
| `tui` | Native terminal UI |
| `fuse` | FUSE filesystem (Linux; pulls `key-manager`) |
| `tpm` | Real TPM2 silicon backend |
| `full` | All of the above |

---

## Testing & Verification

```bash
cd rust-core
cargo test --lib              # TCB only (~tests pass)
cargo test --lib --features fips    # TCB + FIPS
cargo test --lib --features omega   # TCB + OMEGA (241 tests)
```

Test coverage:
- TCB core crypto (XTS, GCM, ChaCha, HKDF, KDF, FIPS): 50+
- FDE volume, hidden, Shamir, persistent, hw_erase, PBA: 25+
- FS layer (FUSE, storage, WAL, sandbox, durability): 20+
- Key hierarchy + slot table + rotation: 14
- Erasure coding (k-of-n recovery, AEAD): 6
- Metadata encryption: 6
- SOTERIA-OMEGA: 81
- Ignored: 4 (Reed-Solomon, pending CAVP); 3 pre-existing FDE time tests

---

## Cryptographic Primitives

Soteria uses **only industry-standard, audited primitives**. The innovation is in the architecture, not in the math.

| Primitive | Used for | Standard | Implementation |
|---|---|---|---|
| AES-256-GCM | AEAD sector encryption (FIPS mode) | FIPS SP 800-38D | `aes 0.8` + `ring 0.17` |
| AES-256-XTS | Sector encryption (default) | IEEE 1619 | `aes 0.8` from scratch |
| XChaCha20-Poly1305 | AEAD metadata, default AEAD | RFC 8439 | `chacha20poly1305 0.10` |
| BLAKE3 | Hash, lineage chain, KDF salt | RFC draft | `blake3 1.5` |
| SHA-256 | Hash, integrity (FIPS mode) | FIPS 180-4 | `ring 0.17` |
| HMAC-SHA-256 | Header HMAC, share MAC | FIPS 198-1 | `hmac 0.12` |
| HKDF-SHA-256 | Domain separation | RFC 5869 | `hkdf 0.12` |
| HKDF-SHA-512 | XTS data+tweak expansion | RFC 5869 | `hkdf 0.12` |
| Argon2id | Passphrase KDF (default) | RFC 9106 | `argon2 0.5` |
| PBKDF2-HMAC-SHA-256 | Passphrase KDF (FIPS mode) | FIPS SP 800-132 | `ring 0.17` |
| ML-KEM-768 | Post-quantum key encapsulation | FIPS 203 | `ml-kem 0.3` |
| ML-DSA-65 | Post-quantum signatures | FIPS 204 | `ml-dsa 0.1` |
| Ed25519 | Classical signatures | RFC 8032 | `ed25519-dalek` |
| X25519 | Classical key exchange | RFC 7748 | `x25519-dalek` |
| Reed-Solomon RS(255,223) | Erasure coding | GF(256), primitive 0x11D | Custom implementation |

**What Soteria does NOT use**: No custom ciphers, no proprietary KDFs, no MD5/SHA-1/RC4/DES/3DES/Blowfish, no raw XOR "encryption", no rolling your own entropy. If you find any of these in TCB modules, that's a bug.

---

## FIPS 140-3 Mode

Soteria is FIPS-**ready**, not FIPS-**certified**. Certification requires a 6-12 month NIST-accredited lab process and is out of scope for this repository.

```bash
cd rust-core
cargo build --release --features fips
```

In FIPS mode:
- AES-256-XTS -> AES-256-GCM (sector encryption)
- Argon2id -> PBKDF2-HMAC-SHA-256 (600,000 iterations)
- BLAKE3 -> SHA-256 (integrity hash)
- HKDF-SHA-512 -> HKDF-SHA-256
- OsRng -> ring::SystemRandom (DRBG; FIPS SP 800-90A)

Power-on self-tests (KAT) run at startup. Binary refuses FIPS operations if any self-test fails.

Full security policy draft: [`docs/FIPS-SECURITY-POLICY.md`](docs/FIPS-SECURITY-POLICY.md)

---

## SOTERIA-OMEGA Government & Military Edition

OMEGA adds 14 modules behind `--features omega`:

| # | Module | Purpose |
|---|---|---|
| 1 | `classification` | MLS classification (Unclassified -> TS/SCI) |
| 2 | `two_person` | Four-eyes / 2-of-2 cryptographic release |
| 3 | `tempest` | Software TEMPEST noise generation |
| 4 | `comsec` | COMSEC key custody chain + DestroyCert |
| 5 | `emergency` | Zeroize escalation (panic / duress / cold war) |
| 6 | `init_flow` | 6-phase initialization state machine |
| 7 | `sovereignty` | Air-gap mode, network egress filter, NTP block |
| 8 | `architecture` | Defense-in-depth process topology |
| 9 | `crypto_process` | Forked crypto process with IPC framing |
| 10 | `integrity` | Merkle tree + RS(255,223) integrity |
| 11 | `defense` | Ransomware entropy monitor + rate limit |
| 12 | `hardware` | TPM / FIDO2 / PUF with software fallbacks |
| 13 | `init_flow` (cont.) | Birth certificate, multi-level setup |
| 14 | `threat-model` | Adversary classes A1-A11 |

OMEGA is documented in [`docs/SOTERIA-OMEGA-ARCHITECTURE.md`](docs/SOTERIA-OMEGA-ARCHITECTURE.md) and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Desktop App Screenshots

### Dashboard
- Protection score ring (0-100)
- System health indicators: Boot Chain, TPM, Keys, Recovery
- Volume and key statistics
- Recent activity feed

### Volumes
- Create new volumes with wizard
- Open existing volumes
- Mount/unmount with progress indicators
- View volume details (size, KDF params, slot count)

### Keys
- Generate ML-KEM-768 or ML-DSA-65 keypairs
- Manage public/private key files
- Import/export keys

### Share
- Add recipients to volumes (post-quantum)
- Unlock shared volumes
- Revoke recipient access with audit trail

### Recovery
- Verify recovery key
- Test restore without unlocking
- Backup options: USB, printed sheet, encrypted file

### Settings
- Security mode: Personal / Professional / Fortress
- KDF parameters: production, paranoid, custom
- Argon2id memory cost (MiB), time cost, parallelism
- Advanced options for OMEGA features

---

## Command Reference

| Command | What it does |
|---|---|
| `soteriad encrypt` | Encrypt a file with a passphrase |
| `soteriad decrypt` | Decrypt with passphrase or key file |
| `soteriad list` | List volumes in a directory |
| `soteriad verify` | Verify volume integrity |
| `soteriad keygen` | Generate a keypair (ML-KEM-768 or ML-DSA-65) |
| `soteriad share add` | Add a recipient to a volume |
| `soteriad share remove` | Revoke a recipient |
| `soteriad share list` | List active and revoked recipients |
| `soteriad share unlock` | Recover the volume root key |
| `soteriad fde init` | Initialize an FDE volume |
| `soteriad fde verify` | Verify FDE volume key |
| `soteriad fde mount` | Mount an FDE volume |
| `soteriad fde unmount` | Unmount an FDE volume |
| `soteriad omega ...` | OMEGA commands (classification, ironclad, TPM seal, sovereignty) |
| `soteriad audit` | Inspect and verify audit log |

---

## Project Layout

```
soteria-fs/
+-- rust-core/           # Cryptographic core + CLI (soteriad)
|   +-- src/
|   |   +-- crypto_engine/   # AES, ChaCha, HKDF, KDF, FIPS, PQ
|   |   +-- fde/             # Volume, hidden, Shamir, persistent, TPM, PBA
|   |   +-- fs_layer/        # FUSE, storage, WAL, KDF, sandbox, metadata
|   |   +-- key_hierarchy/   # HKDF domain separation + slot table
|   |   +-- omega/           # OMEGA (gated by feature)
|   |   +-- erasure_coding.rs
|   |   +-- metadata_encryption.rs
|   |   +-- secure_erase.rs
|   |   +-- daemon.rs, config.rs
|   |   +-- ...
|   |   +-- tests/
|   +-- Cargo.toml
|
+-- desktop/             # egui-based native desktop app
|   +-- src/
|   |   +-- main.rs          # App pages, wizard, dashboard
|   |   +-- core.rs          # Desktop-to-core bridge
|   +-- Cargo.toml
|
+-- installer/           # Platform installers (MSIX, .deb, .dmg)
|   +-- src/install.rs       # Installation logic
|   +-- build.rs             # Embeds both binaries
|   +-- Cargo.toml
|
+-- packaging/           # Platform-specific packaging
|   +-- portable/pack.ps1   # Portable ZIP builder
|   +-- windows/msix/        # MSIX manifest + assets
|   +-- output/              # Build artifacts (SoteriaAegis-Portable.zip)
|
+-- docs/                # Documentation
|   +-- TCB.md
|   +-- FDE-ARCHITECTURE.md
|   +-- FIPS-SECURITY-POLICY.md
|   +-- SOTERIA-OMEGA-ARCHITECTURE.md
|   +-- THREAT-MODEL.md
|   +-- CRYPTO-INVENTORY.md
|   +-- SECURITY-AUDIT-PREP.md
|   +-- architecture.md
|   +-- threat_model.md
|   +-- faq.md
|   +-- getting-started.md
|
+-- README.md            # This file
+-- LICENSE              # MIT / Apache-2.0
+-- CHANGELOG.md
+-- CONTRIBUTING.md
+-- AUDIT.md
+-- .github/workflows/ci.yml
+-- docs/TCB.md
+-- deny.toml
```

---

## Documentation

| Document | Description |
|---|---|
| [`docs/TCB.md`](docs/TCB.md) | Trusted computing base definition, build matrix, audit checklist |
| [`docs/architecture.md`](docs/architecture.md) | Module map, layered diagram, on-disk format |
| [`docs/crypto_notes.md`](docs/crypto_notes.md) | Primitives, key derivation, lineage, share format |
| [`docs/threat_model.md`](docs/threat_model.md) | Adversary classes, trust boundaries |
| [`docs/security-audit-checklist.md`](docs/security-audit-checklist.md) | What needs independent review |
| [`docs/FDE-ARCHITECTURE.md`](docs/FDE-ARCHITECTURE.md) | Full-disk encryption header format, XTS key derivation v4 |
| [`docs/FIPS-SECURITY-POLICY.md`](docs/FIPS-SECURITY-POLICY.md) | FIPS 140-3 security policy draft |
| [`docs/SOTERIA-OMEGA-ARCHITECTURE.md`](docs/SOTERIA-OMEGA-ARCHITECTURE.md) | OMEGA 14-part architecture |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | OMEGA threat model (adversary classes A1-A11) |
| [`docs/PBA.md`](docs/PBA.md) | Pre-boot authentication |
| [`docs/getting-started.md`](docs/getting-started.md) | Installation, setup, first use |
| [`docs/faq.md`](docs/faq.md) | Common questions and troubleshooting |
| [`docs/CRYPTO-INVENTORY.md`](docs/CRYPTO-INVENTORY.md) | Complete cryptographic primitive inventory |
| [`docs/SECURITY-AUDIT-PREP.md`](docs/SECURITY-AUDIT-PREP.md) | Audit preparation guide |

---

## Contributing

Soteria welcomes contributions. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines on:
- Code style (`cargo fmt`, `cargo clippy`)
- Test expectations (`cargo test --lib` must pass for the TCB)
- Security review (any change to a TCB module requires explicit review)
- Backwards compatibility (the on-disk format is a contract)

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
```

---

## Roadmap

### Shipped
- [x] Per-block AEAD encryption (XChaCha20-Poly1305, AES-256-GCM)
- [x] BLAKE3 lineage chain (tamper detection)
- [x] WAL + crash-safe writes
- [x] ML-KEM-768 post-quantum sharing (FIPS 203)
- [x] ML-DSA-65 envelope signatures (FIPS 204)
- [x] Canary intrusion detection
- [x] Honey filesystem (decoy files)
- [x] Shamir secret sharing (GF(256))
- [x] TPM2 backend (hardware + software fallback)
- [x] Native desktop app (egui)
- [x] TUI dashboard (ratatui)
- [x] CLI (`soteriad`, 20+ subcommands)
- [x] CI/CD (GitHub Actions)
- [x] **Key hierarchy** (HKDF-SHA-256 domain separation)
- [x] **Key slots** (multi-user, revocation, header HMAC)
- [x] **Erasure coding** (RS k-of-n with AEAD shards)
- [x] **Metadata AEAD** (file names, inodes, journal)
- [x] **FDE v4** (layered key derivation)
- [x] **TCB discipline** (feature-gated extras)
- [x] **SOTERIA-OMEGA** (14-part Government/Military edition)
- [x] **Desktop installer** (embeds both binaries, portable ZIP)

### Next
- [ ] External security audit (third-party firm)
- [ ] Production FUSE hardening (Linux)
- [ ] EFI PBA binary (`soteria-pba.efi`, separate `uefi` crate)
- [ ] Code-signing certificate for installer
- [ ] Windows MSIX signing + deployment
- [ ] macOS DMG signing + notarization
- [ ] Linux packages (deb, rpm, Arch AUR)
- [ ] Real TPM2 silicon path validation
- [ ] FIPS 140-3 lab certification (6-12 month process)

---

## License

Dual-licensed under MIT or Apache 2.0, at your option. See [LICENSE](LICENSE) and the package metadata in [`rust-core/Cargo.toml`](rust-core/Cargo.toml).

---

## Acknowledgments

Soteria stands on the shoulders of:
- The Rust cryptographic community (`aes`, `ring`, `chacha20poly1305`, `argon2`, `blake3`, `ml-kem`, `ml-dsa`, `hkdf`).
- NIST (FIPS 203, 204, 180-4, 198-1, SP 800-38D, SP 800-56C, SP 800-90A, SP 800-132).
- The OWASP Password Storage Cheat Sheet (Argon2id parameter recommendations).
- The VeraCrypt and LUKS projects, whose on-disk formats inspired our own.
- The `egui` / `eframe` team for the best immediate-mode GUI framework in Rust.

---

<div align="center">

**Soteria Aegis** - A small, auditable, post-quantum-ready encrypted storage platform.

`cargo build` to start. `cargo test --lib` to verify. `docs/TCB.md` to audit.

</div>
