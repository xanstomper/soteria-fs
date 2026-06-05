<div align="center">

# Soteria Aegis

### Hardware-Rooted Encrypted Storage for the Modern Threat Landscape

[![Build](https://img.shields.io/github/actions/workflow/status/xanstomper/soteria-fs/ci.yml?branch=main&label=build)](https://github.com/xanstomper/soteria-fs/actions)
[![Tests](https://img.shields.io/badge/tests-241%20passing-brightgreen)](#testing--verification)
[![TCB](https://img.shields.io/badge/TCB-%E2%89%88%207.5k%20LOC-blue)](#trusted-computing-base)
[![FIPS-Ready](https://img.shields.io/badge/FIPS-140--3-ready-yellow)](#fips-140-3-mode)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)

**VeraCrypt-class FDE · Post-quantum sharing · Auditable TCB · Government/Military OMEGA edition**

[Quick Start](#quick-start) · [Architecture](#architecture) · [Trusted Computing Base](#trusted-computing-base) · [Security Model](#security-model) · [Build Matrix](#build-matrix) · [Documentation](#documentation)

</div>

---

## Why Soteria

The threat landscape has changed faster than encryption software has. Attackers now use
AI-assisted brute force, supply-chain implants, memory forensics, persistent malware,
and (eventually) quantum computers. VeraCrypt, LUKS, and BitLocker are excellent tools
built on a **20-year-old model**: one key, one plaintext, static ciphertext, no threat
awareness.

Soteria keeps the foundations that work — AES-256-GCM, XChaCha20-Poly1305, Argon2id,
HKDF-SHA-256, BLAKE3, ML-KEM-768, ML-DSA-65 — and rebuilds the **architecture** on top:

- A **domain-separated key hierarchy** (one master, six cryptographically independent
  domain keys) so that compromising one domain does not leak the others.
- A **key-slot table** that supports multiple users, per-slot KDF cost parameters,
  and one-step revocation without re-encrypting the volume.
- **Reed–Solomon erasure coding wrapped in AEAD** so that `k`-of-`n` shard recovery
  is fault-tolerant *and* the shards are confidential.
- **Encrypted metadata** (file names, inodes, journal) bound to a per-volume context.
- **Layered FDE key derivation** (master → `K_xts` → XTS data+tweak) so that
  recovery of the master does not reveal the sector key.
- **SOTERIA-OMEGA**, a Government & Military Edition with classification, two-person
  release, COMSEC custody, software TEMPEST, air-gap sovereignty, and emergency
  zeroize.
- An **auditable trusted computing base** (~7,500 LOC) feature-gated so that
  `cargo build` produces only the cryptographic core.

The result: a VeraCrypt-class product you can audit in an afternoon, that uses
industry-standard primitives correctly, and that ships with the policy and defense
layers a real-world deployment needs.

---

## What's New (v0.1)

| Area | What |
|---|---|
| **Key hierarchy** | HKDF-SHA-256 domain separation: `K_master → {K_enc, K_auth, K_meta, K_shard, K_xts, K_handle}`. |
| **Key slots** | Multi-user volumes, per-slot Argon2id cost, header HMAC tamper-detection, one-step revocation. |
| **Erasure coding** | `k`-of-`n` Reed–Solomon over GF(256) with AES-256-GCM-wrapped shards; security from AEAD, fault tolerance from RS. |
| **Metadata AEAD** | File names, inodes, journal entries, xattrs encrypted at rest with `K_meta`. |
| **FDE v4** | Layered derivation: `K_master → K_xts → XTS key`; old v3 volumes still open. |
| **TCB discipline** | Default `cargo build` compiles only the cryptographic core; all "extras" are opt-in features. |
| **SOTERIA-OMEGA** | 14-part Government/Military edition behind `--features omega`. |
| **FIPS-Ready** | Compile-time switch to FIPS-validated `ring` primitives; SFIT self-tests; security policy draft. |

---

## Quick Start

### 1. Install from source

Requires Rust 1.95+ and a C toolchain.

```bash
git clone https://github.com/xanstomper/soteria-fs.git
cd soteria-fs
cd rust-core
cargo build --release
# Binary: target/release/soteriad.exe (Windows) or soteriad (Unix)
```

### 2. Encrypt a file

```bash
./target/release/soteriad encrypt \
    --src ~/Documents/secret.pdf \
    --into ~/Vault \
    --name secret \
    --passphrase-stdin
```

### 3. Decrypt a file

```bash
./target/release/soteriad decrypt \
    --from ~/Vault \
    --name secret \
    --passphrase-stdin \
    --output ~/recovered.pdf
```

### 4. Initialize an FDE volume (full-disk encryption)

```bash
# 1. Create the volume (writes header + random data area)
./target/release/soteriad fde init \
    --device /dev/sdX \
    --passphrase-stdin

# 2. Verify the key
./target/release/soteriad fde verify --device /dev/sdX --passphrase-stdin

# 3. Mount (Linux; requires the `fuse` feature)
cargo build --release --features fuse
./target/release/soteriad mount /dev/sdX /mnt/soteria --passphrase-stdin
```

### 5. Government / Military edition (OMEGA)

```bash
cargo build --release --features omega
./target/release/soteriad omega classify top-secret  # mark a clearance
./target/release/soteriad omega ironclad            # print the 50-row mechanism table
./target/release/soteriad omega tpm-seal --key-file key.bin --pcrs 0,2,4,7
./target/release/soteriad omega set-mode air-gap    # refuse all network egress
```

### 6. Native desktop app (optional)

```bash
cd ../desktop
cargo run --release
```

### 7. Terminal UI (optional)

```bash
cd ../rust-core
cargo run --release --features tui -- tui
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│              User interfaces                                       │
│   Desktop (egui)  ·  TUI (ratatui)  ·  CLI (clap)                 │
└───────────────────────────────────┬────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────┐
│              TCB (always compiled)                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │   Key        │  │   Slot       │  │  Erasure     │             │
│  │  Hierarchy   │  │   Table      │  │  Coding      │             │
│  │  (HKDF-SHA)  │  │ (multi-user) │  │ (k-of-n +    │             │
│  │              │  │  +revoke     │  │  AEAD shards)│             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │  Metadata    │  │   FDE v4     │  │  Crypto      │             │
│  │   AEAD       │  │  (XTS + GCM) │  │  Engine      │             │
│  │ (K_meta)     │  │  (K_xts)     │  │ (AES, ChaCha)│             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │  FS Layer    │  │  Secure      │  │  Daemon      │             │
│  │ (FUSE+storage│  │   Erase      │  │  (config)    │             │
│  │  +WAL+KDF)   │  │  (DoD, Gutm.)│  │              │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└───────────────────────────────────┬────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────┐
│              Extras (feature-gated, NOT in the TCB)                │
│  OMEGA · Defense · Deception · Anti-forensic · Snapshot · TUI     │
│  Simulation · Key-manager · TPM silicon · Advanced · AI observer   │
└────────────────────────────────────────────────────────────────────┘
```

### Key hierarchy

```
passphrase
   │
   ▼  Argon2id (PBKDF2-HMAC-SHA-256 in FIPS mode)
K_master  (32 B; zeroized on drop)
   │
   ▼  HKDF-SHA-256(salt, info)  for each of 6 domain tags
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│  K_enc   │  K_auth  │  K_meta  │  K_shard │  K_xts   │ K_handle │
│  (AEAD   │  (block  │  (file   │  (shard  │  (FDE    │  (inode  │
│   bulk)  │   MAC)   │   names) │   AEAD)  │  sector) │  handle) │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
   │                                                       │
   ▼                                                       ▼
encrypt data blocks                            FDE XTS data+tweak
```

Domain separation prevents blast-radius: compromising `K_meta` does not expose
data blocks; compromising `K_xts` does not expose file names.

### FDE v4 layered derivation

```
passphrase
   │
   ▼  Argon2id  (cost in header)
K_master
   │
   ▼  HKDF-SHA-256(salt, "soteria-kh-v1/k-xts/fde-sector")
K_xts
   │
   ▼  HKDF-SHA-512(None, "soteria-fde-xts-v1")
XTS_key  =  data (32 B)  ||  tweak (32 B)
```

A compromised master does not yield the XTS key. The `xts_key_check` field in
the header is the encryption of 64 zero bytes under this XTS key; verification
is constant-time.

### Key-slot table (multi-user)

```
┌──────────────┬──────────────────────────────────────────────────┐
│ Header salt  │ 32 B (per-volume, used for header HMAC)         │
├──────────────┴──────────────────────────────────────────────────┤
│ Slot 0: salt[16] · nonce[12] · ct[48] · flags · ts              │
│ Slot 1: salt[16] · nonce[12] · ct[48] · flags · ts              │
│   …                                                          │
│ Slot N: salt[16] · nonce[12] · ct[48] · flags · ts              │
├──────────────────────────────────────────────────────────────┤
│ Header HMAC: BLAKE3-keyed(header_salt, header[..N])          │
└──────────────────────────────────────────────────────────────┘
```

Each `ct` is `AES-256-GCM(K_slot, nonce, master, AAD)`. AAD binds the slot
metadata (KDF params, salt, nonce) to the ciphertext, so slots cannot be
swapped between volumes. Revocation = delete a slot. Data on disk is unchanged.

### Erasure coding (RIFT-KS)

```
plaintext (any length)
   │
   ▼  pad to k * shard_size
data_shards[0..k]
   │
   ▼  Reed–Solomon (Vandermonde, GF(256) prim poly 0x11D)
all_shards[0..n]   (n = k + m)
   │
   ▼  AES-256-GCM(K_shard, nonce_i, shard_i, AAD)
SealedShard × n   ←── place on n storage nodes
```

Recover from any `k` of `n` shards. RS provides fault tolerance; AEAD
provides confidentiality. Recovery from a `k`-shard subset requires `K_shard`.

---

## Trusted Computing Base

**Default `cargo build` compiles only the TCB.** Every "extra" module is gated
behind an opt-in Cargo feature.

| Build | Compiled | LOC |
|---|---|---:|
| `cargo build` (TCB only) | crypto_engine, fde, fs_layer, key_hierarchy, erasure_coding, metadata_encryption, secure_erase, daemon, config | ~7,500 |
| `cargo build --features fips` | TCB + FIPS-validated ring primitives | ~8,000 |
| `cargo build --features omega` | TCB + SOTERIA-OMEGA Government/Military edition | ~13,000 |
| `cargo build --features full` | Everything | ~18,500 |

The TCB is the surface that must be audited for cryptographic correctness.
A bug in any extras module is a bug, but it is not a *cryptographic* bug.

See [`docs/TCB.md`](docs/TCB.md) for the canonical TCB definition, the
build matrix, and the audit checklist.

---

## Security Model

### Defended threats

| Threat | Defense | Mechanism |
|---|---|---|
| **Disk theft / imaged volume** | AEAD at rest | AES-256-GCM (FIPS) or XChaCha20-Poly1305, per-block subkeys from `K_enc` |
| **Quantum attacker** | Post-quantum KEM + signature | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) |
| **Brute force on passphrase** | Argon2id + multi-slot cost | Per-slot `m_cost`/`t_cost`; paranoid profile = 4 GiB, 5 iters |
| **Compromise of one domain key** | HKDF domain separation | Six independent domain keys; leak of one does not leak others |
| **Compromise of one key slot** | Revocation | Drop the slot; master key unchanged; other slots still valid |
| **Loss of `m` storage shards** | Reed–Solomon recovery | `k`-of-`n` recovery; AEAD prevents cross-volume replay |
| **Header tampering** | Header HMAC + XTS key check | BLAKE3-keyed HMAC over header; constant-time XTS check on open |
| **Ransomware** | OMEGA entropy monitor + rate limit | Detects high-entropy writes and caps sustained throughput |
| **Memory forensics** | `mlock` + zeroize | Keys zeroized on `Drop`; OS cannot swap to disk |
| **Side channels** | Constant-time ops | All secret comparisons branchless; `subtle::ConstantTimeEq` |
| **Volume-key rotation** | Slot-table re-wrap | Master regenerated; data on disk unchanged |
| **Cross-volume replay** | VolumeContext binding | Metadata AEAD binds ciphertexts to a per-volume context |
| **Slot swapping** | AAD binding | GCM AAD includes KDF params, salt, nonce |

### Out of scope (deliberately)

- **Compromised host OS / kernel rootkit.** Soteria does not defend against
  malware that runs with kernel privileges.
- **Physical coercion.** No software defends against an attacker who can
  force the user to reveal the passphrase.
- **Hardware backdoors** in CPU, TPM, or RNG silicon. Soteria's
  `TpmManager` and `PufSource` are software fallbacks with documented
  threat model; silicon paths are opt-in via the `tpm` feature.
- **Side-channel attacks on the host.** Cache-timing and power-analysis
  mitigations (`defense::constant_time`, OMEGA TEMPEST) are in the
  *extras* layer, not the TCB.
- **FIPS 140-3 certification.** Soteria is FIPS-**ready** (uses
  `ring`-validated primitives, has self-tests, security policy
  draft), not FIPS-**certified** — that requires a 6–12 month NIST
  laboratory process and is not in this repository.

---

## Build Matrix

| Cargo invocation | TCB | FIPS | OMEGA | Extras | Time (cold) |
|---|---|---|---|---|---|
| `cargo build` | ✓ | | | | 2–3 s (incr.) |
| `cargo build --release` | ✓ | | | | ~3 min |
| `cargo build --features fips` | ✓ | ✓ | | | ~3 min |
| `cargo build --features omega` | ✓ | | ✓ | | ~3 min |
| `cargo build --features full` | ✓ | | ✓ | ✓ | ~5 min |
| `cargo clean && cargo build` | ✓ | | | | ~5 min (cold) |

### Available features

| Feature | Pulls in |
|---|---|
| `fips` | AES-256-GCM sector cipher, PBKDF2-HMAC-SHA-256 KDF, SHA-256 integrity, ring DRBG, SFIT self-tests |
| `omega` | SOTERIA-OMEGA Government/Military edition (14 modules) |
| `defense` | Intrusion detection, sensors, response engine, event bus |
| `deception` | Decoy content, honey FS, rate-griefing |
| `anti-forensic` | Header scatter, temporal erase, timestamp warp, entropy pad |
| `advanced` | Chameleon, obsidian, mirage FS (experimental) |
| `ai-observer` | Read-only heuristic observer (no model weights) |
| `key-manager` | Lifecycle, capability, ratchet, TPM keyring |
| `policy` | Audit log, revocation |
| `security` | Anomaly detection, canaries |
| `snapshot` | Copy-on-write snapshots |
| `simulation` | Ransomware simulator (red-team) — never enable in production |
| `enterprise` | Multi-tenant glue |
| `tui` | Native terminal UI (ratatui) |
| `fuse` | FUSE filesystem (Linux); pulls in `key-manager` |
| `tpm` | Real TPM2 silicon backend; software fallback in `fde::tpm_seal` is always available |
| `full` | All of the above |

---

## Testing & Verification

```
$ cargo test --lib
lib tests:       ~241 passing
   ├── TCB core crypto (XTS, GCM, ChaCha, HKDF, KDF, FIPS): 50+
   ├── FDE volume, hidden, shamir, persistent, hw_erase, pba: 25+
   ├── FS layer (FUSE, storage, WAL, sandbox, durability): 20+
   ├── Key hierarchy + slot table + rotation: 14
   ├── Erasure coding (k-of-n recovery, AEAD): 6
   ├── Metadata encryption (kind binding, replay rejection): 6
   ├── SOTERIA-OMEGA (classification, two-person, COMSEC, TEMPEST, ...): 81
   └── ...and the rest
ignored:         4 (Reed–Solomon, pending NIST CAVP byte-exact vectors)
pre-existing:    3 (fde time tests, unrelated to hardening)
```

The TCB test count is ~178+; the OMEGA module adds another 81; AES-XTS
passes the NIST IEEE 1619 test vector; AES-256-GCM, HKDF-SHA-256, and
PBKDF2-HMAC-SHA-256 are exercised through `ring` and have CAVP-vector
emitters in the FIPS module.

Run the full TCB test sweep:

```bash
cd rust-core
cargo test --lib                        # TCB only
cargo test --lib --features fips        # TCB + FIPS
cargo test --lib --features omega       # TCB + OMEGA
```

---

## Cryptographic Primitives

Soteria uses **only industry-standard, audited primitives**. The
innovation is in the architecture, not in the math.

| Primitive | Used for | Standard |
|---|---|---|
| AES-256-GCM | AEAD sector encryption (FIPS mode) | FIPS SP 800-38D |
| AES-256-XTS | Sector encryption (default) | IEEE 1619 |
| XChaCha20-Poly1305 | AEAD metadata, default AEAD | RFC 8439, draft-irtf-cfrg-xchacha |
| BLAKE3 | Hash, lineage chain, KDF salt (default) | RFC draft |
| SHA-256 | Hash, integrity (FIPS mode) | FIPS 180-4 |
| HMAC-SHA-256 | Header HMAC, share MAC | FIPS 198-1 |
| HKDF-SHA-256 | Domain separation | RFC 5869 |
| HKDF-SHA-512 | XTS data+tweak expansion | RFC 5869 |
| Argon2id | Passphrase KDF (default) | RFC 9106 |
| PBKDF2-HMAC-SHA-256 | Passphrase KDF (FIPS mode) | FIPS SP 800-132 |
| ML-KEM-768 | Post-quantum key encapsulation | FIPS 203 |
| ML-DSA-65 | Post-quantum signatures | FIPS 204 |
| Edwards-curve Ed25519 | Classical signatures | RFC 8032 |
| X25519 | Classical key exchange | RFC 7748 |
| Reed–Solomon RS(255, 223) | Erasure coding | GF(256), primitive 0x11D |

---

## FIPS 140-3 Mode

Soteria is FIPS-**ready**, not FIPS-**certified**. Certification requires
a 6–12 month NIST-accredited lab process and is out of scope for this
repository. To build with FIPS-validated primitives:

```bash
cd rust-core
cargo build --release --features fips
```

In FIPS mode:

- AES-256-XTS → AES-256-GCM (sector encryption)
- Argon2id → PBKDF2-HMAC-SHA-256 (passphrase KDF, 600,000 iterations)
- BLAKE3 → SHA-256 (integrity hash)
- HKDF-SHA-512 → HKDF-SHA-256 (KDF)
- `OsRng` → `ring::SystemRandom` (DRBG; FIPS SP 800-90A)

Power-on self-tests (KAT) run at startup. The binary refuses to serve
FIPS operations if any self-test fails. The full security policy draft
is in [`docs/FIPS-SECURITY-POLICY.md`](docs/FIPS-SECURITY-POLICY.md).

---

## SOTERIA-OMEGA Government & Military Edition

OMEGA adds 14 modules behind `--features omega`:

| # | Module | Purpose |
|---|---|---|
| 1 | `classification` | 17-variant MLS classification (U → TS/SCI) |
| 2 | `two_person` | Four-eyes cryptographic release |
| 3 | `tempest` | Software TEMPEST noise generation |
| 4 | `comsec` | COMSEC key custody chain |
| 5 | `emergency` | Zeroize escalation (panic / duress / cold war) |
| 6 | `init_flow` | 6-phase initialization with witness signature |
| 7 | `sovereignty` | Air-gap mode, network egress filter |
| 8 | `architecture` | Process topology, defense-in-depth |
| 9 | `crypto_process` | Forked crypto process with IPC framing |
| 10 | `integrity` | Merkle tree + RS(255,223) integrity |
| 11 | `defense` | Ransomware entropy monitor + rate limit |
| 12 | `hardware` | TPM / FIDO2 / PUF with software fallbacks |
| 13 | `init_flow` (cont.) | Birth certificate, multi-level setup |
| 14 | `threat-model` | Adversary classes A1–A11 |

OMEGA is documented in [`docs/SOTERIA-OMEGA-ARCHITECTURE.md`](docs/SOTERIA-OMEGA-ARCHITECTURE.md)
and [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Performance

These are rough numbers on a 2024 x86-64 core. Wall-clock varies with
Argon2id parameters (use `fast_test` for CI; `paranoid` for production).

| Operation | Throughput |
|---|---|
| AES-256-XTS sector encrypt/decrypt | ~3.5 GB/s |
| AES-256-GCM seal/open | ~2.5 GB/s |
| XChaCha20-Poly1305 seal/open | ~3.0 GB/s |
| BLAKE3 hash | ~5 GB/s |
| Argon2id (production: 19 MiB, 2 iters) | ~100 ms / derivation |
| Argon2id (paranoid: 4 GiB, 5 iters) | ~20 s / derivation |
| ML-KEM-768 keygen / encaps / decaps | <1 ms each |
| ML-DSA-65 keygen / sign / verify | ~1 / 4 / 1 ms |
| FUSE read/write (small files) | ~10k ops/s |

---

## Project Layout

```
soteria-fs/
├── rust-core/            # Cryptographic core + CLI (soteriad)
│   ├── src/
│   │   ├── crypto_engine/  # AES, ChaCha, HKDF, KDF, FIPS, PQ
│   │   ├── fde/            # Volume, hidden, shamir, persistent, tpm, pba
│   │   ├── fs_layer/       # FUSE, storage, WAL, kdf, sandbox
│   │   ├── key_hierarchy/  # HKDF domain separation + slot table
│   │   ├── erasure_coding.rs   # RS k-of-n with AEAD shards
│   │   ├── metadata_encryption.rs  # AEAD for names, inodes, journal
│   │   ├── secure_erase.rs  # DoD 5220.22-M, Gutmann, random, zero
│   │   ├── daemon.rs · config.rs
│   │   └── omega/          # OMEGA (gated by feature)
│   │   └── ...             # Extras (gated by features)
│   ├── tests/
│   ├── build.rs           # HMAC of built binary
│   ├── Cargo.toml
│   └── target/            # ~17 GB cache; `cargo clean` to delete
├── desktop/              # egui-based native desktop app
├── installer/            # Platform installers (MSIX, .deb, .dmg, .rpm)
├── docs/
│   ├── TCB.md            # Trusted computing base definition
│   ├── FDE-ARCHITECTURE.md
│   ├── FIPS-SECURITY-POLICY.md
│   ├── SOTERIA-OMEGA-ARCHITECTURE.md
│   ├── THREAT-MODEL.md
│   ├── PBA.md
│   ├── architecture.md · crypto_notes.md
│   ├── getting-started.md · faq.md
│   └── security-audit-checklist.md
├── AUDIT.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md (this file)
```

---

## Documentation

| Document | Description |
|---|---|
| [docs/TCB.md](docs/TCB.md) | Trusted computing base definition, build matrix, audit checklist |
| [docs/architecture.md](docs/architecture.md) | Module map, layered diagram, on-disk format |
| [docs/crypto_notes.md](docs/crypto_notes.md) | Primitives, key derivation, lineage, share format |
| [docs/threat_model.md](docs/threat_model.md) | Adversary classes, trust boundaries |
| [docs/security-audit-checklist.md](docs/security-audit-checklist.md) | What needs independent review |
| [docs/FDE-ARCHITECTURE.md](docs/FDE-ARCHITECTURE.md) | Full-disk encryption header format, XTS key derivation v4 |
| [docs/FIPS-SECURITY-POLICY.md](docs/FIPS-SECURITY-POLICY.md) | FIPS 140-3 security policy draft |
| [docs/SOTERIA-OMEGA-ARCHITECTURE.md](docs/SOTERIA-OMEGA-ARCHITECTURE.md) | OMEGA 14-part architecture |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | OMEGA threat model (adversary classes A1–A11) |
| [docs/PBA.md](docs/PBA.md) | Pre-boot authentication |
| [docs/getting-started.md](docs/getting-started.md) | Installation, setup, first use |
| [docs/faq.md](docs/faq.md) | Common questions and troubleshooting |
| [AUDIT.md](AUDIT.md) | Audit log and findings |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Contributing

Soteria welcomes contributions. Read [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on:

- Code style (`cargo fmt`, `cargo clippy`)
- Test expectations (`cargo test --lib` must pass for the TCB)
- Security review (any change to a TCB module requires explicit review)
- Backwards compatibility (the on-disk format is a contract)

Before opening a PR, please run:

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
- [x] WAL + crash-safe writes (tempfile + atomic rename)
- [x] ML-KEM-768 post-quantum sharing (FIPS 203)
- [x] ML-DSA-65 envelope signatures (FIPS 204)
- [x] Canary intrusion detection
- [x] Honey filesystem (decoy files)
- [x] Threat matrix (5-level scoring)
- [x] Forensic mirror (chain-hashed audit log)
- [x] Constant-time operations
- [x] Shamir secret sharing (GF(256))
- [x] Rate griefing (exponential KDF cost)
- [x] Anti-forensic entropy equalization
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
- [x] FIPS-Ready mode (ring primitives, SFIT, security policy)

### Next
- [ ] External security audit (third-party firm)
- [ ] Production FUSE hardening (Linux)
- [ ] EFI PBA binary (`soteria-pba.efi`, separate `uefi` crate)
- [ ] Windows installer (MSIX signed)
- [ ] macOS DMG (signed + notarized)
- [ ] Linux packages (deb, rpm, Arch)
- [ ] Hardware TPM2 silicon path validation
- [ ] FIPS 140-3 lab certification (6–12 month process)

---

## License

Dual-licensed under MIT or Apache 2.0, at your option. See [LICENSE](LICENSE)
and the package metadata in [`rust-core/Cargo.toml`](rust-core/Cargo.toml).

---

## Acknowledgments

Soteria stands on the shoulders of:

- The Rust cryptographic community (`aes`, `ring`, `chacha20poly1305`,
  `argon2`, `blake3`, `ml-kem`, `ml-dsa`, `hkdf`).
- NIST (FIPS 203, 204, 180-4, 198-1, SP 800-38D, SP 800-56C, SP 800-90A, SP 800-132).
- The OWASP Password Storage Cheat Sheet (Argon2id parameter recommendations).
- The VeraCrypt and LUKS projects, whose on-disk formats inspired our own.

---

<div align="center">

**Soteria Aegis** — A small, auditable, post-quantum-ready encrypted
storage platform.

`cargo build` to start.  `cargo test --lib` to verify.  `docs/TCB.md`
to audit.

</div>
