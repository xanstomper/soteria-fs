<div align="center">

# Soteria

### Modern Encrypted Storage with Hardware-Rooted Security

[![CI](https://github.com/example/soteria-fs/actions/workflows/ci.yml/badge.svg)](https://github.com/example/soteria-fs/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/Tests-134%20passing-brightgreen.svg)](#testing)

[Soteria](#what-is-soteria) · [Installation](#installation) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md)

</div>

---

## What is Soteria

Soteria is a next-generation encrypted storage platform designed to replace legacy disk encryption tools with modern architecture, better usability, and intelligent threat containment.

**Soteria does NOT invent new cryptographic algorithms.** It uses vetted, industry-standard primitives (AES-256-GCM, XChaCha20-Poly1305, BLAKE3, Argon2id, ML-KEM-768, ML-DSA-65) in a hardened system architecture.

### Why Soteria Exists

Traditional encryption tools like VeraCrypt have served well, but they were designed for a different threat model:

| Problem | Legacy Tools | Soteria |
|---|---|---|
| **Threat model** | Offline disk theft only | Malware, ransomware, partial compromise, session attacks |
| **Key management** | Static, long-lived keys | Automatic rotation, hardware-bound, session-based |
| **Blast radius** | Entire volume trusted or untrusted | Per-domain, per-block isolation |
| **Threat detection** | None | Canary tokens, anomaly detection, decoy filesystem |
| **Usability** | Technical dialogs, crypto jargon | Guided onboarding, progressive disclosure, modern UI |
| **Recovery** | Hidden, poorly explained | Front-and-center, guided, verifiable |

### What Makes Soteria Different

- **TPM-bound encryption** — Keys sealed to hardware. Removing the disk doesn't help an attacker.
- **Per-block encryption** — Each block gets its own key. Compromising one block doesn't leak others.
- **Capability-based access** — Processes get tokens that say what they can do, not who they are.
- **Honey filesystem** — Decoy files detect unauthorized access.
- **Canary intrusion detection** — Invisible tripwires alert on suspicious activity.
- **Post-quantum sharing** — ML-KEM-768 and ML-DSA-65 for future-proof file sharing.
- **Crash-safe writes** — WAL + atomic rename. Never a half-written volume.

---

## Installation

### From Release

Download the latest release for your platform:

| Platform | Download |
|---|---|
| Windows | [Soteria-Setup.mix](https://github.com/example/soteria-fs/releases/latest) |
| macOS | [Soteria.dmg](https://github.com/example/soteria-fs/releases/latest) |
| Linux (Debian) | [soteria_amd64.deb](https://github.com/example/soteria-fs/releases/latest) |
| Linux (RPM) | [soteria-x86_64.rpm](https://github.com/example/soteria-fs/releases/latest) |

### From Source

```bash
# Prerequisites: Rust stable (https://rustup.rs)
git clone https://github.com/example/soteria-fs.git
cd soteria-fs/rust-core
cargo build --release

# The binary is at target/release/soteriad
./target/release/soteriad --help
```

### System Requirements

| | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10, macOS 11, Ubuntu 20.04 | Latest stable |
| **RAM** | 256 MB | 1 GB |
| **Disk** | 50 MB install | 100 MB + protected data |
| **TPM** | Optional (software fallback) | TPM 2.0 |

---

## Quick Start

### 1. Generate Keys

```bash
# Generate an ML-KEM-768 keypair (for sharing)
soteriad keygen --out ~/soteria-keys/recipient

# Generate an ML-DSA-65 keypair (for signing)
soteriad keygen --scheme ml-dsa65 --out ~/soteria-keys/owner
```

### 2. Encrypt a File

```bash
soteriad encrypt \
  --src ~/Documents/secret.pdf \
  --into ~/Vault \
  --name secret \
  --passphrase "your-strong-passphrase"
```

### 3. Decrypt a File

```bash
soteriad decrypt \
  --from ~/Vault \
  --name secret \
  --passphrase "your-strong-passphrase" \
  --output ~/recovered.pdf
```

### 4. Share with a Recipient

```bash
# Add recipient (signed with your ML-DSA-65 key)
soteriad share add \
  --volume ~/Vault/secret.sot \
  --passphrase "your-strong-passphrase" \
  --recipient-pk ~/soteria-keys/recipient.pk \
  --owner-sk ~/soteria-keys/owner.dsa.sk

# Recipient unlocks
soteriad share unlock \
  --volume ~/Vault/secret.sot \
  --sk ~/soteria-keys/recipient.sk \
  --owner-pk ~/soteria-keys/owner.dsa.pk \
  --out ~/recovered-key.bin

# Recipient decrypts
soteriad decrypt \
  --from ~/Vault \
  --name secret \
  --key-file ~/recovered-key.bin \
  --output ~/recovered.pdf
```

### 5. Start the Web Dashboard

```bash
# Terminal 1: API server
soteriad serve

# Terminal 2: Web UI
cd ui
bundle install
bundle exec ruby app.rb -p 4567

# Open http://localhost:4567
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Interfaces                      │
│         CLI · Web Dashboard · REST API · FUSE           │
└────────────────────────┬────────────────────────────────┘
                         │
    ┌────────────────────┼─────────────────────┐
    │                    │                     │
┌───▼──────┐   ┌─────────▼────────┐   ┌────────▼────────┐
│ Sensors  │   │ Response Engine  │   │   FS Layer      │
│(untrust.)│   │ (deterministic)  │   │  WAL · FUSE     │
└───┬──────┘   └────────┬─────────┘   └────────┬────────┘
    │ events             │ decisions            │ ops
    ▼                    ▼                      ▼
┌─────────────────────────────────────────────────────────┐
│            Event Bus + Audit Log (BLAKE3-chained)       │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    Aegis Security Layer                  │
│  AEAD · Block Crypto · KDF · PQ · DSA · Shares · WAL   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
                   Encrypted Storage
```

### Aegis Security Layer

Aegis is Soteria's internal security orchestration system. It:

- Manages encryption primitives (AES-256-GCM / XChaCha20-Poly1305)
- Enforces authenticated encryption on every block
- Handles key lifecycle (rotation, derivation, revocation)
- Binds encryption state to TPM + system integrity
- Prevents unsafe configuration states
- Ensures per-domain encryption isolation

---

## Security Model

### Threat Assumptions

Soteria assumes:

- **Malware may be present** on the host OS
- **Partial memory compromise** is possible
- **Active ransomware** may be running
- **Session-based attacks** can target mounted volumes
- **The disk may be stolen** while the system is off

### Defenses

| Threat | Defense |
|---|---|
| Disk theft | Per-block AEAD encryption, TPM-bound keys |
| Ransomware | Canary detection, honey filesystem, capability revocation |
| Memory compromise | Key rotation, session-based keys, zeroization |
| Boot tampering | Secure Boot + TPM PCR binding |
| Key exposure | Per-block key isolation, forward-secure ratcheting |
| Share tampering | ML-DSA-65 envelope signatures |

### What Soteria Does NOT Claim

- Soteria does NOT claim to be "unbreakable."
- Soteria does NOT use "NSA-grade" or "military-grade" encryption.
- Soteria does NOT invent new cryptographic algorithms.
- Soteria does NOT protect against a fully compromised kernel (A6) or physical coercion (A7).

---

## Testing

```bash
# Run all tests
cargo test --all-targets

# Run benchmarks
cargo bench

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Security audit
cargo audit
```

134 tests across 8 integration test files covering: binary volume, AEAD, block crypto, KDF, ML-KEM, ML-DSA, shares, WAL, audit log, storage layer, capability, defense layers, config/policy, CLI integration, durability.

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation, setup, first use |
| [FAQ](docs/faq.md) | Common questions and troubleshooting |
| [Threat Model](docs/threat_model.md) | Adversary classes, trust boundaries, failure modes |
| [Architecture](docs/architecture.md) | Module map, layered diagram, on-disk format |
| [Crypto Notes](docs/crypto_notes.md) | Primitives, key derivation, lineage, WAL, share format |
| [Changelog](CHANGELOG.md) | Version history |

---

## Roadmap

- [x] Per-block AEAD encryption
- [x] BLAKE3 lineage chain
- [x] WAL + crash-safe writes
- [x] ML-KEM-768 post-quantum sharing
- [x] ML-DSA-65 envelope signatures
- [x] Canary intrusion detection
- [x] Honey filesystem
- [x] Web dashboard (Ruby + REST API)
- [x] Background daemon
- [x] Enterprise features (SSO, MDM, compliance)
- [ ] Real TPM2 backend (feature-gated, needs testing on hardware)
- [ ] Full FUSE volume mounting (production hardening)
- [ ] Security audit (external firm)
- [ ] Windows installer (MSIX)
- [ ] macOS DMG
- [ ] Linux packages (deb, rpm)

---

## Downloads

| Platform | Architecture | Link |
|---|---|---|
| Windows | x86_64 | [soteriad-windows.exe](https://github.com/example/soteria-fs/releases/latest) |
| macOS | x86_64 / ARM64 | [soteriad-macos](https://github.com/example/soteria-fs/releases/latest) |
| Linux | x86_64 | [soteriad-linux](https://github.com/example/soteria-fs/releases/latest) |
| Source | — | [Source code](https://github.com/example/soteria-fs/archive/refs/tags/v0.1.0.tar.gz) |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Soteria** — Protect your files. Defend your system. Stay in control.

Built with Rust. Powered by Aegis.

</div>
