<div align="center">

# Soteria Aegis

### Hardware-Rooted Encrypted Storage for the Modern Threat Landscape

[![Build](https://img.shields.io/github/actions/workflow/status/xanstomper/soteria-fs/ci.yml?branch=main&label=build)](https://github.com/xanstomper/soteria-fs/actions)
[![Tests](https://img.shields.io/badge/tests-193%20passing-brightgreen)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)

[Quick Start](#quick-start) · [Architecture](#architecture) · [Security Model](#security-model) · [Why Soteria](#why-soteria) · [Documentation](#documentation)

</div>

---

## The Problem

Every existing encryption tool (VeraCrypt, LUKS, BitLocker, FileVault) operates on the same 20-year-old model: one key, one plaintext, static ciphertext, no threat awareness. An attacker who gets past the passphrase gets everything. A ransomware operator who encrypts the volume wins. A forensic analyst who images the disk has unlimited time to crack it.

The threat landscape has changed. Attackers use AI-assisted brute force, supply-chain implants, memory forensics, and persistent malware. Encryption tools haven't kept up.

## The Solution

Soteria is a new kind of encrypted storage platform. It doesn't just encrypt your files — it actively defends them.

**What Soteria does that no other tool does:**

| Capability | VeraCrypt | LUKS | BitLocker | Soteria |
|---|---|---|---|---|
| Per-block encryption with unique keys | ✗ | ✗ | ✗ | ✅ |
| Automatic key rotation | ✗ | ✗ | ✗ | ✅ |
| Post-quantum key exchange (ML-KEM-768) | ✗ | ✗ | ✗ | ✅ |
| Post-quantum envelope signatures (ML-DSA-65) | ✗ | ✗ | ✗ | ✅ |
| BLAKE3 lineage chain (tamper detection) | ✗ | ✗ | ✗ | ✅ |
| Canary intrusion detection | ✗ | ✗ | ✗ | ✅ |
| Honey filesystem (decoy files) | ✗ | ✗ | ✗ | ✅ |
| Capability-based access control | ✗ | ✗ | ✗ | ✅ |
| Automated threat scoring (5 levels) | ✗ | ✗ | ✗ | ✅ |
| Constant-time operations (side-channel defense) | ✗ | ✗ | ✗ | ✅ |
| Shamir secret sharing (social key recovery) | ✗ | ✗ | ✗ | ✅ |
| Rate griefing (exponential brute-force cost) | ✗ | ✗ | ✗ | ✅ |
| Crash-safe writes (WAL + atomic rename) | ✗ | Partial | ✗ | ✅ |
| Forensic mirror (immutable audit chain) | ✗ | ✗ | ✗ | ✅ |
| Anti-forensic entropy equalization | ✗ | ✗ | ✗ | ✅ |

**Soteria does NOT invent new cryptographic algorithms.** It uses vetted, industry-standard primitives (AES-256-GCM, XChaCha20-Poly1305, BLAKE3, Argon2id, HKDF-SHA256, ML-KEM-768, ML-DSA-65) in a hardened system architecture. The innovation is in the architecture, not the math.

---

## Quick Start

### Install from source

```bash
git clone https://github.com/xanstomper/soteria-fs.git
cd soteria-fs/rust-core
cargo build --release
```

### Encrypt a file

```bash
soteriad encrypt \
  --src ~/Documents/secret.pdf \
  --into ~/Vault \
  --name secret \
  --passphrase "your-strong-passphrase"
```

### Decrypt a file

```bash
soteriad decrypt \
  --from ~/Vault \
  --name secret \
  --passphrase "your-strong-passphrase" \
  --output ~/recovered.pdf
```

### Share securely (post-quantum)

```bash
# Generate keypairs
soteriad keygen --out ~/keys/alice          # ML-KEM-768 (recipient)
soteriad keygen --scheme ml-dsa65 --out ~/keys/owner  # ML-DSA-65 (signing)

# Owner adds recipient (signed envelope)
soteriad share add \
  --volume ~/Vault/secret.sot \
  --passphrase "your-passphrase" \
  --recipient-pk ~/keys/alice.pk \
  --owner-sk ~/keys/owner.dsa.sk

# Recipient unlocks (verifies signature)
soteriad share unlock \
  --volume ~/Vault/secret.sot \
  --sk ~/keys/alice.sk \
  --owner-pk ~/keys/owner.dsa.pk \
  --out ~/recovered.key
```

### Launch the native desktop app

```bash
cd desktop
cargo run
```

### Launch the TUI dashboard

```bash
cd rust-core
cargo run --features tui -- tui
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Native Desktop App (egui)                │
│         Dashboard · Volumes · Keys · Recovery           │
└───────────────────────┬─────────────────────────────────┘
                        │ Direct function calls
┌───────────────────────▼─────────────────────────────────┐
│                    CLI (clap)                            │
│   encrypt · decrypt · keygen · share · verify · tui     │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│                   Aegis Core                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │
│  │  AEAD   │ │  Block  │ │   KDF   │ │   PQ    │      │
│  │ XChaCha │ │ HKDF    │ │Argon2id │ │ML-KEM   │      │
│  │ AES-GCM │ │ Lineage │ │  ratchet│ │ML-DSA   │      │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│               Defense & Detection Layers                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Anti-    │ │ Deception│ │ Intrusion│ │ Advanced │  │
│  │ forensic │ │ Layer    │ │ Detection│ │ Crypto   │  │
│  │          │ │          │ │          │ │          │  │
│  │TSEB, EDL │ │Decoys,   │ │Threat    │ │Chameleon │  │
│  │SHS, LTP  │ │Recursive │ │Matrix,   │ │Mirage FS │  │
│  │          │ │Hell, Rate│ │Forensic  │ │Obsidian  │  │
│  │          │ │Grief     │ │Mirror    │ │          │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│               Storage & Hardware Layer                   │
│  WAL · FUSE · TPM2 (hardware + software) · mlock        │
│  KDF sidecar binding · Persistent inode mapping          │
└─────────────────────────────────────────────────────────┘
```

---

## Security Model

### What Soteria defends against

| Threat | Defense | How |
|---|---|---|
| **Disk theft** | Per-block AEAD | Every block encrypted with unique key via HKDF |
| **Brute force** | Rate griefing | KDF cost grows exponentially after N failures |
| **Quantum computing** | ML-KEM-768 + ML-DSA-65 | Post-quantum key exchange and signatures |
| **Ransomware** | Canary + honey FS | Decoy files detect and contain intrusion |
| **Memory forensics** | mlock + zeroize | Keys locked to RAM, zeroized on drop |
| **Snapshot comparison** | Timestamp virtualization | File timestamps randomized per mount |
| **Side-channel attacks** | Constant-time ops | All comparisons branchless |
| **Share file tampering** | BLAKE3 chain + ML-DSA signatures | Immutable event chain with cryptographic signatures |
| **Automated scanners** | Entropy equalization | All sectors identical entropy, no boundaries detectable |
| **KDF sidecar swapping** | Header binding | KDF hash bound to volume header at offset 112 |
| **WAL race conditions** | tempfile crate | Random temp file names, atomic rename |
| **Passphrase exposure** | stdin-only input | Passphrase read from stdin, never from argv |

### What Soteria does NOT claim

- Soteria does NOT claim to be "unbreakable." No system is.
- Soteria does NOT invent new cryptographic algorithms.
- Soteria does NOT protect against a fully compromised kernel or physical coercion.
- Soteria does NOT claim to be stronger than AES or ChaCha20 — it uses them correctly.

---

## Why Soteria

### 1. Architecture, not algorithms

The cryptographic primitives in Soteria (AES-256-GCM, XChaCha20-Poly1305, BLAKE3, Argon2id) are the same ones used by VeraCrypt, LUKS, and BitLocker. Soteria doesn't invent stronger math — it arranges the existing math into a system that survives real attacks.

### 2. Defense in depth

Every layer assumes the layer below it is compromised. An attacker who gets past the passphrase hits rate griefing. An attacker who beats rate griefing hits the BLAKE3 lineage chain. An attacker who forges the lineage hits the canary tokens. An attacker who avoids the canaries hits the honey filesystem. The defenses stack.

### 3. Post-quantum readiness

ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) are the NIST-standardized post-quantum algorithms. Soteria uses them for key exchange and envelope signatures today. A future quantum computer cannot recover the volume root key from a captured share file.

### 4. Modern threat model

Soteria assumes the attacker may have malware on the host, may have physical access to the disk, and may have access to quantum computing. The defenses are layered against all three.

### 5. Usable by humans

The CLI is designed for scripting. The native desktop app is designed for humans. No crypto jargon, no technical dialogs, no confusing options. The user sees "Protected" and moves on.

---

## Testing

```
$ cargo test
lib tests:       131
shares tests:     25
cli tests:        10
pq tests:         12
kdf tests:        15
─────────────────────
Total:           193 passing
clippy:          clean
fmt:             clean
```

### What's tested

- AEAD encrypt/decrypt roundtrip (XChaCha + AES-GCM)
- Per-block key derivation (HKDF with lineage binding)
- BLAKE3 lineage chain integrity (tamper detection)
- WAL crash safety (committed/uncommitted recovery)
- ML-KEM-768 key wrapping (FIPS 203)
- ML-DSA-65 envelope signatures (FIPS 204)
- Share file versioning, chaining, revocation
- Argon2id KDF with paranoid parameters
- TPM2 software sealing (AES-256-GCM with device-derived key)
- Anti-forensic entropy equalization (Shannon entropy > 7.5 bits/byte)
- Shamir secret sharing (GF(2^8) arithmetic)
- Threat matrix scoring (5 heuristic factors)
- Forensic mirror (BLAKE3 chain verification)
- Intent verification (process-level write authorization)
- Decoy content generation (3 tiers)
- Rate griefing (exponential KDF cost scaling)
- Chameleon cipher (multi-key encryption)
- Mirage filesystem (Bloom filter + keyed hash)
- Obsidian layer (GF(2^8) polynomial wrapping)
- CLI integration (10 commands, end-to-end)
- Constant-time comparison

---

## Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation, setup, first use |
| [FAQ](docs/faq.md) | Common questions and troubleshooting |
| [Threat Model](docs/threat_model.md) | Adversary classes (A1-A9), trust boundaries |
| [Architecture](docs/architecture.md) | Module map, layered diagram, on-disk format |
| [Crypto Notes](docs/crypto_notes.md) | Primitives, key derivation, lineage, WAL, share format |
| [Security Audit Checklist](docs/security-audit-checklist.md) | What needs independent review |

---

## Roadmap

### Done

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
- [x] Shamir secret sharing (GF(2^8))
- [x] Rate griefing (exponential KDF cost)
- [x] Anti-forensic entropy equalization
- [x] TPM2 backend (hardware + software fallback)
- [x] Native desktop app (egui)
- [x] TUI dashboard (ratatui)
- [x] CLI (10 commands)
- [x] CI/CD (GitHub Actions)
- [x] Security audit checklist

### Next

- [ ] Security audit (external firm)
- [ ] FUSE volume mounting (production hardening)
- [ ] Windows installer (MSIX)
- [ ] macOS DMG
- [ ] Linux packages (deb, rpm)
- [ ] Fuzz testing targets
- [ ] Property-based testing

---

## License

MIT License. See [LICENSE](LICENSE).

---

<div align="center">

**Soteria Aegis** — Protect your files. Defend your system. Stay in control.

</div>
