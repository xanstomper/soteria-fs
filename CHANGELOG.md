# Changelog

All notable changes to Soteria are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-02

First public alpha release.

### Added

#### Aegis Core (Encryption Engine)
- Per-block authenticated encryption (XChaCha20-Poly1305, AES-256-GCM)
- BLAKE3 lineage chain for integrity verification
- Argon2id passphrase KDF (OWASP 2024 parameters)
- HKDF-SHA256 key derivation and ratcheting
- ML-KEM-768 post-quantum file sharing (FIPS 203)
- ML-DSA-65 envelope signatures (FIPS 204)
- WAL + atomic rename + parent-dir fsync for crash safety

#### Defense Layer
- Canary intrusion detection tokens
- Honey (decoy) filesystem
- Anomaly detector (entropy, write patterns, canary hits)
- Capability-based access control with revocation engine
- BLAKE3-chained audit log

#### CLI (`soteriad`)
- 10 subcommands: status, simulate-event, mount, encrypt, decrypt, list, verify, keygen, audit, share
- Nested share commands: add, remove, list, unlock
- ML-KEM-768 and ML-DSA-65 keygen with `--scheme` flag
- REST API server (`soteriad serve`) for web UI integration

#### Web Dashboard (Ruby)
- Sinatra + HTMX + Tailwind CSS
- Dashboard with protection score, storage overview, event stream
- Threat center with severity filtering
- Recovery center with key verification
- Key lifecycle viewer
- Security domain management
- Settings with security mode selection
- 7-step installer wizard
- Learning center with 3-tier explanations

#### Infrastructure
- GitHub Actions CI (lint, test, security audit, multi-OS build)
- TPM2 backend (feature-gated, `--features tpm`)
- Hardened FUSE layer with write-back cache and persistent inodes
- Background daemon with configurable intervals
- Enterprise features (SSO, MDM, compliance reports)
- Performance benchmarks (Criterion)
- Windows MSIX, macOS DMG, Linux deb/rpm packaging scripts

### Tests
- 134 tests across 8 integration test files
- 100% pass on stable Rust (Windows, Linux)

[0.1.0]: https://github.com/example/soteria-fs/releases/tag/v0.1.0
