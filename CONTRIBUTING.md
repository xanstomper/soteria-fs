# Contributing to Soteria

Thank you for your interest in contributing to Soteria! This document explains how to contribute code, report issues, and participate in the community.

## Code of Conduct

Be respectful, constructive, and professional. We're building security software — trust matters.

## How to Contribute

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- Include your OS, Rust version, and steps to reproduce.
- For security vulnerabilities, please email security@soteria.dev (do NOT open a public issue).

### Submitting Code

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes.
4. Run tests: `cargo test --all-targets`
5. Run clippy: `cargo clippy --all-targets -- -D warnings`
6. Check formatting: `cargo fmt --check`
7. Commit with a clear message.
8. Push and open a Pull Request.

### Code Style

- Follow Rust standard conventions.
- Use `cargo fmt` for formatting.
- Use `cargo clippy` to catch common mistakes.
- Write tests for new functionality.
- Document public APIs with doc comments.

### Cryptographic Contributions

- Do NOT invent new cryptographic primitives.
- Use only vetted, industry-standard algorithms.
- All crypto changes require review by a maintainer.
- Reference the relevant standard (FIPS, RFC, etc.) in your PR.

## Development Setup

```bash
# Clone
git clone https://github.com/example/soteria-fs.git
cd soteria-fs/rust-core

# Build
cargo build

# Test
cargo test --all-targets

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Project Structure

```
soteria-fs/
├── rust-core/          # Rust core (lib + CLI binary)
│   ├── src/
│   │   ├── crypto_engine/   # Aegis: AEAD, KDF, PQ, shares
│   │   ├── fs_layer/        # Storage, WAL, FUSE, KDF sidecar
│   │   ├── policy/          # Audit log, revocation engine
│   │   ├── api.rs           # REST API for web UI
│   │   ├── daemon.rs        # Background service
│   │   └── enterprise.rs    # SSO, MDM, compliance
│   ├── tests/               # Integration tests
│   └── benches/             # Performance benchmarks
├── ui/                 # Ruby web dashboard
├── docs/               # Documentation
├── packaging/          # Build scripts (MSIX, DMG, deb, rpm)
└── scripts/            # Release and utility scripts
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
