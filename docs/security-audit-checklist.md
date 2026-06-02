# Security Audit Checklist

This document outlines what needs to be reviewed in an independent security audit of Soteria.

## Scope

The audit covers the `rust-core/` crate — the trusted computing base of Soteria. The Ruby web UI (`ui/`) and packaging scripts are out of scope (they don't handle cryptographic material directly).

## Modules to Audit

### Critical (Must Audit)

| Module | File | What to Review |
|--------|------|----------------|
| AEAD | `crypto_engine/aead.rs` | Encrypt/decrypt correctness, nonce handling, AAD binding, key zeroization |
| Block crypto | `crypto_engine/block.rs` | Per-block key derivation, lineage chain, HKDF usage |
| KDF | `crypto_engine/kdf.rs` | Argon2id parameters, HKDF-SHA256 usage, salt handling |
| Key ratchet | `crypto_engine/kdf.rs` | Ratchet formula, old key zeroization, entropy source |
| ML-KEM-768 | `crypto_engine/pq.rs` | Key wrapping, HKDF KEK derivation, AEAD envelope |
| ML-DSA-65 | `crypto_engine/dsa.rs` | Signing, verification, deterministic variant |
| Shares | `crypto_engine/shares.rs` | Envelope signature payload, fingerprint binding, revocation logic |
| Storage | `fs_layer/storage.rs` | Binary format parsing, header integrity, lineage verification |
| WAL | `fs_layer/wal.rs` | Commit marker handling, recovery logic, crash safety |
| KDF sidecar | `fs_layer/kdf.rs` | Sidecar format, integrity check, parameter validation |

### High Priority

| Module | File | What to Review |
|--------|------|----------------|
| Audit log | `policy/audit_log.rs` | Chain formula, tamper detection, truncated line handling |
| Revocation | `policy/revocation.rs` | Capability token scoping, TTL enforcement, revocation persistence |
| TPM2 | `tpm/software.rs` | Software sealing key derivation, device identity binding |
| TPM2 | `tpm/hardware.rs` | TPM2 ESAPI usage, PCR policy, sealed object format |
| Nonce | `crypto_engine/nonce.rs` | Random nonce generation, OsRng usage |

### Medium Priority

| Module | File | What to Review |
|--------|------|----------------|
| Event bus | `event_bus/` | BLAKE3 chain formula, event serialization |
| Config | `config.rs` | Default parameter safety, deserialization |
| FUSE | `fs_layer/fuse_fs.rs` | Inode mapping, cache eviction, write-back flush |
| API | `api.rs` | Input validation, error handling |
| CLI | `main.rs` | Argument handling, secret zeroization |

## Specific Concerns

### 1. Key Material Zeroization

- [ ] All key material uses `Zeroizing<>` wrapper
- [ ] Keys are zeroized on drop
- [ ] No key material in error messages
- [ ] No key material in log output
- [ ] Stack-allocated keys are zeroized

### 2. Nonce Uniqueness

- [ ] AES-256-GCM nonces are random 96-bit (collision risk documented)
- [ ] XChaCha20-Poly1305 nonces are random 192-bit (collision negligible)
- [ ] No nonce reuse possible across crashes
- [ ] Per-block nonces are independent

### 3. Key Derivation

- [ ] Argon2id parameters meet OWASP 2024 minimums
- [ ] HKDF salt includes block index and lineage hash
- [ ] HKDF info string includes domain separation tag
- [ ] No key derivation shortcut attacks

### 4. Integrity Verification

- [ ] BLAKE3 lineage chain detects block reordering
- [ ] BLAKE3 lineage chain detects block insertion/deletion
- [ ] Header integrity check covers all header fields
- [ ] KDF sidecar integrity check covers all fields

### 5. Post-Quantum Cryptography

- [ ] ML-KEM-768 implementation matches FIPS 203
- [ ] ML-DSA-65 implementation matches FIPS 204
- [ ] Envelope signature payload is canonical (no ambiguity)
- [ ] Domain separator prevents cross-protocol replay

### 6. Crash Safety

- [ ] WAL commit marker is written before data
- [ ] Atomic rename is the final step
- [ ] Parent directory fsync follows rename
- [ ] Recovery handles all crash scenarios

### 7. Share File Security

- [ ] Fingerprint prevents cross-volume graft
- [ ] Envelope signature prevents envelope tampering
- [ ] Revocation is enforced (revoked envelopes not active)
- [ ] Double-add is rejected

### 8. Software TPM Fallback

- [ ] Device key derivation is deterministic
- [ ] Device key is unique per machine
- [ ] Software sealing uses authenticated encryption
- [ ] Tampered sealed blob is rejected

## Known Limitations (Not Bugs)

These are documented limitations, not vulnerabilities:

1. **AES-GCM nonce collision** — Random 96-bit nonces have a birthday-bound collision risk. Mitigated by XChaCha20-Poly1305 default (192-bit nonces).
2. **Software TPM fallback** — Not equivalent to hardware binding. Resists casual disk access but not a determined attacker with hardware access.
3. **Memory disclosure** — Plaintext exists in process memory while volumes are mounted. Mitigated by unmount lifecycle.
4. **No constant-time comparison** — Some hex string comparisons may not be constant-time. Not a practical attack vector for the use case.

## Audit Deliverables

The auditor should produce:

1. **Findings report** — List of vulnerabilities with severity (Critical/High/Medium/Low/Info)
2. **Remediation guidance** — How to fix each finding
3. **Code quality assessment** — Overall code quality, test coverage, documentation
4. **Cryptographic correctness** — Verification that implementations match standards
5. **Sign-off letter** — Statement of audit scope and findings

## Contact

For security vulnerabilities, please email: security@soteria.dev

Do NOT open public issues for security vulnerabilities.
