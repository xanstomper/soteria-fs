# Soteria Security Audit Preparation

This document is the **audit prep package** for third-party
security firms. It scopes the audit, lists the artifacts the
auditor will need, points to the test vectors we have, and lists
the things the auditor is *not* expected to review.

## 1. Scope of the audit

### 1.1 In scope (TCB)

The auditor should review the **Trusted Computing Base (TCB)**,
defined in [`docs/TCB.md`](TCB.md). Specifically:

| Module | LOC | Critical questions |
|---|---:|---|
| `crypto_engine/aead.rs` | 109 | Are AEAD nonces unique? Are AADs bound to the right context? Is the AAD length check enforced? |
| `crypto_engine/xts.rs` | 262 | XTS from scratch. Does it match IEEE 1619-2018? Is the tweak construction right? NIST AVP vector test? |
| `crypto_engine/block.rs` | 86 | Per-block encryption: subkey derivation, header parsing. |
| `crypto_engine/kdf.rs` | 38 | Argon2id cost validation. HKDF-SHA-256 expand length checks. Ratchet. |
| `crypto_engine/nonce.rs` | 36 | Counter-based, monotonically increasing, never reused. |
| `crypto_engine/shares.rs` | 621 | Share file format. BLAKE3 chain integrity (V-AUDIT-7/8/9 fixes). |
| `crypto_engine/secure_box.rs` | 138 | `Drop` zeroes. Not `Send + Sync`. |
| `crypto_engine/pq.rs` | 270 | ML-KEM-768: KAT, encapsulation, decapsulation. |
| `crypto_engine/dsa.rs` | 240 | Ed25519 + ML-DSA-65. Sign/verify. Domain separation. |
| `crypto_engine/fips/primitives.rs` | 274 | FIPS-validated primitives (ring). |
| `crypto_engine/fips/kat.rs` | 259 | Power-on self-tests. |
| `crypto_engine/fips/integrity.rs` | 105 | SFIT (Software Integrity Test). |
| `crypto_engine/fips/cavp.rs` | 142 | CAVP vector writers. |
| `fde/volume.rs` | 730 | Header v4 format, layered derivation, XTS key check, hidden volume. |
| `fde/hidden.rs` | 231 | Hidden inner volume; midpoint header. |
| `fde/shamir.rs` | 236 | GF(256) Shamir. Lagrange interpolation. |
| `fde/persistent.rs` | 257 | NVRAM split-key. |
| `fde/tpm_seal.rs` | 239 | Software TPM seal fallback. |
| `fde/hw_erase.rs` | 179 | NVMe Format / ATA Secure Erase. |
| `fde/pba.rs` | 190 | PBA config and auth modes. |
| `fde/gcm_sector.rs` | 138 | AES-256-GCM sector. |
| `fde/block_device.rs` | 219 | Block I/O trait. |
| `fs_layer/fuse_fs.rs` | 678 | FUSE filesystem (gated by `fuse` feature). |
| `fs_layer/storage.rs` | 549 | On-disk file format. |
| `fs_layer/kdf.rs` | 217 | KDF sidecar format. |
| `fs_layer/wal.rs` | 157 | Write-ahead log. |
| `fs_layer/sandbox.rs` | 106 | Process sandbox. |
| `key_hierarchy/mod.rs` | 226 | HKDF domain separation. |
| `key_hierarchy/slots.rs` | 534 | Slot table, header HMAC, GCM AAD binding. |
| `erasure_coding.rs` | 500 | RS k-of-n with AEAD shards. |
| `metadata_encryption.rs` | 239 | AEAD over file names, inodes, journal. |
| `secure_erase.rs` | 270 | DoD 5220.22-M, Gutmann. |
| `daemon.rs` | 124 | Daemon orchestration. |
| `config.rs` | 84 | Config parser. |
| **Total TCB** | **~7,500** | |

### 1.2 Out of scope

- **Extras modules** (gated behind Cargo features). These are
  operational / UX / policy, not cryptographic. A bug here is
  not a cryptographic bug. Auditor may sample them but is not
  required to do a full review.
- **Build infrastructure** (CI, packaging, installers). The
  auditor should verify that releases are built reproducibly
  but does not need to review the installer scripts.
- **Documentation.** Style and completeness of the docs is not
  a security concern.

### 1.3 Build flag for the audit

The auditor should review the **default** build (`cargo build`).
Optionally, they may also review `--features fips` (FIPS-validated
primitives) and `--features omega` (SOTERIA-OMEGA).

## 2. Audit deliverables

We expect the auditor to deliver:

1. A **threat-model-driven** review. (We provide the threat
   model in [`docs/THREAT-MODEL.md`](THREAT-MODEL.md) and
   [`docs/threat_model.md`](threat_model.md).)
2. A list of **findings**, each with:
   - Severity (Critical / High / Medium / Low / Informational).
   - Affected file and line number.
   - Reproduction steps.
   - Recommended fix.
3. A **mapping of findings to the threat model** (which
   adversary class is affected).
4. An **executive summary** suitable for the public security
   page.

We commit to responding to every finding within 14 days and to
publishing the resolved findings.

## 3. Evidence the auditor will be given

### 3.1 Source

- The full source at the audited commit SHA.
- `git log` history with commit messages and authors.
- A clean `cargo build --release` and `cargo test --lib` from
  the audited commit.

### 3.2 Tests

- The unit-test suite (`cargo test --lib`).
- The integration-test suite (`cargo test --test '*'`).
- The fuzz targets (if built — `cargo fuzz run` for each).
- The proptest configurations.

### 3.3 Test vectors

| Vector | Where |
|---|---|
| AES-256-XTS NIST IEEE 1619 vector | `crypto_engine::xts::tests::xts_passes_nist_avp_vector_1` |
| AES-256-GCM (NIST SP 800-38D) | CAVP writers in `crypto_engine/fips/cavp.rs` |
| HMAC-SHA-256 (RFC 4231) | `crypto_engine/fips/primitives.rs` |
| HKDF-SHA-256 (RFC 5869) | `crypto_engine/kdf.rs` |
| Argon2id (RFC 9106) | `crypto_engine/fips/cavp.rs` |
| PBKDF2-HMAC-SHA-256 (RFC 7914 / SP 800-132) | `crypto_engine/fips/cavp.rs` |
| BLAKE3 (RFC draft) | direct `blake3` |
| ML-KEM-768 (FIPS 203) | KAT in `crypto_engine/pq.rs` |
| ML-DSA-65 (FIPS 204) | KAT in `crypto_engine/dsa.rs` |
| Ed25519 (RFC 8032) | `crypto_engine/dsa.rs` |
| X25519 (RFC 7748) | `crypto_engine/dsa.rs` |

### 3.4 Configuration

- `Cargo.toml` (with all features).
- `build.rs`.
- `rust-toolchain.toml` (if present; we pin a specific Rust
  version for reproducible builds).
- The release profile (`lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = "symbols"`).

### 3.5 CI

- The CI workflow files in `.github/workflows/`.
- The `cargo deny` configuration (`deny.toml`).
- The reproducer script (`scripts/audit-repro.sh`).

## 4. Reproducer

A self-contained reproducer is in
[`scripts/audit-repro.sh`](../../scripts/audit-repro.sh). It:

1. Clones the repo at the audited SHA.
2. Runs `cargo build --release` and `cargo test --lib`.
3. Captures the test output.
4. Computes the binary HMAC (matches `build.rs`).
5. Captures the dependency tree (`cargo tree`).

The auditor can run this to verify the build is reproducible.

## 5. Known limitations

We are explicit about what Soteria does *not* claim:

1. **Not FIPS 140-3 certified.** Soteria is FIPS-*ready* (uses
   `ring`-validated primitives, has self-tests, has a security
   policy draft). Certification is a 6–12 month NIST lab process
   and is on the roadmap.
2. **Not protected against a compromised host OS.**
3. **Not protected against physical coercion.**
4. **Not protected against hardware backdoors** in CPU, TPM,
   or RNG silicon.
5. **Side-channel mitigations** are in the *extras* layer
   (`defense::constant_time`, OMEGA TEMPEST), not the TCB.

## 6. Contact

- **Security email:** TBD (will be set up before audit).
- **PGP key:** TBD.
- **Disclosure policy:** [SECURITY.md](../../SECURITY.md) (TBD).
- **Bug-bounty program:** Not yet. The audit is a prerequisite.

## 7. Auditor checklist

Use this checklist to track the audit:

- [ ] TCB compilation clean (`cargo build --lib`, `--features fips`)
- [ ] TCB tests pass (`cargo test --lib`)
- [ ] AES-256-XTS matches IEEE 1619 vector
- [ ] AES-256-GCM matches SP 800-38D vectors (CAVP)
- [ ] HKDF-SHA-256 matches RFC 5869 vectors
- [ ] Argon2id cost validation correct
- [ ] Master key zeroized on drop
- [ ] Slot table header HMAC verifies
- [ ] Slot table GCM AAD binds metadata
- [ ] FDE v4 layered derivation is layered (not single-step)
- [ ] FDE XTS key check is constant-time
- [ ] FDE hidden volume midpoint lookup is correct
- [ ] FUSE `release`/`forget` clean up state
- [ ] FUSE `fsync` propagates to disk
- [ ] FUSE no privileged operations
- [ ] Erasure coding `n > k`; recovery from `k` shards
- [ ] Erasure coding AEAD AAD binds shard index
- [ ] Metadata AEAD AAD binds `kind` and `VolumeContext`
- [ ] No `unsafe` outside `crypto_engine` (verify with
      `cargo geiger`)
- [ ] No MD5, SHA-1, or other deprecated primitives
- [ ] All `Result<_, _>` errors are inspected (no `unwrap` in
      production paths; verify with `cargo clippy -- -D clippy::unwrap_used`)
- [ ] `cargo audit` clean (no advisories)
- [ ] `cargo deny check` clean (license + advisory)
- [ ] `cargo build --release` reproducible

## 8. What we are NOT asking the auditor to do

- **Penetration test the host OS.** Out of scope.
- **Test hardware backdoors.** Out of scope.
- **Validate against side-channel attacks on the host.** Out of
  scope; we have a separate side-channel roadmap.
- **Audit the extras modules in depth.** Operational, not
  cryptographic.
- **Audit the build infrastructure (CI).** Sampling only.
- **Audit third-party crates.** Crates are pinned and
  `cargo deny`-checked; the auditor may sample but is not
  expected to do a full third-party review.
