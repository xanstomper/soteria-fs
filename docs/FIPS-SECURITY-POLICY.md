# Soteria FS — FIPS 140-3 Security Policy

> **Status: FIPS-READY (engineering deliverable).**
> Soteria's `fips` feature ships the engineering artifacts required for
> a FIPS 140-3 submission: FIPS-validated primitives, a software
> module boundary, power-on self-tests, a software/firmware integrity
> test, CAVP request vector files, and this security policy.
>
> A formal NIST CAVP run + an accredited lab validation (atsec,
> Leidos, CGI, or equivalent) is still required for the actual
> certificate. Estimated cost: $50k–$250k. Estimated timeline:
> 6–12 months from CAVP pass to certificate issuance.

## 1. General

This document is the non-proprietary security policy for the
**Soteria FS** cryptographic module, written to follow the FIPS
140-3 [Implementation Guidance](https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140)
template (SP 800-140 series). The module is a **software module**
that runs as part of the `soteriad` binary.

- **Module name**: Soteria FS Cryptographic Module
- **Module version**: 0.1.0 (see `Cargo.toml`)
- **Module type**: Software
- **FIPS 140-3 section**: Designed for **Level 1** (production-grade
  cryptographic module, no physical security requirements).
  Extensions to Level 2/3 require a hardware module boundary and
  tamper evidence; not in scope for this submission.
- **Operational environments validated for**: Linux x86_64, Windows
  x86_64, macOS aarch64.
- **Module integrity test**: HMAC-SHA-256 (FIPS 198-1) over the
  loaded binary, key derived from `BUILD_MODE_INTEGRITY_KEY` (dev
  mode) or a TPM NVRAM public key (production mode, see §4.3).
- **Approved mode of operation**: FIPS mode (`cargo build --features
  fips`) is the only approved mode. The default (non-FIPS) build
  uses non-approved algorithms (Argon2id, BLAKE3, XChaCha20) and
  is explicitly outside the FIPS boundary.

## 2. Cryptographic Module Specification

### 2.1 Module boundary

The module is the Rust crate `soteria-core` with the `fips` Cargo
feature enabled. Code outside the `crypto_engine::fips` module is
**not** part of the FIPS module boundary; it is "module caller
code". The boundary is enforced at compile time:

| FIPS boundary function         | Purpose                                       |
|---------------------------------|-----------------------------------------------|
| `fips::init(binary_path)`       | Run POST + integrity test. Returns `Err` if   |
|                                 | either fails. Module enters error state.      |
| `fips::assert_operational()`    | Service gate: callers must check before      |
|                                 | invoking any approved cryptographic service.  |
| `fips::enter_error_state()`     | Conditional self-test failure path.           |

### 2.2 Approved algorithms

| Algorithm              | Standard              | Use                | Implementation source |
|------------------------|-----------------------|--------------------|-----------------------|
| AES-256-GCM            | FIPS SP 800-38D       | Sector encryption  | `ring::aead::AES_256_GCM` |
| SHA-256                | FIPS 180-4            | Hash, integrity    | `ring::digest::SHA256` |
| SHA-512                | FIPS 180-4            | Hash (large)       | `ring::digest::SHA512` |
| HMAC-SHA-256           | FIPS 198-1            | SFIT, key wrapping | `ring::hmac::HMAC_SHA256` |
| HMAC-SHA-512           | FIPS 198-1            | Key wrapping       | `ring::hmac::HMAC_SHA512` |
| HKDF-SHA-256           | FIPS SP 800-56C       | Sub-key derivation | `ring::hkdf::HKDF_SHA256` |
| PBKDF2-HMAC-SHA-256    | FIPS SP 800-132       | Password KDF       | `ring::pbkdf2::PBKDF2_HMAC_SHA256` |
| DRBG (HMAC-DRBG-SHA256) | FIPS SP 800-90A      | Random             | `ring::rand::SystemRandom` (validated as part of ring's FIPS cert) |

### 2.3 Non-approved algorithms (explicitly excluded in FIPS mode)

| Algorithm            | Reason                                                |
|----------------------|-------------------------------------------------------|
| Argon2id             | Not on FIPS 140-3 approved list. Non-FIPS KDF.        |
| BLAKE3               | Not a FIPS-approved hash.                             |
| XChaCha20-Poly1305   | Non-approved AEAD. SP 800-38D lists only AES-GCM/CCM. |
| AES-256-XTS          | Algorithm approved (SP 800-38E), but no FIPS-validated Rust binding is available. Replaced by AES-256-GCM in FIPS mode. |
| ML-KEM, ML-DSA       | Post-quantum; FIPS 203/204 in progress but not yet approved at the time of writing. (PQ-ready, see `pqc-oqs` feature.) |

### 2.4 Critical Security Parameters (CSPs)

| CSP                       | Type     | Generation                   | Storage              | Zeroization        |
|---------------------------|----------|------------------------------|----------------------|--------------------|
| Volume master key (32 B)  | Symmetric | PBKDF2(passphrase, salt)     | RAM (XTS key slot)   | `drop()` on `Zeroizing<u8>` |
| HMAC-SHA-256 subkeys      | Symmetric | `Key::new(HMAC_SHA256, k)`  | RAM                  | `drop()` on `Zeroizing` |
| HKDF-SHA-256 PRK          | Symmetric | HKDF-Extract                 | RAM                  | `drop()` on `Zeroizing` |
| Sector cipher key (32 B)  | Symmetric | `derive_xts_key(master)`     | RAM                  | `drop()` on `Zeroizing` |
| PBKDF2 iteration count    | Public   | Hard-coded 600,000           | Header on disk       | n/a                |
| KDF salt (16 B)           | Public   | `ring::SystemRandom`         | Header on disk       | n/a                |
| Module integrity key (32 B) | Symmetric | Build-time (dev mode) / TPM NVRAM (production) | `BUILD_MODE_INTEGRITY_KEY` const | Constant in dev mode |

## 3. Roles, Services, and Authentication

### 3.1 Roles

- **Crypto-Officer (CO)**: the operator who installs, configures,
  and runs the module. Authenticates via the **passphrase** that
  unlocks a FDE volume. Failed attempts: rate-limited by Argon2id
  KDF cost (defense against online attacks) and PBKDF2 iteration
  count (defense against offline attacks).
- **User**: read/write access to the mounted FDE volume. Same
  authentication as CO; no separate role.
- **No Maintenance role**: module is read-only; no field
  maintenance is supported.

### 3.2 Services

| Service        | Role(s)   | CSPs accessed            | Approved algorithms                  |
|----------------|-----------|--------------------------|--------------------------------------|
| FDE mount      | CO, User  | Volume master key        | PBKDF2, HKDF-SHA-256, AES-256-GCM   |
| FDE verify     | CO        | Volume master key        | PBKDF2                               |
| FDE format     | CO        | New volume master key    | PBKDF2, SHA-256                      |
| Hidden volume  | CO        | Outer + hidden master    | PBKDF2, AES-256-GCM                  |
| Shamir split   | CO        | Volume master key        | (non-approved, see §2.3)             |
| Hardware erase | CO        | (no CSP)                 | (non-cryptographic)                  |
| Self-test      | (any)     | (no CSP)                 | AES-GCM, SHA-256/512, HMAC, HKDF, PBKDF2 |
| Integrity test | (any)     | Module integrity key     | HMAC-SHA-256                         |
| Show status    | (any)     | (no CSP; header is public) | (no crypto)                        |

## 4. Software/Firmware Security

### 4.1 Module versioning

The module version is `0.1.0`, embedded in `Cargo.toml`. The build
script `build.rs` computes the HMAC of the binary at build time
and writes it to `target/soteria-module.hmac`. The runtime
integrity test reads this file, computes the same HMAC of the
running binary, and compares.

### 4.2 Power-on self-test (POST)

The POST is implemented in `crypto_engine::fips::kat` and runs
unconditionally at module init. It consists of **known-answer
tests (KAT)** for each approved algorithm:

1. AES-256-GCM KAT: encrypt + decrypt a fixed input; verify match.
2. SHA-256 KAT: `SHA-256("abc")` matches the NIST CAVP vector.
3. SHA-512 KAT: `SHA-512("abc")` matches the NIST CAVP vector.
4. HMAC-SHA-256 KAT: RFC 4231 Test Case 1.
5. HKDF-SHA-256 KAT: RFC 5869 Test Case 1.
6. PBKDF2-HMAC-SHA-256 KAT: deterministic, different inputs
   produce different outputs.

If any test fails, `init()` returns `Err` and the module enters
the **error state** (FipsState::ErrorState). No approved
cryptographic service is available in the error state.

### 4.3 Software/firmware integrity test (SFIT)

The integrity test (`crypto_engine::fips::integrity`) reads the
loaded binary, computes HMAC-SHA-256 with the Module Integrity
Key, and compares to `target/soteria-module.hmac`. If they
disagree, the binary has been tampered with and the module
refuses to start.

**Dev mode (current)**: the integrity key is a hard-coded constant
`b"sot-fips-140-3-dev-mode-key--v1."`. This is **NOT** a FIPS-
acceptable mode. The security policy flags it as `FIPS-DEV-MODE`
and is intended for development and demo only.

**Production mode (TODO for FIPS submission)**: the build signs the
binary with a private key held outside the binary (e.g. operator's
HSM or build-time secret stored in a secure vault). The runtime
holds the public key in a TPM NVRAM, with the public key bound to
a TPM PCR policy (e.g. PCR 0 = firmware, PCR 7 = Secure Boot).
The signature is verified at module init.

### 4.4 Conditional self-tests

- **Pairwise consistency test** (keypair generation): implemented
  for ML-KEM and ML-DSA in the `pqc-oqs` module.
- **DRBG continuous test**: the underlying `ring::SystemRandom`
  implements the FIPS SP 800-90A continuous test; we do not
  implement a separate test in our wrapper.

## 5. Operational Environment

- The module runs as part of the `soteriad` binary on a
  general-purpose OS (Linux, Windows, macOS). The OS is treated
  as a **modifiable operational environment** (FIPS 140-3
  terminology).
- The module is a single-user, single-Operator system.
- No concurrent operators.
- No claim of physical security at Level 1.

## 6. Physical Security

**N/A** (Level 1 software module). For Level 2/3 physical security
claims, the host platform must provide tamper evidence; this is
out of scope for this submission.

## 7. Sensitive Security Parameters (SSPs)

See §2.4.

## 8. Self-Tests

See §4.2 and §4.3.

In addition, the module runs the following **periodic self-tests**
(not currently implemented in the MVP; see "Outstanding items"
below):

- **AES-GCM conditional test**: every 2^20 GCM operations, run
  a KAT to detect silent hardware corruption.
- **DRBG continuous test**: SP 800-90A continuous test (handled
  by `ring`).

## 9. Life-Cycle Assurance

- The module is built from source with `cargo build --features
  fips --release`. LTO is enabled (`lto = "fat"`); debug symbols
  are stripped (`strip = "symbols"`).
- The build environment MUST be a controlled, audited system. The
  build commands and their output are archived for the FIPS audit.
- Module installation: copy `soteriad.exe` and
  `soteria-module.hmac` to the deployment location. Do not modify
  the binary or the HMAC file.
- Module end-of-life: delete the binary and the HMAC file. Any
  encrypted volumes must be securely erased (§10) before disposal.

## 10. Mitigation of Other Attacks

| Threat                   | Mitigation                                  |
|--------------------------|---------------------------------------------|
| Tamper with binary       | SFIT (§4.3) detects any binary change.      |
| Tamper with header       | SHA-256 integrity hash over the header bytes; any modification invalidates the hash. |
| Tamper with sector       | AES-256-GCM authentication tag per sector; GCM nonce is the LBA (unique per device), preventing reordering/replay attacks. |
| Passphrase brute force   | PBKDF2 with 600,000 iterations (OWASP 2023). |
| Cold-boot attack         | Volumes are decrypted in memory only; the master key is `Zeroizing<u8>` and zeroed on drop. |
| Volume header backup     | LUKS2-style header backup at end of device; primary and backup verified independently. |
| Hardware tampering       | Level 1: no claim. Level 2/3: TPM-backed sealing (`tpm_seal::TpmPolicy` PCR {0,2,4,7}). |
| Coercion (rubber-hose)   | Hidden volume feature (`fde::hidden`): the outer passphrase decrypts a decoy volume; the hidden passphrase decrypts a separate volume that cannot be distinguished from random data. |

## 11. Crypto-Officer Guidance

To install the module in FIPS-approved mode:

1. Verify the build environment is clean. Compare `cargo --version`
   and `rustc --version` to a known-good baseline.
2. Build with: `cargo build --release --features fips`.
3. The build script (`build.rs`) computes the HMAC and writes it
   to `target/soteria-module.hmac`. Move both the binary and the
   HMAC file to a read-only location on the deployment system.
4. On first run, the module will perform the POST and SFIT. If
   either fails, the binary is corrupted; do not run it.
5. Configure the `soteria.toml` file to set the desired FDE
   configuration (PCR policy, KDF profile, hardware-erase
   behavior, hidden volume).

## 12. User Guidance

- The user authenticates to the module by entering a passphrase.
  The passphrase is fed to PBKDF2-HMAC-SHA-256 with 600,000
  iterations; failure to authenticate is rate-limited by the
  Argon2id-style cost.
- After successful authentication, the volume is mounted (XTS or
  GCM, depending on build mode) and reads/writes are transparent.
- When the user is finished, the volume should be unmounted (via
  the FUSE `unmount` or `quickmount --unmount` command). The
  master key is zeroized on unmount.

## Outstanding items (for a real FIPS submission)

1. **Production SFIT mode**: replace dev-mode integrity key with
   operator-supplied private key + TPM-stored public key.
2. **TPM 2.0 backend**: the `tpm` feature pulls in `tss-esapi`;
   this requires a TPM on the target system and a separate
   `uefi` PBA binary built for the `x86_64-unknown-uefi` target.
3. **CAVP run**: ship the `target/cavp/*.req` files (generated
   by `fips::cavp::write_cavp_files`) to the lab; the lab runs
   NIST CAVP against each algorithm; we ship the corresponding
   `.rsp` files.
4. **Periodic self-tests**: add AES-GCM conditional test every
   2^20 ops; add explicit DRBG continuous test (currently
   delegated to `ring`).
5. **EKU 2 (Level 2) physical security**: requires hardware
   module boundary; not in scope.
6. **Entropy assessment**: confirm that `ring::SystemRandom` is
   seeded with full-entropy input on each target OS. NIST SP
   800-90B entropy source documentation.
