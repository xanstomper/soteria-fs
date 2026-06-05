# SOTERIA-OMEGA Architecture

> **Status:** Software MVP. All components implemented as pure-Rust
> modules under `--features omega`. Hardware-dependent pieces
> (TPM 2.0, FIDO2, PUF, EARD) ship with software fallbacks that
> match the "fail-to-wiretap" pattern.

## 1. Purpose

SOTERIA-OMEGA is the Government & Military Edition of Soteria-FS. It
extends the FDE + FIPS-READY engine with defence-in-depth mechanisms
required by operators who must protect classified or sensitive
data against well-resourced, persistent, and coercive adversaries.

OMEGA is a *superset* of FDE + FIPS, not a replacement. Operators
who do not need government/military features should use the base
Soteria-FS build.

## 2. Module layout

```
rust-core/src/omega/
├── mod.rs                  — public API, IRONCLAD table generator
├── classification.rs       — Part 1: MLS (5+ level, compartments)
├── two_person.rs           — Part 2: four-eyes / 2-of-2 share release
├── tempest.rs              — Part 3: software TEMPEST (jam loop, zone policy)
├── comsec.rs               — Part 4: COMSEC custody chain + DestroyCert
├── emergency.rs            — Part 5: zeroize escalation (Panic/Duress/ColdWar)
├── sovereignty.rs          — Part 7: air-gap mode + URL/egress/NTP filter
├── crypto_process.rs       — Part 9: forked crypto process + IPC framing
├── integrity.rs            — Part 10: Merkle + Reed-Solomon RS(255,223)
├── init_flow.rs            — Parts 6/13: 6-phase init state machine
├── defense/
│   └── mod.rs              — Part 11: ransomware defence (entropy, rate, ext, ancestry)
└── hardware/
    └── mod.rs              — Part 12: TPM, FIDO2, PUF (software fallbacks)
```

Each module is a `pub mod` in `omega/mod.rs` and is fully gated by
`#[cfg(feature = "omega")]`.

## 3. The 14 parts

| # | Part                       | File                          | MVP status          |
|---|----------------------------|-------------------------------|---------------------|
| 1 | Classification & MLS       | `classification.rs`           | complete            |
| 2 | Two-Person / Four-Eyes     | `two_person.rs`               | complete            |
| 3 | TEMPEST                    | `tempest.rs`                  | software stub       |
| 4 | COMSEC Custody Chain       | `comsec.rs`                   | complete            |
| 5 | Emergency Zeroization      | `emergency.rs`                | complete            |
| 6 | Multi-Level Init Flow      | `init_flow.rs`                | complete            |
| 7 | Operational Sovereignty    | `sovereignty.rs`              | complete            |
| 8 | (Architecture)             | this document                 | complete            |
| 9 | Forked Crypto Process      | `crypto_process.rs`           | software + IPC      |
|10 | Integrity (Merkle + RS)    | `integrity.rs`                | complete            |
|11 | Ransomware Defence         | `defense/mod.rs`              | complete (Linux)    |
|12 | Hardware Root of Trust     | `hardware/mod.rs`             | software fallback   |
|13 | Init Flow                  | `init_flow.rs` (same as 6)    | complete            |
|14 | Threat Model + IRONCLAD    | `docs/THREAT-MODEL.md`        | complete            |

## 4. Process topology

```
                         +--------------------+
                         | soteriad (control) |
                         |  - CLI / audit     |
                         |  - sovereignty     |
                         |  - integrity verify|
                         +---------+----------+
                                   |  IPC over length-prefixed JSON
                                   |  (magic = "SOM1", HMAC signed)
                                   v
                         +--------------------+
                         |  crypto process    |
                         |  (data plane)      |
                         |  - master key      |
                         |  - sector cipher   |
                         |  - HMAC/PBKDF2     |
                         +---------+----------+
                                   |
                                   v
                         +--------------------+
                         |  hardware (TPM/    |
                         |  FIDO2/PUF)        |
                         +--------------------+
```

On Linux the data-plane process is created via `fork()` + capability
drop + namespace unsharing + seccomp-bpf. On Windows it is a separate
child process spawned with `CreateProcess`; the actual privilege drop
is unsupported, so the data plane must run as a Windows service with
a low-privilege account.

The IPC framing is platform-agnostic and the data-plane binary
(source) is the same on both OSes.

## 5. Data flow during a normal read

```
operator -> CLI: decrypt /mnt/foo
control plane: parse path, compute subkey via HKDF
control plane: build CryptoRequest with HMAC + nonce + deadline
control plane: send length-prefixed frame over Unix socket
data plane: verify HMAC, check deadline, dispatch to sub-routine
data plane: read encrypted block from device, AES-XTS decrypt
data plane: build CryptoResponse, return ciphertext
control plane: return plaintext to operator
```

## 6. Data flow during OMEGA init (TS/SCI)

```
operator A: persona assign (signs with ML-DSA-65)
operator B: role attest (security officer countersigns)
both      : cleared key gen (master key split via Shamir 2-of-2)
engine    : audit anchor (BLAKE3 of init event, anchor to local log)
engine    : committed publish (write OMEGA header with merkle root,
            RS-encoded root, custody genesis event, software
            attestation marker, operator identities)
witness   : witness sign (third party countersigns the header)
result    : birth certificate (BLAKE3 hash of completed phases)
```

## 7. Hardware dependencies

OMEGA's IRONCLAD table (50 mechanisms) lists 6 hardware dependencies:

| Dependency | MVP behaviour                                    |
|------------|--------------------------------------------------|
| TPM 2.0    | `TpmManager` derives a stable 32-byte "TPM key" from `/etc/machine-id` (Linux) or falls back to a constant. Status: `SoftwareFallback`. |
| FIDO2      | `Fido2Device::sign` is a deterministic BLAKE3 of `device_key || challenge`. Real YubiKey would do a CTAP2 sign. Status: `SoftwareFallback`. |
| PUF        | `PufSource::challenge` is BLAKE3 of `fingerprint || challenge`. Real silicon PUF would do an SRAM-powerup fingerprint. Status: `SoftwareFallback`. |
| /proc      | `defense::ransomware::get_process_ancestry` reads `/proc/<pid>/status`. On Windows it returns empty. |
| EARD       | `tempest::ShieldingConfig` tracks the zone, but no actual hardware jamming. Operator must pair with real EARD for Zone 3+. |
| fork()     | Process isolation via fork() on Linux, `CreateProcess` on Windows. The IPC schema is the same. |

Each module logs a `HardwareDependencyMissing` event to the audit
chain when it falls back, so an operator running in production can
spot the missing hardware.

## 8. Audit chain

OMEGA writes every state-changing event to the existing
`policy::audit_log`, which is a BLAKE3-chained append-only log. The
`comsec::CustodyEvent` chain is the COMSEC-specific sub-set of this
log; each custody event also embeds the witness signature and the
policy reference (e.g., "NISPOM 8-303").

`emergency::ZeroizeReport` and `two_person::SessionEvent` are
appended to the same log.

## 9. Build and run

```bash
# Build with OMEGA
cargo build --release --features omega

# Run a normal status check
./target/release/soteriad --features omega status

# Trigger an emergency wipe
./target/release/soteriad --features omega panic --level 3 --reason "hostile-intruder"

# Seal a 32-byte key to TPM PCRs
./target/release/soteriad --features omega omega tpm-seal \
    --key-file ./master.key --pcrs 0,2,4,7

# Print the IRONCLAD mechanism table
./target/release/soteriad --features omega omega ironclad

# Set the air-gap mode
./target/release/soteriad --features omega omega set-mode --mode air-gap
```

## 10. What OMEGA is not

- **Not a hardware TPM replacement.** A real TPM 2.0 silicon chip
  must be present; the software fallback is a stopgap for development.
- **Not a TEMPEST certification.** Hardware EARD + NISPOM-compliant
  physical installation are out of scope.
- **Not a complete MLS kernel.** The crypto and key-binding are
  enforced in software; the OS-level MAC enforcement is the
  operator's responsibility (SELinux MLS, AppArmor, etc.).
- **Not a FIPS-validated module.** The base FDE + FIPS-READY track
  ships the FIPS engineering; the OMEGA track does not add to that
  certification. If a FIPS-certified OMEGA is required, the FIPS
  module boundary must be redrawn and re-validated.
- **Not a cure for rubber-hose cryptanalysis.** If both cleared
  operators are coerced simultaneously, the data is lost. The
  organisational mitigation is dual-control assignment, polygraph,
  and continuous evaluation.

## 11. Software-fallback policy

Every OMEGA component with a hardware dependency:

1. Logs a `HardwareDependencyMissing` event to the audit log.
2. Returns a `HardwareUnavailable` result to the caller.
3. Lets the operator choose "fail closed" (refuse the operation)
   or "fail open with attestation" (proceed and sign the operation
   with a `SoftwareAttestation` marker).

This matches the NSA "fail-to-wiretap" pattern: when hardware is
missing, you must either stop or be very loud about it.

## 12. Performance

The MVP is engineered for clarity, not throughput. On a 2023-era
laptop:

- AES-256-XTS sector cipher: ~3 GiB/s (AES-NI) / ~80 MiB/s (soft)
- AES-256-GCM (FIPS): ~2.5 GiB/s (AES-NI + CLMUL)
- ML-KEM-768 keygen: ~50 µs
- ML-KEM-768 encap: ~60 µs
- ML-KEM-768 decap: ~70 µs
- ML-DSA-65 sign: ~150 µs
- ML-DSA-65 verify: ~80 µs
- BLAKE3 (1 MiB): ~1.2 ms
- Argon2id (19 MiB, 2 iter): ~80 ms
- Argon2id (4 GiB, 5 iter): ~20 s
- RS(255,223) encode 1 KiB: ~80 µs
- Merkle build (1024 leaves): ~2 ms
- Two-person key release: ~3 ms (excl. operator input)

## 13. IRONCLAD mechanism table

See `soteria-core/src/omega/mod.rs::ironclad_table()` and the
companion CLI command:

```bash
soteriad --features omega omega ironclad
```

The 50-row matrix maps each OMEGA part to its defense mechanism, the
threat it defends against, and its software/hardware dependency.

## 14. References

- NSA/CSS Policy Manual 8-303 (COMSEC key destruction)
- NIST SP 800-88 Rev 1 (Guidelines for Media Sanitization)
- NIST SP 800-131A (Transitioning the Use of Cryptographic Algorithms)
- NIST SP 800-38D (AES-GCM) and SP 800-38E (AES-XTS)
- FIPS 180-4 (SHA-256), FIPS 202 (SHA-3), FIPS 203 (ML-KEM),
  FIPS 204 (ML-DSA), FIPS 140-3 (Security Requirements)
- CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)
- IEEE 1619-2007 (XTS-AES for block-oriented storage)
- RFC 9106 (Argon2)
- RFC 5869 (HKDF)
- ISO/IEC 19790:2012 (Security requirements for cryptographic modules)
- DoD 5220.22-M (National Industrial Security Program Operating Manual)
- NISPOM (National Industrial Security Program Operating Manual)
- ATOMAL (NATO Marking Standard)
- Bell-LaPadula (1973) — Multi-Level Security reference model
