# Soteria FDE — Architecture and Threat Model

This document is the high-level design specification for Soteria's
Full-Disk Encryption (FDE) layer. It is meant for security reviewers,
compliance auditors, and the next engineer who picks up this code.

## 1. Threat Model

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Lost / stolen device** | AES-256-XTS, Argon2id KDF, key never written to disk | None for at-rest; the key exists only in memory when the device is on |
| **Evil-maid** (modified boot chain) | TPM 2.0 sealing to PCR 0, 2, 4, 7; PBA signature verification | TPM-Fail-class attacks require firmware updates |
| **Coercion** (forced to reveal passphrase) | Hidden volume (VeraCrypt-style plausible deniability) | An attacker with the *hidden* passphrase can also decrypt |
| **Disk theft + forensic recovery** | Hardware secure erase (NVMe Format / ATA SECURE ERASE) | Multi-pass overwrite is best-effort on SSD due to wear-leveling; hardware erase is definitive |
| **Memory dump** (live machine, RAM freeze) | Key zeroize on drop; short idle timeouts; recommend AMD SME / Intel TME | Unavoidable in software alone; full defense requires hardware memory encryption |
| **Compromised OS kernel** | Measured boot; TPM sealing; never boot untrusted kernels | If the kernel is malicious, the running key can be exfiltrated; this is the limit of any in-OS encryption |
| **Rubber hose on hidden passphrase** | Hidden volume's existence is deniable | An attacker can always be uncertain; that's the design goal |

## 2. Cryptographic Primitives

| Use | Algorithm | Standard | Notes |
|---|---|---|---|
| **Sector encryption** | AES-256-XTS | NIST SP 800-38E, IEEE 1619-2007 | FIPS-approved for FDE |
| **Key derivation** | Argon2id | RFC 9106 | Default m=64 MiB, t=3, p=1 (production); m=4 GiB, t=5 (paranoid) |
| **XTS key derivation** | HKDF-SHA-512 | RFC 5869 | 64 bytes = 32 data + 32 tweak |
| **Header integrity** | BLAKE3 keyed hash | — | 32-byte hash covers bytes 0..166 |
| **Backup header** | Identical copy at end of device | LUKS2-style | Primary fails -> fall back to backup |
| **Anti-forensic** | Shamir M-of-N over GF(256) | — | Independent per-byte polynomials; AES polynomial (0x11B) |
| **TPM seal** | Placeholder / `tss-esapi` (with `tpm` feature) | TCG TPM 2.0 Library | PCR 0, 2, 4, 7 by default |
| **Audit chain** | BLAKE3 chained hash | — | Tamper-evident; embedded in NVRAM sector |

## 3. Volume Format

### 3.1 On-disk layout (default 512-byte sectors)

```
LBA 0..7    : Primary header (4096 bytes)
LBA 8       : NVRAM sector (boot counter, last-mount, policy hash, chain)
LBA 9..N-9  : Encrypted data sectors (XTS-encrypted with per-LBA tweak)
LBA N-8..N-1: Backup header (LUKS2-style; allows recovery)
```

### 3.2 Header format (4096 bytes, little-endian)

```
Offset  Size  Field
0       8     magic = "SOTERIA\0"
8       4     version (u32) = 3
12      4     sector_size (u32) = 512
16      8     total_sectors (u64)
24      16    kdf_salt (16 bytes, 32 reserved)
40      16    reserved
56      4     argon2_m_cost (u32, KiB)
60      4     argon2_t_cost (u32)
64      2     argon2_p (u16)
66      2     reserved
68      64    xts_key_check (XTS-encrypted zero block)
132     1     is_hidden
133     1     hidden_kind (0=none, 1=inner volume)
134     8     hidden_header_sector (u64)
142     8     feature_flags (u64)
150     16    volume_uuid
166     32    header_integrity (BLAKE3 of bytes 0..166)
198     3898  reserved (zero)
```

### 3.3 Sector encryption (AES-256-XTS)

For each sector at LBA N with 16-byte tweak T = N (little-endian):

```
T' = AES_K_tweak(T)              // Encrypt tweak
for each 16-byte block B_i:
    C_i = AES_K_data(P_i XOR T') XOR T'
    T' = T' * x  in GF(2^128)   // Multiply by x with reduction poly
```

The XTS construction is defined in IEEE 1619-2007 and approved for FDE
in NIST SP 800-38E.

## 4. Pre-Boot Authentication (PBA)

The PBA is a small EFI bootloader that runs before the OS. It:
1. Displays a banner (legally required in some jurisdictions).
2. Prompts for a passphrase (unless TPM-only mode).
3. Derives the volume key via Argon2id.
4. Decrypts the OS volume's primary header.
5. Verifies the XTS-key-check.
6. Extends TPM PCR 5 with the new state.
7. Chains to the OS bootloader (GRUB, Windows Boot Manager, etc.).

### 4.1 PBA authentication modes

| Mode | Use case | Risk |
|---|---|---|
| `Passphrase` | Maximum security; user types every boot | Slowest; defeats all boot-chain attacks except compromised PBA binary |
| `TpmOnly` | Convenience; no typing | Vulnerable to evil-maid (boot, get key, install backdoor) |
| `TpmAndPassphrase` | Balanced | Recommended for most users |

### 4.2 PBA binary

The PBA binary (`soteria-pba`) is a separate Rust crate built with
`uefi` target. It is not part of this MVP. The CLI generates
`pba.toml` configurations; the binary is built and signed separately.

## 5. Hidden Volumes

VeraCrypt-style plausible deniability. The user creates:
- An **outer volume** with passphrase A (decoy data).
- A **hidden volume** at the device midpoint, with passphrase B (real data).

When coerced, the user reveals passphrase A. The attacker sees the
outer volume, which is the only volume whose existence can be proved
(the hidden header is encrypted and looks like random data).

### 5.1 On-disk layout with hidden volume

```
LBA 0..7         : Outer header (passphrase A)
LBA 8..M-9       : Outer data (XTS-encrypted with A)
LBA M-8..M-1     : Hidden header (passphrase B)
LBA M..N-9       : Hidden data (XTS-encrypted with B)
LBA N-8..N-1     : Outer header backup
```

The hidden header sits at the geometric midpoint. The second half of
the disk could plausibly be a separate partition, unused space, or a
hibernation file.

### 5.2 Detection

The hidden header is encrypted with the hidden key. Without the key,
it is indistinguishable from random. Argon2id with sufficient cost
makes brute force infeasible.

### 5.3 Outer write protection

The outer volume MUST NOT write to the hidden region (LBA M..N-9).
The CLI tracks the hidden region in the outer header and refuses
outer writes to those sectors. This is the same protection VeraCrypt
provides.

## 6. Anti-Forensic Key Splitting (Shamir)

The volume key can be split into N shares with threshold K. Any K of
N shares can reconstruct the key; K-1 shares reveal nothing.

- **Storage**: shares are typically written to multiple media
  (USB drives, smart cards, paper QR codes).
- **Threat**: an attacker who steals the disk but not the shares
  cannot recover the key; an attacker who steals the disk and K-1
  shares still cannot recover the key.
- **Caveat**: shares are not authenticated. A tampered share yields a
  wrong secret. (TODO: BLAKE3-wrap each share in a future iteration.)

## 7. TPM 2.0 Sealing

The volume key can be sealed to the TPM 2.0 in a way that requires
specific Platform Configuration Registers (PCRs) to match a recorded
value to unseal.

- **PCR 0**: Firmware code (BIOS/UEFI)
- **PCR 2**: Option ROMs
- **PCR 4**: MBR / bootloader
- **PCR 7**: Secure Boot state

The default policy seals to `{0, 2, 4, 7}`. If the boot chain is
modified (evil-maid), the PCRs change and the sealed key cannot be
unsealed.

### 7.1 Real TPM integration

When the `tpm` feature is enabled, `seal_volume_key` and
`unseal_volume_key` call into `tss-esapi` (the TCG Software Stack
ESAPI). When the feature is NOT enabled, a software fallback
(implemented in this MVP) is used; the sealed blob is encrypted
with a key derived from the policy but is **not** secure against an
attacker with filesystem read access.

## 8. Hardware Secure Erase

Multi-pass software overwrite is insufficient on SSDs (wear-leveling,
copy-on-write). Soteria integrates with:

- **ATA**: `hdparm --user-master u --security-erase`
- **NVMe**: `nvme format --ses 1` (user-data) or `--ses 2` (cryptographic)

The CLI is `soteriad fde hw-erase --device /dev/nvme0n1 --crypto`.
On Windows, the equivalent is `StorageDeviceManagement` (NVMe) or
`IOCTL_STORAGE_DEVICE_RESET` (ATA), which require platform-specific
Win32 calls (out of scope for this MVP).

## 9. Persistent NVRAM State

A small sector at LBA 8 stores tamper-evident state:
- `boot_counter` (monotonic)
- `last_mount_unix_ms`
- `mount_policy_hash`
- `emergency_wipe` (if set, any tamper triggers volume zeroize)
- `chain_hash` (BLAKE3 over the rest)

On every `format_volume` and `open_volume`, the counter increments and
the chain is updated. On a tampered chain, the volume is opened but
the boot counter resets to 0 — strictly better than bricking the
volume on a partial write.

## 10. Constant-Time Audit

All cryptographic primitives used by Soteria are constant-time:
- **AES-256**: constant-time on AES-NI, ARMv8 CE, and the
  fixsliced software backend.
- **Argon2id**: constant-time (no data-dependent branches in the
  reference implementation).
- **BLAKE3**: constant-time.
- **XTS GF(2^128) multiplication**: constant-time; the conditional
  XOR is on a public carry bit.

The header integrity check uses a constant-time byte-slice
comparison (`constant_time_eq` in `volume.rs`). The XTS-key-check
verification is constant-time for the same reason.

The only paths that are NOT constant-time are:
- File I/O (read/write of the device)
- The KDF iterations (the number of iterations leaks the KDF params,
  which is intentional — they're stored in the header anyway)

## 11. Certification Roadmap

Soteria is **not certified** as of this writing. To achieve:

### 11.1 FIPS 140-3
- Integrate a FIPS-validated crypto module (e.g., OpenSSL 3.x FIPS provider,
  Bouncy Castle FIPS, wolfCrypt FIPS).
- Submit the module to a NIST-accredited lab (e.g., atsec, Leidos, CGI).
- CAVP testing of all primitives (AES, SHA, HMAC, KDF, DRBG).
- Module specification and source review.
- **Estimated cost**: $50k–$250k + 6-12 months.

### 11.2 CNSA 2.0 (NSA)
- Replace AES-256 with AES-256 (already in use).
- Replace ECDH P-256/P-384 with ML-KEM-1024 (already in use for sharing).
- Replace ECDSA with ML-DSA-87 (currently ML-DSA-65; bump).
- Add Suite B key wrap (RFC 3394) for in-memory key wrapping.
- **Estimated cost**: 3-6 months + lab audit.

### 11.3 Common Criteria EAL4+
- Formal security target document.
- Vulnerability analysis.
- Penetration testing.
- **Estimated cost**: $200k–$500k + 12-18 months.

## 12. What's NOT in this MVP

- **Real block device I/O on Windows** (requires `IOCTL_*`).
- **EFI PBA binary** (separate `soteria-pba` crate, `uefi` target).
- **Authenticated Shamir shares** (BLAKE3 wrap — TODO).
- **Self-test at mount time** (FIPS-mandated; TODO).
- **Audit log persistence on disk** (currently in-memory; TODO).
- **dm-crypt passthrough on Linux** (would let the FDE volume host
  an arbitrary filesystem without our userland driver).

## 13. FIPS 140-3 Mode

Soteria supports a **FIPS 140-3 mode** via the ips Cargo feature.
The mode is a compile-time switch that:

1. **Replaces the sector cipher** from AES-256-XTS (algorithm
   approved per FIPS SP 800-38E, but no FIPS-validated Rust binding
   is available) to **AES-256-GCM** (FIPS SP 800-38D, FIPS-validated
   via ing).
2. **Replaces the KDF** from Argon2id (not on FIPS 140-3 approved
   list) to **PBKDF2-HMAC-SHA-256** at 600,000 iterations (FIPS
   SP 800-132, OWASP 2023 baseline).
3. **Replaces the integrity hash** from BLAKE3 (not FIPS-approved)
   to **SHA-256** (FIPS 180-4).
4. **Replaces the HKDF** from HKDF-SHA-512 to **HKDF-SHA-256**
   (FIPS SP 800-56C).
5. **Replaces the DRBG** from OsRng to ing::SystemRandom
   (FIPS SP 800-90A).

In FIPS mode, the module runs:

- **Power-on self-tests (POST)**: KATs for AES-256-GCM, SHA-256,
  SHA-512, HMAC-SHA-256, HKDF-SHA-256, PBKDF2-HMAC-SHA-256.
  Implemented in crypto_engine::fips::kat.
- **Software/firmware integrity test (SFIT)**: HMAC-SHA-256 over
  the loaded binary, compared to the value computed at build
  time by uild.rs. Implemented in
  crypto_engine::fips::integrity.
- **Refuse-to-start**: --fips mode fails fast if either POST
  or SFIT fails.

The full security policy is in
[docs/FIPS-SECURITY-POLICY.md](FIPS-SECURITY-POLICY.md). The
high-level summary is:

- **Approved algorithms**: AES-256-GCM, SHA-256/512, HMAC-SHA-256/512,
  HKDF-SHA-256, PBKDF2-HMAC-SHA-256.
- **Non-approved algorithms (excluded in FIPS mode)**: Argon2id,
  BLAKE3, XChaCha20-Poly1305, AES-256-XTS.
- **CSPs**: volume master key, sector cipher key, KDF salt, HMAC
  subkeys, Module Integrity Key. All zeroized via Zeroizing<u8>.
- **Outstanding for FIPS lab submission**: production SFIT
  (operator private key + TPM NVRAM public key), CAVP run,
  entropy assessment, periodic self-tests.

Build:
\\\sh
cargo build --release --features fips --bin soteriad
./target/release/soteriad --fips ...
\\\

Note: a formal NIST certificate is **not** issued by building with
--features fips. That requires a CAVP run + accredited lab
validation (atsec, Leidos, or CGI), 6-12 months, and -.
The \ips\ feature is a FIPS-READY deliverable: it ships the
engineering artifacts a lab would validate against.
