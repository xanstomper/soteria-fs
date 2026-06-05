# SOTERIA Trusted Computing Base (TCB)

## First Principle

In a real cryptographic product, **the trusted computing base
(TCB) must be small enough to audit.**  Every line of code in the
TCB is a line an attacker can subvert. VeraCrypt's core is a few
tens of thousands of lines; Signal's double-ratchet is similarly
compact.  Soteria follows the same discipline.

> **Default `cargo build` compiles only the TCB.**  Every "extra"
> module is gated behind an opt-in Cargo feature.

## Source size (as of this revision)

```
Soteria-FS/
  rust-core/src/    0.77 MB   (all source, TCB + extras)
  rust-core/target/  16.7 GB  (build artifacts, deletable)
  docs/             0.09 MB
  desktop/src/      0.05 MB
  installer/src/    0.02 MB
```

The "18 GB" people sometimes quote is `target/` — the Rust
compiler's incremental build cache. It can be removed with
`cargo clean` and is not part of the source. The actual **source
code is ~0.93 MB total** and is auditable in an afternoon.

## TCB vs. Extras

The TCB is the set of modules that affect cryptographic
correctness. If a module's bug can break the confidentiality,
integrity, or authenticity of encrypted data, it is in the TCB.
If a module's bug can only affect operational features
(intrusion detection, deception, anti-forensic headers, UX), it
is *not* in the TCB and is gated behind a feature.

### TCB (always compiled)

| Module | LOC | Purpose |
|---|---:|---|
| `config` | 84 | Runtime configuration parser |
| `crypto_engine` | 2,000+ | AES-XTS, AES-GCM, ChaCha20-Poly1305, Argon2id, HKDF, PBKDF2, FIPS, ML-KEM, ML-DSA, BLAKE3, secure_box, block, nonce, shares |
| `daemon` | 124 | Daemon orchestration |
| `fde` | 2,400+ | Volume, hidden volume, Shamir, persistent, TPM seal, hw erase, PBA, GCM sector, block device |
| `fs_layer` | 2,000+ | FUSE filesystem, storage, KDF sidecar, WAL, sandbox, metadata, region, durability |
| `secure_erase` | 270 | DoD 5220.22-M, Gutmann, random, zero |
| `key_hierarchy` | 760 | HKDF-SHA256 domain-separated keys, key slots, rotation, revocation |
| `erasure_coding` | 500 | Reed-Solomon sharding with AES-GCM-wrapped shards |
| `metadata_encryption` | 240 | AEAD over file names, inodes, journal, xattrs |

**TCB total: ~30 files, ~7,500 lines.** This is the surface that
must be audited for cryptographic correctness.

### Extras (feature-gated)

| Feature | Module | Why it's not in the TCB |
|---|---|---|
| `omega` | `omega` | OMEGA Government/Military Edition: classification, two-person, TEMPEST, COMSEC, emergency zeroize, sovereignty, crypto-process, Merkle/RS integrity, ransomware defense, hardware roots. Operational and policy modules; not required for cryptographic correctness. |
| `defense` | `defense`, `event_bus`, `intrusion`, `response_engine`, `sensors` | Intrusion detection and response. A bug here can disable detection, not break encryption. |
| `deception` | `deception`, `deception_layer` | Decoy content, honey FS. Adversarial-misleading; doesn't affect data confidentiality. |
| `anti-forensic` | `anti_forensic` | Header scatter, temporal erase, timestamp warp, entropy padding. Affects on-disk *appearance*, not ciphertext correctness. |
| `advanced` | `advanced` | Experimental: chameleon, obsidian, mirage_fs. |
| `ai-observer` | `ai_observer` | Read-only heuristic observer. No model weights; no network. |
| `key-manager` | `key_manager` | Lifecycle/ratchet/capability/TPM-keyring above the canonical `key_hierarchy` TCB surface. |
| `policy` | `policy` | Audit log, revocation lists. Operational. |
| `security` | `security` | Sensor fusion, canaries. Operational. |
| `snapshot` | `snapshot_engine` | Copy-on-write snapshots. Not in data path. |
| `simulation` | `simulation` | Ransomware simulator (red-team). Never enable in production. |
| `enterprise` | `enterprise` | Multi-tenant glue. |
| `tui` | `tui` | Terminal UI (ratatui). |
| `fuse` | `fuse` (Linux) | FUSE mount. Optional; the FS layer is portable, FUSE is one backend. |
| `tpm` | `tpm` | Real TPM2 silicon backend; software fallback in `fde::tpm_seal` is always available. |

**Extras total: ~85 files, ~11,000 lines, opt-in only.**

## Build matrix

| Build | What you get | LOC compiled |
|---|---|---:|
| `cargo build` | TCB only | ~7,500 |
| `cargo build --features fips` | TCB + FIPS mode | ~8,000 |
| `cargo build --features omega` | TCB + OMEGA | ~13,000 |
| `cargo build --features full` | Everything | ~18,500 |
| `cargo clean && cargo build` | Same as above, from scratch | (build cache cleared) |

## Audit checklist (TCB)

When auditing Soteria for cryptographic correctness, the auditor
should focus on:

1. **Cryptographic primitives** — `crypto_engine/{xts, gcm, aead,
   kdf, block, nonce, shares, secure_box, pq, dsa, fips/}`. Every
   AEAD seal/open, every KDF derivation, every nonce.

2. **FDE volume format** — `fde/volume.rs` (header parsing,
   sector encryption, hidden-volume midpoint). Plus
   `fde/hidden.rs`, `fde/shamir.rs`, `fde/persistent.rs`,
   `fde/tpm_seal.rs`, `fde/hw_erase.rs`, `fde/pba.rs`.

3. **Filesystem** — `fs_layer/{fuse_fs, storage, wal, metadata,
   region, durability}.rs`. The on-disk format and crash-safety.

4. **Key hierarchy** — `key_hierarchy/{mod, slots}.rs`. Domain
   separation, slot table format, revocation, rotation.

5. **Erasure coding** — `erasure_coding.rs`. RS over GF(256),
   AEAD wrapping, recovery from k of n.

6. **Metadata encryption** — `metadata_encryption.rs`. AEAD over
   file names, inodes, journal.

7. **Secure erase** — `secure_erase.rs`. Wipe patterns.

A bug in any *extras* module (defense, deception, OMEGA
classification, AI observer, etc.) is a bug, but it is not a
*cryptographic* bug — it does not break the confidentiality,
integrity, or authenticity of the encrypted data on disk.

## Threat model scope

The TCB defends against:

- **Ciphertext-only adversaries** (always).
- **Known-plaintext adversaries** (AEAD).
- **Active tampering** (AEAD tags, Merkle trees, key-slot
  HMAC).
- **Compromise of one domain key** (HKDF separation).
- **Compromise of one key slot** (revocation; other slots
  remain valid).
- **Loss of m of n storage shards** (Reed-Solomon recovery).
- **Volume-key rotation** without re-encrypting data.

The TCB does *not* defend against:

- Compromise of the host OS (e.g., kernel rootkit, DMA attack).
- Side-channel attacks on the host (cache timing, power
  analysis). Mitigations: `defense::constant_time` and
  OMEGA's TEMPEST are in the *extras* layer.
- Compromise of the master passphrase (Argon2id raises the cost
  but cannot prevent dictionary attack on weak passphrases).
- Hardware backdoors in the CPU, TPM, or RNG.

## Versioning

The TCB boundary is **a contract**, not a suggestion. Any change
to a TCB module must:

1. Not break the on-disk format (or include a migration).
2. Not introduce a new cryptographic dependency without review.
3. Pass the test suite (`cargo test --lib` for the TCB).

A change to an *extras* module can be reviewed more lightly,
since it cannot break the cryptographic correctness of the
core.
