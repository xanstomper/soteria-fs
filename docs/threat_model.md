# Threat Model

> Soteria: a self-defending encrypted security platform powered by Aegis, the trusted encryption and protection core.

## Adversary classes

| Class | Capability | In scope? |
|---|---|---|
| **A1 — Local malware** | Reads/writes files, scrapes process memory, observes the filesystem. | Yes |
| **A2 — Ransomware operator** | Encrypts or destroys user files; attempts to disable defenses. | Yes |
| **A3 — Disk forensic analyst** | Steals the device or copies the raw disk; has unlimited offline time. | Yes |
| **A4 — Network attacker** | MITM, replay, or active interference on a sharing flow. | Yes (sharing only) |
| **A5 — Future-quantum adversary** | Records ciphertext today; decrypts later with a CRQC. | Yes (sharing only) |
| **A6 — Compromised kernel** | Full DMA, can read any userspace memory, can call any syscall. | Partial — see below |
| **A7 — Coercion / rubber hose** | Adversary forces the user to reveal keys. | Out of scope |
| **A8 — Firmware/UEFI/SMM rootkit** | Pre-OS, below the filesystem layer. | Out of scope |
| **A9 — Side-channel attacker with full system control** | Cache, TLB, power, EM, timing. | Out of scope |

## Trust boundaries

1. **Aegis core (trusted)** — AEAD, KDF, key ratcheting, BLAKE3 lineage, ML-KEM wrapping, ML-DSA signing, audit chain, policy engine. Must be small, auditable, deterministic.
2. **Sensors (untrusted)** — Emit events. Cannot mutate keys or take enforcement actions. May be wrong, missing, or malicious; the policy engine treats them as hints.
3. **AI observer (read-only)** — Produces risk scores from event records. `enforcement_allowed: false` is hard-coded. The policy engine may consume the score but never an action.
4. **FUSE / OS kernel (partially trusted)** — Trusted to deliver bytes between userspace and the backing store. Not trusted to keep keys confidential while the volume is mounted.
5. **Storage (untrusted at rest)** — Disk is treated as an adversary. AES-256-GCM / XChaCha20-Poly1305 + lineage integrity defend against A3.

## Security objectives

- **Confidentiality** — Every block on disk is AEAD-encrypted. A3 learns nothing.
- **Integrity** — AEAD auth tags + BLAKE3 lineage chain detect any in-block or cross-block tampering. The first bad block is identified exactly.
- **Compartmentalization** — Per-block keys derived from the volume root via HKDF. Compromising one block does not leak other blocks' keys.
- **Forward secrecy** — Key ratcheting and per-block lineage mean historical state is unrecoverable from any single future compromise.
- **Post-quantum sharing** — ML-KEM-768 (FIPS 203) protects the volume root key in the share file. A5 cannot recover the key from a captured share file even with a future CRQC.
- **Tamper-evident audit** — The BLAKE3-chained audit log identifies the first tampered record.
- **Crash safety** — WAL + atomic rename + parent-directory fsync guarantee the on-disk volume is either the old or the new state, never a half-written mix.
- **Determinism** — No AI or random state influences enforcement. The same events produce the same policy decision.
- **No silent trust escalation** — A wrong passphrase for the KDF sidecar, a wrong share-file fingerprint, or a wrong key file all fail loudly.

## Defended against

- **A1** cannot exfiltrate plaintext off disk (encryption) or through the share file (no envelope for an unauthorized recipient).
- **A2** cannot permanently destroy data: per-block lineage is verified by `verify`, and snapshots (when enabled) capture prior versions.
- **A3** cannot read ciphertext without the volume root key. The KDF sidecar's Argon2id parameters resist offline brute force; production m/t costs are OWASP 2024 minimums (19 MiB / 2 iters).
- **A4** (sharing flow only) sees only the public key of the recipient. MITM substitution is detected when the recipient's actual secret key fails to decapsulate a KEM ciphertext.
- **A5** (sharing flow only) cannot recover the volume root key from a recorded ML-KEM ciphertext. ML-KEM-768 is IND-CCA2 secure under standard lattice assumptions. ML-DSA-65 envelope signatures prevent an attacker from modifying the envelope without the owner's signing key.
- **Tampering of the audit log** is detected at the first bad record; the audit tool exits non-zero.
- **Cross-volume graft** of a share file is detected by the `BLAKE3(volume_root_key)` fingerprint stored in the share header.
- **WAL corruption** is handled by the parser: a missing commit marker is treated as uncommitted (discarded); a committed payload is replayed atomically.

## Not defended against (explicit)

- **A6** — A fully compromised kernel can intercept plaintext after the crypto core hands it back to the syscall path. Mitigations (sealed sessions, dm-crypt, secure enclaves) are layered atop Soteria, not built into it. TPM-backed volume keys would close part of this gap.
- **A7** — No defense against coercion. Users must keep volumes mounted only when needed.
- **A8** — Firmware-level compromise sits below the filesystem; the crypto guarantees hold but the keys may already be exfiltrated.
- **A9** — Side channels with full system control are out of scope for this userspace implementation.
- **Memory disclosure while mounted** — When the volume is unlocked, the volume root key and per-block plaintext exist in process memory. Treat the mount lifecycle as the security boundary: unmount to drop the key.

## Failure modes and recovery

| Failure | Detection | Recovery |
|---|---|---|
| Power loss mid-write | WAL is committed but data file rename incomplete | `Wal::recover` on next load replays the WAL |
| Power loss mid-WAL-write | WAL exists but has no commit marker | `Wal::recover` discards the uncommitted WAL; old data is intact |
| Bit rot in a block | AEAD auth tag mismatch on decrypt | `verify_lineage` reports the first bad block index |
| Bit rot in the header | BLAKE3 integrity check fails in `OnDiskFile::from_bytes` | Reject the volume; restore from a snapshot if available |
| Tampered audit log | `verify_bytes` returns `Tampered` at the first bad index | Investigate the record; the chain is broken but pre-chain records are still valid |
| Wrong passphrase | `Argon2id` derivation produces a key; `verify_key_for_volume` rejects it | User re-tries; repeated failures should trigger account lockout (out of scope here) |
| Lost volume root key | No recovery path | This is a feature, not a bug: encryption without key recovery is the threat-model intent |
| Compromised recipient SK | Attacker can unlock past shares for that recipient | Owner revokes the recipient and rotates the volume root key (re-encrypt) |
| Share file from wrong volume | Fingerprint mismatch in `ShareFile::open` | Refused; the share file is rejected |

## Operational notes

- **Argon2id parameters** are stored in the KDF sidecar. Production mode uses 19 MiB / 2 iters. Test mode uses 64 KiB / 1 iter (gated behind `--fast-kdf` and an explicit test fixture; never use in production).
- **Volume IDs** are 256-bit random values generated at encrypt time; uniqueness is not enforced but the BLAKE3 lineage still binds all blocks to the file.
- **Snapshots** (when enabled) capture the per-block ciphertext at a point in time; lineage is preserved across snapshots.
- **Random nonces** for AES-256-GCM are 96 bits; the XChaCha20-Poly1305 nonce is 192 bits. For AES-GCM in production, a crash-safe monotonic per-key counter should be layered atop the random nonce. The 192-bit XChaCha nonce makes random collision practically impossible.
- **Production gaps** (see `architecture.md`): real TPM2 binding, monotonic nonce registry, FUSE hardening.
