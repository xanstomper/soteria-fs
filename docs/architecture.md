# Soteria Architecture

## Trust domains

1. **Aegis core (trusted)** — AEAD, KDF, key ratchet, lineage chain, ML-KEM wrapping, ML-DSA signing, audit chain, policy engine. Small, auditable, deterministic. Aegis is the trusted computing base; everything else is untrusted or partially trusted.
2. **Security monitor (untrusted)** — Sensors emit events. They cannot mutate keys or take enforcement actions. The policy engine treats them as hints.
3. **AI observer (read-only)** — Produces risk scores from event records. `enforcement_allowed: false` is hard-coded. The policy engine may consume the score but never an action.
4. **FUSE / OS kernel (partially trusted)** — Trusted to deliver bytes between userspace and the backing store. Not trusted to keep keys confidential while the volume is mounted.

## Module map (`rust-core/src/`)

| Module | Purpose |
|---|---|
| `crypto_engine` | **Aegis** — the trusted encryption and protection core. Contains all cryptographic primitives, key management, and share file logic. |
| `crypto_engine::aead` | AEAD primitives (XChaCha20-Poly1305, AES-256-GCM), nonce + AAD handling |
| `crypto_engine::block` | Per-block encryption with lineage. HKDF-derived block keys. |
| `crypto_engine::kdf` | Argon2id volume key derivation; HKDF-SHA256 for subkeys and ratchets. |
| `crypto_engine::pq` | ML-KEM-768 (FIPS 203) hybrid key wrapping. Pure-Rust `ml-kem` crate by default; `pqc-oqs` feature flag for liboqs. |
| `crypto_engine::dsa` | ML-DSA-65 (FIPS 204) envelope signatures. Pure-Rust `ml-dsa` crate. Signs share envelopes so recipients can cryptographically verify the volume owner. |
| `crypto_engine::shares` | Multi-recipient share file (`<volume>.sot.shares`). Append-only event log: `Added` (with ML-DSA-65 signature) and `Revoked` events per recipient. |
| `crypto_engine::nonce` | Random-nonce generation via `OsRng`. |
| `fs_layer::storage` | Binary volume format: 256-byte header + per-block index + ciphertext blob. `OnDiskFile::save` is crash-safe (WAL + atomic rename + parent-dir fsync). |
| `fs_layer::wal` | Write-ahead log with `Wal\x01` magic and `COM\x01` commit marker. `Wal::recover` replays committed-but-unrenamed payloads. |
| `fs_layer::kdf` | KDF sidecar (`<volume>.sot.kdf`, 61 bytes): kdf_id, m/t/p cost, 16-byte salt, BLAKE3 integrity. |
| `fs_layer::durability` | `fsync_dir` helper. Best-effort cross-platform parent-directory fsync after atomic renames. |
| `fs_layer::fuse_fs` | FUSE integration (feature-gated; Linux/macOS only). |
| `fs_layer::metadata` | Per-file metadata (region, capability, snapshot linkage). |
| `fs_layer::region` | Region definitions: a partition of the mount tree that can be frozen in response to threats. |
| `key_manager` | TPM abstraction, key lifecycle states, capability tokens, key ratchet. |
| `event_bus` | Append-only BLAKE3-chained event stream. |
| `policy::revocation` | `RevocationEngine` — process-level capability revocation. Persists to `policy::audit_log`. |
| `policy::audit_log` | BLAKE3-chained JSONL audit log. `AuditLog::open`/`append`/`verify`; `VerifyResult::{Ok,Tampered,Malformed}`. |
| `response_engine` | Deterministic rule engine with allowlisted action set (`FREEZE`, `ISOLATE`, `REVOKE`, `ROLLBACK`, `ALLOW`). |
| `snapshot_engine` | Copy-on-write file snapshots and cryptographic version chains. |
| `ai_observer` | Read-only AI advice interface. `enforcement_allowed: false`. |
| `deception_layer` | Optional honeypot/decoy structure generator. |
| `sensors` | Entropy, write, process, key-access sensors. |
| `tpm` | TPM provider interface with mock provider for development. |
| `simulation` | `ransomware_sim` and friends — end-to-end attack scenarios for integration testing. |

## Layered diagram

```
            ┌───────────────────────────────────────┐
            │           CLI / FUSE / Daemon         │  ← userspace surface
            └────────────────┬──────────────────────┘
                             │
        ┌────────────────────┼─────────────────────┐
        │                    │                     │
   ┌────▼─────┐    ┌─────────▼────────┐   ┌────────▼────────┐
   │ sensors  │    │ response_engine  │   │   fs_layer      │
   │(untrust.)│    │ (deterministic)  │   │  (FUSE, WAL)    │
   └────┬─────┘    └────────┬─────────┘   └────────┬────────┘
        │ events             │ decisions            │ ops
        ▼                    ▼                      ▼
   ┌─────────────────────────────────────────────────────┐
   │              event_bus  +  policy::audit_log        │  ← BLAKE3-chained
   └──────────────────────┬──────────────────────────────┘
                          │
                          ▼
   ┌─────────────────────────────────────────────────────┐
   │                  Aegis (crypto_engine)              │  ← trusted core
   │  aead │ block │ kdf │ nonce │ pq │ dsa │ shares     │
   └─────────────────────────────────────────────────────┘
                          │
                          ▼
                  storage at rest
```

## Cryptographic property guarantees

- **Authenticated encryption** on every write; tampered ciphertext rejected by AEAD auth.
- **Per-block key independence** via HKDF(domain_key, block_index_le || lineage_prev_hash).
- **Forward-secure key ratcheting** via HKDF with counter and entropy; old key zeroized.
- **BLAKE3-chained audit log** and **BLAKE3-chained event bus**; tampering detectable at the first bad record.
- **Tamper-evident lineage chain** for snapshot versions and per-block data.
- **Crash-safe writes** via WAL + atomic rename + parent-directory fsync.
- **Post-quantum sharing** via ML-KEM-768; recipient SK compromise is contained by `Revoked` events in the share file.
- **Post-quantum envelope signatures** via ML-DSA-65; every `Added` event is signed by the volume owner so recipients can verify envelope authenticity.
- **Volume-binding share file** via `BLAKE3(volume_root_key)` fingerprint in the share header.

## On-disk volume format

```
<dir>/<name>.sot                ← encrypted volume (256B header + index + ciphertext)
<dir>/<name>.sot.kdf            ← KDF sidecar (61B: kdf_id, m/t/p, salt, BLAKE3)
<dir>/<name>.sot.wal            ← write-ahead log (transient; cleaned after rename)
<dir>/<name>.sot.shares         ← ML-KEM share file (JSON; append-only event log)
```

## Production gaps (explicit)

- Replace `MockTpmProvider` with a real TPM2 / secure enclave backend for volume key sealing.
- Persist a monotonic nonce registry per key to make random-nonce reuse effectively impossible across crashes (currently mitigated by 192-bit XChaCha nonces and per-volume key rotation).
- Expand FUSE inode mapping beyond the prototype root.
- Add platform-specific process quarantine hooks.
- Add periodic re-keying: rotate the volume root key and re-encrypt with the new key on a schedule.
- Add an HSM / KMS provider for volume keys in server deployments.
