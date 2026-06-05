# Soteria Cryptographic Inventory

This document is the **canonical reference** for every cryptographic
primitive used in Soteria. It is intended to be exhaustive: an
auditor should be able to verify from this document that every
operation touching keys, ciphertexts, or signatures uses a
documented primitive in a documented way.

> **Rule:** if a primitive appears in code but not in this document,
> it is a bug. Update both.

## 1. Primitives

| Primitive | Where defined | Standard | Implementation |
|---|---|---|---|
| **AES-256-GCM** | `crypto_engine/aead.rs`, `crypto_engine/fips/primitives.rs` | FIPS SP 800-38D | `aes 0.8` + `ring 0.17` (FIPS path) |
| **AES-256-XTS** | `crypto_engine/xts.rs` | IEEE 1619-2018 | `aes 0.8` (XTS-256 from scratch) |
| **XChaCha20-Poly1305** | `crypto_engine/aead.rs` | RFC 8439, draft-irtf-cfrg-xchacha | `chacha20poly1305 0.10` |
| **BLAKE3** | direct `blake3 1.5` | RFC draft | `blake3 1.5` |
| **SHA-256** | `crypto_engine/fips/primitives.rs` | FIPS 180-4 | `ring 0.17` (FIPS path) |
| **SHA-512** | `crypto_engine/kdf.rs` (XTS expansion) | FIPS 180-4 | `sha2 0.10` |
| **HMAC-SHA-256** | `crypto_engine/fips/primitives.rs` | FIPS 198-1 | `ring 0.17` (FIPS), `hmac 0.12` (default) |
| **HKDF-SHA-256** | `crypto_engine/kdf.rs` | RFC 5869 | `hkdf 0.12` |
| **HKDF-SHA-512** | `fde/volume.rs::derive_xts_key` | RFC 5869 | `hkdf 0.12` |
| **Argon2id** | `crypto_engine/kdf.rs` | RFC 9106 | `argon2 0.5` |
| **PBKDF2-HMAC-SHA-256** | `crypto_engine/fips/primitives.rs` | FIPS SP 800-132 | `ring 0.17` (FIPS path) |
| **ML-KEM-768** | `crypto_engine/pq.rs` | FIPS 203 (draft) | `ml-kem 0.3` (pure Rust) |
| **ML-DSA-65** | `crypto_engine/dsa.rs` | FIPS 204 (draft) | `ml-dsa 0.1` (pure Rust) |
| **Ed25519** | `crypto_engine/dsa.rs` | RFC 8032 | `ed25519-dalek` (Cargo.lock) |
| **X25519** | `crypto_engine/dsa.rs` | RFC 7748 | `x25519-dalek` (Cargo.lock) |
| **Reed–Solomon RS(255,223)** | `omega/integrity.rs`, `erasure_coding.rs` | Standard | custom GF(256) (primitive 0x11D) |
| **system DRBG** | everywhere | FIPS SP 800-90A | `ring::SystemRandom` (FIPS) / `OsRng` (default) |

## 2. Per-Module Usage

### 2.1 `crypto_engine/`

| Submodule | Primitive | Notes |
|---|---|---|
| `aead.rs` | AES-256-GCM, XChaCha20-Poly1305 | `AeadAlgorithm` enum. Default = XChaCha (24-byte nonce), FIPS = AES-GCM. |
| `xts.rs` | AES-256-XTS | From-scratch implementation. NIST IEEE 1619 vector test. |
| `kdf.rs` | Argon2id, PBKDF2 (FIPS), HKDF-SHA-256, HKDF-SHA-512 | `argon2id_root_from_password`, `hkdf_derive`, `ratchet_key`. |
| `block.rs` | AES-256-GCM | Per-block encrypt/decrypt with subkeys. |
| `nonce.rs` | nonce generation | Counter-based; `OsRng` for random nonces. |
| `shares.rs` | Ed25519, ML-KEM, ML-DSA | Share file format with BLAKE3 chain. |
| `secure_box.rs` | Zeroizing wrapper | `Drop` impl zeroes buffer. |
| `pq.rs` | ML-KEM-768 | `Keypair::generate`, `encapsulate`, `decapsulate`. |
| `dsa.rs` | Ed25519, ML-DSA-65 | `Keypair::sign`, `Keypair::verify`. |
| `fips/` | SHA-256, HMAC-SHA-256, PBKDF2, AES-256-GCM, ring DRBG | `primitives.rs` is the FIPS-validated path. |
| `fips/kat.rs` | KAT self-tests | Power-on self-test (POST). |
| `fips/integrity.rs` | SFIT (Software Integrity Test) | BLAKE3 over module table. |
| `fips/cavp.rs` | CAVP vector writers | Produces `.req` files for NIST CAVP. |

### 2.2 `fde/`

| File | Primitive | Notes |
|---|---|---|
| `volume.rs` | HKDF-SHA-256, HKDF-SHA-512, Argon2id, BLAKE3, AES-256-XTS, AES-256-GCM (FIPS) | Header v4 layered derivation. XTS key check. |
| `hidden.rs` | (uses `volume`) | Hidden inner volume with midpoint header. |
| `shamir.rs` | GF(256) Shamir (0x11B) | k-of-n secret sharing. |
| `persistent.rs` | (uses `volume`) | NVRAM at LBA 8 for split-key. |
| `tpm_seal.rs` | SHA-256 (TPM PCR-derived), AES-256-GCM | Software fallback; uses PCR 0,2,4,7. |
| `hw_erase.rs` | (no crypto) | NVMe Format + ATA Secure Erase. |
| `pba.rs` | (no crypto) | PBA configuration and auth modes. |
| `gcm_sector.rs` | AES-256-GCM | FIPS-mode sector encryption. |
| `block_device.rs` | (no crypto) | Block I/O trait. |

### 2.3 `fs_layer/`

| File | Primitive | Notes |
|---|---|---|
| `fuse_fs.rs` | AES-256-GCM, XChaCha20-Poly1305 (via `crypto_engine::aead`) | Per-file AEAD; `key_hierarchy` not yet wired (FUSE feature). |
| `storage.rs` | AES-256-GCM, BLAKE3 | On-disk file format with per-file `file_id`. |
| `kdf.rs` | Argon2id, BLAKE3 | Volume KDF sidecar format. |
| `wal.rs` | BLAKE3 | Write-ahead log with chain hash. |
| `sandbox.rs` | (no crypto) | Process sandboxing. |
| `metadata.rs` | (uses `storage`) | Plaintext (legacy); replace with `metadata_encryption`. |
| `region.rs` | (no crypto) | Region allocation. |
| `durability.rs` | (no crypto) | fsync semantics. |

### 2.4 `key_hierarchy/`

| File | Primitive | Notes |
|---|---|---|
| `mod.rs` | HKDF-SHA-256 | 6 domain keys from master. |
| `slots.rs` | Argon2id (per slot), AES-256-GCM, BLAKE3-keyed HMAC | Multi-user slots, header HMAC. |

### 2.5 `erasure_coding.rs`

| Primitive | Notes |
|---|---|
| GF(256) (primitive 0x11D) | Custom; arithmetic in `gf256` submodule. |
| Reed–Solomon Vandermonde | Parity shards = V * data over GF(256). |
| AES-256-GCM | Per-shard seal with `K_shard`. |

### 2.6 `metadata_encryption.rs`

| Primitive | Notes |
|---|---|
| AES-256-GCM | Per-metadata-record seal with `K_meta`. AAD binds `kind` and `VolumeContext`. |

### 2.7 `omega/`

OMEGA modules (gated by `--features omega`) use the same primitives
as above. Notable usages:

| File | Primitive | Notes |
|---|---|---|
| `classification.rs` | BLAKE3 | Classification chain. |
| `two_person.rs` | BLAKE3-keyed HMAC | Session commitments. |
| `comsec.rs` | BLAKE3 | Custody chain. |
| `init_flow.rs` | BLAKE3 | Phase state. |
| `sovereignty.rs` | (no crypto) | Network policy. |
| `crypto_process.rs` | BLAKE3-keyed HMAC | IPC signing. |
| `integrity.rs` | GF(256) RS(255,223), BLAKE3 Merkle | Tamper detection. |
| `defense/mod.rs` | Shannon entropy | Ransomware detection. |
| `hardware/mod.rs` | SHA-256 (TPM), BLAKE3 (FIDO2) | Software fallbacks. |
| `tempest.rs` | (no crypto) | Noise generation. |
| `emergency.rs` | Zeroize | Panic/duress wipe. |
| `mod.rs` | (composes all) | `ironclad_table()` 50-row matrix. |

### 2.8 `secure_erase.rs`

| Pattern | Notes |
|---|---|
| Zero, Random, DoD 5220.22-M, Gutmann | Wipe patterns. No crypto. |

## 3. Key Hierarchy

```
passphrase
   │
   ▼  Argon2id (PBKDF2-HMAC-SHA-256 in FIPS)
K_master  (32 B; zeroized on drop)
   │
   ▼  HKDF-SHA-256(salt, info)  for each of 6 domain tags
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│  K_enc   │  K_auth  │  K_meta  │  K_shard │  K_xts   │ K_handle │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
   │
   ▼  HKDF-SHA-512(None, "soteria-fde-xts-v1")
XTS_key  =  data (32 B)  ||  tweak (32 B)
```

### 3.1 Domain info tags (immutable)

| Tag | Value |
|---|---|
| `K_ENC` | `b"soteria-kh-v1/k-enc/aead-bulk"` |
| `K_AUTH` | `b"soteria-kh-v1/k-auth/block-mac"` |
| `K_META` | `b"soteria-kh-v1/k-meta/metadata"` |
| `K_SHARD` | `b"soteria-kh-v1/k-shard/erasure-coding"` |
| `K_XTS` | `b"soteria-kh-v1/k-xts/fde-sector"` |
| `K_HANDLE` | `b"soteria-kh-v1/k-handle/identity"` |
| Master salt | `b"soteria-kh-v1/master-salt"` |

### 3.2 Subkey derivation

```rust
pub fn subkey(domain: &[u8; 32], context: &[u8]) -> [u8; 32] {
    hkdf_derive(domain, b"soteria-kh-v1/subkey-salt", context)
}
```

## 4. Slot Table Format

```
HEADER_MAGIC = b"SOTK"  (4 bytes)
HEADER_VERSION = 1      (1 byte)
slot_count              (1 byte, max 16)
for each slot:
   slot_id: 16 B
   kdf_id: 1 B  (1 = Argon2id)
   kdf_m_cost: 4 B (LE)
   kdf_t_cost: 4 B (LE)
   kdf_p_cost: 4 B (LE)
   salt: 16 B
   nonce: 12 B
   ct: 48 B  (master || gcm_tag)
   flags: 1 B
   created_at: 8 B (LE)
header_hmac: 32 B  (BLAKE3-keyed(header_salt, body))
```

AAD for slot GCM:
```
HEADER_MAGIC || HEADER_VERSION || KDF_ID_ARGON2ID ||
m_cost || t_cost || p_cost || salt || nonce
```

## 5. FDE Header Format (v4)

See `docs/FDE-ARCHITECTURE.md` for the byte-level layout.
Header version 4 = layered XTS derivation.

## 6. Randomness

- Default build: `rand::rngs::OsRng` (CSPRNG backed by the OS;
  on Linux, getrandom(2) which reads from the kernel CSPRNG).
- FIPS build: `ring::SystemRandom` (FIPS SP 800-90A DRBG).

## 7. Constant-Time Operations

Every secret comparison in the TCB uses `subtle::ConstantTimeEq`
or a manual XOR-OR accumulator (see `fde/volume.rs::constant_time_eq`).
No early-exit on byte mismatch.

## 8. Zeroization

Every key-like buffer is `Zeroizing<...>` or has a manual `Drop`
impl that zeroes it. `zeroize 1.8` is used with the `derive`
feature. The compiler does *not* guarantee the zeroes are not
optimized away; `zeroize` uses volatile writes to defeat this.

## 9. Self-Tests

| Test | What it covers |
|---|---|
| `xts_known_vector_roundtrip` | NIST IEEE 1619 vector |
| `xts_passes_nist_avp_vector_1` | NIST AVP |
| `aes_gcm_roundtrip` | AEAD round-trip |
| `hkdf_test_vectors` | RFC 5869 vectors |
| `argon2id_kat` | RFC 9106 vectors (FIPS module has CAVP writers) |
| `fips::kat` | KAT at startup when `--features fips` |
| `fips::integrity` | SFIT at startup |

## 10. Things Soteria Does NOT Use

- No custom ciphers.
- No proprietary KDFs.
- No MD5, SHA-1, RC4, DES, 3DES, Blowfish, or other deprecated
  primitives.
- No raw `xor` "encryption".
- No "rolling your own" entropy extractor.
- No time-based key derivation (no `time::now()` in KDF).

If you find any of these in a TCB module, that is a bug.
