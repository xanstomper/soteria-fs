# Cryptographic Notes

> These are the internal cryptographic design notes for Aegis, the trusted encryption and protection core of Soteria.

## Allowed primitives

- **Data encryption:** XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) or AES-256-GCM (12-byte nonce, 16-byte tag).
- **Hashing and integrity:** BLAKE3 (256-bit output, used for header integrity, lineage, audit chain, share-file fingerprint, ML-KEM recipient key id).
- **KDF:** HKDF-SHA256 (per-block subkeys, key ratchet) and Argon2id (passphrase → volume root key).
- **PQC:** ML-KEM-768 (FIPS 203) for hybrid key wrapping. ML-DSA-65 (FIPS 204) for envelope signatures. Pure-Rust `ml-kem` and `ml-dsa` crates are the default; the `pqc-oqs` feature flag swaps in liboqs for environments where the C dependency is acceptable.

## Nonce discipline

The on-disk volume uses 96-bit (AES-GCM) or 192-bit (XChaCha20-Poly1305) random nonces via `OsRng`. The 192-bit XChaCha20-Poly1305 nonce is large enough that random collision under the same key is not a practical concern. For AES-GCM in production, a crash-safe monotonic per-key counter must be layered atop the random nonce; the current scaffold records the nonce in the envelope but does not enforce uniqueness beyond randomness.

## Key derivation

- **Volume root key:** `Argon2id(passphrase, salt, m, t, p)`. Default production parameters: 19 MiB memory, 2 iterations, 1 lane (OWASP 2024 minimum for interactive authentication on commodity hardware). Test parameters: 64 KiB / 1 iter (gated behind `KdfParams::fast_test()` and `--fast-kdf`; never use in production).
- **Per-block key:** `HKDF-SHA256(volume_root_key, salt = LE-u64(block_index) || BLAKE3(lineage_prev), info = "SOTERIA per-block key v1")`. The lineage_prev hash binds each block's key to the previous block's ciphertext, breaking key reuse across the chain.
- **Key ratchet:** `HKDF-SHA256(current_key, salt = random 32B, info = "SOTERIA key ratchet v1")`. Old key is zeroized.
- **ML-KEM KEK (share unwrap):** `HKDF-SHA256(kem_shared_secret, salt = "soteria-pq-kek-salt-v1", info = "SOTERIA pq-wrap v1")`. The KEK then AES-256-GCM-encrypts the 32-byte volume root key with `AAD = "soteria:pq:data-key:v1"`.

## Block AAD

For each encrypted block, the AEAD AAD is `BLAKE3("soteria:block:<i>:prev:<lineage_prev>")`. The previous block's lineage hash binds the AAD to the chain, so swapping a block into a different position in the chain breaks auth.

## Volume header integrity

The 256-byte volume header is integrity-protected by `BLAKE3(header[..80])` stored at offset 80. Any single-byte change to the magic, version, algorithm id, file_id, block_size, plaintext_size, or block_count is detected on load.

## Lineage chain

Each block's `lineage_new` is `BLAKE3("GENESIS" || ciphertext)` for block 0, or `BLAKE3(lineage_prev || ciphertext)` for subsequent blocks. `OnDiskFile::verify_lineage` walks the chain and returns the first bad block index on tamper. The chain detects:
- Ciphertext modification (the chain hash no longer matches).
- Block reordering (the previous lineage hash no longer matches the actual predecessor).
- Block insertion or deletion (chain length and content both shift).

## WAL (write-ahead log)

```
+--------+   offset 0
| WAL\x01|   4 bytes
+--------+   offset 4
|  len   |   u32 LE (length of payload)
+--------+   offset 8
| payload|   len bytes (full new volume bytes)
+--------+   offset 8 + len
| COM\x01|   4 bytes
+--------+
```

`Wal::write` writes the WAL with a commit marker, `sync_all` the file, and `fsync_dir` the parent directory. `Wal::recover` inspects the WAL on the next load: committed payloads are replayed (atomic temp + rename + parent-dir fsync); uncommitted payloads are discarded.

## Audit chain

Each audit entry is serialized with deterministic field order via `serde_json::Map`:
```
seq, process_id, region_id, reason, revoked_at_unix_ms
```
(`chain` is computed externally.) The chain formula is:
```
chain_n = BLAKE3(chain_{n-1} || canonical_json(entry_n))
chain_0.prev_chain = 32 zero bytes
```
Truncated final lines are tolerated (treated as mid-write crash). Tampering of an earlier line breaks the chain at exactly the first bad index.

## Share file format

```json
{
  "version": 2,
  "volume_root_key_fingerprint": "<BLAKE3 of volume root key, 64 hex>",
  "events": [
    { "action": "added",   "recipient_key_id": "<64 hex>", "envelope": {...},
      "owner_sig_pk_id": "<64 hex>", "owner_signature": "<hex>", "at_unix_ms": 1700... },
    { "action": "revoked", "recipient_key_id": "<64 hex>", "reason": "rotation", "at_unix_ms": 1700... }
  ]
}
```

The `envelope` is a `KeyEnvelope`:
- `recipient_key_id` = `BLAKE3(recipient_public_key)` (32 B, hex)
- `kem_ciphertext` = ML-KEM-768 ciphertext (1088 B, hex)
- `wrap_nonce` = AES-256-GCM nonce (12 B, hex)
- `wrapped_key` = AES-256-GCM ciphertext + tag (48 B, hex)

`owner_sig_pk_id` is `BLAKE3(owner_ml_dsa_65_pk_bytes)` (32 B, hex). `owner_signature` is the ML-DSA-65 signature (3309 B, hex) over the canonical envelope bytes (see below).

The currently-active set is derived by walking the events in reverse and taking each recipient's latest state. The fingerprint prevents cross-volume graft attacks: opening a share file for a different volume (or a wrong root key) errors with "fingerprint mismatch".

## ML-DSA-65 envelope signatures

Every `Added` event is signed by the volume owner's ML-DSA-65 secret key. Recipients can verify the signature with the owner's ML-DSA-65 public key. The signature binds every field of the envelope so any tampering (key id swap, KEM ciphertext modification, wrapped key swap, nonce modification) is detected.

The canonical signing payload is:
```
"soteria:share:envelope:v1" || recipient_key_id || recipient_ml_kem_pk_bytes || wrap_nonce || kem_ciphertext || wrapped_key
```

The domain separator `"soteria:share:envelope:v1"` pins the signature to the share-envelope protocol; a signature minted for any other context cannot be replayed against a share envelope.

ML-DSA-65 uses the deterministic Sign variant (the `Signer` trait impl from the `ml-dsa` crate). The same `(sk, payload)` pair always produces the same signature, which is desirable for the share-file audit trail.

The owner key is stored as a 32-byte seed (the FIPS 204 preferred form). The expanded 4032-byte form is reconstructed on demand. Public keys are 1952 bytes; signatures are 3309 bytes. All values are hex-encoded in the JSON share file.

## AI safety

The AI observer trait returns an `AiObservation` with `enforcement_allowed: false`. Policy enforcement is exclusively the responsibility of `response_engine::PolicyEngine`, which maps known event types to an allowlisted action set. If the configured allowlist excludes a triggered action, the engine downgrades the decision to `Allow`.

## Algorithm agility

The volume header carries a 1-byte algorithm id. The current `crypto_engine::AeadAlgorithm` enum supports `XChaCha20Poly1305` (1) and `Aes256Gcm` (2). Adding a new AEAD is a matter of:
1. Implementing the algorithm in `crypto_engine::aead`.
2. Adding the enum variant and the new id byte.
3. Updating the binary header serializer / deserializer.
4. Adding `encrypt_block` / `decrypt_block` support in `crypto_engine::block`.

The header version byte is 1; bumping to 2 would signal a breaking format change and require a migration tool.
