# Soteria-FS Security Audit

**Scope:** `rust-core/src/crypto_engine/`, `rust-core/src/fs_layer/`, `rust-core/src/key_manager/`, `rust-core/src/policy/audit_log.rs`
**Date:** 2026-06-04
**Auditor:** defensive code review (no exploit tooling produced)
**Methodology:** static review of source for known crypto / FS / concurrency footguns, threat-model alignment, attacker-capability enumeration.

---

## Severity summary

| # | Title | Severity | File |
|---|-------|----------|------|
| 1 | FUSE mount uses hardcoded volume key `[7u8; 32]` | **CRITICAL** | `fs_layer/fuse_fs.rs:74` |
| 2 | Header integrity does not cover `KDF_HASH` field (PATCH-05 bypass) | **CRITICAL** | `fs_layer/storage.rs:128-180` |
| 3 | `plaintext()` does not call `verify_lineage()` | **HIGH** | `fs_layer/storage.rs:274-298` |
| 4 | `setattr` truncate leaves ciphertext in place (recoverable data) | **HIGH** | `fs_layer/fuse_fs.rs:577-609` |
| 5 | `rename` breaks encryption (file becomes unreadable) | **HIGH** | `fs_layer/fuse_fs.rs:553-575` |
| 6 | Capability tokens are unsigned, `token_blake3` is never verified | **HIGH** | `key_manager/capability.rs:25` |
| 7 | `verify_chain` allows chain shorter than events list | **HIGH** | `crypto_engine/shares.rs:307-322` |
| 8 | `append_chain_hash` uses `unwrap_or_default()` for serialization | **HIGH** | `crypto_engine/shares.rs:296-301` |
| 9 | `Open` does not call `verify_chain()` on share file load | **MEDIUM** | `crypto_engine/shares.rs:168-186` |
| 10 | WAL parser does not bound payload length (DoS via 4 GiB allocation) | **MEDIUM** | `fs_layer/wal.rs:120-142` |
| 11 | `from_bytes` allocates `block_count * 80` bytes on parse (DoS) | **MEDIUM** | `fs_layer/storage.rs:194` |
| 12 | `argon2id_root_from_password` enforces no minimum work factor | **MEDIUM** | `crypto_engine/kdf.rs:6-20` |
| 13 | Deterministic nonce from BLAKE3(key, aad) with same AAD across regions | **MEDIUM** | `crypto_engine/aead.rs:38-41`, `crypto_engine/block.rs:61-63` |
| 14 | Decrypt path uses envelope-supplied `algorithm` (malleable) | **MEDIUM** | `crypto_engine/aead.rs:79-113` |
| 15 | `assert!` / `expect` in security-critical input validation | **MEDIUM** | `crypto_engine/block.rs:88-93` |
| 16 | FUSE reports all files as `uid: 0, gid: 0, perm: 0o600` (no real perms) | **MEDIUM** | `fs_layer/fuse_fs.rs:189-208` |
| 17 | `open()` loads whole file into memory (memory-exhaustion DoS) | **MEDIUM** | `fs_layer/fuse_fs.rs:388-424` |
| 18 | `.soteria.inode_map` has no integrity protection (DoS / confused-deputy) | **MEDIUM** | `fs_layer/fuse_fs.rs:122-131` |
| 19 | `derive_file_key` is a hash, not a KDF (no work factor) | **LOW** | `fs_layer/fuse_fs.rs:155-160` |
| 20 | `hex_to_bytes` silently drops invalid hex | **LOW** | `fs_layer/storage.rs:404-416` |
| 21 | `nonce_len` is silently truncated to 24 bytes | **LOW** | `fs_layer/storage.rs:375-378` |
| 22 | `SecureBox::new` `mlock` failure is silent (no metric / no log) | **LOW** | `crypto_engine/secure_box.rs:42-65` |
| 23 | `Open` of share file is unbounded size (DoS via large JSON) | **LOW** | `crypto_engine/shares.rs:174-176` |
| 24 | Audit-log `rotate` window can leave log empty if crash mid-rotate | **LOW** | `policy/audit_log.rs:189-207` |
| 25 | `ratchet_key` accepts caller-supplied `entropy` (audit caller) | **INFO** | `crypto_engine/kdf.rs:30-40` |

---

## CRITICAL findings

### 1. FUSE mount uses hardcoded volume key `[7u8; 32]`
**File:** `rust-core/src/fs_layer/fuse_fs.rs:74`
```rust
let volume_key = [7u8; 32]; // TODO: TPM-unsealed root key
```
**Impact:** *Every* file mounted via this FUSE layer is encrypted with a publicly known key. An attacker with read access to any file in `<backing>/` (e.g., a backup, a stolen disk, a cloud snapshot) can decrypt the entire volume offline without any secret. The `// TODO: TPM-unsealed root key` indicates this is unfinished, but the code is what ships.

This **invalidates the entire encryption story** for the FUSE mount. Until this is fixed, the FUSE layer provides no confidentiality.

**Fix:**
- Read the volume key from the config / KDF sidecar / TPM, never hardcode.
- Until then, gate `SoteriaFs::new` to return `Err` if the key source is not configured, so the daemon refuses to mount rather than mounting an "encrypted" volume with a known key.
- Add a startup self-test: refuse to start if the volume key equals any all-same-byte sentinel (e.g., `[0;32]`, `[7;32]`, `[0xFF;32]`).

### 2. Header integrity does not cover `KDF_HASH` field (PATCH-05 bypass)
**File:** `rust-core/src/fs_layer/storage.rs:128-180`
```rust
// 0..80 covered by integrity at 80..112
// KDF_HASH at 112..144  ← NOT covered
let integrity = blake3::hash(&header[..HEADER_INTEGRITY_OFFSET]); // bytes 0..80
header[HEADER_INTEGRITY_OFFSET..HEADER_INTEGRITY_OFFSET + HEADER_INTEGRITY_SIZE]
    .copy_from_slice(integrity.as_bytes());
if let Some(kdf_hash) = &self.kdf_hash {
    header[KDF_HASH_OFFSET..KDF_HASH_OFFSET + KDF_HASH_SIZE].copy_from_slice(kdf_hash);
}
```
**Impact:** The header integrity field covers bytes `0..80`. The KDF_HASH lives at bytes `112..144`, which is **outside** the integrity window. An attacker with raw write access to the volume file can swap the KDF_HASH to point at a different KDF sidecar (e.g., one with cheap Argon2 params or a known salt), the header integrity check passes, and the victim is fooled into using a weakened key derivation. This **bypasses PATCH-05 entirely** — the protection is in name only.

**Fix:** Extend the integrity window to cover the KDF_HASH field. Specifically, compute integrity over `header[..KDF_HASH_OFFSET + KDF_HASH_SIZE]` and place the integrity field at the end of the header, not in the middle. Or, store the integrity in a separate trailing field with explicit length.

---

## HIGH findings

### 3. `plaintext()` does not call `verify_lineage()`
**File:** `rust-core/src/fs_layer/storage.rs:274-298`
The `plaintext` function reconstructs each block's AAD from the *previous block's stored `lineage_new`*. If the attacker tampers with block N's `lineage_new` in the index, block N+1's AAD changes and AEAD auth fails — caught. But block N itself decrypts fine because its own AAD is independent of its own `lineage_new`. So a single-block lineage-swap goes undetected by the decrypt path. `verify_lineage()` is the only check that catches this, and it's never called.

**Fix:** Call `self.verify_lineage()` at the top of `plaintext()` and bail with `anyhow::bail!("volume: lineage chain broken at index {i}")` if it returns `Some(i)`.

### 4. `setattr` truncate leaves ciphertext in place
**File:** `rust-core/src/fs_layer/fuse_fs.rs:577-609`
```rust
if let Some(new_size) = size {
    let map = self.inode_map.lock();
    if let Some(name) = map.get(&ino) {
        let path = self.backing_path(name);
        if let Ok(mut on_disk) = OnDiskFile::load(&path) {
            if (new_size as usize) < on_disk.plaintext.len() {
                on_disk.plaintext.truncate(new_size as usize);
            }
            on_disk.plaintext_size = new_size;
            let _ = on_disk.save(&path);
        }
    }
}
```
`on_disk.ciphertext` is the original encrypted bytes, untouched. After truncate, the on-disk file has `plaintext_size = new_size` but the ciphertext blob still contains the full original blocks. Reads honor `plaintext_size` and only decrypt up to that, so the file *appears* truncated — but the underlying ciphertext is recoverable from the raw device. Worse, the unused blocks are at the **end** of the ciphertext, which is exactly where `read()` doesn't look. Anyone with `cat file.sot | xxd | grep -A 10000` gets the truncated plaintext back.

**Fix:** Truncation must re-encrypt the surviving plaintext and produce a fresh ciphertext blob (re-run `encrypt_to_disk` with the truncated plaintext, replace the file). Don't just update `plaintext_size` and write the old ciphertext.

### 5. `rename` breaks encryption
**File:** `rust-core/src/fs_layer/fuse_fs.rs:553-575`
`derive_file_key(name)` uses the **current** name. Renaming a file changes the derived key, so the file's stored ciphertext (encrypted under the old name's key) becomes undecryptable under the new name's key. AEAD auth fails on first read, file is unreadable, data is lost.

**Fix:** Either bind the encryption key to an immutable file ID (which is what `OnDiskFile.file_id` is for, but it isn't used for key derivation here) and persist the mapping `name → file_id` in a tamper-resistant way, or re-encrypt the entire file on rename. The simplest fix: store `file_id` in `.soteria.inode_map` next to `(inode, name)` and derive the key from `file_id`, not name.

### 6. Capability tokens are unsigned, `token_blake3` is never verified
**File:** `rust-core/src/key_manager/capability.rs:25`
```rust
let material = format!("{process_id}:{:?}:{ttl_seconds}:{issued_at:?}", scope);
Self {
    process_id, scope, issued_at, ttl_seconds,
    token_blake3: blake3::hash(material.as_bytes()).to_hex().to_string(),
}
```
The `token_blake3` is computed but the file has no `verify` method, and no other module in the audited surface calls into a verifier. The token is metadata. If the rest of the system relies on it for access control, every check is bypassable: an attacker forges a `Capability` with whatever `process_id`, `scope`, and `ttl_seconds` they want.

**Fix:** Either (a) make the token a keyed MAC using a server-held secret, with a real `verify_token` function used at every enforcement point, or (b) remove the token field and `valid()` should actually call into whatever ACL check is the source of truth. The current code is misleading dead crypto.

### 7. `verify_chain` allows chain shorter than events list
**File:** `rust-core/src/crypto_engine/shares.rs:307-322`
```rust
for (i, event) in self.events.iter().enumerate() {
    let event_bytes = serde_json::to_vec(event).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"soteria:share-chain:v1");
    hasher.update(&prev);
    hasher.update(&event_bytes);
    let expected = *hasher.finalize().as_bytes();
    if i < self.chain.len() && self.chain[i] != expected {  // ← only checks if chain[i] exists
        return Some(i);
    }
    prev = expected;
}
```
The condition `i < self.chain.len() && self.chain[i] != expected` is satisfied (vacuously) when the chain is shorter than the events list. An attacker who has write access to the share file can **delete arbitrary trailing chain entries** without detection. Combined with #8 (silent `unwrap_or_default` on serialize failure), the chain integrity is bypassable.

**Fix:** Change the condition to `if self.chain.get(i) != Some(&expected) { return Some(i); }` and also check `self.chain.len() == self.events.len()` at the top of the function, returning an error if not.

### 8. `append_chain_hash` uses `unwrap_or_default()` for serialization
**File:** `rust-core/src/crypto_engine/shares.rs:296-301`
```rust
let event_bytes = serde_json::to_vec(event).unwrap_or_default();
```
If serialization ever fails, the chain is computed over an empty byte string — which is what an attacker can also produce. An attacker who can craft an event that fails serialization (e.g., by overflowing an internal serializer limit) can make the chain hash equal to the hash of empty bytes, which they can predict and forge.

**Fix:** Replace `unwrap_or_default()` with `.expect("ShareEvent serialization is total")` or `.map_err(|e| anyhow::anyhow!("share: serialize event: {e}"))?`. Serialization of a `ShareEvent` cannot fail for any input — the failure mode is a bug, not a runtime condition.

---

## MEDIUM findings

### 9. `open` does not call `verify_chain()` on share file load
**File:** `rust-core/src/crypto_engine/shares.rs:168-186`
The share file is loaded, deserialized, and the volume fingerprint is checked, but `verify_chain()` is never called. An attacker with file-write access can rewrite the share file with a corrupt chain (or no chain at all) and `open` will succeed. The chain is purely advisory.

**Fix:** Call `sf.verify_chain()` after the version+fp checks and return an error if it returns `Some(_)`.

### 10. WAL parser does not bound payload length
**File:** `rust-core/src/fs_layer/wal.rs:120-142`
The parser reads `len: u32` and uses it to slice into the byte buffer. A malicious WAL file of `12 + 0xFFFFFFFF` bytes triggers a ~4 GiB allocation via `to_vec()`. `payload_end > bytes.len().saturating_sub(4)` does bound it to the actual file size, so the *allocation* is bounded by the file size, but the parser still accepts a 4 GiB file and tries to read it all into RAM. An attacker with file-write access (e.g., a second user on a shared volume) can OOM the daemon by creating a 4 GiB file at `<data_path>.sot.wal`.

**Fix:** Add an early check: if `len > MAX_WAL_PAYLOAD` (e.g., 1 GiB) and `bytes.len() < 12 + len`, return `WalState::Uncommitted`. Cap the parser's accepted file size.

### 11. `from_bytes` allocates `block_count * 80` bytes on parse
**File:** `rust-core/src/fs_layer/storage.rs:194`
```rust
let index_size = block_count * INDEX_ENTRY_SIZE;  // 80 bytes per block
```
A crafted header with `block_count = u32::MAX` causes a `~320 GiB` allocation on load. DoS via OOM.

**Fix:** Cap `block_count` to a sane max (e.g., 1<<24 = 16M blocks = 64 GiB at 4 KiB each) and bail with a typed error otherwise.

### 12. `argon2id_root_from_password` enforces no minimum work factor
**File:** `rust-core/src/crypto_engine/kdf.rs:6-20`
The function accepts arbitrary `memory_kib` and `iterations` from the caller. If config validation is weak (e.g., allows `memory_kib = 64, iterations = 1`), the resulting key is brute-forceable on a single GPU in minutes.

**Fix:** Add minimums inside the function itself (defense in depth): `memory_kib >= 64 * 1024` (64 MiB), `iterations >= 3`, and `parallelism >= 1`. Return `Err` if the supplied values are below the floor, with a clear message naming the minimums. The OWASP password storage cheat sheet (2024) recommends Argon2id with m=64 MiB, t=3, p=1 as a minimum.

### 13. Deterministic nonce from BLAKE3(key, aad) with same AAD across regions
**File:** `rust-core/src/crypto_engine/aead.rs:38-41`, `crypto_engine/block.rs:61-63`
```rust
// aead.rs
let n = Nonce96::derive(&self.key, aad);
```
The AAD is `format!("soteria:block:{block_index}:prev:{lineage_prev}")`. Within a single volume, two different regions that both have a "first block" (block_index 0, lineage_prev "GENESIS") will produce the same AAD and thus the same nonce. **AES-GCM nonce reuse with the same key is catastrophic**: it leaks the XOR of plaintexts and the auth hash subkey.

This isn't an immediate plaintext recovery (the attacker needs to *observe* two ciphertexts under the same nonce, then they can XOR them), but it removes a critical security property. With multi-region volumes, this is reachable.

**Fix:** Add a region or domain tag to the AAD. E.g., AAD = `format!("soteria:vol:{volume_id}:block:{block_index}:prev:{lineage_prev}")` and bind `volume_id` into the salt as well. Or, use a per-volume random nonce base and XOR with a per-block counter (XChaCha20-Poly1305 already uses 24-byte random nonces safely; consider migrating AES-256-GCM users to that).

### 14. Decrypt path uses envelope-supplied `algorithm` (malleable)
**File:** `rust-core/src/crypto_engine/aead.rs:79-113`
```rust
match envelope.algorithm {
    AeadAlgorithm::Aes256Gcm => { ... }
    AeadAlgorithm::XChaCha20Poly1305 => { ... }
}
```
The decrypt function trusts `envelope.algorithm` to select the AEAD. Both algorithms use 32-byte keys (so the same HKDF-derived key works for both), but the AEAD constructions are different. An attacker can swap `Aes256Gcm` to `XChaCha20Poly1305` in the envelope. The nonce is also different sizes (12 vs 24 bytes), so the nonce is read as a 24-byte buffer regardless — meaning the attacker also has to forge a valid 24-byte nonce that the receiver accepts. The bound check is `envelope.nonce.len() == 24` for XChaCha, so swapping to XChaCha without re-padding the nonce fails. But this is a fragile defense.

**Fix:** Bind `algorithm` into the AAD. Compute AAD as `format!("soteria:alg:{}:block:{}:prev:{}", alg_id, block_index, lineage_prev)`. Then swapping the algorithm invalidates the AAD, decryption fails with auth error. Alternatively, include `algorithm` in the index `BlockIndexEntry` (signed by header integrity).

### 15. `assert!` / `expect` in security-critical input validation
**File:** `rust-core/src/crypto_engine/block.rs:88-93`
```rust
assert!(lineage_prev.len() == 64, ...);
let mut out = [0u8; 32];
hex::decode_to_slice(lineage_prev, &mut out).expect("lineage_prev must be valid 64-char hex");
```
On a panic in release with `panic = "abort"`, the daemon dies. On a panic in release with unwind, the caller has to choose between propagating the panic or catching it. Either way, malformed input should produce a typed `Err` and a logged warning, not a panic. A panic that escapes the FUSE handler will take down the daemon, and a maliciously-crafted file that triggers the panic is a DoS vector.

**Fix:** Convert to `Result`-returning functions: `fn lineage_prev_salt(lineage_prev: &str) -> Result<[u8; 32], anyhow::Error>`. Replace the `assert!` with a `bail!` and the `.expect` with `.map_err(...)?`.

### 16. FUSE reports all files as `uid: 0, gid: 0, perm: 0o600`
**File:** `rust-core/src/fs_layer/fuse_fs.rs:189-208`
Every file in the FUSE mount is reported as root-owned with mode 0600. This is fine for confidentiality if the daemon enforces it, but **the daemon doesn't enforce it**: any process running as the user that can read the FUSE mount can read all files (the FUSE kernel module enforces the mode bits, so root-only read of `mode 0600` does prevent other users). The deeper issue is that **the underlying backing files are also in the same directory** (e.g., `~/.soteria/backing/foo.sot`), and the daemon runs as the user. If an attacker can read the backing directory (which they often can, since it lives in $HOME), they can read the raw ciphertext. The encryption protects the *contents*, but not the *fact that the file exists*, and the encryption is bypassable via #1.

**Fix:** Add a `default_permissions` mount option to FUSE and propagate real UID/GID from the request. Add a check that the backing directory is `0700` and the daemon refuses to start if it's looser.

### 17. `open()` loads whole file into memory (memory-exhaustion DoS)
**File:** `rust-core/src/fs_layer/fuse_fs.rs:388-424`
`open` decrypts the entire file into a `CachedFile { plaintext: Vec<u8>, ... }`. A 10 GiB file in the volume causes a 10 GiB allocation in the daemon on first read. Combined with the read cache, the daemon can OOM.

**Fix:** Use streaming reads. Decrypt the requested `offset..offset+size` window on demand, not the whole file. The block index already provides per-block offsets and lengths.

### 18. `.soteria.inode_map` has no integrity protection
**File:** `rust-core/src/fs_layer/fuse_fs.rs:122-131`
The inode map is JSON written to disk with no MAC, no signature, no header integrity. An attacker with file-write access to the backing directory can replace it with arbitrary `(inode, name)` mappings. The mount will then use attacker-chosen names for key derivation (via `derive_file_key`). This doesn't directly leak plaintext (AEAD auth still applies), but it allows:
- **Confused-deputy**: the FUSE mount tries to read a file using an attacker-supplied name, the attacker controls the key derivation input.
- **DoS**: arbitrary garbage names cause O(n) string ops and key derivation per lookup.
- **Inode prediction attacks**: the inode is `inode_for(name) = BLAKE3(name)[0..8]`. If the attacker can predict the names, they can predict inodes.

**Fix:** Sign the inode map with a key bound to the volume (HKDF over the volume key). On load, verify the signature before trusting the contents. Alternatively, store the inode map inside the encrypted volume itself.

---

## LOW findings

### 19. `derive_file_key` is a hash, not a KDF
**File:** `rust-core/src/fs_layer/fuse_fs.rs:155-160`
The function is named `derive_file_key` but is a single BLAKE3 hash. There's no work factor, no salt, no key-stretching. If the volume key is weak (e.g., a 6-character passphrase that survived Argon2id with a low cost), the per-file keys are weak.

**Fix:** Either rename it to `derive_file_id` (since it produces a file_id, not a key) or wrap the volume key in HKDF with a per-file salt.

### 20. `hex_to_bytes` silently drops invalid hex
**File:** `rust-core/src/fs_layer/storage.rs:404-416`
```rust
if let Ok(b) = u8::from_str_radix(..., 16) { out.push(b); }
i += 2;
```
Invalid hex characters are silently dropped. A corrupted `lineage_new` string would produce a partial 32-byte array (with leading zeros), and the lineage check would fail at a different point. This makes debugging harder and may mask real corruption. Same issue exists in `crypto_engine/shares.rs` `hex_decode`.

**Fix:** Use `hex::decode` and propagate errors. Or, validate input is exactly 64 hex chars before decoding.

### 21. `nonce_len` is silently truncated to 24 bytes
**File:** `rust-core/src/fs_layer/storage.rs:375-378`
```rust
let mut nonce = [0u8; 24];
let n = ct.envelope.nonce.len().min(24);
nonce[..n].copy_from_slice(&ct.envelope.nonce[..n]);
```
The index has a fixed 24-byte nonce field. AES-GCM uses 12 bytes, so the upper 12 bytes are always zero for AES. The decrypt path slices the nonce correctly via `envelope.nonce[..nonce_len(self.algorithm)]`. This is fine, but the silent truncation is a code smell.

**Fix:** Make the index nonce field a tagged union (`enum Nonce { Aes96([u8;12]), XChaCha192([u8;24]) }`) or store the actual length.

### 22. `SecureBox::new` `mlock` failure is silent
**File:** `rust-core/src/crypto_engine/secure_box.rs:42-65`
`mlock` is best-effort and the `locked` flag is recorded but never read. There's no log, no metric, no warning. In a containerized environment without `CAP_IPC_LOCK`, the key material is silently pageable to swap.

**Fix:** At minimum, log a warning on mlock failure. Better: propagate the failure to the caller and let the daemon policy decide whether to continue.

### 23. `Open` of share file is unbounded size
**File:** `rust-core/src/crypto_engine/shares.rs:174-176`
```rust
let raw = std::fs::read(&path)?;
```
A multi-gigabyte share file is read entirely into memory. DoS via large JSON.

**Fix:** Either use a streaming JSON parser (e.g., `serde_json::Deserializer::from_reader`) or cap the file size before reading.

### 24. Audit-log `rotate` window can leave log empty if crash mid-rotate
**File:** `rust-core/src/policy/audit_log.rs:189-207`
The `rotate` function renames the current log to `.1`, then resets in-memory state. If the daemon crashes between the rename and the next append, the next `open` call reads an empty log, missing all pre-rotation entries. The entries are still on disk in `.1`, but the active log is gone.

**Fix:** Mark the rotation with an explicit "rotation in progress" entry that gets appended before the rename and removed after, so recovery can detect the state.

---

## INFO findings

### 25. `ratchet_key` accepts caller-supplied `entropy` (audit caller)
**File:** `rust-core/src/crypto_engine/kdf.rs:30-40`
```rust
pub fn ratchet_key(
    current: &mut Zeroizing<[u8; 32]>,
    entropy: &[u8],
    counter: u64,
) -> crate::Result<[u8; 32]>
```
The `entropy` parameter is the HKDF salt. The ratchet state is mixed with this entropy. If a caller passes low-entropy or attacker-controlled `entropy`, the ratchet can be predicted or replayed. Need to audit every caller of `ratchet_key` to confirm `entropy` is high-quality random (e.g., `OsRng` output).

I didn't audit the callers in this pass — flagged for follow-up.

---

## Non-findings (things that look suspicious but are OK)

- **`dsa.rs:138` `VerifyingKey::decode(&pk_enc)`** — `decode` returns `Result`; caller handles errors. OK.
- **`wal.rs:131` `try_into().unwrap()`** — Infallible on the 4-byte slice for u32. OK.
- **`storage.rs:120-132` Header magic / version / integrity check** — Magic and version are checked, integrity covers 0..80. The bug is that KDF_HASH is outside that window (#2), not that the existing check is broken.
- **`pq.rs:108-121` `KeyEnvelope` field validation** — Lengths are validated in `wrap_key`/`unwrap_key` at use time. OK.
- **`dsa.rs:79-92` `generate_keypair` uses `OsRng`** — Good. No `thread_rng()`.
- **`secure_box.rs:88-110` `Drop` order (zeroize then munlock)** — Correct ordering. OK.
- **`audit_log.rs:241-263` `parse_bytes` drops malformed non-final lines** — Chain verifier catches dropped middle lines via broken chain hash. OK.
- **`wal.rs:88-91` Tempfile with random name** — Good, prevents predictable path races. OK.
- **`fs_layer/storage.rs:236-271` `save` 6-step crash-safe write** — WAL + atomic rename + dir fsync. Looks correct. OK.

---

## Recommended remediation order

1. **#1 (CRITICAL, FUSE hardcoded key)** — refuse to mount until a real key source is wired. Add a startup self-test.
2. **#2 (CRITICAL, header integrity bypass)** — move integrity to end of header, extend coverage to include KDF_HASH.
3. **#3, #4, #5 (HIGH, decrypt / truncate / rename)** — fix in one PR: switch key derivation to use `file_id` (immutable, persisted in `.soteria.inode_map` with integrity), call `verify_lineage()` from `plaintext()`, fix truncate to re-encrypt.
4. **#6 (HIGH, capability forgery)** — either implement real MAC verification or remove the dead `token_blake3` field entirely.
5. **#7, #8, #9 (HIGH/MEDIUM, share-file chain integrity)** — fix chain length check, error on serialize failure, call `verify_chain()` on open.
6. **#10, #11, #12, #13, #14, #15, #16, #17, #18** (MEDIUM) — bundle into a "defense-in-depth" PR: bound parser allocations, enforce Argon2id minimums, bind nonce to region+volume, bind algorithm to AAD, replace `assert!`/`expect` with `Result`, real FUSE perms, streaming reads, signed inode map.
7. **#19–#24** (LOW) — opportunistic cleanup PR.
8. **#25** (INFO) — caller audit of `ratchet_key`.

---

## What this audit did NOT cover

- `intrusion/*`, `security/*`, `sensors/*`, `deception*`, `anti_forensic/*`, `snapshot_engine/*` (out of scope this pass).
- `response_engine/*` (out of scope).
- `tpm/*` (TPM keyring path; relevant to #1 fix but not audited).
- `simulation/*` (test harness only).
- `tui/*` (TUI, not security-critical).
- Fuzzing / property-based tests with the actual `proptest` / `cargo-fuzz` machinery.
- `cargo audit` / `cargo geiger` / `cargo clippy -- -W clippy::correctness` runs.

A follow-up audit pass should cover the intrusion and snapshot engines, and run automated tooling.
