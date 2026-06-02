//! Append-only audit log for capability revocations.
//!
//! ## Format
//!
//! JSONL: one [`AuditEntry`] per line, each line a self-contained JSON object.
//! A `chain` field carries the BLAKE3 hash of the previous line, producing a
//! tamper-evident log:
//!
//! ```text
//! chain_n = BLAKE3( chain_{n-1} || canonical_json(entry_n) )
//! ```
//!
//! The first entry's `prev_chain` is the all-zero 32-byte hash. Any mutation
//! to a historical entry breaks the chain at the next entry, so the audit
//! reader can detect exactly which entry was tampered with.
//!
//! ## Crashes
//!
//! The writer appends one entry at a time with `O_APPEND`, then `fsync`s.
//! On a crash between two appends, the most recent entry may be truncated
//! or missing. The reader treats the last partial line as garbage and
//! truncates it before verifying.
//!
//! ## Concurrency
//!
//! Multiple processes can write to the same log if they cooperate via OS
//! append-mode file locking. For now we assume a single writer (the
//! `soteriad` daemon); tests simulate concurrent writers by giving each
//! writer its own log.

use crate::policy::revocation::RevocationRecord;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A single audit-log entry. Includes the BLAKE3 chain hash.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub process_id: u32,
    pub region_id: String,
    pub reason: String,
    /// Wall-clock time in milliseconds since the Unix epoch. Stored as i64
    /// for portability across systems whose `SystemTime` is signed.
    pub revoked_at_unix_ms: i64,
    /// 32-byte BLAKE3 chain hash, hex-encoded.
    pub chain: String,
}

impl AuditEntry {
    fn compute_chain(prev: &[u8; 32], payload: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(prev);
        h.update(payload);
        *h.finalize().as_bytes()
    }

    fn to_canonical_json(&self) -> Vec<u8> {
        // Deterministic JSON serialization: same field order, no whitespace.
        // Implemented by constructing a JSON object via serde_json with the
        // default serializer (which preserves struct field order).
        let mut obj = serde_json::Map::new();
        obj.insert("seq".into(), serde_json::Value::from(self.seq));
        obj.insert(
            "process_id".into(),
            serde_json::Value::from(self.process_id),
        );
        obj.insert(
            "region_id".into(),
            serde_json::Value::from(self.region_id.clone()),
        );
        obj.insert(
            "reason".into(),
            serde_json::Value::from(self.reason.clone()),
        );
        obj.insert(
            "revoked_at_unix_ms".into(),
            serde_json::Value::from(self.revoked_at_unix_ms),
        );
        serde_json::to_vec(&serde_json::Value::Object(obj)).expect("audit entry serializes")
    }
}

/// Outcome of a chain verification.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VerifyResult {
    /// Every entry in the log chain-checks against the previous one.
    Ok { entries: usize },
    /// The entry at `index` has an invalid `chain` field. Earlier entries
    /// are intact.
    Tampered { first_bad_index: usize },
    /// A non-final line failed to deserialize as JSON, indicating a crash
    /// mid-write or filesystem corruption. Earlier entries are intact.
    Malformed { first_bad_index: usize },
}

/// Append-only audit log over [`RevocationRecord`]s.
pub struct AuditLog {
    path: PathBuf,
    last_chain: [u8; 32],
    next_seq: u64,
}

impl AuditLog {
    /// Open or create a log at `path`, reading any existing entries to
    /// establish the chain head. Returns the log and the number of entries
    /// that were already present.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<(Self, usize)> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        // Read existing entries to establish the chain head. The reader
        // tolerates a truncated final line.
        let entries = read_entries(&path).map_err(|e| std::io::Error::other(e.to_string()))?;
        let (last_chain, next_seq) = match entries.last() {
            Some(e) => (hex_to_32(&e.chain)?, e.seq + 1),
            None => ([0u8; 32], 0),
        };
        Ok((
            Self {
                path,
                last_chain,
                next_seq,
            },
            entries.len(),
        ))
    }

    /// Append a revocation to the log. Returns the new entry.
    pub fn append(&mut self, record: &RevocationRecord) -> std::io::Result<AuditEntry> {
        let unix_ms = system_time_to_unix_ms(record.revoked_at);
        let payload = AuditEntry {
            seq: self.next_seq,
            process_id: record.process_id,
            region_id: record.region_id.clone(),
            reason: record.reason.clone(),
            revoked_at_unix_ms: unix_ms,
            chain: String::new(), // placeholder; computed below
        };
        let canonical = payload.to_canonical_json();
        let new_chain = AuditEntry::compute_chain(&self.last_chain, &canonical);
        let mut entry = payload;
        entry.chain = hex_32(&new_chain);
        // Write the entry as a single line, fsync.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line =
            serde_json::to_string(&entry).map_err(|e| std::io::Error::other(e.to_string()))?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        // Update in-memory state.
        self.last_chain = new_chain;
        self.next_seq += 1;
        Ok(entry)
    }

    /// Path of the underlying log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify the entire log file end-to-end. A missing log file is
    /// considered a valid empty log (`Ok { entries: 0 }`).
    pub fn verify(&self) -> std::io::Result<VerifyResult> {
        let raw = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(VerifyResult::Ok { entries: 0 });
            }
            Err(e) => return Err(e),
        };
        verify_bytes(&raw)
    }
}

/// Read the log file and return all valid entries, tolerating a truncated
/// final line. Public for tests and CLI use.
pub fn read_entries(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!(e)),
    };
    Ok(parse_bytes(&raw))
}

/// Parse a byte buffer into entries, dropping a truncated trailing line.
pub fn parse_bytes(raw: &[u8]) -> Vec<AuditEntry> {
    let mut out = Vec::new();
    for line in raw.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_slice::<AuditEntry>(line) {
            Ok(e) => out.push(e),
            Err(_) => {
                // A non-empty line that fails to parse is either a truncated
                // final entry (drop it) or a corrupt earlier entry (the
                // chain verifier will catch it).
                if out.is_empty() {
                    return out;
                }
                // We can't tell which case this is from parsing alone; the
                // chain verifier will resolve it.
                continue;
            }
        }
    }
    out
}

/// Verify a raw log buffer.
pub fn verify_bytes(raw: &[u8]) -> std::io::Result<VerifyResult> {
    let entries = parse_bytes(raw);
    if entries.is_empty() && raw.iter().any(|b| !b.is_ascii_whitespace()) {
        return Ok(VerifyResult::Malformed { first_bad_index: 0 });
    }
    let mut prev: [u8; 32] = [0u8; 32];
    for (i, entry) in entries.iter().enumerate() {
        if entry.seq != i as u64 {
            return Ok(VerifyResult::Tampered { first_bad_index: i });
        }
        // Recompute the chain from the entry's payload (without the chain
        // field itself).
        let payload = AuditEntry {
            seq: entry.seq,
            process_id: entry.process_id,
            region_id: entry.region_id.clone(),
            reason: entry.reason.clone(),
            revoked_at_unix_ms: entry.revoked_at_unix_ms,
            chain: String::new(),
        }
        .to_canonical_json();
        let expected = AuditEntry::compute_chain(&prev, &payload);
        let got = match hex_to_32(&entry.chain) {
            Ok(b) => b,
            Err(_) => return Ok(VerifyResult::Tampered { first_bad_index: i }),
        };
        if expected != got {
            return Ok(VerifyResult::Tampered { first_bad_index: i });
        }
        prev = got;
    }
    Ok(VerifyResult::Ok {
        entries: entries.len(),
    })
}

fn hex_32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn hex_to_32(s: &str) -> std::io::Result<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected 64 hex chars, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let h = (bytes[i * 2] as char)
            .to_digit(16)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad hex"))?;
        let l = (bytes[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad hex"))?;
        out[i] = ((h << 4) | l) as u8;
        i += 1;
    }
    Ok(out)
}

fn system_time_to_unix_ms(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
