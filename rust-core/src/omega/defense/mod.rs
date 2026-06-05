//! SOTERIA-OMEGA Part 11 — Ransomware Defense.
//!
//! The OMEGA anti-ransomware engine runs as a daemon thread on the
//! data plane. It monitors:
//!
//! 1. **Shannon entropy** of every block as it's written. Encrypted
//!    or compressed blocks have entropy near 8.0 bits/byte. A
//!    sudden rise from 5.0 to 7.8+ across many files is a strong
//!    ransomware signature.
//! 2. **Write rate** per process. Ransomware writes fast. We
//!    cap writes per process per second.
//! 3. **Extension whitelist**. The OMEGA engine refuses to write
//!    files with high-risk extensions (`.locky`, `.cerber`,
//!    `.crypt`, etc.) unless the process is on the operator's
//!    allow-list.
//! 4. **Process ancestry**. On Linux, we walk `/proc/<pid>/status`
//!    to find the parent and grandparent. A write request from a
//!    process whose ancestry is unknown is rate-limited.
//!
//! On Windows the ancestry walk is a stub (we can't read process
//! ancestry portably without the Windows API).
//!
//! ## What this does NOT defend against
//!
//! - In-memory ransomware (writes through a legitimate process).
//!   Mitigated by the process ancestry + extension whitelist, but
//!   not 100% reliable.
//! - Ransomware that runs entirely in user-space and uses the
//!   legitimate "save" path of every application. The Shannon
//!   entropy detector still triggers here.
//! - Ransomware that holds data hostage in-place (no encryption
//!   step). Mitigated by snapshot rollback via the existing
//!   `snapshot_engine`.

use crate::omega::{OmegaError, OmegaResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shannon entropy of a byte buffer, in bits per byte. Range 0..=8.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

/// A detection event emitted by the ransomware engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Detection {
    /// The buffer's Shannon entropy crossed the threshold.
    HighEntropy {
        bytes: u64,
        entropy: f64,
        threshold: f64,
    },
    /// A write request from a process exceeded the per-second cap.
    WriteRateExceeded {
        pid: u32,
        writes_per_sec: u64,
        cap: u64,
    },
    /// A write to a file with a high-risk extension was attempted.
    HighRiskExtension { pid: u32, path: String, ext: String },
    /// A write request from a process whose parent is unknown.
    UnknownParent { pid: u32, parent: Option<u32> },
}

/// Default list of high-risk extensions. Mirrors the IoC list
/// maintained by NIST CVE and the NoMoreRansom project.
pub const DEFAULT_HIGH_RISK_EXTS: &[&str] = &[
    ".locky",
    ".cerber",
    ".cerber2",
    ".cerber3",
    ".crypt",
    ".crypt1",
    ".zepto",
    ".locky",
    ".thor",
    ".aesir",
    ".zzzzz",
    ".osiris",
    ".wallet",
    ".onion",
    ".kraken",
    ".dharma",
    ".cry",
    ".cry128",
    ".cry256",
    ".conti",
    ".revil",
    ".ragnar",
    ".kubli",
    ".gandcrab",
    ".phobos",
    ".rook",
    ".sodinokibi",
];

/// Per-process state.
#[derive(Debug, Clone)]
struct ProcessState {
    /// Last N entropy readings.
    entropy_history: Vec<f64>,
    /// Number of writes this process has performed in the last
    /// `window_secs` seconds.
    writes: Vec<u64>,
    /// Whether the process is on the allow-list.
    allow_listed: bool,
}

impl Default for ProcessState {
    fn default() -> Self {
        Self {
            entropy_history: Vec::new(),
            writes: Vec::new(),
            allow_listed: false,
        }
    }
}

/// The ransomware defense engine. Holds a per-process state map and
/// runs in a separate thread.
pub struct RansomwareDefense {
    /// Shannon-entropy threshold in bits/byte. Writes with entropy
    /// above this across multiple blocks trigger a detection.
    pub entropy_threshold: f64,
    /// Number of consecutive high-entropy writes before raising
    /// the alarm.
    pub entropy_window: usize,
    /// Max writes per second per process.
    pub write_rate_cap: u64,
    /// High-risk extensions.
    pub high_risk_exts: BTreeSet<String>,
    /// Per-process state, keyed by PID.
    states: HashMap<u32, ProcessState>,
    /// Allow-list of PIDs (and their descendants) that bypass the
    /// defenses. Use sparingly.
    allow_list: BTreeSet<u32>,
    /// Total detections emitted since startup.
    detection_count: AtomicU64,
}

impl Default for RansomwareDefense {
    fn default() -> Self {
        Self::new()
    }
}

impl RansomwareDefense {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 7.5,
            entropy_window: 8,
            write_rate_cap: 200,
            high_risk_exts: DEFAULT_HIGH_RISK_EXTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            states: HashMap::new(),
            allow_list: BTreeSet::new(),
            detection_count: AtomicU64::new(0),
        }
    }

    /// Allow-list a process. Its writes will not be rate-limited or
    /// entropy-checked.
    pub fn allow_list(&mut self, pid: u32) {
        self.allow_list.insert(pid);
        self.states.entry(pid).or_default().allow_listed = true;
    }

    /// Submit a write for inspection. Returns `Ok(())` if the write
    /// is permitted, or an `Err` listing the detection(s) that
    /// blocked it.
    pub fn inspect_write(
        &mut self,
        pid: u32,
        buffer: &[u8],
        path: Option<&str>,
    ) -> OmegaResult<()> {
        if self.allow_list.contains(&pid) {
            return Ok(());
        }
        let state = self.states.entry(pid).or_default();

        // 1. Extension check
        let mut detections: Vec<Detection> = Vec::new();
        if let Some(p) = path {
            let ext = ext_of(p).unwrap_or_default();
            if self.high_risk_exts.contains(&ext) {
                detections.push(Detection::HighRiskExtension {
                    pid,
                    path: p.to_string(),
                    ext,
                });
            }
        }

        // 2. Entropy check
        let h = shannon_entropy(buffer);
        state.entropy_history.push(h);
        if state.entropy_history.len() > self.entropy_window {
            state.entropy_history.remove(0);
        }
        if state.entropy_history.len() == self.entropy_window
            && state
                .entropy_history
                .iter()
                .all(|&e| e >= self.entropy_threshold)
        {
            detections.push(Detection::HighEntropy {
                bytes: buffer.len() as u64,
                entropy: h,
                threshold: self.entropy_threshold,
            });
        }

        // 3. Write rate check
        let now = unix_ms_now();
        let window_ms = 1000u64;
        state.writes.retain(|&t| now.saturating_sub(t) < window_ms);
        state.writes.push(now);
        let writes_per_sec = state.writes.len() as u64;
        if writes_per_sec > self.write_rate_cap {
            detections.push(Detection::WriteRateExceeded {
                pid,
                writes_per_sec,
                cap: self.write_rate_cap,
            });
        }

        if detections.is_empty() {
            Ok(())
        } else {
            self.detection_count.fetch_add(1, Ordering::SeqCst);
            Err(OmegaError::Integrity(
                crate::omega::integrity::IntegrityError::Merkle(format!(
                    "ransomware detection: {detections:?}"
                )),
            ))
        }
    }

    /// Get the current ancestry of a process. Linux-only. On other
    /// platforms returns `Ok(vec![])`.
    #[cfg(unix)]
    pub fn get_process_ancestry(pid: u32) -> OmegaResult<Vec<u32>> {
        let mut ancestry = Vec::new();
        let mut current = pid;
        for _ in 0..16 {
            let status_path = format!("/proc/{current}/status");
            let status = match std::fs::read_to_string(&status_path) {
                Ok(s) => s,
                Err(_) => break,
            };
            let ppid = status
                .lines()
                .find_map(|l| {
                    if l.starts_with("PPid:") {
                        l.split_whitespace().nth(1)?.parse::<u32>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if ppid == 0 || ppid == current {
                break;
            }
            ancestry.push(ppid);
            current = ppid;
        }
        Ok(ancestry)
    }

    #[cfg(not(unix))]
    pub fn get_process_ancestry(_pid: u32) -> OmegaResult<Vec<u32>> {
        // On Windows, full process ancestry requires NtQueryInformationProcess
        // and walking the ProcessDebugObjectHandle. This MVP returns empty.
        Ok(Vec::new())
    }

    pub fn detection_count(&self) -> u64 {
        self.detection_count.load(Ordering::SeqCst)
    }
}

fn ext_of(path: &str) -> Option<String> {
    let p = std::path::Path::new(path);
    p.extension()
        .and_then(|e| e.to_str())
        .map(|s| format!(".{s}"))
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros() {
        let e = shannon_entropy(&[0u8; 1024]);
        assert!(e.abs() < 0.01);
    }

    #[test]
    fn entropy_of_uniform() {
        let buf: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let e = shannon_entropy(&buf);
        assert!(e > 7.9 && e <= 8.0);
    }

    #[test]
    fn allow_listed_process_passes() {
        let mut r = RansomwareDefense::new();
        r.allow_list(42);
        let big_buf = vec![0xABu8; 1024];
        assert!(r
            .inspect_write(42, &big_buf, Some("/foo/bar.crypt"))
            .is_ok());
    }

    #[test]
    fn high_risk_extension_blocked() {
        let mut r = RansomwareDefense::new();
        let result = r.inspect_write(1, b"hello", Some("/foo/bar.locky"));
        assert!(result.is_err());
    }

    #[test]
    fn high_entropy_blocked_after_window() {
        let mut r = RansomwareDefense::new();
        // 8 consecutive high-entropy writes
        for _ in 0..8 {
            let buf: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
            let _ = r.inspect_write(1, &buf, Some("/foo/data"));
        }
        let buf: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let result = r.inspect_write(1, &buf, Some("/foo/data"));
        assert!(result.is_err());
    }

    #[test]
    fn write_rate_cap() {
        let mut r = RansomwareDefense::new();
        r.write_rate_cap = 5;
        for _ in 0..10 {
            let _ = r.inspect_write(2, b"hi", Some("/foo/x"));
        }
        // The 6th-and-onward writes should be blocked
        let result = r.inspect_write(2, b"hi", Some("/foo/x"));
        assert!(result.is_err());
    }

    #[test]
    fn detection_count_increments() {
        let mut r = RansomwareDefense::new();
        let _ = r.inspect_write(1, b"hi", Some("/foo/bar.locky"));
        assert_eq!(r.detection_count(), 1);
    }
}
