use crate::key_manager::{Capability, CapabilityScope};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Tracks capability tokens issued to processes and supports explicit
/// revocation. Revoked tokens are removed immediately and a record of the
/// revocation is kept for audit purposes.
pub struct RevocationEngine {
    active: BTreeMap<u32, Capability>,
    revoked: Vec<RevocationRecord>,
    /// When set, every revocation is also appended to the audit log at
    /// this path. The engine never blocks on log I/O errors; it returns
    /// the error so the caller can decide what to do.
    audit_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub process_id: u32,
    pub region_id: String,
    pub reason: String,
    pub revoked_at: std::time::SystemTime,
}

impl RevocationRecord {
    pub fn new(process_id: u32, region_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            process_id,
            region_id: region_id.into(),
            reason: reason.into(),
            revoked_at: std::time::SystemTime::now(),
        }
    }
}

impl RevocationEngine {
    pub fn new() -> Self {
        Self {
            active: BTreeMap::new(),
            revoked: Vec::new(),
            audit_path: None,
        }
    }

    /// Configure the on-disk audit log. If set, every [`Self::revoke`] call
    /// also appends a BLAKE3-chained entry to the log at this path. Pass
    /// `None` to disable persistence.
    pub fn set_audit_path(&mut self, path: Option<PathBuf>) {
        self.audit_path = path;
    }

    /// Path of the on-disk audit log, if configured.
    pub fn audit_path(&self) -> Option<&Path> {
        self.audit_path.as_deref()
    }

    pub fn issue(
        &mut self,
        process_id: u32,
        scope: CapabilityScope,
        ttl_seconds: u64,
    ) -> &Capability {
        let cap = Capability::issue(process_id, scope, ttl_seconds);
        self.active.insert(process_id, cap);
        self.active.get(&process_id).expect("just inserted")
    }

    pub fn has_valid_capability(&self, process_id: u32) -> bool {
        match self.active.get(&process_id) {
            Some(c) => c.valid() && c.ttl_seconds > 0,
            None => false,
        }
    }

    pub fn scope_for(&self, process_id: u32) -> Option<&CapabilityScope> {
        self.active.get(&process_id).map(|c| &c.scope)
    }

    pub fn allow_read(&self, process_id: u32, path: &Path) -> bool {
        match self.active.get(&process_id) {
            Some(c) => c.valid() && c.scope.can_read && path.starts_with(&c.scope.path_prefix),
            None => false,
        }
    }

    pub fn allow_write(&self, process_id: u32, path: &Path) -> bool {
        match self.active.get(&process_id) {
            Some(c) => c.valid() && c.scope.can_write && path.starts_with(&c.scope.path_prefix),
            None => false,
        }
    }

    /// Revoke a process. Removes the active capability and records the
    /// revocation with the supplied reason. If an audit path is configured,
    /// the record is also appended to the BLAKE3-chained log on disk and
    /// any I/O error is returned.
    pub fn revoke(
        &mut self,
        process_id: u32,
        reason: impl Into<String>,
    ) -> Result<Option<RevocationRecord>, RevocationError> {
        let Some(cap) = self.active.remove(&process_id) else {
            return Ok(None);
        };
        let record = RevocationRecord::new(process_id, cap.scope.region_id, reason);
        // Persist BEFORE updating in-memory state. If the write fails, the
        // revocation is rolled back so the in-memory and on-disk states
        // never disagree.
        if let Some(path) = &self.audit_path {
            let mut log = crate::policy::audit_log::AuditLog::open(path.clone())
                .map_err(|e| RevocationError::AuditOpen(e.to_string()))?
                .0;
            log.append(&record)
                .map_err(|e| RevocationError::AuditAppend(e.to_string()))?;
        }
        self.revoked.push(record.clone());
        Ok(Some(record))
    }

    pub fn revocation_history(&self) -> &[RevocationRecord] {
        &self.revoked
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Reap capabilities whose TTL has elapsed. Returns the number of
    /// capabilities that expired.
    pub fn reap_expired(&mut self) -> usize {
        let mut reaped = 0usize;
        let now = std::time::SystemTime::now();
        self.active.retain(|_, c| {
            let elapsed = now.duration_since(c.issued_at).unwrap_or(Duration::MAX);
            let keep = elapsed <= Duration::from_secs(c.ttl_seconds);
            if !keep {
                reaped += 1;
            }
            keep
        });
        reaped
    }
}

/// Errors that can be returned from [`RevocationEngine::revoke`] when the
/// audit log is configured and a write fails.
#[derive(Debug, Clone)]
pub enum RevocationError {
    /// Failed to open the audit log for append.
    AuditOpen(String),
    /// Failed to append the entry to the audit log.
    AuditAppend(String),
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditOpen(m) => write!(f, "audit open: {m}"),
            Self::AuditAppend(m) => write!(f, "audit append: {m}"),
        }
    }
}

impl std::error::Error for RevocationError {}

impl Default for RevocationEngine {
    fn default() -> Self {
        Self::new()
    }
}
