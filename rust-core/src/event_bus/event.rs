use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct Severity(pub f64);

impl Severity {
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoteriaEvent {
    pub event_type: String,
    pub source: String,
    pub severity: Severity,
    pub metadata: serde_json::Value,
    pub timestamp_unix_ms: u128,
}

impl SoteriaEvent {
    pub fn new(
        event_type: impl Into<String>,
        source: impl Into<String>,
        severity: Severity,
        metadata: serde_json::Value,
    ) -> crate::Result<Self> {
        Ok(Self {
            event_type: event_type.into(),
            source: source.into(),
            severity,
            metadata,
            timestamp_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        })
    }
}
