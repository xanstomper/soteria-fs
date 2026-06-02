use crate::event_bus::bus::EventRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiObservation {
    pub risk_score: f64,
    pub label: String,
    pub recommendation: String,
    pub enforcement_allowed: bool,
}

pub trait AiObserver {
    fn observe(&self, records: &[EventRecord]) -> AiObservation;
}

pub struct ReadOnlyHeuristicObserver;

impl AiObserver for ReadOnlyHeuristicObserver {
    fn observe(&self, records: &[EventRecord]) -> AiObservation {
        let max = records
            .iter()
            .map(|r| match r.severity {
                crate::event_bus::bus::Severity::Critical => 1.0,
                crate::event_bus::bus::Severity::Warning => 0.7,
                crate::event_bus::bus::Severity::Advisory => 0.4,
                crate::event_bus::bus::Severity::Info => 0.1,
            })
            .fold(0.0, f64::max);
        AiObservation {
            risk_score: max,
            label: if max > 0.8 {
                "high_risk_activity"
            } else {
                "normal"
            }
            .into(),
            recommendation: "review_policy_decision".into(),
            enforcement_allowed: false,
        }
    }
}
