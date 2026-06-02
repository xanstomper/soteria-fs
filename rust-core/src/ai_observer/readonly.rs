use crate::event_bus::EventRecord;
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
            .map(|r| r.event.severity.0)
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
