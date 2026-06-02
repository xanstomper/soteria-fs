use super::{ResponseAction, ResponseContext};
use crate::config::ResponseConfig;
use crate::event_bus::SoteriaEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PolicyDecision {
    pub action: ResponseAction,
    pub reason: String,
}

pub struct PolicyEngine {
    entropy_threshold: f64,
    allowed_actions: Vec<ResponseAction>,
}

impl PolicyEngine {
    pub fn from_config(cfg: &ResponseConfig) -> Self {
        let allowed_actions = cfg
            .allowed_actions
            .iter()
            .filter_map(|a| match a.as_str() {
                "FREEZE" => Some(ResponseAction::Freeze),
                "ISOLATE" => Some(ResponseAction::Isolate),
                "REVOKE" => Some(ResponseAction::Revoke),
                "ROLLBACK" => Some(ResponseAction::Rollback),
                _ => None,
            })
            .collect();
        Self {
            entropy_threshold: cfg.entropy_spike_threshold,
            allowed_actions,
        }
    }
    pub fn evaluate(&mut self, event: &SoteriaEvent, ctx: &mut ResponseContext) -> PolicyDecision {
        let decision = match event.event_type.as_str() {
            "ENTROPY_SPIKE" if event.severity.0 >= self.entropy_threshold => PolicyDecision {
                action: ResponseAction::Freeze,
                reason: "entropy spike exceeded threshold".into(),
            },
            "KEY_ACCESS_DENIED" => PolicyDecision {
                action: ResponseAction::Revoke,
                reason: "unauthorized key access attempt".into(),
            },
            "PROCESS_ANOMALY" => PolicyDecision {
                action: ResponseAction::Isolate,
                reason: "process anomaly".into(),
            },
            "RANSOMWARE_PATTERN" => PolicyDecision {
                action: ResponseAction::Rollback,
                reason: "ransomware pattern".into(),
            },
            _ => PolicyDecision {
                action: ResponseAction::Allow,
                reason: "no deterministic rule matched".into(),
            },
        };
        if decision.action != ResponseAction::Allow
            && !self.allowed_actions.contains(&decision.action)
        {
            return PolicyDecision {
                action: ResponseAction::Allow,
                reason: "action not in configured allowlist".into(),
            };
        }
        ctx.apply(
            &decision.action,
            "default",
            event
                .metadata
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
        );
        decision
    }
}
