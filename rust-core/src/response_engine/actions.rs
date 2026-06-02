use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ResponseAction {
    Freeze,
    Isolate,
    Revoke,
    Rollback,
    Allow,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseContext {
    pub frozen_domains: BTreeSet<String>,
    pub isolated_processes: BTreeSet<u32>,
    pub revoked_sessions: BTreeSet<String>,
}

impl ResponseContext {
    pub fn apply(&mut self, action: &ResponseAction, domain: &str, pid: Option<u32>) {
        match action {
            ResponseAction::Freeze => {
                self.frozen_domains.insert(domain.into());
            }
            ResponseAction::Isolate => {
                if let Some(pid) = pid {
                    self.isolated_processes.insert(pid);
                }
            }
            ResponseAction::Revoke => {
                self.revoked_sessions.insert(domain.into());
            }
            ResponseAction::Rollback | ResponseAction::Allow => {}
        }
    }
}
