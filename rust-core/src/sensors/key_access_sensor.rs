use crate::event_bus::{Severity, SoteriaEvent};

pub fn key_access_event(pid: u32, allowed: bool) -> crate::Result<SoteriaEvent> {
    SoteriaEvent::new(
        if allowed {
            "KEY_ACCESS"
        } else {
            "KEY_ACCESS_DENIED"
        },
        "key_access_sensor",
        Severity::new(if allowed { 0.1 } else { 0.9 }),
        serde_json::json!({"pid": pid, "allowed": allowed}),
    )
}
