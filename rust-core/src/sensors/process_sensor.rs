use crate::event_bus::{Severity, SoteriaEvent};

pub fn unknown_process_event(pid: u32, reason: &str) -> crate::Result<SoteriaEvent> {
    SoteriaEvent::new(
        "PROCESS_ANOMALY",
        "process_sensor",
        Severity::new(0.75),
        serde_json::json!({"pid": pid, "reason": reason}),
    )
}
