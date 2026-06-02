use crate::event_bus::{Severity, SoteriaEvent};

pub fn write_event(path: &str, bytes: usize, pid: u32) -> crate::Result<SoteriaEvent> {
    SoteriaEvent::new(
        "FS_WRITE",
        "write_sensor",
        Severity::new(0.2),
        serde_json::json!({"path": path, "bytes": bytes, "pid": pid}),
    )
}
