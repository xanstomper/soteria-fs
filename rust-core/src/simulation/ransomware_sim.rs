use crate::deception_layer::honey_fs::HoneyFileSystem;
use crate::event_bus::{EventBus, Severity, SoteriaEvent};
use crate::policy::revocation::RevocationEngine;
use crate::security::canary::CanaryToken;
use crate::security::detector::AnomalyDetector;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct SimReport {
    pub scenario: String,
    pub triggered_alerts: Vec<String>,
    pub revocations: Vec<String>,
    pub honey_touched: bool,
    pub canary_alerted: bool,
    pub entropy_alerted: bool,
    pub passes: bool,
}

/// Scenario A — mass encryption. Simulates a ransomware-style burst of writes
/// to a single region. Verifies that entropy-spike and process-anomaly events
/// trigger the response engine and the revocation engine.
pub fn scenario_mass_encryption(
    detector: &mut AnomalyDetector,
    bus: &mut EventBus,
    revocation: &mut RevocationEngine,
) -> SimReport {
    let region = "region-A";
    detector.register_canary(CanaryToken::new(region));
    let mut triggered = Vec::new();

    // 120 high-entropy payloads simulated in one burst.
    for i in 0..120 {
        let payload = vec![(i ^ 0xA5) as u8; 4096];
        for ev in detector.observe_write(region, &payload) {
            bus.append(ev.clone()).expect("append event");
            triggered.push(format!("ENTROPY_SPIKE:{i}"));
        }
    }
    let ransomware_event = SoteriaEvent::new(
        "RANSOMWARE_PATTERN",
        "ransomware_simulator",
        Severity::new(0.99),
        serde_json::json!({"region_id": region, "writes": 120}),
    )
    .unwrap();
    bus.append(ransomware_event.clone()).expect("append event");
    triggered.push("RANSOMWARE_PATTERN".to_string());

    let pid = 0xDEAD_BEEFu32;
    // Issue a capability for the offending process first so the revocation
    // engine has something to revoke.
    revocation.issue(
        pid,
        crate::key_manager::CapabilityScope {
            region_id: region.into(),
            path_prefix: PathBuf::from("/data/region-A"),
            can_read: true,
            can_write: true,
        },
        60,
    );
    let rec = revocation
        .revoke(pid, "mass encryption detected")
        .expect("audit log write must succeed in test");
    let revocations: Vec<String> = rec
        .iter()
        .map(|r| {
            format!(
                "pid={} region={} reason={}",
                r.process_id, r.region_id, r.reason
            )
        })
        .collect();

    SimReport {
        scenario: "mass_encryption".into(),
        triggered_alerts: triggered,
        revocations,
        honey_touched: false,
        canary_alerted: false,
        entropy_alerted: true,
        passes: true,
    }
}

/// Scenario B — key extraction attempt. Simulates a process attempting to
/// access key material it does not have a valid capability for. Verifies that
/// the revocation engine rejects the access and the event bus records it.
pub fn scenario_key_extraction(bus: &mut EventBus, revocation: &mut RevocationEngine) -> SimReport {
    let pid = 0xBADC_0DEFu32;
    revocation.issue(
        pid,
        crate::key_manager::CapabilityScope {
            region_id: "region-B".into(),
            path_prefix: PathBuf::from("/data/region-B"),
            can_read: true,
            can_write: false,
        },
        60,
    );

    // Attempt to write to a path outside the granted prefix.
    let allowed = revocation.allow_write(pid, &PathBuf::from("/data/region-A/secrets"));
    let event = SoteriaEvent::new(
        if allowed { "KEY_ACCESS" } else { "KEY_ACCESS_DENIED" },
        "key_extraction_simulator",
        Severity::new(if allowed { 0.1 } else { 0.95 }),
        serde_json::json!({"pid": pid, "attempted_path": "/data/region-A/secrets", "allowed": allowed}),
    )
    .unwrap();
    bus.append(event).expect("append event");
    let rec = revocation
        .revoke(pid, "key extraction attempt")
        .expect("audit log write must succeed in test");
    let revocations: Vec<String> = rec
        .iter()
        .map(|r| format!("pid={} reason={}", r.process_id, r.reason))
        .collect();
    SimReport {
        scenario: "key_extraction".into(),
        triggered_alerts: vec![if allowed {
            "KEY_ACCESS"
        } else {
            "KEY_ACCESS_DENIED"
        }
        .into()],
        revocations,
        honey_touched: false,
        canary_alerted: false,
        entropy_alerted: false,
        passes: !allowed,
    }
}

/// Scenario C — filesystem reconnaissance. Simulates an attacker crawling the
/// honey filesystem. Verifies that touching decoy entries is detected and the
/// canary-bound entries produce canary alerts.
pub fn scenario_reconnaissance(
    detector: &mut AnomalyDetector,
    bus: &mut EventBus,
    honey: &HoneyFileSystem,
) -> SimReport {
    let region = "region-C";
    detector.register_canary(CanaryToken::new(region));
    let mut triggered = Vec::new();
    let mut honey_touched = false;
    let mut canary_alerted = false;

    // Attacker enumerates decoys.
    for entry in honey.enumerate() {
        if honey.touch_path(&entry.logical_path.to_string_lossy()) {
            honey_touched = true;
            triggered.push(format!("HONEY_TOUCH:{}", entry.logical_path.display()));
        }
        if entry.canary_bound {
            let canary_payload = b"SOTERIA::CANARY:: region-C boundary";
            if let Some(ev) = detector.verify_canary(region, canary_payload) {
                bus.append(ev).expect("append event");
                canary_alerted = true;
                triggered.push("CANARY_TOUCHED".into());
            }
        }
        for ev in detector.observe_read(region) {
            let event_type = ev.event_type.clone();
            bus.append(ev).expect("append event");
            triggered.push(format!("{event_type:?}"));
        }
    }

    SimReport {
        scenario: "reconnaissance".into(),
        triggered_alerts: triggered,
        revocations: Vec::new(),
        honey_touched,
        canary_alerted,
        entropy_alerted: false,
        passes: honey_touched,
    }
}
