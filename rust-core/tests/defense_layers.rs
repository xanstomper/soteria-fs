use soteria_core::deception_layer::honey_fs::HoneyFileSystem;
use soteria_core::event_bus::EventBus;
use soteria_core::policy::revocation::RevocationEngine;
use soteria_core::security::canary::CanaryToken;
use soteria_core::security::detector::AnomalyDetector;
use soteria_core::simulation::ransomware_sim::{
    scenario_key_extraction, scenario_mass_encryption, scenario_reconnaissance,
};
use std::path::PathBuf;

#[test]
fn mass_encryption_scenario_triggers_response() {
    let mut detector = AnomalyDetector::new(7.0, 50);
    let mut bus = EventBus::new();
    let mut revocation = RevocationEngine::new();
    let report = scenario_mass_encryption(&mut detector, &mut bus, &mut revocation);
    assert!(report.passes);
    assert!(report.entropy_alerted);
    assert!(!report.revocations.is_empty());
    assert!(bus
        .records()
        .iter()
        .any(|r| r.event.event_type == "RANSOMWARE_PATTERN"));
}

#[test]
fn key_extraction_scenario_revokes_process() {
    let mut bus = EventBus::new();
    let mut revocation = RevocationEngine::new();
    let report = scenario_key_extraction(&mut bus, &mut revocation);
    assert!(report.passes);
    assert!(!revocation.has_valid_capability(0xBADC_0DEF));
    assert_eq!(revocation.revocation_history().len(), 1);
}

#[test]
fn reconnaissance_scenario_triggers_canary_and_honey() {
    let mut detector = AnomalyDetector::new(7.0, 50);
    let mut bus = EventBus::new();
    let honey = HoneyFileSystem::seed_default(&PathBuf::from("/tmp/decoys"));
    let report = scenario_reconnaissance(&mut detector, &mut bus, &honey);
    assert!(report.passes);
    assert!(report.honey_touched);
    assert!(report.canary_alerted);
}

#[test]
fn canary_token_verifies_marker() {
    let token = CanaryToken::new("region-X");
    assert!(token.verify("region-X", b"SOTERIA::CANARY:: something"));
    assert!(!token.verify("region-Y", b"SOTERIA::CANARY:: something"));
    assert!(!token.verify("region-X", b"unrelated bytes"));
}

#[test]
fn revocation_engine_reaps_expired() {
    use soteria_core::key_manager::CapabilityScope;
    let mut engine = RevocationEngine::new();
    engine.issue(
        1,
        CapabilityScope {
            region_id: "r".into(),
            path_prefix: PathBuf::from("/"),
            can_read: true,
            can_write: true,
        },
        0,
    );
    std::thread::sleep(std::time::Duration::from_millis(5));
    let reaped = engine.reap_expired();
    assert_eq!(reaped, 1);
    assert_eq!(engine.active_count(), 0);
}

#[test]
fn scope_path_prefix_is_enforced() {
    use soteria_core::key_manager::CapabilityScope;
    let mut engine = RevocationEngine::new();
    engine.issue(
        7,
        CapabilityScope {
            region_id: "r".into(),
            path_prefix: PathBuf::from("/data/r1"),
            can_read: true,
            can_write: true,
        },
        60,
    );
    assert!(engine.allow_read(7, &PathBuf::from("/data/r1/file")));
    assert!(!engine.allow_read(7, &PathBuf::from("/data/r2/file")));
}
