use soteria_core::config::SoteriaConfig;
use soteria_core::event_bus::{EventBus, Severity, SoteriaEvent};
use soteria_core::response_engine::{PolicyEngine, ResponseContext};
use std::path::PathBuf;

#[test]
fn loads_default_config() {
    let cfg =
        SoteriaConfig::load(&PathBuf::from("../config/soteria.toml")).expect("config must load");
    assert_eq!(cfg.crypto.block_size, 65536);
    assert!(cfg.response.allowed_actions.contains(&"FREEZE".to_string()));
}

#[test]
fn event_bus_chains_events() {
    let mut bus = EventBus::new();
    let a = SoteriaEvent::new(
        "FS_WRITE",
        "write_sensor",
        Severity::new(0.1),
        serde_json::json!({"path": "a"}),
    )
    .unwrap();
    let b = SoteriaEvent::new(
        "FS_WRITE",
        "write_sensor",
        Severity::new(0.1),
        serde_json::json!({"path": "b"}),
    )
    .unwrap();
    let ra = bus.append(a).unwrap();
    let rb = bus.append(b).unwrap();
    assert_ne!(ra.chain_hash, rb.chain_hash);
    assert_eq!(rb.previous_hash, ra.chain_hash);
}

#[test]
fn policy_engine_triggers_freeze_on_entropy_spike() {
    let cfg = SoteriaConfig::load(&PathBuf::from("../config/soteria.toml")).unwrap();
    let mut policy = PolicyEngine::from_config(&cfg.response);
    let event = SoteriaEvent::new(
        "ENTROPY_SPIKE",
        "entropy_sensor",
        Severity::new(0.95),
        serde_json::json!({"entropy": 7.99}),
    )
    .unwrap();
    let mut ctx = ResponseContext::default();
    let decision = policy.evaluate(&event, &mut ctx);
    assert_eq!(
        decision.action,
        soteria_core::response_engine::ResponseAction::Freeze
    );
    assert!(ctx.frozen_domains.contains("default"));
}

#[test]
fn policy_engine_revokes_on_unauthorized_key_access() {
    let cfg = SoteriaConfig::load(&PathBuf::from("../config/soteria.toml")).unwrap();
    let mut policy = PolicyEngine::from_config(&cfg.response);
    let event = SoteriaEvent::new(
        "KEY_ACCESS_DENIED",
        "key_access_sensor",
        Severity::new(0.9),
        serde_json::json!({"pid": 4242}),
    )
    .unwrap();
    let mut ctx = ResponseContext::default();
    let decision = policy.evaluate(&event, &mut ctx);
    assert_eq!(
        decision.action,
        soteria_core::response_engine::ResponseAction::Revoke
    );
}

#[test]
fn policy_engine_ignores_disallowed_actions() {
    let mut cfg = SoteriaConfig::load(&PathBuf::from("../config/soteria.toml")).unwrap();
    cfg.response.allowed_actions.clear();
    let mut policy = PolicyEngine::from_config(&cfg.response);
    let event = SoteriaEvent::new(
        "ENTROPY_SPIKE",
        "entropy_sensor",
        Severity::new(0.99),
        serde_json::json!({}),
    )
    .unwrap();
    let mut ctx = ResponseContext::default();
    let decision = policy.evaluate(&event, &mut ctx);
    assert_eq!(
        decision.action,
        soteria_core::response_engine::ResponseAction::Allow
    );
}
