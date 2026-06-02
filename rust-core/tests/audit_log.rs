//! Tests for the append-only audit log: BLAKE3 chain, tamper detection,
//! crash tolerance, and integration with `RevocationEngine`.

use soteria_core::key_manager::CapabilityScope;
use soteria_core::policy::audit_log::{
    parse_bytes, read_entries, verify_bytes, AuditEntry, AuditLog, VerifyResult,
};
use soteria_core::policy::revocation::RevocationEngine;
use std::path::PathBuf;
use std::time::SystemTime;

fn unique_tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("soteria-audit-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn make_record(
    pid: u32,
    region: &str,
    reason: &str,
) -> soteria_core::policy::revocation::RevocationRecord {
    soteria_core::policy::revocation::RevocationRecord {
        process_id: pid,
        region_id: region.into(),
        reason: reason.into(),
        revoked_at: SystemTime::now(),
    }
}

#[test]
fn open_creates_empty_log() {
    let tmp = unique_tmp("open-empty");
    let log_path = tmp.join("audit.jsonl");
    let (log, n) = AuditLog::open(&log_path).unwrap();
    assert_eq!(n, 0);
    assert_eq!(log.path(), log_path);
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 0),
        other => panic!("expected Ok(0), got {other:?}"),
    }
}

#[test]
fn append_grows_seq_and_chain() {
    let tmp = unique_tmp("append");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, n) = AuditLog::open(&log_path).unwrap();
    assert_eq!(n, 0);
    let e1 = log.append(&make_record(1, "region-A", "first")).unwrap();
    let e2 = log.append(&make_record(2, "region-B", "second")).unwrap();
    let e3 = log.append(&make_record(3, "region-C", "third")).unwrap();
    assert_eq!(e1.seq, 0);
    assert_eq!(e2.seq, 1);
    assert_eq!(e3.seq, 2);
    assert_ne!(e1.chain, e2.chain);
    assert_ne!(e2.chain, e3.chain);
    assert_eq!(e1.chain.len(), 64); // 32 bytes hex
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 3),
        other => panic!("expected Ok(3), got {other:?}"),
    }
}

#[test]
fn reopen_continues_chain_from_disk() {
    let tmp = unique_tmp("reopen");
    let log_path = tmp.join("audit.jsonl");
    {
        let (mut log, _) = AuditLog::open(&log_path).unwrap();
        log.append(&make_record(1, "r", "a")).unwrap();
        log.append(&make_record(2, "r", "b")).unwrap();
    }
    // Reopen.
    let (mut log, n) = AuditLog::open(&log_path).unwrap();
    assert_eq!(n, 2);
    let e3 = log.append(&make_record(3, "r", "c")).unwrap();
    assert_eq!(e3.seq, 2); // continues from the disk state
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 3),
        other => panic!("expected Ok(3), got {other:?}"),
    }
}

#[test]
fn tampered_field_breaks_chain_at_correct_index() {
    let tmp = unique_tmp("tamper");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, _) = AuditLog::open(&log_path).unwrap();
    log.append(&make_record(1, "r", "alpha")).unwrap();
    log.append(&make_record(2, "r", "beta")).unwrap();
    log.append(&make_record(3, "r", "gamma")).unwrap();

    // Tamper with the FIRST entry's reason.
    let raw = std::fs::read(&log_path).unwrap();
    let mut lines: Vec<Vec<u8>> = raw.split(|b| *b == b'\n').map(|l| l.to_vec()).collect();
    // Drop the trailing empty line from the final newline.
    while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    assert_eq!(lines.len(), 3);
    // Replace the reason field in the first line.
    let first = std::str::from_utf8(&lines[0]).unwrap();
    assert!(first.contains("\"reason\":\"alpha\""));
    let tampered = first.replace("\"alpha\"", "\"ALPHA_TAMPERED\"");
    lines[0] = tampered.into_bytes();
    let new_raw: Vec<u8> = lines
        .join(&b'\n')
        .into_iter()
        .chain(std::iter::once(b'\n'))
        .collect();
    std::fs::write(&log_path, &new_raw).unwrap();

    match verify_bytes(&new_raw).unwrap() {
        VerifyResult::Tampered { first_bad_index } => {
            // The first tampered entry's stored chain no longer matches.
            assert_eq!(first_bad_index, 0);
        }
        other => panic!("expected Tampered at 0, got {other:?}"),
    }
}

#[test]
fn truncated_final_line_is_tolerated() {
    let tmp = unique_tmp("trunc");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, _) = AuditLog::open(&log_path).unwrap();
    log.append(&make_record(1, "r", "a")).unwrap();
    log.append(&make_record(2, "r", "b")).unwrap();

    // Simulate a crash mid-write: append a half-line to the log.
    let mut raw = std::fs::read(&log_path).unwrap();
    raw.extend_from_slice(b"{\"seq\":2,\"process_id\":99,\"re");
    std::fs::write(&log_path, &raw).unwrap();

    let entries = read_entries(&log_path).unwrap();
    // The truncated line is dropped; only the two complete entries remain.
    assert_eq!(entries.len(), 2);
    match verify_bytes(&raw).unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 2),
        other => panic!("expected Ok(2), got {other:?}"),
    }
}

#[test]
fn parse_bytes_handles_empty_and_malformed() {
    assert!(parse_bytes(b"").is_empty());
    assert!(parse_bytes(b"\n\n\n").is_empty());
    let raw = b"{\"seq\":0,\"process_id\":1,\"region_id\":\"r\",\"reason\":\"x\",\"revoked_at_unix_ms\":0,\"chain\":\"deadbeef\"}";
    let entries = parse_bytes(raw);
    assert_eq!(entries.len(), 1);
}

#[test]
fn revocation_engine_writes_to_audit_log() {
    let tmp = unique_tmp("engine-writes");
    let log_path = tmp.join("audit.jsonl");

    let mut engine = RevocationEngine::new();
    engine.set_audit_path(Some(log_path.clone()));
    let scope = CapabilityScope {
        region_id: "region-A".into(),
        path_prefix: "/data/region-A".into(),
        can_read: true,
        can_write: true,
    };
    engine.issue(100, scope, 3600);
    let rec = engine.revoke(100, "compromised").unwrap().unwrap();
    assert_eq!(rec.process_id, 100);

    // The log file must exist and contain exactly one entry.
    let entries = read_entries(&log_path).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].process_id, 100);
    assert_eq!(entries[0].region_id, "region-A");
    assert_eq!(entries[0].reason, "compromised");

    // Engine's in-memory history matches the log.
    assert_eq!(engine.revocation_history().len(), 1);
    assert_eq!(engine.revocation_history()[0].process_id, 100);
}

#[test]
fn revocation_engine_with_no_audit_path_still_works() {
    let mut engine = RevocationEngine::new();
    let scope = CapabilityScope {
        region_id: "r".into(),
        path_prefix: "/p".into(),
        can_read: true,
        can_write: true,
    };
    engine.issue(7, scope, 60);
    let rec = engine.revoke(7, "test").unwrap().unwrap();
    assert_eq!(rec.process_id, 7);
    assert!(engine.audit_path().is_none());
}

#[test]
fn revocation_engine_persists_across_reopens() {
    let tmp = unique_tmp("engine-persist");
    let log_path = tmp.join("audit.jsonl");

    {
        let mut engine = RevocationEngine::new();
        engine.set_audit_path(Some(log_path.clone()));
        let scope = CapabilityScope {
            region_id: "r".into(),
            path_prefix: "/p".into(),
            can_read: true,
            can_write: true,
        };
        for pid in [1u32, 2, 3] {
            engine.issue(pid, scope.clone(), 60);
            engine.revoke(pid, format!("reason-{pid}")).unwrap();
        }
    }
    // Reopen the same log in a fresh engine and confirm the chain is intact.
    let (log, n) = AuditLog::open(&log_path).unwrap();
    assert_eq!(n, 3);
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 3),
        other => panic!("expected Ok(3), got {other:?}"),
    }
    let entries = read_entries(&log_path).unwrap();
    assert_eq!(entries[0].process_id, 1);
    assert_eq!(entries[2].process_id, 3);
}

#[test]
fn empty_then_appended_chain_verifies() {
    let tmp = unique_tmp("empty-then-fill");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, _) = AuditLog::open(&log_path).unwrap();
    // Sanity: empty log is Ok(0).
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 0),
        other => panic!("empty must be Ok(0), got {other:?}"),
    }
    for i in 0..5 {
        log.append(&make_record(i, "r", &format!("r{i}"))).unwrap();
    }
    match log.verify().unwrap() {
        VerifyResult::Ok { entries } => assert_eq!(entries, 5),
        other => panic!("expected Ok(5), got {other:?}"),
    }
}

#[test]
fn audit_entry_serializes_with_all_fields() {
    let entry = AuditEntry {
        seq: 42,
        process_id: 7,
        region_id: "r".into(),
        reason: "test".into(),
        revoked_at_unix_ms: 1_700_000_000_000,
        chain: "0".repeat(64),
    };
    let s = serde_json::to_string(&entry).unwrap();
    assert!(s.contains("\"seq\":42"));
    assert!(s.contains("\"process_id\":7"));
    assert!(s.contains("\"region_id\":\"r\""));
    assert!(s.contains("\"reason\":\"test\""));
    assert!(s.contains("\"revoked_at_unix_ms\":1700000000000"));
    assert!(s.contains(&"0".repeat(64)));
}
