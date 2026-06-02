//! Integration tests for the `soteriad` CLI binary.
//!
//! These tests build and invoke the `soteriad` binary end-to-end. They use
//! `assert_cmd` to run the binary and inspect stdout/stderr/exit code.

use assert_cmd::Command;
use predicates::prelude::*;

fn soteriad() -> Command {
    Command::cargo_bin("soteriad").unwrap()
}

fn fresh_tmp(label: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "soteria-cli-test-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn cli_help_lists_all_subcommands() {
    soteriad()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("encrypt"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("keygen"));
}

#[test]
fn cli_encrypt_decrypt_roundtrip() {
    let tmp = fresh_tmp("roundtrip");
    let vol_dir = tmp.join("vol");
    std::fs::create_dir_all(&vol_dir).unwrap();
    let src = tmp.join("plain.txt");
    let plaintext = b"soteria CLI integration test payload, multi-line\nwith newlines.\n";
    std::fs::write(&src, plaintext).unwrap();

    // Encrypt.
    soteriad()
        .args([
            "encrypt",
            "--src",
            src.to_str().unwrap(),
            "--into",
            vol_dir.to_str().unwrap(),
            "--name",
            "hello",
            "--passphrase",
            "correct-horse-battery-staple",
            "--fast-kdf",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"));

    // Both files should exist.
    assert!(vol_dir.join("hello.sot").exists());
    assert!(vol_dir.join("hello.sot.kdf").exists());

    // Decrypt back.
    let out = tmp.join("recovered.txt");
    soteriad()
        .args([
            "decrypt",
            "--from",
            vol_dir.to_str().unwrap(),
            "--name",
            "hello",
            "--output",
            out.to_str().unwrap(),
            "--passphrase",
            "correct-horse-battery-staple",
        ])
        .assert()
        .success();
    let recovered = std::fs::read(&out).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn cli_decrypt_with_wrong_passphrase_fails() {
    let tmp = fresh_tmp("wrong-pw");
    let vol_dir = tmp.join("vol");
    std::fs::create_dir_all(&vol_dir).unwrap();
    let src = tmp.join("plain.txt");
    std::fs::write(&src, b"secret payload").unwrap();

    soteriad()
        .args([
            "encrypt",
            "--src",
            src.to_str().unwrap(),
            "--into",
            vol_dir.to_str().unwrap(),
            "--name",
            "secret",
            "--passphrase",
            "right-passphrase",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let out = tmp.join("recovered.txt");
    soteriad()
        .args([
            "decrypt",
            "--from",
            vol_dir.to_str().unwrap(),
            "--name",
            "secret",
            "--output",
            out.to_str().unwrap(),
            "--passphrase",
            "wrong-passphrase",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_list_reports_files_and_lineage() {
    let tmp = fresh_tmp("list");
    let vol_dir = tmp.join("vol");
    std::fs::create_dir_all(&vol_dir).unwrap();
    let src_a = tmp.join("a.txt");
    let src_b = tmp.join("b.txt");
    std::fs::write(&src_a, b"alpha payload").unwrap();
    std::fs::write(&src_b, b"beta payload is longer than alpha").unwrap();

    for (src, name) in [(&src_a, "alpha"), (&src_b, "beta")] {
        soteriad()
            .args([
                "encrypt",
                "--src",
                src.to_str().unwrap(),
                "--into",
                vol_dir.to_str().unwrap(),
                "--name",
                name,
                "--passphrase",
                "pw",
                "--fast-kdf",
            ])
            .assert()
            .success();
    }

    soteriad()
        .args(["list", "--dir", vol_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"alpha\""))
        .stdout(predicate::str::contains("\"name\": \"beta\""))
        .stdout(predicate::str::contains("\"lineage_ok\": true"));
}

#[test]
fn cli_verify_passes_for_untampered_volume() {
    let tmp = fresh_tmp("verify-ok");
    let vol_dir = tmp.join("vol");
    std::fs::create_dir_all(&vol_dir).unwrap();
    let src = tmp.join("p.txt");
    std::fs::write(&src, b"some content").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            src.to_str().unwrap(),
            "--into",
            vol_dir.to_str().unwrap(),
            "--name",
            "p",
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();
    soteriad()
        .args(["verify", "--dir", vol_dir.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"));
}

#[test]
fn cli_verify_fails_for_tampered_volume() {
    let tmp = fresh_tmp("verify-bad");
    let vol_dir = tmp.join("vol");
    std::fs::create_dir_all(&vol_dir).unwrap();
    let src = tmp.join("p.txt");
    std::fs::write(&src, b"tamper me").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            src.to_str().unwrap(),
            "--into",
            vol_dir.to_str().unwrap(),
            "--name",
            "p",
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    // Tamper: flip a byte in the ciphertext region of the volume.
    let path = vol_dir.join("p.sot");
    let mut raw = std::fs::read(&path).unwrap();
    // Flip a byte well past the header + index region.
    let idx = raw.len() - 5;
    raw[idx] ^= 0xFF;
    std::fs::write(&path, &raw).unwrap();

    soteriad()
        .args(["verify", "--dir", vol_dir.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"ok\": false"));
}

#[test]
fn cli_keygen_writes_pk_and_sk_with_correct_sizes() {
    let tmp = fresh_tmp("keygen");
    let prefix = tmp.join("alice");
    soteriad()
        .args(["keygen", "--out", prefix.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"));
    let pk_path = prefix.with_extension("pk");
    let sk_path = prefix.with_extension("sk");
    assert!(pk_path.exists());
    assert!(sk_path.exists());
    // PK is 1184 raw bytes = 2368 hex chars.
    let pk_hex = std::fs::read_to_string(&pk_path).unwrap();
    assert_eq!(pk_hex.len(), 2368, "PK must be 2368 hex chars (1184 bytes)");
    let sk_hex = std::fs::read_to_string(&sk_path).unwrap();
    assert_eq!(sk_hex.len(), 128, "SK must be 128 hex chars (64 bytes)");
}

#[test]
fn cli_audit_reports_missing_log_as_empty() {
    let tmp = fresh_tmp("audit-missing");
    let log = tmp.join("does-not-exist.jsonl");
    soteriad()
        .args(["audit", "--log", log.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"entries\": 0"));
}

#[test]
fn cli_audit_verify_only_on_clean_log_succeeds() {
    use soteria_core::policy::audit_log::AuditLog;
    use soteria_core::policy::revocation::RevocationRecord;

    let tmp = fresh_tmp("audit-verify");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, _) = AuditLog::open(&log_path).unwrap();
    log.append(&RevocationRecord {
        process_id: 1,
        region_id: "r".into(),
        reason: "x".into(),
        revoked_at: std::time::SystemTime::now(),
    })
    .unwrap();
    drop(log);

    soteriad()
        .args([
            "audit",
            "--log",
            log_path.to_str().unwrap(),
            "--verify-only",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"))
        .stdout(predicate::str::contains("\"entries\": 1"));
}

#[test]
fn cli_audit_exits_nonzero_on_tamper() {
    use soteria_core::policy::audit_log::AuditLog;
    use soteria_core::policy::revocation::RevocationRecord;

    let tmp = fresh_tmp("audit-tamper");
    let log_path = tmp.join("audit.jsonl");
    let (mut log, _) = AuditLog::open(&log_path).unwrap();
    log.append(&RevocationRecord {
        process_id: 7,
        region_id: "r".into(),
        reason: "original".into(),
        revoked_at: std::time::SystemTime::now(),
    })
    .unwrap();
    drop(log);

    // Tamper: replace "original" with "ORIGINAL" in the raw log.
    let raw = std::fs::read_to_string(&log_path).unwrap();
    let tampered = raw.replace("\"original\"", "\"ORIGINAL\"");
    std::fs::write(&log_path, tampered).unwrap();

    soteriad()
        .args([
            "audit",
            "--log",
            log_path.to_str().unwrap(),
            "--verify-only",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("\"ok\": false"));
}
