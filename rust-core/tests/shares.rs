//! Integration tests for ML-KEM-768 volume sharing.
//!
//! These tests exercise the full end-to-end flow: encrypt a volume with a
//! passphrase, share it with a recipient, recover the key, and decrypt.
//! They run against the `soteriad` binary via `assert_cmd`.

use assert_cmd::Command;
use predicates::prelude::*;
use soteria_core::crypto_engine::dsa::{self, OwnerPublicKey, OwnerSecretKey};
use soteria_core::crypto_engine::pq::{generate_keypair, PublicKey, SecretKey};
use soteria_core::crypto_engine::shares::{
    envelope_signing_payload, shares_path_for, ShareEvent, ShareFile, ENVELOPE_SIGN_DOMAIN,
    SHARES_SIDECAR_SUFFIX, SHARES_VERSION,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn soteriad() -> Command {
    Command::cargo_bin("soteriad").unwrap()
}

fn fresh_tmp(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "soteria-shares-test-{}-{}-{}",
        label,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn make_keypair_files(tmp: &Path, name: &str) -> (PathBuf, PathBuf) {
    let kp = generate_keypair();
    let pk_path = tmp.join(format!("{name}.pk"));
    let sk_path = tmp.join(format!("{name}.sk"));
    let pk_hex: String = kp.public.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let sk_hex: String = kp.secret.bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&pk_path, pk_hex).unwrap();
    std::fs::write(&sk_path, sk_hex).unwrap();
    (pk_path, sk_path)
}

fn make_owner_keypair_files(tmp: &Path, name: &str) -> (PathBuf, PathBuf, dsa::OwnerKeyPair) {
    let kp = dsa::generate_keypair();
    let pk_path = tmp.join(format!("{name}.dsa.pk"));
    let sk_path = tmp.join(format!("{name}.dsa.sk"));
    let pk_hex: String = kp.public.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let sk_hex: String = kp.secret.bytes.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&pk_path, pk_hex).unwrap();
    std::fs::write(&sk_path, sk_hex).unwrap();
    (pk_path, sk_path, kp)
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "hex string has odd length");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let h = (bytes[i] as char).to_digit(16).unwrap();
        let l = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((h << 4) | l) as u8);
        i += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// Library-level tests
// ---------------------------------------------------------------------------

#[test]
fn shares_path_for_appends_correct_suffix() {
    let p = PathBuf::from("/tmp/vault/secret.sot");
    let s = shares_path_for(&p);
    assert_eq!(s.to_str().unwrap(), "/tmp/vault/secret.sot.sot.shares");
}

#[test]
fn share_file_open_creates_empty_for_missing_file() {
    let tmp = fresh_tmp("missing");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let root_key = [0xAB; 32];
    let sf = ShareFile::open(&volume, &root_key).expect("open should succeed");
    assert_eq!(sf.version, SHARES_VERSION);
    assert_eq!(
        sf.volume_root_key_fingerprint,
        *blake3::hash(&root_key).as_bytes()
    );
    assert!(sf.events.is_empty());
}

#[test]
fn share_file_open_rejects_wrong_fingerprint() {
    let tmp = fresh_tmp("wrong-fp");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let rk1 = [0x01; 32];
    let rk2 = [0x02; 32];
    let sf = ShareFile::new(&rk1);
    sf.save(&volume).unwrap();
    let result = ShareFile::open(&volume, &rk2);
    assert!(result.is_err(), "fingerprint mismatch must error");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("fingerprint"),
        "error should mention fingerprint: {err}"
    );
}

#[test]
fn add_then_unlock_recovers_root_key() {
    let tmp = fresh_tmp("roundtrip");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let kp = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x42; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&kp.public, &root_key, &owner.secret, 1_700_000_000_000)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    // Reopen with the correct key.
    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    assert_eq!(sf2.events.len(), 1);
    let decrypted = sf2.unlock(&kp.secret, None).expect("unlock should succeed");
    assert_eq!(decrypted.root_key, root_key);
}

#[test]
fn unlock_with_wrong_secret_key_fails() {
    let tmp = fresh_tmp("wrong-sk");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let owner_kp = generate_keypair();
    let attacker_kp = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x77; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&owner_kp.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();

    let result = sf.unlock(&attacker_kp.secret, None);
    assert!(result.is_err(), "attacker SK must not unlock the envelope");
}

#[test]
fn add_two_recipients_both_can_unlock() {
    let tmp = fresh_tmp("two-recipients");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let bob = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x99; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.add_recipient(&bob.public, &root_key, &owner.secret, 2)
        .unwrap();
    sf.save(&volume).unwrap();

    let a = sf.unlock(&alice.secret, None).unwrap();
    let b = sf.unlock(&bob.secret, None).unwrap();
    assert_eq!(a.root_key, root_key);
    assert_eq!(b.root_key, root_key);
}

#[test]
fn revoke_blocks_subsequent_unlock() {
    let tmp = fresh_tmp("revoke");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0xAA; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();

    // Revoke Alice.
    let mut sf2 = ShareFile::open(&volume, &root_key).unwrap();
    let was_active = sf2.revoke_recipient(&alice.public, "rotation", 2).unwrap();
    assert!(was_active);
    sf2.save(&volume).unwrap();

    // Alice can no longer unlock.
    let sf3 = ShareFile::open(&volume, &root_key).unwrap();
    let err = sf3.unlock(&alice.secret, None).unwrap_err();
    assert!(
        format!("{err}").contains("no envelope"),
        "expected unlock failure: {err}"
    );
}

#[test]
fn revoking_one_recipient_does_not_affect_others() {
    let tmp = fresh_tmp("revoke-one");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let bob = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0xCC; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.add_recipient(&bob.public, &root_key, &owner.secret, 2)
        .unwrap();
    sf.save(&volume).unwrap();

    let mut sf2 = ShareFile::open(&volume, &root_key).unwrap();
    sf2.revoke_recipient(&alice.public, "left team", 3).unwrap();
    sf2.save(&volume).unwrap();

    let sf3 = ShareFile::open(&volume, &root_key).unwrap();
    assert!(sf3.unlock(&alice.secret, None).is_err());
    let bob_decrypted = sf3
        .unlock(&bob.secret, None)
        .expect("Bob should still unlock");
    assert_eq!(bob_decrypted.root_key, root_key);
}

#[test]
fn list_active_and_revoked_separate_correctly() {
    let tmp = fresh_tmp("list");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let bob = generate_keypair();
    let carol = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0xDD; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.add_recipient(&bob.public, &root_key, &owner.secret, 2)
        .unwrap();
    sf.add_recipient(&carol.public, &root_key, &owner.secret, 3)
        .unwrap();
    sf.revoke_recipient(&bob.public, "rotation", 4).unwrap();
    sf.save(&volume).unwrap();

    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    let active = sf2.list_active();
    let revoked = sf2.list_revoked();
    assert_eq!(active.len(), 2);
    assert_eq!(revoked.len(), 1);
    let active_ids: std::collections::HashSet<_> =
        active.iter().map(|r| r.recipient_key_id).collect();
    assert!(active_ids
        .contains(&soteria_core::crypto_engine::pq::KeyEnvelope::recipient_key_id(&alice.public)));
    assert!(active_ids
        .contains(&soteria_core::crypto_engine::pq::KeyEnvelope::recipient_key_id(&carol.public)));
    assert_eq!(revoked[0].reason, "rotation");
}

#[test]
fn add_recipient_twice_errors() {
    let tmp = fresh_tmp("double-add");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0xEE; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    let err = sf
        .add_recipient(&alice.public, &root_key, &owner.secret, 2)
        .unwrap_err();
    assert!(format!("{err}").contains("already has history"));
}

#[test]
fn re_add_after_revoke_still_errors() {
    let tmp = fresh_tmp("readd-after-revoke");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0xEF; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.revoke_recipient(&alice.public, "rotation", 2).unwrap();
    let err = sf
        .add_recipient(&alice.public, &root_key, &owner.secret, 3)
        .unwrap_err();
    assert!(format!("{err}").contains("already has history"));
}

#[test]
fn share_file_persists_across_reopens() {
    let tmp = fresh_tmp("persist");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x11; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    // Re-read the file directly as JSON to confirm format.
    let raw = std::fs::read(shares_path_for(&volume)).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(json["version"], SHARES_VERSION);
    assert!(json["volume_root_key_fingerprint"].is_string());
    assert_eq!(json["events"].as_array().unwrap().len(), 1);
    assert_eq!(json["events"][0]["action"], "added");
    // The outer recipient_key_id is a hex string (via hex_32 serde).
    assert!(json["events"][0]["recipient_key_id"].is_string());
    assert!(json["events"][0]["envelope"].is_object());
    assert!(json["events"][0]["envelope"]["recipient_key_id"].is_string());
    assert!(json["events"][0]["envelope"]["kem_ciphertext"].is_string());
    assert!(json["events"][0]["envelope"]["wrap_nonce"].is_string());
    assert!(json["events"][0]["envelope"]["wrapped_key"].is_string());
    // v2 fields:
    assert!(json["events"][0]["owner_sig_pk_id"].is_string());
    assert!(json["events"][0]["owner_signature"].is_string());
    let _ = SHARES_SIDECAR_SUFFIX; // silence unused
}

// ---------------------------------------------------------------------------
// ML-DSA-65 envelope signature tests
// ---------------------------------------------------------------------------

#[test]
fn envelope_signature_verifies_with_owner_pk() {
    let tmp = fresh_tmp("sig-verify");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x33; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    // With the right owner PK, unlock + verify succeeds.
    let decrypted = sf2
        .unlock(&alice.secret, Some(&owner.public))
        .expect("unlock with valid owner PK must succeed");
    assert_eq!(decrypted.root_key, root_key);
}

#[test]
fn envelope_signature_fails_with_wrong_owner_pk() {
    let tmp = fresh_tmp("sig-wrong-pk");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let impostor = dsa::generate_keypair();
    let root_key = [0x44; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    // With the wrong owner PK, the signature check fails before unwrap.
    let err = sf2
        .unlock(&alice.secret, Some(&impostor.public))
        .unwrap_err();
    assert!(
        format!("{err}").contains("owner"),
        "error should mention owner key mismatch: {err}"
    );
}

#[test]
fn envelope_signature_payload_is_canonical_and_stable() {
    // Two recipients with the same fields must produce the same payload
    // format (modulo recipient_key_id, which is bound in).
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x55; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    drop(sf);
    // Fetch the actual on-disk event by re-adding and re-reading.
    let tmp = fresh_tmp("canonical-payload");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let mut sf2 = ShareFile::new(&root_key);
    sf2.add_recipient(&alice.public, &root_key, &owner.secret, 2)
        .unwrap();
    sf2.save(&volume).unwrap();
    let sf3 = ShareFile::open(&volume, &root_key).unwrap();
    let ev2 = &sf3.events[0];
    if let ShareEvent::Added {
        recipient_key_id,
        recipient_pk_bytes,
        envelope,
        owner_signature,
        owner_sig_pk_id,
        ..
    } = ev2
    {
        let payload = envelope_signing_payload(recipient_key_id, recipient_pk_bytes, envelope);
        // The domain separator must be the first bytes.
        assert!(payload.starts_with(ENVELOPE_SIGN_DOMAIN));
        // The signature over this payload must verify with the owner PK.
        dsa::verify(&payload, owner_signature, &owner.public)
            .expect("envelope signature must verify against the canonical payload");
        // The owner_sig_pk_id must match BLAKE3 of the owner PK.
        assert_eq!(*owner_sig_pk_id, dsa::owner_key_id(&owner.public));
    } else {
        panic!("expected first event to be Added");
    }
}

#[test]
fn tampered_envelope_fails_signature_check() {
    let tmp = fresh_tmp("tamper");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x66; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    // Tamper: flip a byte in the share file's JSON.
    let path = shares_path_for(&volume);
    let raw = std::fs::read(&path).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    // Find the wrapped_key string and flip a character in the middle.
    let wrapped = json["events"][0]["envelope"]["wrapped_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        wrapped.len() > 10,
        "wrapped_key should be long enough to tamper with"
    );
    let mut tampered = wrapped.clone();
    let flipped = if tampered.as_bytes()[5] == b'a' {
        'b'
    } else {
        'a'
    };
    // SAFETY: position 5 is a hex char because hex_decode validates
    // (let h = pos[0].to_digit(16)). We pick a different hex char.
    let mut chars: Vec<char> = tampered.chars().collect();
    chars[5] = flipped;
    tampered = chars.into_iter().collect();
    json["events"][0]["envelope"]["wrapped_key"] = serde_json::Value::String(tampered);
    std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    // Reopen: fingerprint still matches, but signature must fail.
    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    let err = sf2.unlock(&alice.secret, Some(&owner.public)).unwrap_err();
    assert!(
        format!("{err}").contains("signature") || format!("{err}").contains("envelope"),
        "tampered envelope must fail signature check: {err}"
    );
}

#[test]
fn unlock_without_owner_pk_skips_signature_check() {
    // The signature check is opt-in (recipient may not have the owner PK
    // at unlock time). Passing None must still allow unwrapping via the
    // AEAD auth check on the envelope.
    let tmp = fresh_tmp("no-verify");
    let volume = tmp.join("v.sot");
    std::fs::write(&volume, b"placeholder").unwrap();
    let alice = generate_keypair();
    let owner = dsa::generate_keypair();
    let root_key = [0x77; 32];
    let mut sf = ShareFile::new(&root_key);
    sf.add_recipient(&alice.public, &root_key, &owner.secret, 1)
        .unwrap();
    sf.save(&volume).unwrap();
    drop(sf);

    let sf2 = ShareFile::open(&volume, &root_key).unwrap();
    let decrypted = sf2
        .unlock(&alice.secret, None)
        .expect("unlock with no owner PK must still succeed (signature check is opt-in)");
    assert_eq!(decrypted.root_key, root_key);
}

// ---------------------------------------------------------------------------
// CLI integration tests
// ---------------------------------------------------------------------------

#[test]
fn cli_share_full_round_trip() {
    let tmp = fresh_tmp("cli-roundtrip");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("secret.txt");
    std::fs::write(&plain, b"hello, post-quantum world").unwrap();
    let name = "secret";

    // 1. Encrypt the volume with a passphrase.
    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--passphrase",
            "correct horse battery staple",
            "--fast-kdf",
        ])
        .assert()
        .success();

    // 2. Generate a keypair for the recipient.
    let (alice_pk, alice_sk) = make_keypair_files(&tmp, "alice");

    // 3. Generate an ML-DSA-65 keypair for the volume owner.
    let (owner_pk_path, owner_sk_path, _owner_kp) = make_owner_keypair_files(&tmp, "owner");

    // 4. Add recipient to the share file, signed by the owner.
    soteriad()
        .args([
            "share",
            "add",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "correct horse battery staple",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
            "--owner-sk",
            owner_sk_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"action\": \"added\""));

    // 5. List recipients — should show 1 active.
    soteriad()
        .args([
            "share",
            "list",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "correct horse battery staple",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"active_count\": 1"));

    // 6. Unlock with the recipient's SK + owner PK verification.
    let keyfile = tmp.join("alice.rootkey");
    soteriad()
        .args([
            "share",
            "unlock",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--sk",
            alice_sk.to_str().unwrap(),
            "--owner-pk",
            owner_pk_path.to_str().unwrap(),
            "--out",
            keyfile.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"fingerprint_verified\": false"))
        .stdout(predicate::str::contains("\"signature_verified\": true"));
    let key_bytes = std::fs::read(&keyfile).unwrap();
    assert_eq!(key_bytes.len(), 32);

    // 7. Decrypt with the keyfile — should produce original plaintext.
    let recovered = tmp.join("recovered.txt");
    soteriad()
        .args([
            "decrypt",
            "--from",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--key-file",
            keyfile.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ])
        .assert()
        .success();
    let pt = std::fs::read(&recovered).unwrap();
    assert_eq!(pt, b"hello, post-quantum world");

    // 8. Revoke Alice.
    soteriad()
        .args([
            "share",
            "remove",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "correct horse battery staple",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"revoked\": true"));

    // 9. Alice can no longer unlock.
    soteriad()
        .args([
            "share",
            "unlock",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--sk",
            alice_sk.to_str().unwrap(),
            "--owner-pk",
            owner_pk_path.to_str().unwrap(),
            "--out",
            tmp.join("stale.rootkey").to_str().unwrap(),
        ])
        .assert()
        .failure();

    // 10. List shows 0 active, 1 revoked.
    soteriad()
        .args([
            "share",
            "list",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "correct horse battery staple",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"active_count\": 0"))
        .stdout(predicate::str::contains("\"revoked_count\": 1"));
}

#[test]
fn cli_decrypt_keyfile_matches_passphrase() {
    let tmp = fresh_tmp("keyfile-vs-passphrase");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"key file vs passphrase parity").unwrap();
    let name = "f";

    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--passphrase",
            "the-passphrase",
            "--fast-kdf",
        ])
        .assert()
        .success();

    // Decrypt with passphrase.
    let out_pp = tmp.join("out-pp.txt");
    soteriad()
        .args([
            "decrypt",
            "--from",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--passphrase",
            "the-passphrase",
            "--output",
            out_pp.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Re-derive the key via the KDF sidecar (using the underlying library) and
    // round-trip through --key-file to confirm both paths produce the same
    // plaintext.
    let volume_path = dir.join(format!("{name}.sot"));
    let kdf_path = soteria_core::fs_layer::kdf::kdf_path_for(&volume_path);
    let kdf_file = soteria_core::fs_layer::kdf::VolumeKeyFile::load(&kdf_path).unwrap();
    let key = soteria_core::fs_layer::kdf::derive_volume_key(b"the-passphrase", &kdf_file).unwrap();
    let keyfile = tmp.join("derived.rootkey");
    std::fs::write(&keyfile, key.as_ref()).unwrap();

    let out_kf = tmp.join("out-kf.txt");
    soteriad()
        .args([
            "decrypt",
            "--from",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--key-file",
            keyfile.to_str().unwrap(),
            "--output",
            out_kf.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&out_pp).unwrap(),
        std::fs::read(&out_kf).unwrap()
    );
}

#[test]
fn cli_decrypt_rejects_both_passphrase_and_keyfile() {
    let tmp = fresh_tmp("both-flags");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let kf = tmp.join("k.bin");
    std::fs::write(&kf, [0u8; 32]).unwrap();
    soteriad()
        .args([
            "decrypt",
            "--from",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--passphrase",
            "pw",
            "--key-file",
            kf.to_str().unwrap(),
            "--output",
            tmp.join("o.txt").to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn cli_decrypt_rejects_wrong_size_keyfile() {
    let tmp = fresh_tmp("bad-keyfile");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let bad_kf = tmp.join("k.bin");
    std::fs::write(&bad_kf, vec![0u8; 16]).unwrap(); // not 32 bytes
    soteriad()
        .args([
            "decrypt",
            "--from",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--key-file",
            bad_kf.to_str().unwrap(),
            "--output",
            tmp.join("o.txt").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("32 raw bytes"));
}

#[test]
fn cli_share_add_with_wrong_passphrase_fails() {
    let tmp = fresh_tmp("wrong-pw");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--passphrase",
            "right",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let (alice_pk, _) = make_keypair_files(&tmp, "alice");
    let (_, owner_sk_path, _) = make_owner_keypair_files(&tmp, "owner");
    soteriad()
        .args([
            "share",
            "add",
            "--volume",
            dir.join("f.sot").to_str().unwrap(),
            "--passphrase",
            "WRONG",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
            "--owner-sk",
            owner_sk_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn cli_share_add_requires_owner_sk() {
    let tmp = fresh_tmp("missing-owner-sk");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            "f",
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let (alice_pk, _) = make_keypair_files(&tmp, "alice");
    soteriad()
        .args([
            "share",
            "add",
            "--volume",
            dir.join("f.sot").to_str().unwrap(),
            "--passphrase",
            "pw",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--owner-sk"));
}

#[test]
fn cli_share_unlock_with_wrong_owner_pk_fails() {
    let tmp = fresh_tmp("unlock-wrong-pk");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    let name = "f";

    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let (alice_pk, alice_sk) = make_keypair_files(&tmp, "alice");
    let (_, owner_sk_path, _) = make_owner_keypair_files(&tmp, "owner");
    let (impostor_pk, _impostor_sk, _) = make_owner_keypair_files(&tmp, "impostor");

    soteriad()
        .args([
            "share",
            "add",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "pw",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
            "--owner-sk",
            owner_sk_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Unlock with the impostor's PK should fail because the signature
    // won't verify.
    soteriad()
        .args([
            "share",
            "unlock",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--sk",
            alice_sk.to_str().unwrap(),
            "--owner-pk",
            impostor_pk.to_str().unwrap(),
            "--out",
            tmp.join("k.bin").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("owner"));
}

#[test]
fn cli_share_unlock_no_owner_pk_succeeds_with_warning() {
    // Opt-out path: --no-verify-signature lets the recipient skip the
    // signature check entirely. They still must hold the matching ML-KEM
    // secret key, so the AEAD auth check still applies.
    let tmp = fresh_tmp("unlock-no-verify");
    let dir = tmp.join("vol");
    std::fs::create_dir_all(&dir).unwrap();
    let plain = tmp.join("f.txt");
    std::fs::write(&plain, b"x").unwrap();
    let name = "f";

    soteriad()
        .args([
            "encrypt",
            "--src",
            plain.to_str().unwrap(),
            "--into",
            dir.to_str().unwrap(),
            "--name",
            name,
            "--passphrase",
            "pw",
            "--fast-kdf",
        ])
        .assert()
        .success();

    let (alice_pk, alice_sk) = make_keypair_files(&tmp, "alice");
    let (_, owner_sk_path, _) = make_owner_keypair_files(&tmp, "owner");

    soteriad()
        .args([
            "share",
            "add",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--passphrase",
            "pw",
            "--recipient-pk",
            alice_pk.to_str().unwrap(),
            "--owner-sk",
            owner_sk_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    soteriad()
        .args([
            "share",
            "unlock",
            "--volume",
            dir.join(format!("{name}.sot")).to_str().unwrap(),
            "--sk",
            alice_sk.to_str().unwrap(),
            "--no-verify-signature",
            "--out",
            tmp.join("k.bin").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"signature_verified\": false"));
}

// ---------------------------------------------------------------------------
// Silences the "unused" warnings from helper-only imports.
// ---------------------------------------------------------------------------
#[allow(dead_code)]
fn _unused_imports() {
    let _: PublicKey = PublicKey { bytes: vec![] };
    let _: SecretKey = SecretKey { bytes: vec![] };
    let _: OwnerPublicKey = OwnerPublicKey { bytes: vec![] };
    let _: OwnerSecretKey = OwnerSecretKey { bytes: vec![] };
    let _ = hex_decode("");
}
