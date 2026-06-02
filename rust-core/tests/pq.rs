//! Tests for the post-quantum file-sharing path (ML-KEM-768 + AES-256-GCM).

use soteria_core::crypto_engine::pq::{
    generate_keypair, unwrap_key, wrap_key, KeyEnvelope, PublicKey, SecretKey, ML_KEM_768_CT_LEN,
    ML_KEM_768_PK_LEN, ML_KEM_768_SK_SEED_LEN,
};

#[test]
fn keypair_has_expected_sizes() {
    let kp = generate_keypair();
    assert_eq!(kp.public().bytes.len(), ML_KEM_768_PK_LEN);
    assert_eq!(kp.secret().bytes.len(), ML_KEM_768_SK_SEED_LEN);
}

#[test]
fn keypairs_are_independent() {
    let a = generate_keypair();
    let b = generate_keypair();
    assert_ne!(a.public().bytes, b.public().bytes);
    assert_ne!(a.secret().bytes, b.secret().bytes);
}

#[test]
fn wrap_then_unwrap_recovers_data_key() {
    let recipient = generate_keypair();
    let data_key = [0x42u8; 32];
    let envelope = wrap_key(&data_key, recipient.public()).unwrap();
    assert_eq!(envelope.kem_ciphertext.len(), ML_KEM_768_CT_LEN);
    assert_eq!(envelope.wrapped_key.len(), 32 + 16);
    let recovered = unwrap_key(&envelope, recipient.secret()).unwrap();
    assert_eq!(recovered, data_key);
}

#[test]
fn envelope_recipient_id_is_blake3_of_public_key() {
    let recipient = generate_keypair();
    let data_key = [0x33u8; 32];
    let envelope = wrap_key(&data_key, recipient.public()).unwrap();
    let expected = blake3::hash(&recipient.public().bytes);
    assert_eq!(
        envelope.recipient_key_id,
        *expected.as_bytes(),
        "recipient_key_id must be BLAKE3(public_key)"
    );
}

#[test]
fn unwrap_with_wrong_recipient_fails() {
    let alice = generate_keypair();
    let mallory = generate_keypair();
    let data_key = [0x77u8; 32];
    let envelope = wrap_key(&data_key, alice.public()).unwrap();
    let result = unwrap_key(&envelope, mallory.secret());
    assert!(result.is_err(), "wrong recipient must fail AEAD auth");
}

#[test]
fn tampered_kem_ciphertext_fails_unwrap() {
    let recipient = generate_keypair();
    let data_key = [0x55u8; 32];
    let mut envelope = wrap_key(&data_key, recipient.public()).unwrap();
    envelope.kem_ciphertext[0] ^= 0xFF;
    let result = unwrap_key(&envelope, recipient.secret());
    assert!(
        result.is_err(),
        "tampered ML-KEM ciphertext must fail unwrap"
    );
}

#[test]
fn tampered_wrapped_key_fails_unwrap() {
    let recipient = generate_keypair();
    let data_key = [0x99u8; 32];
    let mut envelope = wrap_key(&data_key, recipient.public()).unwrap();
    // Flip a byte in the ciphertext portion (not the auth tag).
    envelope.wrapped_key[5] ^= 0xFF;
    let result = unwrap_key(&envelope, recipient.secret());
    assert!(result.is_err(), "tampered wrapped_key must fail AEAD auth");
}

#[test]
fn two_envelopes_have_different_kem_ciphertexts() {
    // The ML-KEM encapsulation uses a fresh random nonce on every call,
    // so two wraps to the same recipient produce different ciphertexts.
    let recipient = generate_keypair();
    let dk1 = [0x01u8; 32];
    let dk2 = [0x02u8; 32];
    let env1 = wrap_key(&dk1, recipient.public()).unwrap();
    let env2 = wrap_key(&dk2, recipient.public()).unwrap();
    assert_ne!(env1.kem_ciphertext, env2.kem_ciphertext);
    assert_ne!(env1.wrap_nonce, env2.wrap_nonce);
}

#[test]
fn wrap_rejects_malformed_public_key() {
    let data_key = [0xABu8; 32];
    let bad_pk = PublicKey {
        bytes: vec![0u8; 100],
    };
    let result = wrap_key(&data_key, &bad_pk);
    assert!(result.is_err(), "malformed public key must fail wrap_key");
}

#[test]
fn unwrap_rejects_malformed_secret_key() {
    let recipient = generate_keypair();
    let data_key = [0xCDu8; 32];
    let envelope = wrap_key(&data_key, recipient.public()).unwrap();
    let bad_sk = SecretKey {
        bytes: vec![0u8; 32],
    };
    let result = unwrap_key(&envelope, &bad_sk);
    assert!(result.is_err(), "wrong-length secret key must fail");
}

#[test]
fn unwrap_rejects_truncated_wrapped_key() {
    let recipient = generate_keypair();
    let data_key = [0xEFu8; 32];
    let mut envelope = wrap_key(&data_key, recipient.public()).unwrap();
    envelope.wrapped_key.truncate(10);
    let result = unwrap_key(&envelope, recipient.secret());
    assert!(result.is_err(), "truncated wrapped_key must fail");
}

#[test]
fn recipient_key_id_helper_matches_wrap_result() {
    let recipient = generate_keypair();
    let id_from_helper = KeyEnvelope::recipient_key_id(recipient.public());
    let envelope = wrap_key(&[0u8; 32], recipient.public()).unwrap();
    assert_eq!(envelope.recipient_key_id, id_from_helper);
}
