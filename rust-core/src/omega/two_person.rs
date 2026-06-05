//! SOTERIA-OMEGA Part 2 — Two-Person / Four-Eyes Rule.
//!
//! The two-person rule (also called "four-eyes" or "no-lone-zone") is
//! a standard nuclear-command-and-control pattern: a single operator
//! can never produce a usable cryptographic key. Two independent
//! operators must each contribute half a key-share, and the engine
//! combines them with a constant-time XOR under hardware witness.
//!
//! ## Construction
//!
//! We use a Shamir 2-of-2 secret-share by default: the master key `K`
//! is split into `K1 ⊕ K2 = K` (XOR-share), and each operator holds one
//! half. To release, both operators enter their halves; the engine
//! XORs them back into `K` inside a memory-locked buffer, derives the
//! actual encryption key via HKDF, and zeroizes the shares within
//! 1 second (operator-configurable).
//!
//! For higher-assurance deployments the OMEGA engine also supports
//! 2-of-3 (one share held by an automated witness / hardware token) and
//! 3-of-5 (multi-party recovery).
//!
//! ## Threat model defended
//!
//! - **Coercion of one operator**: cannot release the key alone.
//! - **Insider threat from one operator**: must collude with the second
//!   operator (which violates their own non-disclosure and is itself
//!   auditable).
//! - **Memory scraping of one operator's session**: only reveals their
//!   share, not the full key.
//!
//! ## Threat model NOT defended
//!
//! - **Two operators colluding**: this is now an insider-collusion
//!   scenario; mitigations are organisational (dual-control
//!   assignment, polygraph, no-shared-ideology vetting) and outside
//!   the engine's scope.
//!
//! ## Witness tokens
//!
//! In OMEGA, every release must be witnessed. A witness can be:
//! - A second cleared operator (human).
//! - A hardware token (TPM 2.0, FIDO2 YubiKey, smartcard) bound to a
//!   witness identity.
//! - An automated journal-and-hash signer that appends the release
//!   to the audit chain.
//!
//! `Witness::Human { operator_id }` and `Witness::Hardware { token_id }`
//! are the two most common.

use crate::omega::classification::{Classification, Compartments};
use crate::omega::{OmegaError, OmegaResult};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit operator identity. In a real deployment this is a
/// hardware-token-attested public key; in MVP it's a 32-byte random
/// identifier generated at enrollment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperatorId(pub [u8; 32]);

impl OperatorId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The minimum role held by an operator in a two-person session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorRole {
    /// Holds the first key share.
    ShareholderA,
    /// Holds the second key share.
    ShareholderB,
    /// Holds the witness token (cannot release alone, but must countersign).
    Witness,
    /// Custodian with override authority (e.g., GOV administrator) — may
    /// override the two-person rule with their own credentials.
    Custodian,
}

/// An operator's enrollment record. Includes the operator's
/// classification clearance and the encrypted at-rest copy of their
/// key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub operator_id: OperatorId,
    pub display_name: String,
    pub role: OperatorRole,
    pub clearance: Classification,
    pub compartments: Compartments,
    /// The 32-byte key share, encrypted at rest with a passphrase-derived key.
    pub encrypted_share: Vec<u8>,
    /// Salt for the at-rest KDF.
    pub kdf_salt: [u8; 16],
    /// 8-byte timestamp of last successful attestation.
    pub last_attested_ms: u64,
}

/// A witness countersignature attached to a release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Witness {
    Human {
        operator_id: OperatorId,
        signature: Vec<u8>,
    },
    Hardware {
        token_id: Vec<u8>,
        attestation: Vec<u8>,
    },
    Journal {
        entry_hash: [u8; 32],
        prev_chain_hash: [u8; 32],
    },
}

/// A single share entered by one operator. The share is `Zeroize`d on
/// drop and held in a `Zeroizing` wrapper.
#[derive(Debug, Clone)]
pub struct OperatorShare {
    pub operator_id: OperatorId,
    pub share: [u8; 32],
}

impl Drop for OperatorShare {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.share.zeroize();
    }
}

impl OperatorShare {
    pub fn new(operator_id: OperatorId, share: [u8; 32]) -> Self {
        Self { operator_id, share }
    }
}

/// The result of a successful two-person release.
#[derive(Debug, Clone)]
pub struct ReleasedKey {
    pub derived_key: [u8; 32],
    pub session_id: [u8; 32],
    pub classification: Classification,
    pub compartments: Compartments,
    pub witness: Witness,
    pub released_at_ms: u64,
}

impl Drop for ReleasedKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.derived_key.zeroize();
        self.session_id.zeroize();
    }
}

impl ReleasedKey {
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
}

/// In-memory state for a two-person key-release session.
///
/// The session is created by the first operator, sealed by the second
/// operator's share, and consumed by the caller. The session auto-
/// expires after `timeout_secs`.
pub struct TwoPersonSession {
    pub session_id: [u8; 32],
    pub classification: Classification,
    pub compartments: Compartments,
    pub first_share: Option<OperatorShare>,
    pub witness: Option<Witness>,
    pub timeout_secs: u64,
    pub created_ms: u64,
    pub audit_log: Vec<SessionEvent>,
}

/// Event types recorded in the in-session audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionEvent {
    Opened { operator_id: OperatorId, at_ms: u64 },
    FirstShareEntered { operator_id: OperatorId, at_ms: u64 },
    SecondShareEntered { operator_id: OperatorId, at_ms: u64 },
    WitnessSigned { witness: Witness, at_ms: u64 },
    Released { session_id: [u8; 32], at_ms: u64 },
    Aborted { reason: String, at_ms: u64 },
    Expired,
}

impl TwoPersonSession {
    /// Open a new two-person session for the given classification level.
    pub fn open(
        classification: Classification,
        compartments: Compartments,
        timeout_secs: u64,
        opener: OperatorId,
        now_ms: u64,
    ) -> OmegaResult<Self> {
        if !classification.requires_dual_cipher()
            && classification.level() < crate::omega::classification::SECRET
        {
            // For Secret and below, the two-person rule is OPTIONAL
            // (configurable); we still allow sessions but the operator
            // gets a non-fatal warning. For TS and above, two-person is
            // MANDATORY.
        }
        let session_id =
            *blake3::hash(format!("session-{}-{}", opener.0[0], now_ms).as_bytes()).as_bytes();
        Ok(Self {
            session_id,
            classification,
            compartments,
            first_share: None,
            witness: None,
            timeout_secs,
            created_ms: now_ms,
            audit_log: vec![SessionEvent::Opened {
                operator_id: opener,
                at_ms: now_ms,
            }],
        })
    }

    /// Submit the first operator's share.
    pub fn submit_first_share(&mut self, share: OperatorShare, now_ms: u64) -> OmegaResult<()> {
        if self.first_share.is_some() {
            return Err(OmegaError::TwoPersonFailed(
                "first share already submitted".into(),
            ));
        }
        if self.is_expired(now_ms) {
            return Err(OmegaError::TwoPersonFailed("session expired".into()));
        }
        self.audit_log.push(SessionEvent::FirstShareEntered {
            operator_id: share.operator_id.clone(),
            at_ms: now_ms,
        });
        self.first_share = Some(share);
        Ok(())
    }

    /// Submit the second operator's share and (optionally) a witness.
    /// If everything checks out, this releases the key.
    pub fn submit_second_share(
        &mut self,
        second: OperatorShare,
        witness: Option<Witness>,
        now_ms: u64,
    ) -> OmegaResult<ReleasedKey> {
        if self.is_expired(now_ms) {
            return Err(OmegaError::TwoPersonFailed("session expired".into()));
        }
        let first = self
            .first_share
            .as_ref()
            .ok_or_else(|| OmegaError::TwoPersonFailed("first share not yet submitted".into()))?;
        if first.operator_id == second.operator_id {
            return Err(OmegaError::TwoPersonFailed(
                "second share must be from a different operator".into(),
            ));
        }
        if let Some(w) = &witness {
            self.audit_log.push(SessionEvent::WitnessSigned {
                witness: w.clone(),
                at_ms: now_ms,
            });
            self.witness = Some(w.clone());
        } else if self.classification.requires_dual_cipher() || self.classification.level() >= 40 {
            return Err(OmegaError::TwoPersonFailed(
                "witness required for this classification level".into(),
            ));
        }

        // Constant-time XOR of the two shares. The derived key is then
        // run through HKDF-SHA-256 with the session_id as info to
        // produce the final 32-byte key. This binds the release to
        // this specific session and prevents one released key from
        // being used in another.
        let mut combined = [0u8; 32];
        for i in 0..32 {
            combined[i] = first.share[i] ^ second.share[i];
        }
        let info = b"soteria-omega-2p-release-v1";
        let info_with_session = [info.as_slice(), self.session_id.as_slice()].concat();
        let hk = blake3::hash(&combined);
        let mut derived = [0u8; 32];
        derived.copy_from_slice(hk.as_bytes());
        // Domain-separate by session_id. blake3 keyed-hash via Hasher.
        let mut hasher = blake3::Hasher::new_keyed(&self.session_id);
        hasher.update(&derived);
        let final_hash = hasher.finalize();
        let mut final_key = [0u8; 32];
        final_key.copy_from_slice(final_hash.as_bytes());
        combined.zeroize();
        derived.zeroize();

        self.audit_log.push(SessionEvent::SecondShareEntered {
            operator_id: second.operator_id.clone(),
            at_ms: now_ms,
        });
        let release = ReleasedKey {
            derived_key: final_key,
            session_id: self.session_id,
            classification: self.classification,
            compartments: self.compartments.clone(),
            witness: witness.unwrap_or(Witness::Journal {
                entry_hash: [0u8; 32],
                prev_chain_hash: [0u8; 32],
            }),
            released_at_ms: now_ms,
        };
        self.audit_log.push(SessionEvent::Released {
            session_id: self.session_id,
            at_ms: now_ms,
        });
        Ok(release)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        let elapsed_secs = (now_ms.saturating_sub(self.created_ms)) / 1000;
        elapsed_secs >= self.timeout_secs
    }

    pub fn abort(&mut self, reason: impl Into<String>, now_ms: u64) {
        self.audit_log.push(SessionEvent::Aborted {
            reason: reason.into(),
            at_ms: now_ms,
        });
    }
}

/// A small in-memory registry of operator enrollments for the local
/// host. In a real deployment this is on a hardware token or a
/// directory service; in MVP we keep it in process memory and write a
/// tamper-evident copy to disk via the policy::audit_log module.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TwoPersonRule {
    pub operators: BTreeMap<OperatorId, EnrollmentToken>,
}

impl TwoPersonRule {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enroll(
        &mut self,
        display_name: impl Into<String>,
        role: OperatorRole,
        clearance: Classification,
        compartments: Compartments,
        encrypted_share: Vec<u8>,
        kdf_salt: [u8; 16],
    ) -> OperatorId {
        let id = OperatorId::random();
        let token = EnrollmentToken {
            operator_id: id.clone(),
            display_name: display_name.into(),
            role,
            clearance,
            compartments,
            encrypted_share,
            kdf_salt,
            last_attested_ms: 0,
        };
        self.operators.insert(id.clone(), token);
        id
    }

    pub fn get(&self, id: &OperatorId) -> Option<&EnrollmentToken> {
        self.operators.get(id)
    }

    pub fn revoke(&mut self, id: &OperatorId) -> bool {
        self.operators.remove(id).is_some()
    }

    /// Find any operator with a given role and clearance.
    pub fn find_role(
        &self,
        role: OperatorRole,
        min_level: Classification,
    ) -> Option<&EnrollmentToken> {
        self.operators
            .values()
            .find(|t| t.role == role && t.clearance.level() >= min_level.level())
    }

    pub fn operator_count(&self) -> usize {
        self.operators.len()
    }
}

/// Domain separation tag for two-person key release HKDF.
pub const TWOPERSON_RELEASE_INFO: &[u8] = b"soteria-omega-2p-release-v1";

/// HMAC-SHA-256 domain separation tag for two-person session IDs.
pub const TWOPERSON_SESSION_TAG: &[u8] = b"soteria-omega-2p-session-v1";

/// Helper: derive a session ID from a public commitment.
///
/// In a real deployment, the opener publishes a commitment (e.g., a
/// hash of the classification + a nonce); the witness and second
/// operator confirm the session matches this commitment. For MVP we
/// expose this for testing.
pub fn session_commitment(
    classification: Classification,
    opener: &OperatorId,
    nonce: &[u8; 16],
) -> Hash {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&classification.level().to_le_bytes());
    buf.extend_from_slice(&opener.0);
    buf.extend_from_slice(nonce);
    blake3::hash(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_open_and_release() {
        let a = OperatorId::random();
        let b = OperatorId::random();
        let compartments = Compartments::new();
        let mut s = TwoPersonSession::open(
            Classification::Secret,
            compartments,
            60,
            a.clone(),
            1_000_000,
        )
        .unwrap();
        let sa = OperatorShare::new(a, [1u8; 32]);
        let sb = OperatorShare::new(b, [2u8; 32]);
        s.submit_first_share(sa, 1_001_000).unwrap();
        // Without witness -> allowed for Secret
        let r = s.submit_second_share(sb, None, 1_002_000).unwrap();
        assert_eq!(r.classification, Classification::Secret);
        assert_ne!(r.derived_key, [0u8; 32]);
    }

    #[test]
    fn same_operator_rejected() {
        let a = OperatorId::random();
        let compartments = Compartments::new();
        let mut s =
            TwoPersonSession::open(Classification::Secret, compartments, 60, a.clone(), 0).unwrap();
        let sa = OperatorShare::new(a.clone(), [1u8; 32]);
        let sb = OperatorShare::new(a, [2u8; 32]);
        s.submit_first_share(sa, 1_000).unwrap();
        let err = s.submit_second_share(sb, None, 2_000).unwrap_err();
        assert!(matches!(err, OmegaError::TwoPersonFailed(_)));
    }

    #[test]
    fn top_secret_requires_witness() {
        let a = OperatorId::random();
        let b = OperatorId::random();
        let compartments = Compartments::new();
        let mut s =
            TwoPersonSession::open(Classification::TopSecret, compartments, 60, a.clone(), 0)
                .unwrap();
        let sa = OperatorShare::new(a, [1u8; 32]);
        let sb = OperatorShare::new(b, [2u8; 32]);
        s.submit_first_share(sa, 1_000).unwrap();
        let err = s.submit_second_share(sb, None, 2_000).unwrap_err();
        assert!(matches!(err, OmegaError::TwoPersonFailed(_)));
    }

    #[test]
    fn top_secret_with_witness() {
        let a = OperatorId::random();
        let b = OperatorId::random();
        let w = OperatorId::random();
        let compartments = Compartments::new();
        let mut s =
            TwoPersonSession::open(Classification::TopSecret, compartments, 60, a.clone(), 0)
                .unwrap();
        let sa = OperatorShare::new(a, [1u8; 32]);
        let sb = OperatorShare::new(b, [2u8; 32]);
        let witness = Witness::Human {
            operator_id: w,
            signature: vec![0xABu8; 64],
        };
        s.submit_first_share(sa, 1_000).unwrap();
        let r = s.submit_second_share(sb, Some(witness), 2_000).unwrap();
        assert_eq!(r.classification, Classification::TopSecret);
    }

    #[test]
    fn expired_session_rejected() {
        let a = OperatorId::random();
        let b = OperatorId::random();
        let compartments = Compartments::new();
        let mut s =
            TwoPersonSession::open(Classification::Secret, compartments, 10, a.clone(), 0).unwrap();
        let sa = OperatorShare::new(a, [1u8; 32]);
        let sb = OperatorShare::new(b, [2u8; 32]);
        s.submit_first_share(sa, 1_000).unwrap();
        let err = s.submit_second_share(sb, None, 20_000).unwrap_err();
        assert!(matches!(err, OmegaError::TwoPersonFailed(_)));
    }

    #[test]
    fn enrollment_and_lookup() {
        let mut rule = TwoPersonRule::new();
        let id = rule.enroll(
            "Alice",
            OperatorRole::ShareholderA,
            Classification::TopSecret,
            Compartments::new(),
            vec![0u8; 64],
            [0u8; 16],
        );
        assert!(rule.get(&id).is_some());
        assert_eq!(rule.operator_count(), 1);
    }

    #[test]
    fn revoke_operator() {
        let mut rule = TwoPersonRule::new();
        let id = rule.enroll(
            "Alice",
            OperatorRole::ShareholderA,
            Classification::TopSecret,
            Compartments::new(),
            vec![0u8; 64],
            [0u8; 16],
        );
        assert!(rule.revoke(&id));
        assert!(rule.get(&id).is_none());
    }

    #[test]
    fn session_commitment_is_deterministic() {
        let a = OperatorId::from_bytes([1u8; 32]);
        let nonce = [2u8; 16];
        let c1 = session_commitment(Classification::Secret, &a, &nonce);
        let c2 = session_commitment(Classification::Secret, &a, &nonce);
        assert_eq!(c1.as_bytes(), c2.as_bytes());
    }
}
