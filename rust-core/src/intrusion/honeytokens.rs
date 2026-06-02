//! Honeytoken Lure System (R-1) — passive version.
//!
//! Generates decoy files that look valuable but are actually tripwires.
//! When a honeytoken is accessed, the event is logged to the forensic
//! mirror. No malware, no beacons, no active counter-measures.
//!
//! # Legal
//!
//! This is a standard honeypot technique. The honeytokens are just
//! files with specific content. Access logging is passive audit logging.

use blake3;
use serde::{Deserialize, Serialize};

/// Type of honeytoken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HoneytokenType {
    /// Looks like a cryptocurrency wallet seed phrase.
    CryptoWallet,
    /// Looks like a password manager export.
    PasswordVault,
    /// Looks like a private key file.
    PrivateKey,
    /// Looks like a classified document.
    ClassifiedDoc,
    /// Looks like a database dump.
    DatabaseDump,
}

/// A single honeytoken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeytoken {
    pub id: [u8; 16],
    pub token_type: HoneytokenType,
    pub filename: String,
    pub content: Vec<u8>,
    pub placed_at: u64,
}

/// Generate a honeytoken of the given type.
pub fn generate_honeytoken(
    token_type: HoneytokenType,
    seed: &[u8; 32],
    index: usize,
) -> Honeytoken {
    let hash = blake3::keyed_hash(seed, &index.to_le_bytes());
    let id_bytes: [u8; 16] = hash.as_bytes()[..16].try_into().unwrap();

    let (filename, content) = match &token_type {
        HoneytokenType::CryptoWallet => {
            let phrases = generate_seed_phrases(seed, index);
            let content = phrases.join("\n");
            (
                format!(
                    "wallet_backup_{:04x}.txt",
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                ),
                content.into_bytes(),
            )
        }
        HoneytokenType::PasswordVault => {
            let entries = generate_credential_entries(seed, index);
            let content = entries.join("\n");
            (
                format!(
                    "passwords_export_{:04x}.csv",
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                ),
                content.into_bytes(),
            )
        }
        HoneytokenType::PrivateKey => {
            let key = generate_fake_private_key(seed, index);
            (
                format!(
                    "id_rsa_{:04x}",
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                ),
                key.into_bytes(),
            )
        }
        HoneytokenType::ClassifiedDoc => {
            let doc = generate_classified_doc(seed, index);
            (
                format!(
                    "classified_report_{:04x}.pdf",
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                ),
                doc.into_bytes(),
            )
        }
        HoneytokenType::DatabaseDump => {
            let dump = generate_db_dump(seed, index);
            (
                format!(
                    "database_backup_{:04x}.sql",
                    u16::from_le_bytes([id_bytes[0], id_bytes[1]])
                ),
                dump.into_bytes(),
            )
        }
    };

    let placed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Honeytoken {
        id: id_bytes,
        token_type,
        filename,
        content,
        placed_at,
    }
}

fn generate_seed_phrases(seed: &[u8; 32], index: usize) -> Vec<String> {
    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual",
    ];
    (0..12u64)
        .map(|i| {
            let hash = blake3::keyed_hash(seed, &[index.to_le_bytes(), i.to_le_bytes()].concat());
            let idx = hash.as_bytes()[0] as usize % words.len();
            words[idx].to_string()
        })
        .collect()
}

fn generate_credential_entries(seed: &[u8; 32], index: usize) -> Vec<String> {
    let services = [
        "gmail.com",
        "github.com",
        "aws.amazon.com",
        "bank.com",
        "work.com",
    ];
    let mut entries = Vec::new();
    entries.push("url,username,password".to_string());
    for (i, service) in services.iter().enumerate() {
        let hash = blake3::keyed_hash(
            seed,
            &[index.to_le_bytes(), (i as u64).to_le_bytes()].concat(),
        );
        let user = format!(
            "user{:04x}@{}",
            u16::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]),
            service
        );
        let pass = format!(
            "{:032x}",
            u128::from_le_bytes(hash.as_bytes()[..16].try_into().unwrap())
        );
        entries.push(format!("{},{},{}", service, user, pass));
    }
    entries
}

fn generate_fake_private_key(seed: &[u8; 32], index: usize) -> String {
    let hash = blake3::keyed_hash(seed, &index.to_le_bytes());
    let key_data: String = hash.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
        key_data
    )
}

fn generate_classified_doc(seed: &[u8; 32], index: usize) -> String {
    let hash = blake3::keyed_hash(seed, &index.to_le_bytes());
    let doc_id = format!(
        "DOC-{:08x}",
        u32::from_le_bytes(hash.as_bytes()[..4].try_into().unwrap())
    );
    format!(
        "CLASSIFICATION: TOP SECRET // SI / TK\n\
         DOCUMENT ID: {}\n\
         ORIGINATOR: SOTERIA ANALYSIS DIVISION\n\
         DATE: 2024-01-15\n\
         \n\
         SUBJECT: Assessment of Regional Security Posture\n\
         \n\
         1. EXECUTIVE SUMMARY\n\
         This document contains sensitive information regarding...\n\
         [CONTENT REDACTED FOR HONEYTOKEN]\n",
        doc_id
    )
}

fn generate_db_dump(seed: &[u8; 32], index: usize) -> String {
    let hash = blake3::keyed_hash(seed, &index.to_le_bytes());
    format!(
        "-- Database backup\n\
         -- Host: db.internal.corp\n\
         -- Generated: 2024-01-15\n\
         \n\
         CREATE TABLE users (\n\
           id SERIAL PRIMARY KEY,\n\
           email VARCHAR(255),\n\
           password_hash VARCHAR(255),\n\
           ssn VARCHAR(11)\n\
         );\n\
         \n\
         INSERT INTO users VALUES\n\
         (1, 'admin@corp.com', '{:064x}', '000-00-0001');\n",
        u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_honeytoken_correct_size() {
        let seed = [0x42u8; 32];
        for t in [
            HoneytokenType::CryptoWallet,
            HoneytokenType::PasswordVault,
            HoneytokenType::PrivateKey,
            HoneytokenType::ClassifiedDoc,
            HoneytokenType::DatabaseDump,
        ] {
            let ht = generate_honeytoken(t, &seed, 0);
            assert!(!ht.content.is_empty());
            assert!(!ht.filename.is_empty());
        }
    }

    #[test]
    fn honeytoken_is_deterministic() {
        let seed = [0x42u8; 32];
        let h1 = generate_honeytoken(HoneytokenType::CryptoWallet, &seed, 0);
        let h2 = generate_honeytoken(HoneytokenType::CryptoWallet, &seed, 0);
        assert_eq!(h1.filename, h2.filename);
        assert_eq!(h1.content, h2.content);
    }

    #[test]
    fn honeytokens_differ_by_index() {
        let seed = [0x42u8; 32];
        let h1 = generate_honeytoken(HoneytokenType::CryptoWallet, &seed, 0);
        let h2 = generate_honeytoken(HoneytokenType::CryptoWallet, &seed, 1);
        assert_ne!(h1.filename, h2.filename);
    }

    #[test]
    fn wallet_seed_has_12_words() {
        let seed = [0x42u8; 32];
        let ht = generate_honeytoken(HoneytokenType::CryptoWallet, &seed, 0);
        let content = String::from_utf8_lossy(&ht.content);
        let words: Vec<&str> = content.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn private_key_has_pem_format() {
        let seed = [0x42u8; 32];
        let ht = generate_honeytoken(HoneytokenType::PrivateKey, &seed, 0);
        let content = String::from_utf8_lossy(&ht.content);
        assert!(content.contains("BEGIN RSA PRIVATE KEY"));
        assert!(content.contains("END RSA PRIVATE KEY"));
    }
}
