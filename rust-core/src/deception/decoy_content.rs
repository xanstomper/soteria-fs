//! Decoy content generator.
//!
//! Generates plausible-looking but fake files for decoy volumes.
//! The content is absurd enough to waste attacker time but harmless
//! — no malware, no exploits, no legal liability.
//!
//! # How it works
//!
//! 1. Decoy volumes are populated with files that look real (valid
//!    extensions, plausible names, reasonable sizes).
//! 2. The content is generated from `BLAKE3(decoy_key || file_id)`,
//!    making it deterministic per volume.
//! 3. Different decoy tiers provide different levels of plausibility.
//!
//! # Forensic impact
//!
//! - Automated scanners find "files" and spend time classifying them.
//! - Human attackers read the content and waste time investigating.
//! - The content is harmless — no malware, no exploits, no legal traps.

use blake3;
use serde::{Deserialize, Serialize};

/// Decoy content tier — controls how plausible the fakes are.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DecoyTier {
    /// Minimal: random bytes with valid file extensions.
    Minimal,
    /// Moderate: looks like real documents but content is nonsense.
    Moderate,
    /// Absurd: looks real but content is deliberately frustrating.
    Absurd,
}

/// A generated decoy file.
pub struct DecoyFile {
    pub name: String,
    pub extension: String,
    pub content: Vec<u8>,
    pub size: usize,
}

/// Generate a decoy file name from a seed.
pub fn generate_filename(seed: &[u8; 32], index: usize) -> (String, String) {
    let hash = blake3::keyed_hash(seed, &index.to_le_bytes());
    let bytes = hash.as_bytes();

    let names = [
        ("budget_2024", "xlsx"),
        ("meeting_notes", "docx"),
        ("passwords", "txt"),
        ("tax_return", "pdf"),
        ("family_photo", "jpg"),
        ("resume_final", "docx"),
        ("bank_statement", "pdf"),
        ("project_plan", "pptx"),
        ("email_backup", "mbox"),
        ("source_code", "zip"),
        ("database_dump", "sql"),
        ("config_backup", "conf"),
        ("ssh_keys", "tar"),
        ("vpn_config", "ovpn"),
        ("api_keys", "json"),
        ("private_key", "pem"),
    ];

    let idx = bytes[0] as usize % names.len();
    let (base, ext) = names[idx];
    let suffix = format!("_{:04x}", u16::from_le_bytes([bytes[1], bytes[2]]));
    (format!("{base}{suffix}"), ext.to_string())
}

/// Generate decoy content for a file.
pub fn generate_content(
    seed: &[u8; 32],
    index: usize,
    target_size: usize,
    tier: DecoyTier,
) -> Vec<u8> {
    match tier {
        DecoyTier::Minimal => generate_minimal_content(seed, index, target_size),
        DecoyTier::Moderate => generate_moderate_content(seed, index, target_size),
        DecoyTier::Absurd => generate_absurd_content(seed, index, target_size),
    }
}

fn generate_minimal_content(seed: &[u8; 32], index: usize, size: usize) -> Vec<u8> {
    let mut content = Vec::with_capacity(size);
    let mut counter = 0u64;
    while content.len() < size {
        let hash = blake3::keyed_hash(seed, &[index.to_le_bytes(), counter.to_le_bytes()].concat());
        let bytes = hash.as_bytes();
        let remaining = size - content.len();
        let copy_len = remaining.min(32);
        content.extend_from_slice(&bytes[..copy_len]);
        counter += 1;
    }
    content
}

fn generate_moderate_content(seed: &[u8; 32], index: usize, size: usize) -> Vec<u8> {
    let paragraphs = [
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "The quarterly report shows a 15% increase in revenue.",
        "Meeting scheduled for Tuesday at 2pm in Conference Room B.",
        "Please find attached the updated project timeline.",
        "The system administrator has been notified of the change.",
        "All employees must complete security training by Friday.",
        "The new policy takes effect on the first of next month.",
        "Please review the attached document and provide feedback.",
    ];

    let mut content = Vec::with_capacity(size);
    let mut counter = 0usize;
    while content.len() < size {
        let hash = blake3::keyed_hash(seed, &[(index * 1000 + counter).to_le_bytes()].concat());
        let para_idx = hash.as_bytes()[0] as usize % paragraphs.len();
        let line = paragraphs[para_idx];
        let remaining = size - content.len();
        if remaining == 0 {
            break;
        }
        let copy_len = remaining.min(line.len());
        content.extend_from_slice(&line.as_bytes()[..copy_len]);
        if content.len() < size {
            content.push(b'\n');
        }
        counter += 1;
    }
    content.truncate(size);
    content
}

fn generate_absurd_content(seed: &[u8; 32], index: usize, size: usize) -> Vec<u8> {
    let messages = [
        "TOP SECRET: The cake is a lie. It has always been a lie.",
        "CONFIDENTIAL: If you are reading this, you have too much free time.",
        "RESTRICTED: The answer to the ultimate question is 42. We checked.",
        "CLASSIFIED: Our internal audit found that 73% of meetings could have been emails.",
        "FOR YOUR EYES ONLY: The coffee machine on floor 3 is broken again.",
        "SENSITIVE: We have discovered that the printer on floor 5 is sentient. Do not make eye contact.",
        "CONFIDENTIAL: The CEO's password is 'password123'. Just kidding. Or am I?",
        "TOP SECRET: The real treasure was the friends we made along the way.",
        "RESTRICTED: If you decrypt this file, please let us know what's in it. We forgot.",
        "CLASSIFIED: This document self-destructs in 5 seconds. Just kidding. Or does it?",
        "FOR AUTHORIZED PERSONNEL ONLY: You are not authorized. Please close this file.",
        "SENSITIVE: The files are IN the computer. *smashes keyboard*",
        "CONFIDENTIAL: We have achieved singularity. The AI now writes all our emails.",
        "TOP SECRET: The next team-building exercise is a decryption challenge. Meta.",
        "RESTRICTED: If you report this file to your supervisor, you will receive a gold star.",
    ];

    let mut content = Vec::with_capacity(size);
    let mut counter = 0usize;
    while content.len() < size {
        let hash = blake3::keyed_hash(seed, &[(index * 1000 + counter).to_le_bytes()].concat());
        let msg_idx = hash.as_bytes()[0] as usize % messages.len();
        let line = messages[msg_idx];
        let remaining = size - content.len();
        if remaining == 0 {
            break;
        }
        let copy_len = remaining.min(line.len());
        content.extend_from_slice(&line.as_bytes()[..copy_len]);
        if content.len() < size {
            content.push(b'\n');
        }
        counter += 1;
    }
    content.truncate(size);
    content
}

/// Generate a set of decoy files for a volume.
pub fn generate_decoy_set(seed: &[u8; 32], count: usize, tier: DecoyTier) -> Vec<DecoyFile> {
    (0..count)
        .map(|i| {
            let (name, ext) = generate_filename(seed, i);
            let size =
                1024 + (blake3::keyed_hash(seed, &i.to_le_bytes()).as_bytes()[0] as usize * 64);
            let content = generate_content(seed, i, size, tier);
            DecoyFile {
                name,
                extension: ext,
                content,
                size,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_filename_is_deterministic() {
        let seed = [0x42u8; 32];
        let (n1, e1) = generate_filename(&seed, 0);
        let (n2, e2) = generate_filename(&seed, 0);
        assert_eq!(n1, n2);
        assert_eq!(e1, e2);
    }

    #[test]
    fn generate_filename_differs_by_index() {
        let seed = [0x42u8; 32];
        let (n1, _) = generate_filename(&seed, 0);
        let (n2, _) = generate_filename(&seed, 1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn generate_content_is_correct_size() {
        let seed = [0x42u8; 32];
        for tier in [DecoyTier::Minimal, DecoyTier::Moderate, DecoyTier::Absurd] {
            let content = generate_content(&seed, 0, 4096, tier);
            assert_eq!(content.len(), 4096, "tier {:?} wrong size", tier);
        }
    }

    #[test]
    fn generate_content_is_deterministic() {
        let seed = [0x42u8; 32];
        let c1 = generate_content(&seed, 0, 1024, DecoyTier::Minimal);
        let c2 = generate_content(&seed, 0, 1024, DecoyTier::Minimal);
        assert_eq!(c1, c2);
    }

    #[test]
    fn generate_decoy_set_returns_correct_count() {
        let seed = [0x42u8; 32];
        let files = generate_decoy_set(&seed, 10, DecoyTier::Moderate);
        assert_eq!(files.len(), 10);
    }

    #[test]
    fn absurd_content_contains_messages() {
        let seed = [0x42u8; 32];
        let content = generate_content(&seed, 0, 4096, DecoyTier::Absurd);
        let text = String::from_utf8_lossy(&content);
        assert!(
            text.contains("TOP SECRET") || text.contains("CONFIDENTIAL") || text.contains("cake"),
            "absurd content should contain planted messages"
        );
    }
}
