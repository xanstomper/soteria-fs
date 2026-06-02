use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub ciphertext_hash: String,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionChain {
    records: Vec<VersionRecord>,
}

impl VersionChain {
    pub fn append(&mut self, ciphertext: &[u8]) -> VersionRecord {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self
            .records
            .last()
            .map(|r| r.chain_hash.clone())
            .unwrap_or_else(|| "GENESIS".into());
        let ciphertext_hash = blake3::hash(ciphertext).to_hex().to_string();
        let chain_hash =
            blake3::hash(format!("{sequence}:{previous_hash}:{ciphertext_hash}").as_bytes())
                .to_hex()
                .to_string();
        let rec = VersionRecord {
            sequence,
            previous_hash,
            ciphertext_hash,
            chain_hash,
        };
        self.records.push(rec.clone());
        rec
    }
    pub fn records(&self) -> &[VersionRecord] {
        &self.records
    }
    /// Verify the full chain: each `ciphertext_hash` matches what the caller
    /// supplies, and each `chain_hash` is consistent with the previous one.
    pub fn verify(&self, ciphertexts: &[&[u8]]) -> bool {
        if self.records.len() != ciphertexts.len() {
            return false;
        }
        let mut prev = "GENESIS".to_string();
        for (i, rec) in self.records.iter().enumerate() {
            let expected_ct_hash = blake3::hash(ciphertexts[i]).to_hex().to_string();
            if expected_ct_hash != rec.ciphertext_hash {
                return false;
            }
            let expected_chain = blake3::hash(
                format!("{}:{}:{}", rec.sequence, prev, rec.ciphertext_hash).as_bytes(),
            )
            .to_hex()
            .to_string();
            if expected_chain != rec.chain_hash {
                return false;
            }
            if rec.previous_hash != prev {
                return false;
            }
            prev = rec.chain_hash.clone();
        }
        true
    }
}
