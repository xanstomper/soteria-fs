use super::SoteriaEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event_hash: String,
    pub chain_hash: String,
    pub event: SoteriaEvent,
}

pub struct EventBus {
    sequence: u64,
    last_hash: String,
    records: Vec<EventRecord>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            last_hash: "GENESIS".into(),
            records: Vec::new(),
        }
    }
    pub fn append(&mut self, event: SoteriaEvent) -> crate::Result<EventRecord> {
        self.sequence += 1;
        let event_bytes = serde_json::to_vec(&event)?;
        let event_hash = blake3::hash(&event_bytes).to_hex().to_string();
        let mut chain_material = self.last_hash.as_bytes().to_vec();
        chain_material.extend_from_slice(event_hash.as_bytes());
        chain_material.extend_from_slice(&self.sequence.to_le_bytes());
        let chain_hash = blake3::hash(&chain_material).to_hex().to_string();
        let record = EventRecord {
            sequence: self.sequence,
            previous_hash: self.last_hash.clone(),
            event_hash,
            chain_hash: chain_hash.clone(),
            event,
        };
        self.last_hash = chain_hash;
        self.records.push(record.clone());
        Ok(record)
    }
    pub fn records(&self) -> &[EventRecord] {
        &self.records
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
