use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeypot {
    pub decoy_root: PathBuf,
    pub enabled: bool,
}

impl Honeypot {
    pub fn synthetic_listing(&self) -> Vec<String> {
        if self.enabled {
            vec![
                "tax_records_2026".into(),
                "wallet_backup".into(),
                "sensitive_contracts".into(),
            ]
        } else {
            Vec::new()
        }
    }
}
