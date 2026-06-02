use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: String,
    pub block_size: usize,
    pub frozen: bool,
}

impl Region {
    pub fn freeze(&mut self) {
        self.frozen = true;
    }
}
