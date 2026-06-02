use crate::event_bus::{Severity, SoteriaEvent};

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn entropy_event(data: &[u8], threshold: f64) -> crate::Result<Option<SoteriaEvent>> {
    let entropy = shannon_entropy(data);
    if entropy >= threshold {
        Ok(Some(SoteriaEvent::new(
            "ENTROPY_SPIKE",
            "entropy_sensor",
            Severity::new(entropy / 8.0),
            serde_json::json!({"entropy": entropy}),
        )?))
    } else {
        Ok(None)
    }
}
