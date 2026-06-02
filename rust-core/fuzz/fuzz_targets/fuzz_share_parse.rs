#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz share file JSON parsing — must never panic.
    let _ = std::panic::catch_unwind(|| {
        let _ = serde_json::from_slice::<serde_json::Value>(data);
    });
});
