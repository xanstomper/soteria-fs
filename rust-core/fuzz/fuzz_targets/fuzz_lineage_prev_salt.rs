#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::crypto_engine::block::lineage_prev_salt;

fuzz_target!(|data: &[u8]| {
    // Convert to string (may not be valid UTF-8, but that's OK for fuzzing).
    let s = std::str::from_utf8(data).unwrap_or("");
    // Must never panic on any input.
    let _ = std::panic::catch_unwind(|| {
        lineage_prev_salt(s);
    });
});
