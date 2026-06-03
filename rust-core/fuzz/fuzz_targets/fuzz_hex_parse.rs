#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let s = std::str::from_utf8(data).unwrap_or("");
    let _ = soteria_core::crypto_engine::block::lineage_prev_salt(s);
});
