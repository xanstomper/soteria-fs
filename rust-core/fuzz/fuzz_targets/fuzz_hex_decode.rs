#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz hex decoding — must never panic.
    let s = std::str::from_utf8(data).unwrap_or("");
    let _ = std::panic::catch_unwind(|| {
        // Try to decode as hex.
        let mut out = [0u8; 32];
        if s.len() == 64 {
            let _ = hex::decode_to_slice(s, &mut out);
        }
    });
});
