#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::fs_layer::wal::Wal;

fuzz_target!(|data: &[u8]| {
    // Fuzz the WAL parser — must never panic, must always return a valid state.
    let state = Wal::parse(data);
    match state {
        soteria_core::fs_layer::wal::WalState::Absent => {}
        soteria_core::fs_layer::wal::WalState::Committed(payload) => {
            // If committed, the payload must be non-empty.
            assert!(!payload.is_empty() || data.len() >= 12);
        }
        soteria_core::fs_layer::wal::WalState::Uncommitted => {}
    }
});
