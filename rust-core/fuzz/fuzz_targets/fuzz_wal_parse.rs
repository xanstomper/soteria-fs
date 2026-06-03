#![no_main]
use libfuzzer_sys::fuzz_target;
use soteria_core::fs_layer::wal::Wal;

fuzz_target!(|data: &[u8]| {
    let state = Wal::parse(data);
    match state {
        soteria_core::fs_layer::wal::WalState::Absent => {}
        soteria_core::fs_layer::wal::WalState::Committed(_) => {}
        soteria_core::fs_layer::wal::WalState::Uncommitted => {}
    }
});
