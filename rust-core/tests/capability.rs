use soteria_core::key_manager::{Capability, CapabilityScope};
use std::path::PathBuf;

#[test]
fn capability_expires() {
    let scope = CapabilityScope {
        region_id: "region-a".into(),
        path_prefix: PathBuf::from("/data"),
        can_read: true,
        can_write: false,
    };
    let cap = Capability::issue(101, scope, 0);
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert!(!cap.valid());
}
