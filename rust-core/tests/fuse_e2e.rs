#![cfg(all(target_os = "linux", feature = "fuse"))]

//! Linux-gated end-to-end FUSE test. Mounts a real FUSE filesystem, writes
//! files through the kernel, reads them back, then unmounts and verifies the
//! on-disk ciphertext.

use soteria_core::config::{CryptoConfig, SoteriaConfig};
use soteria_core::fs_layer::fuse_fs::SoteriaFs;
use soteria_core::fs_layer::storage::BACKING_EXT;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn unique_paths(label: &str) -> (PathBuf, PathBuf) {
    let mut base = std::env::temp_dir();
    base.push(format!("soteria-fuse-{}-{}", label, std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let backing = base.join("backing");
    let mount = base.join("mount");
    std::fs::create_dir_all(&backing).unwrap();
    std::fs::create_dir_all(&mount).unwrap();
    (backing, mount)
}

#[test]
fn mount_write_read_unmount() {
    let (backing, mount) = unique_paths("rw");
    let cfg = SoteriaConfig {
        crypto: CryptoConfig {
            algorithm: "xchacha20-poly1305".into(),
            block_size: 4096,
            argon2_memory_kib: 8192,
            argon2_iterations: 1,
        },
        key_lifecycle: Default::default(),
        event_bus: Default::default(),
        response: Default::default(),
        snapshot: Default::default(),
        ai_observer: Default::default(),
        deception: Default::default(),
    };
    let fs = SoteriaFs::new(backing.clone(), cfg).unwrap();

    let mountpoint = mount.clone();
    let backing_for_thread = backing.clone();
    let mount_for_thread = mount.clone();
    let handle = std::thread::spawn(move || {
        fuser::mount2(
            fs,
            &mountpoint,
            &[
                fuser::MountOption::FSName("soteria-fs".into()),
                fuser::MountOption::AutoUnmount,
                fuser::MountOption::DefaultPermissions,
            ],
        )
    });

    // Wait for the mount to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if mount.join(".").exists() && std::fs::metadata(&mount).is_ok() {
            let entries: Vec<_> = std::fs::read_dir(&mount).map(|it| it.count()).unwrap_or(0);
            if entries > 0 || mount.join(".").exists() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Write a file through the kernel.
    let payload = b"through-the-kernel-encrypted-blocks".repeat(200);
    let target = mount_for_thread.join("hello.txt");
    std::fs::write(&target, &payload).expect("write through FUSE must succeed");

    // Read it back.
    let read_back = std::fs::read(&target).expect("read through FUSE must succeed");
    assert_eq!(read_back, payload, "round-trip equality through FUSE");

    // Verify the on-disk file is encrypted and does not contain the plaintext.
    let backing_file = backing_for_thread.join(format!("hello.txt.{BACKING_EXT}"));
    assert!(backing_file.exists(), "backing file should exist");
    let raw = std::fs::read(&backing_file).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(
        !raw_str.contains("through-the-kernel"),
        "plaintext must not be in backing file"
    );

    // Unmount.
    let _ = Command::new("fusermount")
        .args(["-u", mount_for_thread.to_str().unwrap()])
        .output();
    let _ = Command::new("umount").arg(&mount_for_thread).output();
    let _ = handle.join();
}
