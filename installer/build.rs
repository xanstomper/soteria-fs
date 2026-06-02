use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir.parent().unwrap();

    // Find the soteriad binary. Check release first, then debug.
    let binary_name = if cfg!(target_os = "windows") {
        "soteriad.exe"
    } else {
        "soteriad"
    };

    let candidates = vec![
        root.join(format!("rust-core/target/release/{binary_name}")),
        root.join(format!("rust-core/target/debug/{binary_name}")),
        root.join(format!("target/release/{binary_name}")),
        root.join(format!("target/debug/{binary_name}")),
    ];

    let source = candidates
        .iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| {
            panic!(
                "Could not find {binary_name}. Build it first:\n  cd rust-core && cargo build --release\n\nSearched: {candidates:?}"
            )
        });

    let dest = out_dir.join("soteriad_embedded");
    fs::copy(&source, &dest).unwrap_or_else(|e| {
        panic!(
            "Failed to copy {} to {}: {e}",
            source.display(),
            dest.display()
        )
    });

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed=rust-core/src/main.rs");
}
