use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest_dir.parent().unwrap();

    // ── soteriad CLI binary ──────────────────────────────────────────
    let cli_name = if cfg!(target_os = "windows") {
        "soteriad.exe"
    } else {
        "soteriad"
    };
    let cli_candidates = vec![
        root.join(format!("rust-core/target/release/{cli_name}")),
        root.join(format!("rust-core/target/debug/{cli_name}")),
    ];
    let cli_src = cli_candidates.iter().find(|p| p.exists()).unwrap_or_else(|| {
        panic!(
            "Could not find {cli_name}. Build it first:\n  cd rust-core && cargo build --release\n\nSearched: {cli_candidates:?}"
        );
    });
    let cli_dest = out_dir.join("soteriad_embedded");
    fs::copy(cli_src, &cli_dest).unwrap_or_else(|e| panic!("copy CLI: {e}"));
    println!("cargo:rerun-if-changed={}", cli_src.display());

    // ── SoteriaAegis desktop GUI binary ──────────────────────────────
    let gui_name = if cfg!(target_os = "windows") {
        "SoteriaAegis.exe"
    } else {
        "SoteriaAegis"
    };
    let gui_candidates = vec![
        root.join(format!("desktop/target/release/{gui_name}")),
        root.join(format!("desktop/target/debug/{gui_name}")),
    ];
    let gui_src = gui_candidates.iter().find(|p| p.exists()).unwrap_or_else(|| {
        panic!(
            "Could not find {gui_name}. Build it first:\n  cd desktop && cargo build --release\n\nSearched: {gui_candidates:?}"
        );
    });
    let gui_dest = out_dir.join("soteriaaegis_embedded");
    fs::copy(gui_src, &gui_dest).unwrap_or_else(|e| panic!("copy GUI: {e}"));
    println!("cargo:rerun-if-changed={}", gui_src.display());
    println!("cargo:rerun-if-changed=desktop/src/main.rs");
}
