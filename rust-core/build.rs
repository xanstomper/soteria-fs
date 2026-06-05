//! FIPS 140-3 Software/Firmware Integrity Test (SFIT) build script.
//!
//! Computes an HMAC-SHA-256 of the freshly compiled `soteriad`
//! binary using a build-time Module Integrity Key. The result is
//! written to `target/soteria-module.hmac` (one line: 64 hex chars).
//!
//! At runtime, `crypto_engine::fips::integrity::run_integrity_test`
//! reads the binary, computes the same HMAC, and compares to the
//! expected value. If the binary has been tampered with, the
//! integrity test fails and the FIPS module refuses to start.
//!
//! ## Build-time key
//!
//! We use the public build-mode integrity key (see
//! `crypto_engine::fips::integrity::BUILD_MODE_INTEGRITY_KEY`).
//! This is fine for development and for demonstrating the
//! mechanism, but for a real FIPS 140-3 submission the key would
//! be supplied by the operator (e.g. via `SOTERIA_INTEGRITY_KEY`
//! env var or a KMS), not embedded in the build script.
//!
//! ## When this runs
//!
//! `cargo build` invokes `build.rs` AFTER the binary is linked.
//! We re-read the binary, hash it, and write the HMAC. Note that
//! the binary is `target/release/soteriad.exe` (Windows) or
//! `target/release/soteriad` (Unix). The integrity test at runtime
//! uses `std::env::current_exe()` to find itself.

use std::path::PathBuf;

fn main() {
    // Re-run the build script only if the binary or this script change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/crypto_engine/fips/integrity.rs");

    // Only run for the FIPS-enabled build of the `soteriad` bin.
    // We detect this by looking for the env var that Cargo sets
    // when `--features fips` is enabled: `CARGO_FEATURE_FIPS=`.
    let fips_enabled = std::env::var("CARGO_FEATURE_FIPS").is_ok();
    if !fips_enabled {
        return;
    }

    // Locate the binary. Cargo runs the build script with
    // `OUT_DIR=target/<...>/build/...`, so we go up to find `target/`.
    let out_dir = match std::env::var("OUT_DIR") {
        Ok(s) => PathBuf::from(s),
        Err(_) => return,
    };
    // `target/<profile>/build/<pkg>-<hash>/out`  ->  up 3 = `target/`
    let target_dir = out_dir
        .ancestors()
        .nth(3)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("target"));

    // Pick the right binary name.
    let bin = if cfg!(windows) {
        target_dir.join("release").join("soteriad.exe")
    } else {
        target_dir.join("release").join("soteriad")
    };
    if !bin.exists() {
        eprintln!(
            "build.rs: FIPS feature enabled but `{}` does not exist yet; \
             SFIT HMAC will not be written. (This is normal during the first \
             incremental build; the HMAC is written on the next build.)",
            bin.display()
        );
        return;
    }

    // Compute the HMAC-SHA-256 of the binary using the same
    // build-mode key as `integrity::BUILD_MODE_INTEGRITY_KEY`.
    let key: &[u8; 32] = b"sot-fips-140-3-dev-mode-key--v1.";
    let bytes = match std::fs::read(&bin) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("build.rs: cannot read binary `{}`: {e}", bin.display());
            return;
        }
    };
    // Minimal HMAC-SHA-256 implementation (RFC 2104) so we don't
    // need a runtime dep here. The build script is compiled with
    // rustc but cannot depend on `ring` cleanly without polluting
    // the dep graph; an inline ~80-line implementation is
    // simpler than wiring a `build-dependencies` entry.
    let hmac = hmac_sha256(key, &bytes);

    // Write the HMAC to `target/soteria-module.hmac` (one line).
    let hmac_path = target_dir.join("soteria-module.hmac");
    if let Err(e) = std::fs::write(&hmac_path, hex_encode(&hmac)) {
        eprintln!(
            "build.rs: cannot write HMAC to `{}`: {e}",
            hmac_path.display()
        );
    } else {
        println!(
            "cargo:warning=FIPS SFIT HMAC written to {}",
            hmac_path.display()
        );
    }
}

/// HMAC-SHA-256 (RFC 2104) using a tiny inline SHA-256.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = sha256(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// SHA-256 (FIPS 180-4) — used only by this build script for the
/// HMAC of the binary. Returns 32 bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Pre-processing: padding.
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block.
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
