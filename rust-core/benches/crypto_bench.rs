//! Performance benchmarks for Soteria's cryptographic operations.
//!
//! Run with: `cargo bench --bench crypto_bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use soteria_core::crypto_engine::aead::CryptoEngine;
use soteria_core::crypto_engine::block::BlockCrypto;
use soteria_core::crypto_engine::kdf::{derive_volume_key, KdfParams};
use soteria_core::crypto_engine::AeadAlgorithm;

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    let sizes = [1024, 4096, 16384, 65536, 262144]; // 1K to 256K

    for size in sizes {
        let plaintext = vec![0xABu8; size];
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 24];
        let engine = CryptoEngine::new(AeadAlgorithm::XChaCha20Poly1305, key);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            format!("xchacha20-encrypt-{}", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    engine.encrypt(black_box(pt), &nonce, b"aad").unwrap();
                });
            },
        );

        let ciphertext = engine.encrypt(&plaintext, &nonce, b"aad").unwrap();
        group.bench_with_input(
            format!("xchacha20-decrypt-{}", size),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    engine.decrypt(black_box(ct), &nonce, b"aad").unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");
    group.sample_size(10); // KDF is slow

    let passphrase = b"correct horse battery staple";
    let salt = [0x01u8; 16];

    group.bench_function("argon2id-fast-test", |b| {
        let params = KdfParams::fast_test();
        b.iter(|| {
            derive_volume_key(black_box(passphrase), &salt, &params).unwrap();
        });
    });

    group.finish();
}

fn bench_block_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_crypto");

    let key = [0x42u8; 32];
    let crypto = BlockCrypto::new(AeadAlgorithm::XChaCha20Poly1305, key);

    let sizes = [4096, 16384, 65536];

    for size in sizes {
        let plaintext = vec![0xABu8; size];
        let lineage_prev = [0x00u8; 32];
        let block_index = 0u64;

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("encrypt-block-{}", size), &plaintext, |b, pt| {
            b.iter(|| {
                crypto
                    .encrypt_block(black_box(pt), block_index, &lineage_prev)
                    .unwrap();
            });
        });

        let encrypted = crypto
            .encrypt_block(&plaintext, block_index, &lineage_prev)
            .unwrap();
        group.bench_with_input(format!("decrypt-block-{}", size), &encrypted, |b, ct| {
            b.iter(|| {
                crypto
                    .decrypt_block(black_box(ct), block_index, &lineage_prev)
                    .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    let sizes = [1024, 4096, 16384, 65536, 262144, 1048576]; // 1K to 1M

    for size in sizes {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("hash-{}", size), &data, |b, d| {
            b.iter(|| {
                blake3::hash(black_box(d));
            });
        });
    }

    group.finish();
}

fn bench_ml_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_kem_768");
    group.sample_size(50);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::pq::generate_keypair();
        });
    });

    let kp = soteria_core::crypto_engine::pq::generate_keypair();
    let data = [0x42u8; 32];

    group.bench_function("wrap", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::pq::wrap_key(black_box(&data), &kp.public).unwrap();
        });
    });

    let envelope = soteria_core::crypto_engine::pq::wrap_key(&data, &kp.public).unwrap();

    group.bench_function("unwrap", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::pq::unwrap_key(black_box(&envelope), &kp.secret).unwrap();
        });
    });

    group.finish();
}

fn bench_ml_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_65");
    group.sample_size(50);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::dsa::generate_keypair();
        });
    });

    let kp = soteria_core::crypto_engine::dsa::generate_keypair();
    let message = b"soteria:benchmark:message:v1";

    group.bench_function("sign", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::dsa::sign(black_box(message), &kp.secret).unwrap();
        });
    });

    let signature = soteria_core::crypto_engine::dsa::sign(message, &kp.secret).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            soteria_core::crypto_engine::dsa::verify(
                black_box(message),
                black_box(&signature),
                &kp.public,
            )
            .unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_aead,
    bench_kdf,
    bench_block_crypto,
    bench_blake3,
    bench_ml_kem,
    bench_ml_dsa
);
criterion_main!(benches);
