//! Benchmarks for batch updates (`build_fresh` + `update_existing`) and
//! multiproof prove/verify.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hyperscale_jmt::{Blake3Hasher, Key, MemoryStore, MultiProof, Tree, ValueHash};

type Jmt = Tree<Blake3Hasher>;

fn make_key(i: u32) -> Key {
    let mut k = [0u8; 32];
    k[0..4].copy_from_slice(&i.to_be_bytes());
    // Spread entropy across the path so buckets actually branch.
    let h = blake3::hash(&k);
    k.copy_from_slice(h.as_bytes());
    k
}

fn make_value(i: u32) -> ValueHash {
    let mut v = [0u8; 32];
    v[28..32].copy_from_slice(&i.to_be_bytes());
    v
}

fn build_store(n: u32) -> MemoryStore {
    let mut store = MemoryStore::new();
    let updates: BTreeMap<Key, Option<ValueHash>> =
        (0..n).map(|i| (make_key(i), Some(make_value(i)))).collect();
    let result = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
    store.apply(&result);
    store
}

fn bench_build_fresh(c: &mut Criterion) {
    let mut group = c.benchmark_group("build_fresh");
    for &n in &[1_000u32, 10_000, 100_000] {
        let updates: BTreeMap<Key, Option<ValueHash>> =
            (0..n).map(|i| (make_key(i), Some(make_value(i)))).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let store = MemoryStore::new();
                let r = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
                black_box(r.root_hash);
            });
        });
    }
    group.finish();
}

fn bench_update_existing(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_existing");
    for &n in &[10_000u32, 100_000] {
        let store = build_store(n);
        for &batch_n in &[100u32, 1_000, 10_000] {
            // Mix: half overwrites, half new keys.
            let updates: BTreeMap<Key, Option<ValueHash>> = (0..batch_n)
                .map(|i| {
                    let k = if i % 2 == 0 {
                        make_key(i % n)
                    } else {
                        make_key(n + i)
                    };
                    (k, Some(make_value(i.wrapping_add(7))))
                })
                .collect();
            group.bench_with_input(
                BenchmarkId::new(format!("tree_{n}"), batch_n),
                &batch_n,
                |b, _| {
                    b.iter(|| {
                        let r = Jmt::apply_updates(&store, Some(1), 2, &updates).unwrap();
                        black_box(r.root_hash);
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("prove");
    for &n in &[10_000u32, 100_000] {
        let store = build_store(n);
        let root_key = store.latest_root_key().unwrap();
        for &batch_n in &[1u32, 100, 1_000] {
            let keys: Vec<Key> = (0..batch_n)
                .map(|i| make_key(i * (n / batch_n.max(1))))
                .collect();
            group.bench_with_input(
                BenchmarkId::new(format!("tree_{n}"), batch_n),
                &batch_n,
                |b, _| {
                    b.iter(|| {
                        let p = Jmt::prove(&store, &root_key, &keys).unwrap();
                        black_box(p);
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    for &n in &[10_000u32, 100_000] {
        let store = build_store(n);
        let root_key = store.latest_root_key().unwrap();
        let root_hash = Jmt::root_hash_at(&store, 1).unwrap();
        for &batch_n in &[1u32, 100, 1_000] {
            let keys: Vec<Key> = (0..batch_n)
                .map(|i| make_key(i * (n / batch_n.max(1))))
                .collect();
            let proof: MultiProof = Jmt::prove(&store, &root_key, &keys).unwrap();
            let expected: Vec<(Key, Option<ValueHash>)> = keys
                .iter()
                .map(|k| (*k, Jmt::get(&store, &root_key, k)))
                .collect();
            group.bench_with_input(
                BenchmarkId::new(format!("tree_{n}"), batch_n),
                &batch_n,
                |b, _| {
                    b.iter(|| {
                        Jmt::verify(&proof, root_hash, &expected).unwrap();
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_build_fresh,
    bench_update_existing,
    bench_prove,
    bench_verify
);
criterion_main!(benches);
