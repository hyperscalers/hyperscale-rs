//! Snap-sync import throughput: stage → finalize over generated leaves.
//!
//! Measures the full boundary-import write path — chunked staging into
//! the staging CF, then the batched JMT finalize — into a fresh store
//! per iteration, reporting value-byte throughput (leaves/s follows
//! from the fixed leaf size in each benchmark id). The numbers feed the
//! production `split_bytes` choice: how much state a shard can carry
//! before a joiner's import outruns its ready budget.
//!
//! The 10M-leaf case runs minutes per iteration; filter to the size you
//! want, e.g. `cargo bench -p hyperscale-storage-rocksdb 1m_leaves`.

use std::hint::black_box;

use blake3::hash as blake3_hash;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperscale_jmt::NibblePath;
use hyperscale_storage::test_helpers::completed_import_progress;
use hyperscale_storage::{BoundaryStore, ImportLeaf, WitnessSeed};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{BlockHeight, StateRoot};
use tempfile::TempDir;

/// Raw value bytes per generated leaf.
const VALUE_BYTES: usize = 128;

/// Raw storage-key bytes per generated leaf.
const KEY_BYTES: usize = 40;

/// Leaves per `stage_import_chunk` call — the order of a wire chunk.
const CHUNK_LEAVES: usize = 4_096;

/// The boundary height finalize installs; deep enough that the batch
/// count never has to grow to fit the version chain.
const HEIGHT: BlockHeight = BlockHeight::new(1_000);

/// One deterministic generated leaf. Keys are hashed from the index so
/// paths spread uniformly, exactly like real `jmt_leaf_key` output.
fn leaf(index: u64) -> ImportLeaf {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    let key = *blake3_hash(&seed).as_bytes();
    let mut storage_key = vec![0u8; KEY_BYTES];
    storage_key[..32].copy_from_slice(&key);
    storage_key[32..40].copy_from_slice(&index.to_be_bytes());
    ImportLeaf {
        leaf_key: key,
        storage_key,
        value: seed.repeat(VALUE_BYTES / 32),
    }
}

/// Stage `total` generated leaves in wire-sized chunks and finalize,
/// returning the imported root.
fn import(total: u64) -> StateRoot {
    let dir = TempDir::new().expect("temp dir");
    let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).expect("open store");
    let progress = completed_import_progress(HEIGHT, total * VALUE_BYTES as u64);
    let mut chunk = Vec::with_capacity(CHUNK_LEAVES);
    for index in 0..total {
        chunk.push(leaf(index));
        if chunk.len() == CHUNK_LEAVES {
            storage
                .stage_import_chunk(&progress, &chunk)
                .expect("stage chunk");
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        storage
            .stage_import_chunk(&progress, &chunk)
            .expect("stage chunk");
    }
    storage
        .finalize_boundary_import(HEIGHT, WitnessSeed::default())
        .expect("finalize")
}

fn bench_import(c: &mut Criterion) {
    let mut group = c.benchmark_group("snap_sync_import");
    group.sample_size(10);
    for (label, total) in [("1m_leaves", 1_000_000u64), ("10m_leaves", 10_000_000)] {
        group.throughput(Throughput::Bytes(total * VALUE_BYTES as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &total, |b, &total| {
            b.iter(|| black_box(import(total)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_import);
criterion_main!(benches);
