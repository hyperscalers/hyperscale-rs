//! Range-read throughput: what a declared scan actually costs off disk.
//!
//! The block read cap is derived in the fee plan from an assumed
//! sustained read rate, and a declared range is the shape that spends
//! it: `(cap + 1) × width` bytes prepaid per interval, walked as one
//! contiguous scan. This measures that walk on a real store, at the tip
//! and off it, so the assumption has a measurement beside it.
//!
//! Off the tip is the case worth measuring separately: the historical
//! walk advances the current and history iterators in lockstep and
//! applies each version's override, so it pays for the versions between
//! the anchor and the tip rather than reading the tip's values.
//!
//! Filter to one case with e.g.
//! `cargo bench -p hyperscale-storage-rocksdb at_the_tip`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperscale_jmt::NibblePath;
use hyperscale_storage::test_helpers::{commit_writes, entry_key, make_settled_entries};
use hyperscale_storage::{SubstateStore, Substates, VersionedStore};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::BlockHeight;
use tempfile::TempDir;

/// Raw value bytes per entry — the order of a vault or a book level,
/// and the figure the throughput below is reported in.
const VALUE_BYTES: usize = 128;

/// The owner every entry is written under.
const OWNER: u8 = 0x11;

/// Entries per commit, so a store of `total` entries takes a bounded
/// number of versions to build.
const PER_COMMIT: usize = 4_096;

/// One store holding `total` entries in one collection, and the height
/// its last write landed at.
fn stocked(dir: &TempDir, total: u128) -> (RocksDbShardStorage, BlockHeight) {
    let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).expect("open store");
    let mut order = 0u128;
    while order < total {
        let batch: Vec<(u128, Option<Vec<u8>>)> = (order..(order + PER_COMMIT as u128).min(total))
            .map(|index| (index, Some(vec![0xAB; VALUE_BYTES])))
            .collect();
        order += batch.len() as u128;
        commit_writes(&storage, &make_settled_entries(OWNER, &batch));
    }
    let tip = storage.jmt_height();
    (storage, tip)
}

/// Read `limit` entries of the collection, at the tip or at `anchor`.
fn scan(storage: &RocksDbShardStorage, anchor: Option<BlockHeight>, limit: usize) -> usize {
    let key = entry_key(OWNER, 0);
    let read = |snapshot: &dyn Substates| {
        snapshot
            .entries_in_range(key.owner, key.collection, 0, u128::MAX, limit)
            .len()
    };
    anchor.map_or_else(
        || read(&storage.snapshot()),
        |height| read(&storage.snapshot_at(height)),
    )
}

fn bench_range_read(c: &mut Criterion) {
    // Enough entries that the scan is the cost rather than the seek,
    // and enough versions behind the tip that the historical walk has
    // history to advance through.
    const TOTAL: u128 = 65_536;
    const LIMIT: usize = 4_096;

    let dir = TempDir::new().expect("temp dir");
    let (storage, tip) = stocked(&dir, TOTAL);
    // Half the versions back, so the walk carries real overrides rather
    // than degenerating to the tip's fast path.
    let behind = BlockHeight::new(tip.inner() / 2);

    let mut group = c.benchmark_group("range_read");
    group.throughput(Throughput::Bytes((LIMIT * VALUE_BYTES) as u64));
    group.bench_with_input(
        BenchmarkId::from_parameter("at_the_tip"),
        &LIMIT,
        |b, &n| {
            b.iter(|| black_box(scan(&storage, None, n)));
        },
    );
    group.bench_with_input(
        BenchmarkId::from_parameter("off_the_tip"),
        &LIMIT,
        |b, &n| {
            b.iter(|| black_box(scan(&storage, Some(behind), n)));
        },
    );
    group.finish();
}

criterion_group!(benches, bench_range_read);
criterion_main!(benches);
