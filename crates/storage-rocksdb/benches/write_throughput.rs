//! Settled-write cost: what a block's writes actually charge the store.
//!
//! The block write cap is derived in the fee plan from an assumed
//! sustained write rate, and that rate is the one input of the four with
//! no measurement beside it — the read side has
//! [`range_read`](range_read.rs), and this is its counterpart. A
//! declared write is priced at `cap × width`, so what a declaration buys
//! is this path: the leaf, the internal nodes the update dirties, and
//! the version the commit persists.
//!
//! Three groups, because a rate in bytes per second is only a rate if
//! the cost is in bytes:
//!
//! - `write_throughput` sweeps the batch at a fixed width. A commit
//!   carries a block, a certificate and a root recomputation whatever it
//!   writes, and a per-byte cap derived from a measurement dominated by
//!   that fixed half would be a cap on commits wearing a byte's units.
//!   The fixed part would show as throughput climbing with the batch.
//! - `write_per_leaf` holds the leaf count and grows the value. This is
//!   the discriminating one: if a byte is what costs, time tracks the
//!   width; if the leaf is, time holds flat while the reported
//!   throughput climbs in proportion to a width that bought nothing.
//! - `write_throughput_deep` runs one batch into a tree an order of
//!   magnitude larger, for whether a write costs more as state grows.
//!
//! Overwrites rather than appends, so the tree the measurement runs
//! against holds still: the leaf count is fixed by the stocking and only
//! values change, which is both the repeatable shape and a real one —
//! vault balances and book levels are written far more often than they
//! are created.
//!
//! Filter to one group with e.g.
//! `cargo bench -p hyperscale-storage-rocksdb --bench write_throughput -- write_per_leaf`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hyperscale_jmt::NibblePath;
use hyperscale_storage::test_helpers::{commit_writes, make_settled_entries};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use tempfile::TempDir;

/// Raw value bytes per entry, matching `range_read` so the two
/// throughputs are the same quantity.
const VALUE_BYTES: usize = 128;

/// The owner every entry is written under.
const OWNER: u8 = 0x11;

/// Entries per commit while stocking, bounding the versions a build
/// takes.
const PER_COMMIT: usize = 4_096;

/// Entries overwritten per measured commit: 512 KiB of values against a
/// 4 MiB block write cap, so the batch is a realistic block's worth
/// rather than the cap's.
const BATCH: usize = 4_096;

/// One store holding `total` entries in one collection.
fn stocked(dir: &TempDir, total: u128) -> RocksDbShardStorage {
    let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).expect("open store");
    let mut order = 0u128;
    while order < total {
        let batch: Vec<(u128, Option<Vec<u8>>)> = (order..(order + PER_COMMIT as u128).min(total))
            .map(|index| (index, Some(vec![0xAB; VALUE_BYTES])))
            .collect();
        order += batch.len() as u128;
        commit_writes(&storage, &make_settled_entries(OWNER, &batch));
    }
    storage
}

/// Commit one block's worth of overwrites over the first `entries`
/// orders at `width` bytes each, filled with `fill` so successive
/// commits carry real changes rather than identical bytes.
fn overwrite(storage: &RocksDbShardStorage, entries: usize, width: usize, fill: u8) -> usize {
    let batch: Vec<(u128, Option<Vec<u8>>)> = (0..entries as u128)
        .map(|order| (order, Some(vec![fill; width])))
        .collect();
    commit_writes(storage, &make_settled_entries(OWNER, &batch));
    entries * width
}

fn bench_write_throughput(c: &mut Criterion) {
    const TREE: u128 = 65_536;
    // A sweep rather than one figure, because a rate in bytes per second
    // is only a rate if it is one: a commit carries a block, a
    // certificate and a root recomputation whatever it writes, and a
    // per-byte cap derived from a measurement dominated by that fixed
    // half would be a cap on commits wearing a byte's units. Across two
    // orders of magnitude the fixed part shows as throughput climbing
    // with the batch.
    const BATCHES: [usize; 4] = [256, 1_024, 4_096, 16_384];

    let dir = TempDir::new().expect("temp dir");
    let storage = stocked(&dir, TREE);
    {
        let mut group = c.benchmark_group("write_throughput");
        group.sample_size(20);
        for batch in BATCHES {
            group.throughput(Throughput::Bytes((batch * VALUE_BYTES) as u64));
            let mut fill = 0u8;
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("batch_{batch}")),
                &batch,
                |b, &n| {
                    b.iter(|| {
                        fill = fill.wrapping_add(1);
                        black_box(overwrite(&storage, n, VALUE_BYTES, fill));
                    });
                },
            );
        }
        group.finish();
    }

    // The decisive one: hold the leaf count and grow the value. If a
    // byte is what costs, time tracks the width; if the leaf is, time
    // holds flat and a cap denominated in bytes is measuring the wrong
    // quantity.
    {
        let mut group = c.benchmark_group("write_per_leaf");
        group.sample_size(20);
        for width in [32usize, 128, 512, 2_048] {
            group.throughput(Throughput::Bytes((BATCH * width) as u64));
            let mut fill = 0u8;
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("width_{width}")),
                &width,
                |b, &w| {
                    b.iter(|| {
                        fill = fill.wrapping_add(1);
                        black_box(overwrite(&storage, BATCH, w, fill));
                    });
                },
            );
        }
        group.finish();
    }

    // And the same batch into a tree an order of magnitude larger: what
    // the cap needs beyond a rate is whether a byte costs more as the
    // state it lands in grows.
    let deep_dir = TempDir::new().expect("temp dir");
    let deep = stocked(&deep_dir, 524_288);
    let mut group = c.benchmark_group("write_throughput_deep");
    group.throughput(Throughput::Bytes((BATCH * VALUE_BYTES) as u64));
    group.sample_size(20);
    let mut fill = 0u8;
    group.bench_with_input(
        BenchmarkId::from_parameter("batch_4096_into_524288_leaves"),
        &BATCH,
        |b, &n| {
            b.iter(|| {
                fill = fill.wrapping_add(1);
                black_box(overwrite(&deep, n, VALUE_BYTES, fill));
            });
        },
    );
    group.finish();
}

criterion_group!(benches, bench_write_throughput);
criterion_main!(benches);
