//! What isolation costs a source on the proposer commit path: one block
//! of 4,096 transfers to one target, over a store of 2^20 leaves, proven
//! once as one bundle under one multiproof and once as one part per
//! transaction.
//!
//! The bundle reads each transaction's cells and proves every key under
//! one walk, the shape a source built before parts. The parts come from
//! the production builder, which reads, leaf-paths and proves each
//! transaction on its own. A part's walk shares no upper nodes with its
//! neighbours', so it pays the root-to-leaf descent once per key rather
//! than once per block. The bound accepted for that is at most 2× the
//! bundle's time.
//!
//! `proofs_only` times the proof walks alone, the same keys either way,
//! so the builder's other work can be read off the difference.
//!
//! Filter to one case with e.g.
//! `cargo bench -p hyperscale-storage-rocksdb --bench proof_cost per_part`.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use hyperscale_core::ProvisionsRequest;
use hyperscale_jmt::NibblePath;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateView, Substates};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    Address, AddressClass, BlockHeight, Hash, LocalKey, SettledWrites, ShardId, SubstateKey,
    TxHash, WeightedTimestamp,
};
use tempfile::TempDir;

/// Leaves in the source's tree.
const LEAVES: u32 = 1 << 20;
/// Transfers in the source block, each reading one cell, all owed to
/// one target: a full block.
const TRANSFERS: u32 = 4_096;
/// Raw value bytes per cell, the order of a vault balance.
const VALUE_BYTES: usize = 32;

const SOURCE: ShardId = ShardId::ROOT;
const TARGET: ShardId = ShardId::leaf(1, 1);

/// The `index`th cell of the source, under an owner spread over the key
/// space as hashed addresses are.
fn cell(index: u32) -> SubstateKey {
    let digest = Hash::from_bytes(&index.to_be_bytes());
    let mut body = [0u8; 31];
    body.copy_from_slice(&digest.as_bytes()[..31]);
    SubstateKey {
        owner: Address::new(body, AddressClass::Principal),
        local: LocalKey([0u8; 16]),
    }
}

/// A store of [`LEAVES`] cells at genesis, and the view a proposer reads
/// it through.
fn stocked(dir: &TempDir) -> Arc<SubstateView<RocksDbShardStorage>> {
    let storage = RocksDbShardStorage::open(dir.path(), NibblePath::empty()).expect("open store");
    let cells: BTreeMap<SubstateKey, Option<Vec<u8>>> = (0..LEAVES)
        .map(|index| {
            let mut value = vec![0u8; VALUE_BYTES];
            value[..4].copy_from_slice(&index.to_be_bytes());
            (cell(index), Some(value))
        })
        .collect();
    let seeded = SettledWrites::from_parts(cells, BTreeMap::new());
    storage.install_genesis(&seeded, &seeded);
    Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS)).view_at_persisted_tip()
}

/// One request per transfer, each reading one cell, every 256th of the
/// store so the block reads across the whole tree.
fn transfers() -> Vec<ProvisionsRequest> {
    let stride = LEAVES / TRANSFERS;
    (0..TRANSFERS)
        .map(|t| ProvisionsRequest {
            tx_hash: TxHash::from(Hash::from_bytes(&t.to_be_bytes())),
            targets: vec![TARGET],
            local_keys: vec![cell(t * stride)],
            local_ranges: vec![],
        })
        .collect()
}

/// The bundle: every transaction's cells read, then one proof over all
/// their keys, answering the proof's length.
fn bundle(view: &SubstateView<RocksDbShardStorage>, requests: &[ProvisionsRequest]) -> usize {
    let state = view.served_snapshot().expect("genesis is held");
    let mut keys = Vec::with_capacity(requests.len());
    let mut values = Vec::with_capacity(requests.len());
    for request in requests {
        for &key in &request.local_keys {
            values.push(state.cell(key));
            keys.push(key);
        }
    }
    let proof = generate_proof(view, &keys, BlockHeight::GENESIS).expect("the bundle proof builds");
    black_box(values);
    proof.as_bytes().len()
}

/// The bundle's build against the production builder's parts.
fn bench_builders(
    c: &mut Criterion,
    view: &SubstateView<RocksDbShardStorage>,
    requests: &[ProvisionsRequest],
) {
    let ts = WeightedTimestamp::from_millis(0);
    let mut group = c.benchmark_group("proof_cost");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(40));
    group.bench_function("one_multiproof", |b| {
        b.iter(|| black_box(bundle(view, requests)));
    });
    group.bench_function("per_part", |b| {
        b.iter(|| {
            let parts = build_provisions(view, SOURCE, TARGET, ts, requests, |_| true);
            assert_eq!(parts.len(), requests.len());
            black_box(parts)
        });
    });
    group.finish();
}

/// One proof walk over `keys` against one walk per key.
fn bench_proofs(c: &mut Criterion, view: &SubstateView<RocksDbShardStorage>, keys: &[SubstateKey]) {
    let mut group = c.benchmark_group("proofs_only");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(40));
    group.bench_function("one_multiproof", |b| {
        b.iter(|| black_box(generate_proof(view, keys, BlockHeight::GENESIS)));
    });
    group.bench_function("per_part", |b| {
        b.iter(|| {
            for key in keys {
                black_box(generate_proof(
                    view,
                    std::slice::from_ref(key),
                    BlockHeight::GENESIS,
                ));
            }
        });
    });
    group.finish();
}

fn bench_proof_cost(c: &mut Criterion) {
    let dir = TempDir::new().expect("temp dir");
    let view = stocked(&dir);
    let requests = transfers();
    let keys: Vec<SubstateKey> = requests
        .iter()
        .flat_map(|request| request.local_keys.iter().copied())
        .collect();
    bench_builders(c, &view, &requests);
    bench_proofs(c, &view, &keys);
}

criterion_group!(benches, bench_proof_cost);
criterion_main!(benches);
