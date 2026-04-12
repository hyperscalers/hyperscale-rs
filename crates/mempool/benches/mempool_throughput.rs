//! Criterion benchmarks for mempool hot paths.
//!
//! Measures throughput for the three critical mempool operations:
//! - Transaction submission (RPC ingestion)
//! - Transaction gossip (network propagation)
//! - Ready transaction selection (block proposal)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hyperscale_mempool::MempoolState;
use hyperscale_types::{
    generate_bls_keypair, test_utils::test_transaction_with_nodes, NodeId, TopologySnapshot,
    ValidatorId, ValidatorInfo, ValidatorSet,
};
use std::sync::Arc;
use std::time::Duration;

fn make_topology() -> TopologySnapshot {
    let validators: Vec<_> = (0..4)
        .map(|i| ValidatorInfo {
            validator_id: ValidatorId(i),
            public_key: generate_bls_keypair().public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    TopologySnapshot::new(ValidatorId(0), 1, validator_set)
}

/// Create a unique transaction from an arbitrary index (no u8 limit).
fn make_tx(index: usize) -> Arc<hyperscale_types::RoutableTransaction> {
    let seed = index.to_le_bytes();
    let mut node_bytes = [0u8; 30];
    node_bytes[..seed.len()].copy_from_slice(&seed);
    let node = NodeId(node_bytes);
    Arc::new(test_transaction_with_nodes(&seed, vec![node], vec![]))
}

/// Pre-populate a mempool with `count` unique transactions.
fn prefilled_mempool(topology: &TopologySnapshot, count: usize) -> MempoolState {
    let mut mempool = MempoolState::new();
    for i in 0..count {
        mempool.on_submit_transaction(topology, make_tx(i));
    }
    mempool
}

// ═══════════════════════════════════════════════════════════════════════════
// Submit Transaction
// ═══════════════════════════════════════════════════════════════════════════

fn bench_submit_transaction(c: &mut Criterion) {
    let mut group = c.benchmark_group("submit_transaction");
    let topology = make_topology();

    for pool_size in [0, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let mempool = prefilled_mempool(&topology, size);
                        // Use an index that won't collide with prefilled transactions
                        let tx = make_tx(size + 100_000);
                        (mempool, tx)
                    },
                    |(mut mempool, tx)| {
                        black_box(mempool.on_submit_transaction(&topology, tx));
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction Gossip
// ═══════════════════════════════════════════════════════════════════════════

fn bench_transaction_gossip(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_gossip");
    let topology = make_topology();

    // New transaction via gossip (accepted)
    group.bench_function("new_transaction", |b| {
        b.iter_batched(
            || {
                let mempool = MempoolState::new();
                let tx = make_tx(1);
                (mempool, tx)
            },
            |(mut mempool, tx)| {
                black_box(mempool.on_transaction_gossip(&topology, tx, false));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Duplicate transaction via gossip (rejected by existing pool entry)
    group.bench_function("duplicate_rejection", |b| {
        b.iter_batched(
            || {
                let mut mempool = MempoolState::new();
                let tx = make_tx(1);
                mempool.on_submit_transaction(&topology, tx.clone());
                (mempool, tx)
            },
            |(mut mempool, tx)| {
                black_box(mempool.on_transaction_gossip(&topology, tx, false));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════
// Ready Transaction Selection
// ═══════════════════════════════════════════════════════════════════════════

fn bench_ready_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("ready_transactions");
    let topology = make_topology();

    for pool_size in [100, 1_000, 5_000] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &size| {
                let mempool = prefilled_mempool(&topology, size);
                b.iter(|| {
                    // Select up to 4096 transactions (typical block size)
                    black_box(mempool.ready_transactions(4096, 0, 0));
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_submit_transaction, bench_transaction_gossip, bench_ready_transactions
}
criterion_main!(benches);
