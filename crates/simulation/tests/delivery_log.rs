//! The transport's delivery log: what a record says, and that recording one
//! changes nothing about the run it describes.
//!
//! The log exists for harnesses that observe traffic rather than chain
//! content, which makes both halves load-bearing. A record has to mean what
//! it claims — the sending type's class, the instants the message left and
//! landed — and switching the log on has to leave the simulation it is
//! watching byte-identical, or an observer would be reporting a run that only
//! happens while it watches.

mod support;

use std::time::Duration;

use hyperscale_network_memory::DeliveryDrain;
use hyperscale_scenarios::{ScenarioConfig, grow_to};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::network::notification::BlockHeaderNotification;
use hyperscale_types::{BlockHeight, MessageClass, NetworkMessage, ShardId};
use support::SimCluster;

/// Base inter-host latency. Both the intra-shard and cross-shard legs are
/// configured from this one value, so every delivery in the run draws against
/// the same band.
const LATENCY: Duration = Duration::from_millis(150);

/// Jitter as `SimConfig` defaults it, which `SimCluster` does not override.
const JITTER_FRACTION: f64 = 0.1;

/// Single-shard genesis with the split trigger armed and one cohort of pool
/// surplus — the shape [`grow_to`] drives to two shards.
const CONFIG: ScenarioConfig = ScenarioConfig {
    shard_size: 4,
    vnodes_per_host: 1,
    pool_surplus: 4,
    num_shards: 1,
    split_bytes: 0,
    latency: LATENCY,
};

/// Enough of a run's observable surface to catch the log perturbing it:
/// counts driven by the event loop, plus where each committee actually got to.
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    events_processed: u64,
    messages_sent: u64,
    timers_set: u64,
    actions_generated: u64,
    heights: Vec<BlockHeight>,
}

fn fingerprint(runner: &SimulationRunner) -> Fingerprint {
    let stats = runner.stats();
    Fingerprint {
        events_processed: stats.events_processed,
        messages_sent: stats.messages_sent,
        timers_set: stats.timers_set,
        actions_generated: stats.actions_generated,
        heights: [ShardId::leaf(1, 0), ShardId::leaf(1, 1)]
            .iter()
            .flat_map(|&leaf| {
                runner
                    .shard_replicas(leaf)
                    .into_iter()
                    .map(|v| v.shard_coordinator().committed_height())
                    .collect::<Vec<_>>()
            })
            .collect(),
    }
}

/// Grow a single-shard genesis to two shards with the log at `capacity`,
/// returning the run's fingerprint and everything the log kept.
///
/// The grow is the traffic: it drives consensus on three committees, the
/// beacon that schedules the split, and the catch-up the children seed
/// through, so every class the run is capable of producing appears without
/// the test staging any of it.
fn run(seed: u64, capacity: usize) -> (Fingerprint, DeliveryDrain) {
    let mut cluster = SimCluster::new(&CONFIG, seed);
    cluster.runner_mut().enable_delivery_log(capacity);
    grow_to(&mut cluster, 2);
    let drain = cluster.runner_mut().drain_deliveries();
    (fingerprint(cluster.runner()), drain)
}

/// A record carries the class its *sending type* declares, not a default.
///
/// The class never reaches the wire — it is a static property of the Rust
/// type — so it is threaded from the send site onto the queued message. If
/// that threading broke, every record would still have *a* class and the log
/// would look healthy while reporting the trait default for everything. The
/// guard is a type whose class is known and is not that default: a block
/// header is `Consensus`, and `Recovery` is what a type gets by declaring
/// nothing.
#[test]
fn a_record_carries_the_class_of_the_type_that_sent_it() {
    let (_, drain) = run(9001, 8192);

    let headers: Vec<_> = drain
        .records
        .iter()
        .filter(|r| r.message_type == BlockHeaderNotification::message_type_id())
        .collect();
    assert!(
        !headers.is_empty(),
        "a run that commits blocks must have delivered block headers; \
         saw {} records across {} types",
        drain.records.len(),
        drain
            .records
            .iter()
            .map(|r| r.message_type)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
    );
    for record in &headers {
        assert_eq!(
            record.class,
            MessageClass::Consensus,
            "block headers are Consensus; {} carried {:?}",
            record.message_type,
            record.class,
        );
    }
    assert_ne!(
        MessageClass::Consensus,
        MessageClass::Recovery,
        "the guard is only meaningful while Consensus differs from the default",
    );
}

/// A record's two instants bracket exactly the latency the transport drew for
/// it, so the difference is flight time rather than anything the harness
/// stamped after the fact.
#[test]
fn a_record_spans_the_latency_the_transport_drew() {
    let (_, drain) = run(9002, 8192);
    assert!(!drain.records.is_empty(), "the run delivered nothing");

    let low = LATENCY.mul_f64(1.0 - JITTER_FRACTION);
    let high = LATENCY.mul_f64(1.0 + JITTER_FRACTION);
    for record in &drain.records {
        let flight = record
            .delivered_at
            .checked_sub(record.sent_at)
            .expect("a delivery lands no earlier than it was sent");
        assert!(
            flight >= low && flight <= high,
            "{} flew {flight:?}, outside the configured band {low:?}..={high:?}",
            record.message_type,
        );
    }
}

/// Capacity bounds the records kept, never the counts.
///
/// This is the split a viewer depends on: it can animate a sample of what
/// crossed the network while still reporting true volume, and it can say how
/// much it is not showing.
#[test]
fn capacity_bounds_the_records_but_not_the_totals() {
    const CAPACITY: usize = 16;
    let (_, sampled) = run(9003, CAPACITY);
    let (_, whole) = run(9003, usize::MAX);

    assert_eq!(
        sampled.records.len(),
        CAPACITY,
        "a run this size fills the capacity",
    );
    assert!(
        sampled.dropped > 0,
        "and reports what the capacity forced out",
    );

    let counted = |drain: &DeliveryDrain| -> u64 {
        drain.by_class.iter().map(|tally| tally.deliveries).sum()
    };
    assert_eq!(
        counted(&sampled),
        sampled.records.len() as u64 + sampled.dropped,
        "every delivery is either kept or counted as dropped",
    );
    assert_eq!(
        counted(&sampled),
        counted(&whole),
        "the totals do not depend on how many records were kept",
    );
    assert_eq!(
        sampled.by_class, whole.by_class,
        "nor do the per-class totals",
    );
}

/// Recording is pure observation: the same seed produces the same run whether
/// the log is on or off.
///
/// Without this the log would be a Heisenberg instrument — an observer would
/// report a run that only happens while something is watching, and every
/// seeded reproduction command the viewer prints would be a lie.
#[test]
fn recording_does_not_perturb_the_run() {
    let (unobserved, empty) = run(9004, 0);
    let (observed, drain) = run(9004, usize::MAX);

    assert!(
        empty.records.is_empty() && empty.dropped == 0,
        "capacity zero records nothing",
    );
    assert!(
        !drain.records.is_empty(),
        "the comparison is vacuous unless the observed run recorded something",
    );
    assert_eq!(
        unobserved, observed,
        "a seeded run is identical whether or not the delivery log is on",
    );
}
