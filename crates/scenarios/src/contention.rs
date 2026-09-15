//! Contention scenarios: the baseline load shapes the admission A/B
//! measures — recipient-skewed payments, one saturated hot component, a
//! cross-shard traffic mix, and participant-count scaling.
//!
//! Every scenario is deterministic (seeded sampling, fixed account sets)
//! and budgeted in epochs, and returns its chain-derived observables as a
//! report. Assertions cover correctness — every payment accepts — and how
//! tightly contended work packs into blocks; the numbers are the phase
//! record's baseline.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{PrincipalAddr, ShardId, TransactionDecision, TransactionStatus, TxHash};

use crate::reshape::split_lifecycle;
use crate::support::conservation::{Charges, World};
use crate::support::tx::{
    accounts_routing_to, build_fan_out_tx, build_transfer_tx, participant_sweep_accounts,
    validity_around,
};
use crate::support::{Budget, Cluster, epochs, grow_to};

/// The amount every contention payment moves.
const PAYMENT: u32 = 5;

/// Chain-derived observables of one contention run.
#[derive(Clone, Debug)]
pub struct ContentionReport {
    /// Payments submitted (all asserted `Accept`).
    pub(crate) submitted: usize,
    /// First submission to last observed terminal, on the cluster clock.
    pub elapsed: Duration,
    /// Median submit-to-terminal latency, at the run-until poll
    /// granularity.
    pub(crate) latency_p50: Duration,
    /// 95th-percentile submit-to-terminal latency.
    pub latency_p95: Duration,
}

/// Deterministic 64-bit LCG (Knuth's MMIX constants) for seeded sampling.
pub struct Lcg(pub u64);

impl Lcg {
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    #[allow(clippy::cast_precision_loss)] // uniform draw; 53 bits is the point
    pub(crate) fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// The cumulative Zipf distribution over ranks `1..=n` at exponent
/// `skew`.
#[allow(clippy::cast_precision_loss)] // ranks are tiny
pub fn zipf_cdf(n: usize, skew: f64) -> Vec<f64> {
    let weights: Vec<f64> = (1..=n).map(|rank| 1.0 / (rank as f64).powf(skew)).collect();
    let total: f64 = weights.iter().sum();
    let mut acc = 0.0;
    weights
        .iter()
        .map(|weight| {
            acc += weight / total;
            acc
        })
        .collect()
}

/// Drive the cluster until every hash is terminal, recording each
/// first-observed terminal time at the predicate's poll granularity, then
/// assert every payment accepted and fold the observables into a report.
pub fn settle_and_report(
    c: &mut impl Cluster,
    submissions: &[(TxHash, Duration)],
    budget: Budget,
) -> ContentionReport {
    let report = settle_terminal(c, submissions, budget);
    for (index, (hash, _)) in submissions.iter().enumerate() {
        let status = c.tx_status(*hash);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "contention payment #{index} ({hash:?}) did not accept; status = {status:?}",
        );
    }
    report
}

/// [`settle_and_report`] without the accept assertion — for probes whose
/// observables are entirely admission-side and whose synthetic manifests
/// reject at execution.
fn settle_terminal(
    c: &mut impl Cluster,
    submissions: &[(TxHash, Duration)],
    budget: Budget,
) -> ContentionReport {
    let completed_at = RefCell::new(BTreeMap::<TxHash, Duration>::new());
    let all_terminal = c.run_until(budget, |c| {
        let mut completed_at = completed_at.borrow_mut();
        for (hash, _) in submissions {
            if !completed_at.contains_key(hash)
                && matches!(c.tx_status(*hash), Some(TransactionStatus::Completed(_)))
            {
                completed_at.insert(*hash, c.now());
            }
        }
        completed_at.len() == submissions.len()
    });
    assert!(
        all_terminal,
        "contention payments did not all settle within budget; statuses: {:?}",
        {
            let mut statuses: BTreeMap<TxHash, Option<TransactionStatus>> = BTreeMap::new();
            for (hash, _) in submissions {
                statuses.insert(*hash, c.tx_status(*hash));
            }
            statuses
        }
    );

    let completed_at = completed_at.into_inner();
    let mut latencies: Vec<Duration> = submissions
        .iter()
        .map(|(hash, submitted)| completed_at[hash].saturating_sub(*submitted))
        .collect();
    latencies.sort_unstable();
    let percentile = |p: usize| latencies[(latencies.len() - 1) * p / 100];
    let first_submit = submissions
        .iter()
        .map(|(_, at)| *at)
        .min()
        .unwrap_or_default();
    let last_terminal = completed_at.values().max().copied().unwrap_or_default();
    ContentionReport {
        submitted: submissions.len(),
        elapsed: last_terminal.saturating_sub(first_submit),
        latency_p50: percentile(50),
        latency_p95: percentile(95),
    }
}

/// Fixed load at a varying cross-shard share.
///
/// Grows the root into two shards, then submits `total` payments from
/// left-shard senders, `cross_permille`/1000 of them to right-shard
/// recipients and the rest to left-shard recipients.
///
/// # Panics
///
/// Panics if the grow or any payment misses its budget or does not
/// accept.
pub fn cross_shard_fraction(
    c: &mut impl Cluster,
    total: usize,
    cross_permille: u32,
) -> ContentionReport {
    split_lifecycle(c);
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));

    // The same taken-walk as `cross_fraction_genesis_accounts`, so the
    // senders are exactly the genesis-funded accounts.
    let mut taken = Vec::new();
    let senders = accounts_routing_to(left, 2, total, &mut taken);
    let cross_count = total * cross_permille as usize / 1000;
    let local_recipients = accounts_routing_to(left, 2, total, &mut taken);
    let cross_recipients = accounts_routing_to(right, 2, total, &mut taken);

    let recipients: Vec<PrincipalAddr> = cross_recipients
        .iter()
        .take(cross_count)
        .chain(local_recipients.iter().take(total - cross_count))
        .map(|(_, account)| *account)
        .collect();
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        senders
            .iter()
            .map(|(_, account)| account.address())
            .chain(recipients.iter().map(|account| account.address())),
        [],
    );
    let mut charges = Charges::default();
    let mut submissions = Vec::with_capacity(total);
    for ((payer, from), to) in senders.iter().zip(recipients) {
        let tx = build_transfer_tx(
            payer,
            *from,
            to,
            u128::from(PAYMENT),
            validity_around(c.now()),
        );
        submissions.push((tx.hash(), c.now()));
        charges.submit(c, tx);
    }
    let report = settle_and_report(c, &submissions, epochs(12));
    world.assert_settles_within(c, &charges, epochs(8), "a cross-shard mix of payments");
    report
}

/// Cross-shard fan-outs at `2..=max_participants` participating shards.
///
/// Grows the cluster to `num_shards` leaves, then one funded sender on
/// the first leaf pays one recipient on each of `p - 1` other leaves, one
/// fan-out at a time, and the submit-to-terminal latency is measured per
/// participant count.
///
/// The harness funds the first leaf's first seeded account at genesis.
///
/// # Panics
///
/// Panics if `max_participants` exceeds `num_shards`, the grow misses its
/// budget, or any fan-out misses its budget or does not accept.
pub fn participant_count_sweep(
    c: &mut impl Cluster,
    num_shards: u64,
    max_participants: u32,
) -> Vec<(u32, Duration)> {
    assert!(
        u64::from(max_participants) <= num_shards,
        "a fan-out cannot touch more shards than the topology has",
    );
    grow_to(c, u32::try_from(num_shards).expect("shard count fits"));
    // The same walk `participant_sweep_accounts` funds: the payer on
    // the first leaf, then one payee per leaf in leaf order.
    let accounts = participant_sweep_accounts(num_shards);
    let (payer, from) = (&accounts[0].0, accounts[0].1);
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        accounts.iter().map(|(_, account)| account.address()),
        [],
    );
    let mut charges = Charges::default();

    let mut latencies = Vec::new();
    for participants in 2..=max_participants {
        let recipients: Vec<PrincipalAddr> = (1..participants)
            .map(|leaf| accounts[1 + leaf as usize].1)
            .collect();
        let tx = build_fan_out_tx(
            payer,
            from,
            &recipients,
            u128::from(PAYMENT),
            validity_around(c.now()),
        );
        let submissions = [(tx.hash(), c.now())];
        charges.submit(c, tx);
        let report = settle_and_report(c, &submissions, epochs(10));
        latencies.push((participants, report.latency_p50));
    }
    world.assert_settles_within(c, &charges, epochs(8), "a sweep of fan-outs");
    latencies
}
