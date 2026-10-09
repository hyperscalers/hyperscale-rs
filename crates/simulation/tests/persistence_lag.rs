//! A replica whose disk trails its commits executes what the others do.
//!
//! A commit reaches execution before its write is acknowledged, so with
//! a slow disk the replicas of one shard run the same tick at different
//! persistence depths. A payment delivered across shards is credited by
//! the recipient's commit fold, and a recipient spending it straight away
//! runs in the first ticks after that fold — the ticks whose baseline has
//! to carry the credit on every replica alike.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_scenarios::query::vault_balance;
use hyperscale_scenarios::tx::{account_routing_to, build_transfer_tx, validity_around};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs};
use hyperscale_simulation::ProcessingTimes;
use hyperscale_types::{
    Ed25519PrivateKey, PrincipalAddr, ShardId, TransactionDecision, TransactionStatus, TxHash,
};

mod support;

use support::SimCluster;

const SEED: u64 = 42;

/// What the remote payer holds.
const PAYER_FUNDS: u128 = 10_000_000;

/// What the recipient holds before the delivery: enough for the fees of
/// every spend, and short of any one [`SPEND`].
const RECIPIENT_FUNDS: u128 = 10_000;

/// What the payer delivers.
const DELIVERY: u128 = 5_000_000;

/// The least a spend moves where the recipient covers it only once the
/// delivery is credited.
const SPEND: u128 = 20_000;

/// The least a spend moves where the recipient covers every one of them
/// out of what it held before the delivery.
const POCKET_SPEND: u128 = 10;

/// Spends submitted, one each [`CADENCE`].
const SPENDS: u128 = 120;

/// How often the recipient spends: several times a block interval, so
/// every block's tick runs one.
const CADENCE: Duration = Duration::from_millis(100);

const fn config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        pool_surplus: 4,
        vnodes_per_host: 1,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// A disk whose writes outlast a block interval, each host's drawn
/// apart, beside pools that answer promptly.
const SLOW_DISK: ProcessingTimes = ProcessingTimes {
    consensus: Duration::from_millis(1),
    throughput: Duration::from_millis(1),
    io: Duration::from_millis(600),
    tail_per_million: 0,
    tail: Duration::ZERO,
};

type Account = (Ed25519PrivateKey, PrincipalAddr);

/// The shard the recipient and the account it spends to live on.
const HOME: ShardId = ShardId::leaf(1, 1);

/// The shard a payment crosses from.
const ABROAD: ShardId = ShardId::leaf(1, 0);

/// The payer on `from`, and the recipient and the account it spends to
/// on [`HOME`].
fn cast(from: ShardId) -> (Account, Account, Account) {
    let mut taken = Vec::new();
    (
        account_routing_to(from, &mut taken),
        account_routing_to(HOME, &mut taken),
        account_routing_to(HOME, &mut taken),
    )
}

/// Pay the recipient from an account on `from` while it spends at least
/// `least` every [`CADENCE`], and require every spend to reach a verdict and
/// the account spent to to hold exactly what the accepted ones moved.
///
/// From [`ABROAD`] the payment is a delivery the recipient's commit fold
/// credits; from [`HOME`] it is a member of a tick there, credited by
/// that tick's output.
fn a_recipient_spends_as_a_payment_lands(processing: ProcessingTimes, from: ShardId, least: u128) {
    let (payer, recipient, sink) = cast(from);
    let accounts = [
        (payer.1, PAYER_FUNDS),
        (recipient.1, RECIPIENT_FUNDS),
        (sink.1, RECIPIENT_FUNDS),
    ];
    let mut c =
        SimCluster::with_grown_accounts_and_processing(&config(), SEED, &accounts, processing);
    let sink_before = vault_balance(&c, HOME, sink.1);

    let delivery = Arc::new(build_transfer_tx(
        &payer.0,
        payer.1,
        recipient.1,
        DELIVERY,
        validity_around(c.now()),
    ));
    let delivery_hash = delivery.hash();
    c.submit(delivery);
    // The credit lands once the payer's shard has committed the payment,
    // so the spends start there and run across its landing.
    assert!(
        c.run_until(epochs(16), |c| c
            .chain_fate(from, delivery_hash)
            .0
            .is_some()),
        "the payer's shard never committed the payment",
    );

    let mut spends: Vec<(TxHash, u128)> = Vec::new();
    for index in 0..SPENDS {
        let due = c.now() + CADENCE;
        assert!(
            c.run_until(epochs(2), |c| c.now() >= due),
            "the cluster stopped after {index} spends",
        );
        let amount = least + index;
        let spend = Arc::new(build_transfer_tx(
            &recipient.0,
            recipient.1,
            sink.1,
            amount,
            validity_around(c.now()),
        ));
        spends.push((spend.hash(), amount));
        c.submit(spend);
    }

    let status = await_tx_terminal(&mut c, delivery_hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the delivery did not accept: {status:?}",
    );
    let mut accepted = 0u128;
    for (index, (hash, amount)) in spends.iter().enumerate() {
        let status = await_tx_terminal(&mut c, *hash, epochs(16));
        assert!(
            status.as_ref().is_some_and(TransactionStatus::is_final),
            "spend {index} never reached a verdict: {status:?}",
        );
        if matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ) {
            accepted += amount;
        }
    }
    assert!(accepted > 0, "no spend ran after the delivery was credited");
    assert!(
        c.run_until(epochs(8), |c| vault_balance(c, HOME, sink.1)
            == sink_before + accepted),
        "the account spent to holds {} more and the accepted spends come to {accepted}",
        vault_balance(&c, HOME, sink.1) - sink_before,
    );
}

/// With every write acknowledged as it is made, no replica runs a tick
/// behind its own disk.
#[test]
fn a_recipient_spends_a_delivery_as_it_lands_on_a_prompt_disk() {
    a_recipient_spends_as_a_payment_lands(ProcessingTimes::INSTANT, ABROAD, SPEND);
}

/// With writes acknowledged late, spends that never depend on the
/// delivery run alike on every replica.
#[test]
fn a_recipient_spends_its_own_funds_as_a_delivery_lands_on_a_slow_disk() {
    a_recipient_spends_as_a_payment_lands(SLOW_DISK, ABROAD, POCKET_SPEND);
}

/// With writes acknowledged late, spends that depend on a payment made
/// on the recipient's own shard run alike on every replica: the credit
/// is a tick's output, which the tick chain carries.
#[test]
fn a_recipient_spends_a_local_payment_as_it_lands_on_a_slow_disk() {
    a_recipient_spends_as_a_payment_lands(SLOW_DISK, HOME, SPEND);
}

/// With writes acknowledged late and each host's apart, spends that
/// depend on a delivery the commit fold credited run alike on every
/// replica.
#[test]
fn a_recipient_spends_a_delivery_as_it_lands_on_a_slow_disk() {
    a_recipient_spends_as_a_payment_lands(SLOW_DISK, ABROAD, SPEND);
}
