//! Transaction scenarios.

use std::sync::Arc;

use hyperscale_types::{ShardId, TransactionDecision, TransactionStatus};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;

use crate::reshape::split_lifecycle;
use crate::support::tx::{
    account_from_seed, build_faucet_tx, build_transfer_tx, signer_from_seed, validity_around,
};
use crate::support::wait::{await_height, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// Submit a faucet-funded single-shard transfer and assert it accepts.
///
/// Awaits the transfer completing with an `Accept` decision and the root shard
/// advancing past genesis. The faucet is a fixed native component on both
/// harnesses, so no funded-account discovery is needed.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget or the root shard does
/// not advance past genesis.
pub fn single_shard_tx(c: &mut impl Cluster) {
    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "single-shard tx did not accept within budget; status = {status:?}"
    );
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(2)),
        "root shard did not advance past genesis"
    );
}

/// Grow the root into two shards, then settle a cross-shard transfer.
///
/// Transfers between a funded account on each child, asserting it completes with
/// `Accept` — provisioning, execution, and per-shard certificates all agree,
/// with zero aborts. Composes [`split_lifecycle`] for the grow; account `31`
/// sits on the left child and `30` on the right, both funded at genesis.
///
/// # Panics
///
/// Panics if the grow misses its budget or the transfer does not accept.
pub fn cross_shard_tx(c: &mut impl Cluster) {
    split_lifecycle(c);

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard transfer did not accept (zero aborts) within budget; status = {status:?}"
    );
}

/// Grow to two shards, then submit a conflicting cross-shard pair (`31 → 30`
/// and `30 → 31`, across the two children) and assert it resolves promptly.
///
/// The two transactions contend on the same accounts across both shards. The
/// system resolves the contention — cycle detection aborts a deadlocked loser,
/// or the pair admits sequentially — so both reach a terminal outcome within a
/// bounded budget, never livelocking. At most one aborts: a double-abort would
/// mean a timeout, not prompt resolution. (Whether the cross-shard cycle
/// deadlocks at all is timing-dependent, so the loser-abort is not asserted —
/// prompt non-livelocked resolution is.) Composes [`split_lifecycle`] for the
/// grow.
///
/// # Panics
///
/// Panics if either transaction fails to resolve promptly, or if both abort.
pub fn livelock_resolves_promptly(c: &mut impl Cluster) {
    split_lifecycle(c);

    let network = NetworkDefinition::simulator();
    let validity = validity_around(c.now());
    let key_a = signer_from_seed(31);
    let key_b = signer_from_seed(30);
    let acc_a = account_from_seed(31);
    let acc_b = account_from_seed(30);

    let tx_a = build_transfer_tx(
        &key_a,
        acc_a,
        acc_b,
        Decimal::from(100),
        &network,
        200,
        validity,
    );
    let tx_b = build_transfer_tx(
        &key_b,
        acc_b,
        acc_a,
        Decimal::from(100),
        &network,
        201,
        validity,
    );
    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();
    c.submit(Arc::new(tx_a));
    c.submit(Arc::new(tx_b));

    // The pair shares an account set, so the ready-set invariant serializes it
    // into two back-to-back waves rather than running them together. Each
    // transaction gets the settlement budget a single cross-shard transfer needs
    // (`cross_shard_tx`), well above one wave on wall-clock. A genuine livelock
    // never resolves, so the assertion below still catches it — the budget only
    // has to outlast honest sequential settlement.
    let status_a = await_tx_terminal(c, hash_a, epochs(8));
    let status_b = await_tx_terminal(c, hash_b, epochs(8));
    assert!(
        matches!(status_a, Some(TransactionStatus::Completed(_)))
            && matches!(status_b, Some(TransactionStatus::Completed(_))),
        "conflicting pair must resolve promptly without livelocking; a = {status_a:?}, b = {status_b:?}"
    );
    let aborted = [&status_a, &status_b]
        .into_iter()
        .filter(|s| {
            matches!(
                s,
                Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            )
        })
        .count();
    assert!(
        aborted <= 1,
        "a conflicting pair aborts at most its loser, never both; a = {status_a:?}, b = {status_b:?}"
    );
}
