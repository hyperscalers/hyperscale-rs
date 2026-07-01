//! Portable network-fault scenarios.

use std::sync::Arc;

use hyperscale_types::{ShardId, TransactionDecision, TransactionStatus};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;

use crate::reshape::split_lifecycle;
use crate::support::epochs;
use crate::support::faultable::FaultableCluster;
use crate::support::tx::{
    account_from_seed, build_faucet_tx, build_transfer_tx, signer_from_seed, validity_around,
};
use crate::support::wait::{await_height, await_tx_terminal};

/// Dropping `transaction.gossip` still delivers a submitted transfer — via the
/// fetch fallback — with the drop rule firing and the fetch engaging.
///
/// The feasibility check for the libp2p gate: on the sim the drop is total at
/// delivery; on production the inbound `Ignore` filter suppresses the gossip on
/// every host, so a submitted transaction reaches the committee only by the
/// fetch fallback.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget, the drop rule never
/// fired, or the fetch fallback never engaged.
pub fn gossip_drop_engages_fetch_fallback(c: &mut impl FaultableCluster) {
    let fetch_before = c.metric("fetch_items_sent", Some("transaction"));
    let dropped = c.drop_type("transaction.gossip");

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
        "the transfer must still accept via the fetch fallback; status = {status:?}"
    );
    assert!(
        dropped.fired() >= 1,
        "the transaction.gossip drop rule must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("transaction")) > fetch_before,
        "the transaction fetch fallback must engage (before={fetch_before})",
    );
}

/// A 2-2 host partition starves quorum (3 of 4), so consensus halts; healing it
/// resumes commits as the lagging half catches up.
///
/// Requires a four-host single-shard cluster. The heal exercises the catch-up
/// sync path: the lagging half resynchronises via block fetch, not gossip
/// re-delivery, so the resume budget covers a few sync rounds.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, or commits do not resume after the heal.
pub fn partition_halts_and_heals(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before the partition",
    );
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();

    // Neither half of a 2-2 split has the 3-of-4 quorum, so progress halts.
    c.partition(&[0, 1], &[2, 3]);
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "a 2-2 partition has no quorum, so progress must halt: before={before}, during={during}",
    );

    // Healing lets the pacemaker resynchronise the lagging half; commits resume.
    c.heal_all();
    assert!(
        await_height(c, ShardId::ROOT, during + 3, epochs(6)),
        "consensus must resume committing once the partition heals (stalled at {during})",
    );
}

/// A transaction settles while one validator is isolated: the remaining 3-of-4
/// quorum holds, and the vote-retry rotation recovers any wave the isolated node
/// was leading.
///
/// Requires a four-host single-shard cluster. Submission routes to host 0, so a
/// different host is isolated — one that still proposes some rounds, exercising
/// the leader-failure fallback.
///
/// # Panics
///
/// Panics if consensus does not commit before the isolation or the transfer does
/// not complete while a validator is isolated.
pub fn isolated_validator_still_settles(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before isolating a validator",
    );
    c.isolate(3);

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

    let status = await_tx_terminal(c, hash, epochs(6));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must complete despite an isolated validator; status = {status:?}",
    );
}

/// Grow to two shards, drop the `broadcast` message type, then run a cross-shard
/// transfer that must recover via the `fetch_kind` fetch fallback.
///
/// Works for any broadcast the cross-shard flow relies on — a unicast 2PC
/// delivery (`provisions.broadcast`, `execution.cert.batch`) suppressed at the
/// sender's gate, or a gossip broadcast (`transaction.gossip`, `block.committed`)
/// suppressed by the receiver's inbound filter. The transfer moves 500 XRD from
/// account `31` (left child) to `30` (right child), both funded at genesis.
/// Faults install after the split settles, so the grow rides its own broadcasts
/// cleanly. Asserts the transfer accepts, the drop fired, the fetch engaged, and
/// nothing aborted.
fn cross_shard_broadcast_drop(
    c: &mut impl FaultableCluster,
    broadcast: &'static str,
    fetch_kind: &'static str,
) {
    split_lifecycle(c);
    // Snapshot the fetch counter before the drop: the counter is cluster-wide
    // and monotonic, so measuring the increase isolates the fetches this outage
    // forces from any the split itself emitted (remote-header sync in particular
    // runs as normal machinery in a grown cluster, not only as a fallback).
    let fetch_before = c.metric("fetch_items_sent", Some(fetch_kind));
    let dropped = c.drop_type(broadcast);

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

    let status = await_tx_terminal(c, hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the cross-shard transfer must settle despite the dropped {broadcast}; status = {status:?}",
    );
    assert!(dropped.fired() >= 1, "the {broadcast} drop must fire");
    assert!(
        c.metric("fetch_items_sent", Some(fetch_kind)) > fetch_before,
        "the {fetch_kind} fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping `provisions.broadcast` still settles a cross-shard transfer — the
/// destination shard fetches the provisions rather than receiving them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the provision
/// fetch never engages, or anything aborts.
pub fn cross_shard_provisions_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "provisions.broadcast", "provision");
}

/// Dropping `execution.cert.batch` still settles a cross-shard transfer — the
/// destination shard fetches the execution certificates rather than receiving
/// them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the exec-cert
/// fetch never engages, or anything aborts.
pub fn cross_shard_exec_cert_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "execution.cert.batch", "exec_cert");
}

/// Dropping BOTH `provisions.broadcast` and `execution.cert.batch` at once
/// still settles a cross-shard transfer.
///
/// The two fallback fetches are gated on different timeouts and different fetch
/// instances, so this proves they compose without deadlock when both primary
/// cross-shard channels fail together: each shard fetches its provisions and
/// its execution certificates, and the wave finalizes within its timeout
/// rather than aborting.
///
/// # Panics
///
/// Panics if the transfer does not settle, either drop never fires, either
/// fetch never engages, or anything aborts.
pub fn cross_shard_compound_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let provision_before = c.metric("fetch_items_sent", Some("provision"));
    let exec_cert_before = c.metric("fetch_items_sent", Some("exec_cert"));
    let provisions_dropped = c.drop_type("provisions.broadcast");
    let exec_cert_dropped = c.drop_type("execution.cert.batch");

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

    let status = await_tx_terminal(c, hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite both channels dropped; status = {status:?}",
    );
    assert!(
        provisions_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        exec_cert_dropped.fired() >= 1,
        "the execution.cert.batch drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > provision_before,
        "the provision fetch fallback must engage (before={provision_before})",
    );
    assert!(
        c.metric("fetch_items_sent", Some("exec_cert")) > exec_cert_before,
        "the exec-cert fetch fallback must engage (before={exec_cert_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the compound cross-shard transfer must not abort",
    );
}

/// Dropping `transaction.gossip` in a grown cluster still settles a cross-shard
/// transfer — the source committee fetches the transaction body (the DA
/// fallback) rather than receiving it by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the transaction
/// fetch never engages, or anything aborts.
pub fn cross_shard_transaction_da_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "transaction.gossip", "transaction");
}

/// Dropping `block.committed` still settles a cross-shard transfer — the shard
/// tracking its counterpart's committed headers fetches them via the
/// remote-header sync rather than receiving them by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the
/// remote-header fetch never engages, or anything aborts.
pub fn cross_shard_header_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "block.committed", "remote_header");
}

/// A cross-shard transfer settles under unreliable request RPC.
///
/// Provisions never broadcast — forcing the provision fetch fallback — AND half
/// of every `provision.request` leg is dropped, so each fetch attempt is a
/// coin-flip that must be retried until one gets through. Proves the
/// request-manager retry path recovers a fetch under probabilistic request
/// loss without aborting.
///
/// The 50% loss is exercised per attempt on both harnesses: the sim draws from
/// the engine's own seeded RNG at the request-drain site, and production
/// consults the same gate in the libp2p request pool per send, surfacing a
/// dropped leg as the timeout the retry loop rolls again.
///
/// Returns the cluster-wide `provision.request` drop count. Engagement is
/// deterministic on the sim — the wiring asserts it per seed — but not on
/// production, where the async retry path can settle the fetch on an undropped
/// first leg, so a caller there asserts only the liveness invariants this body
/// checks. All other invariants (settle, broadcast dropped, fetch engaged, zero
/// aborts) hold on both.
///
/// # Panics
///
/// Panics if the transfer fails to settle, the broadcast drop never fires, the
/// provision fetch never engages, or anything aborts.
pub fn cross_shard_provisions_fetch_with_request_loss(c: &mut impl FaultableCluster) -> u64 {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let request_dropped = c.drop_type_with_probability("provision.request", 0.5);

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

    let status = await_tx_terminal(c, hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite 50% provision.request loss; status = {status:?}",
    );
    assert!(
        broadcast_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort under request loss",
    );

    request_dropped.fired()
}

/// A transient `provisions.broadcast` outage recovers even when the fault lifts
/// mid-flight.
///
/// Drop the broadcast, submit a cross-shard transfer, and wait until the outage
/// actually bites — the source shard's one-shot provision broadcast is
/// suppressed. Then lift the fault and confirm the transfer still settles via
/// the provision fetch fallback with nothing aborting. The dropped broadcast is
/// not re-emitted on lift, so the destination shard recovers by fetch either
/// way; the point is that removing a live drop rule mid-recovery is safe — the
/// fetch bridge completes and no wave wedges.
///
/// One transfer, not two: both spendable accounts (`31`, `30`) are declared
/// writes of every transfer between them, so a second overlapping cross-shard
/// transfer would race the first's conflict window rather than test recovery.
///
/// # Panics
///
/// Panics if the transfer fails to settle, the outage never fired, the
/// provision fetch never engaged, or anything aborts.
pub fn cross_shard_provisions_recovers_after_transient_outage(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let dropped = c.drop_type("provisions.broadcast");

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

    // Let the outage bite: the source shard's provision broadcast is dropped
    // before we lift the fault, so the recovery genuinely spans a removal.
    let bit = c.run_until(epochs(8), |_| dropped.fired() >= 1);
    assert!(
        bit,
        "the provisions.broadcast drop must fire before the outage lifts",
    );
    c.clear_drops();

    let status = await_tx_terminal(c, hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle via the provision fetch despite the transient \
         outage; status = {status:?}",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must bridge the outage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort",
    );
}
