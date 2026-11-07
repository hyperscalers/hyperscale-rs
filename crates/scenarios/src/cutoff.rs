//! A payment whose value flow turns on the transaction clock, divided
//! across a two-shard core.
//!
//! The payer withdraws on its own shard, which is the leg feeding the
//! core. The first cutoff keeps the payment if the clock is short of a
//! deadline and passes it on otherwise, and the second keeps whatever it
//! is passed. Each sits on a shard of its own, and both are core, so
//! each of the two shards runs both nodes and applies the half that
//! lands on it. The payment lands in exactly one cutoff only where both
//! shards ran under one clock: were the first's shard to read the clock
//! short of the deadline and the second's to read it past, each would
//! bank the whole payment in its own cutoff.

use std::time::Duration;

use hyperscale_effects_bridge::vm_statics::config_key;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    PrincipalAddr, ProtocolHasher, ShardId, SubstateKey, TransactionDecision, TransactionStatus,
};
use hyperscale_vm_effects::{InstanceMeta, SlotId, Value, child_key};
use hyperscale_vm_fixtures::cutoff;
use hyperscale_vm_sdk::client::VaultField;

use crate::route::{FIRST_VENUE_SHARD, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::support::query::{clock, held, held_at, stands_at};
use crate::support::tx::{build_cutoff_tx, build_instantiate_tx, cutoff_on, validity_around};
use crate::support::wait::await_tx_terminal;
use crate::support::{FaultableCluster, committees_on_separate_hosts, epochs};
use crate::venue::{SWAPPER_FUNDING, accepted, grind_onto};

/// Where the first cutoff sits: the shard that commits the payment
/// first, short of its deadline.
const EARLY_SHARD: ShardId = FIRST_VENUE_SHARD;

/// Where the second sits: the shard the payment is held off until past
/// its deadline.
const LATE_SHARD: ShardId = SECOND_VENUE_SHARD;

/// Where the payer sits, off the core, so its withdrawal is a leg.
const PAYER_SHARD: ShardId = TRADER_SHARD;

/// What the payment moves.
const PAYMENT: u128 = 1_000_000;

/// How far past the cluster's clock at signing the deadline lies: well
/// past the early shard's commit, which follows the payer's within a few
/// blocks.
const CUTOFF_AHEAD: Duration = Duration::from_secs(4);

/// How far past the deadline the payment is kept off the late shard.
const HELD_PAST_CUTOFF: Duration = Duration::from_secs(2);

/// How long the cutoffs are watched past the payment first landing.
const SETTLED_TAIL: Duration = Duration::from_secs(5);

/// Genesis funding: the payer alone.
#[must_use]
pub fn cutoff_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    vec![(grind_onto(PAYER_SHARD, &mut Vec::new()).1, SWAPPER_FUNDING)]
}

/// The two core shards commit one payment on either side of its
/// deadline, and the payment lands in exactly one cutoff.
///
/// The payment is held off the late shard's committee until the
/// cluster's clock is past the deadline, so the early shard commits it
/// short of the deadline and the late shard past it. The two run the
/// same core under one clock, and the earliest committing clock is the
/// early shard's: the first cutoff keeps the payment on both, so the
/// early shard banks it and the late shard banks nothing.
///
/// Requires the two core shards' committees on hosts of their own.
///
/// # Panics
///
/// Panics if the cutoffs are not sealed, if the early shard does not
/// commit the payment short of its deadline or the late shard does not
/// commit it past, if the payment does not accept, if the payer is not
/// charged it, or if it lands anywhere but the first cutoff.
pub fn a_divided_core_pays_out_under_one_clock<C: FaultableCluster>(c: &mut C) {
    let (payer_key, payer) = grind_onto(PAYER_SHARD, &mut Vec::new());
    let first = cutoff_on(EARLY_SHARD);
    let second = cutoff_on(LATE_SHARD);
    accepted(
        c,
        build_instantiate_tx(
            &payer_key,
            &[first.clone(), second.clone()],
            validity_around(c.now()),
        ),
        "both cutoffs must be sealed before they can be called",
    );
    assert!(
        c.run_until(epochs(1), |c| [&first, &second]
            .iter()
            .all(|meta| stands_at(c, config_key(meta.address(&ProtocolHasher))))),
        "both seals must apply on their shards",
    );

    let kept = [kept_cell(&first), kept_cell(&second)];
    let funded = held(c, payer.address(), *PROTOCOL_RESOURCE);

    let (_, late_hosts) = committees_on_separate_hosts(c, EARLY_SHARD, LATE_SHARD);
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !late_hosts.contains(host))
        .collect();
    let _ = c.drop_type_between(&others, &late_hosts, "transaction.gossip");
    let _ = c.drop_type_between(&late_hosts, &others, "transaction.request");

    let cutoff = clock(c).plus(CUTOFF_AHEAD);
    let tx = build_cutoff_tx(
        &payer_key,
        (&first, &second),
        PAYMENT,
        cutoff.as_millis(),
        validity_around(c.now()),
    );
    // At the payer's shard by name: a harness that cannot route the
    // payment itself would otherwise hand it to whichever host it holds
    // first, which may be the late shard's.
    let hash = tx.hash();
    c.submit_to(PAYER_SHARD, tx.clone());

    assert!(
        c.run_until(epochs(1), |c| c.chain_fate(EARLY_SHARD, hash).0.is_some()),
        "the early shard must commit the payment",
    );
    let committed_at = |c: &C, shard| {
        let height = c.chain_fate(shard, hash).0?;
        c.committed_clock(shard, height)
    };
    let early = committed_at(c, EARLY_SHARD).expect("the early shard holds its commit");
    assert!(
        early < cutoff,
        "the early shard must commit short of the deadline: {early:?} against {cutoff:?}",
    );
    let held_until = cutoff.plus(HELD_PAST_CUTOFF);
    assert!(
        c.run_until(epochs(1), |c| clock(c) >= held_until),
        "the cluster's clock must pass the deadline",
    );
    assert!(
        c.chain_fate(LATE_SHARD, hash).0.is_none(),
        "the late shard must not hold the payment before the deadline",
    );
    c.clear_drops();
    c.submit_to(LATE_SHARD, tx);

    let status = await_tx_terminal(c, hash, epochs(4));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the payment must accept; status = {status:?}",
    );
    let late = committed_at(c, LATE_SHARD).expect("the late shard holds its commit");
    assert!(
        late >= cutoff,
        "the late shard must commit past the deadline: {late:?} against {cutoff:?}",
    );

    // Held past the first landing, so a second credit of the same
    // payment has its chance to land too.
    let banked = |c: &C| [held_at(c, kept[0]), held_at(c, kept[1])];
    let _ = c.run_until(epochs(4), |c| banked(c).iter().sum::<u128>() >= PAYMENT);
    let tail = c.now() + SETTLED_TAIL;
    let _ = c.run_until(epochs(1), |c| c.now() >= tail);
    let spent = funded - held(c, payer.address(), *PROTOCOL_RESOURCE);
    assert!(
        spent > PAYMENT,
        "the payer pays the payment and its price: {spent} against {PAYMENT}",
    );
    assert_eq!(
        banked(c),
        [PAYMENT, 0],
        "the payment lands in the first cutoff alone, under the early shard's clock",
    );
}

/// The cell `meta` keeps the protocol resource in.
fn kept_cell(meta: &InstanceMeta) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        meta.address(&ProtocolHasher).address(),
        SlotId(<cutoff::Kept as VaultField>::SLOT),
        &[Value::Address(PROTOCOL_RESOURCE.address()).canonical_bytes()],
    )
}
