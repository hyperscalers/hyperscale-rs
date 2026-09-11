//! Transaction scenarios.

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{TransactionDecision, TransactionStatus};

use crate::reshape::split_lifecycle;
use crate::support::conservation::{Charges, World};
use crate::support::tx::{PROBE_PAYMENT, build_transfer_tx, livelock_pair, validity_around};
use crate::support::wait::await_tx_terminal;
use crate::support::{Cluster, epochs};

/// Grow to two shards, then submit a conflicting cross-shard pair — each
/// account paying the other, one on each child — and assert it resolves.
///
/// Each transfer is the other's mirror across the two children, so the
/// pair shares its whole account set and each engages the shard the other
/// pays from. Both reach a terminal outcome within a bounded budget and
/// the contention clears behind them — which is what "no livelock" means
/// here.
///
/// **A symmetric pair resolves by deadline, not by a loser.** There is no
/// cycle detector: each payer's shard holds a lock the other's tick needs,
/// neither can engage, and the deadline abort is what breaks it — the
/// fee model's backstop doing the job it exists for. So both aborting is
/// the expected shape, and asserting "at most one aborts" would be
/// asserting a mechanism this engine does not have.
///
/// What that leaves worth asserting is that the deadlock was transient:
/// the pair moves nothing, and a single transfer submitted afterwards
/// settles, which it could not if either shard were still holding a lock.
/// Composes [`split_lifecycle`] for the grow.
///
/// # Panics
///
/// Panics if either transaction fails to reach a terminal outcome, or if
/// the contention does not clear behind them.
pub fn livelock_resolves_promptly(c: &mut impl Cluster) {
    split_lifecycle(c);

    let validity = validity_around(c.now());
    let pair = livelock_pair();
    let (key_a, acc_a) = &pair[0];
    let (key_b, acc_b) = &pair[1];

    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [acc_a.address(), acc_b.address()],
        [],
    );
    let mut charges = Charges::default();
    let tx_a = build_transfer_tx(key_a, *acc_a, *acc_b, PROBE_PAYMENT, validity);
    let tx_b = build_transfer_tx(key_b, *acc_b, *acc_a, PROBE_PAYMENT, validity);
    let hash_a = charges.submit(c, tx_a);
    let hash_b = charges.submit(c, tx_b);

    // The budget has to outlast a payer's deadline, which is its signed
    // window's end plus the evidence margin — wall-clock, and longer than
    // the tick a settlement would take. A genuine livelock never resolves
    // at all, so the assertion still catches one.
    let status_a = await_tx_terminal(c, hash_a, epochs(8));
    let status_b = await_tx_terminal(c, hash_b, epochs(8));
    assert!(
        matches!(status_a, Some(TransactionStatus::Completed(_)))
            && matches!(status_b, Some(TransactionStatus::Completed(_))),
        "conflicting pair must resolve without livelocking; a = {status_a:?}, b = {status_b:?}"
    );

    // The control on that: whatever the pair did, neither shard is still
    // encumbered. A lock the deadlock left behind would refuse this.
    let after = build_transfer_tx(
        key_a,
        *acc_a,
        *acc_b,
        PROBE_PAYMENT,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, after);
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the contention must clear behind the pair; status = {status:?}",
    );
    world.assert_settles_within(c, &charges, epochs(8), "a livelocked pair and its control");
}
