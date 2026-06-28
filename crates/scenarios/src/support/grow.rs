//! Growing a cluster to a starting topology.
//!
//! Genesis is always a single ROOT shard; a deeper partition exists only once
//! the network has split into it. [`grow_to`] is the harness-agnostic step that
//! drives that growth, so a scenario (or a harness's `with_grown_balances`
//! constructor) reaches a multi-shard starting point the only way the network
//! ever does — by splitting. [`vote_reshape_threshold`] then raises the live
//! threshold so the grown topology stabilizes.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, Ed25519PrivateKey, Epoch, ShardId};
use radix_common::network::NetworkDefinition;

use super::query::beacon_epoch;
use super::tx::{build_reshape_threshold_vote_tx, validity_around};
use super::{Budget, Cluster, epochs};

/// Epochs of lead before the threshold vote activates — enough for the vote
/// transaction to commit and fold into the tally before it is read.
const VOTE_ACTIVATE_LEAD: u64 = 4;

/// Activation windows the threshold vote retries across before giving up.
const VOTE_ATTEMPTS: u32 = 4;

/// Epochs to wait for one vote window to fold and apply — the activation lead
/// plus slack for the witness to commit, reach the beacon, and fold.
const VOTE_WINDOW_EPOCHS: u32 = 6;

/// Grow the single-shard root into a uniform `target`-leaf partition through the
/// organic split lifecycle.
///
/// Genesis is always a single ROOT shard; a deeper partition exists only once
/// the network has split into it. A scenario that needs `target` shards calls
/// this once to grow there the only way the network ever does — by splitting —
/// and then runs an identical body on either harness.
///
/// The cluster must start at a single ROOT shard with `split_bytes = 0` armed,
/// so every generation splits. This drives [`Cluster::run_until`] until all
/// `target` leaves serve and commit past genesis. Pair it with
/// [`vote_reshape_threshold`] to raise the threshold afterward, so the grown
/// leaves stop splitting and any pair a scenario later merges falls under the
/// derived merge threshold.
///
/// `target` must be a power of two. The pump-vs-poll difference between harnesses
/// is absorbed by `run_until`, so this one definition serves both.
///
/// # Panics
///
/// Panics if `target` is not a power of two, or if the grow misses its budget.
pub fn grow_to(c: &mut impl Cluster, target: u32) {
    assert!(
        target.is_power_of_two(),
        "grow target must be a power of two; got {target}",
    );
    let depth = target.trailing_zeros();
    if depth == 0 {
        return;
    }
    let leaves: Vec<ShardId> = (0..u64::from(target))
        .map(|i| ShardId::leaf(depth, i))
        .collect();
    // One generation per level of depth, budgeted generously over the
    // admission → gate → seed → child-run phases each split walks through.
    let budget = Budget((depth * 40).max(40));
    assert!(
        c.run_until(budget, |c| leaves.iter().all(|&leaf| {
            c.committed_height(leaf)
                .is_some_and(|h| h > BlockHeight::GENESIS)
        })),
        "grow to {target} leaves did not complete within budget",
    );
}

/// Vote the live reshape threshold up to `split_bytes`, paid by `payer`, and
/// await its activation.
///
/// A grown topology can't merge under the frozen threshold that split it, and a
/// cold child re-splits if the threshold stays at zero; raising it stabilizes the
/// grown leaves and brackets a later merge's derived threshold above their byte
/// totals. `payer` must control a genesis-funded account seated on a live shard,
/// so the system-action fee is payable.
///
/// # Panics
///
/// Panics if the threshold does not activate within budget.
pub fn vote_reshape_threshold(c: &mut impl Cluster, payer: &Ed25519PrivateKey, split_bytes: u64) {
    // Re-submit the vote each activation window until the beacon folds and
    // applies it. A single vote carries a fixed `VOTE_ACTIVATE_LEAD` lead and is
    // dropped if its witness folds at or after `activate_at`; at a long epoch
    // that lead is only a few minutes of slack, so a fold delayed by a committee
    // hiccup can miss it. Retrying past the miss with a fresh window keeps the
    // step robust without widening the lead (which would just defer activation).
    for nonce in 1..=VOTE_ATTEMPTS {
        let current = beacon_epoch(c).expect("a beacon epoch is committed");
        let activate_at = Epoch::new(current.inner() + VOTE_ACTIVATE_LEAD);
        let vote = build_reshape_threshold_vote_tx(
            payer,
            split_bytes,
            activate_at,
            &NetworkDefinition::simulator(),
            nonce,
            validity_around(c.now()),
        );
        c.submit(Arc::new(vote));
        if c.run_until(epochs(VOTE_WINDOW_EPOCHS), |c| {
            c.beacon_state()
                .is_some_and(|state| state.params.reshape_thresholds.split_bytes == split_bytes)
        }) {
            return;
        }
    }
    panic!("the reshape threshold did not activate to {split_bytes} within budget");
}
