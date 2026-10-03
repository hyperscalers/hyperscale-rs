//! Growing a cluster to a starting topology.
//!
//! Genesis is always a single ROOT shard; a deeper partition exists only once
//! the network has split into it. [`grow_to`] is the harness-agnostic step that
//! drives that growth, so a scenario (or a harness's `with_grown_balances`
//! constructor) reaches a multi-shard starting point the only way the network
//! ever does — by splitting. [`vote_reshape_threshold`] then raises the live
//! threshold so the grown topology stabilizes, and [`grow_and_hold`] does both,
//! registers the pool extras genesis held back, and checks the topology held.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    Epoch, NetworkDefinition, NetworkParams, ShardId, Stake, Transaction, ValidatorStatus,
    validator_possession_proof_sign,
};

use super::query::{beacon_epoch, live_shards, pool_total_stake, validator_status};
use super::tx::{
    ParamBallot, STAKE_POOL_ID, build_param_vote_tx, build_register_tx, build_stake_tx, delegator,
    pool_at, pool_operator, validity_around,
};
use super::{Budget, Cluster, epochs};

/// Epochs of lead before the threshold vote activates — enough for the vote
/// transaction to commit and fold into the tally before it is read.
const VOTE_ACTIVATE_LEAD: u64 = 4;

/// Activation windows the threshold vote retries across before giving up.
const VOTE_ATTEMPTS: u32 = 4;

/// Epochs to wait for one vote window to fold and apply — the activation lead
/// plus slack for the witness to commit, reach the beacon, and fold.
const VOTE_WINDOW_EPOCHS: u32 = 6;

/// Submissions each staging step retries across before giving up.
const STAGE_ATTEMPTS: u32 = 4;

/// Epochs to wait for one staging submission to commit and fold.
const STAGE_WINDOW_EPOCHS: u32 = 8;

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
/// `target` leaves serve and commit past their own genesis: a child's store
/// is seeded at the height its parent handed off, so holding a chain is not
/// yet running one. Pair it with
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
                .zip(c.chain_origin(leaf))
                .is_some_and(|(height, origin)| height > origin.genesis_height)
        })),
        "grow to {target} leaves did not complete within budget",
    );
}

/// [`grow_to`] `target` leaves, then [`vote_reshape_threshold`] up to
/// `split_bytes`, then [`register_staged`] the validators genesis held back,
/// and check the grown topology is still exactly `target` leaves.
///
/// The leaves run under the zero threshold that grew them until the vote
/// activates, and every one of them asserts a split in that window. What
/// refuses it is the beacon's pool gate: genesis registered only the cohorts
/// the grow draws and fewer than a cohort's spares (see
/// [`ScenarioConfig::staged_pool_extras`](crate::ScenarioConfig::staged_pool_extras)),
/// so the rest of the pool the scenario was sized for joins only once the
/// raised threshold is in force.
///
/// # Panics
///
/// Panics if the grow, the vote or a staged registration misses its budget,
/// or if a leaf split again before the vote activated.
pub fn grow_and_hold(c: &mut impl Cluster, target: u32, split_bytes: u64) {
    grow_to(c, target);
    vote_reshape_threshold(c, split_bytes);
    register_staged(c);
    let depth = target.trailing_zeros();
    let expected: BTreeSet<ShardId> = (0..u64::from(target))
        .map(|i| ShardId::leaf(depth, i))
        .collect();
    let live = live_shards(c);
    assert_eq!(
        live, expected,
        "the grown leaves split again before the threshold vote activated",
    );
}

/// Register every validator [`Cluster::staged_validators`] names, and wait
/// until the beacon holds each one.
///
/// A registration takes a seat of its pool's capacity at the dynamic
/// `min_stake`, and the founding pool has none to spare. `min_stake` is
/// capped by an active pool's stake per active validator, so stake added
/// to the founding pool raises the price of a seat along with the budget
/// for one. The staged validators join the staking pool instead, a pool
/// with no active validators to move that cap, which the delegator first
/// funds for one more seat than they take at the `min_stake` the beacon
/// holds now: the founding pool's stake accrues as the chain runs, and
/// the price of a seat with it.
///
/// # Panics
///
/// Panics if the delegation or a registration does not fold within budget.
fn register_staged(c: &mut impl Cluster) {
    let staged = c.staged_validators();
    if staged.is_empty() {
        return;
    }
    let pool = pool_at(STAKE_POOL_ID);
    let seats = u128::try_from(staged.len() + 1).expect("staged count fits u128");
    let price = c
        .beacon_state()
        .expect("a committed beacon state")
        .min_stake();
    let capacity = Stake::from_quanta(price.quanta() * seats);
    let (key, from) = delegator();
    land(
        c,
        |now| build_stake_tx(&key, from, pool, capacity.quanta(), validity_around(now)),
        |c| pool_total_stake(c, STAKE_POOL_ID).is_some_and(|stake| stake >= capacity),
        "the staging pool's delegation",
    );
    let (operator, _) = pool_operator();
    for (validator, signer) in &staged {
        let validator = *validator;
        let proof = validator_possession_proof_sign(
            signer.as_ref(),
            &NetworkDefinition::simulator(),
            validator,
        )
        .expect("a possession proof signs");
        let pubkey = signer.public_key();
        land(
            c,
            |now| {
                build_register_tx(
                    &operator,
                    pool,
                    validator,
                    &pubkey,
                    &proof,
                    validity_around(now),
                )
            },
            |c| {
                matches!(
                    validator_status(c, validator),
                    Some(
                        ValidatorStatus::Pooled
                            | ValidatorStatus::Observing { .. }
                            | ValidatorStatus::OnShard { .. }
                    )
                )
            },
            &format!("staged validator {validator}'s registration"),
        );
    }
}

/// Submit `build`'s transaction until `folded` reads true, re-signing it
/// over a fresh validity window each attempt.
///
/// # Panics
///
/// Panics if `folded` never reads true within budget.
fn land<C: Cluster>(
    c: &mut C,
    build: impl Fn(Duration) -> Transaction,
    folded: impl Fn(&C) -> bool,
    what: &str,
) {
    for _ in 0..STAGE_ATTEMPTS {
        c.submit(Arc::new(build(c.now())));
        if c.run_until(epochs(STAGE_WINDOW_EPOCHS), &folded) {
            return;
        }
    }
    panic!("{what} did not fold within budget");
}

/// Vote the live reshape threshold up to `split_bytes`, paid by `payer`, and
/// await its activation.
///
/// A grown topology can't merge under the frozen threshold that split it, and a
/// cold child re-splits if the threshold stays at zero; raising it stabilizes the
/// grown leaves and brackets a later merge's derived threshold above their byte
/// totals. The vote is the founding pool's, cast by the operator its seat
/// names, so the cluster has to seat that pool and fund its operator.
///
/// # Panics
///
/// Panics if the threshold does not activate within budget.
pub fn vote_reshape_threshold(c: &mut impl Cluster, split_bytes: u64) {
    vote_params(
        c,
        |ballot| ballot.split_bytes = split_bytes,
        |params| params.reshape_thresholds.split_bytes == split_bytes,
        &format!("the reshape threshold to {split_bytes}"),
    );
}

/// Cast the founding pool's vote for the chain's live parameters with
/// `change` applied, and wait until the fold applies it, as `applied`
/// reads them back.
///
/// Re-submits each activation window until it lands. A single vote
/// carries a fixed `VOTE_ACTIVATE_LEAD` lead and is dropped if its
/// witness folds at or after `activate_at`; at a long epoch that lead is
/// only a few minutes of slack, so a fold delayed by a committee hiccup
/// can miss it. Retrying past the miss with a fresh window keeps the
/// step robust without widening the lead, which would only defer
/// activation.
///
/// # Panics
///
/// Panics if `applied` never reads true within budget.
pub fn vote_params(
    c: &mut impl Cluster,
    change: impl Fn(&mut ParamBallot),
    applied: impl Fn(&NetworkParams) -> bool,
    what: &str,
) {
    for _ in 1..=VOTE_ATTEMPTS {
        let current = beacon_epoch(c).expect("a beacon epoch is committed");
        // Seeded from what the chain runs right now, so a caller that
        // names one row proposes one change. A vote is a whole proposal
        // and the tally buckets by the exact set, so a ballot built from
        // anything else votes to reset every row it guessed at.
        let live = c.beacon_state().expect("a committed beacon state").params;
        let mut ballot = ParamBallot::of(&live);
        change(&mut ballot);
        let activate_at = Epoch::new(current.inner() + VOTE_ACTIVATE_LEAD);
        let vote = build_param_vote_tx(
            &pool_operator().0,
            ballot,
            activate_at,
            validity_around(c.now()),
        );
        c.submit(Arc::new(vote));
        if c.run_until(epochs(VOTE_WINDOW_EPOCHS), |c| {
            c.beacon_state().is_some_and(|state| applied(&state.params))
        }) {
            return;
        }
    }
    panic!("{what} did not activate within budget");
}
