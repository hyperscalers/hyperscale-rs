//! Shuffle step, beacon-committee resample, and per-shard membership
//! diff.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, CommitteeTransition, ShardGroupId, TransitionCause, ValidatorId, ValidatorStatus,
};
use rand::RngExt;

use crate::constants::{BEACON_SIGNER_COUNT, SHUFFLE_INTERVAL_EPOCHS};
use crate::sampling::{prng_from, sample_committee};
use crate::state::derived::beacon_eligible;
use crate::state::pool::pool_draw;

/// Domain tag for [`run_shuffle_step`]'s victim-selection seed. Distinct
/// from [`crate::sampling`]'s pool-draw tag so the two PRNG streams
/// never collide on the same `(randomness, epoch, shard)` input.
const DOMAIN_SHUFFLE_EXIT: &[u8] = b"hyperscale-shuffle-exit-v1";

/// Trickled committee rotation. When `state.current_epoch` lands on a
/// [`SHUFFLE_INTERVAL_EPOCHS`] boundary (and `epoch > 0`), each shard
/// rotates one of its ready `OnShard` validators back to `Pooled` and
/// immediately refills the freed slot via [`pool_draw`]. The system-wide
/// rotation rate is one validator per shard per
/// [`SHUFFLE_INTERVAL_EPOCHS`] epochs, keeping per-shard composition
/// churn uniform and bounded.
///
/// Shards iterate in sorted [`ShardGroupId`] order; the victim within
/// each shard is picked deterministically by hashing
/// `(state.randomness, current_epoch, shard)` under a domain tag
/// distinct from [`pool_draw`]'s. Shards whose `OnShard { ready: true }`
/// member set is empty are skipped.
///
/// Ordering invariant — pinned by `shuffle_avoids_self_replacement`:
///
/// 1. Remove the victim from the shard committee.
/// 2. [`pool_draw`] to refill — the derived pool excludes the victim
///    because their status is still `OnShard` here.
/// 3. Flip the victim's status to `Pooled`.
///
/// Flipping status *after* the draw is what prevents self-replacement:
/// derivation makes "in the pool" mean "status == Pooled", so flipping
/// early would put the victim in the pool just in time for the same
/// draw to pick them. A later shard's draw in the same step may pick
/// the victim and place them on a different shard — a legitimate
/// cross-shard reassignment.
pub(super) fn run_shuffle_step(state: &mut BeaconState) {
    let epoch = state.current_epoch;
    if epoch.inner() == 0 || !epoch.inner().is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
        return;
    }
    let shard_ids: Vec<ShardGroupId> = state.shard_committees.keys().copied().collect();
    for shard in shard_ids {
        // Bind the candidate set to validators whose status records
        // *this* shard. The global invariant `members ⇔ status ==
        // OnShard { shard: s, .. }` holds today; matching the shard
        // here means a future bug that drops a transition site (a
        // stale `members` entry pointing at a different shard) fails
        // to a skipped shuffle rather than picking from the wrong
        // shard.
        let ready_members: Vec<ValidatorId> = state
            .shard_committees
            .get(&shard)
            .expect("just iterated")
            .members
            .iter()
            .copied()
            .filter(|id| {
                matches!(
                    state.validators.get(id).map(|r| &r.status),
                    Some(ValidatorStatus::OnShard { shard: s, ready: true, .. }) if *s == shard
                )
            })
            .collect();
        if ready_members.is_empty() {
            continue;
        }
        let mut h = Hasher::new();
        h.update(DOMAIN_SHUFFLE_EXIT);
        h.update(state.randomness.as_bytes());
        h.update(&epoch.inner().to_le_bytes());
        h.update(&shard.inner().to_le_bytes());
        let seed = *h.finalize().as_bytes();
        let mut prng = prng_from(&seed);
        let idx = prng.random_range(0..ready_members.len());
        let victim = ready_members[idx];

        state
            .shard_committees
            .get_mut(&shard)
            .expect("present")
            .members
            .retain(|v| *v != victim);
        pool_draw(state, shard);
        state
            .validators
            .get_mut(&victim)
            .expect("victim is in state.validators")
            .status = ValidatorStatus::Pooled;
    }
}

/// Resample `state.committee` from [`beacon_eligible`] using
/// `state.randomness`, returning the resulting handover.
///
/// Runs every epoch — the slot-equals-epoch model makes every
/// `apply_epoch` a beacon-committee boundary, so the runner gets a
/// fresh SPC instance per epoch regardless of whether the resampled
/// set differs from the prior one.
///
/// Reads the post-shuffle eligible set: validators rotated to `Pooled`
/// by [`run_shuffle_step`] are excluded from this resample's input.
/// Order matters — putting the resample before the shuffle would feed
/// stale `OnShard { ready: true }` ids into the sampler.
///
/// `excluded` is the validator set the sampler must skip on top of the
/// natural [`beacon_eligible`] filter — empty on the normal path,
/// populated from a
/// [`RecoveryCertificate`](hyperscale_types::RecoveryCertificate)'s
/// cumulative exclusions on the recovery path. `cause` tags the
/// resulting transition.
pub(super) fn resample_beacon_committee(
    state: &mut BeaconState,
    excluded: &BTreeSet<ValidatorId>,
    cause: TransitionCause,
) -> CommitteeTransition {
    let prior = std::mem::take(&mut state.committee);
    let eligible: Vec<ValidatorId> = beacon_eligible(state)
        .into_iter()
        .filter(|id| !excluded.contains(id))
        .collect();
    state.committee = sample_committee(&eligible, state.randomness.as_bytes(), BEACON_SIGNER_COUNT);
    CommitteeTransition {
        from: prior,
        to: state.committee.clone(),
        cause,
        at_slot: state.current_epoch,
    }
}

/// Compare each shard's current `members` against the epoch-start
/// snapshot and emit one [`CommitteeTransition`] per shard whose
/// membership *set* changed. Members are compared as sets, so a no-op
/// churn (e.g. jail one validator, [`pool_draw`] refills with the same
/// one) doesn't register as a transition.
///
/// The cause is shared across all transitions emitted in one epoch:
///
/// - [`TransitionCause::NaturalShuffle`] when the epoch landed on a
///   shuffle interval boundary (the dominant cadence on those epochs).
/// - [`TransitionCause::MembershipChange`] otherwise — irregular events
///   like jail, deactivate, or withdrawal-completion auto-deactivation
///   drove the change.
///
/// Shards present in the snapshot but missing from the current state
/// (or vice versa) aren't normal under a stable shard count, but the
/// diff is robust to either case by treating the missing side as an
/// empty member list.
pub(super) fn diff_shard_committees(
    state: &BeaconState,
    pre_shard_members: &BTreeMap<ShardGroupId, Vec<ValidatorId>>,
) -> BTreeMap<ShardGroupId, CommitteeTransition> {
    let epoch = state.current_epoch;
    let cause = if epoch.inner() > 0 && epoch.inner().is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
        TransitionCause::NaturalShuffle
    } else {
        TransitionCause::MembershipChange
    };
    let mut shard_ids: BTreeSet<ShardGroupId> = pre_shard_members.keys().copied().collect();
    shard_ids.extend(state.shard_committees.keys().copied());
    let mut transitions = BTreeMap::new();
    for shard in shard_ids {
        let prior = pre_shard_members.get(&shard).cloned().unwrap_or_default();
        let current = state
            .shard_committees
            .get(&shard)
            .map(|c| c.members.clone())
            .unwrap_or_default();
        let prior_set: BTreeSet<ValidatorId> = prior.iter().copied().collect();
        let current_set: BTreeSet<ValidatorId> = current.iter().copied().collect();
        if prior_set != current_set {
            transitions.insert(
                shard,
                CommitteeTransition {
                    from: prior,
                    to: current,
                    cause,
                    at_slot: epoch,
                },
            );
        }
    }
    transitions
}
