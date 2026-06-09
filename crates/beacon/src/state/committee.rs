//! Shuffle step, beacon-committee resample, and per-shard membership
//! diff.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, CommitteeTransition, SHUFFLE_INTERVAL_EPOCHS, ShardId, TransitionCause,
    ValidatorId, ValidatorStatus,
};
use rand::RngExt;

use crate::sampling::{prng_from, sample_committee};
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
/// Shards iterate in sorted [`ShardId`] order; the victim within
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
    let shard_ids: Vec<ShardId> = state.next_shard_committees.keys().copied().collect();
    for shard in shard_ids {
        // Bind the candidate set to validators whose status records
        // *this* shard. The global invariant `members ⇔ status ==
        // OnShard { shard: s, .. }` holds today; matching the shard
        // here means a future bug that drops a transition site (a
        // stale `members` entry pointing at a different shard) fails
        // to a skipped shuffle rather than picking from the wrong
        // shard.
        let ready_members: Vec<ValidatorId> = state
            .next_shard_committees
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
            .next_shard_committees
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
/// natural [`beacon_eligible`] filter — empty under both the natural
/// resample and the Skip-cert path; carried so future schedulers that
/// want to exclude additional validators (e.g. operator-driven
/// quarantine) have a single seam to plumb through. `cause` tags the
/// resulting transition.
pub(super) fn resample_beacon_committee(
    state: &mut BeaconState,
    excluded: &BTreeSet<ValidatorId>,
    cause: TransitionCause,
) -> CommitteeTransition {
    let prior = std::mem::take(&mut state.committee);
    let eligible: Vec<ValidatorId> = state
        .beacon_eligible()
        .into_iter()
        .filter(|id| !excluded.contains(id))
        .collect();
    let committee_size = state.chain_config.beacon_committee_size as usize;
    state.committee = sample_committee(&eligible, state.randomness.as_bytes(), committee_size);
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
    pre_shard_members: &BTreeMap<ShardId, Vec<ValidatorId>>,
) -> BTreeMap<ShardId, CommitteeTransition> {
    let epoch = state.current_epoch;
    let cause = if epoch.inner() > 0 && epoch.inner().is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
        TransitionCause::NaturalShuffle
    } else {
        TransitionCause::MembershipChange
    };
    let mut shard_ids: BTreeSet<ShardId> = pre_shard_members.keys().copied().collect();
    shard_ids.extend(state.next_shard_committees.keys().copied());
    let mut transitions = BTreeMap::new();
    for shard in shard_ids {
        let prior = pre_shard_members.get(&shard).cloned().unwrap_or_default();
        let current = state
            .next_shard_committees
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BEACON_SIGNER_COUNT, BeaconState, Epoch, JailReason, MIN_STAKE_FLOOR, Randomness,
        SHUFFLE_INTERVAL_EPOCHS, ShardCommittee, ShardId, Stake, StakePool, StakePoolId,
        TransitionCause, ValidatorId, ValidatorStatus,
    };

    use crate::state::test_fixtures::{
        apply_next_epoch, empty_state, single_pool_state, validator_record,
    };
    // ─── run_shuffle_step + shard_committee_transitions diff ─────────────

    /// Two shards, `per_shard` ready members each, `pool_extras`
    /// `Pooled` validators kept in reserve so refills have stock.
    /// Pool stake is sized generously to keep `min_stake` at the floor.
    fn multi_shard_state(shard_count: u64, per_shard: u64, pool_extras: u64) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let total = shard_count * per_shard + pool_extras;
        let mut pool_validators = BTreeSet::new();
        let mut next_id = 0u64;
        for s in 0..shard_count {
            let shard = ShardId::leaf(1, s);
            let mut members = Vec::new();
            for _ in 0..per_shard {
                let id = ValidatorId::new(next_id);
                pool_validators.insert(id);
                members.push(id);
                state.validators.insert(
                    id,
                    validator_record(
                        next_id,
                        0,
                        ValidatorStatus::OnShard {
                            shard,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    ),
                );
                next_id += 1;
            }
            state
                .next_shard_committees
                .insert(shard, ShardCommittee { members });
        }
        for _ in 0..pool_extras {
            let id = ValidatorId::new(next_id);
            pool_validators.insert(id);
            state
                .validators
                .insert(id, validator_record(next_id, 0, ValidatorStatus::Pooled));
            next_id += 1;
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                // Generous stake so `min_stake` stays clamped at the
                // floor and no admission gate trips during the test.
                total_stake: Stake::from_attos(u128::from(total) * MIN_STAKE_FLOOR.attos() * 4),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
    }

    /// Off-interval epoch: shard committees and the pool stay
    /// byte-identical; no transition emitted.
    #[test]
    fn shuffle_doesnt_fire_off_interval() {
        // Land at epoch 1 — not a multiple of SHUFFLE_INTERVAL_EPOCHS.
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Park a Pooled extra so a hypothetical refill would have stock.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .validators
            .insert(ValidatorId::new(99));
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        let initial_members = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let initial_pool = state.pooled_validators();

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.next_shard_committees[&ShardId::leaf(1, 0)].members,
            initial_members
        );
        assert_eq!(state.pooled_validators(), initial_pool);
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// On a `SHUFFLE_INTERVAL_EPOCHS` boundary, each shard rotates one
    /// of its ready `OnShard` validators back to `Pooled` and refills
    /// the freed slot via `pool_draw`.
    #[test]
    fn shuffle_rotates_one_validator_per_shard_at_interval() {
        // 2 shards × 4 ready actives + 2 pool extras = 10 validators.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let initial_shard_0 = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let initial_shard_1 = state.next_shard_committees[&ShardId::leaf(1, 1)]
            .members
            .clone();

        apply_next_epoch(&mut state, &[]);

        let final_shard_0 = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let final_shard_1 = state.next_shard_committees[&ShardId::leaf(1, 1)]
            .members
            .clone();

        // Capacity preserved.
        assert_eq!(final_shard_0.len(), 4);
        assert_eq!(final_shard_1.len(), 4);
        // Each shard saw at most one membership change (zero is
        // possible if a cross-shard rotation lands the same set
        // back).
        let shard_0_diff = final_shard_0
            .iter()
            .filter(|id| !initial_shard_0.contains(id))
            .count();
        let shard_1_diff = final_shard_1
            .iter()
            .filter(|id| !initial_shard_1.contains(id))
            .count();
        assert!(shard_0_diff <= 1, "shard 0 churned by {shard_0_diff}");
        assert!(shard_1_diff <= 1, "shard 1 churned by {shard_1_diff}");
    }

    /// Not-ready members are ineligible to be rotated out — only
    /// `OnShard { ready: true }` validators are picked.
    #[test]
    fn shuffle_picks_only_from_ready_members() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        // Mark validators 2 and 3 as not-yet-ready.
        for id in [2u64, 3] {
            state
                .validators
                .get_mut(&ValidatorId::new(id))
                .unwrap()
                .status = ValidatorStatus::OnShard {
                shard,
                ready: false,
                placed_at_epoch: Epoch::GENESIS,
            };
        }
        state.committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        // Pool extra and headroom so refill has stock and admission
        // gates stay clear.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        // Not-ready validators must still be on the shard.
        for not_ready_id in [2u64, 3] {
            assert!(
                state.next_shard_committees[&shard]
                    .members
                    .contains(&ValidatorId::new(not_ready_id)),
                "not-ready validator {not_ready_id} got shuffled out"
            );
        }
        // Exactly one of the ready members (0 or 1) was rotated out.
        let rotated = initial_members
            .iter()
            .filter(|id| !state.next_shard_committees[&shard].members.contains(id))
            .count();
        assert_eq!(rotated, 1, "exactly one ready member rotates out");
    }

    /// With the pool empty before the shuffle, the per-shard
    /// `pool_draw` must not pick the just-rotated victim and restore
    /// them. Victim flips to `Pooled` *after* the draw, so the draw
    /// sees an empty pool and returns `None` — the shard shrinks by
    /// one (no validator was available to fill).
    #[test]
    fn shuffle_avoids_self_replacement() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);
        assert!(state.pooled_validators().is_empty());

        let initial_members = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        apply_next_epoch(&mut state, &[]);

        // Shard shrunk by one — empty pool, no refill possible.
        assert_eq!(
            state.next_shard_committees[&ShardId::leaf(1, 0)]
                .members
                .len(),
            3
        );
        // Victim ended up in the pool, not back on the shard.
        let pool_now = state.pooled_validators();
        assert_eq!(pool_now.len(), 1);
        let victim = pool_now[0];
        assert!(initial_members.contains(&victim));
        assert!(
            !state.next_shard_committees[&ShardId::leaf(1, 0)]
                .members
                .contains(&victim)
        );
        assert!(matches!(
            state.validators[&victim].status,
            ValidatorStatus::Pooled,
        ));
    }

    /// On a shuffle-boundary epoch, any shard membership change is
    /// attributed to `NaturalShuffle` (the dominant cause on those
    /// epochs).
    #[test]
    fn shuffle_emits_shard_committee_transition_with_natural_shuffle_cause() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool extra so the rotation swaps in a fresh validator
        // rather than just shrinking the shard.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        let effects = apply_next_epoch(&mut state, &[]);
        let transition = effects
            .shard_committee_transitions
            .get(&ShardId::leaf(1, 0))
            .expect("shuffle on shard 0 emits a transition");
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert_eq!(transition.at_slot, Epoch::new(SHUFFLE_INTERVAL_EPOCHS));
    }

    /// Empty epoch with no witnesses and no shuffle boundary leaves
    /// shard committees untouched and emits no transitions.
    #[test]
    fn no_membership_change_emits_no_transition() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_next_epoch(&mut state, &[]);
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// The lookahead committee finalized at epoch `E`
    /// (`next_shard_committees`) becomes the active committee
    /// (`shard_committees`) at epoch `E + 1` — the one-epoch promotion
    /// that lets every shard hold its committee before the window opens.
    /// Checked across a shuffle boundary so the committee provably
    /// changes between epochs; otherwise active and lookahead coincide
    /// and the promotion proves nothing.
    #[test]
    fn next_shard_committee_promotes_to_active_one_epoch_later() {
        // 2 shards × 4 ready + 2 pool extras so the shuffle swaps rather
        // than shrinks, making the lookahead differ from the active.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(SHUFFLE_INTERVAL_EPOCHS - 1);

        // Boundary epoch: the pipeline rotates `next_shard_committees`
        // (the lookahead governing the following window); the active
        // committee is the pre-rotation set promoted in at the top of
        // `apply_epoch`.
        apply_next_epoch(&mut state, &[]);
        let lookahead = state.next_shard_committees.clone();
        assert_ne!(
            state.shard_committees, lookahead,
            "shuffle must change the lookahead so the promotion is observable"
        );

        // The following epoch promotes that lookahead into the active slot.
        apply_next_epoch(&mut state, &[]);
        assert_eq!(
            state.shard_committees, lookahead,
            "epoch E's next_shard_committees becomes epoch E+1's shard_committees"
        );
    }

    // ─── beacon_eligible + resample_beacon_committee ─────────────────────

    /// `beacon_eligible` returns exactly the `OnShard { ready: true }`
    /// validators; `Pooled`, `Jailed`, `InsufficientStake`, and
    /// not-yet-ready `OnShard` validators are all excluded.
    #[test]
    fn beacon_eligible_filters_to_on_shard_ready() {
        let shard = ShardId::leaf(1, 0);
        let mut state = empty_state();
        let ready_id = ValidatorId::new(1);
        state.validators.insert(
            ready_id,
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(2),
            validator_record(
                2,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(3),
            validator_record(3, 0, ValidatorStatus::Pooled),
        );
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(
                4,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::InsufficientStake),
        );

        assert_eq!(state.beacon_eligible(), vec![ready_id]);
    }

    /// `apply_epoch` always populates `committee_changed = true` and a
    /// `beacon_committee_transition` with `NaturalShuffle` cause anchored
    /// at the applied epoch.
    #[test]
    fn apply_epoch_populates_committee_changed_and_transition() {
        let mut state = single_pool_state(4);
        state.committee = vec![]; // start empty to make the handover visible

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.committee_changed);
        let transition = effects
            .beacon_committee_transition
            .expect("resample populates the transition");
        assert_eq!(transition.from, vec![]);
        assert_eq!(
            transition.to,
            (0u64..4).map(ValidatorId::new).collect::<Vec<_>>()
        );
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert_eq!(transition.at_slot, Epoch::new(1));
        // State carries the resampled committee.
        assert_eq!(state.committee, transition.to);
    }

    /// When `beacon_eligible` exceeds `BEACON_SIGNER_COUNT`, the
    /// resample returns exactly `BEACON_SIGNER_COUNT` validators, all
    /// drawn from the eligible set.
    #[test]
    fn resample_picks_subset_when_eligible_oversize() {
        // 2 shards × 4 ready actives = 8 eligible, BEACON_SIGNER_COUNT = 4.
        let mut state = multi_shard_state(2, 4, 0);
        let eligible: BTreeSet<ValidatorId> = state.beacon_eligible().into_iter().collect();
        assert!(eligible.len() > BEACON_SIGNER_COUNT);

        apply_next_epoch(&mut state, &[]);

        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
        for id in &state.committee {
            assert!(eligible.contains(id), "{id:?} not in eligible set");
        }
        // Sorted output (sample_committee's contract).
        let mut sorted = state.committee.clone();
        sorted.sort();
        assert_eq!(state.committee, sorted);
    }

    /// Two states with byte-identical inputs (validators, pools,
    /// randomness, `current_epoch`) produce byte-identical committees
    /// after `apply_epoch`. Pins the cross-replica determinism property
    /// the resample relies on.
    #[test]
    fn resample_is_deterministic_across_replicas() {
        let mut a = multi_shard_state(2, 4, 0);
        let mut b = multi_shard_state(2, 4, 0);
        // Same non-zero seed on both — the Fisher–Yates path activates
        // only when the eligible set exceeds `BEACON_SIGNER_COUNT`,
        // which is true here (8 > 4).
        a.randomness = Randomness::new([0x5A; 32]);
        b.randomness = Randomness::new([0x5A; 32]);

        apply_next_epoch(&mut a, &[]);
        apply_next_epoch(&mut b, &[]);

        assert_eq!(a.committee, b.committee);
        assert_eq!(a.randomness, b.randomness);
    }

    /// A validator jailed during the epoch must not appear in the
    /// resampled committee — the resample reads the post-pipeline
    /// `beacon_eligible` set.
    #[test]
    fn resample_excludes_jailed_validators() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-jail validator 0 — `beacon_eligible` excludes them on the
        // next apply.
        state
            .validators
            .get_mut(&ValidatorId::new(0))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };
        // Drop validator 0 from the shard committee too, matching the
        // global invariant.
        state
            .next_shard_committees
            .get_mut(&ShardId::leaf(1, 0))
            .unwrap()
            .members
            .retain(|v| *v != ValidatorId::new(0));

        apply_next_epoch(&mut state, &[]);

        assert!(!state.committee.contains(&ValidatorId::new(0)));
        assert_eq!(
            state.committee,
            vec![
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }
}
