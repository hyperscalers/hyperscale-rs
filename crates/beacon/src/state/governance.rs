//! Per-epoch network-parameter vote tally.
//!
//! The witness fold records each epoch's `ParamVote`s into
//! [`BeaconState::param_votes`](BeaconState). Once per
//! normal epoch [`tally_param_votes`] reads the accumulated slots, applies
//! any proposal a stake majority backs at this epoch, and prunes spent
//! votes. The outcome is a pure function of the live votes and pool
//! stakes — re-derived every epoch — so every replica agrees, a
//! flip-flopping pool can't sneak a change through, and there is nothing
//! to unschedule.

use std::collections::BTreeMap;

use hyperscale_types::{BeaconState, NetworkParams};

/// Decide the params governing the next epoch and stage them into
/// [`BeaconState::next_params`], then prune spent votes.
///
/// Resolved one epoch ahead — the same lookahead discipline as
/// `next_shard_committees`: at epoch E this tallies proposals naming
/// `E + 1`, so a change a majority backs is frozen into the next epoch's
/// topology snapshot before any block resolves against it. `apply_epoch`
/// promotes the result into [`BeaconState::params`] at `E + 1`, so the
/// change still takes effect at its `activate_at`; only the decision (and
/// the vote deadline) lands an epoch earlier.
///
/// Votes are bucketed by their proposed `(params, activate_at)` tuple,
/// filtered to those naming the next epoch. Because each pool backs
/// exactly one tuple the buckets are disjoint, so at most one can exceed
/// half of total pool stake; abstaining stake sits in the denominator,
/// never a bucket, so a change needs an outright majority of all stake —
/// not just of votes cast. Absent a majority the next epoch inherits the
/// current params. Every vote naming the next epoch or earlier is then
/// pruned: applied or expired, it is spent, and only later proposals stay
/// live.
pub(super) fn tally_param_votes(state: &mut BeaconState) {
    let target = state.current_epoch.next();

    // Bucket the votes naming the next epoch by their proposed params,
    // summing each bucket's backing pool stake.
    let mut buckets: BTreeMap<NetworkParams, u128> = BTreeMap::new();
    for (pool_id, proposal) in &state.param_votes {
        if proposal.activate_at != target {
            continue;
        }
        let weight = state
            .pools
            .get(pool_id)
            .map_or(0, |pool| pool.total_stake.attos());
        let bucket = buckets.entry(proposal.params).or_insert(0);
        *bucket = bucket.saturating_add(weight);
    }

    // Total pool stake is the denominator; a bucket wins iff it holds
    // strictly more than the rest of the stake combined. Each backing
    // vote validated its params when recorded; a final bounds check keeps
    // an invalid value out even if that gate ever loosens. Absent a valid
    // winner the next epoch carries the current params forward.
    let total = state.pools.values().fold(0u128, |acc, pool| {
        acc.saturating_add(pool.total_stake.attos())
    });
    let winner = buckets
        .into_iter()
        .find(|&(_, backing)| backing > total.saturating_sub(backing))
        .map(|(params, _)| params)
        .filter(|params| params.validate().is_ok());
    state.next_params = winner.unwrap_or(state.params);

    state
        .param_votes
        .retain(|_, proposal| proposal.activate_at > target);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BeaconState, Epoch, NetworkParams, ParamProposal, ParamVote, ReshapeThresholds, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId,
    };

    use super::tally_param_votes;
    use crate::state::test_fixtures::{empty_state, net};
    use crate::state::witness::apply_shard_payload;

    const HIGH: u64 = 1_000_000;

    fn proposal(split_bytes: u64, activate_at: u64) -> ParamProposal {
        ParamProposal {
            params: NetworkParams {
                reshape_thresholds: ReshapeThresholds { split_bytes },
            },
            activate_at: Epoch::new(activate_at),
        }
    }

    /// A state at `current_epoch` with one pool per `(id, stake_attos)`.
    fn state_with_pools(current_epoch: u64, pools: &[(u32, u128)]) -> BeaconState {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(current_epoch);
        for &(id, stake) in pools {
            state.pools.insert(
                StakePoolId::new(id),
                StakePool {
                    id: StakePoolId::new(id),
                    total_stake: Stake::from_attos(stake),
                    validators: BTreeSet::new(),
                    pending_withdrawals: Vec::new(),
                },
            );
        }
        state
    }

    fn cast(state: &mut BeaconState, pool: u32, proposal: Option<ParamProposal>) {
        apply_shard_payload(
            state,
            &net(),
            ShardId::ROOT,
            &ShardWitnessPayload::ParamVote(ParamVote {
                pool: StakePoolId::new(pool),
                proposal,
            }),
        );
    }

    // ─── fold arm: record / replace / clear / reject ─────────────────────

    #[test]
    fn fold_records_replaces_and_clears_a_pools_vote() {
        let mut state = state_with_pools(3, &[(0, 100)]);

        cast(&mut state, 0, Some(proposal(HIGH, 5)));
        assert_eq!(state.param_votes[&StakePoolId::new(0)], proposal(HIGH, 5));

        // A new vote replaces the pool's one slot.
        cast(&mut state, 0, Some(proposal(HIGH * 2, 6)));
        assert_eq!(
            state.param_votes[&StakePoolId::new(0)],
            proposal(HIGH * 2, 6),
        );

        // Clearing removes the slot.
        cast(&mut state, 0, None);
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn fold_drops_votes_for_unknown_pool_past_epoch_or_bad_bounds() {
        let mut state = state_with_pools(3, &[(0, 100)]);

        // Unknown pool — never recorded.
        cast(&mut state, 99, Some(proposal(HIGH, 5)));
        assert!(state.param_votes.is_empty());

        // Activation this epoch or earlier — undecidable (a change is
        // decided at `activate_at - 1`), so dead on arrival.
        cast(&mut state, 0, Some(proposal(HIGH, 2)));
        assert!(state.param_votes.is_empty());
        cast(&mut state, 0, Some(proposal(HIGH, 3)));
        assert!(state.param_votes.is_empty());

        // Out-of-bounds params (zero split threshold) — never recorded.
        cast(&mut state, 0, Some(proposal(0, 5)));
        assert!(state.param_votes.is_empty());

        // Activation next epoch is the earliest decidable — recorded.
        cast(&mut state, 0, Some(proposal(HIGH, 4)));
        assert_eq!(state.param_votes[&StakePoolId::new(0)], proposal(HIGH, 4));
    }

    // ─── tally: majority, abstention, disjoint buckets ───────────────────

    #[test]
    fn majority_of_total_stake_stages_the_change_for_next_epoch() {
        // A holds 60 of 100; its lone vote is an outright majority. The
        // proposal names epoch 5, so the epoch-4 tally stages it into
        // `next_params` for promotion at epoch 5.
        let mut state = state_with_pools(4, &[(0, 60), (1, 40)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.next_params.reshape_thresholds.split_bytes, HIGH);
        // Decided, so spent.
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn sub_majority_leaves_next_params_inheriting_current() {
        // A holds 40 of 100; 40 is not a majority of the total, so the next
        // epoch inherits the current params.
        let mut state = state_with_pools(4, &[(0, 40), (1, 60)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.next_params, state.params);
        // Still spent — its decision epoch has passed.
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn abstaining_stake_counts_in_the_denominator() {
        // Two pools back the same proposal with 60 combined; a third pool
        // abstains with 50. 60 > 50, so the change is staged.
        let mut majority = state_with_pools(4, &[(0, 30), (1, 30), (2, 50)]);
        majority
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        majority
            .param_votes
            .insert(StakePoolId::new(1), proposal(HIGH, 5));
        tally_param_votes(&mut majority);
        assert_eq!(majority.next_params.reshape_thresholds.split_bytes, HIGH);

        // Same backers but the abstaining pool now holds 70: 60 is no
        // longer an outright majority, so the next epoch inherits.
        let mut shy = state_with_pools(4, &[(0, 30), (1, 30), (2, 70)]);
        shy.param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        shy.param_votes
            .insert(StakePoolId::new(1), proposal(HIGH, 5));
        tally_param_votes(&mut shy);
        assert_eq!(shy.next_params, shy.params);
    }

    #[test]
    fn split_coalitions_in_disjoint_buckets_reach_no_majority() {
        // Two proposals each draw a plurality but neither a majority.
        let mut state = state_with_pools(4, &[(0, 40), (1, 35), (2, 25)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        state
            .param_votes
            .insert(StakePoolId::new(1), proposal(HIGH * 2, 5));
        // Pool 2 abstains.
        tally_param_votes(&mut state);
        assert_eq!(state.next_params, state.params);
    }

    // ─── activation epoch + pruning ──────────────────────────────────────

    #[test]
    fn change_is_decided_exactly_one_epoch_before_activation() {
        let mut state = state_with_pools(3, &[(0, 100)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        // Epoch 3: the proposal names epoch 5, decided at epoch 4 — too
        // early, so nothing stages and the vote survives.
        tally_param_votes(&mut state);
        assert_eq!(state.next_params, state.params);
        assert_eq!(state.param_votes[&StakePoolId::new(0)], proposal(HIGH, 5));

        // Epoch 4: it's staged into `next_params` and the spent vote is
        // pruned. `apply_epoch` promotes it into `params` at epoch 5.
        state.current_epoch = Epoch::new(4);
        tally_param_votes(&mut state);
        assert_eq!(state.next_params.reshape_thresholds.split_bytes, HIGH);
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn a_vote_whose_decision_epoch_passed_is_pruned_unapplied() {
        // Folded late: the tally for epoch 6 (deciding epoch 7) never sees
        // an epoch-5 proposal whose decision epoch (4) is long gone.
        let mut state = state_with_pools(6, &[(0, 100)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.next_params, state.params);
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn tally_defensively_rejects_out_of_bounds_winner() {
        // A majority-backed but out-of-bounds proposal (inserted directly,
        // bypassing the fold's record-time guard) is not staged.
        let mut state = state_with_pools(4, &[(0, 100)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(0, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.next_params, state.params);
        assert!(state.param_votes.is_empty());
    }
}
