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

/// Tally this epoch's parameter votes and apply any proposal a strict
/// majority of total pool stake backs at the current epoch, then prune
/// spent votes.
///
/// Votes are bucketed by their proposed `(params, activate_at)` tuple,
/// filtered to those naming this epoch. Because each pool backs exactly
/// one tuple the buckets are disjoint, so at most one can exceed half of
/// total pool stake; abstaining stake sits in the denominator, never a
/// bucket, so a change needs an outright majority of all stake — not just
/// of votes cast. Every vote naming this epoch or earlier is then pruned:
/// applied or expired, it is spent, and only future proposals stay live.
pub(super) fn tally_param_votes(state: &mut BeaconState) {
    let current = state.current_epoch;

    // Bucket the votes naming this epoch by their proposed params, summing
    // each bucket's backing pool stake.
    let mut buckets: BTreeMap<NetworkParams, u128> = BTreeMap::new();
    for (pool_id, proposal) in &state.param_votes {
        if proposal.activate_at != current {
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
    // strictly more than the rest of the stake combined.
    let total = state.pools.values().fold(0u128, |acc, pool| {
        acc.saturating_add(pool.total_stake.attos())
    });
    let winner = buckets
        .into_iter()
        .find(|&(_, backing)| backing > total.saturating_sub(backing))
        .map(|(params, _)| params);
    if let Some(params) = winner {
        // Each backing vote validated its params when recorded; a final
        // bounds check keeps an invalid value off `state.params` even if
        // that gate ever loosens.
        if params.validate().is_ok() {
            state.params = params;
        }
    }

    state
        .param_votes
        .retain(|_, proposal| proposal.activate_at > current);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BeaconState, Epoch, NetworkParams, ParamProposal, ParamVote, ReshapeThresholds, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId,
    };

    use super::tally_param_votes;
    use crate::state::test_fixtures::empty_state;
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

        // Activation already in the past — dead on arrival.
        cast(&mut state, 0, Some(proposal(HIGH, 2)));
        assert!(state.param_votes.is_empty());

        // Out-of-bounds params (zero split threshold) — never recorded.
        cast(&mut state, 0, Some(proposal(0, 5)));
        assert!(state.param_votes.is_empty());

        // Activation at the current epoch is allowed (it tallies this epoch).
        cast(&mut state, 0, Some(proposal(HIGH, 3)));
        assert_eq!(state.param_votes[&StakePoolId::new(0)], proposal(HIGH, 3));
    }

    // ─── tally: majority, abstention, disjoint buckets ───────────────────

    #[test]
    fn majority_of_total_stake_applies_the_change() {
        // A holds 60 of 100; its lone vote is an outright majority.
        let mut state = state_with_pools(5, &[(0, 60), (1, 40)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.params.reshape_thresholds.split_bytes, HIGH);
        // Spent once tallied.
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn sub_majority_does_not_change_the_param() {
        // A holds 40 of 100; 40 is not a majority of the total.
        let mut state = state_with_pools(5, &[(0, 40), (1, 60)]);
        let before = state.params;
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.params, before);
        // Still spent — its activation epoch has passed.
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn abstaining_stake_counts_in_the_denominator() {
        // Two pools back the same proposal with 60 combined; a third pool
        // abstains with 50. 60 > 50, so the change applies.
        let mut majority = state_with_pools(5, &[(0, 30), (1, 30), (2, 50)]);
        majority
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        majority
            .param_votes
            .insert(StakePoolId::new(1), proposal(HIGH, 5));
        tally_param_votes(&mut majority);
        assert_eq!(majority.params.reshape_thresholds.split_bytes, HIGH);

        // Same backers but the abstaining pool now holds 70: 60 is no
        // longer an outright majority, so nothing changes.
        let mut shy = state_with_pools(5, &[(0, 30), (1, 30), (2, 70)]);
        let before = shy.params;
        shy.param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        shy.param_votes
            .insert(StakePoolId::new(1), proposal(HIGH, 5));
        tally_param_votes(&mut shy);
        assert_eq!(shy.params, before);
    }

    #[test]
    fn split_coalitions_in_disjoint_buckets_reach_no_majority() {
        // Two proposals each draw a plurality but neither a majority.
        let mut state = state_with_pools(5, &[(0, 40), (1, 35), (2, 25)]);
        let before = state.params;
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));
        state
            .param_votes
            .insert(StakePoolId::new(1), proposal(HIGH * 2, 5));
        // Pool 2 abstains.
        tally_param_votes(&mut state);
        assert_eq!(state.params, before);
    }

    // ─── activation epoch + pruning ──────────────────────────────────────

    #[test]
    fn change_flips_exactly_at_the_named_activation_epoch() {
        let mut state = state_with_pools(4, &[(0, 100)]);
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        // Epoch 4: the proposal names epoch 5, so nothing happens and the
        // vote survives.
        let before = state.params;
        tally_param_votes(&mut state);
        assert_eq!(state.params, before);
        assert_eq!(state.param_votes[&StakePoolId::new(0)], proposal(HIGH, 5));

        // Epoch 5: it activates and the spent vote is pruned.
        state.current_epoch = Epoch::new(5);
        tally_param_votes(&mut state);
        assert_eq!(state.params.reshape_thresholds.split_bytes, HIGH);
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn a_vote_whose_activation_epoch_passed_is_pruned_unapplied() {
        // Folded late: the tally for epoch 6 never sees an epoch-5 proposal.
        let mut state = state_with_pools(6, &[(0, 100)]);
        let before = state.params;
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(HIGH, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.params, before);
        assert!(state.param_votes.is_empty());
    }

    #[test]
    fn tally_defensively_rejects_out_of_bounds_winner() {
        // A majority-backed but out-of-bounds proposal (inserted directly,
        // bypassing the fold's record-time guard) is not applied.
        let mut state = state_with_pools(5, &[(0, 100)]);
        let before = state.params;
        state
            .param_votes
            .insert(StakePoolId::new(0), proposal(0, 5));

        tally_param_votes(&mut state);
        assert_eq!(state.params, before);
        assert!(state.param_votes.is_empty());
    }
}
