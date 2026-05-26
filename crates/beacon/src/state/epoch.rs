//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconCert, BeaconProposal, BeaconState, CertifiedBeaconBlock, Epoch, NetworkDefinition,
    ShardGroupId, SlotEffects, TransitionCause, ValidatorId,
};

use crate::state::committee::{diff_shard_committees, resample_beacon_committee, run_shuffle_step};
use crate::state::lifecycle::{auto_reactivate, auto_ready_timeout, distribute_epoch_rewards};
use crate::state::vrf::filter_and_roll_randomness;
use crate::state::withdrawals::complete_pending_withdrawals;
use crate::state::witness::ingest_witnesses;

/// Discriminator for [`apply_epoch`] — distinguishes a Normal epoch
/// from a Skip epoch (empty proposal set, committee resampled with
/// [`TransitionCause::Skip`]).
///
/// The authenticating [`BeaconCert`](hyperscale_types::BeaconCert) is
/// not threaded through — by the time `adopt_block` calls `apply_epoch`
/// the cert has already authenticated the block. This enum carries
/// only the structural information the state pipeline needs:
/// committed-proposal payload and the Normal-vs-Skip discriminator
/// that picks the right [`TransitionCause`] on the committee transition.
#[derive(Debug, Clone, Copy)]
pub enum ApplyEpochInput<'a> {
    /// Normal epoch with the SPC-agreed proposal set.
    Normal {
        /// Committed proposals from SPC's Agreement output.
        committed: &'a [(ValidatorId, BeaconProposal)],
    },
    /// Skip epoch — pool-quorum abandonment of the epoch. Pipeline
    /// runs over an empty proposal set; committee resamples under
    /// [`TransitionCause::Skip`].
    Skip,
}

/// Pick the [`ApplyEpochInput`] for a certified block.
///
/// # Panics
///
/// Panics on `BeaconCert::Genesis` — callers must filter genesis blocks
/// before adoption.
#[must_use]
pub fn apply_input_for(block: &CertifiedBeaconBlock) -> ApplyEpochInput<'_> {
    match block.cert() {
        BeaconCert::Normal(_) => ApplyEpochInput::Normal {
            committed: block.block().committed_proposals(),
        },
        BeaconCert::Skip(_) => ApplyEpochInput::Skip,
        BeaconCert::Genesis(_) => panic!("apply_input_for called on Genesis block"),
    }
}

/// Apply one epoch to `state`.
///
/// Pure deterministic function of `(state, network, epoch, input)` —
/// every honest party with byte-identical inputs lands at byte-identical
/// state. The full pipeline runs on both Normal and Skip; Skip
/// degenerates to "empty proposal set" — every downstream stage handles
/// an empty input naturally (VRF roll uses just the hash chain, witness
/// ingest is a no-op, etc.).
///
/// # Panics
///
/// Panics if `epoch <= state.current_epoch`. The epoch watermark must
/// strictly advance: a regressed or repeated epoch from the runner
/// would silently corrupt epoch-difference math (cooldowns, unbonding,
/// ready timeout) and replay witnesses against a watermark that
/// already accounts for them. Genesis sits at `current_epoch =
/// GENESIS` and the first apply is `epoch > GENESIS`, so strict `>` is
/// the right bound. Tests sometimes skip slots, so we don't require
/// strict-linear `epoch == current_epoch + 1`.
pub fn apply_epoch(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    input: ApplyEpochInput<'_>,
) -> SlotEffects {
    assert!(
        epoch > state.current_epoch,
        "apply_epoch regression: epoch {epoch} <= state.current_epoch {}",
        state.current_epoch,
    );
    // Set `current_epoch` before the pipeline runs so every downstream
    // helper (including `pool_draw`'s seed binding) reads "the epoch
    // I'm in," not "the epoch before mine."
    state.current_epoch = epoch;

    // Snapshot each shard's member list before the pipeline runs so the
    // end-of-epoch set-diff against this snapshot can surface
    // membership changes through `SlotEffects.shard_committee_transitions`.
    let pre_shard_members: BTreeMap<ShardGroupId, Vec<ValidatorId>> = state
        .shard_committees
        .iter()
        .map(|(s, c)| (*s, c.members.clone()))
        .collect();

    let (committed, transition_cause): (&[_], TransitionCause) = match input {
        ApplyEpochInput::Normal { committed } => (committed, TransitionCause::NaturalShuffle),
        ApplyEpochInput::Skip => (&[], TransitionCause::Skip),
    };

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
    let witness = ingest_witnesses(state, network, &vrf.accepted);
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    let rewards_credited = distribute_epoch_rewards(state);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);
    let beacon_committee_transition =
        resample_beacon_committee(state, &BTreeSet::new(), transition_cause);

    let mut jailed = vrf.jailed;
    jailed.extend(witness.jailed);
    let mut deactivated = witness.deactivated;
    deactivated.extend(withdrawal.deactivated);
    let mut readied = witness.readied;
    readied.extend(timeout_readied);

    let shard_committee_transitions = diff_shard_committees(state, &pre_shard_members);

    SlotEffects {
        registered: witness.registered,
        deactivated,
        jailed,
        unjailed: witness.unjailed,
        reactivated,
        readied,
        rejected_reveals: vrf.rejected_reveals,
        rewards_credited,
        shard_committee_transitions,
        committee_changed: true,
        beacon_committee_transition: Some(beacon_committee_transition),
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{Epoch, TransitionCause, ValidatorId};

    use super::super::test_fixtures::{net, single_pool_state};
    use super::*;

    // ─── apply_epoch regression check + epoch advance ──────────────────────

    /// `apply_epoch` rejects a epoch that doesn't strictly advance
    /// `state.current_epoch`. Catches runner bugs that replay or
    /// re-order SPC commits before the chain-difference math
    /// (cooldown, unbonding, ready-timeout) silently underflows.
    #[test]
    #[should_panic(expected = "apply_epoch regression")]
    fn apply_epoch_panics_on_slot_replay() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(5),
            ApplyEpochInput::Normal { committed: &[] },
        );
        // Replay of epoch 5: current_epoch is now 5, so epoch=5 is
        // neither advance nor regression — must panic.
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(5),
            ApplyEpochInput::Normal { committed: &[] },
        );
    }

    #[test]
    #[should_panic(expected = "apply_epoch regression")]
    fn apply_epoch_panics_on_slot_going_backwards() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(5),
            ApplyEpochInput::Normal { committed: &[] },
        );
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(3),
            ApplyEpochInput::Normal { committed: &[] },
        );
    }

    #[test]
    fn apply_epoch_advances_current_epoch() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(7),
            ApplyEpochInput::Normal { committed: &[] },
        );
        assert_eq!(state.current_epoch, Epoch::new(7));
    }

    // ─── apply_epoch Skip-path coverage ────────────────────────────────

    /// `ApplyEpochInput::Skip` runs the same pipeline as Normal over an
    /// empty proposal set but tags the committee transition with
    /// `TransitionCause::Skip` for observability. The committee is
    /// still resampled (epoch counter advances, randomness rolls,
    /// shuffle / shard rotation all fire) — only the cause label
    /// distinguishes Skip from an empty Normal epoch.
    #[test]
    fn apply_epoch_skip_path_resamples_with_skip_cause() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let next = state.current_epoch.next();
        let effects = apply_epoch(&mut state, &net(), next, ApplyEpochInput::Skip);

        assert_eq!(state.current_epoch, next);
        let transition = effects
            .beacon_committee_transition
            .expect("skip emits a committee transition");
        assert_eq!(transition.cause, TransitionCause::Skip);
        assert_eq!(transition.at_slot, next);
    }

    /// Empty-Normal and Skip diverge only on `TransitionCause`. The
    /// rest of `SlotEffects` and the post-state should be identical
    /// because the pipeline runs over the same inputs (empty
    /// proposals, same randomness).
    #[test]
    fn apply_epoch_skip_and_empty_normal_diverge_only_on_transition_cause() {
        let baseline_state = single_pool_state(4);
        let committee: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();

        let mut normal_state = baseline_state.clone();
        normal_state.committee = committee.clone();
        let next = normal_state.current_epoch.next();
        let normal_effects = apply_epoch(
            &mut normal_state,
            &net(),
            next,
            ApplyEpochInput::Normal { committed: &[] },
        );

        let mut skip_state = baseline_state;
        skip_state.committee = committee;
        let skip_effects = apply_epoch(&mut skip_state, &net(), next, ApplyEpochInput::Skip);

        // Post-state should be byte-identical: both runs roll
        // randomness via the empty-VRF hash chain, run the same
        // lifecycle stages, and resample the committee from the same
        // post-shuffle eligible set.
        assert_eq!(normal_state, skip_state);
        // Effects diverge only on the committee-transition cause.
        let n_trans = normal_effects.beacon_committee_transition.unwrap();
        let s_trans = skip_effects.beacon_committee_transition.unwrap();
        assert_eq!(n_trans.cause, TransitionCause::NaturalShuffle);
        assert_eq!(s_trans.cause, TransitionCause::Skip);
        assert_eq!(n_trans.from, s_trans.from);
        assert_eq!(n_trans.to, s_trans.to);
        assert_eq!(n_trans.at_slot, s_trans.at_slot);
    }
}
