//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconCert, BeaconProposal, BeaconState, CertifiedBeaconBlock, Epoch, NetworkDefinition,
    ShardBoundary, ShardEpochContribution, ShardId, SlotEffects, TransitionCause, ValidatorId,
    Verifiable, WeightedTimestamp,
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
        /// Per-shard canonical boundary contributions assembled for this
        /// block. Bound to the committed `boundary_qcs` by block hash and
        /// folded into [`BeaconState::boundaries`].
        shard_contributions: &'a BTreeMap<ShardId, ShardEpochContribution>,
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
            shard_contributions: block.block().shard_contributions(),
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

    // Promote the lookahead committee into the active slot before the
    // pipeline runs. `next_shard_committees` was finalized one epoch ago
    // and governs this epoch's shard consensus; freeze it here as
    // `shard_committees`. The pipeline below then evolves
    // `next_shard_committees` into the lookahead for the epoch after this
    // one — so the committee for any window is fixed a full epoch before
    // the window opens, and a validator jailed this epoch leaves the
    // committee one epoch out rather than mid-window.
    state.shard_committees = state.next_shard_committees.clone();

    // Snapshot each shard's member list before the pipeline runs so the
    // end-of-epoch set-diff against this snapshot can surface
    // membership changes through `SlotEffects.shard_committee_transitions`.
    let pre_shard_members: BTreeMap<ShardId, Vec<ValidatorId>> = state
        .next_shard_committees
        .iter()
        .map(|(s, c)| (*s, c.members.clone()))
        .collect();

    let (committed, transition_cause): (&[_], TransitionCause) = match input {
        ApplyEpochInput::Normal { committed, .. } => (committed, TransitionCause::NaturalShuffle),
        ApplyEpochInput::Skip => (&[], TransitionCause::Skip),
    };

    // Fold this epoch's per-shard boundaries. A `Skip` carries every
    // prior boundary forward untouched (no record, no miss bump); a
    // Normal epoch records fresh boundaries and bumps the miss counter
    // for any active shard with no qualifying contribution.
    if let ApplyEpochInput::Normal {
        committed,
        shard_contributions,
    } = input
    {
        record_boundaries(state, epoch, committed, shard_contributions);
    }

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

/// Canonical end-of-epoch [`WeightedTimestamp`] derived from `epoch` and
/// the chain's configured epoch duration. Beacon blocks carry no explicit
/// `weighted_timestamp` field; the value is `epoch.inner() ×
/// epoch_duration_ms` by construction, matching how shards stamp their
/// accumulators' eligibility windows. Both the boundary fold and the
/// proposer's boundary sourcing read the cut from here.
pub const fn epoch_end_weighted_timestamp(
    epoch: Epoch,
    epoch_duration_ms: u64,
) -> WeightedTimestamp {
    WeightedTimestamp::from_millis(epoch.inner().saturating_mul(epoch_duration_ms))
}

/// The largest epoch-boundary weighted timestamp strictly below `wt`
/// (`k × epoch_duration_ms` for the greatest `k ≥ 1`), or `None` when no
/// boundary lies below it. The boundary block's predecessor must sit
/// at/before this for the block to be the first across the boundary.
pub const fn epoch_boundary_below(wt: u64, epoch_duration_ms: u64) -> Option<u64> {
    if epoch_duration_ms == 0 || wt == 0 {
        return None;
    }
    let k = (wt - 1) / epoch_duration_ms;
    if k == 0 {
        None
    } else {
        Some(k * epoch_duration_ms)
    }
}

/// Record each shard's epoch boundary from the committed contributions.
///
/// A contribution's boundary header is authenticated by a committed
/// boundary QC. For each shard, some committed proposal must carry a QC
/// that (1) names this exact block (`hash(boundary_header) ==
/// qc.block_hash`), (2) is a valid `2f+1` quorum of the shard's committee,
/// and (3) places the boundary as the first block across the epoch cut —
/// the predecessor at/before the cut, the boundary across it
/// (`header.parent_qc.wt ≤ epoch_end_wt < qc.wt`), unique by chain
/// monotonicity. A shard with a qualifying boundary records its
/// `state_root` and witness leaf count and resets its miss counter; an
/// active shard with none carries its prior record forward and bumps
/// `consecutive_misses` (the "not observed crossing" signal). A forged QC
/// fails the quorum check, so its shard simply reads as missed —
/// identically on every node.
fn record_boundaries(
    state: &mut BeaconState,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
    shard_contributions: &BTreeMap<ShardId, ShardEpochContribution>,
) {
    let dur = state.chain_config.epoch_duration_ms;

    let mut refreshed: BTreeSet<ShardId> = BTreeSet::new();
    for (shard, contribution) in shard_contributions {
        let header = &contribution.boundary_header;
        let block_hash = header.hash();
        // Find a committed boundary QC that names this block. The QC's
        // quorum was checked by the remote-header pipeline that admitted
        // the boundary header, so the fold binds rather than re-verifies.
        let Some(qc) = committed.iter().find_map(|(_, proposal)| {
            proposal
                .boundary_qcs()
                .get(shard)
                .and_then(|opt| opt.as_ref())
                .map(Verifiable::as_unverified)
                .filter(|qc| qc.block_hash() == block_hash)
        }) else {
            continue;
        };
        // Require a genuine epoch crossing: the boundary block (whose
        // weighted timestamp is `qc.wt`) is the first across some epoch
        // boundary, so its predecessor sits in an earlier epoch.
        let Some(cut) = epoch_boundary_below(qc.weighted_timestamp().as_millis(), dur) else {
            continue;
        };
        let leaf_count = header.beacon_witness_leaf_count();
        let monotone = state
            .boundaries
            .get(shard)
            .is_none_or(|prior| leaf_count.inner() >= prior.witness_leaf_count.inner());
        if header.parent_qc().weighted_timestamp().as_millis() <= cut && monotone {
            state.boundaries.insert(
                *shard,
                ShardBoundary {
                    state_root: header.state_root(),
                    block_hash,
                    witness_leaf_count: leaf_count,
                    last_live_epoch: epoch,
                    consecutive_misses: 0,
                },
            );
            refreshed.insert(*shard);
        }
    }

    // Active shards with no fresh boundary carry their prior record
    // forward and bump the miss counter (the "not observed crossing"
    // signal). The shard set is fixed here, so every tracked boundary
    // belongs to an active shard.
    for (shard, boundary) in &mut state.boundaries {
        if !refreshed.contains(shard) {
            boundary.consecutive_misses = boundary.consecutive_misses.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconProposal, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader,
        BlockHeight, CertificateRoot, Epoch, Hash, InFlightCount, LocalReceiptRoot,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardBoundary, ShardId,
        SignerBitfield, StateRoot, TransactionRoot, TransitionCause, ValidatorId, VrfProof,
        WeightedTimestamp, zero_bls_signature,
    };

    use super::super::test_fixtures::{net, single_pool_state};
    use super::*;

    // ─── boundary fold ──────────────────────────────────────────────────────

    /// A shard block header at `height` whose predecessor's weighted
    /// timestamp (on its parent QC) is `pred_wt`, carrying `state_root` and
    /// witness `leaf_count`.
    fn boundary_block(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> BlockHeader {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(pred_wt),
        );
        BlockHeader::new(
            shard,
            BlockHeight::new(height),
            BlockHash::ZERO,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            state_root,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::new(leaf_count),
        )
    }

    /// A QC naming `header` with weighted timestamp `wt`.
    fn qc_over(header: &BlockHeader, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            header.hash(),
            header.shard_id(),
            header.height(),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(wt),
        )
    }

    /// A boundary block (predecessor wt 900 ≤ the 1000 cut, own wt 1500
    /// past it) bound to a committed proposal's QC and seated as a
    /// contribution records the shard's anchor and clears its miss counter.
    #[test]
    fn record_boundaries_records_an_epoch_crossing() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        let anchor = StateRoot::from_raw(Hash::from_bytes(b"anchor"));
        let b = boundary_block(shard, 5, 900, anchor, 7);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            Vec::new(),
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> =
            std::iter::once((shard, ShardEpochContribution { boundary_header: b })).collect();

        record_boundaries(&mut state, Epoch::new(1), &committed, &contributions);

        let recorded = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(recorded.state_root, anchor);
        assert_eq!(recorded.witness_leaf_count, BeaconWitnessLeafCount::new(7));
        assert_eq!(recorded.last_live_epoch, Epoch::new(1));
        assert_eq!(recorded.consecutive_misses, 0);
    }

    /// A contribution whose predecessor sits past the cut (1200 > 1000) is
    /// not a crossing, so the active shard's miss counter advances instead.
    #[test]
    fn record_boundaries_bumps_miss_when_no_crossing() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
            },
        );

        let b = boundary_block(shard, 5, 1_200, StateRoot::ZERO, 0);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            Vec::new(),
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> =
            std::iter::once((shard, ShardEpochContribution { boundary_header: b })).collect();

        record_boundaries(&mut state, Epoch::new(1), &committed, &contributions);

        assert_eq!(state.boundaries.get(&shard).unwrap().consecutive_misses, 1,);
    }

    // ─── apply_epoch regression check + epoch advance ──────────────────────

    /// `apply_epoch` rejects an epoch that doesn't strictly advance
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
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        // Replay of epoch 5: current_epoch is now 5, so epoch=5 is
        // neither advance nor regression — must panic.
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(5),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
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
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(3),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
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
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
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
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
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
