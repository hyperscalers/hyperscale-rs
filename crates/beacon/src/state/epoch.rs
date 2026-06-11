//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconCert, BeaconProposal, BeaconState, BeaconWitnessLeafCount, CertifiedBeaconBlock, Epoch,
    NetworkDefinition, ShardBoundary, ShardEpochContribution, ShardId, SlotEffects,
    TransitionCause, ValidatorId,
};

use crate::rules::{canonical_boundary_qcs, chunk_bounds, is_boundary_crossing};
use crate::state::committee::{diff_shard_committees, resample_beacon_committee, run_shuffle_step};
use crate::state::lifecycle::{auto_reactivate, auto_ready_timeout, distribute_epoch_rewards};
use crate::state::vrf::filter_and_roll_randomness;
use crate::state::withdrawals::complete_pending_withdrawals;
use crate::state::witness::{WitnessOutcome, apply_contribution_witnesses, ingest_equivocations};

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
    // `shard_committees`, along with its ready-filtered consensus subset
    // resolved from statuses as they stand right now — before any of this
    // epoch's witnesses apply — so it matches what the prior state's
    // lookahead derivation computed from the same statuses. The pipeline
    // below then evolves `next_shard_committees` into the lookahead for
    // the epoch after this one — so the committee (and its consensus
    // subset) for any window is fixed a full epoch before the window
    // opens, and a validator jailed or readied this epoch changes the
    // consensus set one epoch out rather than mid-window.
    state.shard_consensus_members = state.ready_consensus_members(&state.next_shard_committees);
    state.shard_committees = state.next_shard_committees.clone();
    // Freeze each shard's beacon-witness window base under the same
    // discipline: the applied watermark as it stands before this epoch's
    // fold advances it, matching what the prior state's lookahead
    // derivation read live from the same boundaries.
    state.witness_window_bases = state.live_witness_bases();

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

    // Fold this epoch's per-shard boundaries and apply their witness
    // chunks. A `Skip` carries every prior boundary forward untouched (no
    // record, no miss bump, no witnesses); a Normal epoch records fresh
    // boundaries, applies each chunk, and bumps the miss counter for any
    // active shard with no qualifying contribution.
    let mut witness = if let ApplyEpochInput::Normal {
        committed,
        shard_contributions,
    } = input
    {
        record_boundaries(state, epoch, committed, shard_contributions)
    } else {
        WitnessOutcome::default()
    };

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
    // Equivocation evidence rides committed proposals; shard-witness lifts
    // ride the boundary contributions applied above.
    witness.extend(ingest_equivocations(state, network, &vrf.accepted));
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

/// Record each shard's epoch boundary from the committed contributions and
/// apply each boundary's witness chunk.
///
/// A contribution's boundary header is authenticated by a committed
/// boundary QC (the QC's `2f+1` is admission-gated, so the fold binds
/// rather than re-verifies). For each shard, some committed proposal must
/// carry a QC that (1) names this exact block (`hash(boundary_header) ==
/// qc.block_hash`) and (2) places the boundary as the first block across
/// the epoch cut (`header.parent_qc.wt ≤ cut < qc.wt`, unique by chain
/// monotonicity). The contribution then carries the witness **chunk**
/// `[prior, chunk_end)` — `prior = boundaries[shard].witness_leaf_count`
/// (the applied watermark), `chunk_end = min(prior + MAX_WITNESSES_PER_SHARD,
/// boundary_header.beacon_witness_leaf_count())`. The chunk must be exactly
/// those contiguous 0-based leaves, each merkle-proving into the boundary
/// root; it applies in leaf order and the watermark advances to
/// `chunk_end` (which lags the boundary's full count while a backlog
/// drains — the anchor still records the latest crossing).
///
/// A shard whose boundary qualifies and whose chunk is well-formed records
/// its anchor + advanced watermark and resets its miss counter; an active
/// shard with no qualifying, well-formed contribution carries its prior
/// record forward and bumps `consecutive_misses`. A forged QC or malformed
/// chunk simply reads as missed — identically on every node. Returns the
/// validator-status events the applied chunks produced.
fn record_boundaries(
    state: &mut BeaconState,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
    shard_contributions: &BTreeMap<ShardId, ShardEpochContribution>,
) -> WitnessOutcome {
    let dur = state.chain_config.epoch_duration_ms;
    // Bind each contribution to its shard's canonical committed QC — the
    // same selection the receiver's `contributions_well_formed` gate
    // applied — so the fold and the verifier never diverge on which QC
    // governs the boundary.
    let canonical = canonical_boundary_qcs(committed.iter().map(|(_, p)| p));

    let mut outcome = WitnessOutcome::default();
    let mut refreshed: BTreeSet<ShardId> = BTreeSet::new();
    for (shard, contribution) in shard_contributions {
        let header = &contribution.boundary_header;
        let block_hash = header.hash();
        let Some(qc) = canonical
            .get(shard)
            .copied()
            .filter(|qc| qc.block_hash() == block_hash)
        else {
            continue;
        };
        // Require a genuine epoch crossing: the boundary block is the first
        // block across some epoch boundary, so its predecessor sits at or
        // before the cut.
        if !is_boundary_crossing(header, qc, dur) {
            continue;
        }
        // Chunk math (0-based, count-aligned): `prior` is the applied
        // watermark, `boundary_count` the boundary block's accumulator
        // count. A boundary whose count regressed below what we've already
        // applied is rejected (monotonicity).
        let prior = state
            .boundaries
            .get(shard)
            .map_or(0, |b| b.witness_leaf_count.inner());
        let boundary_count = header.beacon_witness_leaf_count().inner();
        if boundary_count < prior {
            continue;
        }
        let (_, chunk_end) = chunk_bounds(prior, boundary_count);
        if !apply_contribution_witnesses(
            state,
            header,
            &contribution.witnesses,
            prior,
            chunk_end,
            &mut outcome,
        ) {
            continue;
        }
        state.boundaries.insert(
            *shard,
            ShardBoundary {
                state_root: header.state_root(),
                block_hash,
                height: header.height(),
                witness_leaf_count: BeaconWitnessLeafCount::new(chunk_end),
                last_live_epoch: epoch,
                consecutive_misses: 0,
            },
        );
        refreshed.insert(*shard);
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

    outcome
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconProposal, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader,
        BlockHeight, BoundedVec, CertificateRoot, Epoch, Hash, InFlightCount, LeafIndex,
        LocalReceiptRoot, MAX_WITNESSES_PER_SHARD, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardBoundary, ShardId, ShardWitness, ShardWitnessPayload,
        ShardWitnessProof, SignerBitfield, Stake, StakePoolId, StateRoot, TransactionRoot,
        TransitionCause, ValidatorId, VrfProof, WeightedTimestamp, compute_merkle_root_with_proof,
        zero_bls_signature,
    };

    use super::*;
    use crate::state::test_fixtures::{net, single_pool_state};

    // ─── boundary fold ──────────────────────────────────────────────────────

    /// A shard block header at `height` whose predecessor's weighted
    /// timestamp (on its parent QC) is `pred_wt`, carrying `state_root`,
    /// `root` as its `beacon_witness_root`, and witness `leaf_count`.
    fn boundary_block_with_root(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        root: BeaconWitnessRoot,
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
            root,
            BeaconWitnessLeafCount::new(leaf_count),
            BeaconWitnessLeafCount::ZERO,
        )
    }

    /// A boundary block carrying no witness accumulator (`ZERO` root).
    fn boundary_block(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> BlockHeader {
        boundary_block_with_root(
            shard,
            height,
            pred_wt,
            state_root,
            BeaconWitnessRoot::ZERO,
            leaf_count,
        )
    }

    /// A boundary block committing a real beacon-witness accumulator over
    /// `payloads`, plus the matching per-leaf witnesses (merkle-proven
    /// against the block's root, anchored to its hash).
    fn boundary_block_with_payloads(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        payloads: Vec<ShardWitnessPayload>,
    ) -> (BlockHeader, Vec<ShardWitness>) {
        let leaf_count = payloads.len() as u64;
        let leaf_hashes: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        let root = if leaf_hashes.is_empty() {
            BeaconWitnessRoot::ZERO
        } else {
            BeaconWitnessRoot::from_raw(compute_merkle_root_with_proof(&leaf_hashes, 0).0)
        };
        let header = boundary_block_with_root(shard, height, pred_wt, state_root, root, leaf_count);
        let block_hash = header.hash();
        let witnesses = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let (_, siblings, _) = compute_merkle_root_with_proof(&leaf_hashes, i);
                ShardWitness {
                    payload,
                    proof: ShardWitnessProof {
                        shard_id: shard,
                        committed_block_hash: block_hash,
                        leaf_index: LeafIndex::new(i as u64),
                        siblings: siblings.into(),
                    },
                }
            })
            .collect();
        (header, witnesses)
    }

    /// [`boundary_block_with_payloads`] over `leaf_count` `StakeDeposit`
    /// leaves. Deposits apply without a validator-status precondition, so
    /// the fold's chunk-apply step always succeeds on the well-formed set.
    fn boundary_block_with_witnesses(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> (BlockHeader, Vec<ShardWitness>) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200 + u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        boundary_block_with_payloads(shard, height, pred_wt, state_root, payloads)
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
        let (b, witnesses) = boundary_block_with_witnesses(shard, 5, 900, anchor, 7);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                witnesses: witnesses.into(),
            },
        ))
        .collect();

        record_boundaries(&mut state, Epoch::new(1), &committed, &contributions);

        let recorded = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(recorded.state_root, anchor);
        assert_eq!(recorded.height, BlockHeight::new(5));
        assert_eq!(recorded.witness_leaf_count, BeaconWitnessLeafCount::new(7));
        assert_eq!(recorded.last_live_epoch, Epoch::new(1));
        assert_eq!(recorded.consecutive_misses, 0);
    }

    /// The witness window base frozen at promotion is byte-identical to
    /// what the prior state's lookahead derivation read live from
    /// `boundaries`: the stamp happens before the epoch's fold advances
    /// the watermark, and nothing mutates `boundaries` between the end
    /// of one `apply_epoch` and the start of the next.
    #[test]
    fn witness_window_base_freeze_matches_prior_lookahead() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
            },
        );
        state.witness_window_bases = state.live_witness_bases();

        // Epoch 1 folds a boundary whose chunk applies 7 witness leaves.
        let root = StateRoot::from_raw(Hash::from_bytes(b"epoch1"));
        let (header, witnesses) = boundary_block_with_witnesses(shard, 5, 900, root, 7);
        let qc = qc_over(&header, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: header,
                witnesses: witnesses.into(),
            },
        ))
        .collect();
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(1),
            ApplyEpochInput::Normal {
                committed: &committed,
                shard_contributions: &contributions,
            },
        );

        // The stamp ran before the fold: window 1's base is the genesis
        // watermark, not the count the fold just applied.
        assert_eq!(
            state.witness_window_bases.get(&shard),
            Some(&BeaconWitnessLeafCount::ZERO)
        );
        // What the lookahead derivation for window 2 reads live now.
        let lookahead = state.live_witness_bases();
        assert_eq!(lookahead.get(&shard), Some(&BeaconWitnessLeafCount::new(7)));

        // Window 2's promotion freezes exactly what the lookahead read.
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(2),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        assert_eq!(state.witness_window_bases, lookahead);
    }

    /// The topology snapshot projects a recorded boundary as a
    /// `ShardAnchor`, but a zeroed genesis placeholder reads as `None` —
    /// no attested anchor to snap-sync against.
    #[test]
    fn snapshot_projects_recorded_anchor_not_placeholder() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
            },
        );
        assert_eq!(
            state.derive_topology_snapshot(net()).boundary(shard),
            None,
            "placeholder boundary must not project",
        );

        let anchor_root = StateRoot::from_raw(Hash::from_bytes(b"anchor"));
        let b = boundary_block(shard, 5, 900, anchor_root, 0);
        let block_hash = b.hash();
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                witnesses: BoundedVec::new(),
            },
        ))
        .collect();
        record_boundaries(&mut state, Epoch::new(1), &committed, &contributions);

        let projected = state.derive_topology_snapshot(net()).boundary(shard);
        let anchor = projected.expect("recorded boundary projects");
        assert_eq!(anchor.state_root, anchor_root);
        assert_eq!(anchor.block_hash, block_hash);
        assert_eq!(anchor.height, BlockHeight::new(5));
        // Re-derivation is deterministic.
        assert_eq!(
            state.derive_topology_snapshot(net()).boundary(shard),
            projected
        );
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
                height: BlockHeight::GENESIS,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
            },
        );

        let b = boundary_block(shard, 5, 1_200, StateRoot::ZERO, 0);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                witnesses: BoundedVec::new(),
            },
        ))
        .collect();

        record_boundaries(&mut state, Epoch::new(1), &committed, &contributions);

        assert_eq!(state.boundaries.get(&shard).unwrap().consecutive_misses, 1,);
    }

    /// A backlog larger than `MAX_WITNESSES_PER_SHARD` drains in bounded
    /// chunks across successive epochs: the applied watermark climbs by at
    /// most the cap each epoch — never jumping straight to the boundary's
    /// full leaf count — while the anchor stays pinned to the crossing,
    /// until the watermark reaches that count. The contribution for each
    /// epoch carries only that epoch's chunk, all proving against the one
    /// boundary block's accumulator root.
    #[test]
    fn record_boundaries_drains_a_backlog_over_multiple_epochs() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let cap = MAX_WITNESSES_PER_SHARD;
        // One full chunk plus a small remainder, so the drain spans two
        // epochs: `[0, cap)` then `[cap, total)`.
        let total = cap + 3;

        let anchor = StateRoot::from_raw(Hash::from_bytes(b"backlog-anchor"));
        let (b, witnesses) = boundary_block_with_witnesses(shard, 5, 900, anchor, total as u64);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];

        let contribution_with =
            |chunk: &[ShardWitness]| -> BTreeMap<ShardId, ShardEpochContribution> {
                std::iter::once((
                    shard,
                    ShardEpochContribution {
                        boundary_header: b.clone(),
                        witnesses: chunk.to_vec().into(),
                    },
                ))
                .collect()
            };

        // Epoch 1: the watermark is cap-gated — it advances to exactly the
        // cap even though the boundary commits `total > cap` leaves.
        record_boundaries(
            &mut state,
            Epoch::new(1),
            &committed,
            &contribution_with(&witnesses[..cap]),
        );
        let after_1 = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(
            after_1.witness_leaf_count,
            BeaconWitnessLeafCount::new(cap as u64)
        );
        assert_eq!(after_1.block_hash, b.hash());
        assert_eq!(after_1.state_root, anchor);
        assert_eq!(after_1.consecutive_misses, 0);

        // Epoch 2: the remainder `[cap, total)` drains against the same
        // crossing; the watermark reaches the boundary's full leaf count.
        record_boundaries(
            &mut state,
            Epoch::new(2),
            &committed,
            &contribution_with(&witnesses[cap..]),
        );
        let after_2 = state
            .boundaries
            .get(&shard)
            .expect("boundary still recorded");
        assert_eq!(
            after_2.witness_leaf_count,
            BeaconWitnessLeafCount::new(total as u64)
        );
        assert_eq!(after_2.block_hash, b.hash());
        assert_eq!(after_2.consecutive_misses, 0);
    }

    /// A Ready witness folding in epoch E flips the validator's status
    /// but not E's consensus committee: the active window's subset is
    /// frozen at promotion from pre-fold statuses, so it is identical to
    /// what the prior state's lookahead derivation computed — a node
    /// resolving the window from either schedule entry sees the same
    /// committee — and the newly-ready member first counts one window
    /// out. Full membership keeps the member reachable throughout.
    #[test]
    fn ready_flip_takes_consensus_effect_one_window_out() {
        use hyperscale_types::ValidatorStatus;

        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let joiner = ValidatorId::new(3);
        let ready_members: Vec<ValidatorId> = [0u64, 1, 2].map(ValidatorId::new).to_vec();
        state.validators.get_mut(&joiner).unwrap().status = ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch: Epoch::GENESIS,
        };

        // The lookahead snapshot for the next window: full membership
        // keeps the joiner, the consensus subset excludes it.
        let lookahead = state.derive_next_topology_snapshot(net());
        assert!(lookahead.committee_for_shard(shard).contains(&joiner));
        assert_eq!(
            lookahead.consensus_committee_for_shard(shard),
            ready_members.as_slice()
        );

        // Epoch 1 folds a Ready witness for the joiner, carried in the
        // boundary contribution's chunk.
        let (b, witnesses) = boundary_block_with_payloads(
            shard,
            5,
            900,
            StateRoot::from_raw(Hash::from_bytes(b"anchor")),
            vec![ShardWitnessPayload::Ready { id: joiner }],
        );
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                witnesses: witnesses.into(),
            },
        ))
        .collect();
        let effects = apply_epoch(
            &mut state,
            &net(),
            Epoch::new(1),
            ApplyEpochInput::Normal {
                committed: &committed,
                shard_contributions: &contributions,
            },
        );
        assert_eq!(effects.readied, vec![joiner]);
        assert!(matches!(
            state.validators.get(&joiner).unwrap().status,
            ValidatorStatus::OnShard { ready: true, .. }
        ));

        // The active window's consensus subset matches the lookahead's —
        // the mid-fold flip did not retroactively change the window.
        let active = state.derive_topology_snapshot(net());
        assert_eq!(
            active.consensus_committee_for_shard(shard),
            lookahead.consensus_committee_for_shard(shard)
        );
        assert!(active.committee_for_shard(shard).contains(&joiner));

        // The next window's lookahead picks the joiner up.
        let next = state.derive_next_topology_snapshot(net());
        assert!(next.consensus_committee_for_shard(shard).contains(&joiner));
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
