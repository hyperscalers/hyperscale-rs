//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconCert, BeaconProposal, BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeader,
    CertifiedBeaconBlock, Epoch, EpochWindows, KeptSeat, NetworkDefinition, ObserverSeat,
    PendingReshape, QuorumCertificate, RESHAPE_HANDOFF_TTL_EPOCHS, RETENTION_HORIZON,
    ShardBoundary, ShardEpochContribution, ShardId, ShardWitness, ShardWitnessPayload, SlotEffects,
    SplitChildRoots, TransitionCause, ValidatorId, ValidatorStatus, VrfOutput, WeightedTimestamp,
};

use crate::rules::{
    canonical_boundary_qcs, chunk_bounds, crossing_already_recorded, is_boundary_crossing,
};
use crate::state::committee::{
    diff_shard_committees, recover_halted_committees, resample_beacon_committee, run_shuffle_step,
    top_up_committees,
};
use crate::state::governance::tally_param_votes;
use crate::state::lifecycle::{auto_reactivate, auto_ready_timeout, distribute_epoch_rewards};
use crate::state::reshape::{execute_ready_merges, execute_ready_splits};
use crate::state::vrf::filter_and_roll_randomness;
use crate::state::withdrawals::complete_pending_withdrawals;
use crate::state::witness::{
    WitnessOutcome, apply_contribution_witnesses, defer_reshape_ttls, ingest_equivocations,
    prune_stale_reshapes,
};

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
/// The discriminator is the block's *content*, never its cert variant:
/// a proposal-less block folds as a skip whichever certificate commits
/// it. A proposal-less Normal block is byte-identical to the epoch's
/// skip block, and the fold is a pure function of the committed block
/// sequence — if the cert variant picked the pipeline, an assembler
/// pairing the same commit certificate with the other variant would
/// fork byte-identical chains into different states.
///
/// # Panics
///
/// Panics on `BeaconCert::Genesis` — callers must filter genesis blocks
/// before adoption.
#[must_use]
pub fn apply_input_for(block: &CertifiedBeaconBlock) -> ApplyEpochInput<'_> {
    assert!(
        !matches!(block.cert(), BeaconCert::Genesis(_)),
        "apply_input_for called on Genesis block",
    );
    if block.block().committed_proposals().is_empty() {
        ApplyEpochInput::Skip
    } else {
        ApplyEpochInput::Normal {
            committed: block.block().committed_proposals(),
            shard_contributions: block.block().shard_contributions(),
        }
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
    // Promote the lookahead params under the same discipline: a vote
    // tallied a prior epoch installed its change into `next_params` at
    // `activate_at - 1`, so this epoch's blocks resolve the value every
    // member already froze into this window's topology snapshot.
    state.params = state.next_params;
    // Freeze each shard's beacon-witness window base under the same
    // discipline: the applied watermark as it stands before this epoch's
    // fold advances it, matching what the prior state's lookahead
    // derivation read live from the same boundaries.
    state.witness_window_bases = state.live_witness_bases();
    // Freeze the pending-split set the same way — before this fold's
    // admissions, cancellations, and executions mutate it — so a
    // window's split-at-boundary projection is byte-identical whether
    // resolved from the lookahead schedule entry or the re-derived
    // active one.
    state.split_pending_window = state.live_split_pending();
    state.settled_window_floors = state.live_settled_window_floors();
    // Freeze the reshape-seat projections under the same discipline.
    // The execution fold flips a split's observer cohort to `OnShard`
    // and consumes a merge's keepers mid-fold, so a live projection
    // would differ between a window's lookahead write and its active
    // overwrite — diverging the `ReshapeReady` leaf classification (and
    // the merge-terminal settled-waves carry) across replicas at
    // different fold heights, which forks the beacon-witness root.
    state.reshape_observers_window = state.live_reshape_observers();
    state.reshape_keepers_window = state.live_reshape_keepers();

    // Snapshot each shard's member list before the pipeline runs so the
    // end-of-epoch set-diff against this snapshot can surface
    // membership changes through `SlotEffects.shard_committee_transitions`.
    let pre_shard_members: BTreeMap<ShardId, Vec<ValidatorId>> = state
        .next_shard_committees
        .iter()
        .map(|(s, c)| (*s, c.members.clone()))
        .collect();
    // Snapshot the observer seats under the same discipline: the
    // end-of-epoch diff surfaces draws and releases through
    // `SlotEffects.observers_drawn` / `observers_released`.
    let pre_seats = cohort_seats(state);
    // The same for keeper seats, surfaced through
    // `SlotEffects.keepers_drawn` / `keepers_released`.
    let pre_keeper_seats = keeper_seats(state);

    let (committed, transition_cause): (&[_], TransitionCause) = match input {
        ApplyEpochInput::Normal { committed, .. } => (committed, TransitionCause::NaturalShuffle),
        ApplyEpochInput::Skip => (&[], TransitionCause::Skip),
    };

    // Fold this epoch's per-shard boundaries and apply their witness
    // chunks. A `Skip` carries every prior boundary forward untouched (no
    // record, no miss bump, no witnesses); a Normal epoch records fresh
    // boundaries, applies each chunk, and bumps the miss counter for any
    // active shard with no qualifying contribution.
    let (mut witness, reveals) = if let ApplyEpochInput::Normal {
        committed,
        shard_contributions,
    } = input
    {
        record_boundaries(state, network, epoch, committed, shard_contributions)
    } else {
        (WitnessOutcome::default(), BTreeMap::new())
    };

    // The boundary fold above advanced each shard's anchor and witness
    // watermark, so drop the parent-half cohort of any child that has now
    // committed past its genesis.
    release_seated_parent_halves(state);

    // A normal epoch folded its witnesses above, so sweep reshapes whose
    // triggers went quiet — an assertion folded this epoch is never swept.
    // A skip folds nothing, so no trigger could re-assert; carry the TTL
    // anchors forward instead, sparing a reshape that only looks quiet
    // because the beacon stalled.
    match input {
        ApplyEpochInput::Normal { .. } => {
            prune_stale_reshapes(state);
            // Tally the parameter votes the boundary fold just recorded and
            // apply any majority-backed change at its activation epoch. A
            // skip folds no votes and activates none, carrying live
            // proposals forward to a real epoch.
            tally_param_votes(state);
        }
        ApplyEpochInput::Skip => defer_reshape_ttls(state),
    }

    let vrf = filter_and_roll_randomness(state, network, epoch, committed, &reveals);
    // Equivocation evidence rides committed proposals; shard-witness lifts
    // ride the boundary contributions applied above.
    witness.extend(ingest_equivocations(state, network, &vrf.accepted));
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    let rewards_credited = distribute_epoch_rewards(state);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);
    // After the shuffle so the parent-half assignment reads
    // post-rotation membership and the children first shuffle one
    // epoch after they form; before the resample so freshly placed
    // ready members enter this epoch's beacon-eligible set like any
    // witness-readied validator.
    execute_ready_splits(state);
    // Merges fold the same way, inverted: two children collapse into
    // their parent once the keeper committee is ready.
    execute_ready_merges(state);
    // Halt detection reads the settled reshape state: a shard whose reshape
    // executed this epoch is already terminal-marked or placeholder-fresh,
    // so it reads as legitimately quiet. Recovery runs before the top-up
    // and the beacon resample, so replaced members return to the pool in
    // time to backfill other short committees and the resample reads
    // post-recovery placements.
    let halted_shards = state.halted_shards();
    for shard in &halted_shards {
        tracing::error!(
            ?shard,
            "shard halted: no boundary crossing within the halt threshold"
        );
    }
    recover_halted_committees(state, &halted_shards);
    // Grow any committee a short cohort draw left under `shard_size` back to
    // full strength, now that dissolved predecessors have freed their members.
    top_up_committees(state);
    let beacon_committee_transition =
        resample_beacon_committee(state, &BTreeSet::new(), transition_cause);

    let mut jailed = vrf.jailed;
    jailed.extend(witness.jailed);
    let mut deactivated = witness.deactivated;
    deactivated.extend(withdrawal.deactivated);
    let mut readied = witness.readied;
    readied.extend(timeout_readied);

    let shard_committee_transitions = diff_shard_committees(state, &pre_shard_members);
    let (observers_drawn, observers_released) = diff_observer_seats(state, &pre_seats);
    let (keepers_drawn, keepers_released) = diff_keeper_seats(state, &pre_keeper_seats);
    let executed_parent_halves = diff_split_parent_halves(state, &pre_shard_members, &pre_seats);
    // Retain each freshly split child's parent halves until the child commits
    // past its genesis, so the reshape orchestrator discovers and seats them
    // from the committed view.
    for (child, members) in executed_parent_halves {
        state
            .reshape_parent_halves
            .entry(child)
            .or_default()
            .extend(members);
    }

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
        observers_drawn,
        observers_released,
        keepers_drawn,
        keepers_released,
        halted_shards,
    }
}

/// The parent-half cohorts a split execution placed on its fresh children,
/// keyed by child, mapping each member to the parent it re-roots its local
/// store from.
///
/// A child is fresh when it entered the lookahead this fold while its parent
/// left it. Each of its members either held an observer seat for exactly this
/// child at the epoch start (the synced store reopens — not a parent half) or
/// sat on the parent committee (the store hard-links from a local checkpoint —
/// a parent half); the execution gate admits no third provenance.
fn diff_split_parent_halves(
    state: &BeaconState,
    pre_shard_members: &BTreeMap<ShardId, Vec<ValidatorId>>,
    pre_seats: &BTreeMap<(ValidatorId, ShardId), ShardId>,
) -> BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
    let mut parent_halves: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> = BTreeMap::new();
    for (child, committee) in &state.next_shard_committees {
        if pre_shard_members.contains_key(child) {
            continue;
        }
        let Some(parent) = child.parent() else {
            continue;
        };
        let Some(parent_members) = pre_shard_members.get(&parent) else {
            continue;
        };
        for member in &committee.members {
            if pre_seats.get(&(*member, parent)) != Some(child) && parent_members.contains(member) {
                parent_halves
                    .entry(*child)
                    .or_default()
                    .insert(*member, parent);
            }
        }
    }
    parent_halves
}

/// Drop the parent-half cohort of every child that has committed past its
/// genesis. A real anchor (non-zero `block_hash`) paired with a non-zero
/// witness watermark means the child is live and producing — which requires
/// its members, the parent halves among them, to have seated — so the reshape
/// orchestrator no longer needs the cohort to discover them.
fn release_seated_parent_halves(state: &mut BeaconState) {
    let established: Vec<ShardId> = state
        .reshape_parent_halves
        .keys()
        .filter(|child| {
            state.boundaries.get(child).is_some_and(|b| {
                b.block_hash != BlockHash::ZERO
                    && b.witness_leaf_count != BeaconWitnessLeafCount::ZERO
            })
        })
        .copied()
        .collect();
    for child in established {
        state.reshape_parent_halves.remove(&child);
    }
}

/// Every pending split's cohort seats, keyed `(validator, splitting
/// shard) → assigned child`.
fn cohort_seats(state: &BeaconState) -> BTreeMap<(ValidatorId, ShardId), ShardId> {
    state
        .pending_reshapes
        .iter()
        .filter_map(|(target, reshape)| match reshape {
            PendingReshape::Split { cohort, .. } => Some((*target, cohort)),
            PendingReshape::Merge { .. } => None,
        })
        .flat_map(|(target, cohort)| {
            cohort
                .iter()
                .map(move |(validator, seat)| ((*validator, target), seat.child))
        })
        .collect()
}

/// Diff the observer seats against the epoch-start snapshot.
///
/// New seats surface as draws. Vanished seats surface as releases —
/// except those a split consumed, whose holder now sits `OnShard` on
/// the very child the seat named; their transition surfaces through
/// the committee diff instead.
fn diff_observer_seats(
    state: &BeaconState,
    pre_seats: &BTreeMap<(ValidatorId, ShardId), ShardId>,
) -> (Vec<ObserverSeat>, Vec<ObserverSeat>) {
    let post_seats = cohort_seats(state);
    let drawn = post_seats
        .iter()
        .filter(|(key, _)| !pre_seats.contains_key(key))
        .map(|((validator, shard), child)| ObserverSeat {
            validator: *validator,
            shard: *shard,
            child: *child,
        })
        .collect();
    let released = pre_seats
        .iter()
        .filter(|(key, _)| !post_seats.contains_key(key))
        .filter(|((validator, _), child)| {
            !matches!(
                state.validators.get(validator).map(|r| r.status),
                Some(ValidatorStatus::OnShard { shard, .. }) if shard == **child
            )
        })
        .map(|((validator, shard), child)| ObserverSeat {
            validator: *validator,
            shard: *shard,
            child: *child,
        })
        .collect();
    (drawn, released)
}

/// Every pending merge's keeper seats, keyed `(validator, merged
/// parent) → the child the keeper runs`.
fn keeper_seats(state: &BeaconState) -> BTreeMap<(ValidatorId, ShardId), ShardId> {
    state
        .pending_reshapes
        .iter()
        .filter_map(|(parent, reshape)| match reshape {
            PendingReshape::Merge { keepers, .. } => Some((*parent, keepers)),
            PendingReshape::Split { .. } => None,
        })
        .flat_map(|(parent, keepers)| {
            keepers
                .iter()
                .map(move |(validator, seat)| ((*validator, parent), seat.child))
        })
        .collect()
}

/// Diff the keeper seats against the epoch-start snapshot.
///
/// New seats surface as draws — a merge pairing fixes its keeper
/// committee. Vanished seats surface as releases, except those a merge
/// consumed, whose holder now sits `OnShard` on the merged parent; their
/// move surfaces through the committee diff instead.
fn diff_keeper_seats(
    state: &BeaconState,
    pre_keeper_seats: &BTreeMap<(ValidatorId, ShardId), ShardId>,
) -> (Vec<KeptSeat>, Vec<KeptSeat>) {
    let post_seats = keeper_seats(state);
    let drawn = post_seats
        .iter()
        .filter(|(key, _)| !pre_keeper_seats.contains_key(key))
        .map(|((validator, parent), child)| KeptSeat {
            validator: *validator,
            parent: *parent,
            child: *child,
        })
        .collect();
    let released = pre_keeper_seats
        .iter()
        .filter(|(key, _)| !post_seats.contains_key(key))
        .filter(|((validator, parent), _child)| {
            !matches!(
                state.validators.get(validator).map(|r| r.status),
                Some(ValidatorStatus::OnShard { shard, .. }) if shard == *parent
            )
        })
        .map(|((validator, parent), child)| KeptSeat {
            validator: *validator,
            parent: *parent,
            child: *child,
        })
        .collect();
    (drawn, released)
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
/// Terminal marks a crossing refresh carries onto a shard's rebuilt
/// boundary record; a refresh must never clear them.
struct TerminalMarks {
    terminal_epoch: Option<Epoch>,
    reshape_admitted_epoch: Option<Epoch>,
    terminal_qc_wt: Option<WeightedTimestamp>,
}

/// The marks for a shard's rebuilt boundary record, plus whether this
/// contribution is the chain's terminal block (its crossing lands in an
/// epoch past the scheduled terminal). The scheduled-terminal marks come
/// from the prior record. The certifying QC's timestamp is recorded on
/// the terminal contribution: a merge parent floors it to the cut, and
/// persisting it lets the parent compose even when its two children's
/// terminals fold in separate epochs. A split parent seeds in-fold and
/// never composes, so only merge children (no `split_child_roots`)
/// carry it.
///
/// Terminal is judged by the cut the contribution *crosses*, not the
/// window its QC lands in: the boundary instant counts as not yet
/// crossed, so the final window's own refresh — which can certify
/// exactly on the terminal cut — stays non-terminal, and its pre-freeze
/// state root never reaches a merge compose.
fn carried_terminal_marks(
    state: &BeaconState,
    shard: ShardId,
    header: &BlockHeader,
    qc: &QuorumCertificate,
    windows: EpochWindows,
) -> (TerminalMarks, bool) {
    let (terminal_epoch, reshape_admitted_epoch) =
        state.boundaries.get(&shard).map_or((None, None), |b| {
            (b.terminal_epoch, b.reshape_admitted_epoch)
        });
    let is_terminal = terminal_epoch.is_some_and(|t| {
        windows
            .crossing_epoch(
                header.parent_qc().weighted_timestamp(),
                qc.weighted_timestamp(),
            )
            .is_some_and(|crossed| crossed > t)
    });
    let terminal_qc_wt =
        (is_terminal && header.split_child_roots().is_none()).then(|| qc.weighted_timestamp());
    (
        TerminalMarks {
            terminal_epoch,
            reshape_admitted_epoch,
            terminal_qc_wt,
        },
        is_terminal,
    )
}

/// The `RandomnessReveal` outputs of an applied witness chunk, in leaf
/// order — one reveal per block, so ascending block height.
fn reveal_outputs(witnesses: &[ShardWitness]) -> Vec<VrfOutput> {
    witnesses
        .iter()
        .filter_map(|w| match &w.payload {
            ShardWitnessPayload::RandomnessReveal { output } => Some(*output),
            _ => None,
        })
        .collect()
}

/// The halt-recovery randomness fence line for a chunk about to fold: the
/// leaf count below which its reveals stay out of the seed. A fresh
/// crossing above a pending recovery's attested frontier fences its whole
/// count (the beyond-f retained committee's possible post-halt
/// production); its count dominates any carried band since the
/// accumulator is monotone along the chain. A drain re-fold carries the
/// band the recording crossing already fenced. `None` when nothing is
/// fenced.
fn reveal_fence_for(
    state: &BeaconState,
    shard: &ShardId,
    header: &BlockHeader,
    boundary_count: u64,
    drain_refold: bool,
) -> Option<BeaconWitnessLeafCount> {
    let carried = state
        .boundaries
        .get(shard)
        .and_then(|b| b.reveals_fenced_below);
    if drain_refold {
        return carried;
    }
    let own = state
        .pending_recoveries
        .get(shard)
        .filter(|recovery| header.height() > recovery.attested_frontier)
        .map(|_| BeaconWitnessLeafCount::new(boundary_count));
    own.or(carried)
}

/// A drain re-fold of the recorded crossing: advance only the applied
/// watermark, and clear the persisted reveal fence once the watermark
/// reaches it (the fenced band is fully drained).
fn advance_drain_watermark(state: &mut BeaconState, shard: &ShardId, chunk_end: u64) {
    if let Some(boundary) = state.boundaries.get_mut(shard) {
        boundary.witness_leaf_count = BeaconWitnessLeafCount::new(chunk_end);
        if boundary
            .reveals_fenced_below
            .is_some_and(|f| chunk_end >= f.inner())
        {
            boundary.reveals_fenced_below = None;
        }
    }
}

fn record_boundaries(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
    shard_contributions: &BTreeMap<ShardId, ShardEpochContribution>,
) -> (WitnessOutcome, BTreeMap<ShardId, Vec<VrfOutput>>) {
    let windows = state.chain_config.epoch_windows();
    // Bind each contribution to its shard's canonical committed QC — the
    // same selection the receiver's `contributions_well_formed` gate
    // applied — so the fold and the verifier never diverge on which QC
    // governs the boundary.
    let canonical = canonical_boundary_qcs(committed.iter().map(|(_, p)| p));

    let mut outcome = WitnessOutcome::default();
    let mut reveals: BTreeMap<ShardId, Vec<VrfOutput>> = BTreeMap::new();
    let mut refreshed: BTreeSet<ShardId> = BTreeSet::new();
    // Merge children whose terminal contribution — the coast block past
    // their cut, carrying their frozen terminal root — landed this fold.
    // Drives the compose attempt below: the children's terminal records (and
    // their persisted `terminal_qc_wt`) linger across folds, so a parent
    // composes once both children have folded, whichever fold completes the
    // pair.
    let mut terminal_recorded: BTreeSet<ShardId> = BTreeSet::new();
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
        if !is_boundary_crossing(header, qc, windows) {
            continue;
        }
        // Chunk math (0-based, count-aligned): `prior` is the applied
        // watermark, `boundary_count` the boundary block's accumulator
        // count. A boundary whose count regressed below what we've already
        // applied is rejected (monotonicity).
        let prior = state.fold_watermark(*shard);
        let boundary_count = header.beacon_witness_leaf_count().inner();
        if boundary_count < prior {
            continue;
        }
        let (_, chunk_end) = chunk_bounds(prior, boundary_count);
        // Only a new crossing is a liveness observation. A committed re-fold
        // of the recorded crossing means the chain has not moved past the
        // recorded anchor: it must not reset the miss counter, refresh the
        // live epoch, or release a pending recovery's retention — a halting
        // committee can leave one final crossing carrying an arbitrarily
        // large witness backlog, and treating each drain chunk as a fresh
        // observation would defer halt detection until the backlog ran dry.
        // A re-fold with no witness progress carries nothing at all; one
        // with progress drains the backlog watermark-only below.
        let drain_refold = crossing_already_recorded(state, *shard, block_hash);
        if drain_refold && chunk_end == prior {
            continue;
        }
        if !apply_contribution_witnesses(
            state,
            network,
            header,
            &contribution.witnesses,
            prior,
            chunk_end,
            &mut outcome,
        ) {
            continue;
        }
        // The halt-recovery randomness fence, judged here while the
        // shard's recovery record (if any) is still live. A crossing above
        // the recovery's attested frontier commits history the beyond-f
        // retained committee could have forged post-halt, so the fence
        // covers every leaf up to that crossing's count — persisted on the
        // boundary record so the whole band stays out of the seed across
        // drain epochs and later record refreshes, until the applied
        // watermark passes it.
        let fence = reveal_fence_for(state, shard, header, boundary_count, drain_refold);
        let fenced = fence.is_some_and(|f| prior < f.inner());
        // Collect the chunk's reveal-leaf outputs for the randomness
        // fold — exactly the leaves the application above accepted.
        // Drain re-folds contribute like any other chunk's, unless the
        // fence holds the band out of the seed.
        if !fenced {
            let outputs = reveal_outputs(&contribution.witnesses);
            if !outputs.is_empty() {
                reveals.insert(*shard, outputs);
            }
        }
        if drain_refold {
            advance_drain_watermark(state, shard, chunk_end);
            continue;
        }
        let (marks, is_terminal_contribution) =
            carried_terminal_marks(state, *shard, header, qc, windows);
        state.boundaries.insert(
            *shard,
            ShardBoundary {
                state_root: header.state_root(),
                block_hash,
                height: header.height(),
                weighted_timestamp: header.parent_qc().weighted_timestamp(),
                witness_leaf_count: BeaconWitnessLeafCount::new(chunk_end),
                witness_base: header.beacon_witness_base(),
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch: marks.terminal_epoch,
                terminal_qc_wt: marks.terminal_qc_wt,
                settled_waves_root: header.settled_waves_root(),
                reshape_admitted_epoch: marks.reshape_admitted_epoch,
                reveals_fenced_below: fence.filter(|f| chunk_end < f.inner()),
            },
        );
        refreshed.insert(*shard);
        // This shard folded a real crossing of its own — past its seeded
        // genesis (a seed is never itself a contribution). Mark it produced;
        // the reshape handoff reads this as "successor live".
        state.advanced.insert(*shard);
        // A crossing under an in-flight halt recovery means the fresh
        // committee produced: the recovery is complete, so release the
        // retained replaced committee from the routing view. The seating
        // epoch moves to the permanent record — certified resolution of
        // the recovery's bridge band reads it so blocks anchored below
        // the bridge keep binding to the fresh committee that produced
        // them, no matter when a replica processes them.
        if let Some(recovery) = state.pending_recoveries.remove(shard) {
            state
                .completed_recoveries
                .insert(*shard, recovery.rotated_at);
        }

        // A terminal shard's contribution crossing its final cut is the
        // chain's terminal block. A split parent seeds its pending
        // children from the header's `split_child_roots`; a merge child
        // carries none — its parent composes from both children's terminal
        // roots in the post-loop pass below. The record then lingers,
        // carrying the terminated shard's `settled_waves_root` for
        // surviving counterparts to read, until the retention GC below
        // drops it.
        if is_terminal_contribution {
            if header.split_child_roots().is_some() {
                seed_split_children(state, *shard, header, qc, epoch);
            } else {
                terminal_recorded.insert(*shard);
            }
        }
    }

    // Active shards with no fresh boundary carry their prior record
    // forward and bump the miss counter (the "not observed crossing"
    // signal). The shard set is fixed at the fold, so every tracked
    // boundary belongs to an active shard — except terminal records,
    // whose chains stopped on purpose and are never "missing".
    for (shard, boundary) in &mut state.boundaries {
        if !refreshed.contains(shard) && boundary.terminal_epoch.is_none() {
            boundary.consecutive_misses = boundary.consecutive_misses.saturating_add(1);
        }
    }

    // Compose any merge parent whose two children have both delivered their
    // terminal contribution, after the miss bump so the freshly composed
    // anchor starts clean.
    compose_merge_parents(state, epoch, windows, &terminal_recorded);

    gc_terminal_boundaries(state, epoch, windows);

    (outcome, reveals)
}

/// Drop terminal records past their retention horizon. A terminated
/// shard's record lingers only to project its `settled_waves_root` to
/// surviving counterparts; past `terminal_wt + RETENTION_HORIZON` the
/// split-boundary fence rejects any wave naming it regardless, so the
/// record is dead weight. Bounded so a terminated shard can't
/// accumulate forever.
///
/// A terminal record whose reshape successors aren't live yet is exempt: it
/// is what `seed_split_children` folds the children from (or what a merge
/// parent composes from), and that fold can only land on an epoch the beacon
/// commits a proposal carrying the terminal QC. The beacon can commit empty
/// for several epochs across the reshape's committee transition, so the
/// horizon alone would drop the record first — stranding the children on
/// their placeholders, or the merge parent uncomposed. It is also the anchor
/// a coasting predecessor's observers snap-sync against while they finish
/// adopting; under make-before-break the predecessor keeps coasting until its
/// successors are live, so the record must outlive the horizon until then,
/// not merely until they seed. Holding it until the successors have produced
/// past genesis (`BeaconState.advanced`) covers both, and frees the record
/// for the next horizon sweep once the handoff has demonstrably completed.
fn gc_terminal_boundaries(state: &mut BeaconState, epoch: Epoch, windows: EpochWindows) {
    let now = windows.window_of(epoch).start;
    let pending_fold: BTreeMap<ShardId, Epoch> = state
        .boundaries
        .iter()
        .filter_map(|(shard, b)| {
            let terminal = b.terminal_epoch?;
            (!successors_live_for_terminal(state, *shard)).then_some((*shard, terminal))
        })
        .collect();
    // A handoff still pending RESHAPE_HANDOFF_TTL_EPOCHS after its execution
    // has stalled: make-before-break commits and serves the terminal reliably,
    // so the successors should have seated and produced past genesis well
    // inside the bound. Surface it loudly. The predecessor keeps coasting — it
    // is the successors' only anchor, so tearing it down here would strand them
    // — until they go live or an operator intervenes.
    for (shard, executed_at) in stalled_handoffs(&pending_fold, epoch) {
        tracing::error!(
            ?shard,
            executed_at = executed_at.inner(),
            current = epoch.inner(),
            "reshape handoff stalled: successors not live within the TTL after execution"
        );
    }
    state.boundaries.retain(|shard, b| {
        b.terminal_epoch.is_none_or(|t| {
            pending_fold.contains_key(shard)
                || now <= windows.window_of(t).end.plus(RETENTION_HORIZON)
        })
    });
    // A shard that left `boundaries` is gone; drop its produced mark and
    // any in-flight recovery record too.
    state
        .advanced
        .retain(|shard| state.boundaries.contains_key(shard));
    state
        .pending_recoveries
        .retain(|shard, _| state.boundaries.contains_key(shard));
}

/// Whether a terminal `shard`'s reshape successors are live — both split
/// children, or a merge's reformed parent, have produced past their genesis
/// (`BeaconState.advanced`). The `BeaconState`-level companion of
/// [`TopologySnapshot::successors_live`](hyperscale_types::TopologySnapshot::successors_live);
/// both release on the same `advanced` signal, so the record outlives the
/// coasting predecessor exactly. A split is keyed on its children's boundary
/// records — present from the split execution, so it never mistakes a
/// terminated grandparent for a successor — and a merge on its reformed
/// parent's *live committee*, which a lingering pre-merge terminal record never
/// carries. A successor not yet seated reads not-live, so the record stays.
fn successors_live_for_terminal(state: &BeaconState, shard: ShardId) -> bool {
    let (left, right) = shard.children();
    if state.boundaries.contains_key(&left) && state.boundaries.contains_key(&right) {
        return state.advanced.contains(&left) && state.advanced.contains(&right);
    }
    if let Some(parent) = shard.parent()
        && state.shard_committees.contains_key(&parent)
    {
        return state.advanced.contains(&parent);
    }
    false
}

/// The terminal shards whose handoff has stalled — their reshape successors
/// are still not live [`RESHAPE_HANDOFF_TTL_EPOCHS`] epochs after the reshape
/// executed. `pending` maps each terminal shard whose successors aren't yet
/// live to the epoch its reshape executed (the boundary's `terminal_epoch`),
/// and `epoch` is the fold's current epoch. Each result pairs the stalled
/// shard with that execution epoch for the diagnostic.
fn stalled_handoffs(pending: &BTreeMap<ShardId, Epoch>, epoch: Epoch) -> Vec<(ShardId, Epoch)> {
    pending
        .iter()
        .filter(|(_, executed_at)| {
            epoch.inner().saturating_sub(executed_at.inner()) >= RESHAPE_HANDOFF_TTL_EPOCHS
        })
        .map(|(shard, executed_at)| (*shard, *executed_at))
        .collect()
}

/// Seed a terminated parent's pending children from its terminal header.
///
/// The header carries `split_child_roots` — the two child hashes of the
/// root node behind its `state_root` — self-verified here by one
/// `hash_internal` composition: collision resistance means a Byzantine
/// shard cannot forge children that compose to the committed terminal
/// root. Each still-pending child record fills completely: the verified
/// subtree root, the child's deterministic genesis block hash (the same
/// block the flip installs), genesis height, and a fresh accumulator. A
/// failed or absent pair leaves the children pending — they then seed
/// from their own first boundary contributions instead.
fn seed_split_children(
    state: &mut BeaconState,
    parent: ShardId,
    terminal_header: &BlockHeader,
    terminal_qc: &QuorumCertificate,
    epoch: Epoch,
) {
    let Some(pair) = terminal_header.split_child_roots() else {
        tracing::warn!(
            shard = ?parent,
            "terminal contribution carries no split child roots; children seed from their own contributions"
        );
        return;
    };
    if !pair.composes_to(terminal_header.state_root()) {
        tracing::warn!(
            shard = ?parent,
            "terminal contribution's split child roots do not compose to its state root"
        );
        return;
    }
    let (left, right) = parent.children();
    for (child, child_root) in [(left, pair.left), (right, pair.right)] {
        let pending = state
            .boundaries
            .get(&child)
            .is_some_and(|b| b.block_hash == BlockHash::ZERO);
        if !pending {
            continue;
        }
        let genesis = BlockHeader::split_child_genesis(
            child,
            child_root,
            terminal_header,
            terminal_qc.weighted_timestamp(),
        );
        state.boundaries.insert(
            child,
            ShardBoundary {
                state_root: child_root,
                block_hash: genesis.hash(),
                height: genesis.height(),
                weighted_timestamp: genesis.parent_qc().weighted_timestamp(),
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            },
        );
    }
}

/// Compose every pending merge parent whose two children both delivered
/// their terminal contribution this fold (in `terminal_recorded`).
///
/// The beacon holds only `r_p0`/`r_p1` and can't decompose a single
/// `r_p`, so it composes the merged anchor itself —
/// `r_p = hash_internal(r_p0, r_p1)` — and seeds the placeholder with the
/// deterministic merged genesis (the same block every keeper installs).
/// The two children then drain and drop on subsequent folds, once their
/// parent is no longer pending. Both terminal records linger and are
/// re-sourced every fold until then, so the fold after the later child
/// terminates carries both here.
fn compose_merge_parents(
    state: &mut BeaconState,
    epoch: Epoch,
    windows: EpochWindows,
    terminal_recorded: &BTreeSet<ShardId>,
) {
    let mut parents: BTreeSet<ShardId> = BTreeSet::new();
    for child in terminal_recorded {
        let Some(parent) = child.parent() else {
            continue;
        };
        // Both children have folded their terminal contribution — each
        // carries a `terminal_qc_wt` — and the parent is still a pending
        // placeholder (zero hash, post-genesis; a split-child placeholder has
        // no children, so this never matches one). The two children's
        // terminals may have landed in separate folds: each terminal record
        // lingers until the parent composes, so whichever fold completes the
        // pair triggers here.
        let children: [ShardId; 2] = parent.children().into();
        let both_terminal = children.iter().all(|c| {
            state
                .boundaries
                .get(c)
                .is_some_and(|b| b.terminal_qc_wt.is_some())
        });
        if both_terminal
            && state.boundaries.get(&parent).is_some_and(|b| {
                b.block_hash == BlockHash::ZERO && b.last_live_epoch > Epoch::GENESIS
            })
        {
            parents.insert(parent);
        }
    }
    for parent in parents {
        compose_merge_parent(state, parent, epoch, windows);
    }
}

fn compose_merge_parent(
    state: &mut BeaconState,
    parent: ShardId,
    epoch: Epoch,
    windows: EpochWindows,
) {
    let (left, right) = parent.children();
    let left_b = state.boundaries[&left];
    let right_b = state.boundaries[&right];
    // The merged chain's clock anchors at the start of the epoch the left
    // child's terminal block fell in — floored from its certifying QC's
    // weighted timestamp, the same value the keeper derives off the same
    // QC in `merge_genesis_from_terminals`. Flooring `terminal_epoch`'s
    // window end instead would diverge whenever a child coasted more than
    // one epoch past its cut, so the keeper's reconstruction would not
    // reproduce this genesis hash.
    let left_terminal_wt = left_b
        .terminal_qc_wt
        .expect("a child in compose has folded its terminal");
    let cut_wt = windows.window_of(windows.epoch_for(left_terminal_wt)).start;
    let composed = SplitChildRoots {
        left: left_b.state_root,
        right: right_b.state_root,
    }
    .composed_root();
    let genesis = BlockHeader::merge_parent_genesis(
        parent,
        composed,
        (left_b.block_hash, left_b.height),
        (right_b.block_hash, right_b.height),
        cut_wt,
    );
    state.boundaries.insert(
        parent,
        ShardBoundary {
            state_root: composed,
            block_hash: genesis.hash(),
            height: genesis.height(),
            weighted_timestamp: genesis.parent_qc().weighted_timestamp(),
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            last_live_epoch: epoch,
            consecutive_misses: 0,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
            reshape_admitted_epoch: None,
            reveals_fenced_below: None,
        },
    );
    tracing::info!(
        ?parent,
        "Merged shard anchor composed from terminal child roots"
    );
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconProposal, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader,
        BlockHeight, BoundedVec, CertificateRoot, Epoch, Hash, InFlightCount, LeafIndex,
        LocalReceiptRoot, MAX_WITNESSES_PER_SHARD, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, SettledWavesRoot, ShardBoundary, ShardCommittee, ShardId,
        ShardWitness, ShardWitnessPayload, ShardWitnessProof, SignerBitfield, SplitChildRoots,
        Stake, StakePoolId, StateRoot, TransactionRoot, TransitionCause, ValidatorId, VrfProof,
        WeightedTimestamp, compute_merkle_root_with_proof, zero_bls_signature,
    };

    use super::*;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, net, single_pool_state,
    };

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
        boundary_block_full(
            shard, height, pred_wt, state_root, root, leaf_count, None, None,
        )
    }

    #[allow(clippy::too_many_arguments)] // test fixture mirroring the header fields it sets
    fn boundary_block_full(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        root: BeaconWitnessRoot,
        leaf_count: u64,
        split_child_roots: Option<SplitChildRoots>,
        settled_waves_root: Option<SettledWavesRoot>,
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
            split_child_roots,
            settled_waves_root,
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
        boundary_block_with_payloads_full(shard, height, pred_wt, state_root, payloads, None, None)
    }

    /// [`boundary_block_with_payloads`] with `split_child_roots` set at
    /// construction, so the per-leaf proofs anchor to the carrying
    /// header's final hash (the terminal-block shape).
    fn boundary_block_with_payloads_full(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        payloads: Vec<ShardWitnessPayload>,
        split_child_roots: Option<SplitChildRoots>,
        settled_waves_root: Option<SettledWavesRoot>,
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
        let header = boundary_block_full(
            shard,
            height,
            pred_wt,
            state_root,
            root,
            leaf_count,
            split_child_roots,
            settled_waves_root,
        );
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

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );

        let recorded = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(recorded.state_root, anchor);
        assert_eq!(recorded.height, BlockHeight::new(5));
        assert_eq!(recorded.witness_leaf_count, BeaconWitnessLeafCount::new(7));
        // The record carries the boundary header's own window base — the
        // retention floor serving members hold for snap-sync assembly.
        assert_eq!(
            recorded.witness_base,
            contributions[&shard].boundary_header.beacon_witness_base(),
        );
        assert_eq!(recorded.last_live_epoch, Epoch::new(1));
        assert_eq!(recorded.consecutive_misses, 0);
        // Folding the shard's own crossing marks it produced past genesis —
        // the successor-liveness signal the reshape handoff reads.
        assert!(state.advanced.contains(&shard));
    }

    /// The boundary fold hands the epoch's reveal-leaf outputs to the
    /// randomness roll: exactly the applied chunk's `RandomnessReveal`
    /// payloads, in leaf order, keyed by shard and carrying the
    /// crossing's boundary height for the recovery fence.
    #[test]
    fn record_boundaries_collects_reveal_outputs_in_leaf_order() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        let payloads = vec![
            ShardWitnessPayload::RandomnessReveal {
                output: VrfOutput::new([7; 32]),
            },
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200),
                amount: Stake::from_whole_tokens(1),
            },
            ShardWitnessPayload::RandomnessReveal {
                output: VrfOutput::new([9; 32]),
            },
        ];
        let (b, witnesses) = boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, payloads);
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

        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );

        let chunk = reveals.get(&shard).expect("reveals collected");
        assert_eq!(
            chunk,
            &vec![VrfOutput::new([7; 32]), VrfOutput::new([9; 32])],
        );
    }

    /// A committed re-fold of the recorded crossing with no witness
    /// progress is a miss, not a refresh: the counter keeps accumulating,
    /// `last_live_epoch` stays at the original fold, and a pending
    /// recovery's retention record survives. Without this a halted shard
    /// whose stale crossing keeps riding proposals resets its counter
    /// every epoch and never flags.
    #[test]
    fn record_boundaries_ignores_a_no_progress_refold() {
        use hyperscale_types::HaltRecovery;

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
        let fresh: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b.clone(),
                witnesses: witnesses.into(),
            },
        ))
        .collect();
        record_boundaries(&mut state, &net(), Epoch::new(1), &committed, &fresh);
        assert_eq!(state.boundaries[&shard].consecutive_misses, 0);

        state.pending_recoveries.insert(
            shard,
            HaltRecovery {
                rotated_at: Epoch::new(1),
                retained: Vec::new(),
                attested_frontier: BlockHeight::GENESIS,
            },
        );

        // The same crossing rides a later epoch's proposals; its chunk is
        // already drained, so the re-fold carries no progress.
        let refold: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                witnesses: BoundedVec::new(),
            },
        ))
        .collect();
        record_boundaries(&mut state, &net(), Epoch::new(2), &committed, &refold);

        let recorded = &state.boundaries[&shard];
        assert_eq!(
            recorded.consecutive_misses, 1,
            "a no-progress re-fold must read as a miss",
        );
        assert_eq!(recorded.last_live_epoch, Epoch::new(1));
        assert!(
            state.pending_recoveries.contains_key(&shard),
            "a stale re-fold must not release the recovery's retention",
        );
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
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
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
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
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
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );

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
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
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

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );

        assert_eq!(state.boundaries.get(&shard).unwrap().consecutive_misses, 1,);
    }

    /// A backlog larger than `MAX_WITNESSES_PER_SHARD` drains in bounded
    /// chunks across successive epochs: the applied watermark climbs by at
    /// most the cap each epoch — never jumping straight to the boundary's
    /// full leaf count — while the anchor stays pinned to the crossing,
    /// until the watermark reaches that count. The contribution for each
    /// epoch carries only that epoch's chunk, all proving against the one
    /// boundary block's accumulator root.
    ///
    /// Draining is not liveness: each re-fold of the same crossing bumps
    /// the miss counter, keeps the recorded live epoch, and holds a
    /// pending recovery's retention, so a halting committee cannot defer
    /// halt detection behind a pre-loaded backlog.
    #[test]
    fn record_boundaries_drains_a_backlog_over_multiple_epochs() {
        use hyperscale_types::HaltRecovery;

        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let cap = MAX_WITNESSES_PER_SHARD;
        // Two full chunks plus a small remainder, so the drain spans three
        // epochs: `[0, cap)`, `[cap, 2 * cap)`, then `[2 * cap, total)`.
        let total = 2 * cap + 3;

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

        // Epoch 1: the fresh crossing records the anchor; the watermark is
        // cap-gated — it advances to exactly the cap even though the
        // boundary commits `total > cap` leaves.
        record_boundaries(
            &mut state,
            &net(),
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
        assert_eq!(after_1.last_live_epoch, Epoch::new(1));

        // A recovery stamped mid-drain: only a fresh crossing may release
        // its retention.
        state.pending_recoveries.insert(
            shard,
            HaltRecovery {
                rotated_at: Epoch::new(1),
                retained: Vec::new(),
                attested_frontier: after_1.height,
            },
        );

        // Epoch 2: the second chunk drains against the same crossing — the
        // watermark advances, but the re-fold is a miss, not a refresh, and
        // the pending recovery survives.
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contribution_with(&witnesses[cap..2 * cap]),
        );
        let after_2 = state
            .boundaries
            .get(&shard)
            .expect("boundary still recorded");
        assert_eq!(
            after_2.witness_leaf_count,
            BeaconWitnessLeafCount::new(2 * cap as u64)
        );
        assert_eq!(after_2.block_hash, b.hash());
        assert_eq!(after_2.consecutive_misses, 1);
        assert_eq!(after_2.last_live_epoch, Epoch::new(1));
        assert!(state.pending_recoveries.contains_key(&shard));

        // Epoch 3: the remainder drains; the watermark reaches the
        // boundary's full leaf count while the miss counter keeps climbing.
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contribution_with(&witnesses[2 * cap..]),
        );
        let after_3 = state
            .boundaries
            .get(&shard)
            .expect("boundary still recorded");
        assert_eq!(
            after_3.witness_leaf_count,
            BeaconWitnessLeafCount::new(total as u64)
        );
        assert_eq!(after_3.block_hash, b.hash());
        assert_eq!(after_3.consecutive_misses, 2);
        assert_eq!(after_3.last_live_epoch, Epoch::new(1));
        assert!(state.pending_recoveries.contains_key(&shard));
    }

    /// `n` `RandomnessReveal` payloads with per-index outputs, so a
    /// chunk's folded reveals can be asserted exactly.
    fn reveal_payloads(n: usize) -> Vec<ShardWitnessPayload> {
        (0..n)
            .map(|i| ShardWitnessPayload::RandomnessReveal {
                output: reveal_output_at(i),
            })
            .collect()
    }

    fn reveal_output_at(i: usize) -> VrfOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        VrfOutput::new(bytes)
    }

    fn stamp_recovery(state: &mut BeaconState, shard: ShardId, frontier: u64) {
        use hyperscale_types::HaltRecovery;
        state.pending_recoveries.insert(
            shard,
            HaltRecovery {
                rotated_at: Epoch::new(1),
                retained: Vec::new(),
                attested_frontier: BlockHeight::new(frontier),
            },
        );
    }

    /// A crossing above a pending recovery's attested frontier holds its
    /// reveals out of the seed for its entire backlog — the completing
    /// epoch and every drain epoch after it — even though the completing
    /// fold removed the recovery record. Without the persisted fence the
    /// beyond-f retained committee's post-halt reveal backlog would seed
    /// from the second epoch onward.
    #[test]
    fn fence_covers_a_beyond_frontier_crossings_entire_drain() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let cap = MAX_WITNESSES_PER_SHARD;
        let total = cap + 3;

        stamp_recovery(&mut state, shard, 3);
        let (b, witnesses) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, reveal_payloads(total));

        // Completing epoch: the crossing (height 5 > frontier 3) folds,
        // clears the recovery, and contributes nothing to the seed; the
        // fence over its full count persists on the record.
        let (committed, contributions) =
            contribution_for(shard, b.clone(), witnesses[..cap].to_vec(), 1_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );
        assert!(reveals.is_empty(), "completing chunk is fenced");
        assert!(!state.pending_recoveries.contains_key(&shard));
        let record = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(
            record.reveals_fenced_below,
            Some(BeaconWitnessLeafCount::new(total as u64))
        );

        // Drain epoch: the backlog remainder applies but stays out of the
        // seed; the fence clears once the watermark reaches it.
        let (committed, contributions) =
            contribution_for(shard, b, witnesses[cap..].to_vec(), 1_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );
        assert!(reveals.is_empty(), "drain chunk is fenced");
        let record = state.boundaries.get(&shard).expect("boundary kept");
        assert_eq!(
            record.witness_leaf_count,
            BeaconWitnessLeafCount::new(total as u64)
        );
        assert_eq!(record.reveals_fenced_below, None);

        // The next crossing is post-recovery production: its chunk seeds.
        let (b2, witnesses2) = boundary_block_with_payloads(
            shard,
            9,
            1_900,
            StateRoot::ZERO,
            reveal_payloads(total + 2),
        );
        let (committed, contributions) =
            contribution_for(shard, b2, witnesses2[total..].to_vec(), 2_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
        );
        assert_eq!(
            reveals.get(&shard),
            Some(&vec![reveal_output_at(total), reveal_output_at(total + 1)]),
        );
    }

    /// A recovering shard's crossing at (or below) the attested frontier
    /// is legitimate retained history: its reveals fold and no fence is
    /// recorded.
    #[test]
    fn fence_admits_a_crossing_at_the_frontier() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        stamp_recovery(&mut state, shard, 5);
        let (b, witnesses) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, reveal_payloads(2));
        let (committed, contributions) = contribution_for(shard, b, witnesses, 1_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );

        assert_eq!(
            reveals.get(&shard),
            Some(&vec![reveal_output_at(0), reveal_output_at(1)]),
        );
        let record = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(record.reveals_fenced_below, None);
    }

    /// The fence survives a record refresh: when a newer crossing folds
    /// while a fenced backlog is still draining, its chunk covers leaves
    /// of the fenced band, so the carried fence keeps them out of the
    /// seed; only content past the band seeds.
    #[test]
    fn fence_carries_across_a_record_refresh() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let cap = MAX_WITNESSES_PER_SHARD;
        let band = 2 * cap;

        stamp_recovery(&mut state, shard, 3);
        let (b, witnesses) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, reveal_payloads(band));

        // Completing epoch: first chunk of the beyond-frontier backlog.
        let (committed, contributions) =
            contribution_for(shard, b, witnesses[..cap].to_vec(), 1_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
        );
        assert!(reveals.is_empty());
        assert_eq!(
            state.boundaries.get(&shard).unwrap().reveals_fenced_below,
            Some(BeaconWitnessLeafCount::new(band as u64))
        );

        // A newer crossing extends the same chain mid-drain (the shape a
        // crossing eviction produces). Its chunk still sits inside the
        // fenced band: no seeding, and the refreshed record keeps the
        // fence only while leaves below it remain.
        let (b2, witnesses2) = boundary_block_with_payloads(
            shard,
            9,
            1_900,
            StateRoot::ZERO,
            reveal_payloads(band + 3),
        );
        let (committed, contributions) =
            contribution_for(shard, b2.clone(), witnesses2[cap..band].to_vec(), 2_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );
        assert!(reveals.is_empty(), "carried fence covers the band");
        let record = state.boundaries.get(&shard).expect("record refreshed");
        assert_eq!(record.block_hash, b2.hash());
        assert_eq!(record.reveals_fenced_below, None, "band fully drained");

        // The newer crossing's own remainder is past the band: it seeds.
        let (committed, contributions) =
            contribution_for(shard, b2, witnesses2[band..].to_vec(), 2_500);
        let (_, reveals) = record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
        );
        assert_eq!(
            reveals.get(&shard),
            Some(&vec![
                reveal_output_at(band),
                reveal_output_at(band + 1),
                reveal_output_at(band + 2),
            ]),
        );
    }

    // ─── halt detection ──────────────────────────────────────────────────

    /// The fold surfaces the halted-shard set on `SlotEffects`: a live
    /// shard whose boundary watermark stalls flags on the first epoch
    /// past `HALT_THRESHOLD_EPOCHS` — never before — and a fresh
    /// crossing refreshes the watermark and clears the flag.
    #[test]
    fn apply_epoch_flags_a_stalled_shard_and_a_crossing_clears_it() {
        use hyperscale_types::HALT_THRESHOLD_EPOCHS;

        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let deposit = ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(200),
            amount: Stake::from_whole_tokens(1),
        };

        // Epoch 1 folds a real crossing: the watermark is fresh.
        let effects = apply_witness_chunk(&mut state, 0, vec![deposit.clone()]);
        assert!(effects.halted_shards.is_empty());

        // Quiet epochs up to the threshold: not flagged.
        for _ in 0..HALT_THRESHOLD_EPOCHS {
            let effects = apply_next_epoch(&mut state, &[]);
            assert!(
                effects.halted_shards.is_empty(),
                "flagged early at epoch {}",
                state.current_epoch,
            );
        }

        // The first epoch past the threshold flags the shard.
        let effects = apply_next_epoch(&mut state, &[]);
        assert_eq!(effects.halted_shards, BTreeSet::from([shard]));

        // A fresh crossing clears it.
        let effects = apply_witness_chunk(&mut state, 0, vec![deposit]);
        assert!(effects.halted_shards.is_empty());
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

    /// A terminal boundary block: `leaf_count` deposit witnesses plus a
    /// `split_child_roots` pair carried from construction (so the
    /// per-leaf proofs anchor to the final header hash).
    fn terminal_block_with_witnesses(
        shard: ShardId,
        height: u64,
        pred_wt: u64,
        pair: SplitChildRoots,
        state_root: StateRoot,
        leaf_count: u64,
        settled_waves_root: Option<SettledWavesRoot>,
    ) -> (BlockHeader, Vec<ShardWitness>) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200 + u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        boundary_block_with_payloads_full(
            shard,
            height,
            pred_wt,
            state_root,
            payloads,
            Some(pair),
            settled_waves_root,
        )
    }

    /// A terminal-marked parent (final epoch 1, cut at 2000ms) with both
    /// children pending, plus the composing child-root pair.
    fn terminating_state() -> (BeaconState, ShardId, SplitChildRoots, StateRoot) {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let parent = ShardId::leaf(1, 0);
        state.boundaries.insert(
            parent,
            ShardBoundary {
                state_root: StateRoot::from_raw(Hash::from_bytes(b"pre-terminal")),
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"pre-terminal-block")),
                height: BlockHeight::new(8),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: Some(Epoch::new(1)),
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            },
        );
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.boundaries.insert(
                child,
                ShardBoundary {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: BlockHeight::GENESIS,
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    terminal_qc_wt: None,
                    settled_waves_root: None,
                    reshape_admitted_epoch: None,
                    reveals_fenced_below: None,
                },
            );
        }
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let composed = pair.composed_root();
        (state, parent, pair, composed)
    }

    fn contribution_for(
        shard: ShardId,
        header: BlockHeader,
        witnesses: Vec<ShardWitness>,
        qc_wt: u64,
    ) -> (
        Vec<(ValidatorId, BeaconProposal)>,
        BTreeMap<ShardId, ShardEpochContribution>,
    ) {
        let qc = qc_over(&header, qc_wt);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: header,
                witnesses: witnesses.into(),
            },
        ))
        .collect();
        (committed, contributions)
    }

    /// The terminal contribution — predecessor inside the final window,
    /// QC past its cut, carrying a composing pair — seeds both pending
    /// children with their verified subtree roots and deterministic
    /// genesis hashes, and the parent's terminal record lingers (carrying
    /// its settled-waves root for surviving counterparts) past the drain.
    #[test]
    fn terminal_contribution_seeds_the_children_and_retains_the_parent() {
        let (mut state, parent, pair, composed) = terminating_state();
        let (left, right) = parent.children();

        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header.clone(), witnesses, 2_500);

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        for (child, child_root) in [(left, pair.left), (right, pair.right)] {
            let record = state.boundaries.get(&child).expect("child seeded");
            let genesis = BlockHeader::split_child_genesis(
                child,
                child_root,
                &header,
                WeightedTimestamp::from_millis(2_500),
            );
            assert_eq!(record.state_root, child_root);
            assert_eq!(record.block_hash, genesis.hash());
            assert_eq!(record.height, BlockHeight::new(10));
            assert_eq!(record.witness_leaf_count, BeaconWitnessLeafCount::ZERO);
            assert_eq!(record.terminal_epoch, None);
        }
        let record = state
            .boundaries
            .get(&parent)
            .expect("terminal record lingers for the retention window");
        assert_eq!(record.terminal_epoch, Some(Epoch::new(1)));
        assert_eq!(record.block_hash, header.hash());
    }

    /// A pair that does not compose to the terminal root leaves the
    /// children pending (they seed from their own first contributions);
    /// the parent's terminal record still lingers past the drain.
    #[test]
    fn non_composing_pair_leaves_children_pending() {
        let (mut state, parent, pair, composed) = terminating_state();
        let forged = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"forged")),
            right: pair.right,
        };
        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, forged, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header, witnesses, 2_500);

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        for child in <[ShardId; 2]>::from(parent.children()) {
            let record = state.boundaries.get(&child).expect("placeholder kept");
            assert_eq!(record.block_hash, BlockHash::ZERO, "child stays pending");
        }
        assert!(
            state.boundaries.contains_key(&parent),
            "terminal record lingers"
        );
    }

    /// A crossing of an earlier cut (QC inside the final window) records
    /// normally but is not the terminal block: no seeding, no drop.
    #[test]
    fn pre_terminal_crossing_does_not_seed() {
        let (mut state, parent, pair, composed) = terminating_state();
        let (left, _) = parent.children();

        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 900, pair, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header, witnesses, 1_500);

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        let record = state.boundaries.get(&parent).expect("record kept");
        assert_eq!(
            record.terminal_epoch,
            Some(Epoch::new(1)),
            "marker survives"
        );
        assert_eq!(
            state.boundaries.get(&left).unwrap().block_hash,
            BlockHash::ZERO,
            "children untouched"
        );
    }

    /// A terminal record with no contribution this fold carries forward
    /// without a miss bump — the chain stopped on purpose.
    #[test]
    fn terminal_records_do_not_bump_misses() {
        let (mut state, parent, _, _) = terminating_state();

        record_boundaries(&mut state, &net(), Epoch::new(2), &[], &BTreeMap::new());

        assert_eq!(state.boundaries.get(&parent).unwrap().consecutive_misses, 0);
    }

    /// A terminal backlog deeper than one chunk drains over two folds: the
    /// children seed at the first terminal fold, the record applies one
    /// chunk and survives, and the next fold's continuation chunk completes
    /// the drain. The record then lingers (within the retention window) to
    /// project the terminated shard's settled-waves root.
    #[test]
    fn deep_terminal_backlog_drains_over_two_folds() {
        let (mut state, parent, pair, composed) = terminating_state();
        let total = MAX_WITNESSES_PER_SHARD as u64 + 6;

        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, total, None);

        let first_chunk = witnesses[..MAX_WITNESSES_PER_SHARD].to_vec();
        let (committed, contributions) =
            contribution_for(parent, header.clone(), first_chunk, 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        let record = state.boundaries.get(&parent).expect("lingers mid-drain");
        assert_eq!(
            record.witness_leaf_count,
            BeaconWitnessLeafCount::new(MAX_WITNESSES_PER_SHARD as u64)
        );
        let (left, _) = parent.children();
        assert_ne!(
            state.boundaries.get(&left).unwrap().block_hash,
            BlockHash::ZERO,
            "children seed at the first terminal fold"
        );

        let rest = witnesses[MAX_WITNESSES_PER_SHARD..].to_vec();
        let (committed, contributions) = contribution_for(parent, header, rest, 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
        );

        let record = state
            .boundaries
            .get(&parent)
            .expect("terminal record lingers past the drain");
        assert_eq!(
            record.witness_leaf_count,
            BeaconWitnessLeafCount::new(total),
            "the second chunk completed the drain",
        );
    }

    /// A terminal record drops once the chain advances past its retention
    /// horizon — it lingers only to project the settled-waves root, dead
    /// weight once the fence rejects naming the shard regardless.
    #[test]
    fn terminal_record_drops_past_the_retention_horizon() {
        let (mut state, parent, pair, composed) = terminating_state();
        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header, witnesses, 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );
        assert!(
            state.boundaries.contains_key(&parent),
            "lingers within the retention window",
        );

        // The children seat and produce past their genesis — the handoff is
        // done, so the parent's record is dead weight, free to drop on the next
        // horizon sweep.
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.advanced.insert(child);
        }
        // Advance to an epoch whose window opens past the terminal cut
        // (2000ms at epoch_duration 1000) plus `RETENTION_HORIZON`.
        let past = Epoch::new(RETENTION_HORIZON.as_secs() + 5);
        record_boundaries(&mut state, &net(), past, &[], &BTreeMap::new());
        assert!(
            !state.boundaries.contains_key(&parent),
            "terminal record drops past the retention horizon once its children are live",
        );
    }

    /// The handoff stall diagnostic fires exactly at the bound: a terminal
    /// shard whose successors are still not live `RESHAPE_HANDOFF_TTL_EPOCHS`
    /// epochs after its reshape executed is flagged; one epoch shy it stays
    /// quiet.
    #[test]
    fn stalled_handoffs_fire_at_the_ttl_not_before() {
        let parent = ShardId::ROOT;
        let executed_at = Epoch::new(5);
        let pending = BTreeMap::from([(parent, executed_at)]);

        let just_under = Epoch::new(executed_at.inner() + RESHAPE_HANDOFF_TTL_EPOCHS - 1);
        assert!(
            stalled_handoffs(&pending, just_under).is_empty(),
            "quiet one epoch shy of the bound",
        );

        let at_bound = Epoch::new(executed_at.inner() + RESHAPE_HANDOFF_TTL_EPOCHS);
        assert_eq!(
            stalled_handoffs(&pending, at_bound),
            vec![(parent, executed_at)],
            "flagged once the bound is reached",
        );
    }

    /// A split parent whose children are still placeholders outlives the
    /// retention horizon. The children seed only from the parent's terminal
    /// fold, and the beacon can commit empty for several epochs across the
    /// reshape's committee transition before any non-empty commit carries
    /// that fold — dropping the record on the horizon alone would strand
    /// both children on their placeholders forever.
    #[test]
    fn unseeded_split_parent_outlives_the_retention_horizon() {
        let (mut state, parent, pair, composed) = terminating_state();

        // The beacon commits empty well past the horizon: no terminal fold
        // yet, so both children stay on their placeholder anchors.
        let past = Epoch::new(RETENTION_HORIZON.as_secs() + 5);
        record_boundaries(&mut state, &net(), past, &[], &BTreeMap::new());
        assert!(
            state.boundaries.contains_key(&parent),
            "an unseeded split parent is held past the horizon",
        );
        for child in <[ShardId; 2]>::from(parent.children()) {
            assert_eq!(
                state.boundaries.get(&child).unwrap().block_hash,
                BlockHash::ZERO,
                "children still pending",
            );
        }

        // The terminal contribution finally lands: it seeds both children.
        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header, witnesses, 2_500);
        let later = Epoch::new(RETENTION_HORIZON.as_secs() + 6);
        record_boundaries(&mut state, &net(), later, &committed, &contributions);

        for child in <[ShardId; 2]>::from(parent.children()) {
            assert_ne!(
                state.boundaries.get(&child).unwrap().block_hash,
                BlockHash::ZERO,
                "children seed from the terminal fold",
            );
        }
        // Seeded is not yet live: the parent is held until its children produce,
        // so a straggling observer can still snap-sync its terminal anchor while
        // it coasts under make-before-break.
        assert!(
            state.boundaries.contains_key(&parent),
            "a seeded-but-not-live parent is still held",
        );

        // The children produce past their genesis — the handoff is complete, so
        // the parent drops on the next horizon sweep.
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.advanced.insert(child);
        }
        let even_later = Epoch::new(RETENTION_HORIZON.as_secs() + 7);
        record_boundaries(&mut state, &net(), even_later, &[], &BTreeMap::new());
        assert!(
            !state.boundaries.contains_key(&parent),
            "the parent drops once its children are live",
        );
    }

    /// A merge child whose parent is still an uncomposed placeholder outlives
    /// the retention horizon. The parent composes only from both children's
    /// terminal folds, and the beacon can commit empty for several epochs
    /// across the reshape's committee transition before either fold lands —
    /// dropping a child on the horizon alone would strand the parent on its
    /// placeholder forever.
    #[test]
    fn merge_child_outlives_horizon_until_parent_composes() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();

        // The placeholder a merge execution seeds, still uncomposed.
        state.boundaries.insert(
            parent,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            },
        );
        // Both children have folded their terminal contribution (a real
        // anchor, `terminal_qc_wt` set), waiting for the parent to compose.
        for child in [left, right] {
            state.boundaries.insert(
                child,
                ShardBoundary {
                    state_root: StateRoot::from_raw(Hash::from_bytes(b"child terminal root")),
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"child terminal block")),
                    height: BlockHeight::new(9),
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: Some(Epoch::new(1)),
                    terminal_qc_wt: Some(WeightedTimestamp::from_millis(1_900)),
                    settled_waves_root: None,
                    reshape_admitted_epoch: None,
                    reveals_fenced_below: None,
                },
            );
        }

        // The reformed parent's live committee — present only once the merge
        // actually reforms it, distinct from the placeholder record above.
        state.shard_committees.insert(
            parent,
            ShardCommittee {
                members: vec![ValidatorId::new(0)],
            },
        );

        // The beacon commits empty well past the horizon: the parent hasn't
        // composed, so both children's terminal records must be held.
        let past = Epoch::new(RETENTION_HORIZON.as_secs() + 5);
        record_boundaries(&mut state, &net(), past, &[], &BTreeMap::new());
        for child in [left, right] {
            assert!(
                state.boundaries.contains_key(&child),
                "a merge child is held past the horizon while its parent is uncomposed",
            );
        }

        // The parent composes — a real anchor — but composing is not yet live:
        // the children are still held so the reformed parent can keep seeding
        // from them while it comes up.
        state
            .boundaries
            .get_mut(&parent)
            .expect("parent placeholder")
            .block_hash = BlockHash::from_raw(Hash::from_bytes(b"composed parent"));
        let later = Epoch::new(RETENTION_HORIZON.as_secs() + 6);
        record_boundaries(&mut state, &net(), later, &[], &BTreeMap::new());
        for child in [left, right] {
            assert!(
                state.boundaries.contains_key(&child),
                "a merge child is held while the reformed parent is composed but not yet live",
            );
        }

        // The reformed parent produces past its genesis — the handoff completes,
        // so the children drop on the next horizon sweep.
        state.advanced.insert(parent);
        let even_later = Epoch::new(RETENTION_HORIZON.as_secs() + 7);
        record_boundaries(&mut state, &net(), even_later, &[], &BTreeMap::new());
        for child in [left, right] {
            assert!(
                !state.boundaries.contains_key(&child),
                "a merge child drops once its reformed parent is live",
            );
        }
    }

    /// A terminal contribution carrying a `settled_waves_root` folds it
    /// onto the parent's boundary record and projects it onto the
    /// snap-sync anchor — the path a surviving counterpart reads the
    /// terminated shard's settled-waves commitment from. Folded with a
    /// lingering backlog so the terminal record survives the fold (a
    /// fully drained one drops in-fold).
    #[test]
    fn terminal_settled_waves_root_folds_and_projects() {
        let (mut state, parent, pair, composed) = terminating_state();
        let total = MAX_WITNESSES_PER_SHARD as u64 + 6;
        let root = SettledWavesRoot::from_raw(Hash::from_bytes(b"settled waves"));

        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, total, Some(root));
        let first_chunk = witnesses[..MAX_WITNESSES_PER_SHARD].to_vec();
        let (committed, contributions) = contribution_for(parent, header, first_chunk, 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        let folded = state.boundaries.get(&parent).expect("lingers mid-drain");
        assert_eq!(folded.settled_waves_root, Some(root));

        // The projection carries the root onto the anchor regardless of
        // trie membership: a terminated parent leaves the trie, but its
        // boundary record projects from the global map.
        let anchor = state
            .derive_topology_snapshot(net())
            .boundary(parent)
            .expect("terminal record projects");
        assert_eq!(anchor.settled_waves_root, Some(root));
    }

    // ─── merge parent composition ────────────────────────────────────────

    /// A pending merge parent (zero-hash placeholder, final epoch 1, cut
    /// at 2000ms) whose two children are live with real anchors marked
    /// terminal at epoch 1. The terminal roots seed the contributions.
    fn merge_terminating_state() -> (BeaconState, ShardId, StateRoot, StateRoot) {
        let mut state = single_pool_state(0);
        state.chain_config.epoch_duration_ms = 1_000;
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let left_root = StateRoot::from_raw(Hash::from_bytes(b"left terminal root"));
        let right_root = StateRoot::from_raw(Hash::from_bytes(b"right terminal root"));
        for (child, root, height) in [(left, left_root, 7), (right, right_root, 8)] {
            state.boundaries.insert(
                child,
                ShardBoundary {
                    state_root: root,
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
                    height: BlockHeight::new(height),
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: Some(Epoch::new(1)),
                    terminal_qc_wt: None,
                    settled_waves_root: None,
                    reshape_admitted_epoch: None,
                    reveals_fenced_below: None,
                },
            );
        }
        state.boundaries.insert(
            parent,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            },
        );
        (state, parent, left_root, right_root)
    }

    /// The merged anchor a keeper installs for the given terminal pair.
    fn expected_merge_anchor(
        parent: ShardId,
        left: &BlockHeader,
        right: &BlockHeader,
        cut_ms: u64,
    ) -> BlockHeader {
        let composed = SplitChildRoots {
            left: left.state_root(),
            right: right.state_root(),
        }
        .composed_root();
        BlockHeader::merge_parent_genesis(
            parent,
            composed,
            (left.hash(), left.height()),
            (right.hash(), right.height()),
            WeightedTimestamp::from_millis(cut_ms),
        )
    }

    /// Both children's terminal contributions in one fold compose the
    /// parent — `hash_internal(r_p0, r_p1)` and the deterministic merged
    /// genesis — while the children hold their terminal records so the
    /// composition can still read both roots.
    #[test]
    fn terminal_children_compose_the_merge_parent() {
        let (mut state, parent, left_root, right_root) = merge_terminating_state();
        let (left, right) = parent.children();

        let (lh, lw) =
            boundary_block_with_payloads_full(left, 9, 1_900, left_root, vec![], None, None);
        let (rh, rw) =
            boundary_block_with_payloads_full(right, 10, 1_900, right_root, vec![], None, None);
        let proposal = BeaconProposal::new(
            [
                (left, Some(qc_over(&lh, 2_500))),
                (right, Some(qc_over(&rh, 2_500))),
            ]
            .into_iter()
            .collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = [
            (
                left,
                ShardEpochContribution {
                    boundary_header: lh.clone(),
                    witnesses: lw.into(),
                },
            ),
            (
                right,
                ShardEpochContribution {
                    boundary_header: rh.clone(),
                    witnesses: rw.into(),
                },
            ),
        ]
        .into_iter()
        .collect();

        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        let anchor = expected_merge_anchor(parent, &lh, &rh, 2_000);
        let record = state.boundaries.get(&parent).expect("parent composed");
        assert_eq!(record.state_root, anchor.state_root());
        assert_eq!(record.block_hash, anchor.hash());
        assert_eq!(record.height, BlockHeight::new(11));
        assert_eq!(record.terminal_epoch, None);
        // The children hold their terminal records this fold so both
        // roots stay readable for the composition.
        assert!(state.boundaries.contains_key(&left));
        assert!(state.boundaries.contains_key(&right));
    }

    /// A final-window refresh certified exactly on the terminal cut is
    /// not the terminal contribution — the boundary instant counts as
    /// not yet crossed — so its pre-freeze root never composes the
    /// merge parent. The real coast block past the cut then composes
    /// with the frozen terminal root.
    #[test]
    fn exact_cut_refresh_does_not_compose_the_merge_parent() {
        let (mut state, parent, left_root, right_root) = merge_terminating_state();
        let (left, right) = parent.children();

        // Right child: genuine terminal coast (crosses the 2_000 cut).
        let (rh, rw) =
            boundary_block_with_payloads_full(right, 10, 1_900, right_root, vec![], None, None);
        // Left child: spans its whole final window — anchored before the
        // window opens, certified exactly on the terminal cut. A genuine
        // crossing (of the cut INTO the final window), carrying the
        // still-running chain's pre-freeze root.
        let pre_freeze = StateRoot::from_raw(Hash::from_bytes(b"left pre-freeze root"));
        let (span_header, span_witnesses) =
            boundary_block_with_payloads_full(left, 9, 900, pre_freeze, vec![], None, None);
        let proposal = BeaconProposal::new(
            [
                (left, Some(qc_over(&span_header, 2_000))),
                (right, Some(qc_over(&rh, 2_500))),
            ]
            .into_iter()
            .collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = [
            (
                left,
                ShardEpochContribution {
                    boundary_header: span_header,
                    witnesses: span_witnesses.into(),
                },
            ),
            (
                right,
                ShardEpochContribution {
                    boundary_header: rh.clone(),
                    witnesses: rw.into(),
                },
            ),
        ]
        .into_iter()
        .collect();
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );

        // The spanning refresh recorded — but as a live refresh, not a
        // terminal: no terminal_qc_wt, and the parent stays pending
        // rather than composing with the pre-freeze root.
        let left_record = state.boundaries.get(&left).expect("left refreshed");
        assert_eq!(left_record.state_root, pre_freeze);
        assert_eq!(left_record.terminal_qc_wt, None);
        let parent_record = state.boundaries.get(&parent).expect("parent tracked");
        assert_eq!(
            parent_record.block_hash,
            BlockHash::ZERO,
            "parent composed early"
        );

        // The real coast block crosses the cut with the frozen root; the
        // parent composes from it and the lingering right terminal.
        let (coast_header, coast_witnesses) =
            boundary_block_with_payloads_full(left, 10, 2_000, left_root, vec![], None, None);
        let proposal = BeaconProposal::new(
            std::iter::once((left, Some(qc_over(&coast_header, 2_100)))).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = std::iter::once((
            left,
            ShardEpochContribution {
                boundary_header: coast_header.clone(),
                witnesses: coast_witnesses.into(),
            },
        ))
        .collect();
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
        );

        let anchor = expected_merge_anchor(parent, &coast_header, &rh, 2_000);
        let record = state.boundaries.get(&parent).expect("parent composed");
        assert_eq!(record.state_root, anchor.state_root());
        assert_eq!(record.block_hash, anchor.hash());
    }

    /// A lone terminal child holds its record across folds until its
    /// sibling lands and the parent composes; once the parent is no
    /// longer pending, the children drain and drop.
    #[test]
    fn a_lone_terminal_child_holds_until_its_sibling_composes_the_parent() {
        let (mut state, parent, left_root, right_root) = merge_terminating_state();
        let (left, right) = parent.children();
        let (lh, lw) =
            boundary_block_with_payloads_full(left, 9, 1_900, left_root, vec![], None, None);
        let (rh, rw) =
            boundary_block_with_payloads_full(right, 10, 1_900, right_root, vec![], None, None);

        // Both children's terminal records, sourced together — the
        // proposer re-sources every lingering terminal record each fold.
        let both = |left_qc_wt: u64, right_qc_wt: u64| {
            let proposal = BeaconProposal::new(
                [
                    (left, Some(qc_over(&lh, left_qc_wt))),
                    (right, Some(qc_over(&rh, right_qc_wt))),
                ]
                .into_iter()
                .collect(),
                Vec::new(),
                VrfProof::ZERO,
            );
            let committed = vec![(ValidatorId::new(0), proposal)];
            let contributions = [
                (
                    left,
                    ShardEpochContribution {
                        boundary_header: lh.clone(),
                        witnesses: lw.clone().into(),
                    },
                ),
                (
                    right,
                    ShardEpochContribution {
                        boundary_header: rh.clone(),
                        witnesses: rw.clone().into(),
                    },
                ),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>();
            (committed, contributions)
        };

        // Fold E: only the left child terminates. It is held (the parent
        // can't compose without the sibling) and the parent stays pending.
        let (committed, contributions) = contribution_for(left, lh.clone(), lw.clone(), 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
        );
        assert!(state.boundaries.contains_key(&left), "left held");
        assert_eq!(
            state.boundaries[&parent].block_hash,
            BlockHash::ZERO,
            "parent still pending"
        );

        // Fold E+1: only the right child lands — the left does not re-source
        // this fold. The parent composes anyway, off the left's persisted
        // terminal record, so the compose no longer hinges on both terminals
        // landing in a single fold (the case staggered witness fetches miss).
        let (committed, contributions) = contribution_for(right, rh.clone(), rw.clone(), 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
        );
        let anchor = expected_merge_anchor(parent, &lh, &rh, 2_000);
        assert_eq!(state.boundaries[&parent].block_hash, anchor.hash());
        assert!(
            state.boundaries.contains_key(&left),
            "children held at compose"
        );

        // Fold E+2: the children re-source again and, with the parent
        // composed, linger past the drain (carrying their settled-waves
        // roots for surviving counterparts) until the retention GC.
        let (committed, contributions) = both(2_500, 2_500);
        record_boundaries(
            &mut state,
            &net(),
            Epoch::new(4),
            &committed,
            &contributions,
        );
        assert!(state.boundaries.contains_key(&left), "left lingers");
        assert!(state.boundaries.contains_key(&right), "right lingers");
        assert_eq!(
            state.boundaries[&parent].block_hash,
            anchor.hash(),
            "parent anchor unchanged"
        );
    }

    /// Members a split places on a fresh child classify by provenance:
    /// observer seats reopen their synced store, parent members
    /// hard-link a checkpoint. Pre-existing shards contribute nothing.
    #[test]
    fn split_adoptions_classify_parent_half_and_observer() {
        let mut state = single_pool_state(4);
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let observer = ValidatorId::new(1000);

        let pre_members: BTreeMap<ShardId, Vec<ValidatorId>> = state
            .next_shard_committees
            .iter()
            .map(|(s, c)| (*s, c.members.clone()))
            .collect();
        let pre_seats: BTreeMap<(ValidatorId, ShardId), ShardId> =
            std::iter::once(((observer, parent), left)).collect();

        // The execution's committee mutation: parent out, children in.
        let parent_members = state
            .next_shard_committees
            .remove(&parent)
            .expect("fixture seats the parent")
            .members;
        state.next_shard_committees.insert(
            left,
            ShardCommittee {
                members: vec![parent_members[0], parent_members[1], observer],
            },
        );
        state.next_shard_committees.insert(
            right,
            ShardCommittee {
                members: vec![parent_members[2], parent_members[3]],
            },
        );

        let parent_halves = diff_split_parent_halves(&state, &pre_members, &pre_seats);

        // The parent halves project keyed by the child each one lands on,
        // mapping member to the parent it re-roots from; the observer reopens
        // its own synced store, so it is not among them.
        assert_eq!(parent_halves[&left].get(&parent_members[0]), Some(&parent));
        assert_eq!(parent_halves[&left].get(&parent_members[1]), Some(&parent));
        assert_eq!(parent_halves[&right].get(&parent_members[2]), Some(&parent));
        assert_eq!(parent_halves[&right].get(&parent_members[3]), Some(&parent));
        assert!(!parent_halves[&left].contains_key(&observer));
        assert_eq!(parent_halves[&left].len() + parent_halves[&right].len(), 4);
    }

    /// A parent half's cohort survives until its child commits past genesis —
    /// a real anchor whose witness watermark has advanced.
    #[test]
    fn parent_halves_release_once_the_child_is_established() {
        use hyperscale_types::{BlockHeight, Hash, StateRoot, WeightedTimestamp};

        fn boundary(block_hash: BlockHash, witness: BeaconWitnessLeafCount) -> ShardBoundary {
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash,
                height: BlockHeight::GENESIS,
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: witness,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            }
        }

        let mut state = single_pool_state(4);
        let parent = ShardId::leaf(1, 0);
        let (child, _) = parent.children();
        let member = ValidatorId::new(7);
        state
            .reshape_parent_halves
            .insert(child, std::iter::once((member, parent)).collect());

        // A placeholder child (zero anchor) keeps the cohort.
        state.boundaries.insert(
            child,
            boundary(BlockHash::ZERO, BeaconWitnessLeafCount::ZERO),
        );
        release_seated_parent_halves(&mut state);
        assert!(
            state.reshape_parent_halves.contains_key(&child),
            "a placeholder child keeps its parent halves",
        );

        // A seeded anchor that has not yet produced keeps it.
        let seeded = BlockHash::from_raw(Hash::from_bytes(b"child-genesis"));
        state
            .boundaries
            .insert(child, boundary(seeded, BeaconWitnessLeafCount::ZERO));
        release_seated_parent_halves(&mut state);
        assert!(
            state.reshape_parent_halves.contains_key(&child),
            "a seeded but quiet child keeps its parent halves",
        );

        // A live child that has folded a contribution drops it.
        state
            .boundaries
            .insert(child, boundary(seeded, BeaconWitnessLeafCount::new(1)));
        release_seated_parent_halves(&mut state);
        assert!(
            !state.reshape_parent_halves.contains_key(&child),
            "an established child releases its parent halves",
        );
    }

    /// The retained parent halves project onto the head snapshot keyed by
    /// child, so the orchestrator can discover them.
    #[test]
    fn parent_halves_project_onto_the_head_snapshot() {
        let mut state = single_pool_state(4);
        let parent = ShardId::leaf(1, 0);
        let (child, _) = parent.children();
        let member = ValidatorId::new(7);
        state
            .reshape_parent_halves
            .insert(child, std::iter::once((member, parent)).collect());

        let snapshot = state.derive_topology_snapshot(net());
        assert_eq!(
            snapshot.reshape_parent_half_parent(child, member),
            Some(parent),
        );
        assert!(snapshot.reshape_parent_half_cohorts().contains_key(&child));
    }
}
