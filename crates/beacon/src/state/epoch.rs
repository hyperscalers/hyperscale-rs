//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconCert, BeaconProposal, BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeader,
    CertifiedBeaconBlock, Epoch, EpochWindows, KeptSeat, NetworkDefinition, ObserverSeat,
    PendingReshape, QuorumCertificate, RETENTION_HORIZON, ShardBoundary, ShardEpochContribution,
    ShardId, SlotEffects, SplitAdoption, SplitChildRoots, TransitionCause, ValidatorId,
    ValidatorStatus,
};

use crate::rules::{canonical_boundary_qcs, chunk_bounds, is_boundary_crossing};
use crate::state::committee::{diff_shard_committees, resample_beacon_committee, run_shuffle_step};
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
    // Freeze the pending-split set the same way — before this fold's
    // admissions, cancellations, and executions mutate it — so a
    // window's split-at-boundary projection is byte-identical whether
    // resolved from the lookahead schedule entry or the re-derived
    // active one.
    state.split_pending_window = state.live_split_pending();
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
    let mut witness = if let ApplyEpochInput::Normal {
        committed,
        shard_contributions,
    } = input
    {
        record_boundaries(state, epoch, committed, shard_contributions)
    } else {
        WitnessOutcome::default()
    };

    // A normal epoch folded its witnesses above, so sweep reshapes whose
    // triggers went quiet — an assertion folded this epoch is never swept.
    // A skip folds nothing, so no trigger could re-assert; carry the TTL
    // anchors forward instead, sparing a reshape that only looks quiet
    // because the beacon stalled.
    match input {
        ApplyEpochInput::Normal { .. } => prune_stale_reshapes(state),
        ApplyEpochInput::Skip => defer_reshape_ttls(state),
    }

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
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
    let split_adoptions = diff_split_adoptions(state, &pre_shard_members, &pre_seats);

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
        split_adoptions,
        keepers_drawn,
        keepers_released,
    }
}

/// Map each member a split execution placed on a fresh child to its
/// store-adoption path.
///
/// A child is fresh when it entered the lookahead this fold while its
/// parent left it. Each of its members either held an observer seat for
/// exactly this child at the epoch start (the synced store reopens) or
/// sat on the parent committee (the store hard-links from a local
/// checkpoint) — the execution gate admits no third provenance.
fn diff_split_adoptions(
    state: &BeaconState,
    pre_shard_members: &BTreeMap<ShardId, Vec<ValidatorId>>,
    pre_seats: &BTreeMap<(ValidatorId, ShardId), ShardId>,
) -> BTreeMap<ValidatorId, SplitAdoption> {
    let mut adoptions = BTreeMap::new();
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
            if pre_seats.get(&(*member, parent)) == Some(child) {
                adoptions.insert(*member, SplitAdoption::Observer { parent });
            } else if parent_members.contains(member) {
                adoptions.insert(*member, SplitAdoption::ParentHalf { parent });
            }
        }
    }
    adoptions
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
fn record_boundaries(
    state: &mut BeaconState,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
    shard_contributions: &BTreeMap<ShardId, ShardEpochContribution>,
) -> WitnessOutcome {
    let windows = state.chain_config.epoch_windows();
    // Bind each contribution to its shard's canonical committed QC — the
    // same selection the receiver's `contributions_well_formed` gate
    // applied — so the fold and the verifier never diverge on which QC
    // governs the boundary.
    let canonical = canonical_boundary_qcs(committed.iter().map(|(_, p)| p));

    let mut outcome = WitnessOutcome::default();
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
        let terminal_epoch = state.boundaries.get(shard).and_then(|b| b.terminal_epoch);
        // Once this contribution is the chain's terminal block — its crossing
        // lands in an epoch past the scheduled terminal — record the
        // certifying QC's timestamp. A merge parent floors it to the cut, and
        // persisting it lets the parent compose even when its two children's
        // terminals fold in separate epochs. A split parent seeds in-fold and
        // never composes, so only merge children (no `split_child_roots`)
        // carry it.
        let is_terminal_contribution =
            terminal_epoch.is_some_and(|t| windows.epoch_for(qc.weighted_timestamp()) > t);
        let terminal_qc_wt = (is_terminal_contribution && header.split_child_roots().is_none())
            .then(|| qc.weighted_timestamp());
        state.boundaries.insert(
            *shard,
            ShardBoundary {
                state_root: header.state_root(),
                block_hash,
                height: header.height(),
                weighted_timestamp: header.parent_qc().weighted_timestamp(),
                witness_leaf_count: BeaconWitnessLeafCount::new(chunk_end),
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch,
                terminal_qc_wt,
                settled_waves_root: header.settled_waves_root(),
            },
        );
        refreshed.insert(*shard);

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

    // Drop terminal records past their retention horizon. A terminated
    // shard's record lingers only to project its `settled_waves_root` to
    // surviving counterparts; past `terminal_wt + RETENTION_HORIZON` the
    // split-boundary fence rejects any wave naming it regardless, so the
    // record is dead weight. Bounded so a terminated shard can't
    // accumulate forever.
    //
    // A split parent whose children are still placeholders is exempt: its
    // terminal record is what `seed_split_children` folds the children from,
    // and that fold can only happen on an epoch the beacon commits a proposal
    // carrying the parent's terminal QC. The beacon can commit empty for
    // several epochs across the reshape's committee transition, so the horizon
    // alone would drop the record before any non-empty commit folds it —
    // stranding both children on their placeholders forever. Holding it until
    // both children carry a real anchor (seeded here, or from their own first
    // contributions) keeps the parent sourced until it folds; the fold then
    // marks the record so it stops being re-sourced and the next horizon sweep
    // collects it.
    let now = windows.window_of(epoch).start;
    let unseeded_split_parents: BTreeSet<ShardId> = state
        .boundaries
        .iter()
        .filter(|(shard, b)| {
            b.terminal_epoch.is_some() && children_unseeded(&state.boundaries, **shard)
        })
        .map(|(shard, _)| *shard)
        .collect();
    state.boundaries.retain(|shard, b| {
        b.terminal_epoch.is_none_or(|t| {
            unseeded_split_parents.contains(shard)
                || now <= windows.window_of(t).end.plus(RETENTION_HORIZON)
        })
    });

    outcome
}

/// Whether either of `parent`'s two children holds a placeholder boundary —
/// present but still on the zero anchor a split execution seeds. A `false`
/// here means both children carry a real anchor (a parent never split, or its
/// children have folded), so the parent's terminal record no longer needs to
/// outlive the retention horizon.
fn children_unseeded(boundaries: &BTreeMap<ShardId, ShardBoundary>, parent: ShardId) -> bool {
    let children: [ShardId; 2] = parent.children().into();
    children.iter().any(|child| {
        boundaries
            .get(child)
            .is_some_and(|b| b.block_hash == BlockHash::ZERO)
    })
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
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
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
            last_live_epoch: epoch,
            consecutive_misses: 0,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
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
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
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
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
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
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
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
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: Some(Epoch::new(1)),
                terminal_qc_wt: None,
                settled_waves_root: None,
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
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    terminal_qc_wt: None,
                    settled_waves_root: None,
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

        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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

        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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

        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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

        record_boundaries(&mut state, Epoch::new(2), &[], &BTreeMap::new());

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
        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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
        record_boundaries(&mut state, Epoch::new(3), &committed, &contributions);

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
        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);
        assert!(
            state.boundaries.contains_key(&parent),
            "lingers within the retention window",
        );

        // Advance to an epoch whose window opens past the terminal cut
        // (2000ms at epoch_duration 1000) plus `RETENTION_HORIZON`.
        let past = Epoch::new(RETENTION_HORIZON.as_secs() + 5);
        record_boundaries(&mut state, past, &[], &BTreeMap::new());
        assert!(
            !state.boundaries.contains_key(&parent),
            "terminal record drops past the retention horizon",
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
        record_boundaries(&mut state, past, &[], &BTreeMap::new());
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

        // The terminal contribution finally lands: it seeds both children,
        // and the now-seeded parent is collected by the same fold's horizon
        // sweep.
        let (header, witnesses) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) = contribution_for(parent, header, witnesses, 2_500);
        let later = Epoch::new(RETENTION_HORIZON.as_secs() + 6);
        record_boundaries(&mut state, later, &committed, &contributions);

        for child in <[ShardId; 2]>::from(parent.children()) {
            assert_ne!(
                state.boundaries.get(&child).unwrap().block_hash,
                BlockHash::ZERO,
                "children seed from the terminal fold",
            );
        }
        assert!(
            !state.boundaries.contains_key(&parent),
            "the seeded parent drops on the next horizon sweep",
        );
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
        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: Some(Epoch::new(1)),
                    terminal_qc_wt: None,
                    settled_waves_root: None,
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
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
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

        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);

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
        record_boundaries(&mut state, Epoch::new(2), &committed, &contributions);
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
        record_boundaries(&mut state, Epoch::new(3), &committed, &contributions);
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
        record_boundaries(&mut state, Epoch::new(4), &committed, &contributions);
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

        let adoptions = diff_split_adoptions(&state, &pre_members, &pre_seats);
        assert_eq!(
            adoptions.get(&parent_members[0]),
            Some(&SplitAdoption::ParentHalf { parent })
        );
        assert_eq!(
            adoptions.get(&parent_members[3]),
            Some(&SplitAdoption::ParentHalf { parent })
        );
        assert_eq!(
            adoptions.get(&observer),
            Some(&SplitAdoption::Observer { parent })
        );
        assert_eq!(adoptions.len(), 5);
    }
}
