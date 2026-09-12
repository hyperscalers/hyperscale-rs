//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BLOCK_CAPS, BeaconCert, BeaconProposal, BeaconState, BeaconWitnessLeafCount, Block, BlockHash,
    BlockHeader, BlockHeight, CertifiedBeaconBlock, CompletedRecovery, DeclaredWork, Epoch,
    EpochWindows, FiveWay, KeptSeat, NetworkDefinition, ObserverSeat, PendingReshape, QcContext,
    QuorumCertificate, RESHAPE_HANDOFF_TTL_EPOCHS, RecoveryCause, RevealChain, ShardBoundary,
    ShardEpochContribution, ShardId, SlotEffects, TerminalRef, TopologySnapshot, TransitionCause,
    Utilization, ValidatorId, ValidatorStatus, Verifier, Verify,
};

use crate::rules::{
    canonical_boundary_qcs, chunk_bounds, crossing_already_recorded, is_boundary_crossing,
};
use crate::state::committee::{
    diff_shard_committees, recover_committees, resample_beacon_committee,
    resolve_pending_rotations, run_shuffle_step, top_up_committees,
};
use crate::state::conviction::convict_pool;
use crate::state::governance::tally_param_votes;
use crate::state::lifecycle::{auto_reactivate, auto_ready_timeout, distribute_epoch_rewards};
use crate::state::reshape::{
    apply_scheduled_merges, apply_scheduled_splits, schedule_ready_merges, schedule_ready_splits,
};
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

/// What the network declared this epoch against what it could have,
/// per dimension.
///
/// Over the shards whose boundary advanced, and only those: a shard
/// that produced nothing this epoch has no reading to contribute, and
/// counting it as idle would walk every price down through an outage
/// nobody chose. The sum of numerators over the sum of denominators is
/// a block-weighted mean — a shard that committed twice as many blocks
/// had twice the capacity to fill, and filled or not, that is what it
/// says about the network.
///
/// A mean cannot see one hot shard among many idle ones, and that is
/// deliberate: the price is uniform because placement is the protocol's
/// choice, so a hotspot is answered by capacity through reshape rather
/// than by billing the addresses that landed on it.
fn network_utilization(
    state: &BeaconState,
    before: &BTreeMap<ShardId, (DeclaredWork, BlockHeight)>,
) -> FiveWay {
    let mut reading = FiveWay::default();
    for (shard, record) in &state.boundaries {
        let (used_before, height_before) = before
            .get(shard)
            .copied()
            .unwrap_or((DeclaredWork::ZERO, BlockHeight::GENESIS));
        let blocks = u128::from(record.height.inner().saturating_sub(height_before.inner()));
        if blocks == 0 {
            continue;
        }
        let used = record.used;
        let row = |into: &mut Utilization, used: u64, before: u64, cap: u64| {
            into.used = into
                .used
                .saturating_add(u128::from(used.saturating_sub(before)));
            into.capacity = into
                .capacity
                .saturating_add(u128::from(cap).saturating_mul(blocks));
        };
        row(
            &mut reading.compute,
            used.compute,
            used_before.compute,
            BLOCK_CAPS.compute,
        );
        row(
            &mut reading.read_bytes,
            used.read_bytes,
            used_before.read_bytes,
            BLOCK_CAPS.read_bytes,
        );
        row(
            &mut reading.write_bytes,
            used.write_bytes,
            used_before.write_bytes,
            BLOCK_CAPS.write_bytes,
        );
        row(
            &mut reading.footprint,
            used.footprint,
            used_before.footprint,
            BLOCK_CAPS.footprint,
        );
        row(
            &mut reading.retention,
            used.retention,
            used_before.retention,
            BLOCK_CAPS.retention,
        );
    }
    reading
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
#[allow(clippy::too_many_lines)] // sequential epoch-fold pipeline; each step is already a helper
pub fn apply_epoch(
    verifier: &dyn Verifier,
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
    // The price level travels with the bounds that hold it: the fold
    // that computed it wrote `next_prices` an epoch ago, so this
    // window's blocks resolve the table every member already froze into
    // their topology snapshot.
    state.prices = state.next_prices;
    // Freeze everything the window's schedule entry fixes, in one step
    // and before this fold mutates any of it. A window's entry is
    // written twice — the lookahead at the end of the preceding fold, the
    // active entry re-derived here — and proposers stamp boundary verdicts
    // into signed headers from whichever they hold, so the two must agree.
    // Assigning the whole projection is what makes that structural: a
    // field cannot gain a live value and miss its freeze.
    state.window = state.live_window();

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

    // Ingest fork proofs before the boundary fold; every flagged shard —
    // newly proven or carried from an earlier fold whose re-draw couldn't
    // stamp — is fenced out of it and nominated for re-draw this pass
    // (see `ingest_fork_proofs`).
    ingest_fork_proofs(verifier, state, network, epoch, committed);
    let fork_fenced: BTreeSet<ShardId> = state.fork_flagged.keys().copied().collect();

    // Fold this epoch's per-shard boundaries and apply their witness chunks.
    // A `Skip` carries every prior boundary forward untouched; a Normal
    // epoch records fresh boundaries and bumps the miss counter for any
    // active shard with no qualifying contribution.
    // The epoch's attested work per shard is the movement of each boundary
    // record's high-water mark across this fold, so snapshot the marks
    // before the crossings land and difference them after.
    let work_marks_before: BTreeMap<ShardId, u64> = state
        .boundaries
        .iter()
        .map(|(shard, record)| (*shard, record.attested_work))
        .collect();
    // The declared half, snapshotted the same way and for the same
    // reason: what the epoch's blocks reserved is the movement of each
    // record's vector across this fold, and what they could have
    // reserved is the caps times the blocks between the two marks.
    let load_marks_before: BTreeMap<ShardId, (DeclaredWork, BlockHeight)> = state
        .boundaries
        .iter()
        .map(|(shard, record)| (*shard, (record.used, record.height)))
        .collect();
    let (mut witness, reveals) = if let ApplyEpochInput::Normal {
        committed,
        shard_contributions,
    } = input
    {
        record_boundaries(
            verifier,
            state,
            network,
            epoch,
            committed,
            shard_contributions,
            &fork_fenced,
        )
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
    // The price level for the window after next, stepped by what this
    // epoch's blocks declared and held inside the bounds the vote above
    // just settled — so a vote that narrows an interval brings the level
    // in at the same promotion that installs the interval.
    state.next_prices = state.prices.stepped(
        &network_utilization(state, &load_marks_before),
        &state.next_params.price_bounds,
    );

    let vrf = filter_and_roll_randomness(verifier, state, network, epoch, committed, &reveals);
    // Equivocation evidence rides committed proposals; shard-witness lifts
    // ride the boundary contributions applied above.
    witness.extend(ingest_equivocations(
        verifier,
        state,
        network,
        &vrf.accepted,
    ));
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    // A shard with no prior record differences against zero, which is its
    // whole cumulative — right for a chain seeded this epoch.
    let shard_work: BTreeMap<ShardId, u64> = state
        .boundaries
        .iter()
        .map(|(shard, record)| {
            let before = work_marks_before.get(shard).copied().unwrap_or(0);
            (*shard, record.attested_work.saturating_sub(before))
        })
        .collect();
    let rewards_credited = distribute_epoch_rewards(state, &shard_work);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);
    // Close resolvable rotations after the shuffle, never before it. The
    // ready timeout backstops an entrant a whole sync window after it
    // seats, which lands on a shuffle boundary as often as not; resolving
    // first would free the shard to rotate again in the same fold and put
    // the victim in the pool in time for that rotation's own draw to seat
    // it right back. Ordering the retirement last keeps every victim
    // outside the derived pool for every draw of the step that retires
    // it, the same discipline the shuffle's own draw relies on.
    resolve_pending_rotations(state);
    // After the shuffle so the parent-half assignment reads
    // post-rotation membership and the children first shuffle one
    // epoch after they form; before the resample so freshly placed
    // ready members enter this epoch's beacon-eligible set like any
    // witness-readied validator.
    // Reshapes fold in two steps a window apart. Apply first, so a cut
    // scheduled by an earlier fold lands on the window it named; then
    // gate the rest, which can only schedule for the window after this
    // one. A record cannot pass both in the same fold — scheduling always
    // names a later epoch than the fold that stamps it.
    apply_scheduled_splits(state);
    schedule_ready_splits(state);
    // Merges fold the same way, inverted: two children collapse into
    // their parent once the keeper committee is ready.
    apply_scheduled_merges(state);
    schedule_ready_merges(state);
    // INV-RESHAPE-9, asserted where it is established: a cut named for the
    // window this fold opens would land after the promotion freeze above,
    // so the window's two schedule entries would disagree about whether a
    // boundary lands at its end — and its proposers would stamp verdicts
    // from whichever they held.
    debug_assert!(
        state
            .live_scheduled_terminals()
            .values()
            .all(|terminal| *terminal > epoch),
        "a fold scheduled a terminal for the window it opens",
    );
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
    recover_committees(state, &halted_shards);
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
        revoked: witness.revoked,
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
    terminal_delivered: bool,
    handoff_complete: Option<Epoch>,
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
    let (terminal_epoch, reshape_admitted_epoch, handoff_complete) = state
        .boundaries
        .get(&shard)
        .map_or((None, None, None), |b| {
            (
                b.terminal_epoch,
                b.reshape_admitted_epoch,
                b.handoff_complete,
            )
        });
    let is_terminal = terminal_epoch.is_some_and(|t| {
        windows
            .crossing_epoch(
                header.parent_qc().weighted_timestamp(),
                qc.weighted_timestamp(),
            )
            .is_some_and(|crossed| crossed > t)
    });
    let terminal_delivered = is_terminal && header.split_child_roots().is_none();
    (
        TerminalMarks {
            terminal_epoch,
            reshape_admitted_epoch,
            terminal_delivered,
            handoff_complete,
        },
        is_terminal,
    )
}

/// Whether a crossing's reveal chain stays out of the seed.
///
/// A crossing above a pending recovery's attested frontier commits history
/// the beyond-f retained committee could have forged after its halt, so its
/// epoch contributes nothing. Per-epoch chains are independent — no later
/// epoch's chain descends from a fenced one — so the judgement is per
/// crossing and needs no persisted band.
fn reveal_chain_fenced(state: &BeaconState, shard: &ShardId, header: &BlockHeader) -> bool {
    state
        .pending_recoveries
        .get(shard)
        .is_some_and(|recovery| header.height() > recovery.attested_frontier)
}

/// A drain re-fold of the recorded crossing: advance only the applied
/// watermark.
fn advance_drain_watermark(state: &mut BeaconState, shard: &ShardId, chunk_end: u64) {
    if let Some(boundary) = state.boundaries.get_mut(shard) {
        boundary.witness_leaf_count = BeaconWitnessLeafCount::new(chunk_end);
    }
}

/// Ingest the fork proofs riding this epoch's committed proposals and
/// flag each forked shard for a fork-caused recovery.
///
/// A committed proof is trusted (proposal admission verified it against
/// the topology schedule, and SPC commits only a 2f+1 quorum, so ≥ f+1
/// honest verifiers stood behind it), exactly as boundary QCs fold on
/// trust. Per forked shard, one of two things happens:
///
/// - **No recovery pending** — the shard enters
///   [`BeaconState::fork_flagged`], the durable trigger every fold's
///   `recover_committees` pass consults until the re-draw is actually
///   stamped; a fork that folds while the free pool is short retries
///   once the pool refills.
/// - **A recovery already pending** — a `Halt` cause is upgraded to
///   `Fork` in place (fork provenance dominates); a `Fork` cause is left
///   as-is, so a repeat proof for an already-recovering shard is
///   idempotent.
///
/// A proof whose forked height sits at or below the shard's last
/// completed recovery frontier is inert: that fork was already answered,
/// and re-folding its evidence must not re-draw the innocent successor
/// committee.
///
/// Runs before `record_boundaries`; the flagged set fences the forked
/// shards' own crossings out of the boundary fold so the retained
/// committee can neither advance the boundary nor clear the recovery.
///
/// A proof carrying a same-round sub-pair also jails the equivocators when
/// the forked committee is resolvable from current state (the bonus path;
/// see [`revoke_fork_equivocators`]). Fence and re-draw are the reliable,
/// round-invariant consequence; jailing lands only against an attacker who
/// left a same-round double-sign.
fn ingest_fork_proofs(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
) {
    let mut seen = BTreeSet::new();
    // Evidence pairs already jailed this fold, content-keyed by the
    // conflicting QCs' block hashes: distinct evidence still jails, but
    // duplicate copies across committed proposals verify their aggregate
    // signatures once.
    let mut revoked_pairs: BTreeSet<(BlockHash, BlockHash)> = BTreeSet::new();
    // The pre-recovery snapshot resolves each forked committee's ordering
    // for jailing; derived once (lazily, only if a same-round pair appears)
    // so its committee is the one that signed, not the re-drawn successor.
    let mut snapshot: Option<TopologySnapshot> = None;
    for (_, proposal) in committed {
        // The fold keys everything off the proof's own shard, never the
        // proposal's map key: admission authenticates the key against the
        // proof, and re-deriving here keeps a mis-keyed entry from ever
        // steering another shard's recovery.
        for proof in proposal.fork_proofs().values() {
            let proof = proof.as_unverified();
            let shard = proof.shard();
            // A proof at or below the shard's last completed recovery
            // frontier is a replay of already-recovered history: the fork
            // it evidences was answered, the equivocators (if attributable)
            // jailed, and the fresh committee seated. Re-arming would
            // re-draw the innocent successor committee forever.
            if state
                .completed_recoveries
                .get(&shard)
                .is_some_and(|completed| proof.height() <= completed.attested_frontier)
            {
                continue;
            }
            if let Some((qc_a, qc_b)) = proof.same_round_conflict()
                && revoked_pairs.insert((qc_a.block_hash(), qc_b.block_hash()))
            {
                let snap =
                    snapshot.get_or_insert_with(|| state.derive_topology_snapshot(network.clone()));
                revoke_fork_equivocators(verifier, state, snap, network, shard, epoch, qc_a, qc_b);
            }
            // Recovery classification runs once per shard.
            if !seen.insert(shard) {
                continue;
            }
            match state.pending_recoveries.get_mut(&shard) {
                Some(recovery) => {
                    if recovery.cause == RecoveryCause::Halt {
                        recovery.cause = RecoveryCause::Fork;
                    }
                }
                None => {
                    state
                        .fork_flagged
                        .entry(shard)
                        .or_insert_with(|| proof.height());
                }
            }
        }
    }
}

/// Jail the seats that double-signed at one `(height, round)` — the
/// optional, PoP-gated attribution over a fork proof.
///
/// `same_round_conflict` hands over two QCs at the same slot with
/// different block hashes; the intersection of their signer bitfields is
/// the set of seats that signed both, i.e. equivocated. Bitfield
/// membership is attributable only under proof of possession (the branch
/// this codebase enforces at registration), which forecloses the rogue-key
/// cancellation that would let the intersection name an innocent seat.
///
/// The bitfield indexes the shard's consensus committee. That ordering is
/// resolved from `snapshot` (derived from pre-recovery state) and confirmed
/// by re-verifying both QCs against it: a pass proves the resolved
/// committee is the signing committee, so `committee[i]` is the validator
/// behind bit `i`. A committee that has rotated beyond what current state
/// resolves fails the re-verify and is left fence-only. Each signer's
/// pool is convicted — permanent and idempotent.
#[allow(clippy::too_many_arguments)] // fold-internal helper mirroring the proof's fields
fn revoke_fork_equivocators(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    snapshot: &TopologySnapshot,
    network: &NetworkDefinition,
    shard: ShardId,
    epoch: Epoch,
    qc_a: &QuorumCertificate,
    qc_b: &QuorumCertificate,
) {
    let committee = snapshot.consensus_committee_for_shard(shard);
    let Some(public_keys) = committee
        .iter()
        .map(|v| snapshot.public_key(*v))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    let ctx = QcContext {
        verifier,
        network,
        public_keys: &public_keys,
        quorum_threshold: snapshot.quorum_threshold_for_shard(shard),
    };
    if qc_a.verify(&ctx).is_err() || qc_b.verify(&ctx).is_err() {
        return;
    }
    for pos in qc_a
        .signers()
        .set_indices()
        .filter(|&i| qc_b.signers().is_set(i))
    {
        let Some(&victim) = committee.get(pos) else {
            continue;
        };
        let Some(pool_id) = state.validators.get(&victim).map(|r| r.pool) else {
            continue;
        };
        convict_pool(state, pool_id, epoch);
    }
}

#[allow(clippy::too_many_lines)] // one pass folding every shard's boundary contribution
fn record_boundaries(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &[(ValidatorId, BeaconProposal)],
    shard_contributions: &BTreeMap<ShardId, ShardEpochContribution>,
    fork_fenced: &BTreeSet<ShardId>,
) -> (WitnessOutcome, BTreeMap<ShardId, RevealChain>) {
    let windows = state.chain_config.epoch_windows();
    // Bind each contribution to its shard's canonical committed QC — the
    // same selection the receiver's `contributions_well_formed` gate
    // applied — so the fold and the verifier never diverge on which QC
    // governs the boundary.
    let canonical = canonical_boundary_qcs(committed.iter().map(|(_, p)| p));

    let mut outcome = WitnessOutcome::default();
    let mut reveals: BTreeMap<ShardId, RevealChain> = BTreeMap::new();
    let mut refreshed: BTreeSet<ShardId> = BTreeSet::new();
    // Merge children whose terminal contribution — the coast block past
    // their cut, carrying their frozen terminal root — landed this fold.
    // Drives the compose attempt below: the children's terminal records (and
    // their persisted `terminal_delivered`) linger across folds, so a parent
    // composes once both children have folded, whichever fold completes the
    // pair.
    let mut terminal_recorded: BTreeSet<ShardId> = BTreeSet::new();
    for (shard, contribution) in shard_contributions {
        // A fork-flagged shard is frozen: the retained committee's
        // crossing must not advance the boundary or clear the recovery,
        // whether the re-draw stamps this pass or waits on the pool. The
        // re-drawn committee's next crossing completes it.
        if fork_fenced.contains(shard) {
            continue;
        }
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
            verifier,
            state,
            network,
            header,
            &contribution.payloads,
            &contribution.range_proof,
            prior,
            chunk_end,
            &mut outcome,
        ) {
            continue;
        }
        // The crossing block is the last anchored in the epoch it ends, so
        // the chain it carries closes that epoch. A drain re-fold names the
        // crossing already folded, so it contributes nothing: exactly-once
        // falls out of the fresh-crossing test rather than a watermark. The
        // test covers a chain whole only because successive crossings anchor
        // in increasing epochs — inherited from the weighted-timestamp clamp
        // each QC applies at aggregation, not established here, and that
        // field rides outside the aggregate signature. The fence is judged
        // while the shard's recovery record (if any) is still live: the
        // completing fold clears it.
        if !drain_refold && !reveal_chain_fenced(state, shard, header) {
            reveals.insert(*shard, header.reveal_chain());
        }
        if drain_refold {
            advance_drain_watermark(state, shard, chunk_end);
            continue;
        }
        let (marks, is_terminal_contribution) =
            carried_terminal_marks(state, *shard, header, qc, windows);
        // Read before the insert replaces the record: the byte level is
        // carried forward when this crossing's header resolved no total.
        let prior_substate_bytes = state
            .boundaries
            .get(shard)
            .map_or(0, |record| record.substate_bytes);
        state.boundaries.insert(
            *shard,
            ShardBoundary {
                state_root: header.state_root(),
                block_hash,
                height: header.height(),
                weighted_timestamp: header.parent_qc().weighted_timestamp(),
                witness_leaf_count: BeaconWitnessLeafCount::new(chunk_end),
                witness_base: header.beacon_witness_base(),
                attested_work: header.load().cumulative_work,
                used: header.load().used,
                // A level: an unresolved claim carries the previous value
                // forward instead of reading as "the shard emptied".
                substate_bytes: header.load().substate_bytes.unwrap_or(prior_substate_bytes),
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch: marks.terminal_epoch,
                handoff_complete: marks.handoff_complete,
                terminal_delivered: marks.terminal_delivered,
                terminal_roots: header.terminal_roots(),
                reshape_admitted_epoch: marks.reshape_admitted_epoch,
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
        // epoch and attested frontier move to the permanent record —
        // certified resolution of the recovery's bridge band reads the
        // epoch so blocks anchored below the bridge keep binding to the
        // fresh committee that produced them, and the frontier tombstones
        // replayed fork proofs for the recovered history.
        if let Some(recovery) = state.pending_recoveries.remove(shard) {
            state.completed_recoveries.insert(
                *shard,
                CompletedRecovery {
                    rotated_at: recovery.rotated_at,
                    attested_frontier: recovery.attested_frontier,
                },
            );
        }

        // A terminal shard's contribution crossing its final cut is the
        // chain's terminal block. A split parent seeds its pending
        // children from the header's `split_child_roots`; a merge child
        // carries none — its parent composes from both children's terminal
        // roots in the post-loop pass below. The record then lingers,
        // carrying the terminated shard's `settled_txs_root` for
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
        if !refreshed.contains(shard)
            && boundary.terminal_epoch.is_none()
            && !fork_fenced.contains(shard)
        {
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

/// Stamp handoff completion and drop terminal records past their evidence
/// window. A terminated shard's record lingers only to project its
/// `settled_txs_root` to surviving counterparts; past its
/// [terminal-evidence expiry](EpochWindows::terminal_evidence_expiry) the
/// split-boundary fence rejects any tick naming it regardless, so the
/// record is dead weight. The window is the same one the fence and the
/// acquisition read, and it counts from the epoch the handoff completed —
/// the successors produced past genesis — because that is the earliest
/// milestone by which every survivor could have both read the boundary
/// (folded two epochs after the cut at best) and reached the terminal
/// committee to acquire the set. A window counted from the cut closes
/// while a slow seeding or a partition is still in the way, killing the
/// very recovery the evidence exists for. Bounded so a terminated shard
/// can't accumulate forever.
///
/// A terminal record whose handoff is still pending carries no stamp and
/// is never dropped: it is what `seed_split_children` folds the children
/// from (or what a merge parent composes from), and that fold can only
/// land on an epoch the beacon commits a proposal carrying the terminal
/// QC. The beacon can commit empty for several epochs across the
/// reshape's committee transition, so a bare window would drop the record
/// first — stranding the children on their placeholders, or the merge
/// parent uncomposed. It is also the anchor a coasting predecessor's
/// observers snap-sync against while they finish adopting; under
/// make-before-break the predecessor keeps coasting until its successors
/// are live, so the record must outlive that moment regardless.
fn gc_terminal_boundaries(state: &mut BeaconState, epoch: Epoch, windows: EpochWindows) {
    let now = windows.window_of(epoch).start;
    // Stamp the epoch a terminal's successors first read live. The
    // terminal-evidence window counts from this stamp, not from the cut:
    // evidence is only acquirable once the boundary has folded and the
    // network has delivered, and the handoff's completion is the one
    // deterministic milestone that bounds both.
    let newly_complete: Vec<ShardId> = state
        .boundaries
        .iter()
        .filter(|(shard, b)| {
            b.terminal_epoch.is_some()
                && b.handoff_complete.is_none()
                && successors_live_for_terminal(state, **shard)
        })
        .map(|(shard, _)| *shard)
        .collect();
    for shard in newly_complete {
        if let Some(b) = state.boundaries.get_mut(&shard) {
            b.handoff_complete = Some(epoch);
        }
    }
    let pending_fold: BTreeMap<ShardId, Epoch> = state
        .boundaries
        .iter()
        .filter_map(|(shard, b)| {
            let terminal = b.terminal_epoch?;
            b.handoff_complete.is_none().then_some((*shard, terminal))
        })
        .collect();
    // A handoff still pending RESHAPE_HANDOFF_TTL_EPOCHS after its execution
    // has stalled: make-before-break commits and serves the terminal reliably,
    // so the successors should have seated and produced past genesis well
    // inside the bound. Surface it loudly. The predecessor keeps coasting — it
    // is the successors' only anchor, so tearing it down here would strand them
    // — until they go live or an operator intervenes.
    for (shard, cut) in stalled_handoffs(&pending_fold, epoch) {
        tracing::error!(
            ?shard,
            cut = cut.inner(),
            current = epoch.inner(),
            "reshape handoff stalled: successors not live within the TTL after the cut"
        );
    }
    state.boundaries.retain(|_, b| {
        b.terminal_epoch.is_none()
            || b.handoff_complete
                .is_none_or(|done| now <= windows.handoff_evidence_expiry(done))
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
/// are still not live [`RESHAPE_HANDOFF_TTL_EPOCHS`] epochs after the shard's
/// scheduled cut. `pending` maps each terminal shard whose successors aren't
/// yet live to the window it terminates at (the boundary's `terminal_epoch`),
/// and `epoch` is the fold's current epoch. Each result pairs the stalled
/// shard with that cut for the diagnostic.
fn stalled_handoffs(pending: &BTreeMap<ShardId, Epoch>, epoch: Epoch) -> Vec<(ShardId, Epoch)> {
    pending
        .iter()
        .filter(|(_, cut)| epoch.inner().saturating_sub(cut.inner()) >= RESHAPE_HANDOFF_TTL_EPOCHS)
        .map(|(shard, cut)| (*shard, *cut))
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
    let children: [ShardId; 2] = parent.children().into();
    for child in children {
        let pending = state
            .boundaries
            .get(&child)
            .is_some_and(|b| b.block_hash == BlockHash::ZERO);
        if !pending {
            continue;
        }
        // The one shared derivation, so the record this seeds is the block
        // a successor deriving from the same terminal already installed.
        // A terminal carrying no pair, or one that does not compose to its
        // own committed root, seeds nothing: the children then seed from
        // their own first boundary contributions instead.
        let Some((genesis, _)) = Block::split_child_genesis_from_terminal(
            child,
            terminal_header,
            terminal_qc.weighted_timestamp(),
        ) else {
            tracing::warn!(
                shard = ?parent,
                "terminal contribution carries no composing split child roots; \
                 children seed from their own contributions"
            );
            return;
        };
        state.boundaries.insert(
            child,
            ShardBoundary {
                state_root: genesis.header().state_root(),
                block_hash: genesis.hash(),
                height: genesis.height(),
                weighted_timestamp: genesis.header().parent_qc().weighted_timestamp(),
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: epoch,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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
        // carries a `terminal_delivered` — and the parent is still a pending
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
                .is_some_and(|b| b.terminal_delivered)
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
    // The merged chain's clock anchors at the cut its children terminate
    // at — the end of their scheduled terminal window, which both halves
    // of the handoff read from the same schedule. A keeper reforming the
    // parent derives the same instant from its own frozen projection, so
    // its reconstruction of this genesis needs nothing this fold chose.
    //
    // The children's certifying QCs cannot serve: the fold sees whichever
    // QC `canonical_boundary_qcs` picked as highest across the committed
    // proposal set, which depends on the beacon's own consensus and not on
    // the child chains, so no keeper can predict it.
    let terminal = left_b
        .terminal_epoch
        .expect("a child in compose has folded its terminal");
    let cut_wt = windows.window_of(terminal).end;
    // The one shared derivation, so this record is the block every keeper
    // reforming the parent from the same two terminals already installed.
    let (genesis, _) = Block::merge_parent_genesis_from_terminals(
        parent,
        TerminalRef {
            state_root: left_b.state_root,
            block_hash: left_b.block_hash,
            height: left_b.height,
        },
        TerminalRef {
            state_root: right_b.state_root,
            block_hash: right_b.block_hash,
            height: right_b.height,
        },
        cut_wt,
    );
    state.boundaries.insert(
        parent,
        ShardBoundary {
            state_root: genesis.header().state_root(),
            block_hash: genesis.hash(),
            height: genesis.height(),
            weighted_timestamp: genesis.header().parent_qc().weighted_timestamp(),
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            attested_work: 0,
            used: DeclaredWork::ZERO,
            substate_bytes: 0,
            last_live_epoch: epoch,
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
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

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        AggregateSignature, BeaconProposal, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, ChainOrigin, CommittedTxsRoot, DeclaredWork,
        Epoch, FiveWay, Hash, MAX_WITNESSES_PER_SHARD, MIN_STAKE_FLOOR, PriceBounds, PriceTable,
        QuorumCertificate, Round, SettledTxsRoot, ShardBoundary, ShardCommittee, ShardForkProof,
        ShardId, ShardLoad, ShardRecovery, ShardWitnessPayload, SignerBitfield, SplitChildRoots,
        Stake, StakePool, StakePoolId, StateRoot, TERMINAL_EVIDENCE_EPOCHS, TerminalRoots,
        TransitionCause, ValidatorId, VrfProof, WeightedTimestamp, compute_merkle_root,
        compute_range_proof,
    };

    use super::*;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, net, single_pool_state, validator_record,
    };
    use crate::state::witness::apply_shard_payload;

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
        terminal_roots: Option<TerminalRoots>,
    ) -> BlockHeader {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(pred_wt),
        );
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: parent_qc.into(),
            state_root,
            beacon_witness_root: root,
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
            split_child_roots,
            terminal_roots,
            ..Default::default()
        })
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
    ) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
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
        terminal_roots: Option<TerminalRoots>,
    ) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
        let leaf_count = payloads.len() as u64;
        let leaf_hashes: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        let root = if leaf_hashes.is_empty() {
            BeaconWitnessRoot::ZERO
        } else {
            BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes))
        };
        let header = boundary_block_full(
            shard,
            height,
            pred_wt,
            state_root,
            root,
            leaf_count,
            split_child_roots,
            terminal_roots,
        );
        let range_proof = compute_range_proof(&leaf_hashes, 0, leaf_hashes.len());
        (header, payloads, range_proof)
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
    ) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200 + u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        boundary_block_with_payloads(shard, height, pred_wt, state_root, payloads)
    }

    /// The sub-chunk `[lo, hi)` of a boundary block's window: its payloads
    /// plus the range proof lifting them to the block's root. These
    /// fixtures put the window base at zero, so positions are leaf indices.
    fn sub_chunk(
        payloads: &[ShardWitnessPayload],
        lo: usize,
        hi: usize,
    ) -> (Vec<ShardWitnessPayload>, Vec<Hash>) {
        let leaf_hashes: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        (
            payloads[lo..hi].to_vec(),
            compute_range_proof(&leaf_hashes, lo, hi),
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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt),
        )
    }

    /// `header` with `load` stamped on it — the attested-load claims the
    /// fold reads off a boundary header. Rebuilt rather than mutated
    /// because the field is hash-covered and private.
    fn stamping_load(header: BlockHeader, load: ShardLoad) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            load,
            ..header.into_parts()
        })
    }

    /// The two attested-load quantities land on the record in their own
    /// shapes: work as a high-water mark whose successive differences are one
    /// epoch's work, and the byte total as a level that an unresolved claim
    /// leaves standing rather than zeroing.
    #[test]
    fn record_boundaries_carries_work_as_a_mark_and_bytes_as_a_level() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let anchor_root = StateRoot::from_raw(Hash::from_bytes(b"anchor"));

        let cross =
            |state: &mut BeaconState, epoch: u64, height: u64, pred: u64, load: ShardLoad| {
                let (header, payloads, range_proof) =
                    boundary_block_with_witnesses(shard, height, pred, anchor_root, 0);
                let header = stamping_load(header, load);
                let qc = qc_over(&header, pred + 600);
                let proposal = BeaconProposal::new(
                    std::iter::once((shard, Some(qc))).collect(),
                    Vec::new(),
                    BTreeMap::new(),
                    Vec::new(),
                    VrfProof::ZERO,
                );
                let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
                    shard,
                    ShardEpochContribution {
                        boundary_header: header,
                        payloads,
                        range_proof,
                    },
                ))
                .collect();
                record_boundaries(
                    &BlsVerifier,
                    state,
                    &net(),
                    Epoch::new(epoch),
                    &[(ValidatorId::new(0), proposal)],
                    &contributions,
                    &BTreeSet::new(),
                );
            };

        // First crossing: both quantities come straight off the header.
        cross(
            &mut state,
            1,
            5,
            900,
            ShardLoad::ZERO.advance(400, DeclaredWork::ZERO, Some(8_192)),
        );
        let first = state.boundaries[&shard];
        assert_eq!(first.attested_work, 400);
        assert_eq!(first.substate_bytes, 8_192);

        // Second: the mark advances, and the epoch's work is the difference
        // the weighting reads — not the cumulative.
        cross(
            &mut state,
            2,
            9,
            1_900,
            ShardLoad::ZERO.advance(1_000, DeclaredWork::ZERO, Some(9_000)),
        );
        let second = state.boundaries[&shard];
        assert_eq!(second.attested_work, 1_000);
        assert_eq!(second.attested_work - first.attested_work, 600);
        assert_eq!(second.substate_bytes, 9_000);

        // Third: a crossing whose header resolved no byte total leaves the
        // level standing. Reading the absence as zero would tell the beacon
        // the shard had emptied.
        cross(
            &mut state,
            3,
            13,
            2_900,
            ShardLoad::ZERO.advance(1_250, DeclaredWork::ZERO, None),
        );
        let third = state.boundaries[&shard];
        assert_eq!(third.attested_work, 1_250);
        assert_eq!(third.substate_bytes, 9_000);
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
        let (b, payloads, range_proof) = boundary_block_with_witnesses(shard, 5, 900, anchor, 7);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads,
                range_proof,
            },
        ))
        .collect();

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
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

    // ─── fork-caused recovery ───────────────────────────────────────────────

    /// A committed proposal carrying a fork proof for `shard`, forked at
    /// height 5. The fold trusts committed proofs (admission verified
    /// them), so the proof need not re-verify here; its own shard drives
    /// the recovery.
    fn fork_committed(shard: ShardId) -> (ValidatorId, BeaconProposal) {
        use hyperscale_types::test_utils::shard_fork_proof;
        let committee = TestCommittee::new(4, 1);
        let proof = shard_fork_proof(&committee, shard, BlockHeight::new(5));
        let fork_proofs = std::iter::once((shard, proof)).collect();
        let proposal = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            fork_proofs,
            Vec::new(),
            VrfProof::ZERO,
        );
        (ValidatorId::new(0), proposal)
    }

    fn pending_recovery(cause: RecoveryCause) -> ShardRecovery {
        ShardRecovery {
            cause,
            rotated_at: Epoch::GENESIS,
            retained: vec![ValidatorId::new(9)],
            attested_frontier: BlockHeight::GENESIS,
        }
    }

    /// A shard with no recovery pending gains a durable fork flag at the
    /// proven height — the trigger every fold's recovery pass consults
    /// until the re-draw stamps. Ingest itself stamps nothing.
    #[test]
    fn ingest_fork_proofs_flags_a_shard_without_a_pending_recovery() {
        let mut state = single_pool_state(4);
        let shard = ShardId::leaf(1, 0);
        let committed = [fork_committed(shard)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &committed);
        assert_eq!(state.fork_flagged.get(&shard), Some(&BlockHeight::new(5)));
        assert!(state.pending_recoveries.is_empty());
    }

    /// A fork proof for a shard already under a halt recovery upgrades its
    /// cause to `Fork` in place — no second re-draw, so the shard is not
    /// flagged and the record's retention and rotation stand.
    #[test]
    fn ingest_fork_proofs_upgrades_pending_halt_to_fork() {
        let mut state = single_pool_state(4);
        let shard = ShardId::leaf(1, 0);
        state
            .pending_recoveries
            .insert(shard, pending_recovery(RecoveryCause::Halt));
        let committed = [fork_committed(shard)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &committed);
        assert!(!state.fork_flagged.contains_key(&shard));
        let recovery = &state.pending_recoveries[&shard];
        assert_eq!(recovery.cause, RecoveryCause::Fork);
        assert_eq!(recovery.retained, vec![ValidatorId::new(9)]);
        assert_eq!(recovery.rotated_at, Epoch::GENESIS);
    }

    /// A repeat fork proof for a shard already recovering as a fork is a
    /// no-op: not flagged, cause unchanged.
    #[test]
    fn ingest_fork_proofs_is_idempotent_for_a_pending_fork() {
        let mut state = single_pool_state(4);
        let shard = ShardId::leaf(1, 0);
        state
            .pending_recoveries
            .insert(shard, pending_recovery(RecoveryCause::Fork));
        let committed = [fork_committed(shard)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &committed);
        assert!(!state.fork_flagged.contains_key(&shard));
        assert_eq!(state.pending_recoveries[&shard].cause, RecoveryCause::Fork);
    }

    /// The fold keys recovery off the proof's own shard, never the
    /// proposal's map key: a mis-keyed entry (admission rejects one, but
    /// the fold must not trust the framing either) steers only the shard
    /// the proof actually evidences.
    #[test]
    fn ingest_fork_proofs_keys_recovery_off_the_proofs_own_shard() {
        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};

        let mut state = single_pool_state(4);
        let proof_shard = ShardId::leaf(1, 0);
        let wrong_key = ShardId::leaf(1, 1);
        let committee = TestCommittee::new(4, 1);
        let proof = shard_fork_proof(&committee, proof_shard, BlockHeight::new(5));
        let proposal = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            std::iter::once((wrong_key, proof)).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let proposals = [(ValidatorId::new(0), proposal)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &proposals);
        assert!(state.fork_flagged.contains_key(&proof_shard));
        assert!(!state.fork_flagged.contains_key(&wrong_key));
    }

    /// A replayed proof whose forked height sits at or below the shard's
    /// last completed recovery frontier is inert — the fork was already
    /// answered, and re-folding the evidence must not re-draw the
    /// innocent successor committee.
    #[test]
    fn ingest_fork_proofs_drops_a_replay_below_the_completed_frontier() {
        let mut state = single_pool_state(4);
        let shard = ShardId::leaf(1, 0);
        state.completed_recoveries.insert(
            shard,
            CompletedRecovery {
                rotated_at: Epoch::new(3),
                // `fork_committed` forks at height 5 — at the frontier.
                attested_frontier: BlockHeight::new(5),
            },
        );
        let committed = [fork_committed(shard)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(4), &committed);
        assert!(state.fork_flagged.is_empty());
        assert!(state.pending_recoveries.is_empty());
    }

    /// A fork above the completed frontier is a genuinely new fork of the
    /// recovered chain: the tombstone does not blind the shard forever.
    #[test]
    fn ingest_fork_proofs_rearms_for_a_fork_above_the_completed_frontier() {
        let mut state = single_pool_state(4);
        let shard = ShardId::leaf(1, 0);
        state.completed_recoveries.insert(
            shard,
            CompletedRecovery {
                rotated_at: Epoch::new(3),
                attested_frontier: BlockHeight::new(4),
            },
        );
        let committed = [fork_committed(shard)];
        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(4), &committed);
        assert!(state.fork_flagged.contains_key(&shard));
    }

    /// A Skip epoch cannot drop an armed fork: the recovery pass runs on
    /// Skip folds too, so a standing flag stamps the re-draw with no
    /// committed proposal in sight.
    #[test]
    fn skip_epoch_stamps_a_flagged_fork_recovery() {
        use hyperscale_types::ValidatorStatus;

        use crate::state::test_fixtures::validator_record;

        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let shard = ShardId::leaf(1, 0);
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
                height: BlockHeight::new(5),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );
        // A free pool for the re-draw — the flagged shard's own members
        // are still `OnShard` and excluded from their replacement.
        for i in 100..104u64 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(i, 0, ValidatorStatus::Pooled),
            );
        }
        state.fork_flagged.insert(shard, BlockHeight::new(6));

        apply_epoch(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            ApplyEpochInput::Skip,
        );

        let recovery = state
            .pending_recoveries
            .get(&shard)
            .expect("the Skip fold stamps the flagged recovery");
        assert_eq!(recovery.cause, RecoveryCause::Fork);
        assert!(!state.fork_flagged.contains_key(&shard));
    }

    /// A shard fork-recovered this pass has its crossing skipped entirely:
    /// the retained committee's boundary is not recorded, and the recovery
    /// it triggered is neither advanced nor cleared. The fresh committee's
    /// first crossing next epoch is what completes it.
    #[test]
    fn record_boundaries_skips_a_fork_recovered_shard() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        // A prior boundary at height 3 backs the pending recovery (so the
        // retention sweep keeps it) and lets us assert the crossing didn't
        // advance it.
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"prior")),
                height: BlockHeight::new(3),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );
        state
            .pending_recoveries
            .insert(shard, pending_recovery(RecoveryCause::Fork));

        let anchor = StateRoot::from_raw(Hash::from_bytes(b"anchor"));
        let (b, payloads, range_proof) = boundary_block_with_witnesses(shard, 5, 900, anchor, 7);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads,
                range_proof,
            },
        ))
        .collect();

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::from([shard]),
        );

        // The crossing at height 5 was skipped: the boundary stays at 3.
        assert_eq!(state.boundaries[&shard].height, BlockHeight::new(3));
        assert!(!state.advanced.contains(&shard));
        assert!(
            state.pending_recoveries.contains_key(&shard),
            "the recovery is not cleared by the forked committee's own crossing",
        );
        assert!(!state.completed_recoveries.contains_key(&shard));
    }

    /// A beacon state whose shard-`leaf(1,0)` consensus committee is
    /// exactly `committee` (matching pubkeys), so a fork proof signed by
    /// `committee` re-verifies against the state-derived snapshot.
    fn state_with_shard_committee(committee: &TestCommittee) -> BeaconState {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(committee.size() as u64);
        let members: Vec<ValidatorId> = (0..committee.size())
            .map(|i| committee.validator_id(i))
            .collect();
        for i in 0..committee.size() {
            if let Some(rec) = state.validators.get_mut(&committee.validator_id(i)) {
                rec.pubkey = *committee.public_key(i);
            }
        }
        state.shard_committees.insert(
            shard,
            ShardCommittee {
                members: members.clone(),
            },
        );
        state.shard_consensus_members.insert(shard, members);
        state
    }

    fn committed_with(shard: ShardId, proof: ShardForkProof) -> [(ValidatorId, BeaconProposal); 1] {
        let proposal = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            std::iter::once((shard, proof)).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        [(ValidatorId::new(0), proposal)]
    }

    fn revoked(state: &BeaconState, v: u64) -> bool {
        matches!(
            state.validators.get(&ValidatorId::new(v)).map(|r| r.status),
            Some(ValidatorStatus::Revoked { .. })
        )
    }

    /// Rebuild `state.pools` so every validator operates under its own
    /// single-validator pool — the shape that makes conviction
    /// attribution observable per seat.
    fn split_into_single_validator_pools(state: &mut BeaconState) {
        let ids: Vec<ValidatorId> = state.validators.keys().copied().collect();
        state.pools.clear();
        for (i, id) in ids.iter().enumerate() {
            let pool_id = StakePoolId::new(u32::try_from(i).unwrap());
            state.validators.get_mut(id).unwrap().pool = pool_id;
            state.pools.insert(
                pool_id,
                StakePool {
                    id: pool_id,
                    total_stake: MIN_STAKE_FLOOR,
                    validators: std::iter::once(*id).collect(),
                    pending_withdrawals: Vec::new(),
                    released_cumulative: Stake::ZERO,
                    conviction: None,
                },
            );
        }
    }

    /// A same-round double-sign convicts exactly the bitfield
    /// intersection's pools — seats that signed both branches — and
    /// spares the seats that signed only one (each seat under its own
    /// pool, so attribution is per-seat).
    #[test]
    fn same_round_fork_convicts_exactly_the_bitfield_intersection() {
        use hyperscale_types::test_utils::shard_fork_proof_same_round;

        let shard = ShardId::leaf(1, 0);
        let committee = TestCommittee::new(4, 1);
        let mut state = state_with_shard_committee(&committee);
        split_into_single_validator_pools(&mut state);
        // Branch a signed by {0,1,2}, branch b by {1,2,3}: intersection {1,2}.
        let proof = shard_fork_proof_same_round(
            &committee,
            shard,
            BlockHeight::new(5),
            &[0, 1, 2],
            &[1, 2, 3],
        );
        let proposals = committed_with(shard, proof);

        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &proposals);

        assert!(revoked(&state, 1));
        assert!(revoked(&state, 2));
        assert!(!revoked(&state, 0), "signed only branch a");
        assert!(!revoked(&state, 3), "signed only branch b");
    }

    /// Seats sharing a pool with a double-signer are revoked with it —
    /// the conviction cascade treats the pool as the operator.
    #[test]
    fn same_round_fork_convicts_pool_siblings_of_the_equivocators() {
        use hyperscale_types::test_utils::shard_fork_proof_same_round;

        let shard = ShardId::leaf(1, 0);
        let committee = TestCommittee::new(4, 1);
        // The default fixture keeps all four seats in one pool.
        let mut state = state_with_shard_committee(&committee);
        let proof = shard_fork_proof_same_round(
            &committee,
            shard,
            BlockHeight::new(5),
            &[0, 1, 2],
            &[1, 2, 3],
        );
        let proposals = committed_with(shard, proof);

        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &proposals);

        for v in 0..4 {
            assert!(
                revoked(&state, v),
                "pool sibling {v} revokes with the signers"
            );
        }
        assert!(
            state.pools[&StakePoolId::new(0)].conviction.is_some(),
            "one conviction for the shared pool",
        );
    }

    /// A round-spaced proof leaves no seat signing twice at one round, so it
    /// fences and re-draws but jails nobody.
    #[test]
    fn round_spaced_fork_fences_without_jailing() {
        use hyperscale_types::test_utils::shard_fork_proof;

        let shard = ShardId::leaf(1, 0);
        let committee = TestCommittee::new(4, 2);
        let mut state = state_with_shard_committee(&committee);
        let proof = shard_fork_proof(&committee, shard, BlockHeight::new(5));
        let proposals = committed_with(shard, proof);

        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &proposals);

        assert!(
            state.fork_flagged.contains_key(&shard),
            "still fences and re-draws"
        );
        for v in 0..4 {
            assert!(!revoked(&state, v));
        }
    }

    /// A same-round proof whose signing committee the current state cannot
    /// resolve (here, the resolved keys don't authenticate the QCs) fails
    /// the re-verify and is fence-only — no innocent seat is jailed.
    #[test]
    fn same_round_fork_against_unresolvable_committee_is_fence_only() {
        use hyperscale_types::test_utils::shard_fork_proof_same_round;

        let shard = ShardId::leaf(1, 0);
        let signing = TestCommittee::new(4, 3);
        // State resolves the shard to a committee with different keys.
        let resolved = TestCommittee::new(4, 999);
        let mut state = state_with_shard_committee(&resolved);
        let proof = shard_fork_proof_same_round(
            &signing,
            shard,
            BlockHeight::new(5),
            &[0, 1, 2],
            &[1, 2, 3],
        );
        let proposals = committed_with(shard, proof);

        ingest_fork_proofs(&BlsVerifier, &mut state, &net(), Epoch::new(1), &proposals);

        assert!(
            state.fork_flagged.contains_key(&shard),
            "recovers regardless"
        );
        for v in 0..4 {
            assert!(!revoked(&state, v));
        }
    }

    /// The boundary fold hands the randomness roll the crossing block's
    /// reveal chain — the closed value for the epoch that block ends —
    /// keyed by shard.
    #[test]
    fn record_boundaries_collects_the_crossings_reveal_chain() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        let payloads = vec![ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(200),
            amount: Stake::from_whole_tokens(1),
        }];
        let (b, payloads, range_proof) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, payloads);
        let expected_chain = b.reveal_chain();
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads,
                range_proof,
            },
        ))
        .collect();

        let (_, reveals) = record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );

        assert_eq!(reveals.get(&shard), Some(&expected_chain));
    }

    /// A committed re-fold of the recorded crossing with no witness
    /// progress is a miss, not a refresh: the counter keeps accumulating,
    /// `last_live_epoch` stays at the original fold, and a pending
    /// recovery's retention record survives. Without this a halted shard
    /// whose stale crossing keeps riding proposals resets its counter
    /// every epoch and never flags.
    #[test]
    fn record_boundaries_ignores_a_no_progress_refold() {
        use hyperscale_types::{RecoveryCause, ShardRecovery};

        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        let anchor = StateRoot::from_raw(Hash::from_bytes(b"anchor"));
        let (b, payloads, range_proof) = boundary_block_with_witnesses(shard, 5, 900, anchor, 7);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let fresh: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b.clone(),
                payloads,
                range_proof,
            },
        ))
        .collect();
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &fresh,
            &BTreeSet::new(),
        );
        assert_eq!(state.boundaries[&shard].consecutive_misses, 0);

        state.pending_recoveries.insert(
            shard,
            ShardRecovery {
                cause: RecoveryCause::Halt,
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
                payloads: Vec::new(),
                range_proof: Vec::new(),
            },
        ))
        .collect();
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &refold,
            &BTreeSet::new(),
        );

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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );
        state.window.witness_bases = state.live_witness_bases();

        // Epoch 1 folds a boundary whose chunk applies 7 witness leaves.
        let root = StateRoot::from_raw(Hash::from_bytes(b"epoch1"));
        let (header, payloads, range_proof) = boundary_block_with_witnesses(shard, 5, 900, root, 7);
        let qc = qc_over(&header, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: header,
                payloads,
                range_proof,
            },
        ))
        .collect();
        apply_epoch(
            &BlsVerifier,
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
            state.window.witness_bases.get(&shard),
            Some(&BeaconWitnessLeafCount::ZERO)
        );
        // What the lookahead derivation for window 2 reads live now.
        let lookahead = state.live_witness_bases();
        assert_eq!(lookahead.get(&shard), Some(&BeaconWitnessLeafCount::new(7)));

        // Window 2's promotion freezes exactly what the lookahead read —
        // and the whole window-frozen projection agrees, not just this
        // field. A boundary fold is the one that advances a watermark, so
        // this is where a field whose value only moves on a contribution
        // would show a missing freeze.
        let projected = window_frozen_view(&state.derive_next_topology_snapshot(net()));
        apply_epoch(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        assert_eq!(state.window.witness_bases, lookahead);
        assert_eq!(
            projected,
            window_frozen_view(&state.derive_topology_snapshot(net())),
            "the lookahead written across a boundary fold must equal the \
             active entry re-derived at that window's promotion",
        );
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads: Vec::new(),
                range_proof: Vec::new(),
            },
        ))
        .collect();
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );

        let b = boundary_block(shard, 5, 1_200, StateRoot::ZERO, 0);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads: Vec::new(),
                range_proof: Vec::new(),
            },
        ))
        .collect();

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
        use hyperscale_types::{RecoveryCause, ShardRecovery};

        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);
        let cap = MAX_WITNESSES_PER_SHARD;
        // Two full chunks plus a small remainder, so the drain spans three
        // epochs: `[0, cap)`, `[cap, 2 * cap)`, then `[2 * cap, total)`.
        let total = 2 * cap + 3;

        let anchor = StateRoot::from_raw(Hash::from_bytes(b"backlog-anchor"));
        let (b, payloads, _range_proof) =
            boundary_block_with_witnesses(shard, 5, 900, anchor, total as u64);
        let qc = qc_over(&b, 1_500);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];

        let contribution_with =
            |lo: usize, hi: usize| -> BTreeMap<ShardId, ShardEpochContribution> {
                let (chunk, range_proof) = sub_chunk(&payloads, lo, hi);
                std::iter::once((
                    shard,
                    ShardEpochContribution {
                        boundary_header: b.clone(),
                        payloads: chunk,
                        range_proof,
                    },
                ))
                .collect()
            };

        // Epoch 1: the fresh crossing records the anchor; the watermark is
        // cap-gated — it advances to exactly the cap even though the
        // boundary commits `total > cap` leaves.
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contribution_with(0, cap),
            &BTreeSet::new(),
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
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at: Epoch::new(1),
                retained: Vec::new(),
                attested_frontier: after_1.height,
            },
        );

        // Epoch 2: the second chunk drains against the same crossing — the
        // watermark advances, but the re-fold is a miss, not a refresh, and
        // the pending recovery survives.
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contribution_with(cap, 2 * cap),
            &BTreeSet::new(),
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
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contribution_with(2 * cap, payloads.len()),
            &BTreeSet::new(),
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
    fn stamp_recovery(state: &mut BeaconState, shard: ShardId, frontier: u64) {
        use hyperscale_types::{RecoveryCause, ShardRecovery};
        state.pending_recoveries.insert(
            shard,
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at: Epoch::new(1),
                retained: Vec::new(),
                attested_frontier: BlockHeight::new(frontier),
            },
        );
    }

    /// A crossing above a pending recovery's attested frontier keeps its
    /// epoch's chain out of the seed, and no later epoch's chain descends
    /// from it — so the beyond-f retained committee's post-halt production
    /// can never steer the draw, in the completing epoch or after it.
    #[test]
    fn a_beyond_frontier_crossing_never_seeds() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        stamp_recovery(&mut state, shard, 3);
        let (b, payloads, range_proof) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, Vec::new());

        // The crossing (height 5 > frontier 3) folds and clears the
        // recovery, but contributes nothing to the seed.
        let (committed, contributions) = contribution_for(shard, b, (payloads, range_proof), 1_500);
        let (_, reveals) = record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );
        assert!(
            reveals.is_empty(),
            "the fenced crossing contributes nothing"
        );
        assert!(!state.pending_recoveries.contains_key(&shard));

        // The next crossing is post-recovery production, on a chain that
        // reseeded at its own epoch boundary: it seeds normally.
        let (b2, payloads2, proof2) =
            boundary_block_with_payloads(shard, 9, 1_900, StateRoot::ZERO, Vec::new());
        let expected = b2.reveal_chain();
        let (committed, contributions) = contribution_for(shard, b2, (payloads2, proof2), 2_500);
        let (_, reveals) = record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );
        assert_eq!(reveals.get(&shard), Some(&expected));
    }

    /// A recovering shard's crossing at (or below) the attested frontier is
    /// legitimate retained history: its chain folds.
    #[test]
    fn a_crossing_at_the_frontier_seeds() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        let shard = ShardId::leaf(1, 0);

        stamp_recovery(&mut state, shard, 7);
        let (b, payloads, range_proof) =
            boundary_block_with_payloads(shard, 5, 900, StateRoot::ZERO, Vec::new());
        let expected = b.reveal_chain();
        let (committed, contributions) = contribution_for(shard, b, (payloads, range_proof), 1_500);
        let (_, reveals) = record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );
        assert_eq!(reveals.get(&shard), Some(&expected));
    }

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
        let (b, payloads, range_proof) = boundary_block_with_payloads(
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
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions: BTreeMap<ShardId, ShardEpochContribution> = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: b,
                payloads,
                range_proof,
            },
        ))
        .collect();
        let effects = apply_epoch(
            &BlsVerifier,
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
            &BlsVerifier,
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
            &BlsVerifier,
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
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(5),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        apply_epoch(
            &BlsVerifier,
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
            &BlsVerifier,
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
        let effects = apply_epoch(
            &BlsVerifier,
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Skip,
        );

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
            &BlsVerifier,
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
        let skip_effects = apply_epoch(
            &BlsVerifier,
            &mut skip_state,
            &net(),
            next,
            ApplyEpochInput::Skip,
        );

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
        terminal_roots: Option<TerminalRoots>,
    ) -> (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>) {
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
            terminal_roots,
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: Some(Epoch::new(1)),
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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
                    attested_work: 0,
                    used: DeclaredWork::ZERO,
                    substate_bytes: 0,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    handoff_complete: None,
                    terminal_delivered: false,
                    terminal_roots: None,
                    reshape_admitted_epoch: None,
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
        chunk: (Vec<ShardWitnessPayload>, Vec<Hash>),
        qc_wt: u64,
    ) -> (
        Vec<(ValidatorId, BeaconProposal)>,
        BTreeMap<ShardId, ShardEpochContribution>,
    ) {
        let qc = qc_over(&header, qc_wt);
        let proposal = BeaconProposal::new(
            std::iter::once((shard, Some(qc))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let (payloads, range_proof) = chunk;
        let contributions = std::iter::once((
            shard,
            ShardEpochContribution {
                boundary_header: header,
                payloads,
                range_proof,
            },
        ))
        .collect();
        (committed, contributions)
    }

    /// The terminal contribution — predecessor inside the final window,
    /// QC past its cut, carrying a composing pair — seeds both pending
    /// children with their verified subtree roots and deterministic
    /// genesis hashes, and the parent's terminal record lingers (carrying
    /// its settled-transaction root for surviving counterparts) past the drain.
    #[test]
    fn terminal_contribution_seeds_the_children_and_retains_the_parent() {
        let (mut state, parent, pair, composed) = terminating_state();
        let (left, right) = parent.children();

        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) =
            contribution_for(parent, header.clone(), (payloads, range_proof), 2_500);

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, forged, composed, 3, None);
        let (committed, contributions) =
            contribution_for(parent, header, (payloads, range_proof), 2_500);

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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

        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 900, pair, composed, 3, None);
        let (committed, contributions) =
            contribution_for(parent, header, (payloads, range_proof), 1_500);

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );

        assert_eq!(state.boundaries.get(&parent).unwrap().consecutive_misses, 0);
    }

    /// A terminal backlog deeper than one chunk drains over two folds: the
    /// children seed at the first terminal fold, the record applies one
    /// chunk and survives, and the next fold's continuation chunk completes
    /// the drain. The record then lingers (within the retention window) to
    /// project the terminated shard's settled-transaction root.
    #[test]
    fn deep_terminal_backlog_drains_over_two_folds() {
        let (mut state, parent, pair, composed) = terminating_state();
        let total = MAX_WITNESSES_PER_SHARD as u64 + 6;

        let (header, payloads, _range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, total, None);

        let first_chunk = sub_chunk(&payloads, 0, MAX_WITNESSES_PER_SHARD);
        let (committed, contributions) =
            contribution_for(parent, header.clone(), first_chunk, 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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

        let rest = sub_chunk(&payloads, MAX_WITNESSES_PER_SHARD, payloads.len());
        let (committed, contributions) = contribution_for(parent, header, rest, 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
            &BTreeSet::new(),
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

    /// A terminal record drops once the chain advances past its evidence
    /// window — it lingers only to project the settled-transaction root, dead
    /// weight once the fence rejects naming the shard regardless.
    #[test]
    fn terminal_record_drops_past_the_evidence_window() {
        let (mut state, parent, pair, composed) = terminating_state();
        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) =
            contribution_for(parent, header, (payloads, range_proof), 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );
        assert!(
            state.boundaries.contains_key(&parent),
            "lingers within the retention window",
        );

        // The children seat and produce past their genesis — the handoff is
        // done, and the sweep that observes it stamps the completion epoch.
        // The evidence window counts from that stamp, so the record is
        // retained on this very sweep however far past the cut it runs.
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.advanced.insert(child);
        }
        let stamp = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 5);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            stamp,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            state.boundaries.contains_key(&parent),
            "the window counts from the handoff's completion, not the cut",
        );

        // One window past the stamp the record is dead weight and drops.
        let past = Epoch::new(stamp.inner() + TERMINAL_EVIDENCE_EPOCHS + 2);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            past,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            !state.boundaries.contains_key(&parent),
            "terminal record drops once the evidence window past the handoff closes",
        );
    }

    /// The evidence window outlives the fold that first carries the roots.
    ///
    /// A terminal block satisfies `parent ≤ cut < qc`, so it cannot exist
    /// until the window after the one it closes, and the beacon block for
    /// that window is composed while the crossing is still being produced —
    /// the contribution folds one window later again. At a production
    /// 300s epoch that is 600s past the cut, so a window measured in
    /// transaction-artifact retention (144s) would drop the record on the
    /// very fold that first gave it roots to project, and no counterpart
    /// would ever read a departed shard's settled set.
    ///
    /// The successors are live here, so nothing but the window itself is
    /// holding the record.
    #[test]
    fn terminal_roots_land_inside_the_evidence_window() {
        let (mut state, parent, pair, composed) = terminating_state();
        // Production epochs: the cut moves to 600_000ms, and the fold that
        // carries the roots opens at 900_000ms.
        state.chain_config.epoch_duration_ms = 300_000;
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.advanced.insert(child);
        }

        let roots = TerminalRoots {
            settled_txs: SettledTxsRoot::from_raw(Hash::from_bytes(b"settled")),
            committed_txs: CommittedTxsRoot::from_raw(Hash::from_bytes(b"committed")),
        };
        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 599_000, pair, composed, 3, Some(roots));
        let (committed, contributions) =
            contribution_for(parent, header, (payloads, range_proof), 601_000);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );

        let record = state
            .boundaries
            .get(&parent)
            .expect("the record survives the fold that first carries its roots");
        assert_eq!(
            record.terminal_roots,
            Some(roots),
            "and it carries them, for a surviving counterpart to read",
        );
    }

    /// The handoff stall diagnostic fires exactly at the bound: a terminal
    /// shard whose successors are still not live `RESHAPE_HANDOFF_TTL_EPOCHS`
    /// epochs after its scheduled cut is flagged; one epoch shy it stays
    /// quiet.
    #[test]
    fn stalled_handoffs_fire_at_the_ttl_not_before() {
        let parent = ShardId::ROOT;
        let cut = Epoch::new(5);
        let pending = BTreeMap::from([(parent, cut)]);

        let just_under = Epoch::new(cut.inner() + RESHAPE_HANDOFF_TTL_EPOCHS - 1);
        assert!(
            stalled_handoffs(&pending, just_under).is_empty(),
            "quiet one epoch shy of the bound",
        );

        let at_bound = Epoch::new(cut.inner() + RESHAPE_HANDOFF_TTL_EPOCHS);
        assert_eq!(
            stalled_handoffs(&pending, at_bound),
            vec![(parent, cut)],
            "flagged once the bound is reached",
        );
    }

    /// A split parent whose children are still placeholders outlives the
    /// evidence window. The children seed only from the parent's terminal
    /// fold, and the beacon can commit empty for several epochs across the
    /// reshape's committee transition before any non-empty commit carries
    /// that fold — dropping the record on the window alone would strand
    /// both children on their placeholders forever.
    #[test]
    fn unseeded_split_parent_outlives_the_evidence_window() {
        let (mut state, parent, pair, composed) = terminating_state();

        // The beacon commits empty well past the window: no terminal fold
        // yet, so both children stay on their placeholder anchors.
        let past = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 5);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            past,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            state.boundaries.contains_key(&parent),
            "an unseeded split parent is held past the window",
        );
        for child in <[ShardId; 2]>::from(parent.children()) {
            assert_eq!(
                state.boundaries.get(&child).unwrap().block_hash,
                BlockHash::ZERO,
                "children still pending",
            );
        }

        // The terminal contribution finally lands: it seeds both children.
        let (header, payloads, range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, 3, None);
        let (committed, contributions) =
            contribution_for(parent, header, (payloads, range_proof), 2_500);
        let later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 6);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            later,
            &committed,
            &contributions,
            &BTreeSet::new(),
        );

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

        // The children produce past their genesis — the handoff completes and
        // the sweep stamps it, which is what opens the evidence window.
        for child in <[ShardId; 2]>::from(parent.children()) {
            state.advanced.insert(child);
        }
        let even_later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 7);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            even_later,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            state.boundaries.contains_key(&parent),
            "the parent is held through the evidence window past the handoff",
        );

        // And drops once that window closes.
        let closed = Epoch::new(even_later.inner() + TERMINAL_EVIDENCE_EPOCHS + 2);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            closed,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        assert!(
            !state.boundaries.contains_key(&parent),
            "the parent drops once the evidence window past the handoff closes",
        );
    }

    /// A merge child whose parent is still an uncomposed placeholder outlives
    /// the evidence window. The parent composes only from both children's
    /// terminal folds, and the beacon can commit empty for several epochs
    /// across the reshape's committee transition before either fold lands —
    /// dropping a child on the window alone would strand the parent on its
    /// placeholder forever.
    #[test]
    #[allow(clippy::too_many_lines)] // walks three epochs of merge lifecycle in one scenario
    fn merge_child_outlives_the_window_until_parent_composes() {
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );
        // Both children have folded their terminal contribution (a real
        // anchor, `terminal_delivered` set), waiting for the parent to compose.
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
                    attested_work: 0,
                    used: DeclaredWork::ZERO,
                    substate_bytes: 0,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: Some(Epoch::new(1)),
                    handoff_complete: None,
                    terminal_delivered: true,
                    terminal_roots: None,
                    reshape_admitted_epoch: None,
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

        // The beacon commits empty well past the window: the parent hasn't
        // composed, so both children's terminal records must be held.
        let past = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 5);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            past,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        for child in [left, right] {
            assert!(
                state.boundaries.contains_key(&child),
                "a merge child is held past the window while its parent is uncomposed",
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
        let later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 6);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            later,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        for child in [left, right] {
            assert!(
                state.boundaries.contains_key(&child),
                "a merge child is held while the reformed parent is composed but not yet live",
            );
        }

        // The reformed parent produces past its genesis — the handoff
        // completes, the sweep stamps it, and the evidence window opens.
        state.advanced.insert(parent);
        let even_later = Epoch::new(TERMINAL_EVIDENCE_EPOCHS + 7);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            even_later,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        for child in [left, right] {
            assert!(
                state.boundaries.contains_key(&child),
                "a merge child is held through the evidence window past the handoff",
            );
        }

        // And they drop once that window closes.
        let closed = Epoch::new(even_later.inner() + TERMINAL_EVIDENCE_EPOCHS + 2);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            closed,
            &[],
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        for child in [left, right] {
            assert!(
                !state.boundaries.contains_key(&child),
                "a merge child drops once the evidence window past the handoff closes",
            );
        }
    }

    /// A terminal contribution carrying a `settled_txs_root` folds it
    /// onto the parent's boundary record and projects it onto the
    /// snap-sync anchor — the path a surviving counterpart reads the
    /// terminated shard's settled-transaction commitment from. Folded with a
    /// lingering backlog so the terminal record survives the fold (a
    /// fully drained one drops in-fold).
    #[test]
    fn terminal_settled_txs_root_folds_and_projects() {
        let (mut state, parent, pair, composed) = terminating_state();
        let total = MAX_WITNESSES_PER_SHARD as u64 + 6;
        let root = SettledTxsRoot::from_raw(Hash::from_bytes(b"settled transaction"));
        let roots = TerminalRoots {
            settled_txs: root,
            committed_txs: CommittedTxsRoot::ZERO,
        };

        let (header, payloads, _range_proof) =
            terminal_block_with_witnesses(parent, 9, 1_900, pair, composed, total, Some(roots));
        let first_chunk = sub_chunk(&payloads, 0, MAX_WITNESSES_PER_SHARD);
        let (committed, contributions) = contribution_for(parent, header, first_chunk, 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );

        let folded = state.boundaries.get(&parent).expect("lingers mid-drain");
        assert_eq!(folded.terminal_roots.map(|r| r.settled_txs), Some(root));

        // The projection carries the root onto the anchor regardless of
        // trie membership: a terminated parent leaves the trie, but its
        // boundary record projects from the global map.
        let anchor = state
            .derive_topology_snapshot(net())
            .boundary(parent)
            .expect("terminal record projects");
        assert_eq!(anchor.terminal_roots.map(|r| r.settled_txs), Some(root));
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
                    attested_work: 0,
                    used: DeclaredWork::ZERO,
                    substate_bytes: 0,
                    last_live_epoch: Epoch::new(1),
                    consecutive_misses: 0,
                    terminal_epoch: Some(Epoch::new(1)),
                    handoff_complete: None,
                    terminal_delivered: false,
                    terminal_roots: None,
                    reshape_admitted_epoch: None,
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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

        let (lh, lw, lw_proof) =
            boundary_block_with_payloads_full(left, 9, 1_900, left_root, vec![], None, None);
        let (rh, rw, rw_proof) =
            boundary_block_with_payloads_full(right, 10, 1_900, right_root, vec![], None, None);
        let proposal = BeaconProposal::new(
            [
                (left, Some(qc_over(&lh, 2_500))),
                (right, Some(qc_over(&rh, 2_500))),
            ]
            .into_iter()
            .collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = [
            (
                left,
                ShardEpochContribution {
                    boundary_header: lh.clone(),
                    payloads: lw,
                    range_proof: lw_proof,
                },
            ),
            (
                right,
                ShardEpochContribution {
                    boundary_header: rh.clone(),
                    payloads: rw,
                    range_proof: rw_proof,
                },
            ),
        ]
        .into_iter()
        .collect();

        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
        let (rh, rw, rw_proof) =
            boundary_block_with_payloads_full(right, 10, 1_900, right_root, vec![], None, None);
        // Left child: spans its whole final window — anchored before the
        // window opens, certified exactly on the terminal cut. A genuine
        // crossing (of the cut INTO the final window), carrying the
        // still-running chain's pre-freeze root.
        let pre_freeze = StateRoot::from_raw(Hash::from_bytes(b"left pre-freeze root"));
        let (span_header, span_witnesses, span_witnesses_proof) =
            boundary_block_with_payloads_full(left, 9, 900, pre_freeze, vec![], None, None);
        let proposal = BeaconProposal::new(
            [
                (left, Some(qc_over(&span_header, 2_000))),
                (right, Some(qc_over(&rh, 2_500))),
            ]
            .into_iter()
            .collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = [
            (
                left,
                ShardEpochContribution {
                    boundary_header: span_header,
                    payloads: span_witnesses,
                    range_proof: span_witnesses_proof,
                },
            ),
            (
                right,
                ShardEpochContribution {
                    boundary_header: rh.clone(),
                    payloads: rw,
                    range_proof: rw_proof,
                },
            ),
        ]
        .into_iter()
        .collect();
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );

        // The spanning refresh recorded — but as a live refresh, not a
        // terminal: no terminal_delivered, and the parent stays pending
        // rather than composing with the pre-freeze root.
        let left_record = state.boundaries.get(&left).expect("left refreshed");
        assert_eq!(left_record.state_root, pre_freeze);
        assert!(!left_record.terminal_delivered);
        let parent_record = state.boundaries.get(&parent).expect("parent tracked");
        assert_eq!(
            parent_record.block_hash,
            BlockHash::ZERO,
            "parent composed early"
        );

        // The real coast block crosses the cut with the frozen root; the
        // parent composes from it and the lingering right terminal.
        let (coast_header, coast_witnesses, coast_witnesses_proof) =
            boundary_block_with_payloads_full(left, 10, 2_000, left_root, vec![], None, None);
        let proposal = BeaconProposal::new(
            std::iter::once((left, Some(qc_over(&coast_header, 2_100)))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let committed = vec![(ValidatorId::new(0), proposal)];
        let contributions = std::iter::once((
            left,
            ShardEpochContribution {
                boundary_header: coast_header.clone(),
                payloads: coast_witnesses,
                range_proof: coast_witnesses_proof,
            },
        ))
        .collect();
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
        let (lh, lw, lw_proof) =
            boundary_block_with_payloads_full(left, 9, 1_900, left_root, vec![], None, None);
        let (rh, rw, rw_proof) =
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
                BTreeMap::new(),
                Vec::new(),
                VrfProof::ZERO,
            );
            let committed = vec![(ValidatorId::new(0), proposal)];
            let contributions = [
                (
                    left,
                    ShardEpochContribution {
                        boundary_header: lh.clone(),
                        payloads: lw.clone(),
                        range_proof: lw_proof.clone(),
                    },
                ),
                (
                    right,
                    ShardEpochContribution {
                        boundary_header: rh.clone(),
                        payloads: rw.clone(),
                        range_proof: rw_proof.clone(),
                    },
                ),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>();
            (committed, contributions)
        };

        // Fold E: only the left child terminates. It is held (the parent
        // can't compose without the sibling) and the parent stays pending.
        let (committed, contributions) =
            contribution_for(left, lh.clone(), (lw.clone(), lw_proof.clone()), 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(2),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
        let (committed, contributions) =
            contribution_for(right, rh.clone(), (rw.clone(), rw_proof.clone()), 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(3),
            &committed,
            &contributions,
            &BTreeSet::new(),
        );
        let anchor = expected_merge_anchor(parent, &lh, &rh, 2_000);
        assert_eq!(state.boundaries[&parent].block_hash, anchor.hash());
        assert!(
            state.boundaries.contains_key(&left),
            "children held at compose"
        );

        // Fold E+2: the children re-source again and, with the parent
        // composed, linger past the drain (carrying their settled-transaction
        // roots for surviving counterparts) until the retention GC.
        let (committed, contributions) = both(2_500, 2_500);
        record_boundaries(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(4),
            &committed,
            &contributions,
            &BTreeSet::new(),
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
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::GENESIS,
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
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

    // ─── window projection agreement ─────────────────────────────────────

    /// Every window's schedule entry is written twice — once as the
    /// preceding fold's lookahead, once re-derived as that window's active
    /// entry at promotion — and the two must be byte-identical. A window's
    /// boundary verdicts are stamped into signed headers from whichever
    /// copy a node holds, so a divergence between them is a fork.
    ///
    /// The property the per-field promotion freezes exist to establish,
    /// asserted over the whole projection rather than one field at a time:
    /// a field that gains a live value but no freeze fails here.
    /// The window-frozen half of a snapshot: everything a window's own
    /// entry fixes at promotion, which both writes must agree on.
    ///
    /// The rest of a snapshot is deliberately live in both writes, and
    /// excluded here. Boundary anchors, `advanced` and the recovery records
    /// are the current view of the chain rather than a property of the
    /// window. So are the retained parent-half cohorts: the applying fold
    /// derives them from the committee change it is making, so a lookahead
    /// taken before that fold carries none while the active entry re-derived
    /// after it does. Nothing stamps a verdict from either — they drive duty
    /// discovery off the head — so the divergence forks nothing.
    fn window_frozen_view(snapshot: &TopologySnapshot) -> String {
        let mut shards: Vec<ShardId> = snapshot.shard_trie().leaves().collect();
        shards.sort_unstable();
        let per_shard: Vec<String> = shards
            .iter()
            .map(|s| {
                format!(
                    "{s:?} committee={:?} consensus={:?} witness_base={:?} \
                     split_pending={} scheduled_terminal={:?} settled_floor={:?}",
                    snapshot.committee_for_shard(*s),
                    snapshot.consensus_committee_for_shard(*s),
                    snapshot.witness_base(*s),
                    snapshot.split_pending(*s),
                    snapshot.scheduled_terminal(*s),
                    snapshot.settled_window_floor(*s),
                )
            })
            .collect();
        format!(
            "shards={per_shard:?} observers={:?} keepers={:?} params={:?} prices={:?}",
            snapshot.reshape_observer_cohorts(),
            snapshot.reshape_keeper_cohorts(),
            snapshot.params(),
            snapshot.prices(),
        )
    }

    fn assert_lookahead_becomes_the_active_entry(state: &mut BeaconState, what: &str) {
        let lookahead = window_frozen_view(&state.derive_next_topology_snapshot(net()));
        apply_next_epoch(state, &[]);
        let active = window_frozen_view(&state.derive_topology_snapshot(net()));
        assert_eq!(
            lookahead, active,
            "the lookahead written before {what} must equal the active entry \
             re-derived at that window's promotion",
        );
    }

    /// The two writes agree across every fold a reshape passes through:
    /// admission, the readiness gate that schedules the cut, and the fold
    /// at the cut that applies it. The scheduling fold is the one that
    /// motivates INV-RESHAPE-9 — a cut stamped for the window the fold
    /// opens would land after that window's active entry was frozen.
    #[test]
    fn a_window_entry_is_identical_from_either_write_across_a_reshape() {
        let p = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        state.chain_config.shard_size = 4;
        state.chain_config.epoch_duration_ms = 1_000;
        state.shard_committees = state.next_shard_committees.clone();
        for i in 0..4u64 {
            state.validators.insert(
                ValidatorId::new(1000 + i),
                validator_record(1000 + i, 0, ValidatorStatus::Pooled),
            );
        }
        apply_next_epoch(&mut state, &[]);

        assert_lookahead_becomes_the_active_entry(&mut state, "a quiet fold");

        // Admission draws the observer cohort.
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
            },
        );
        assert_lookahead_becomes_the_active_entry(&mut state, "a split admission");

        // Every observer readies, so the next fold's gate schedules the cut.
        let seats: Vec<(ValidatorId, ShardId)> = match &state.pending_reshapes[&p] {
            PendingReshape::Split { cohort, .. } => {
                cohort.iter().map(|(id, seat)| (*id, seat.child)).collect()
            }
            PendingReshape::Merge { .. } => panic!("a split was admitted"),
        };
        for (validator, child) in seats {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                p,
                &ShardWitnessPayload::ReshapeReady { validator, child },
            );
        }
        assert_lookahead_becomes_the_active_entry(&mut state, "the fold that schedules the cut");
        assert!(
            state.pending_reshapes[&p].scheduled_terminal().is_some(),
            "the gate must have fired for this to cover the scheduling fold",
        );

        assert_lookahead_becomes_the_active_entry(&mut state, "the fold at the cut");
        assert!(
            state.pending_reshapes.is_empty(),
            "the cut must have applied for this to cover the applying fold",
        );
    }

    /// The beacon's seed and a successor's own derivation are the same
    /// block, because they are the same function.
    ///
    /// The fold seeds a child's anchor from the parent's terminal
    /// contribution; a follower derives its genesis from the same terminal
    /// as it walks past. Those two once had independent implementations
    /// that had to be kept in step by inspection — and on the merge side
    /// they had already diverged.
    #[test]
    fn the_fold_and_a_successor_derive_one_genesis_from_one_terminal() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let canonical_wt = WeightedTimestamp::from_millis(7_000);
        let terminal = terminal_header_with_pair(parent, pair);

        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        for child in [left, right] {
            state.boundaries.insert(
                child,
                ShardBoundary {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: BlockHeight::GENESIS,
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    attested_work: 0,
                    used: DeclaredWork::ZERO,
                    substate_bytes: 0,
                    last_live_epoch: Epoch::GENESIS,
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    handoff_complete: None,
                    terminal_delivered: false,
                    terminal_roots: None,
                    reshape_admitted_epoch: None,
                },
            );
        }
        seed_split_children(
            &mut state,
            parent,
            &terminal,
            &qc_over(&terminal, canonical_wt.as_millis()),
            Epoch::new(1),
        );

        for child in [left, right] {
            let (derived, origin) =
                Block::split_child_genesis_from_terminal(child, &terminal, canonical_wt)
                    .expect("the pair composes");
            let seeded = state.boundaries[&child];
            assert_eq!(seeded.block_hash, derived.hash());
            assert_eq!(seeded.height, origin.genesis_height);
            assert_eq!(seeded.state_root, derived.header().state_root());
        }
    }

    /// The price level is frozen a window ahead and promoted beside the
    /// params, so a block anchored inside a window resolves the table
    /// that window opened with however many folds have run since.
    ///
    /// The head and the lookahead are what a straddling transaction's
    /// two shards each resolve; the pin is that the lookahead a fold
    /// publishes is exactly what the next promotion installs.
    #[test]
    fn the_price_level_promotes_a_window_behind_the_fold() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;

        // A level the fold has computed but not yet promoted: the head
        // still carries the old one, the lookahead the new.
        let moved = PriceTable {
            compute: PriceTable::GENESIS.compute * 2,
            ..PriceTable::GENESIS
        };
        state.next_prices = moved;
        assert_eq!(
            state.derive_topology_snapshot(net()).prices(),
            PriceTable::GENESIS,
            "this window prices at the table it opened with"
        );
        assert_eq!(
            state.derive_next_topology_snapshot(net()).prices(),
            moved,
            "the next window carries what this fold computed"
        );

        apply_epoch(
            &BlsVerifier,
            &mut state,
            &net(),
            Epoch::new(1),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        assert_eq!(state.prices, moved, "the promotion installs it");
        assert_eq!(state.derive_topology_snapshot(net()).prices(), moved);
    }

    /// The controller reads each dimension on its own and only from the
    /// shards that produced: a saturated epoch in one dimension raises
    /// that row and no other, an idle one lowers it, and a shard whose
    /// boundary never advanced contributes neither a numerator nor a
    /// denominator.
    #[test]
    fn the_controller_steps_each_row_by_its_own_dimension() {
        let live = ShardId::leaf(1, 0);
        let absent = ShardId::leaf(1, 1);
        let blocks = 4u64;

        // Two shards, one of which produces. The absent one is seeded at
        // the same marks it ends on, so it moves nothing either way.
        let mut state = single_pool_state(4);
        for shard in [live, absent] {
            state
                .boundaries
                .insert(shard, load_boundary(DeclaredWork::ZERO, 0));
        }
        let full = DeclaredWork {
            compute: BLOCK_CAPS.compute * blocks,
            ..DeclaredWork::ZERO
        };
        let before: BTreeMap<ShardId, (DeclaredWork, BlockHeight)> = state
            .boundaries
            .iter()
            .map(|(shard, record)| (*shard, (record.used, record.height)))
            .collect();
        state.boundaries.insert(live, load_boundary(full, blocks));

        let reading = network_utilization(&state, &before);
        assert_eq!(
            (reading.compute.used, reading.compute.capacity),
            (
                u128::from(BLOCK_CAPS.compute) * u128::from(blocks),
                u128::from(BLOCK_CAPS.compute) * u128::from(blocks)
            ),
            "the producing shard's blocks are the whole of the capacity"
        );
        assert_eq!(
            reading.read_bytes.used, 0,
            "a dimension nothing declared reads as idle, not as absent"
        );

        let stepped = PriceTable::GENESIS.stepped(&reading, &widened());
        assert!(
            stepped.compute > PriceTable::GENESIS.compute,
            "a saturated dimension raises its own row"
        );
        assert!(
            stepped.read_bytes < PriceTable::GENESIS.read_bytes,
            "an idle dimension lowers its own row"
        );
        assert_eq!(
            stepped.footprint,
            PriceTable::GENESIS
                .stepped(
                    &FiveWay {
                        footprint: reading.footprint,
                        ..FiveWay::default()
                    },
                    &widened()
                )
                .footprint,
            "no row reads another dimension"
        );
    }

    /// A reshaping epoch is read over the boundaries the fold left
    /// standing.
    ///
    /// A child starts its own count at zero, so its blocks and what they
    /// reserved are the whole of what it contributes; the parent it
    /// replaced leaves `boundaries` and contributes nothing, its last
    /// epoch of load going with it. Both understate such an epoch, which
    /// is the safe direction: a row moves on what shards that still
    /// exist declared, never on a count nobody will produce again.
    #[test]
    fn a_reshape_epoch_reads_the_boundaries_that_stand() {
        let parent = ShardId::leaf(1, 0);
        let child = ShardId::leaf(2, 0);
        let blocks = 4u64;
        let mut state = single_pool_state(4);

        // Before the fold: the parent mid-chain, having reserved a full
        // epoch's compute.
        let spent = DeclaredWork {
            compute: BLOCK_CAPS.compute * blocks,
            ..DeclaredWork::ZERO
        };
        state.boundaries.insert(parent, load_boundary(spent, 9));
        let before: BTreeMap<ShardId, (DeclaredWork, BlockHeight)> = state
            .boundaries
            .iter()
            .map(|(shard, record)| (*shard, (record.used, record.height)))
            .collect();

        // After it: the parent is gone and the child holds a count of
        // its own, half its capacity spent.
        let halfway = DeclaredWork {
            compute: BLOCK_CAPS.compute * blocks / 2,
            ..DeclaredWork::ZERO
        };
        state.boundaries.remove(&parent);
        state
            .boundaries
            .insert(child, load_boundary(halfway, blocks));

        let reading = network_utilization(&state, &before);
        assert_eq!(
            (reading.compute.used, reading.compute.capacity),
            (
                u128::from(halfway.compute),
                u128::from(BLOCK_CAPS.compute) * u128::from(blocks)
            ),
            "the child's own blocks are the whole reading, and the parent it \
             replaced is no part of it"
        );
        assert_eq!(
            PriceTable::GENESIS.stepped(&reading, &widened()).compute,
            PriceTable::GENESIS.compute,
            "and a half-full epoch holds the row where it is"
        );
    }

    /// A network where nothing advanced has no reading at all, so every
    /// row holds rather than walking down through an outage.
    #[test]
    fn an_epoch_nothing_produced_in_moves_no_row() {
        let mut state = single_pool_state(4);
        state
            .boundaries
            .insert(ShardId::leaf(1, 0), load_boundary(DeclaredWork::ZERO, 7));
        let before: BTreeMap<ShardId, (DeclaredWork, BlockHeight)> = state
            .boundaries
            .iter()
            .map(|(shard, record)| (*shard, (record.used, record.height)))
            .collect();

        let reading = network_utilization(&state, &before);
        assert_eq!(reading.compute.capacity, 0);
        assert_eq!(
            PriceTable::GENESIS.stepped(&reading, &widened()),
            PriceTable::GENESIS
        );
    }

    /// The fold writes the level the window after next will price at,
    /// held inside whatever interval the vote in the same fold settled.
    ///
    /// What a crossing contributes to the reading is
    /// [`network_utilization`]'s, pinned beside it; what this pins is
    /// the rail around it — that the fold steps at all, that it reads
    /// the bounds the level will live under rather than the ones it is
    /// leaving, and that a level a vote just put out of range comes back
    /// at the fold rather than at the vote.
    #[test]
    fn the_fold_holds_the_level_inside_the_bounds_it_just_settled() {
        let mut state = single_pool_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        state.params.price_bounds = widened();
        state.next_params.price_bounds = widened();
        // A level the controller walked up while the interval was open,
        // seeded on both rails: the fold promotes the lookahead first,
        // so a level set only on the head is one the promotion wipes.
        let raised = PriceTable {
            compute: PriceTable::GENESIS.compute * 4,
            ..PriceTable::GENESIS
        };
        state.prices = raised;
        state.next_prices = raised;

        let fold = |state: &mut BeaconState, epoch: u64| {
            apply_epoch(
                &BlsVerifier,
                state,
                &net(),
                Epoch::new(epoch),
                ApplyEpochInput::Normal {
                    committed: &[],
                    shard_contributions: &BTreeMap::new(),
                },
            );
        };

        // No shard produced, so there is no reading and the level holds
        // where it is rather than reading as idle.
        fold(&mut state, 1);
        assert_eq!(state.next_prices, raised);

        // A vote pinning the interval brings it back in at the next
        // fold, not at the vote: this window keeps pricing at what it
        // opened with.
        state.next_params.price_bounds = PriceBounds::GENESIS;
        let before = state.prices;
        fold(&mut state, 2);
        assert_eq!(
            state.next_prices,
            PriceTable::GENESIS,
            "a level outside the new bounds is clamped at the next fold"
        );
        assert_eq!(
            state.prices, before,
            "and the window in force is untouched by the vote"
        );
    }

    /// An interval a vote opened, so the controller has room to move.
    /// The chain is born pinned, which is what keeps an uncalibrated
    /// weight from wandering before anyone has measured it.
    fn widened() -> PriceBounds {
        let scaled = |by: u64, div: u64| PriceTable {
            compute: PriceTable::GENESIS.compute * by / div,
            read_bytes: PriceTable::GENESIS.read_bytes * by / div,
            write_bytes: PriceTable::GENESIS.write_bytes * by / div,
            footprint: PriceTable::GENESIS.footprint * by / div,
            retention: PriceTable::GENESIS.retention * by / div,
        };
        PriceBounds {
            floor: scaled(1, 8),
            ceiling: scaled(8, 1),
        }
    }

    /// A boundary record at `height` whose chain has reserved `used`.
    fn load_boundary(used: DeclaredWork, height: u64) -> ShardBoundary {
        ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::new(height),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            attested_work: 0,
            used,
            substate_bytes: 0,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        }
    }

    /// A terminal header carrying `pair`, with the composed root as its own
    /// committed state root so the pair self-verifies.
    fn terminal_header_with_pair(shard: ShardId, pair: SplitChildRoots) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(9),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(shard, ChainOrigin::ROOT).into(),
            round: Round::new(3),
            state_root: pair.composed_root(),
            split_child_roots: Some(pair),
            ..Default::default()
        })
    }
}
