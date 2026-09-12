//! Witness ingestion: dedup, watermark gating, per-payload dispatch,
//! and equivocation re-verification.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHeader, Hash, JAIL_COOLDOWN_EPOCHS, JailReason, MAX_SHARDS,
    MISSED_PROPOSAL_JAIL_THRESHOLD, NetworkDefinition, PACKAGE_MATURITY_EPOCHS, PackageFact,
    PendingReshape, PendingWithdrawal, RESHAPE_READY_TTL_EPOCHS, RESHAPE_TRIGGER_TTL_EPOCHS,
    ShardId, ShardTrie, ShardWitnessPayload, Stake, StakePool, ValidatorId, ValidatorRecord,
    ValidatorStatus, Verifier, validator_possession_proof_verify, verify_shard_vote_equivocation,
    verify_vote_equivocation,
};

use crate::rules;
use crate::state::committee::abort_rotations;
use crate::state::conviction::convict_pool;
use crate::state::reshape::{draw_merge_keepers, draw_split_cohort, lapse_split, release_cohort};
use crate::state::vrf::{jail_validator, on_missing_crossings_shard};
use crate::state::withdrawals::deactivate_to_insufficient_stake;

/// Outcome of the epoch's witness application —
/// [`apply_contribution_witnesses`] (boundary chunks) and
/// [`ingest_equivocations`] (proposal-borne evidence).
///
/// Each field is a deterministic-order list of validator ids
/// transitioned by witness application this epoch, used by
/// [`super::epoch::apply_epoch`] to populate the matching
/// [`SlotEffects`](hyperscale_types::SlotEffects) fields.
#[derive(Default)]
pub(super) struct WitnessOutcome {
    pub(super) registered: Vec<ValidatorId>,
    pub(super) deactivated: Vec<ValidatorId>,
    pub(super) jailed: Vec<ValidatorId>,
    pub(super) revoked: Vec<ValidatorId>,
    pub(super) unjailed: Vec<ValidatorId>,
    pub(super) readied: Vec<ValidatorId>,
}

impl WitnessOutcome {
    /// Route a per-witness validator-status event into the matching list.
    fn record(&mut self, event: &HostEvent) {
        match event {
            HostEvent::Registered(id) => self.registered.push(*id),
            HostEvent::Deactivated(id) => self.deactivated.push(*id),
            HostEvent::Jailed(id) => self.jailed.push(*id),
            HostEvent::Unjailed(id) => self.unjailed.push(*id),
            HostEvent::Readied(id) => self.readied.push(*id),
        }
    }

    /// Merge another outcome's lists into this one.
    pub(super) fn extend(&mut self, other: Self) {
        self.registered.extend(other.registered);
        self.deactivated.extend(other.deactivated);
        self.jailed.extend(other.jailed);
        self.revoked.extend(other.revoked);
        self.unjailed.extend(other.unjailed);
        self.readied.extend(other.readied);
    }
}

/// Validator-status effect of one shard-lift application.
///
/// `StakeDeposit` and `StakeWithdraw` payloads mutate pool state but
/// produce no validator-level event (caller sees `None`).
#[derive(Clone)]
pub(super) enum HostEvent {
    Registered(ValidatorId),
    Deactivated(ValidatorId),
    Jailed(ValidatorId),
    Unjailed(ValidatorId),
    Readied(ValidatorId),
}

/// Re-verify and apply the equivocation evidence ridden by `accepted`
/// proposals.
///
/// Evidence is applied without dedup — re-application is idempotent once
/// the validator is `Revoked`. Each entry re-verifies against the
/// registry unless it carries a `Verified` marker upgraded at the
/// admission gate, so apply stays fail-closed on the gossip path
/// (which decodes `Unverified`). Committed evidence is threshold-vouched:
/// a 2f+1 commit implies ≥ f+1 honest verifiers behind every entry.
pub(super) fn ingest_equivocations(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    accepted: &[&(ValidatorId, BeaconProposal)],
) -> WitnessOutcome {
    let mut outcome = WitnessOutcome::default();
    for (_, prop) in accepted {
        for ev in prop.equivocations() {
            let evidence = ev.as_unverified();
            let validator_id = evidence.validator;
            let Some(rec) = state.validators.get(&validator_id) else {
                continue;
            };
            if ev.verified().is_none()
                && verify_vote_equivocation(
                    verifier,
                    evidence,
                    network,
                    &[(validator_id, rec.pubkey)],
                )
                .is_err()
            {
                continue;
            }
            // One proven double-sign convicts the whole pool — the
            // operator behind the key runs every seat the pool backs.
            // The cascade covers the race-exit defence
            // (`InsufficientStake` and fault-cause `Jailed` members
            // revoke with the rest) and its idempotence makes replayed
            // evidence a no-op.
            let pool_id = rec.pool;
            outcome
                .revoked
                .extend(convict_pool(state, pool_id, state.current_epoch));
        }
        for ev in prop.vote_equivocations() {
            let evidence = ev.as_unverified();
            let Some(rec) = state.validators.get(&evidence.validator) else {
                continue;
            };
            if ev.verified().is_none()
                && verify_shard_vote_equivocation(verifier, evidence, network, &rec.pubkey).is_err()
            {
                continue;
            }
            let pool_id = rec.pool;
            outcome
                .revoked
                .extend(convict_pool(state, pool_id, state.current_epoch));
        }
    }
    outcome
}

/// Validate and apply one shard's boundary-contribution witness chunk.
///
/// `payloads` must be exactly the leaf range `[prior, chunk_end)` of
/// `boundary_header`'s witness window, with `range_proof` lifting them to
/// `boundary_header.beacon_witness_root()`. Returns `false` **without
/// mutating `state`** if the chunk is the wrong length or the recomputed
/// root misses — the caller treats the shard as not refreshed. On success
/// every payload applies in leaf-index order via [`apply_shard_payload`],
/// its validator-level event recorded into `outcome`. Validation runs to
/// completion before any application, so a malformed chunk never
/// half-applies.
///
/// The source shard comes from the header rather than the payloads: a
/// contribution's leaves are the ones that shard's own accumulator
/// committed, so there is no per-payload origin to disagree with it.
#[allow(clippy::too_many_arguments)] // fold-internal helper mirroring the contribution's fields
pub(super) fn apply_contribution_witnesses(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    boundary_header: &BlockHeader,
    payloads: &[ShardWitnessPayload],
    range_proof: &[Hash],
    prior: u64,
    chunk_end: u64,
    outcome: &mut WitnessOutcome,
) -> bool {
    if !rules::contribution_chunk_valid(boundary_header, payloads, range_proof, prior, chunk_end) {
        return false;
    }
    let source_shard = boundary_header.shard_id();
    for payload in payloads {
        if let Some(event) = apply_shard_payload(verifier, state, network, source_shard, payload) {
            outcome.record(&event);
        }
    }
    true
}

/// Dispatch a single shard-witness payload to its handler.
///
/// `StakeDeposit` and `StakeWithdraw` mutate pool state without
/// producing a validator-level event — they return `None`. Variants
/// that change validator status return the corresponding
/// [`HostEvent`] for [`apply_contribution_witnesses`] to route into
/// [`WitnessOutcome`].
///
/// `source_shard` is the shard that emitted the witness, read from the
/// contribution's boundary header.
/// Most variants ignore it; `MissedProposal` uses it to scope the
/// miss-counter increment to the witness's source committee — a
/// `MissedProposal` from shard S only counts against validators
/// currently `OnShard { shard: S, .. }`.
#[allow(clippy::too_many_lines)] // single dispatch over ShardWitnessPayload variants
pub(super) fn apply_shard_payload(
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    source_shard: ShardId,
    payload: &ShardWitnessPayload,
) -> Option<HostEvent> {
    match payload {
        ShardWitnessPayload::StakeDeposit { pool_id, amount } => {
            // Implicit pool creation on first deposit; subsequent
            // deposits accumulate into `total_stake`.
            let pool = state.pools.entry(*pool_id).or_insert_with(|| StakePool {
                id: *pool_id,
                total_stake: Stake::ZERO,
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            });
            pool.total_stake = pool.total_stake.saturating_add(*amount);
            None
        }
        ShardWitnessPayload::StakeWithdraw { pool_id, amount } => {
            // Withdrawal request enters the unbonding window.
            // `total_stake` is unchanged until maturation;
            // `effective_stake` drops immediately via the added
            // `pending_withdrawals` entry.
            //
            // Defense-in-depth: reject `amount > effective_stake`.
            // Shard staking contracts validate before emitting; the
            // re-check here keeps total_stake whole through the
            // maturation cycle even if a buggy or hostile shard emits
            // an over-withdrawal that `saturating_sub` would silently
            // clamp.
            let pool = state.pools.get_mut(pool_id)?;
            if *amount > pool.effective_stake() {
                return None;
            }
            pool.pending_withdrawals.push(PendingWithdrawal {
                amount: *amount,
                initiated_at_epoch: state.current_epoch,
            });
            None
        }
        ShardWitnessPayload::RegisterValidator {
            pool_id,
            validator_id,
            pubkey,
            possession_proof,
        } => {
            // Re-registration policy: once a `ValidatorRecord` exists
            // for `validator_id`, no second `RegisterValidator` for
            // that id ever takes effect. The id is dead for the
            // lifetime of the chain.
            if state.validators.contains_key(validator_id) {
                return None;
            }
            // Pool must exist, be unconvicted, and have capacity at the
            // current dynamic `min_stake` for one more active validator.
            // The conviction gate is load-bearing, not defensive: a
            // convicted pool has zero actives against positive stake, so
            // the capacity check alone would tick a replacement seat
            // straight back in.
            let pool = state.pools.get(pool_id)?;
            if pool.conviction.is_some() {
                return None;
            }
            if pool.current_active_count(state) + 1 > pool.max_active_count(state) {
                return None;
            }
            // Proof-of-possession: the registrant must sign for the key
            // it registers. This is the rogue-key defense every
            // aggregate-signature verifier over topology pubkeys relies
            // on — without it, an adversary could register
            // `g^r · pk_H^{-1}` against an honest key `pk_H` and forge
            // aggregates presenting `pk_H` as a co-signer. It also
            // subsumes malformed-key rejection: a key that is not a
            // valid G1 point verifies no signature, including its own
            // PoP. Failure is a no-op registration, like every other
            // rejected witness.
            if !validator_possession_proof_verify(
                verifier,
                network,
                *validator_id,
                pubkey,
                possession_proof,
            ) {
                return None;
            }
            state.validators.insert(
                *validator_id,
                ValidatorRecord {
                    id: *validator_id,
                    pool: *pool_id,
                    status: ValidatorStatus::Pooled,
                    registered_at_epoch: state.current_epoch,
                    pubkey: *pubkey,
                },
            );
            state
                .pools
                .get_mut(pool_id)
                .expect("pool existence checked above")
                .validators
                .insert(*validator_id);
            Some(HostEvent::Registered(*validator_id))
        }
        ShardWitnessPayload::DeactivateValidator {
            pool_id,
            validator_id,
        } => {
            // Operator-initiated retirement. Flips to
            // `InsufficientStake` from every status except those that
            // already represent "not consuming an epoch" or "permanently
            // out": `InsufficientStake` itself and `Revoked` (a
            // deactivation must never downgrade a revocation to a
            // reactivatable status). Fault-cause jails can still be
            // deactivated — the operator chooses to retire a jailed
            // validator rather than wait out the cooldown.
            let rec = state.validators.get(validator_id)?;
            // A pool speaks only about its own validators. The witness
            // names its emitting pool, which the shard derived from the
            // emitter rather than from anything the payload chose, so
            // this is the beacon end of a binding the lift cannot make:
            // the shard that emits has no view of which pool owns a
            // validator, and this does.
            if rec.pool != *pool_id {
                return None;
            }
            let should_deactivate = !matches!(
                rec.status,
                ValidatorStatus::InsufficientStake | ValidatorStatus::Revoked { .. }
            );
            if !should_deactivate {
                return None;
            }
            deactivate_to_insufficient_stake(state, *validator_id);
            Some(HostEvent::Deactivated(*validator_id))
        }
        ShardWitnessPayload::Unjail { pool_id, id } => {
            // Every jail returns to `Pooled` once its cooldown has
            // elapsed AND the pool can still support the additional
            // active epoch at the current dynamic `min_stake`. A pool
            // that over-committed while the validator was jailed
            // strands them — operator recourse is to deactivate
            // another validator or deposit more stake before lifting.
            // A withholding jail holds for a full recency period —
            // long enough that a grinder cannot return inside the
            // window its resample weight would still suppress it —
            // where a plain performance jail lifts after the short
            // fixed cooldown.
            let rec = state.validators.get(id)?;
            // Same binding as a deactivation: the lift stamps the pool
            // and the fold checks the validator is that pool's.
            if rec.pool != *pool_id {
                return None;
            }
            let ValidatorStatus::Jailed {
                since_epoch,
                reason,
            } = rec.status
            else {
                return None;
            };
            let cooldown = match reason {
                JailReason::Withholding => state.beacon_recency_period(),
                JailReason::Performance => JAIL_COOLDOWN_EPOCHS,
            };
            if state.current_epoch.inner() < since_epoch.inner().saturating_add(cooldown) {
                return None;
            }
            let pool = state.pools.get(pool_id)?;
            if pool.conviction.is_some() {
                return None;
            }
            if pool.current_active_count(state) + 1 > pool.max_active_count(state) {
                return None;
            }
            state
                .validators
                .get_mut(id)
                .expect("rec read above guarantees presence")
                .status = ValidatorStatus::Pooled;
            Some(HostEvent::Unjailed(*id))
        }
        ShardWitnessPayload::ParamVote(vote) => {
            // The source committee attests `pool` voted this way; the
            // beacon takes the witness as ground truth and records the
            // pool's one active slot — `None` clears it. A cast is dropped
            // unless its pool exists, its params are in bounds, and it can
            // still activate (a past-epoch proposal is dead on arrival).
            // The per-epoch tally (`tally_param_votes`) then reads the
            // accumulated slots.
            match vote.proposal {
                None => {
                    state.param_votes.remove(&vote.pool);
                }
                Some(proposal) => {
                    // A change is decided one epoch before it activates
                    // (`tally_param_votes` at `activate_at - 1`), so a vote
                    // naming this epoch or earlier can never be tallied —
                    // drop it on arrival rather than carrying dead weight.
                    // A convicted pool casts nothing: its stake is
                    // impounded and it holds no governance weight.
                    if state
                        .pools
                        .get(&vote.pool)
                        .is_some_and(|p| p.conviction.is_none())
                        && proposal.activate_at > state.current_epoch
                        && proposal.params.validate().is_ok()
                    {
                        state.param_votes.insert(vote.pool, proposal);
                    }
                }
            }
            None
        }
        ShardWitnessPayload::Ready { id } => {
            // Flip `ready: false → true` for an `OnShard` validator.
            // Other statuses (including already-ready `OnShard`) are
            // silent no-ops — re-signalling ready isn't an error,
            // just irrelevant.
            let rec = state.validators.get_mut(id)?;
            if let ValidatorStatus::OnShard {
                shard,
                ready: false,
                placed_at_epoch,
            } = rec.status
            {
                rec.status = ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch,
                };
                Some(HostEvent::Readied(*id))
            } else {
                None
            }
        }
        ShardWitnessPayload::MissedProposal { proposer_id, .. } => {
            // Shard-binding filter: only count the miss if the named
            // proposer is currently on the *witness's source shard*.
            // Misses from any other shard against this validator —
            // including stale misses after rotation — are silently
            // dropped. Bounds the threat surface to byzantine
            // majorities on the validator's own shard, which already
            // breaks safety locally.
            let rec = state.validators.get(proposer_id)?;
            let ValidatorStatus::OnShard {
                shard: placement_shard,
                ..
            } = rec.status
            else {
                return None;
            };
            if placement_shard != source_shard {
                return None;
            }
            let count = state.miss_counters.entry(*proposer_id).or_insert(0);
            *count += 1;
            if *count < MISSED_PROPOSAL_JAIL_THRESHOLD {
                return None;
            }
            // Misses reaching the fold while the proposer's shard is
            // missing crossings arrive through the halted chain's drained
            // witness backlog; the count keeps the observation, but the
            // jail defers so the frozen tip's custody stays seated for
            // the halt recovery. A jail lands only on evidence folded
            // after the shard crosses again.
            if on_missing_crossings_shard(state, *proposer_id) {
                return None;
            }
            // Threshold crossed: jail under Performance. `jail_validator`
            // re-reads the status to find the shard for the cascade
            // and clears `miss_counters[proposer]` as part of the
            // shared cleanup.
            jail_validator(
                state,
                *proposer_id,
                JailReason::Performance,
                state.current_epoch,
            );
            Some(HostEvent::Jailed(*proposer_id))
        }
        // The asserted epoch separates one assertion from the next on
        // the shard's own window; what dates a pending record here is
        // the beacon's own clock, so the fold reads the subject only.
        ShardWitnessPayload::ScheduleSplit { shard, epoch: _ } => {
            // Source pinning: only the shard itself asserts its split.
            if source_shard != *shard {
                return None;
            }
            // An existing split's re-assertion refreshes its trigger
            // clock. If a lapse emptied the cohort, the re-assertion also
            // re-staffs it from the frozen seed over the now-refilled
            // pool, re-deriving the identical selection and assignment.
            //
            // Never once the cut is scheduled. The gate approved one
            // specific cohort and froze the carve beside it, and there is
            // no second gate to approve another — a re-staff there would
            // seat the children from a cohort no gate ever passed, every
            // seat unready. A scheduled record's cohort cannot empty today
            // (the TTL lapse skips it), so this is the same property stated
            // where it would be violated rather than two files away.
            let existing = match state.pending_reshapes.get(shard) {
                Some(PendingReshape::Split {
                    cohort,
                    cohort_seed,
                    scheduled,
                    ..
                }) => Some((cohort.is_empty() && scheduled.is_none(), *cohort_seed)),
                _ => None,
            };
            if let Some((restaffable, seed)) = existing {
                let restaffed = (restaffable
                    && state.pooled_validators().len() >= state.chain_config.shard_size as usize)
                    .then(|| draw_split_cohort(state, *shard, &seed));
                if let Some(PendingReshape::Split {
                    cohort,
                    last_asserted,
                    ..
                }) = state.pending_reshapes.get_mut(shard)
                {
                    if let Some(restaffed) = restaffed {
                        *cohort = restaffed;
                    }
                    *last_asserted = state.current_epoch;
                }
                return None;
            }
            // The target must be an active trie leaf, free of any
            // overlapping reshape, and not already on its way out.
            if !state.shard_committees.contains_key(shard)
                || state.reshape_involves(*shard)
                || terminating(state, *shard)
            {
                return None;
            }
            // The shard ceiling counts splits already admitted but not
            // yet executed — each adds one net shard.
            let pending_splits = state
                .pending_reshapes
                .values()
                .filter(|r| matches!(r, PendingReshape::Split { .. }))
                .count();
            if state.shard_committees.len() + pending_splits + 1 > MAX_SHARDS {
                return None;
            }
            // Pool gate: the grow phase draws a full committee's worth
            // of observers; refuse what the pool can't staff. Rejection
            // isn't an error — the shard re-asserts next window and
            // admission resumes when the pool allows.
            if state.pooled_validators().len() < state.chain_config.shard_size as usize {
                return None;
            }
            tracing::info!(?shard, "Shard split admitted; reshape pending");
            // Freeze the current beacon randomness as the split's cohort
            // seed for its whole life, so a re-staff after a lapse draws
            // the identical cohort rather than re-rolling a fresh one.
            let cohort_seed = state.randomness;
            let cohort = draw_split_cohort(state, *shard, &cohort_seed);
            state.pending_reshapes.insert(
                *shard,
                PendingReshape::Split {
                    last_asserted: state.current_epoch,
                    admitted_at: state.current_epoch,
                    cohort,
                    cohort_seed,
                    scheduled: None,
                },
            );
            None
        }
        ShardWitnessPayload::ScheduleMerge { parent, epoch: _ } => {
            // Source pinning: only a child asserts the merge under its
            // parent.
            if source_shard.parent() != Some(*parent) {
                return None;
            }
            // Both children must be active trie leaves, and neither already
            // on its way out.
            let (left, right) = parent.children();
            if !state.shard_committees.contains_key(&left)
                || !state.shard_committees.contains_key(&right)
                || terminating(state, left)
                || terminating(state, right)
            {
                return None;
            }
            // Record or refresh this child's half. The merge pairs —
            // draws its keepers, becomes executable — once both children
            // hold a live half; a lone half expires via the staleness
            // sweep.
            let refreshed = if let Some(PendingReshape::Merge {
                halves,
                admitted_at,
                ..
            }) = state.pending_reshapes.get_mut(parent)
            {
                halves.insert(source_shard, state.current_epoch);
                Some(halves.len() == 2 && admitted_at.is_none())
            } else {
                None
            };
            if let Some(pairs_now) = refreshed {
                if pairs_now {
                    // The keeper draw prefers ready members, and a
                    // rotation's victim is ready by construction — it is
                    // the longest-tenured ready member on its shard. Drawn
                    // as a keeper it would hold a seat the rotation then
                    // retires, and a keeper off its child can neither
                    // signal ready nor reach the keeper move: the gate
                    // loses it and the merged committee seats short. The
                    // victim-exempt filter the shuffle applies covers only
                    // the seats that are keepers when it names a victim, so
                    // cancel here instead, where the keepers are chosen.
                    // Both children read at `shard_size`, every member
                    // ready — the same precondition the split gate gets.
                    for child in [left, right] {
                        abort_rotations(state, child);
                    }
                    let keepers = draw_merge_keepers(state, *parent);
                    if let Some(PendingReshape::Merge {
                        keepers: seats,
                        admitted_at,
                        ..
                    }) = state.pending_reshapes.get_mut(parent)
                    {
                        *seats = keepers;
                        *admitted_at = Some(state.current_epoch);
                    }
                    tracing::info!(
                        ?parent,
                        "Shard merge paired; keepers drawn, reshape pending"
                    );
                }
                return None;
            }
            // Neither child may be involved in another reshape (the
            // same-parent merge was handled by the refresh above).
            if state.reshape_involves(left) || state.reshape_involves(right) {
                return None;
            }
            tracing::info!(
                ?parent,
                child = ?source_shard,
                "Shard merge half asserted; awaiting the sibling"
            );
            state.pending_reshapes.insert(
                *parent,
                PendingReshape::Merge {
                    halves: BTreeMap::from([(source_shard, state.current_epoch)]),
                    keepers: BTreeMap::new(),
                    admitted_at: None,
                    scheduled_terminal: None,
                },
            );
            None
        }
        ShardWitnessPayload::ReshapeReady { validator, child } => {
            // Source pinning: a split's observers signal through the
            // splitting shard's own chain; a merge's keepers signal
            // through their child's chain (the merge is keyed by the
            // child's parent). Only the holder of a seat on that pending
            // reshape can mark it, and only for the successor it actually
            // synced: `child` is the emitter's signed attestation, and a
            // seat is marked ready only when its target matches. A signal
            // retained across a lapse and re-staffed onto the sibling child
            // no longer matches its seat, so it cannot mark it ready.
            if let Some(PendingReshape::Split { cohort, .. }) =
                state.pending_reshapes.get_mut(&source_shard)
            {
                if let Some(seat) = cohort.get_mut(validator)
                    && seat.child == *child
                {
                    seat.ready = true;
                }
                return None;
            }
            if let Some(PendingReshape::Merge { keepers, .. }) = source_shard
                .parent()
                .and_then(|parent| state.pending_reshapes.get_mut(&parent))
                && let Some(seat) = keepers.get_mut(validator)
                && seat.child == source_shard
                && seat.child == *child
            {
                seat.ready = true;
            }
            None
        }
        ShardWitnessPayload::PackagePublished { package, publisher } => {
            // The publisher locates the fact's bytes, so the fact is
            // held to the shard that owns the publisher's prefix — a
            // committee cannot register a publish for a prefix it does
            // not serve. First registration wins: the address is a
            // content address, so a second registration could only
            // restate it.
            if ShardTrie::shard_owns_prefix(source_shard, *publisher) {
                state
                    .packages
                    .entry(*package)
                    .or_insert_with(|| PackageFact {
                        publisher: *publisher,
                        usable_from: state.current_epoch.saturating_add(PACKAGE_MATURITY_EPOCHS),
                    });
            }
            None
        }
    }
}

/// Whether `shard` is already scheduled to leave the trie.
///
/// A reshape's record is consumed by the fold that applies it, at the top
/// of the shard's final window — but the shard stays in the committee set
/// and keeps producing for that whole window, so it keeps asserting its
/// trigger. Without this, admission sees a live leaf with no pending
/// reshape and admits a fresh one against a shard about to vanish, drawing
/// a cohort out of the pool onto a dead target and counting it against the
/// shard ceiling until the TTLs sweep it.
///
/// The terminal mark is stamped when the cut is scheduled, a window before
/// the record is consumed, so it covers the whole exposure. It cannot
/// misfire on a legitimate successor: a reformed merge parent and a fresh
/// split child both get boundaries with no mark.
fn terminating(state: &BeaconState, shard: ShardId) -> bool {
    state
        .boundaries
        .get(&shard)
        .is_some_and(|b| b.terminal_epoch.is_some())
}

/// Lapse or cancel pending reshapes whose triggers went quiet or whose
/// readiness gate never fired.
///
/// Triggers re-derive once per witness window while the load condition
/// holds, so every live assertion refreshes each epoch. The readiness
/// TTL is checked first and unconditionally: a split (or paired merge)
/// still ungated [`RESHAPE_READY_TTL_EPOCHS`] after admission is removed
/// outright — a stalled grow must not park a committee indefinitely, and
/// this is what bounds how long a lapsed split (and its frozen seed)
/// survives. Below that deadline, a split whose trigger has gone quiet
/// for [`RESHAPE_TRIGGER_TTL_EPOCHS`] *lapses*: its cohort returns to the
/// pool but the record is kept, so a re-assertion re-staffs the same
/// cohort. A merge whose half goes quiet for the trigger TTL cancels
/// outright (keepers never left their committees, so nothing to retain).
/// Runs after the epoch's witnesses apply, so an assertion folded this
/// epoch is never swept.
pub(super) fn prune_stale_reshapes(state: &mut BeaconState) {
    let current = state.current_epoch.inner();
    let mut removed: Vec<(ShardId, &str)> = Vec::new();
    let mut lapsed: Vec<ShardId> = Vec::new();
    for (target, reshape) in &mut state.pending_reshapes {
        // A scheduled cut is irrevocable. Its window's proposers have the
        // schedule frozen into their topology snapshot and stamp their
        // boundary verdicts from it, so retracting it here would leave
        // them carrying a verdict for a cut that never lands while the
        // shard stays in the trie. The readiness TTL governs
        // admission-to-scheduling and stops there.
        if reshape.scheduled_terminal().is_some() {
            continue;
        }
        match reshape {
            PendingReshape::Split {
                last_asserted,
                admitted_at,
                cohort,
                ..
            } => {
                if current.saturating_sub(admitted_at.inner()) >= RESHAPE_READY_TTL_EPOCHS {
                    removed.push((*target, "readiness TTL elapsed"));
                } else if !cohort.is_empty()
                    && current.saturating_sub(last_asserted.inner()) >= RESHAPE_TRIGGER_TTL_EPOCHS
                {
                    lapsed.push(*target);
                }
            }
            PendingReshape::Merge {
                halves,
                admitted_at,
                ..
            } => {
                halves.retain(|_, last| {
                    current.saturating_sub(last.inner()) < RESHAPE_TRIGGER_TTL_EPOCHS
                });
                // A lone half waits for its sibling, but once the merge
                // paired both halves must keep asserting — either going
                // quiet cancels the reshape and returns the keepers to
                // ordinary rotation.
                let required = if admitted_at.is_some() { 2 } else { 1 };
                if halves.len() < required {
                    removed.push((*target, "trigger went quiet"));
                } else if admitted_at.is_some_and(|at| {
                    current.saturating_sub(at.inner()) >= RESHAPE_READY_TTL_EPOCHS
                }) {
                    removed.push((*target, "readiness TTL elapsed"));
                }
            }
        }
    }
    for target in lapsed {
        lapse_split(state, target);
        tracing::info!(
            ?target,
            "Pending split lapsed; cohort released, awaiting re-assertion"
        );
    }
    for (target, cause) in removed {
        let Some(reshape) = state.pending_reshapes.remove(&target) else {
            continue;
        };
        if let PendingReshape::Split { cohort, .. } = &reshape {
            release_cohort(state, target, cohort);
        }
        tracing::info!(?target, cause, "Pending reshape cancelled");
    }
}

/// Carry every pending reshape's staleness and readiness anchors forward
/// one epoch.
///
/// The trigger and readiness TTLs measure how many epochs a reshape has
/// gone without asserting or readying, against `current_epoch`. A skip
/// epoch folds no witnesses, so no trigger can re-assert and no readiness
/// can advance; charging that epoch against the TTLs would cancel a
/// reshape that only looks quiet because the beacon stalled. Advancing the
/// anchors in lockstep with the skipped epoch holds each TTL's elapsed
/// count fixed across the stall.
pub(super) fn defer_reshape_ttls(state: &mut BeaconState) {
    for reshape in state.pending_reshapes.values_mut() {
        match reshape {
            PendingReshape::Split {
                last_asserted,
                admitted_at,
                ..
            } => {
                *last_asserted = last_asserted.next();
                *admitted_at = admitted_at.next();
            }
            PendingReshape::Merge {
                halves,
                admitted_at,
                ..
            } => {
                for last in halves.values_mut() {
                    *last = last.next();
                }
                if let Some(at) = admitted_at {
                    *at = at.next();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::{Address, AddressClass, ConsensusSignature, Signer, signed_bytes};
    // ─── witness fold framework + stake variants ─────────────────────────
    use hyperscale_types::{
        BlockHash, BlockHeight, BlockVote, CohortSeat, EMISSIONS_PER_EPOCH, Epoch, Hash,
        JAIL_COOLDOWN_EPOCHS, JailReason, MAX_SHARDS, MIN_STAKE_FLOOR,
        MISSED_PROPOSAL_JAIL_THRESHOLD, PendingReshape, PoolConviction, ProposerTimestamp,
        Randomness, Round, ShardCommittee, ShardId, ShardVoteEquivocation, ShardWitnessPayload,
        Stake, StakePool, StakePoolId, ValidatorId, ValidatorStatus,
    };

    use super::*;
    use crate::rules::contribution_chunk_valid;
    use crate::state::test_fixtures::{
        applied_count, apply_next_epoch, apply_witness_chunk, boundary_chunk, keypair,
        malformed_vrf_proposal, net, possession_proof, pubkey, single_pool_state, validator_record,
        vrf_proposal, vrf_proposal_with_equivocations, vrf_proposal_with_vote_equivocations,
    };

    fn deposit(pool: u32, amount: u64) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(pool),
            amount: Stake::from_whole_tokens(amount),
        }
    }

    /// `contribution_chunk_valid` accepts exactly the run whose recomputed
    /// root matches the boundary header's, and rejects every malformed
    /// shape — short, over-count, gapped, reordered, or proven against the
    /// wrong root. This is the fold-side
    /// (`apply_contribution_witnesses`) defence that mirrors the
    /// `contributions_well_formed` gate; both share this predicate, so a
    /// gap/short/over/wrong-root chunk can never half-apply.
    ///
    /// Gaps and reordering fail here through the recomputed root rather
    /// than a per-element index check: the range fixes each payload's
    /// position, so any permutation hashes to a different root.
    #[test]
    fn contribution_chunk_valid_rejects_malformed_chunks() {
        let (header, payloads, proof) =
            boundary_chunk(0, 0, vec![deposit(7, 1), deposit(7, 2), deposit(7, 3)]);

        // The exact chunk `[0, 3)` — accepted.
        assert!(contribution_chunk_valid(&header, &payloads, &proof, 0, 3));

        // Short: two payloads for a three-leaf range.
        assert!(!contribution_chunk_valid(
            &header,
            &payloads[..2],
            &proof,
            0,
            3
        ));

        // Over-count: three payloads for a two-leaf range.
        assert!(!contribution_chunk_valid(&header, &payloads, &proof, 0, 2));

        // Gapped: leaves 0 and 2 where the range expects 0 and 1.
        let gapped = vec![payloads[0].clone(), payloads[2].clone()];
        assert!(!contribution_chunk_valid(&header, &gapped, &proof, 0, 2));

        // Reordered: the same payloads in the wrong positions.
        let mut reordered = payloads.clone();
        reordered.reverse();
        assert!(!contribution_chunk_valid(&header, &reordered, &proof, 0, 3));

        // Wrong root: the same chunk proven against a different boundary
        // block (distinct payloads → distinct accumulator root).
        let (other, _, _) = boundary_chunk(0, 0, vec![deposit(9, 1), deposit(9, 2), deposit(9, 3)]);
        assert!(!contribution_chunk_valid(&other, &payloads, &proof, 0, 3));

        // A non-empty proof on an empty range spends block bytes for
        // nothing — rejected.
        assert!(contribution_chunk_valid(&header, &[], &[], 0, 0));
        assert!(!contribution_chunk_valid(&header, &[], &[Hash::ZERO], 0, 0));
    }

    /// `StakeDeposit` for an unknown pool implicitly creates the pool and
    /// accumulates `total_stake`; consecutive deposits accumulate further,
    /// and the applied watermark advances by the chunk length.
    #[test]
    fn stake_deposit_creates_pool_implicitly_and_accumulates() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_witness_chunk(&mut state, 0, vec![deposit(7, 100), deposit(7, 50)]);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(150));
        assert_eq!(applied_count(&state, 0), 2);
    }

    /// `StakeWithdraw` appends a `PendingWithdrawal` tagged with the
    /// current epoch; `total_stake` is unchanged but `effective_stake`
    /// drops immediately.
    #[test]
    fn stake_withdraw_records_pending_withdrawal_at_current_epoch() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(3);
        let pool_id = StakePoolId::new(0);
        let pre_total = state.pools.get(&pool_id).unwrap().total_stake;
        let pre_effective = state.pools.get(&pool_id).unwrap().effective_stake();

        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: Stake::from_whole_tokens(1_000),
            }],
        );

        let pool = state.pools.get(&pool_id).unwrap();
        assert_eq!(
            pool.total_stake,
            pre_total.saturating_add(EMISSIONS_PER_EPOCH)
        );
        assert_eq!(pool.pending_withdrawals.len(), 1);
        assert_eq!(
            pool.pending_withdrawals[0].amount,
            Stake::from_whole_tokens(1_000)
        );
        assert_eq!(
            pool.pending_withdrawals[0].initiated_at_epoch,
            state.current_epoch
        );
        assert_eq!(
            pool.effective_stake(),
            pre_effective
                .saturating_add(EMISSIONS_PER_EPOCH)
                .saturating_sub(Stake::from_whole_tokens(1_000)),
        );
    }

    /// Defense-in-depth: an over-withdrawal (`amount > effective_stake`)
    /// is rejected outright — no `pending_withdrawals` entry added — but
    /// the witness is still consumed (the watermark advances).
    #[test]
    fn stake_withdraw_rejects_over_effective_stake() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        let effective = state.pools.get(&pool_id).unwrap().effective_stake();

        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: effective.saturating_add(Stake::from_whole_tokens(1)),
            }],
        );

        let pool = state.pools.get(&pool_id).unwrap();
        assert!(pool.pending_withdrawals.is_empty());
        assert_eq!(applied_count(&state, 0), 1);
    }

    /// A contiguous chunk applies in leaf-index order and advances the
    /// watermark by all of it.
    #[test]
    fn witnesses_applied_in_leaf_index_order() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_witness_chunk(
            &mut state,
            0,
            vec![deposit(7, 1), deposit(7, 2), deposit(7, 3)],
        );

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(6));
        assert_eq!(applied_count(&state, 0), 3);
    }

    // ─── RegisterValidator + DeactivateValidator ─────────────────────────

    /// A convicted pool registers nothing: zero actives against its
    /// standing stake pass the capacity check, so the conviction gate
    /// alone blocks the replacement seat.
    #[test]
    fn register_validator_rejected_on_convicted_pool() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(2);
        let pool_id = StakePoolId::new(0);
        let epoch = state.current_epoch;
        let revoked = convict_pool(&mut state, pool_id, epoch);
        assert_eq!(revoked.len(), 4, "whole pool cascades");

        let new_id = ValidatorId::new(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: pubkey(5),
                possession_proof: possession_proof(5, new_id),
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&new_id));
    }

    /// A convicted pool unjails nothing, even a fault-cause jail whose
    /// cooldown has long elapsed.
    #[test]
    fn unjail_rejected_on_convicted_pool() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .conviction = Some(PoolConviction {
            convicted_at: since,
            lifts_at: Epoch::new(since.inner() + 100),
        });
        state.current_epoch = Epoch::new(since.inner() + 10 * JAIL_COOLDOWN_EPOCHS);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(10),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed { .. },
        ));
    }

    /// The race-exit defence: an operator deactivates the equivocator
    /// before the evidence lands, and the conviction still catches the
    /// whole pool — the fled `InsufficientStake` member included.
    #[test]
    fn conviction_catches_a_member_that_fled_to_insufficient_stake() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: target,
            }],
        );
        assert_eq!(effects.deactivated, vec![target]);

        let w = vote_equivocation_witness(target.inner(), Epoch::new(5), SpcView::new(0));
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, target_epoch, vec![w]),
        )];
        committed.extend((2u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.revoked.contains(&target), "the fled member revokes");
        assert_eq!(effects.revoked.len(), 4, "the whole pool revokes");
        assert!(state.pools[&StakePoolId::new(0)].conviction.is_some());
        for v in 0..4u64 {
            assert!(matches!(
                state.validators[&ValidatorId::new(v)].status,
                ValidatorStatus::Revoked { .. },
            ));
        }
    }

    /// The gossip-fed proposal lane convicts even when the accused
    /// validator sits on no current committee — the fold resolves the
    /// key from its permanent registry, which is what rescues evidence
    /// whose holders (and target) all left the source shard.
    #[test]
    fn proposal_carried_vote_equivocation_convicts_an_ex_member() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Registered but seated nowhere: the registry, not any
        // committee, must resolve the key.
        state.validators.insert(
            ValidatorId::new(9),
            validator_record(9, 0, ValidatorStatus::Pooled),
        );
        isolate_in_own_pool(&mut state, ValidatorId::new(9), 9);

        let ev = genuine_equivocation(9);
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_vote_equivocations(0, target_epoch, vec![ev]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.revoked, vec![ValidatorId::new(9)]);
        assert!(state.pools[&StakePoolId::new(9)].conviction.is_some());
        assert!(matches!(
            state.validators[&ValidatorId::new(9)].status,
            ValidatorStatus::Revoked { .. },
        ));
    }

    /// A forged pair on the proposal lane is dropped at the fold's
    /// fail-closed re-verify — unlike witness leaves, lane evidence
    /// carries no shard QC attestation to trust.
    #[test]
    fn proposal_carried_vote_equivocation_fails_closed_on_a_forgery() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();

        let forged = ShardVoteEquivocation {
            validator: ValidatorId::new(1),
            shard: ShardId::leaf(1, 0),
            height: BlockHeight::new(5),
            round: Round::new(2),
            block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"a")),
            parent_block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"pa")),
            sig_a: ConsensusSignature::ZERO,
            block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"b")),
            parent_block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"pb")),
            sig_b: ConsensusSignature::ZERO,
        };
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_vote_equivocations(0, target_epoch, vec![forged]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.revoked.is_empty());
        assert!(state.pools[&StakePoolId::new(0)].conviction.is_none());
    }

    /// Stake ops fold uniformly on a convicted pool: deposits credit
    /// and withdrawal initiations queue. Conviction only retires
    /// validation and freezes maturation — a fold-side rejection the
    /// shard-layer staking contract doesn't mirror would skew the two
    /// ledgers once custody lands there.
    #[test]
    fn stake_ops_fold_uniformly_on_a_convicted_pool() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        let epoch = state.current_epoch;
        convict_pool(&mut state, pool_id, epoch);
        assert!(state.pools[&pool_id].conviction.is_some());
        let total = state.pools[&pool_id].total_stake;

        apply_witness_chunk(
            &mut state,
            0,
            vec![
                ShardWitnessPayload::StakeDeposit {
                    pool_id,
                    amount: MIN_STAKE_FLOOR,
                },
                ShardWitnessPayload::StakeWithdraw {
                    pool_id,
                    amount: MIN_STAKE_FLOOR,
                },
            ],
        );

        let pool = &state.pools[&pool_id];
        assert_eq!(pool.total_stake, total.saturating_add(MIN_STAKE_FLOOR));
        assert_eq!(pool.pending_withdrawals.len(), 1);
    }

    /// Happy path: a `RegisterValidator` for an unknown id with a pool
    /// that has capacity adds the validator at `Pooled` with
    /// `registered_at_epoch = state.current_epoch`, and the pool's
    /// validator set includes the new id.
    #[test]
    fn register_validator_happy_path() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(2);
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());

        let new_id = ValidatorId::new(5);
        let new_pubkey = pubkey(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: new_pubkey,
                possession_proof: possession_proof(5, new_id),
            }],
        );

        assert_eq!(effects.registered, vec![new_id]);
        let rec = state.validators.get(&new_id).unwrap();
        assert_eq!(rec.pool, pool_id);
        assert_eq!(rec.status, ValidatorStatus::Pooled);
        assert_eq!(rec.registered_at_epoch, state.current_epoch);
        assert_eq!(rec.pubkey, new_pubkey);
        assert!(state.pools[&pool_id].validators.contains(&new_id));
    }

    /// A registration for an already-known id is silently dropped — no
    /// state change, no effect. The id-is-dead-forever policy.
    #[test]
    fn register_validator_duplicate_id_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());

        let existing_id = ValidatorId::new(0);
        let prior = state.validators.get(&existing_id).unwrap().clone();

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: existing_id,
                pubkey: pubkey(99),
                possession_proof: possession_proof(99, existing_id),
            }],
        );

        assert!(effects.registered.is_empty());
        assert_eq!(state.validators.get(&existing_id).unwrap(), &prior);
    }

    /// A registration that would push the pool over `max_active_count` at
    /// the current dynamic `min_stake` is silently dropped, but consumed.
    #[test]
    fn register_validator_rejected_when_pool_lacks_capacity() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(5),
                pubkey: pubkey(5),
                possession_proof: possession_proof(5, ValidatorId::new(5)),
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&ValidatorId::new(5)));
        assert_eq!(applied_count(&state, 0), 1);
    }

    /// A registration whose proof-of-possession does not verify —
    /// here a proof signed by a different key than the one registered —
    /// is silently dropped, but consumed (the watermark advances).
    #[test]
    fn register_validator_rejected_on_wrong_key_pop() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());

        let new_id = ValidatorId::new(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: pubkey(5),
                possession_proof: possession_proof(6, new_id),
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&new_id));
        assert_eq!(applied_count(&state, 0), 1);
    }

    /// A proof-of-possession bound to a different `ValidatorId` — a
    /// captured proof replayed under a new identity — does not verify.
    #[test]
    fn register_validator_rejected_on_replayed_pop() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());

        let new_id = ValidatorId::new(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: pubkey(5),
                possession_proof: possession_proof(5, ValidatorId::new(6)),
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&new_id));
    }

    /// A zeroed (malformed) proof-of-possession is rejected outright.
    #[test]
    fn register_validator_rejected_on_malformed_pop() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());

        let new_id = ValidatorId::new(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: pubkey(5),
                possession_proof: ConsensusSignature::ZERO,
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&new_id));
    }

    /// `DeactivateValidator` from `OnShard` flips status to
    /// `InsufficientStake` AND cascades: shard committee loses the
    /// validator, `pool_draw` refills from any remaining pooled.
    #[test]
    fn deactivate_validator_on_shard_cascades() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(0),
            }],
        );

        assert_eq!(effects.deactivated, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// A pool speaks only about its own validators.
    ///
    /// The witness names the pool that emitted it, stamped by the shard
    /// from the emitting instance rather than taken from a payload, so a
    /// contract cannot claim another pool's. What it can do is name
    /// someone else's validator — and that is refused here, because the
    /// shard that emitted has no view of who operates whom and this does.
    #[test]
    fn an_operator_action_naming_another_pools_validator_is_a_no_op() {
        let mut state = single_pool_state(4);
        let stranger = StakePoolId::new(1);
        state.pools.insert(
            stranger,
            StakePool {
                id: stranger,
                total_stake: Stake::from_quanta(MIN_STAKE_FLOOR.quanta()),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );

        // Every field but the pool matches the deactivation that works.
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: stranger,
                validator_id: ValidatorId::new(0),
            }],
        );
        assert!(effects.deactivated.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));

        // And an unjail the same way: the cooldown has elapsed and the
        // only thing wrong is who is asking.
        let since = Epoch::new(1);
        let mut jailed = state_with_jailed(since, JailReason::Performance);
        jailed.pools.insert(
            stranger,
            StakePool {
                id: stranger,
                total_stake: Stake::from_quanta(MIN_STAKE_FLOOR.quanta()),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        jailed.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS);
        let effects = apply_witness_chunk(
            &mut jailed,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: stranger,
                id: ValidatorId::new(10),
            }],
        );
        assert!(effects.unjailed.is_empty());
        assert!(matches!(
            jailed.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed { .. },
        ));
    }

    /// `DeactivateValidator` from `Pooled` flips status; no cascade.
    #[test]
    fn deactivate_validator_pooled_flips_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(5));

        let pre_members = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(5),
            }],
        );

        assert_eq!(effects.deactivated, vec![ValidatorId::new(5)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        assert_eq!(
            state.next_shard_committees[&ShardId::leaf(1, 0)].members,
            pre_members,
        );
    }

    /// `DeactivateValidator` against an already-`InsufficientStake` or a
    /// `Revoked` validator is a silent no-op.
    #[test]
    fn deactivate_validator_no_op_for_insufficient_or_equivocation() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::InsufficientStake),
        );
        state.validators.insert(
            ValidatorId::new(11),
            validator_record(
                11,
                0,
                ValidatorStatus::Revoked {
                    at_epoch: Epoch::GENESIS,
                },
            ),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![
                ShardWitnessPayload::DeactivateValidator {
                    pool_id: StakePoolId::new(0),
                    validator_id: ValidatorId::new(10),
                },
                ShardWitnessPayload::DeactivateValidator {
                    pool_id: StakePoolId::new(0),
                    validator_id: ValidatorId::new(11),
                },
            ],
        );

        assert!(effects.deactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(11)).unwrap().status,
            ValidatorStatus::Revoked {
                at_epoch: Epoch::GENESIS
            },
        );
    }

    /// `DeactivateValidator` against a fault-cause `Jailed` validator IS
    /// allowed (operator retires a jailed node).
    #[test]
    fn deactivate_validator_allowed_for_fault_cause_jailed() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(10),
            }],
        );

        assert_eq!(effects.deactivated, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    // ─── Unjail ──────────────────────────────────────────────────────────

    fn state_with_jailed(since_epoch: Epoch, reason: JailReason) -> BeaconState {
        let mut state = single_pool_state(3);
        state.committee = (0u64..3).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(10));
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch,
                    reason,
                },
            ),
        );
        state
    }

    /// Unjail after cooldown with pool capacity transitions to `Pooled`.
    #[test]
    fn unjail_after_cooldown_returns_to_pooled() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(10),
            }],
        );

        assert_eq!(effects.unjailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// Unjail before cooldown elapses is a silent no-op.
    #[test]
    fn unjail_before_cooldown_is_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS - 2);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(10),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Performance,
            },
        );
    }

    /// A state seating `ready` `OnShard{ready}` validators (ids
    /// `0..ready`) plus a validator (`jailed_id`) jailed under `reason`
    /// since `since`. `ready / beacon_committee_size` is the recency
    /// period the withholding cooldown reads.
    fn state_with_ready_and_jailed(
        ready: u64,
        jailed_id: u64,
        since: Epoch,
        reason: JailReason,
    ) -> BeaconState {
        let mut state = single_pool_state(1);
        let shard = ShardId::leaf(1, 0);
        let pool_id = StakePoolId::new(0);
        let mut members = Vec::new();
        for i in 0..ready {
            let id = ValidatorId::new(i);
            members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.next_shard_committees.insert(
            shard,
            ShardCommittee {
                members: members.clone(),
            },
        );
        state
            .shard_committees
            .insert(shard, ShardCommittee { members });
        state.validators.insert(
            ValidatorId::new(jailed_id),
            validator_record(
                jailed_id,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: since,
                    reason,
                },
            ),
        );
        let pool = state.pools.get_mut(&pool_id).unwrap();
        pool.validators = (0..ready)
            .chain(std::iter::once(jailed_id))
            .map(ValidatorId::new)
            .collect();
        pool.total_stake = Stake::from_quanta(u128::from(ready + 1) * MIN_STAKE_FLOOR.quanta());
        state
    }

    /// A withholding jail is held for the recency period, longer than the
    /// short performance cooldown: at a beacon size where `eligible/b`
    /// exceeds `JAIL_COOLDOWN_EPOCHS`, an unjail attempted at the
    /// performance cooldown — where a performance jail would lift — is
    /// refused, so a jailed grinder cannot return while its resample
    /// weight would still suppress it. Recovery once the full period
    /// elapses is covered by `async_absence_jail_is_recoverable_after_cooldown`;
    /// the performance-cooldown lift by `unjail_after_cooldown_returns_to_pooled`.
    #[test]
    fn withholding_jail_outlasts_the_performance_cooldown() {
        let since = Epoch::new(5);
        // 68 ready / b=4 → recency period 17, one past JAIL_COOLDOWN_EPOCHS.
        let mut state = state_with_ready_and_jailed(68, 500, since, JailReason::Withholding);
        let period = state.beacon_recency_period();
        assert!(
            period > JAIL_COOLDOWN_EPOCHS,
            "fixture must make the recency period exceed the performance cooldown: \
             period={period}, jail_cooldown={JAIL_COOLDOWN_EPOCHS}",
        );

        // `apply_witness_chunk` folds at `current_epoch + 1`, so the gate
        // evaluates at the performance-cooldown boundary here — where a
        // performance jail lifts. The refusal is decided at the cooldown
        // check, before any pool-capacity gate.
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS - 1);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(500),
            }],
        );
        assert!(
            effects.unjailed.is_empty(),
            "a withholding jail must not lift at the short performance cooldown",
        );
        assert!(matches!(
            state.validators.get(&ValidatorId::new(500)).unwrap().status,
            ValidatorStatus::Jailed {
                reason: JailReason::Withholding,
                ..
            },
        ));
    }

    /// A revoked validator never unjails — it isn't `Jailed`, so the
    /// lift falls through regardless of how much time has passed.
    #[test]
    fn unjail_of_revoked_validator_is_a_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        state
            .validators
            .get_mut(&ValidatorId::new(10))
            .unwrap()
            .status = ValidatorStatus::Revoked { at_epoch: since };
        state.current_epoch = Epoch::new(since.inner() + 10 * JAIL_COOLDOWN_EPOCHS);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(10),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Revoked { at_epoch: since },
        );
    }

    /// Unjail rejected when the pool can't support one more active epoch.
    #[test]
    fn unjail_rejected_when_pool_at_capacity() {
        let since = Epoch::new(5);
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS);
        let pool_id = StakePoolId::new(0);
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(10));
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: since,
                    reason: JailReason::Performance,
                },
            ),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(10),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Performance,
            },
        );
    }

    /// Unjail against a non-jailed validator is a silent no-op.
    #[test]
    fn unjail_of_non_jailed_validator_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(0),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    // ─── Ready ───────────────────────────────────────────────────────────

    /// Ready on `OnShard { ready: false }` flips to `ready: true`.
    #[test]
    fn ready_flips_on_shard_false_to_true() {
        let mut state = single_pool_state(0);
        state.committee = Vec::new();
        let shard = ShardId::leaf(1, 0);
        let placed = Epoch::new(3);
        let pool_id = StakePoolId::new(0);
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: [ValidatorId::new(0), ValidatorId::new(1)]
                    .into_iter()
                    .collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(1),
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: placed,
                },
            ),
        );
        state.committee = vec![ValidatorId::new(0)];
        state.next_shard_committees.insert(
            shard,
            ShardCommittee {
                members: vec![ValidatorId::new(0), ValidatorId::new(1)],
            },
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Ready {
                id: ValidatorId::new(1),
            }],
        );

        assert_eq!(effects.readied, vec![ValidatorId::new(1)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch: placed,
            },
        );
    }

    /// Ready on an already-ready validator is a silent no-op.
    #[test]
    fn ready_on_already_ready_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pre = state.validators.get(&ValidatorId::new(0)).unwrap().clone();

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Ready {
                id: ValidatorId::new(0),
            }],
        );

        assert!(effects.readied.is_empty());
        assert_eq!(state.validators.get(&ValidatorId::new(0)).unwrap(), &pre);
    }

    /// Ready against a `Pooled` validator is a silent no-op.
    #[test]
    fn ready_on_pooled_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Ready {
                id: ValidatorId::new(5),
            }],
        );

        assert!(effects.readied.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    // ─── MissedProposal ──────────────────────────────────────────────────

    fn missed_payload(proposer_id: ValidatorId) -> ShardWitnessPayload {
        ShardWitnessPayload::MissedProposal {
            proposer_id,
            height: BlockHeight::GENESIS,
            round: Round::INITIAL,
        }
    }

    /// A `MissedProposal` from shard S against a validator currently
    /// `OnShard { shard: S, .. }` increments their miss counter. Below
    /// threshold, no jail effect.
    #[test]
    fn missed_proposal_increments_counter_for_on_shard_proposer() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        let effects = apply_witness_chunk(&mut state, 0, vec![missed_payload(target)]);

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&1));
        assert!(matches!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    /// A `MissedProposal` from shard B against a validator currently on
    /// shard A is silently dropped.
    #[test]
    fn missed_proposal_from_wrong_shard_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(10);
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(target);
        state.validators.insert(
            target,
            validator_record(
                10,
                0,
                ValidatorStatus::OnShard {
                    shard: ShardId::leaf(1, 1),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.next_shard_committees.insert(
            ShardId::leaf(1, 1),
            ShardCommittee {
                members: vec![target],
            },
        );

        // Witness emitted by shard 0, targeting a validator on shard 1.
        let effects = apply_witness_chunk(&mut state, 0, vec![missed_payload(target)]);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// A `MissedProposal` against a validator not currently `OnShard` is
    /// silently dropped.
    #[test]
    fn missed_proposal_against_non_on_shard_validator_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(10);
        state
            .validators
            .insert(target, validator_record(10, 0, ValidatorStatus::Pooled));

        let effects = apply_witness_chunk(&mut state, 0, vec![missed_payload(target)]);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// Multiple `MissedProposal`s in a single chunk accumulate.
    #[test]
    fn multiple_missed_proposals_in_one_slot_accumulate() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![
                missed_payload(target),
                missed_payload(target),
                missed_payload(target),
            ],
        );

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&3));
    }

    /// Crossing `MISSED_PROPOSAL_JAIL_THRESHOLD` jails the validator under
    /// `Performance`, cascades the committee removal + `pool_draw` refill,
    /// and clears the miss counter.
    #[test]
    fn missed_proposal_at_threshold_jails_and_clears_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let target = ValidatorId::new(1);
        state
            .miss_counters
            .insert(target, MISSED_PROPOSAL_JAIL_THRESHOLD - 1);

        let effects = apply_witness_chunk(&mut state, 0, vec![missed_payload(target)]);

        assert_eq!(effects.jailed, vec![target]);
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        assert!(!state.miss_counters.contains_key(&target));
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// A miss that crosses the threshold while the proposer's shard sits
    /// past the halt threshold counts but does not jail: the misses
    /// arrive through the halted shard's drained witness backlog, and
    /// jailing on them exits custody holders the halt recovery needs.
    /// The counter keeps the observation; a jail lands only on evidence
    /// folded after the shard crosses again.
    #[test]
    fn missed_proposal_threshold_defers_jail_while_shard_misses_crossings() {
        use hyperscale_types::{
            BeaconWitnessLeafCount, BlockHash, BlockHeight, DeclaredWork, HALT_THRESHOLD_EPOCHS,
            ShardBoundary, StateRoot, WeightedTimestamp,
        };

        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let shard = ShardId::leaf(1, 0);
        state.boundaries.insert(
            shard,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"frozen")),
                height: BlockHeight::new(5),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                attested_work: 0,
                used: DeclaredWork::ZERO,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits") + 1,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );

        let target = ValidatorId::new(1);
        state
            .miss_counters
            .insert(target, MISSED_PROPOSAL_JAIL_THRESHOLD - 1);

        let effects = apply_witness_chunk(&mut state, 0, vec![missed_payload(target)]);

        assert!(
            effects.jailed.is_empty(),
            "a halted shard's member must not be jailed on drained misses",
        );
        assert!(matches!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
        assert_eq!(
            state.miss_counters.get(&target),
            Some(&MISSED_PROPOSAL_JAIL_THRESHOLD),
            "the observation still counts; only the jail defers",
        );
    }

    // ─── Shard double-vote pairs (gossip-fed proposal lane) ─────────────
    // The shard-witness path, distinct from the PC-ballot equivocation
    // tests below (which drive `ingest_equivocations` via a proposal).

    /// Move `id` into its own single-validator pool so a conviction's
    /// cascade stops at its own seat — the shape that keeps the other
    /// fixtures' members observable as unaffected bystanders.
    fn isolate_in_own_pool(state: &mut BeaconState, id: ValidatorId, pool_no: u32) {
        let pool_id = StakePoolId::new(pool_no);
        for pool in state.pools.values_mut() {
            pool.validators.remove(&id);
        }
        state.validators.get_mut(&id).unwrap().pool = pool_id;
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: MIN_STAKE_FLOOR,
                validators: std::iter::once(id).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
    }

    /// Two genuine, conflicting votes by `equivocator` at one `(height,
    /// round)`, assembled into the self-proving evidence a shard proposer
    /// carries. Each signature is real, so the leaf verifies against the
    /// signer's key — the block-validity soundness the shard QC attests.
    fn genuine_equivocation(equivocator: u64) -> ShardVoteEquivocation {
        let sk = keypair(equivocator);
        let shard = ShardId::leaf(1, 0);
        let (height, round) = (BlockHeight::new(5), Round::new(2));
        let voter = ValidatorId::new(equivocator);
        let sign = |blk: &[u8], parent: &[u8]| {
            let block_hash = BlockHash::from_raw(Hash::from_bytes(blk));
            let parent_hash = BlockHash::from_raw(Hash::from_bytes(parent));
            let vote = BlockVote::new(
                &net(),
                block_hash,
                parent_hash,
                shard,
                height,
                round,
                voter,
                &sk,
                ProposerTimestamp::ZERO,
            )
            .expect("sign");
            (block_hash, parent_hash, vote.signature())
        };
        let (block_hash_a, parent_block_hash_a, sig_a) = sign(b"equiv-block-a", b"equiv-parent-a");
        let (block_hash_b, parent_block_hash_b, sig_b) = sign(b"equiv-block-b", b"equiv-parent-b");
        ShardVoteEquivocation {
            validator: voter,
            shard,
            height,
            round,
            block_hash_a,
            parent_block_hash_a,
            sig_a,
            block_hash_b,
            parent_block_hash_b,
            sig_b,
        }
    }

    /// VRF jail cascade also clears the miss counter.
    #[test]
    fn vrf_jail_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.miss_counters.insert(ValidatorId::new(0), 7);

        let committed = vec![(
            ValidatorId::new(0),
            malformed_vrf_proposal(0, state.current_epoch.next()),
        )];
        apply_next_epoch(&mut state, &committed);

        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    /// `DeactivateValidator` cascade also clears the miss counter.
    #[test]
    fn deactivate_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.miss_counters.insert(ValidatorId::new(0), 5);

        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(0),
            }],
        );

        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    // ─── Equivocation witnesses ──────────────────────────────────────────

    use hyperscale_types::{
        PcRound, PcScope, PcValueElement, PcVector, PcVoteEquivocation, PcVoteMessage, PcVoteRound,
        SpcView,
    };

    fn build_vote_equivocation(
        equivocator: u64,
        epoch: Epoch,
        view: SpcView,
    ) -> PcVoteEquivocation {
        let sk = keypair(equivocator);
        let instance = PcScope { epoch, view };
        let value_a = PcVector::new([PcValueElement::new([0xAA; 32])]);
        let value_b = PcVector::new([PcValueElement::new([0xBB; 32])]);
        let msg_a = signed_bytes(
            &PcVoteMessage {
                round: PcRound::Vote1,
                scope: instance,
                vector: value_a.clone(),
            },
            &net(),
        );
        let msg_b = signed_bytes(
            &PcVoteMessage {
                round: PcRound::Vote1,
                scope: instance,
                vector: value_b.clone(),
            },
            &net(),
        );
        PcVoteEquivocation {
            validator: ValidatorId::new(equivocator),
            epoch,
            view,
            round: PcVoteRound::Vote1,
            value_a,
            sig_a: sk.sign(&msg_a).expect("sign"),
            value_b,
            sig_b: sk.sign(&msg_b).expect("sign"),
        }
    }

    fn vote_equivocation_witness(
        equivocator: u64,
        epoch: Epoch,
        view: SpcView,
    ) -> PcVoteEquivocation {
        build_vote_equivocation(equivocator, epoch, view)
    }

    /// Verified PC vote equivocation against an `OnShard` validator
    /// convicts its pool and cascades the committee removal + refill.
    #[test]
    fn vote_equivocation_convicts_on_shard_validator_with_cascade() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_quanta(5 * MIN_STAKE_FLOOR.quanta());
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .insert(ValidatorId::new(4));
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(4, 0, ValidatorStatus::Pooled),
        );

        let target = ValidatorId::new(1);
        isolate_in_own_pool(&mut state, target, 9);
        let w = vote_equivocation_witness(target.inner(), Epoch::new(5), SpcView::new(0));
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, target_epoch, vec![w]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.revoked, vec![target]);
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Revoked {
                at_epoch: state.current_epoch
            },
        );
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// Verified equivocation against a `Pooled` validator revokes it in
    /// place; no committee is touched.
    #[test]
    fn vote_equivocation_revokes_pooled_validator_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::Pooled),
        );
        isolate_in_own_pool(&mut state, ValidatorId::new(10), 9);

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, target_epoch, vec![w]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.revoked, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Revoked {
                at_epoch: state.current_epoch
            },
        );
    }

    /// Equivocation promotes a fault-cause `Jailed{Performance}` to a
    /// permanent revocation.
    #[test]
    fn vote_equivocation_promotes_performance_jail_to_revocation() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );
        isolate_in_own_pool(&mut state, ValidatorId::new(10), 9);

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, target_epoch, vec![w]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.revoked, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Revoked {
                at_epoch: state.current_epoch
            },
        );
    }

    /// Equivocation against an already-`Revoked` validator is a silent
    /// no-op.
    #[test]
    fn vote_equivocation_against_already_equivocation_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let prior_epoch = Epoch::new(2);
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(
                10,
                0,
                ValidatorStatus::Revoked {
                    at_epoch: prior_epoch,
                },
            ),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let target_epoch = state.current_epoch.next();
        let mut committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, target_epoch, vec![w]),
        )];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target_epoch))));
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Revoked {
                at_epoch: prior_epoch
            },
        );
    }

    // ─── reshape trigger admission ───────────────────────────────────────

    /// A state with the given shards as active trie leaves and `pooled`
    /// validators free in the global pool, with a small committee
    /// target so the pool gate is exercisable.
    fn reshape_state(active: &[ShardId], pooled: u64) -> BeaconState {
        let mut state = single_pool_state(0);
        state.current_epoch = Epoch::new(5);
        state.chain_config.shard_size = 4;
        for shard in active {
            state
                .shard_committees
                .insert(*shard, ShardCommittee::default());
        }
        for i in 0..pooled {
            let id = 1000 + i;
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        state
    }

    fn split_payload(shard: ShardId) -> ShardWitnessPayload {
        ShardWitnessPayload::ScheduleSplit {
            shard,
            epoch: Epoch::GENESIS,
        }
    }

    /// Admission records the pending split when the target is an active
    /// leaf and the pool can staff a full observer cohort — and draws
    /// the cohort on the spot: each drawn validator flips to
    /// `Observing`, joins the target's lookahead committee, and gets a
    /// seat split evenly across the two children.
    #[test]
    fn split_admission_draws_the_observer_cohort() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));

        let Some(PendingReshape::Split {
            last_asserted,
            admitted_at,
            cohort,
            ..
        }) = state.pending_reshapes.get(&p)
        else {
            panic!("split not recorded");
        };
        assert_eq!(*last_asserted, Epoch::new(5));
        assert_eq!(*admitted_at, Epoch::new(5));
        assert_eq!(cohort.len(), 4);

        // The pool drained into Observing placements carried on the
        // target's lookahead committee, none ready yet.
        assert!(state.pooled_validators().is_empty());
        let members = &state.next_shard_committees[&p].members;
        let (left, right) = p.children();
        let mut seats_per_child = (0usize, 0usize);
        for (id, seat) in cohort {
            assert!(members.contains(id));
            assert!(!seat.ready);
            assert_eq!(
                state.validators[id].status,
                ValidatorStatus::Observing {
                    shard: p,
                    placed_at_epoch: Epoch::new(5),
                },
            );
            if seat.child == left {
                seats_per_child.0 += 1;
            } else {
                assert_eq!(seat.child, right);
                seats_per_child.1 += 1;
            }
        }
        assert_eq!(seats_per_child, (2, 2));
    }

    /// Two replicas with byte-identical state draw byte-identical
    /// cohorts — the draw is seeded from the frozen `cohort_seed` and
    /// shard under a reshape-specific domain tag.
    #[test]
    fn cohort_draw_is_deterministic_across_replicas() {
        let p = ShardId::leaf(1, 0);
        let mut a = reshape_state(&[p], 8);
        let mut b = reshape_state(&[p], 8);
        apply_shard_payload(&BlsVerifier, &mut a, &net(), p, &split_payload(p));
        apply_shard_payload(&BlsVerifier, &mut b, &net(), p, &split_payload(p));
        assert_eq!(a.pending_reshapes, b.pending_reshapes);
        assert_eq!(a.next_shard_committees, b.next_shard_committees);
        assert_eq!(a.pooled_validators(), b.pooled_validators());
    }

    /// A `ReshapeReady` witness from the splitting shard marks the
    /// observer's seat; one from any other shard, or naming a validator
    /// without a seat, is silently dropped. Re-marking is idempotent.
    #[test]
    fn reshape_ready_marks_only_a_held_seat() {
        let p = ShardId::leaf(1, 0);
        let elsewhere = ShardId::leaf(1, 1);
        let mut state = reshape_state(&[p, elsewhere], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        let observer = *cohort_of(&state, p).keys().next().unwrap();
        let observer_child = cohort_of(&state, p)[&observer].child;
        let ready = |v: ValidatorId| ShardWitnessPayload::ReshapeReady {
            validator: v,
            child: observer_child,
        };

        // Wrong source shard: no seat marked.
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            elsewhere,
            &ready(observer),
        );
        assert!(!cohort_of(&state, p)[&observer].ready);

        // No seat held: dropped.
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ready(ValidatorId::new(9_999)),
        );

        // The shard's own chain marks the seat; re-marking holds.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &ready(observer));
        assert!(cohort_of(&state, p)[&observer].ready);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &ready(observer));
        assert!(cohort_of(&state, p)[&observer].ready);
        let ready_count = cohort_of(&state, p).values().filter(|s| s.ready).count();
        assert_eq!(ready_count, 1);
    }

    /// The observer cohort never enters the consensus subset: the
    /// ready-filtered members of the splitting shard are exactly its
    /// `OnShard` members, before and after admission, so the shard's
    /// quorum stays at target size for the whole grow.
    #[test]
    fn observers_join_the_committee_but_not_the_consensus_subset() {
        let p = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        state.current_epoch = Epoch::new(5);
        state.chain_config.shard_size = 4;
        state.shard_committees = state.next_shard_committees.clone();
        for i in 0..4u64 {
            let id = 1000 + i;
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        let consensus_before = state.ready_consensus_members(&state.next_shard_committees);

        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));

        assert_eq!(state.next_shard_committees[&p].members.len(), 8);
        assert_eq!(
            state.ready_consensus_members(&state.next_shard_committees),
            consensus_before,
        );
    }

    /// A jailed or deactivated observer sheds its cohort seat and its
    /// committee slot without a refill draw — attrition is absorbed by
    /// the execution gate, the staleness cancel, or the readiness TTL.
    #[test]
    fn observer_attrition_drops_the_seat_without_refill() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        let victim = *cohort_of(&state, p).keys().next().unwrap();

        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(0),
                validator_id: victim,
            },
        );

        assert_eq!(
            state.validators[&victim].status,
            ValidatorStatus::InsufficientStake,
        );
        assert!(!cohort_of(&state, p).contains_key(&victim));
        assert_eq!(cohort_of(&state, p).len(), 3);
        assert!(!state.next_shard_committees[&p].members.contains(&victim));
        assert_eq!(state.next_shard_committees[&p].members.len(), 3);
    }

    /// The cohort seats of `state`'s pending split of `target`.
    fn cohort_of(state: &BeaconState, target: ShardId) -> &BTreeMap<ValidatorId, CohortSeat> {
        let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
            panic!("no pending split for {target:?}");
        };
        cohort
    }

    /// The pool gate refuses what it can't staff; admission resumes
    /// once the pool refills (re-assertion is automatic shard-side).
    #[test]
    fn split_rejected_until_pool_can_staff() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 3);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());

        state.validators.insert(
            ValidatorId::new(2000),
            validator_record(2000, 0, ValidatorStatus::Pooled),
        );
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        assert!(state.pending_reshapes.contains_key(&p));
    }

    /// Only the shard itself may assert its split, and only a child may
    /// assert the merge under its parent.
    #[test]
    fn reshape_triggers_are_source_pinned() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let mut state = reshape_state(&[p, sibling], 4);

        apply_shard_payload(&BlsVerifier, &mut state, &net(), sibling, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());

        // A merge under ROOT asserted by a non-child source.
        let stranger = ShardId::leaf(2, 0b11);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            stranger,
            &ShardWitnessPayload::ScheduleMerge {
                parent: ShardId::ROOT,
                epoch: Epoch::GENESIS,
            },
        );
        assert!(state.pending_reshapes.is_empty());
    }

    /// A split target that isn't an active trie leaf is dropped.
    #[test]
    fn split_rejected_on_inactive_target() {
        let p = ShardId::leaf(1, 0);
        let elsewhere = ShardId::leaf(1, 1);
        let mut state = reshape_state(&[elsewhere], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());
    }

    /// Re-assertion refreshes the staleness clock; silence for
    /// `RESHAPE_TRIGGER_TTL_EPOCHS` *lapses* the split — the cohort
    /// returns to the pool but the record (and its seed) is kept — and a
    /// later re-assertion re-staffs the identical cohort from that seed.
    #[test]
    fn silence_lapses_a_split_and_reassertion_restaffs_it_identically() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        let original = cohort_of(&state, p).clone();
        assert_eq!(original.len(), 4);

        // Quiet epochs inside the trigger bound survive untouched.
        state.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS - 1);
        prune_stale_reshapes(&mut state);
        assert_eq!(cohort_of(&state, p), &original);

        // Reaching the trigger TTL (still inside the readiness TTL)
        // lapses: the cohort returns to the pool, the record stays with
        // an empty cohort retaining its seed, and `admitted_at` is
        // unchanged so the readiness TTL keeps counting from first admit.
        state.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS);
        prune_stale_reshapes(&mut state);
        let Some(PendingReshape::Split {
            cohort,
            admitted_at,
            ..
        }) = state.pending_reshapes.get(&p)
        else {
            panic!("a lapsed split keeps its record");
        };
        assert!(cohort.is_empty(), "the lapse empties the cohort");
        assert_eq!(*admitted_at, Epoch::new(5));
        assert_eq!(state.pooled_validators().len(), 4);
        assert!(state.next_shard_committees[&p].members.is_empty());

        // A re-assertion re-staffs the same cohort: the draw seeds on the
        // frozen `cohort_seed` over the now-refilled pool, so an
        // observer's synced child never moves under it.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        assert_eq!(cohort_of(&state, p), &original);
        assert!(state.pooled_validators().is_empty());
    }

    /// A lapsed split that is never re-asserted is removed at the
    /// readiness TTL — bounding how long its frozen seed lives — so a
    /// split admitted later snapshots current randomness afresh rather
    /// than resurrecting the removed split's seed.
    #[test]
    fn readiness_ttl_removes_a_lapsed_split_and_a_later_split_reseeds() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));

        // Trigger silence lapses it, then quiet through the readiness TTL
        // removes the lapsed record outright.
        state.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS);
        prune_stale_reshapes(&mut state);
        assert!(
            cohort_of(&state, p).is_empty(),
            "trigger silence lapses the split"
        );
        state.current_epoch = Epoch::new(5 + RESHAPE_READY_TTL_EPOCHS);
        prune_stale_reshapes(&mut state);
        assert!(
            state.pending_reshapes.is_empty(),
            "the readiness TTL removes a lapsed split",
        );
        assert_eq!(state.pooled_validators().len(), 4);

        // A later split snapshots the current randomness — proof the seed
        // is freshly drawn, not carried over from the removed record.
        state.randomness = Randomness::new([7u8; 32]);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        let Some(PendingReshape::Split { cohort_seed, .. }) = state.pending_reshapes.get(&p) else {
            panic!("re-admitted split not recorded");
        };
        assert_eq!(*cohort_seed, Randomness::new([7u8; 32]));
    }

    /// A split whose gate never fires is abandoned once
    /// `RESHAPE_READY_TTL_EPOCHS` pass after admission, even while the
    /// trigger keeps re-asserting; the cohort returns to the pool.
    #[test]
    fn stalled_split_abandons_at_the_readiness_ttl() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));

        for epoch in 6..(5 + RESHAPE_READY_TTL_EPOCHS) {
            state.current_epoch = Epoch::new(epoch);
            apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
            prune_stale_reshapes(&mut state);
            assert!(
                state.pending_reshapes.contains_key(&p),
                "abandoned early at epoch {epoch}",
            );
        }
        state.current_epoch = Epoch::new(5 + RESHAPE_READY_TTL_EPOCHS);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.is_empty());
        assert_eq!(state.pooled_validators().len(), 4);
        assert!(state.next_shard_committees[&p].members.is_empty());
    }

    /// Skip epochs fold no witnesses, so deferring the TTL anchors across
    /// each one holds both clocks fixed: a split admitted just before a
    /// long beacon stall survives the sweep, then ages normally once real
    /// epochs resume.
    #[test]
    fn skip_epochs_defer_the_reshape_ttls() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), p, &split_payload(p));

        // Stall past the readiness TTL purely on skips; each defers the
        // anchors, so the split is intact when the sweep resumes.
        let stall = RESHAPE_READY_TTL_EPOCHS + 2;
        for _ in 0..stall {
            state.current_epoch = state.current_epoch.next();
            defer_reshape_ttls(&mut state);
        }
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));

        // Real quiet epochs without a re-assertion age the trigger TTL
        // from where the stall left it and lapse the split as usual.
        for _ in 0..RESHAPE_TRIGGER_TTL_EPOCHS {
            state.current_epoch = state.current_epoch.next();
        }
        prune_stale_reshapes(&mut state);
        assert!(
            state.pending_reshapes.contains_key(&p),
            "a lapse keeps the record"
        );
        assert!(
            cohort_of(&state, p).is_empty(),
            "the lapse empties the cohort"
        );
        assert_eq!(state.pooled_validators().len(), 4);
    }

    /// Merge halves pair across the two children; a lone half expires
    /// after the TTL.
    #[test]
    fn merge_halves_pair_and_a_lone_half_expires() {
        let (left, right) = ShardId::ROOT.children();
        let mut state = reshape_state(&[left, right], 0);
        let payload = ShardWitnessPayload::ScheduleMerge {
            parent: ShardId::ROOT,
            epoch: Epoch::GENESIS,
        };

        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &payload);
        let Some(PendingReshape::Merge {
            halves,
            admitted_at,
            ..
        }) = state.pending_reshapes.get(&ShardId::ROOT)
        else {
            panic!("merge half not recorded");
        };
        assert_eq!(halves.len(), 1);
        assert!(admitted_at.is_none(), "a lone half has not paired");

        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &payload);
        let Some(PendingReshape::Merge {
            halves,
            admitted_at,
            ..
        }) = state.pending_reshapes.get(&ShardId::ROOT)
        else {
            panic!("merge record dropped");
        };
        assert_eq!(halves.len(), 2);
        assert!(admitted_at.is_some(), "both halves pair the merge");

        // A fresh lone half goes quiet and expires.
        let mut lone = reshape_state(&[left, right], 0);
        apply_shard_payload(&BlsVerifier, &mut lone, &net(), left, &payload);
        lone.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS);
        prune_stale_reshapes(&mut lone);
        assert!(lone.pending_reshapes.is_empty());
    }

    /// A merge requires both children active; a child already pending a
    /// split blocks the merge (no overlapping reshapes), and vice versa.
    #[test]
    fn overlapping_reshapes_are_rejected() {
        let (left, right) = ShardId::ROOT.children();
        let merge = ShardWitnessPayload::ScheduleMerge {
            parent: ShardId::ROOT,
            epoch: Epoch::GENESIS,
        };

        // Only one child active: merge dropped.
        let mut state = reshape_state(&[left], 0);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        assert!(state.pending_reshapes.is_empty());

        // Pending split on a child blocks the merge.
        let mut state = reshape_state(&[left, right], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &split_payload(left));
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        assert!(matches!(
            state.pending_reshapes.get(&left),
            Some(PendingReshape::Split { .. }),
        ));
        assert!(!state.pending_reshapes.contains_key(&ShardId::ROOT));

        // Pending merge blocks a child's split.
        let mut state = reshape_state(&[left, right], 4);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            right,
            &split_payload(right),
        );
        assert!(!state.pending_reshapes.contains_key(&right));
    }

    /// Splits stop at the shard ceiling, counting splits already
    /// admitted but not yet executed.
    #[test]
    fn split_rejected_at_max_shards() {
        let depth = 12u32; // 2^12 == MAX_SHARDS
        let shards: Vec<ShardId> = (0..MAX_SHARDS as u64)
            .map(|path| ShardId::leaf(depth, path))
            .collect();
        let mut state = reshape_state(&shards, 8);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            shards[0],
            &split_payload(shards[0]),
        );
        assert!(state.pending_reshapes.is_empty());
    }

    /// The publish fact registers only from the shard that owns the
    /// publisher's prefix, and first registration wins.
    #[test]
    fn a_publish_fact_registers_once_from_the_owning_shard() {
        let owner = ShardId::leaf(1, 0);
        let foreign = ShardId::leaf(1, 1);
        let mut state = reshape_state(&[owner, foreign], 4);
        // Top bit 0 puts the publisher under leaf(1, 0).
        let publisher = Address::new([0x00; 31], AddressClass::Principal);
        let package = Hash::from_hash_bytes(&[0x44; 32]);
        let fact = ShardWitnessPayload::PackagePublished { package, publisher };

        // A shard that does not own the prefix registers nothing.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), foreign, &fact);
        assert!(state.packages.is_empty());

        apply_shard_payload(&BlsVerifier, &mut state, &net(), owner, &fact);
        assert_eq!(state.packages[&package].publisher, publisher);

        // Re-registration restates the content address: first wins.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), owner, &fact);
        assert_eq!(state.packages.len(), 1);
    }
}
