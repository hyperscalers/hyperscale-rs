//! Witness ingestion: dedup, watermark gating, per-payload dispatch,
//! and equivocation re-verification.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHeader, JAIL_COOLDOWN_EPOCHS, JailReason, MAX_SHARDS,
    MISSED_PROPOSAL_JAIL_THRESHOLD, NetworkDefinition, PendingReshape, PendingWithdrawal,
    RESHAPE_TRIGGER_TTL_EPOCHS, ShardId, ShardWitness, ShardWitnessPayload, Stake, StakePool,
    ValidatorId, ValidatorRecord, ValidatorStatus, verify_vote_equivocation,
};

use crate::rules;
use crate::state::vrf::jail_validator;
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
    pub(super) unjailed: Vec<ValidatorId>,
    pub(super) readied: Vec<ValidatorId>,
}

impl WitnessOutcome {
    /// Route a per-witness validator-status event into the matching list.
    fn record(&mut self, event: ShardEvent) {
        match event {
            ShardEvent::Registered(id) => self.registered.push(id),
            ShardEvent::Deactivated(id) => self.deactivated.push(id),
            ShardEvent::Jailed(id) => self.jailed.push(id),
            ShardEvent::Unjailed(id) => self.unjailed.push(id),
            ShardEvent::Readied(id) => self.readied.push(id),
        }
    }

    /// Merge another outcome's lists into this one.
    pub(super) fn extend(&mut self, other: Self) {
        self.registered.extend(other.registered);
        self.deactivated.extend(other.deactivated);
        self.jailed.extend(other.jailed);
        self.unjailed.extend(other.unjailed);
        self.readied.extend(other.readied);
    }
}

/// Validator-status effect of one shard-lift application.
///
/// `StakeDeposit` and `StakeWithdraw` payloads mutate pool state but
/// produce no validator-level event (caller sees `None`).
#[derive(Clone, Copy)]
pub(super) enum ShardEvent {
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
/// the validator is `Jailed { Equivocation }`. Each entry re-verifies
/// against the registry unless it carries a `Verified` marker upgraded at
/// the admission gate, so apply stays fail-closed on the gossip path
/// (which decodes `Unverified`). Committed evidence is threshold-vouched:
/// a 2f+1 commit implies ≥ f+1 honest verifiers behind every entry.
pub(super) fn ingest_equivocations(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    accepted: &[&(ValidatorId, BeaconProposal)],
) -> WitnessOutcome {
    let mut outcome = WitnessOutcome::default();
    for (_, prop) in accepted {
        for ev in prop.equivocations().iter() {
            let evidence = ev.as_unverified();
            let validator_id = evidence.validator;
            let Some(rec) = state.validators.get(&validator_id) else {
                continue;
            };
            if ev.verified().is_none()
                && verify_vote_equivocation(evidence, network, &[(validator_id, rec.pubkey)])
                    .is_err()
            {
                continue;
            }
            // Equivocation supersedes every status except an existing
            // permanent equivocation jail. The race-exit defence covers
            // `InsufficientStake` (operator tried to escape via
            // `DeactivateValidator`) and fault-cause `Jailed` (the
            // existing jail is upgraded to permanent).
            let already_permanent = matches!(
                rec.status,
                ValidatorStatus::Jailed {
                    reason: JailReason::Equivocation,
                    ..
                }
            );
            if already_permanent {
                continue;
            }
            jail_validator(
                state,
                validator_id,
                JailReason::Equivocation,
                state.current_epoch,
            );
            outcome.jailed.push(validator_id);
        }
    }
    outcome
}

/// Validate and apply one shard's boundary-contribution witness chunk.
///
/// `witnesses` must be exactly the contiguous, ascending 0-based leaf
/// range `[prior, chunk_end)`, each merkle-proving into
/// `boundary_header.beacon_witness_root()`. Returns `false` **without
/// mutating `state`** if the chunk is the wrong length, has a gap, or any
/// proof fails — the caller treats the shard as not refreshed. On success
/// every payload applies in leaf-index order via [`apply_shard_payload`],
/// its validator-level event recorded into `outcome`. Validation runs to
/// completion before any application, so a malformed chunk never
/// half-applies.
pub(super) fn apply_contribution_witnesses(
    state: &mut BeaconState,
    boundary_header: &BlockHeader,
    witnesses: &[ShardWitness],
    prior: u64,
    chunk_end: u64,
    outcome: &mut WitnessOutcome,
) -> bool {
    if !rules::contribution_chunk_valid(boundary_header, witnesses, prior, chunk_end) {
        return false;
    }
    for witness in witnesses {
        if let Some(event) = apply_shard_payload(state, witness.proof.shard_id, &witness.payload) {
            outcome.record(event);
        }
    }
    true
}

/// Dispatch a single shard-witness payload to its handler.
///
/// `StakeDeposit` and `StakeWithdraw` mutate pool state without
/// producing a validator-level event — they return `None`. Variants
/// that change validator status return the corresponding
/// [`ShardEvent`] for [`apply_contribution_witnesses`] to route into
/// [`WitnessOutcome`].
///
/// `source_shard` is the shard that emitted the witness (carried in
/// the wrapping [`ShardWitnessProof`](hyperscale_types::ShardWitnessProof)).
/// Most variants ignore it; `MissedProposal` uses it to scope the
/// miss-counter increment to the witness's source committee — a
/// `MissedProposal` from shard S only counts against validators
/// currently `OnShard { shard: S, .. }`.
#[allow(clippy::too_many_lines)] // single dispatch over ShardWitnessPayload variants
pub(super) fn apply_shard_payload(
    state: &mut BeaconState,
    source_shard: ShardId,
    payload: &ShardWitnessPayload,
) -> Option<ShardEvent> {
    match payload {
        ShardWitnessPayload::StakeDeposit { pool_id, amount } => {
            // Implicit pool creation on first deposit; subsequent
            // deposits accumulate into `total_stake`.
            let pool = state.pools.entry(*pool_id).or_insert_with(|| StakePool {
                id: *pool_id,
                total_stake: Stake::ZERO,
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
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
        } => {
            // Re-registration policy: once a `ValidatorRecord` exists
            // for `validator_id`, no second `RegisterValidator` for
            // that id ever takes effect. The id is dead for the
            // lifetime of the chain.
            if state.validators.contains_key(validator_id) {
                return None;
            }
            // Pool must exist and have capacity at the current dynamic
            // `min_stake` for one more active validator.
            let pool = state.pools.get(pool_id)?;
            if pool.current_active_count(state) + 1 > pool.max_active_count(state) {
                return None;
            }
            // We accept any 48-byte BLS pubkey at registration. Radix's
            // `Bls12381G1PublicKey` doesn't validate G1 membership at
            // construction and exposes no public validator, so
            // registration cannot eagerly reject a malformed key. A
            // malformed key just fails every signature verification it
            // touches; the validator never signs successfully and gets
            // jailed via the miss-counter, costing at most one stalled
            // epoch per malformed registration.
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
            Some(ShardEvent::Registered(*validator_id))
        }
        ShardWitnessPayload::DeactivateValidator { validator_id } => {
            // Operator-initiated retirement. Flips to
            // `InsufficientStake` from every status except those that
            // already represent "not consuming an epoch" or "permanently
            // out": `InsufficientStake` itself and
            // `Jailed { Equivocation }`. Fault-cause jails
            // (`Performance`) can still be deactivated — the operator
            // chooses to retire a jailed validator rather than wait
            // out the cooldown.
            let rec = state.validators.get(validator_id)?;
            let should_deactivate = !matches!(
                rec.status,
                ValidatorStatus::InsufficientStake
                    | ValidatorStatus::Jailed {
                        reason: JailReason::Equivocation,
                        ..
                    }
            );
            if !should_deactivate {
                return None;
            }
            deactivate_to_insufficient_stake(state, *validator_id);
            Some(ShardEvent::Deactivated(*validator_id))
        }
        ShardWitnessPayload::Unjail { id } => {
            // Fault-cause jails return to `Pooled` once cooldown has
            // elapsed AND the pool can still support the additional
            // active epoch at the current dynamic `min_stake`. A pool
            // that over-committed while the validator was jailed
            // strands them — operator recourse is to deactivate
            // another validator or deposit more stake before lifting.
            // Equivocation jails are permanent regardless.
            let rec = state.validators.get(id)?;
            let ValidatorStatus::Jailed {
                since_epoch,
                reason,
            } = rec.status
            else {
                return None;
            };
            if reason == JailReason::Equivocation {
                return None;
            }
            if state.current_epoch.inner()
                < since_epoch.inner().saturating_add(JAIL_COOLDOWN_EPOCHS)
            {
                return None;
            }
            let pool_id = rec.pool;
            let pool = state.pools.get(&pool_id)?;
            if pool.current_active_count(state) + 1 > pool.max_active_count(state) {
                return None;
            }
            state
                .validators
                .get_mut(id)
                .expect("rec read above guarantees presence")
                .status = ValidatorStatus::Pooled;
            Some(ShardEvent::Unjailed(*id))
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
                Some(ShardEvent::Readied(*id))
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
            Some(ShardEvent::Jailed(*proposer_id))
        }
        ShardWitnessPayload::ScheduleSplit { shard } => {
            // Source pinning: only the shard itself asserts its split.
            if source_shard != *shard {
                return None;
            }
            // Re-assertion of an in-flight split refreshes the
            // staleness clock and nothing else.
            if let Some(PendingReshape::Split { last_asserted }) =
                state.pending_reshapes.get_mut(shard)
            {
                *last_asserted = state.current_epoch;
                return None;
            }
            // The target must be an active trie leaf, free of any
            // overlapping reshape.
            if !state.shard_committees.contains_key(shard) || state.reshape_involves(*shard) {
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
            state.pending_reshapes.insert(
                *shard,
                PendingReshape::Split {
                    last_asserted: state.current_epoch,
                },
            );
            None
        }
        ShardWitnessPayload::ScheduleMerge { parent } => {
            // Source pinning: only a child asserts the merge under its
            // parent.
            if source_shard.parent() != Some(*parent) {
                return None;
            }
            // Both children must be active trie leaves.
            let (left, right) = parent.children();
            if !state.shard_committees.contains_key(&left)
                || !state.shard_committees.contains_key(&right)
            {
                return None;
            }
            // Record or refresh this child's half. The merge pairs —
            // becomes schedulable — once both children hold a live
            // half; a lone half expires via the staleness sweep.
            if let Some(PendingReshape::Merge { halves }) = state.pending_reshapes.get_mut(parent) {
                halves.insert(source_shard, state.current_epoch);
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
                },
            );
            None
        }
    }
}

/// Cancel pending reshapes whose triggers went quiet.
///
/// Triggers re-derive once per witness window while the load condition
/// holds, so every live assertion refreshes each epoch. A split whose
/// target stopped asserting (it drained below the threshold), or a
/// merge half whose child stopped (it regrew), drops once the silence
/// reaches [`RESHAPE_TRIGGER_TTL_EPOCHS`]; a merge record with no live
/// halves left drops entirely. Runs after the epoch's witnesses apply,
/// so an assertion folded this epoch is never swept.
pub(super) fn prune_stale_reshapes(state: &mut BeaconState) {
    let current = state.current_epoch.inner();
    state.pending_reshapes.retain(|target, reshape| {
        let keep = match reshape {
            PendingReshape::Split { last_asserted } => {
                current.saturating_sub(last_asserted.inner()) < RESHAPE_TRIGGER_TTL_EPOCHS
            }
            PendingReshape::Merge { halves } => {
                halves.retain(|_, last| {
                    current.saturating_sub(last.inner()) < RESHAPE_TRIGGER_TTL_EPOCHS
                });
                !halves.is_empty()
            }
        };
        if !keep {
            tracing::info!(?target, "Pending reshape cancelled — trigger went quiet");
        }
        keep
    });
}

#[cfg(test)]
mod tests {

    // ─── witness fold framework + stake variants ─────────────────────────
    use hyperscale_types::{
        BlockHeight, EMISSIONS_PER_EPOCH, Epoch, JAIL_COOLDOWN_EPOCHS, JailReason, MAX_SHARDS,
        MIN_STAKE_FLOOR, MISSED_PROPOSAL_JAIL_THRESHOLD, PendingReshape, Round, ShardCommittee,
        ShardId, ShardWitnessPayload, Stake, StakePool, StakePoolId, ValidatorId, ValidatorStatus,
    };

    use super::*;
    use crate::rules::contribution_chunk_valid;
    use crate::state::test_fixtures::{
        applied_count, apply_next_epoch, apply_witness_chunk, boundary_chunk, keypair,
        malformed_vrf_proposal, net, pubkey, single_pool_state, validator_record,
        vrf_proposal_with_equivocations,
    };

    fn deposit(pool: u32, amount: u64) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(pool),
            amount: Stake::from_whole_tokens(amount),
        }
    }

    /// `contribution_chunk_valid` accepts exactly the contiguous,
    /// ascending chunk that merkle-proves into the boundary root, and
    /// rejects every malformed shape — short, over-count, gapped,
    /// reordered, or proven against the wrong root. This is the fold-side
    /// (`apply_contribution_witnesses`) defence that mirrors the
    /// `contributions_well_formed` gate; both share this predicate, so a
    /// gap/short/over/wrong-root chunk can never half-apply.
    #[test]
    fn contribution_chunk_valid_rejects_malformed_chunks() {
        let (header, witnesses) =
            boundary_chunk(0, 0, vec![deposit(7, 1), deposit(7, 2), deposit(7, 3)]);

        // The exact chunk `[0, 3)` — accepted.
        assert!(contribution_chunk_valid(&header, &witnesses, 0, 3));

        // Short: two witnesses for a three-leaf range.
        assert!(!contribution_chunk_valid(&header, &witnesses[..2], 0, 3));

        // Over-count: three witnesses for a two-leaf range.
        assert!(!contribution_chunk_valid(&header, &witnesses, 0, 2));

        // Gapped: leaves 0 and 2 where the range expects 0 and 1.
        let gapped = vec![witnesses[0].clone(), witnesses[2].clone()];
        assert!(!contribution_chunk_valid(&header, &gapped, 0, 2));

        // Reordered: descending leaf indices.
        let mut reordered = witnesses.clone();
        reordered.reverse();
        assert!(!contribution_chunk_valid(&header, &reordered, 0, 3));

        // Wrong root: the same chunk proven against a different boundary
        // block (distinct payloads → distinct accumulator root).
        let (other, _) = boundary_chunk(0, 0, vec![deposit(9, 1), deposit(9, 2), deposit(9, 3)]);
        assert!(!contribution_chunk_valid(&other, &witnesses, 0, 3));
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
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let new_id = ValidatorId::new(5);
        let new_pubkey = pubkey(5);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: new_pubkey,
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
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let existing_id = ValidatorId::new(0);
        let prior = state.validators.get(&existing_id).unwrap().clone();

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: existing_id,
                pubkey: pubkey(99),
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
            }],
        );

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&ValidatorId::new(5)));
        assert_eq!(applied_count(&state, 0), 1);
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

    /// `DeactivateValidator` against an already-`InsufficientStake` or an
    /// already-permanent `Jailed { Equivocation }` validator is a silent
    /// no-op.
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
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Equivocation,
                },
            ),
        );

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(10),
                },
                ShardWitnessPayload::DeactivateValidator {
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
            ValidatorStatus::Jailed {
                since_epoch: Epoch::GENESIS,
                reason: JailReason::Equivocation,
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
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos());
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

    /// Equivocation jails never unjail, even past the cooldown.
    #[test]
    fn unjail_of_equivocation_jail_is_permanent_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Equivocation);
        state.current_epoch = Epoch::new(since.inner() + 10 * JAIL_COOLDOWN_EPOCHS);

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            }],
        );

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Equivocation,
            },
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
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
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
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
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
                validator_id: ValidatorId::new(0),
            }],
        );

        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    // ─── Equivocation witnesses ──────────────────────────────────────────

    use hyperscale_types::{
        DOMAIN_PC_VOTE1, PcValueElement, PcVector, PcVoteEquivocation, PcVoteRound, SpcView,
        pc_context, pc_vote_signing_message, spc_context,
    };

    fn build_vote_equivocation(
        equivocator: u64,
        epoch: Epoch,
        view: SpcView,
    ) -> PcVoteEquivocation {
        let sk = keypair(equivocator);
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, view);
        let value_a = PcVector::new([PcValueElement::new([0xAA; 32])]);
        let value_b = PcVector::new([PcValueElement::new([0xBB; 32])]);
        let msg_a = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE1, &pc_ctx, &value_a);
        let msg_b = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE1, &pc_ctx, &value_b);
        PcVoteEquivocation {
            validator: ValidatorId::new(equivocator),
            epoch,
            view,
            round: PcVoteRound::Vote1,
            value_a,
            sig_a: sk.sign_v1(&msg_a),
            value_b,
            sig_b: sk.sign_v1(&msg_b),
        }
    }

    fn vote_equivocation_witness(
        equivocator: u64,
        epoch: Epoch,
        view: SpcView,
    ) -> PcVoteEquivocation {
        build_vote_equivocation(equivocator, epoch, view)
    }

    /// Verified PC vote equivocation against an `OnShard` validator jails
    /// permanently under `Equivocation` and cascades.
    #[test]
    fn vote_equivocation_jails_on_shard_validator_with_cascade() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());
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
        let w = vote_equivocation_witness(target.inner(), Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![target]);
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// Verified equivocation against a `Pooled` validator flips status to
    /// permanent `Jailed { Equivocation }`; no cascade.
    #[test]
    fn vote_equivocation_jails_pooled_validator_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::Pooled),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Equivocation promotes a fault-cause `Jailed{Performance}` to
    /// permanent `Jailed{Equivocation}`.
    #[test]
    fn vote_equivocation_promotes_performance_jail_to_equivocation() {
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

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Equivocation against an already-permanent `Jailed{Equivocation}` is
    /// a silent no-op.
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
                ValidatorStatus::Jailed {
                    since_epoch: prior_epoch,
                    reason: JailReason::Equivocation,
                },
            ),
        );

        let w = vote_equivocation_witness(10, Epoch::new(5), SpcView::new(0));
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_equivocations(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: prior_epoch,
                reason: JailReason::Equivocation,
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
        ShardWitnessPayload::ScheduleSplit { shard }
    }

    /// Admission records the pending split when the target is an active
    /// leaf and the pool can staff a full observer cohort.
    #[test]
    fn split_admission_records_pending_when_pool_can_staff() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&mut state, p, &split_payload(p));
        assert_eq!(
            state.pending_reshapes.get(&p),
            Some(&PendingReshape::Split {
                last_asserted: Epoch::new(5),
            }),
        );
    }

    /// The pool gate refuses what it can't staff; admission resumes
    /// once the pool refills (re-assertion is automatic shard-side).
    #[test]
    fn split_rejected_until_pool_can_staff() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 3);
        apply_shard_payload(&mut state, p, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());

        state.validators.insert(
            ValidatorId::new(2000),
            validator_record(2000, 0, ValidatorStatus::Pooled),
        );
        apply_shard_payload(&mut state, p, &split_payload(p));
        assert!(state.pending_reshapes.contains_key(&p));
    }

    /// Only the shard itself may assert its split, and only a child may
    /// assert the merge under its parent.
    #[test]
    fn reshape_triggers_are_source_pinned() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let mut state = reshape_state(&[p, sibling], 4);

        apply_shard_payload(&mut state, sibling, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());

        // A merge under ROOT asserted by a non-child source.
        let stranger = ShardId::leaf(2, 0b11);
        apply_shard_payload(
            &mut state,
            stranger,
            &ShardWitnessPayload::ScheduleMerge {
                parent: ShardId::ROOT,
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
        apply_shard_payload(&mut state, p, &split_payload(p));
        assert!(state.pending_reshapes.is_empty());
    }

    /// Re-assertion refreshes the staleness clock; silence for
    /// `RESHAPE_TRIGGER_TTL_EPOCHS` cancels the pending reshape.
    #[test]
    fn split_reassertion_refreshes_and_silence_cancels() {
        let p = ShardId::leaf(1, 0);
        let mut state = reshape_state(&[p], 4);
        apply_shard_payload(&mut state, p, &split_payload(p));

        state.current_epoch = Epoch::new(6);
        apply_shard_payload(&mut state, p, &split_payload(p));
        assert_eq!(
            state.pending_reshapes.get(&p),
            Some(&PendingReshape::Split {
                last_asserted: Epoch::new(6),
            }),
        );

        // One quiet epoch survives the sweep; the second cancels.
        state.current_epoch = Epoch::new(7);
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));
        state.current_epoch = Epoch::new(8);
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.is_empty());
    }

    /// Merge halves pair across the two children; a lone half expires
    /// after the TTL.
    #[test]
    fn merge_halves_pair_and_a_lone_half_expires() {
        let (left, right) = ShardId::ROOT.children();
        let mut state = reshape_state(&[left, right], 0);
        let payload = ShardWitnessPayload::ScheduleMerge {
            parent: ShardId::ROOT,
        };

        apply_shard_payload(&mut state, left, &payload);
        let Some(PendingReshape::Merge { halves }) = state.pending_reshapes.get(&ShardId::ROOT)
        else {
            panic!("merge half not recorded");
        };
        assert_eq!(halves.len(), 1);

        apply_shard_payload(&mut state, right, &payload);
        let Some(PendingReshape::Merge { halves }) = state.pending_reshapes.get(&ShardId::ROOT)
        else {
            panic!("merge record dropped");
        };
        assert_eq!(halves.len(), 2);

        // A fresh lone half goes quiet and expires.
        let mut lone = reshape_state(&[left, right], 0);
        apply_shard_payload(&mut lone, left, &payload);
        lone.current_epoch = Epoch::new(7);
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
        };

        // Only one child active: merge dropped.
        let mut state = reshape_state(&[left], 0);
        apply_shard_payload(&mut state, left, &merge);
        assert!(state.pending_reshapes.is_empty());

        // Pending split on a child blocks the merge.
        let mut state = reshape_state(&[left, right], 4);
        apply_shard_payload(&mut state, left, &split_payload(left));
        apply_shard_payload(&mut state, right, &merge);
        assert!(matches!(
            state.pending_reshapes.get(&left),
            Some(PendingReshape::Split { .. }),
        ));
        assert!(!state.pending_reshapes.contains_key(&ShardId::ROOT));

        // Pending merge blocks a child's split.
        let mut state = reshape_state(&[left, right], 4);
        apply_shard_payload(&mut state, left, &merge);
        apply_shard_payload(&mut state, right, &split_payload(right));
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
        apply_shard_payload(&mut state, shards[0], &split_payload(shards[0]));
        assert!(state.pending_reshapes.is_empty());
    }
}
