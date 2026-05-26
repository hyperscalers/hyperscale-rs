//! Witness ingestion: dedup, watermark gating, per-payload dispatch,
//! and equivocation re-verification.

use std::collections::BTreeSet;

use hyperscale_types::{
    BeaconProposal, BeaconState, BeaconWitness, Bls12381G1PublicKey, EquivocationEvidence,
    JailReason, LeafIndex, NetworkDefinition, PendingWithdrawal, ShardGroupId, ShardWitness,
    ShardWitnessPayload, Stake, StakePool, ValidatorId, ValidatorRecord, ValidatorStatus, Witness,
};

use crate::constants::{
    JAIL_COOLDOWN_EPOCHS, MAX_WITNESSES_PER_SLOT, MISSED_PROPOSAL_JAIL_THRESHOLD,
};
use crate::pc::verify_vote_equivocation;
use crate::recovery::verify_recovery_equivocation;
use crate::state::derived::{current_active_count, effective_stake, max_active_count};
use crate::state::vrf::jail_validator;
use crate::state::withdrawals::deactivate_to_insufficient_stake;

/// Outcome of [`ingest_witnesses`].
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

/// Validator-status effect of one shard-lift application.
///
/// `StakeDeposit` and `StakeWithdraw` payloads mutate pool state but
/// produce no validator-level event (caller sees `None`).
#[allow(dead_code)] // not every variant is constructed by the apply_shard_payload arms in place
pub(super) enum ShardEvent {
    Registered(ValidatorId),
    Deactivated(ValidatorId),
    Jailed(ValidatorId),
    Unjailed(ValidatorId),
    Readied(ValidatorId),
}

/// Collect, dedup, and apply the witnesses ridden by `accepted`
/// proposals.
///
/// Shard lifts pass the per-shard `consumed_through` watermark — only
/// `watermark + 1` is admitted, gaps and already-consumed leaves are
/// silently dropped. The watermark advances on apply (regardless of
/// whether the variant produced a validator-level event), so an
/// honest committee can re-include a missing leaf next epoch once the
/// gap is filled.
///
/// `Witness::Beacon::Equivocation` variants are collected alongside
/// shard lifts and re-verified before applying. No dedup is needed —
/// re-application is idempotent once the validator is `Jailed {
/// Equivocation }`.
///
/// # Defense-in-depth caps
///
/// The wire decoder already bounds proposals at
/// [`MAX_WITNESSES_PER_PROPOSER`](hyperscale_types::MAX_WITNESSES_PER_PROPOSER)
/// via [`BeaconProposal`]'s `BoundedVec`. The epoch-level cap
/// [`MAX_WITNESSES_PER_SLOT`] is the product
/// `BEACON_SIGNER_COUNT × MAX_WITNESSES_PER_PROPOSER`, which the wire
/// bounds already imply for a well-formed committee. The check here
/// exists as defence in depth: if the committee size ever grows
/// without the epoch cap being re-derived, the epoch cap bounds
/// aggregate witness work regardless.
pub(super) fn ingest_witnesses(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    accepted: &[&(ValidatorId, BeaconProposal)],
) -> WitnessOutcome {
    // Collect Shard witnesses with within-epoch dedup keyed by
    // `(shard_id, leaf_index)` — the unique identity of a witness in
    // its source shard's accumulator. `ShardWitnessProof` isn't `Ord`
    // (it's a wire type), so we key the dedup set on the tuple
    // directly. Beacon witnesses collect without dedup; their jail
    // gate ("not already permanently jailed") provides the idempotence.
    let mut shard_seen: BTreeSet<(ShardGroupId, LeafIndex)> = BTreeSet::new();
    let mut shard_lifts: Vec<&ShardWitness> = Vec::new();
    let mut equivocations: Vec<&BeaconWitness> = Vec::new();
    'collect: for (_, prop) in accepted {
        for w in prop.witnesses().iter() {
            if shard_lifts.len() + equivocations.len() >= MAX_WITNESSES_PER_SLOT {
                break 'collect;
            }
            match w {
                Witness::Shard(sw) => {
                    if !shard_seen.insert((sw.proof.shard_id, sw.proof.leaf_index)) {
                        continue;
                    }
                    shard_lifts.push(sw);
                }
                Witness::Beacon(bw) => {
                    equivocations.push(bw);
                }
            }
        }
    }

    let mut outcome = WitnessOutcome::default();

    // Apply shard lifts in `(shard_id, leaf_index)` order, gated by
    // the per-shard watermark. Watermark advances on apply regardless
    // of whether the variant produced a validator-level event, so a
    // no-op variant (e.g. stake adjustment) doesn't stall the shard's
    // accumulator.
    shard_lifts.sort_by_key(|sw| (sw.proof.shard_id, sw.proof.leaf_index));
    for sw in shard_lifts {
        let watermark = state
            .consumed_through
            .get(&sw.proof.shard_id)
            .copied()
            .unwrap_or(LeafIndex::new(0));
        if sw.proof.leaf_index.inner() != watermark.inner() + 1 {
            continue;
        }
        match apply_shard_payload(state, sw.proof.shard_id, &sw.payload) {
            Some(ShardEvent::Registered(id)) => outcome.registered.push(id),
            Some(ShardEvent::Deactivated(id)) => outcome.deactivated.push(id),
            Some(ShardEvent::Jailed(id)) => outcome.jailed.push(id),
            Some(ShardEvent::Unjailed(id)) => outcome.unjailed.push(id),
            Some(ShardEvent::Readied(id)) => outcome.readied.push(id),
            None => {}
        }
        state
            .consumed_through
            .insert(sw.proof.shard_id, sw.proof.leaf_index);
    }

    // Apply equivocations. Each is re-verified independently before
    // jailing; permanent-Equivocation already-jailed validators are
    // the no-op idempotence case. The validator-id→pubkey lookup is
    // built once per epoch, only when at least one equivocation is
    // present (most slots carry none).
    if !equivocations.is_empty() {
        let lookup: Vec<(ValidatorId, Bls12381G1PublicKey)> = state
            .validators
            .iter()
            .map(|(id, rec)| (*id, rec.pubkey))
            .collect();
        for bw in equivocations {
            let BeaconWitness::Equivocation { evidence } = bw;
            if !verify_equivocation_evidence(evidence, network, &lookup) {
                continue;
            }
            let validator_id = evidence.validator();
            let Some(rec) = state.validators.get(&validator_id) else {
                continue;
            };
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

/// Re-validate an [`EquivocationEvidence`] under the current
/// validator-set pubkey lookup. `Vote` re-runs the PC double-sign
/// check; `Recovery` re-runs the recovery-request / finalized-block
/// double-attestation check.
pub(super) fn verify_equivocation_evidence(
    evidence: &EquivocationEvidence,
    network: &NetworkDefinition,
    lookup: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match evidence {
        EquivocationEvidence::Vote(v) => verify_vote_equivocation(v, network, lookup),
        EquivocationEvidence::Recovery(r) => verify_recovery_equivocation(r, network, lookup),
    }
}

/// Dispatch a single shard-witness payload to its handler.
///
/// `StakeDeposit` and `StakeWithdraw` mutate pool state without
/// producing a validator-level event — they return `None`. Variants
/// that change validator status return the corresponding
/// [`ShardEvent`] for [`ingest_witnesses`] to route into
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
    source_shard: ShardGroupId,
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
            if *amount > effective_stake(pool) {
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
            if current_active_count(pool, state) + 1 > max_active_count(pool, state) {
                return None;
            }
            // We accept any 48-byte BLS pubkey at registration. Radix's
            // `Bls12381G1PublicKey` doesn't validate G1 membership at
            // construction and exposes no public validator, so the
            // prototype's eager-reject path isn't available here. A
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
            // already represent "not consuming a epoch" or "permanently
            // out": `InsufficientStake` itself and
            // `Jailed { Equivocation }`. Fault-cause jails
            // (`Performance`, `Recovery`) can still be deactivated —
            // the operator chooses to retire a jailed validator rather
            // than wait out the cooldown.
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
            if state.current_epoch.inner() < since_epoch.inner() + JAIL_COOLDOWN_EPOCHS {
                return None;
            }
            let pool_id = rec.pool;
            let pool = state.pools.get(&pool_id)?;
            if current_active_count(pool, state) + 1 > max_active_count(pool, state) {
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
    }
}
