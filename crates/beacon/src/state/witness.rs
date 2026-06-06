//! Witness ingestion: dedup, watermark gating, per-payload dispatch,
//! and equivocation re-verification.

use std::collections::BTreeSet;

use hyperscale_types::{
    BeaconProposal, BeaconState, JAIL_COOLDOWN_EPOCHS, JailReason, LeafIndex,
    MISSED_PROPOSAL_JAIL_THRESHOLD, NetworkDefinition, PcVoteEquivocation, PendingWithdrawal,
    ShardId, ShardWitness, ShardWitnessPayload, Stake, StakePool, ValidatorId, ValidatorRecord,
    ValidatorStatus, Verifiable, verify_vote_equivocation,
};

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
/// The wire decoder bounds each proposal at
/// [`MAX_WITNESSES_PER_PROPOSER`](hyperscale_types::MAX_WITNESSES_PER_PROPOSER)
/// via [`BeaconProposal`]'s `BoundedVec`, and the committee size caps
/// proposers per slot. The aggregate is the product, with no
/// additional runtime cap — the wire bound is the authoritative limit.
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
    let mut shard_seen: BTreeSet<(ShardId, LeafIndex)> = BTreeSet::new();
    let mut shard_lifts: Vec<&ShardWitness> = Vec::new();
    let mut equivocations: Vec<&Verifiable<PcVoteEquivocation>> = Vec::new();
    for (_, prop) in accepted {
        for sw in prop.shard_witnesses().iter() {
            let sw = sw.as_unverified();
            if !shard_seen.insert((sw.proof.shard_id, sw.proof.leaf_index)) {
                continue;
            }
            shard_lifts.push(sw);
        }
        for ev in prop.equivocations().iter() {
            equivocations.push(ev);
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
        if sw.proof.leaf_index.inner() != watermark.inner().saturating_add(1) {
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

    if !equivocations.is_empty() {
        // Committed equivocation evidence is threshold-vouched: an honest
        // node only votes for a proposal whose witnesses it verified, so a
        // 2f+1 commit implies ≥ f+1 honest verifiers behind every entry.
        // Trust a carried `Verified` marker (upgraded at the admission
        // gate); re-verify against the registry when it's absent — the
        // gossip path decodes witnesses `Unverified` — so apply stays
        // fail-closed in release, not just under a debug assert.
        for ev in equivocations {
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
    }
}

#[cfg(test)]
mod tests {

    // ─── ingest_witnesses framework + stake variants ─────────────────────
    use hyperscale_types::{
        BeaconProposal, BeaconState, EMISSIONS_PER_EPOCH, Epoch, JAIL_COOLDOWN_EPOCHS, JailReason,
        LeafIndex, MIN_STAKE_FLOOR, MISSED_PROPOSAL_JAIL_THRESHOLD, ShardCommittee, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId, ValidatorId, ValidatorStatus,
    };

    use super::super::test_fixtures::{
        apply_next_epoch, keypair, malformed_vrf_proposal, net, pubkey, shard_witness,
        single_pool_state, validator_record, vrf_proposal_with_equivocations,
        vrf_proposal_with_witnesses,
    };
    use super::*;

    /// `StakeDeposit` for an unknown pool implicitly creates the pool
    /// and accumulates `total_stake`. Subsequent deposits accumulate
    /// further.
    #[test]
    fn stake_deposit_creates_pool_implicitly_and_accumulates() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool 7 doesn't exist yet — first StakeDeposit creates it.
        let w0 = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(100),
            },
        );
        // Second deposit on the same pool accumulates.
        let w1 = shard_witness(
            0,
            2,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(50),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w0, w1]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(150));
        // Watermark advanced to 2 for shard 0.
        assert_eq!(
            state.consumed_through.get(&ShardId::leaf(1, 0)),
            Some(&LeafIndex::new(2))
        );
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: Stake::from_whole_tokens(1_000),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&pool_id).unwrap();
        // StakeWithdraw doesn't touch total_stake; the epoch's emission
        // credit (single ready pool collects the full share) accounts
        // for the only delta.
        assert_eq!(
            pool.total_stake,
            pre_total.saturating_add(EMISSIONS_PER_EPOCH)
        );
        // pending_withdrawals records the request at current_epoch.
        assert_eq!(pool.pending_withdrawals.len(), 1);
        assert_eq!(
            pool.pending_withdrawals[0].amount,
            Stake::from_whole_tokens(1_000)
        );
        assert_eq!(
            pool.pending_withdrawals[0].initiated_at_epoch,
            state.current_epoch
        );
        // effective_stake = total_stake − pending; pending up by 1000
        // whole tokens, total up by the epoch emission.
        assert_eq!(
            pool.effective_stake(),
            pre_effective
                .saturating_add(EMISSIONS_PER_EPOCH)
                .saturating_sub(Stake::from_whole_tokens(1_000)),
        );
    }

    /// Defense-in-depth: an over-withdrawal (`amount > effective_stake`)
    /// is rejected outright — no `pending_withdrawals` entry added.
    /// Without this, `saturating_sub` in `effective_stake` would
    /// silently clamp accounting to zero.
    #[test]
    fn stake_withdraw_rejects_over_effective_stake() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        let effective = state.pools.get(&pool_id).unwrap().effective_stake();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::StakeWithdraw {
                pool_id,
                amount: effective.saturating_add(Stake::from_whole_tokens(1)),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&pool_id).unwrap();
        assert!(pool.pending_withdrawals.is_empty());
        // Watermark still advances on apply (the witness was consumed,
        // even though the variant rejected it).
        assert_eq!(
            state.consumed_through.get(&ShardId::leaf(1, 0)),
            Some(&LeafIndex::new(1))
        );
    }

    /// Within-epoch dedup: the same `(shard_id, leaf_index)` carried by
    /// multiple proposers counts as one event.
    #[test]
    fn witness_dedup_by_shard_and_leaf_index() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Same deposit witness submitted by three proposers — should
        // apply exactly once.
        let payload = ShardWitnessPayload::StakeDeposit {
            pool_id: StakePoolId::new(7),
            amount: Stake::from_whole_tokens(100),
        };
        let committed: Vec<(ValidatorId, BeaconProposal)> = (0u64..3)
            .map(|i| {
                (
                    ValidatorId::new(i),
                    vrf_proposal_with_witnesses(
                        i,
                        Epoch::new(1),
                        vec![shard_witness(0, 1, payload.clone())],
                    ),
                )
            })
            .collect();
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        // Only one deposit applied — total_stake reflects a single 100.
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(100));
    }

    /// Watermark gate: a witness with `leaf_index != consumed + 1` is
    /// silently dropped. Gaps and re-plays don't apply.
    #[test]
    fn watermark_gate_drops_gap_and_replay() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-set the watermark to 5; submit a witness for leaf_index 7
        // (gap) and another for leaf_index 5 (replay). Neither applies.
        state
            .consumed_through
            .insert(ShardId::leaf(1, 0), LeafIndex::new(5));

        let gap = shard_witness(
            0,
            7,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(7),
                amount: Stake::from_whole_tokens(1),
            },
        );
        let replay = shard_witness(
            0,
            5,
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(8),
                amount: Stake::from_whole_tokens(1),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![gap, replay]),
        )];
        apply_next_epoch(&mut state, &committed);

        // Neither pool was touched.
        assert!(!state.pools.contains_key(&StakePoolId::new(7)));
        assert!(!state.pools.contains_key(&StakePoolId::new(8)));
        // Watermark unchanged.
        assert_eq!(
            state.consumed_through.get(&ShardId::leaf(1, 0)),
            Some(&LeafIndex::new(5))
        );
    }

    /// In-order application: a sequence of consecutive `leaf_index` from
    /// the same shard, even when submitted out of order in the
    /// proposal, applies in order and advances the watermark by all.
    #[test]
    fn witnesses_applied_in_leaf_index_order() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Three deposits at indices 1, 2, 3 to pool 7, submitted in
        // reverse order in the proposal.
        let ws = vec![
            shard_witness(
                0,
                3,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(3),
                },
            ),
            shard_witness(
                0,
                1,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(1),
                },
            ),
            shard_witness(
                0,
                2,
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(7),
                    amount: Stake::from_whole_tokens(2),
                },
            ),
        ];
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        apply_next_epoch(&mut state, &committed);

        let pool = state.pools.get(&StakePoolId::new(7)).unwrap();
        assert_eq!(pool.total_stake, Stake::from_whole_tokens(6));
        assert_eq!(
            state.consumed_through.get(&ShardId::leaf(1, 0)),
            Some(&LeafIndex::new(3))
        );
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
        // Bump pool 0's stake to cover one more at floor.
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let new_id = ValidatorId::new(5);
        let new_pubkey = pubkey(5);
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: new_id,
                pubkey: new_pubkey,
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.registered, vec![new_id]);
        let rec = state.validators.get(&new_id).unwrap();
        assert_eq!(rec.pool, pool_id);
        assert_eq!(rec.status, ValidatorStatus::Pooled);
        assert_eq!(rec.registered_at_epoch, state.current_epoch);
        assert_eq!(rec.pubkey, new_pubkey);
        assert!(state.pools[&pool_id].validators.contains(&new_id));
    }

    /// A registration for an already-known id is silently dropped —
    /// no state change, no effect, no entry in `registered`. The
    /// id-is-dead-forever policy.
    #[test]
    fn register_validator_duplicate_id_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        state.pools.get_mut(&pool_id).unwrap().total_stake =
            Stake::from_attos(5 * MIN_STAKE_FLOOR.attos());

        let existing_id = ValidatorId::new(0); // already on shard
        let prior = state.validators.get(&existing_id).unwrap().clone();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id,
                validator_id: existing_id,
                pubkey: pubkey(99),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.registered.is_empty());
        // Record unchanged — pubkey from the duplicate witness didn't
        // overwrite the prior one.
        assert_eq!(state.validators.get(&existing_id).unwrap(), &prior);
    }

    /// A registration that would push the pool over `max_active_count`
    /// at the current dynamic `min_stake` is silently dropped.
    #[test]
    fn register_validator_rejected_when_pool_lacks_capacity() {
        let mut state = single_pool_state(4); // pool stake = 4 * MIN_STAKE_FLOOR
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool already supports 4 actives at the floor; a 5th would
        // exceed max_active_count without bumping stake.
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::RegisterValidator {
                pool_id: StakePoolId::new(0),
                validator_id: ValidatorId::new(5),
                pubkey: pubkey(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.registered.is_empty());
        assert!(!state.validators.contains_key(&ValidatorId::new(5)));
        // Watermark still advances — the witness was consumed even
        // though the variant rejected it.
        assert_eq!(
            state.consumed_through.get(&ShardId::leaf(1, 0)),
            Some(&LeafIndex::new(1))
        );
    }

    /// `DeactivateValidator` from `OnShard` flips status to
    /// `InsufficientStake` AND cascades: shard committee loses the
    /// validator, `pool_draw` refills from any remaining pooled.
    #[test]
    fn deactivate_validator_on_shard_cascades() {
        // 4 actives + 1 pooled. Pool stake exactly covers 4
        // (`max_active_count = 4`), so after the cascade refills the
        // freed epoch the pool sits at `cur = max` and `auto_reactivate`
        // doesn't reverse the deactivation.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

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

    /// `DeactivateValidator` from `Pooled` flips status; no cascade
    /// (validator wasn't on a shard).
    #[test]
    fn deactivate_validator_pooled_flips_in_place() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        // Add a pooled validator and try to deactivate them.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(5)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        // Shard committee unchanged (the validator wasn't there).
        assert_eq!(
            state.next_shard_committees[&ShardId::leaf(1, 0)].members,
            pre_members,
        );
    }

    /// `DeactivateValidator` against an already-`InsufficientStake`
    /// or an already-permanent `Jailed { Equivocation }` validator is
    /// a silent no-op.
    #[test]
    fn deactivate_validator_no_op_for_insufficient_or_equivocation() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert two unreachable-status validators.
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

        let ws = vec![
            shard_witness(
                0,
                1,
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(10),
                },
            ),
            shard_witness(
                0,
                2,
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(11),
                },
            ),
        ];
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

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

    /// `DeactivateValidator` against a fault-cause `Jailed` validator
    /// IS allowed (operator retires a jailed node rather than waiting
    /// out the cooldown). No cascade — they were already off-shard.
    #[test]
    fn deactivate_validator_allowed_for_fault_cause_jailed() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert a Jailed{Performance} validator.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    // ─── Unjail ──────────────────────────────────────────────────────────

    /// Insert a Jailed{Performance} validator under pool 0 at
    /// `since_epoch`. The fixture state's pool has been bumped to
    /// support one extra active validator at the floor, so the
    /// capacity gate inside `Unjail` won't reject.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.unjailed, vec![ValidatorId::new(10)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// Unjail before cooldown elapses is a silent no-op — the
    /// validator stays Jailed.
    #[test]
    fn unjail_before_cooldown_is_no_op() {
        let since = Epoch::new(5);
        let mut state = state_with_jailed(since, JailReason::Performance);
        // current_epoch two short of cooldown — apply_next_epoch's
        // advance lands at (since + cooldown - 1), still under.
        state.current_epoch = Epoch::new(since.inner() + JAIL_COOLDOWN_EPOCHS - 2);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Equivocation,
            },
        );
    }

    /// Unjail rejected when the pool can't support one more active
    /// epoch at the current `min_stake`. Validator stays Jailed.
    #[test]
    fn unjail_rejected_when_pool_at_capacity() {
        // single_pool_state(4) saturates the pool exactly: 4 actives,
        // pool stake = 4 * MIN_STAKE_FLOOR, max_active_count = 4. Add
        // a Jailed validator that would push count to 5 if unjailed.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: since,
                reason: JailReason::Performance,
            },
        );
    }

    /// Unjail against a non-jailed validator (e.g. `Pooled`, `OnShard`)
    /// is a silent no-op.
    #[test]
    fn unjail_of_non_jailed_validator_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Validator 0 is OnShard, not Jailed.
        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.unjailed.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    // ─── Ready ───────────────────────────────────────────────────────────

    /// Ready on `OnShard { ready: false }` flips to `ready: true` —
    /// `placed_at_epoch` and `shard` carry through unchanged.
    #[test]
    fn ready_flips_on_shard_false_to_true() {
        let mut state = single_pool_state(0);
        state.committee = Vec::new();
        let shard = ShardId::leaf(1, 0);
        let placed = Epoch::new(3);
        // Put validator 1 on shard 0 as not-yet-ready.
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

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(1),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

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

    /// Ready on an already-ready `OnShard` validator is a silent
    /// no-op — re-signalling ready isn't an error.
    #[test]
    fn ready_on_already_ready_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pre = state.validators.get(&ValidatorId::new(0)).unwrap().clone();

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.readied.is_empty());
        assert_eq!(state.validators.get(&ValidatorId::new(0)).unwrap(), &pre);
    }

    /// Ready against a `Pooled` validator is a silent no-op (the
    /// validator isn't on a shard yet).
    #[test]
    fn ready_on_pooled_is_no_op() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(5),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.readied.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    // ─── MissedProposal ──────────────────────────────────────────────────

    use hyperscale_types::{BlockHeight, Round};

    fn missed_proposal_witness(
        source_shard: u64,
        leaf_index: u64,
        proposer_id: ValidatorId,
    ) -> ShardWitness {
        shard_witness(
            source_shard,
            leaf_index,
            ShardWitnessPayload::MissedProposal {
                proposer_id,
                height: BlockHeight::GENESIS,
                round: Round::INITIAL,
            },
        )
    }

    /// A `MissedProposal` from shard S against a validator currently
    /// `OnShard { shard: S, .. }` increments their miss counter. Below
    /// threshold, no jail effect.
    #[test]
    fn missed_proposal_increments_counter_for_on_shard_proposer() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&1));
        // Status unchanged — still OnShard.
        assert!(matches!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }

    /// A `MissedProposal` from shard B against a validator currently
    /// on shard A is silently dropped — the witness's source shard
    /// doesn't match the validator's placement.
    #[test]
    fn missed_proposal_from_wrong_shard_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add shard 1 with one validator on it.
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

        // Witness emitted by shard 0, targeting validator on shard 1.
        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// A `MissedProposal` against a validator not currently `OnShard`
    /// (`Pooled`, `Jailed`, `InsufficientStake`) is silently dropped.
    #[test]
    fn missed_proposal_against_non_on_shard_validator_is_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(10);
        state
            .validators
            .insert(target, validator_record(10, 0, ValidatorStatus::Pooled));

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert!(!state.miss_counters.contains_key(&target));
    }

    /// One `MissedProposal` per witness — multiple in a single epoch
    /// against the same validator accumulate. Below threshold, no
    /// jail.
    #[test]
    fn multiple_missed_proposals_in_one_slot_accumulate() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = ValidatorId::new(1);

        // Three distinct misses at leaf indices 1..3.
        let ws: Vec<ShardWitness> = (1u64..=3)
            .map(|leaf| missed_proposal_witness(0, leaf, target))
            .collect();
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), ws),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(state.miss_counters.get(&target), Some(&3));
    }

    /// Crossing `MISSED_PROPOSAL_JAIL_THRESHOLD` jails the validator
    /// under `Performance`, cascades the committee removal +
    /// `pool_draw` refill, and clears the miss counter.
    #[test]
    fn missed_proposal_at_threshold_jails_and_clears_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let pool_id = StakePoolId::new(0);
        // Add a 5th validator in the pool to fuel the refill draw.
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
        // Pre-seed counter to threshold - 1 so a single witness
        // crosses the boundary.
        state
            .miss_counters
            .insert(target, MISSED_PROPOSAL_JAIL_THRESHOLD - 1);

        let w = missed_proposal_witness(0, 1, target);
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![target]);
        // Jailed under Performance at current_epoch.
        assert_eq!(
            state.validators.get(&target).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        // Counter cleared.
        assert!(!state.miss_counters.contains_key(&target));
        // Shard committee refilled from pool.
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&target));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// VRF jail cascade also clears the miss counter — pinning the
    /// "any out-of-OnShard transition clears `miss_counters`" contract.
    #[test]
    fn vrf_jail_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-seed a non-zero miss counter for validator 0.
        state.miss_counters.insert(ValidatorId::new(0), 7);

        let committed = vec![(
            ValidatorId::new(0),
            malformed_vrf_proposal(0, state.current_epoch.next()),
        )];
        apply_next_epoch(&mut state, &committed);

        // Validator 0 jailed via VRF; counter must be cleared.
        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    /// `DeactivateValidator` cascade also clears the miss counter for
    /// the deactivated `OnShard` validator.
    #[test]
    fn deactivate_cascade_clears_miss_counter() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.miss_counters.insert(ValidatorId::new(0), 5);

        let w = shard_witness(
            0,
            1,
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(0),
            },
        );
        let committed = vec![(
            ValidatorId::new(0),
            vrf_proposal_with_witnesses(0, state.current_epoch.next(), vec![w]),
        )];
        apply_next_epoch(&mut state, &committed);

        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
    }

    // ─── Equivocation witnesses ──────────────────────────────────────────

    use hyperscale_types::{
        DOMAIN_PC_VOTE1, PcValueElement, PcVector, PcVoteEquivocation, PcVoteRound, SpcView,
        pc_context, pc_vote_signing_message, spc_context,
    };

    /// Build a valid `PcVoteEquivocation` for `equivocator` at
    /// `(epoch, view)` over two distinct round-1 vectors. Both sigs
    /// verify under the equivocator's pubkey; the value mismatch is
    /// what makes it a contradiction.
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

    /// Verified PC vote equivocation against an `OnShard` validator
    /// jails permanently under `Equivocation` and cascades the
    /// committee removal + `pool_draw` refill.
    #[test]
    fn vote_equivocation_jails_on_shard_validator_with_cascade() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add a 5th validator in the pool to fuel refill.
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

    /// Verified equivocation against a `Pooled` validator flips
    /// status to permanent `Jailed { Equivocation }`; no cascade
    /// (validator wasn't on a shard).
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
    /// permanent `Jailed{Equivocation}` — race-defence so a validator
    /// can't escape permanent record via an earlier soft jail.
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

    /// Equivocation against an already-permanent `Jailed{Equivocation}`
    /// is a silent no-op — re-application is idempotent.
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
        // since_epoch unchanged — no jail re-applied.
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: prior_epoch,
                reason: JailReason::Equivocation,
            },
        );
    }
}
