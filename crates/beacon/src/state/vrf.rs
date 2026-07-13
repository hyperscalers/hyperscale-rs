//! VRF reveal verification + randomness roll + the [`jail_validator`]
//! transition.

use std::collections::BTreeSet;

use blake3::Hasher;
use hyperscale_types::{
    BeaconProposal, BeaconState, Epoch, JailReason, NetworkDefinition, Randomness, ValidatorId,
    ValidatorStatus, VrfOutput, vrf_verify,
};

use crate::state::pool::exit_placement;

/// Domain tag for the beacon-randomness mixer. Binds the BLAKE3 input
/// to "beacon randomness v1" so the digest can't collide with any
/// other 32-byte BLAKE3 hash in the codebase (committee draw seed,
/// pool draw seed, etc.).
const DOMAIN_BEACON_RANDOMNESS: &[u8] = b"hyperscale-beacon-randomness-v1";

/// Outcome of [`filter_and_roll_randomness`]. The borrowed `accepted`
/// slice lets [`super::witness::ingest_equivocations`] iterate the
/// proposals that survived the VRF check without re-running the filter.
pub(super) struct VrfStageOutcome<'a> {
    /// Proposals from committee members whose VRF reveal verified.
    /// References into the `committed` slice supplied to
    /// [`super::epoch::apply_epoch`].
    pub(super) accepted: Vec<&'a (ValidatorId, BeaconProposal)>,
    /// Validators in `state.committee` whose VRF reveal failed to
    /// verify. Their entire proposal — including any witnesses — was
    /// dropped on the same grounds.
    pub(super) rejected_reveals: Vec<ValidatorId>,
    /// Validators jailed during the cascade triggered by malformed VRF
    /// reveals. Subset of `rejected_reveals` (only `OnShard` rejected
    /// proposers cascade through to jail).
    pub(super) jailed: Vec<ValidatorId>,
}

/// Filter `committed` to proposals whose proposer is in
/// `state.committee` and whose VRF reveal verifies under their
/// pubkey, roll `state.randomness` over the accepted VRF outputs, and
/// jail proposers whose reveals were rejected — or whose proposals
/// never reached the committed set at all.
///
/// `state.randomness` advances *always* — even when no proposal is
/// accepted, the BLAKE3 mix runs against the prior randomness alone.
/// An "all-rejected" epoch still advances randomness as a
/// deterministic function of `prev_randomness`. An adversary who can
/// suppress every VRF reveal can therefore predict the next epoch's
/// randomness from the previous one; the mitigation is the
/// jail-on-first-sighting cascades here (malformed reveals and absent
/// proposals alike) plus committee resampling at epoch boundaries.
///
/// A malformed VRF reveal under the proposer's own key is a
/// self-inflicted cryptographic fault — an unmodified honest binary
/// can't produce one. Jail on first sighting under
/// `JailReason::Performance`; the freed shard epoch refills via
/// `pool_draw` in the same step as the status transition. Operators
/// restart with a fixed binary and lift via `Unjail` once cooldown
/// elapses. Non-`OnShard` rejected proposers (shouldn't normally
/// happen — non-committee filter already ran) silently fail the cascade
/// gate without jailing.
pub(super) fn filter_and_roll_randomness<'a>(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &'a [(ValidatorId, BeaconProposal)],
) -> VrfStageOutcome<'a> {
    let committee_set: BTreeSet<ValidatorId> = state.committee.iter().copied().collect();

    let mut accepted: Vec<&'a (ValidatorId, BeaconProposal)> = Vec::new();
    let mut rejected_reveals = Vec::new();
    let mut accepted_outputs: Vec<VrfOutput> = Vec::new();
    for entry in committed {
        let (party, prop) = entry;
        if !committee_set.contains(party) {
            continue;
        }
        // Defensive: committee membership should imply a validator
        // record. If a runner bug or future refactor breaks that
        // invariant, treat the proposer as rejected rather than
        // panic.
        let Some(pk) = state.validators.get(party).map(|r| r.pubkey) else {
            rejected_reveals.push(*party);
            continue;
        };
        if vrf_verify(&pk, network, epoch, &prop.vrf_proof()) {
            accepted_outputs.push(prop.vrf_output());
            accepted.push(entry);
        } else {
            rejected_reveals.push(*party);
        }
    }

    // Roll randomness from accepted VRF outputs. Always runs — see
    // function-level doc for the "all-rejected" semantics.
    let mut h = Hasher::new();
    h.update(DOMAIN_BEACON_RANDOMNESS);
    h.update(state.randomness.as_bytes());
    for o in &accepted_outputs {
        h.update(o.as_bytes());
    }
    state.randomness = Randomness::new(*h.finalize().as_bytes());

    // Cascade jail for rejected proposers currently `OnShard`.
    let mut jailed = Vec::new();
    let since_epoch = state.current_epoch;
    for party in &rejected_reveals {
        let prior_status = state.validators.get(party).map(|r| r.status);
        if !matches!(prior_status, Some(ValidatorStatus::OnShard { .. })) {
            continue;
        }
        jail_validator(state, *party, JailReason::Performance, since_epoch);
        jailed.push(*party);
    }

    // Jail committee members with no committed proposal at all — the
    // withholding lever of the randomness grind (include-or-omit is the
    // only control a member has over the roll above). The committed
    // value is the f+1-shared prefix (`qc1_certify`), so under synchrony
    // an honest proposal reaching a supermajority cannot be forced
    // absent; a member with no entry chose silence. One absence jails —
    // no counter — and the jail cooldown is the recovery knob. Rests on
    // that synchrony assumption: a member cut off for a whole epoch
    // reads as absent and jails, a recoverable performance fault. An
    // epoch with no committed proposals at all carries no absence
    // signal and is skipped.
    if !committed.is_empty() {
        let present: BTreeSet<ValidatorId> = committed.iter().map(|(party, _)| *party).collect();
        let absent: Vec<ValidatorId> = state
            .committee
            .iter()
            .filter(|party| !present.contains(party))
            .copied()
            .collect();
        for party in absent {
            let prior_status = state.validators.get(&party).map(|r| r.status);
            if !matches!(prior_status, Some(ValidatorStatus::OnShard { .. })) {
                continue;
            }
            jail_validator(state, party, JailReason::Performance, since_epoch);
            jailed.push(party);
        }
    }

    VrfStageOutcome {
        accepted,
        rejected_reveals,
        jailed,
    }
}

/// Transition `victim` to `Jailed { since_epoch, reason }`, then run
/// [`exit_placement`]'s shared cleanup (clear miss counters; if they
/// were `OnShard`, drop from that shard's committee and refill from the
/// global pool).
///
/// Silent no-op if `victim` isn't in `state.validators`. Callers that
/// want to gate on the prior status (e.g. equivocation's "skip
/// already-permanent `Equivocation` jails") must do that gate before
/// calling.
pub(super) fn jail_validator(
    state: &mut BeaconState,
    victim: ValidatorId,
    reason: JailReason,
    since_epoch: Epoch,
) {
    let Some(rec) = state.validators.get_mut(&victim) else {
        return;
    };
    let prior = rec.status;
    rec.status = ValidatorStatus::Jailed {
        since_epoch,
        reason,
    };
    exit_placement(state, victim, prior);
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        Epoch, JailReason, MIN_STAKE_FLOOR, ShardId, Stake, StakePoolId, ValidatorId,
        ValidatorStatus,
    };

    use crate::state::test_fixtures::{
        apply_next_epoch, malformed_vrf_proposal, single_pool_state, validator_record, vrf_proposal,
    };
    // ─── filter_and_roll_randomness ──────────────────────────────────────

    /// Randomness rolls even on an all-empty epoch. The mixer runs over
    /// `prev_randomness` alone — needed so the "all rejected" path is
    /// well-defined and the chain doesn't stall on a silent epoch.
    #[test]
    fn randomness_rolls_with_empty_committed() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let prior = state.randomness;
        apply_next_epoch(&mut state, &[]);
        assert_ne!(state.randomness, prior);
    }

    /// A proposal from a non-committee party is silently dropped — no
    /// jail, no randomness contribution, no `rejected_reveals` entry.
    /// Defends against runner-level bugs that pass a stray proposal in.
    /// The committee itself is fully present so the stray is the only
    /// anomaly under test.
    #[test]
    fn non_committee_proposal_is_silently_dropped() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Insert validator 5 with a record but NOT in the committee.
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::Pooled),
        );
        let prior = state.randomness;
        let target = state.current_epoch.next();
        let mut committed: Vec<_> = (0u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        committed.push((ValidatorId::new(5), vrf_proposal(5, target)));
        let effects = apply_next_epoch(&mut state, &committed);
        // Randomness rolled, but no contribution from the dropped
        // proposal — and no rejected_reveals entry.
        assert_ne!(state.randomness, prior);
        assert!(effects.rejected_reveals.is_empty());
        assert!(effects.jailed.is_empty());
    }

    /// Honest VRF reveals verify and contribute to randomness;
    /// `rejected_reveals` stays empty.
    #[test]
    fn honest_proposal_advances_randomness_without_rejection() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let target = state.current_epoch.next();
        let committed: Vec<_> = (0u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let prior = state.randomness;
        let effects = apply_next_epoch(&mut state, &committed);
        assert_ne!(state.randomness, prior);
        assert!(effects.rejected_reveals.is_empty());
        assert!(effects.jailed.is_empty());
    }

    /// Two states fed byte-identical inputs land on byte-identical
    /// randomness — pins the determinism the chain relies on.
    #[test]
    fn randomness_roll_is_deterministic_across_replicas() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        a.committee = (0u64..4).map(ValidatorId::new).collect();
        b.committee = a.committee.clone();
        let target = a.current_epoch.next();
        let committed = vec![
            (ValidatorId::new(0), vrf_proposal(0, target)),
            (ValidatorId::new(1), vrf_proposal(1, target)),
        ];
        apply_next_epoch(&mut a, &committed);
        apply_next_epoch(&mut b, &committed);
        assert_eq!(a.randomness, b.randomness);
    }

    /// Malformed VRF reveal jails the proposer under
    /// `JailReason::Performance` and cascades: removal from the shard
    /// committee + `pool_draw` refill from any remaining pooled
    /// validators.
    #[test]
    fn malformed_vrf_jails_proposer_and_refills_via_pool_draw() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Add a fifth validator sitting in the pool; pool stake bumped
        // to support them.
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

        // The rest of the committee is present, so the malformed cascade
        // is the only jail path exercised.
        let target = state.current_epoch.next();
        let mut committed = vec![(ValidatorId::new(0), malformed_vrf_proposal(0, target))];
        committed.extend((1u64..4).map(|i| (ValidatorId::new(i), vrf_proposal(i, target))));
        let effects = apply_next_epoch(&mut state, &committed);

        // Proposer 0 in rejected_reveals AND jailed.
        assert_eq!(effects.rejected_reveals, vec![ValidatorId::new(0)]);
        assert_eq!(effects.jailed, vec![ValidatorId::new(0)]);
        // Status flipped to Jailed { Performance, since_epoch = current }.
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        // Shard committee size stays at 4 — validator 4 drawn from
        // pool to refill the freed epoch.
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
        // Validator 4 is now OnShard (refill from pool).
        let refill_status = state.validators.get(&ValidatorId::new(4)).unwrap().status;
        assert!(matches!(
            refill_status,
            ValidatorStatus::OnShard { shard, ready: false, .. } if shard == ShardId::leaf(1, 0),
        ));
    }

    /// A committee member with no committed proposal at all jails on the
    /// first absence — the withholding lever of the randomness grind —
    /// and its freed seat refills from the pool.
    #[test]
    fn absent_committee_member_jails_on_first_absence() {
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

        // Members 1..=3 propose; member 0 withholds.
        let target = state.current_epoch.next();
        let committed: Vec<_> = (1u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(effects.jailed, vec![ValidatorId::new(0)]);
        // Absence is not a malformed reveal — nothing to reject.
        assert!(effects.rejected_reveals.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: state.current_epoch,
                reason: JailReason::Performance,
            },
        );
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// An honest member cut off for one epoch — the async-window case —
    /// jails under `Performance`, the recoverable reason, so the penalty
    /// is graceful: after the cooldown an `Unjail` returns it to the pool
    /// (and thence back into placement), not a permanent ejection.
    #[test]
    fn async_absence_jail_is_recoverable_after_cooldown() {
        use hyperscale_types::{JAIL_COOLDOWN_EPOCHS, ShardWitnessPayload};

        use crate::state::test_fixtures::apply_witness_chunk;

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

        // Member 0 is transiently unreachable for one epoch.
        let target = state.current_epoch.next();
        let committed: Vec<_> = (1u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        apply_next_epoch(&mut state, &committed);
        let jailed_at = state.current_epoch;
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Jailed {
                reason: JailReason::Performance,
                ..
            },
        ));

        // Once the cooldown elapses, an Unjail lifts it back to the pool.
        state.current_epoch = Epoch::new(jailed_at.inner() + JAIL_COOLDOWN_EPOCHS);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                id: ValidatorId::new(0),
            }],
        );
        assert_eq!(effects.unjailed, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// An epoch that committed no proposals at all carries no absence
    /// signal — nobody jails. The Skip fold and the empty-Normal fold
    /// both take this shape.
    #[test]
    fn empty_committed_set_jails_nobody() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_next_epoch(&mut state, &[]);
        assert!(effects.jailed.is_empty());
        for i in 0u64..4 {
            assert!(matches!(
                state.validators.get(&ValidatorId::new(i)).unwrap().status,
                ValidatorStatus::OnShard { .. },
            ));
        }
    }

    /// Every member present means nobody jails, epoch after epoch — the
    /// synchronous honest fixture the clean-purge property rests on.
    #[test]
    fn fully_present_committee_never_jails() {
        let mut state = single_pool_state(4);
        for _ in 0..8 {
            state.committee = (0u64..4).map(ValidatorId::new).collect();
            let target = state.current_epoch.next();
            let committed: Vec<_> = (0u64..4)
                .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
                .collect();
            let effects = apply_next_epoch(&mut state, &committed);
            assert!(effects.jailed.is_empty());
        }
    }

    /// A member both absent and no longer `OnShard` (jailed by an
    /// earlier fold, still riding the promoted committee list) is left
    /// alone — the cascade gate keeps the pass idempotent.
    #[test]
    fn absence_pass_skips_members_no_longer_on_shard() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let jailed_earlier = ValidatorId::new(0);
        state.validators.get_mut(&jailed_earlier).unwrap().status = ValidatorStatus::Jailed {
            since_epoch: state.current_epoch,
            reason: JailReason::Performance,
        };
        let earlier_status = state.validators.get(&jailed_earlier).unwrap().status;

        let target = state.current_epoch.next();
        let committed: Vec<_> = (1u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(effects.jailed.is_empty());
        assert_eq!(
            state.validators.get(&jailed_earlier).unwrap().status,
            earlier_status,
            "an already-jailed member must not be re-jailed by the absence pass",
        );
    }

    /// Malformed VRF still rejects the proposal's randomness
    /// contribution even though it jails the proposer — the rejected
    /// reveal's output is NOT mixed in. Pinning this prevents a
    /// regression where a "rejected but contributes anyway" bug would
    /// let a byzantine proposer grind randomness while accepting the
    /// jail.
    #[test]
    fn malformed_vrf_does_not_contribute_to_randomness() {
        let mut state_a = single_pool_state(4);
        let mut state_b = single_pool_state(4);
        state_a.committee = (0u64..4).map(ValidatorId::new).collect();
        state_b.committee = state_a.committee.clone();

        // A: one honest proposer at epoch 1.
        let target = state_a.current_epoch.next();
        let honest_only = vec![(ValidatorId::new(1), vrf_proposal(1, target))];
        apply_next_epoch(&mut state_a, &honest_only);

        // B: same honest proposer + one malformed reveal from proposer 0.
        let mixed = vec![
            (ValidatorId::new(0), malformed_vrf_proposal(0, target)),
            (ValidatorId::new(1), vrf_proposal(1, target)),
        ];
        apply_next_epoch(&mut state_b, &mixed);

        // Randomness identical — the malformed reveal contributed nothing.
        assert_eq!(state_a.randomness, state_b.randomness);
    }
}
