//! VRF reveal verification + randomness roll + the [`jail_validator`]
//! transition.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconProposal, BeaconState, Epoch, EpochSeed, HALT_THRESHOLD_EPOCHS, JailReason,
    NetworkDefinition, Randomness, RevealChain, SeedSource, ShardId, ValidatorId, ValidatorStatus,
    Verifier, VrfOutput, beacon_reveal_verify, byzantine_threshold,
};

use crate::state::pool::exit_placement;

/// Domain tag for the ceremony-randomness mixer — the fallback seed
/// path for epochs where no reveal chain folded. Binds the BLAKE3 input
/// to "beacon randomness v1" so the digest can't collide with any
/// other 32-byte BLAKE3 hash in the codebase (committee draw seed,
/// pool draw seed, etc.).
const DOMAIN_BEACON_RANDOMNESS: &[u8] = b"hyperscale-beacon-randomness-v1";

/// Domain tag for the reveal-leaf randomness fold — the steady-state
/// seed path. Distinct from the ceremony tag so the two preimage
/// shapes (both `prev ‖ 32-byte outputs…`) can never collide across
/// the switch.
const DOMAIN_BEACON_RANDOMNESS_REVEALS: &[u8] = b"hyperscale-beacon-randomness-reveals-v1";

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
/// pubkey, roll `state.randomness`, and jail proposers whose reveals
/// were rejected — or whose proposals never reached the committed set
/// at all.
///
/// The seed's steady-state source is `reveals` — one chain value per
/// shard whose crossing folded this epoch, each closing that shard's
/// anchor epoch. Every link is a hash-VRF over `(shard, height)`,
/// committed before any later block existed, so a chain is fixed by its
/// producers' keys and slots and interior links are blind to their own
/// producers. The fold consumes the chains shard-sorted (the map's
/// order). The boundary fold already dropped any crossing a halt
/// recovery fenced — the beyond-f retained committee's possible
/// post-halt production — so every chain handed here seeds.
///
/// Epochs where no reveal folded (bootstrap before the first
/// crossings, a `Skip`, or total crossing suppression — a
/// self-announcing, every-shard attack) fall back to the ceremony mix
/// over the accepted VRF outputs. `state.randomness` advances
/// *always* — even when no proposal is accepted, the BLAKE3 mix runs
/// against the prior randomness alone, so an "all-rejected" epoch
/// still advances randomness as a deterministic function of
/// `prev_randomness`. The ceremony's verify + jail passes run
/// regardless of which path seeds: beacon participation stays a
/// disciplined duty so the fallback population is honest when the
/// fallback is the seed.
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
    verifier: &dyn Verifier,
    state: &mut BeaconState,
    network: &NetworkDefinition,
    epoch: Epoch,
    committed: &'a [(ValidatorId, BeaconProposal)],
    reveals: &BTreeMap<ShardId, RevealChain>,
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
        if beacon_reveal_verify(verifier, &pk, network, epoch, &prop.vrf_proof()) {
            accepted_outputs.push(prop.vrf_output());
            accepted.push(entry);
        } else {
            rejected_reveals.push(*party);
        }
    }

    // Roll randomness: the folded reveal chains when any crossing folded
    // this epoch, else the ceremony mix over the accepted outputs. Always
    // runs — see the function-level doc for the source switch and the
    // "all-rejected" semantics. Both paths fold the same preimage shape —
    // domain ‖ prior randomness ‖ each 32-byte value — differing only in
    // the domain tag and the source, so the fold lives in one place.
    let mut h = Hasher::new();
    let source = if reveals.is_empty() {
        h.update(DOMAIN_BEACON_RANDOMNESS);
        h.update(state.randomness.as_bytes());
        for o in &accepted_outputs {
            h.update(o.as_bytes());
        }
        SeedSource::Ceremony
    } else {
        h.update(DOMAIN_BEACON_RANDOMNESS_REVEALS);
        h.update(state.randomness.as_bytes());
        for chain in reveals.values() {
            h.update(chain.as_raw().as_bytes());
        }
        SeedSource::Reveals
    };
    state.randomness = Randomness::new(*h.finalize().as_bytes());
    // The value keyed by the epoch it was rolled for, so a consumer
    // resolving against a past epoch reads what stood then. Which roll
    // produced it travels with it: the two are not interchangeable to
    // anything that draws on one.
    state.seeds.record(
        epoch,
        EpochSeed {
            randomness: state.randomness,
            source,
        },
    );

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

    // Jail committee members with no committed proposal — the
    // withholding lever of the randomness grind (include-or-omit is the
    // only control a member has over the roll above). The committed
    // value is the f+1-shared prefix (`qc1_certify`), so under synchrony
    // an honest proposal reaching a supermajority cannot be forced
    // absent; a member with no entry chose silence. One absence jails —
    // no counter — under `JailReason::Withholding`, held out for a full
    // recency period so a grinder cannot cycle its foothold back inside
    // one committee turnover.
    //
    // The sweep runs only when the committed set itself attests a
    // healthy epoch: at least `n − f` of the committee present. Within
    // the fault budget an absence is attributable — every other member's
    // proposal made the shared prefix, so silence was a choice. Beyond
    // it, the epoch failed the synchrony assumption the jail rests on
    // (more than f honest members cannot all be withholding): a pool
    // stall's catch-up folds ratify candidates assembled while peers
    // were unreachable, and jailing the unreachable guts their shards'
    // committees with no pool to refill from. Buying amnesty this way
    // requires forcing more than f proposals out of the f+1-shared
    // prefix — at least f+1 colluding inputs, beyond the fault budget —
    // so the grinding price holds in every epoch where the lever works.
    // The proposal-less epoch (a Skip fold) sits below any threshold and
    // carries no absence signal.
    let present: BTreeSet<ValidatorId> = committed.iter().map(|(party, _)| *party).collect();
    let present_members = state
        .committee
        .iter()
        .filter(|party| present.contains(party))
        .count();
    let attributable =
        present_members >= state.committee.len() - byzantine_threshold(state.committee.len());
    if attributable {
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
            // A halted shard's member is silent through no fault of its
            // own ([`on_missing_crossings_shard`]); sparing it keeps the
            // frozen tip's custody seated for the halt recovery.
            if on_missing_crossings_shard(state, party) {
                continue;
            }
            jail_validator(state, party, JailReason::Withholding, since_epoch);
            jailed.push(party);
        }
    }

    VrfStageOutcome {
        accepted,
        rejected_reveals,
        jailed,
    }
}

/// Whether `party` sits on a shard whose missed crossings have reached
/// the halt threshold — the shield against halt-collateral jailing for
/// the liveness-inferred penalties (ceremony absence, the
/// missed-proposal ratchet). A halted shard silences its members
/// through no fault of theirs, and every jail exits one from the
/// committee — tearing down a copy of the frozen tip the halt recovery
/// needs its retained members to serve.
///
/// The gate is the halt condition itself, not any missed crossing: a
/// transient miss is routine and must not mute the jails that suppress
/// reveal grinding and chronic missed proposals. The shield covers the
/// window between the halt flagging and the recovery redraw pooling the
/// members, where these jails would otherwise strand the frozen tip.
/// Cryptographic faults — a malformed reveal, an equivocation — stay
/// jailable; a halt cannot manufacture those.
pub(super) fn on_missing_crossings_shard(state: &BeaconState, party: ValidatorId) -> bool {
    let Some(ValidatorStatus::OnShard { shard, .. }) =
        state.validators.get(&party).map(|r| r.status)
    else {
        return false;
    };
    state
        .boundaries
        .get(&shard)
        .is_some_and(|b| u64::from(b.consecutive_misses) > HALT_THRESHOLD_EPOCHS)
}

/// Transition `victim` to `Jailed { since_epoch, reason }`, then run
/// [`exit_placement`]'s shared cleanup (clear miss counters; if they
/// were `OnShard`, drop from that shard's committee and refill from the
/// global pool).
///
/// Silent no-op if `victim` isn't in `state.validators`. Callers that
/// want to gate on the prior status must do that gate before calling.
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

/// Permanently revoke `victim` on equivocation evidence: transition to
/// [`ValidatorStatus::Revoked`], then run [`exit_placement`]'s shared
/// cleanup. Idempotent — an already-`Revoked` victim is left untouched
/// so replayed evidence never re-runs the placement teardown.
///
/// Silent no-op if `victim` isn't in `state.validators`.
pub(super) fn revoke_validator(state: &mut BeaconState, victim: ValidatorId, at_epoch: Epoch) {
    let Some(rec) = state.validators.get_mut(&victim) else {
        return;
    };
    if matches!(rec.status, ValidatorStatus::Revoked { .. }) {
        return;
    }
    let prior = rec.status;
    rec.status = ValidatorStatus::Revoked { at_epoch };
    exit_placement(state, victim, prior);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use blake3::Hasher;
    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::{
        BeaconProposal, BeaconState, Epoch, EpochSeed, Hash, JailReason, MIN_STAKE_FLOOR,
        Randomness, RevealChain, SeedLookup, SeedSource, ShardId, Stake, StakePoolId, ValidatorId,
        ValidatorStatus,
    };

    use super::{DOMAIN_BEACON_RANDOMNESS, DOMAIN_BEACON_RANDOMNESS_REVEALS};
    use crate::state::test_fixtures::{
        apply_next_epoch, malformed_vrf_proposal, net, single_pool_state, validator_record,
        vrf_proposal,
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
                reason: JailReason::Withholding,
            },
        );
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 4);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(4)));
    }

    /// A committee member absent from the committed set is spared the
    /// withholding jail while its shard's missed crossings have reached
    /// the halt threshold: a halted shard silences its members through
    /// no fault of theirs, and jailing them exits each from the
    /// committee in turn — tearing down the frozen tip's last copies
    /// before the halt recovery can retain them.
    #[test]
    fn absence_on_a_missing_crossings_shard_does_not_jail() {
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
                cumulative_fees: 0,
                used: DeclaredWork::ZERO,
                blocks: 0,
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

        // Members 1..=3 propose; member 0 is silent — but its shard is
        // halted, so the absence is not attributable to it.
        let target = state.current_epoch.next();
        let committed: Vec<_> = (1u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let effects = apply_next_epoch(&mut state, &committed);

        assert!(
            effects.jailed.is_empty(),
            "a halted shard's member must not be jailed for ceremony absence",
        );
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert!(members.contains(&ValidatorId::new(0)));
    }

    /// A shard one crossing behind is routine, not halted: its silent
    /// member still jails for withholding. The shield engages only at
    /// the halt threshold, so a benign transient miss cannot mute the
    /// grinding-suppression jail.
    #[test]
    fn absence_with_one_missed_crossing_still_jails() {
        use hyperscale_types::{
            BeaconWitnessLeafCount, BlockHash, BlockHeight, DeclaredWork, ShardBoundary, StateRoot,
            WeightedTimestamp,
        };

        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.boundaries.insert(
            ShardId::leaf(1, 0),
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
                height: BlockHeight::new(5),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                cumulative_fees: 0,
                used: DeclaredWork::ZERO,
                blocks: 0,
                substate_bytes: 0,
                last_live_epoch: Epoch::new(1),
                consecutive_misses: 1,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_roots: None,
                reshape_admitted_epoch: None,
            },
        );

        let target = state.current_epoch.next();
        let committed: Vec<_> = (1u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let effects = apply_next_epoch(&mut state, &committed);

        assert_eq!(
            effects.jailed,
            vec![ValidatorId::new(0)],
            "one missed crossing must not shield a withholding member",
        );
    }

    /// An honest member cut off for one epoch — the async-window case —
    /// jails under `Withholding`, a recoverable reason, so the penalty is
    /// graceful: after the recency-period cooldown an `Unjail` returns it
    /// to the pool (and thence back into placement), not a permanent
    /// ejection. This four-member fixture's recency period is one epoch,
    /// so the cooldown here is short; the production coupling holds it far
    /// longer (`withholding_jail_holds_for_the_recency_period`).
    #[test]
    fn async_absence_jail_is_recoverable_after_cooldown() {
        use hyperscale_types::{JAIL_COOLDOWN_EPOCHS, ShardWitnessPayload};

        use crate::state::test_fixtures::apply_witness_chunk;

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
                reason: JailReason::Withholding,
                ..
            },
        ));

        // Once the cooldown elapses, an Unjail lifts it back to the pool.
        state.current_epoch = Epoch::new(jailed_at.inner() + JAIL_COOLDOWN_EPOCHS);
        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(0),
                id: ValidatorId::new(0),
            }],
        );
        assert_eq!(effects.unjailed, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// A committed set carrying fewer than `n − f` committee members'
    /// proposals attests a degraded epoch, not individual withholding —
    /// nobody jails. A ratification stall's catch-up folds take this
    /// shape: the candidate was assembled while part of the committee
    /// was unreachable, and jailing the unreachable would gut their
    /// shards' committees with no pool to refill from.
    #[test]
    fn sub_quorum_committed_set_jails_nobody() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Only two of four members' proposals made the shared prefix —
        // one short of the n − f = 3 attribution threshold.
        let target = state.current_epoch.next();
        let committed: Vec<_> = (0u64..2)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect();
        let effects = apply_next_epoch(&mut state, &committed);
        assert!(effects.jailed.is_empty());
        for i in 0u64..4 {
            assert!(matches!(
                state.validators.get(&ValidatorId::new(i)).unwrap().status,
                ValidatorStatus::OnShard { .. },
            ));
        }
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

    // ─── reveal-leaf fold ─────────────────────────────────────────────

    /// A fully present committee's proposals for `state`'s next epoch.
    fn full_committee_proposals(state: &BeaconState) -> Vec<(ValidatorId, BeaconProposal)> {
        let target = state.current_epoch.next();
        (0u64..4)
            .map(|i| (ValidatorId::new(i), vrf_proposal(i, target)))
            .collect()
    }

    /// Roll `state` directly through the fold under test with a fully
    /// present committee, supplying `reveals`.
    fn roll(state: &mut BeaconState, reveals: &BTreeMap<ShardId, RevealChain>) {
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let committed = full_committee_proposals(state);
        let target = state.current_epoch.next();
        super::filter_and_roll_randomness(&BlsVerifier, state, &net(), target, &committed, reveals);
    }

    fn reveal_chain(seed: u8) -> RevealChain {
        RevealChain::from_raw(Hash::from_bytes(&[seed; 32]))
    }

    /// Reveal leaves seed the roll byte-exactly: BLAKE3 over the reveal
    /// domain, the prior randomness, then every folded output —
    /// shard-sorted, each shard's outputs in leaf order — with the
    /// ceremony outputs contributing nothing. Pinned against a manual
    /// digest so any preimage drift (order, domain, extra bytes) fails
    /// loudly; the map is populated high-shard-first to prove the fold
    /// reads shard order, not insertion order.
    #[test]
    fn reveal_fold_is_byte_exact_and_shard_sorted() {
        let mut state = single_pool_state(4);
        let prev = state.randomness;
        let mut reveals = BTreeMap::new();
        reveals.insert(ShardId::leaf(1, 1), reveal_chain(2));
        reveals.insert(ShardId::leaf(1, 0), reveal_chain(1));
        roll(&mut state, &reveals);

        let mut h = Hasher::new();
        h.update(DOMAIN_BEACON_RANDOMNESS_REVEALS);
        h.update(prev.as_bytes());
        for seed in [1u8, 2] {
            h.update(reveal_chain(seed).as_raw().as_bytes());
        }
        assert_eq!(state.randomness, Randomness::new(*h.finalize().as_bytes()));
    }

    /// The roll files its value under the epoch it rolled for, so a
    /// consumer resolving against a past epoch reads what stood then
    /// rather than the head — which is the whole difference between a
    /// value fixed by a commitment and a value fixed by when it is read.
    #[test]
    fn the_roll_files_its_epochs_seed() {
        let mut state = single_pool_state(4);
        let target = state.current_epoch.next();
        let mut reveals = BTreeMap::new();
        reveals.insert(ShardId::leaf(1, 0), reveal_chain(1));
        roll(&mut state, &reveals);

        assert_eq!(
            state.seeds.at(target),
            SeedLookup::Seed(EpochSeed {
                randomness: state.randomness,
                source: SeedSource::Reveals,
            }),
        );
        assert_eq!(state.seeds.at(target.next()), SeedLookup::NotYetCommitted);
    }

    /// An epoch with no crossing falls back to the ceremony, and the
    /// entry says so. A draw settled on one is settled on the path a
    /// beacon member can withhold from, so the two must be tellable
    /// apart by whoever reads the seed rather than by whoever wrote it.
    #[test]
    fn a_ceremony_roll_files_itself_as_one() {
        let mut state = single_pool_state(4);
        let target = state.current_epoch.next();
        roll(&mut state, &BTreeMap::new());

        assert_eq!(
            state.seeds.at(target),
            SeedLookup::Seed(EpochSeed {
                randomness: state.randomness,
                source: SeedSource::Ceremony,
            }),
        );
    }

    /// With reveals folding, the accepted ceremony outputs stay out of
    /// the preimage: identical reveals over different committed ceremony
    /// sets land on identical randomness. Mixing the ceremony alongside
    /// would hand the last ceremony revealer back its sighted toggle.
    #[test]
    fn reveal_fold_ignores_ceremony_outputs() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        a.committee = (0u64..4).map(ValidatorId::new).collect();
        b.committee = a.committee.clone();
        let target = a.current_epoch.next();
        let full = full_committee_proposals(&a);
        let partial: Vec<_> = full.iter().take(2).cloned().collect();
        let mut reveals = BTreeMap::new();
        reveals.insert(ShardId::leaf(1, 0), reveal_chain(1));
        super::filter_and_roll_randomness(&BlsVerifier, &mut a, &net(), target, &full, &reveals);
        super::filter_and_roll_randomness(&BlsVerifier, &mut b, &net(), target, &partial, &reveals);
        assert_eq!(a.randomness, b.randomness);
    }

    /// An epoch with no folded reveals falls back to the ceremony mix —
    /// byte-exactly the ceremony domain over the accepted outputs, never
    /// bare BLAKE3(prev).
    #[test]
    fn zero_reveals_fall_back_to_the_ceremony_mix() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let prev = state.randomness;
        let committed = full_committee_proposals(&state);
        let target = state.current_epoch.next();
        super::filter_and_roll_randomness(
            &BlsVerifier,
            &mut state,
            &net(),
            target,
            &committed,
            &BTreeMap::new(),
        );

        let mut h = Hasher::new();
        h.update(DOMAIN_BEACON_RANDOMNESS);
        h.update(prev.as_bytes());
        for (_, prop) in &committed {
            h.update(prop.vrf_output().as_bytes());
        }
        assert_eq!(state.randomness, Randomness::new(*h.finalize().as_bytes()));
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
