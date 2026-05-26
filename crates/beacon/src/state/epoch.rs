//! Top-level epoch pipeline: orchestrates VRF filtering, witness
//! ingestion, withdrawal maturation, reactivation, rewards, ready
//! timeout, shuffle, and committee resample into a single
//! `apply_epoch` step.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, BeaconState, CommitteeTransition, Epoch, NetworkDefinition,
    RecoveryCertificate, ShardGroupId, SlotEffects, TransitionCause, ValidatorId,
};

use crate::recovery::verify_recovery_cert;
use crate::state::committee::{diff_shard_committees, resample_beacon_committee, run_shuffle_step};
use crate::state::derived::derive_active_pool;
use crate::state::lifecycle::{auto_reactivate, auto_ready_timeout, distribute_epoch_rewards};
use crate::state::vrf::filter_and_roll_randomness;
use crate::state::withdrawals::complete_pending_withdrawals;
use crate::state::witness::ingest_witnesses;

/// Discriminator for [`apply_epoch`] — distinguishes a Normal epoch
/// (with optional recovery-cert handoff) from a Skip epoch (empty
/// proposal set, committee resampled with [`TransitionCause::Skip`]).
///
/// The authenticating [`BeaconCert`](hyperscale_types::BeaconCert) is
/// not threaded through — by the time `adopt_block` calls `apply_epoch`
/// the cert has already authenticated the block. This enum carries
/// only the structural information the state pipeline needs:
/// committed-proposal payload, optional recovery-cert side-channel
/// (transitional through phase 4), and the Normal-vs-Skip discriminator
/// that picks the right [`TransitionCause`] on the committee transition.
#[derive(Debug, Clone, Copy)]
pub enum ApplyEpochInput<'a> {
    /// Normal epoch with the SPC-agreed proposal set and optional
    /// transitional `recovery_cert` handoff.
    Normal {
        /// Committed proposals from SPC's Agreement output.
        committed: &'a [(ValidatorId, BeaconProposal)],
        /// Transitional `RecoveryCertificate` side-channel; phase 4
        /// removes the parameter once the coordinator no longer threads
        /// recovery certs through commit.
        recovery_cert: Option<&'a RecoveryCertificate>,
    },
    /// Skip epoch — pool-quorum abandonment of the epoch. Pipeline
    /// runs over an empty proposal set; committee resamples under
    /// [`TransitionCause::Skip`].
    Skip,
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

    // Snapshot each shard's member list before the pipeline runs so the
    // end-of-epoch set-diff against this snapshot can surface
    // membership changes through `SlotEffects.shard_committee_transitions`.
    let pre_shard_members: BTreeMap<ShardGroupId, Vec<ValidatorId>> = state
        .shard_committees
        .iter()
        .map(|(s, c)| (*s, c.members.clone()))
        .collect();

    let (committed, recovery_cert, is_skip): (&[_], _, bool) = match input {
        ApplyEpochInput::Normal {
            committed,
            recovery_cert,
        } => (committed, recovery_cert, false),
        ApplyEpochInput::Skip => (&[], None, true),
    };

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
    let witness = ingest_witnesses(state, network, &vrf.accepted);
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    let rewards_credited = distribute_epoch_rewards(state);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);
    let beacon_committee_transition = if is_skip {
        resample_beacon_committee(state, &BTreeSet::new(), TransitionCause::Skip)
    } else {
        apply_recovery_or_resample(state, network, recovery_cert)
    };

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

/// Resample the beacon committee on the Normal path.
///
/// Recovery sub-path: `recovery_cert` is `Some` and verifies — install
/// the replacement committee with exclusion-aware sampling against
/// the cert's `excluded_validators`. Natural sub-path: no cert, or the
/// supplied cert failed verification — fall through to the normal
/// resample over the full pool.
///
/// A failed-verification cert is dropped rather than panicking: the
/// runner shouldn't be able to brick the chain by submitting a bad
/// cert, and a well-formed honest committee will produce a normal
/// block at this epoch in that case.
pub fn apply_recovery_or_resample(
    state: &mut BeaconState,
    network: &NetworkDefinition,
    recovery_cert: Option<&RecoveryCertificate>,
) -> CommitteeTransition {
    if let Some(cert) = recovery_cert {
        let active_pool = derive_active_pool(state);
        if verify_recovery_cert(
            cert,
            network,
            &active_pool,
            state.last_recovery_cert.as_ref(),
        ) {
            let excluded: BTreeSet<ValidatorId> =
                cert.excluded_validators().iter().copied().collect();
            let transition = resample_beacon_committee(state, &excluded, TransitionCause::Recovery);
            state.last_recovery_cert = Some(cert.clone());
            return transition;
        }
    }
    resample_beacon_committee(state, &BTreeSet::new(), TransitionCause::NaturalShuffle)
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{Bls12381G1PrivateKey, Epoch, TransitionCause, ValidatorId};

    use super::super::test_fixtures::{keypair, net, single_pool_state};
    use super::*;
    use crate::constants::BEACON_SIGNER_COUNT;

    // ─── apply_epoch regression check + epoch advance ──────────────────────

    /// `apply_epoch` rejects a epoch that doesn't strictly advance
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
                recovery_cert: None,
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
                recovery_cert: None,
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
                recovery_cert: None,
            },
        );
        apply_epoch(
            &mut state,
            &net(),
            Epoch::new(3),
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: None,
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
                recovery_cert: None,
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
        // Skip never threads a recovery cert through commit.
        assert!(state.last_recovery_cert.is_none());
    }

    /// Empty-Normal and Skip diverge only on `TransitionCause`. The
    /// rest of `SlotEffects` and the post-state should be identical
    /// because the pipeline runs over the same inputs (empty
    /// proposals, no recovery cert, same randomness).
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
                recovery_cert: None,
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

    // ─── apply_epoch recovery-cert integration ───────────────────────────

    use hyperscale_types::{
        BeaconBlockHash, Bls12381G2Signature, Hash, RecoveryCertificate, RecoveryRound,
        SignerBitfield, recovery_request_message,
    };

    /// Build a real `RecoveryCertificate` signed by the first
    /// `signer_count` validators (their keypairs match the ones
    /// `single_pool_state` installs via `validator_record`).
    fn build_recovery_cert(
        pool_size: usize,
        signer_count: usize,
        anchor_hash: BeaconBlockHash,
        anchor_epoch: Epoch,
        round: RecoveryRound,
        excluded: Vec<ValidatorId>,
    ) -> RecoveryCertificate {
        let keys: Vec<Bls12381G1PrivateKey> = (0..pool_size).map(|i| keypair(i as u64)).collect();
        let msg = recovery_request_message(&net(), &anchor_hash, anchor_epoch, round);
        let sigs: Vec<Bls12381G2Signature> = keys
            .iter()
            .take(signer_count)
            .map(|sk| sk.sign_v1(&msg))
            .collect();
        let aggregate_sig =
            Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate succeeds");
        let mut signers = SignerBitfield::new(pool_size);
        for i in 0..signer_count {
            signers.set(i);
        }
        RecoveryCertificate::new(
            anchor_hash,
            anchor_epoch,
            round,
            excluded,
            signers,
            aggregate_sig,
        )
    }

    /// A valid recovery cert flips the committee transition to
    /// `Recovery` and is recorded in `state.last_recovery_cert`.
    #[test]
    fn apply_epoch_with_valid_cert_installs_recovery_committee() {
        let mut state = single_pool_state(7);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"));
        // 7 active validators; quorum = ⌈14/3⌉+1 = 6. Cert signed by all 7.
        let cert = build_recovery_cert(
            7,
            7,
            anchor,
            Epoch::GENESIS,
            RecoveryRound::new(0),
            Vec::new(),
        );
        let next = state.current_epoch.next();
        let effects = apply_epoch(
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: Some(&cert),
            },
        );

        let transition = effects
            .beacon_committee_transition
            .expect("recovery emits a transition");
        assert_eq!(transition.cause, TransitionCause::Recovery);
        assert_eq!(transition.at_slot, next);
        assert_eq!(
            state
                .last_recovery_cert
                .as_ref()
                .map(RecoveryCertificate::recovery_round),
            Some(RecoveryRound::new(0)),
        );
        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
    }

    /// `excluded_validators` are filtered out of the recovery-sampling
    /// input — they never land in the resampled committee.
    #[test]
    fn apply_epoch_with_cert_excludes_validators_from_committee() {
        let mut state = single_pool_state(7);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"));
        // Exclude validators 0 and 1.
        let excluded = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let cert = build_recovery_cert(
            7,
            7,
            anchor,
            Epoch::GENESIS,
            RecoveryRound::new(0),
            excluded.clone(),
        );
        let next = state.current_epoch.next();
        apply_epoch(
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: Some(&cert),
            },
        );

        for ex in &excluded {
            assert!(
                !state.committee.contains(ex),
                "excluded validator {ex:?} landed in committee"
            );
        }
        // Committee is sized to BEACON_SIGNER_COUNT (=4); 5 remaining
        // eligibles (2,3,4,5,6) cover that with one to spare.
        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
    }

    /// A cert that fails verification (here: below quorum) falls
    /// through to the normal resample — natural-shuffle transition,
    /// `last_recovery_cert` unchanged.
    #[test]
    fn apply_epoch_with_invalid_cert_falls_through_to_normal_resample() {
        let mut state = single_pool_state(7);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"));
        // Below quorum: only 3 signers in a pool of 7 (quorum is 6).
        let cert = build_recovery_cert(
            7,
            3,
            anchor,
            Epoch::GENESIS,
            RecoveryRound::new(0),
            Vec::new(),
        );
        let next = state.current_epoch.next();
        let effects = apply_epoch(
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: Some(&cert),
            },
        );

        let transition = effects.beacon_committee_transition.unwrap();
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert!(state.last_recovery_cert.is_none());
    }

    /// Round monotonicity: a second cert at the same anchor with a
    /// non-advancing round is rejected. The first cert is recorded;
    /// the second falls through to natural resample and doesn't
    /// overwrite `last_recovery_cert`.
    #[test]
    fn apply_epoch_rejects_non_monotonic_recovery_round() {
        let mut state = single_pool_state(7);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"));

        // First cert at round 2 lands.
        let first = build_recovery_cert(
            7,
            7,
            anchor,
            Epoch::GENESIS,
            RecoveryRound::new(2),
            Vec::new(),
        );
        let next = state.current_epoch.next();
        apply_epoch(
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: Some(&first),
            },
        );
        assert_eq!(
            state
                .last_recovery_cert
                .as_ref()
                .map(RecoveryCertificate::recovery_round),
            Some(RecoveryRound::new(2)),
        );

        // Second cert at same anchor, round 2 — must not advance state.
        let replay = build_recovery_cert(
            7,
            7,
            anchor,
            Epoch::GENESIS,
            RecoveryRound::new(2),
            Vec::new(),
        );
        let next = state.current_epoch.next();
        let effects = apply_epoch(
            &mut state,
            &net(),
            next,
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: Some(&replay),
            },
        );
        let transition = effects.beacon_committee_transition.unwrap();
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        // last_recovery_cert still holds the first cert.
        assert_eq!(
            state
                .last_recovery_cert
                .as_ref()
                .map(RecoveryCertificate::recovery_round),
            Some(RecoveryRound::new(2)),
        );
    }
}
