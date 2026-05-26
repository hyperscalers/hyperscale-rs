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

/// Apply one epoch's SPC commit to `state`.
///
/// `committed` is the per-epoch proposals SPC's Agreement layer has
/// agreed on. Pure deterministic function of `(state, network, epoch,
/// committed)` — every honest party with byte-identical inputs lands
/// at byte-identical state.
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
    committed: &[(ValidatorId, BeaconProposal)],
    recovery_cert: Option<&RecoveryCertificate>,
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

    let vrf = filter_and_roll_randomness(state, network, epoch, committed);
    let witness = ingest_witnesses(state, network, &vrf.accepted);
    let withdrawal = complete_pending_withdrawals(state);
    let reactivated = auto_reactivate(state);
    let rewards_credited = distribute_epoch_rewards(state);
    let timeout_readied = auto_ready_timeout(state);
    run_shuffle_step(state);
    let beacon_committee_transition = apply_recovery_or_resample(state, network, recovery_cert);

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

/// Resample the beacon committee.
///
/// Recovery path: `recovery_cert` is `Some` and verifies — install
/// the replacement committee with exclusion-aware sampling against
/// the cert's `excluded_validators`. Natural path: no cert, or the
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
