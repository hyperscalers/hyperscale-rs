//! VRF reveal verification + randomness roll + the shared
//! [`jail_validator`] cascade primitive.

use std::collections::BTreeSet;

use blake3::Hasher;
use hyperscale_types::{
    BeaconProposal, BeaconState, Epoch, JailReason, NetworkDefinition, Randomness, ValidatorId,
    ValidatorStatus, VrfOutput, vrf_verify,
};

use crate::state::pool::pool_draw;

/// Domain tag for the beacon-randomness mixer. Binds the BLAKE3 input
/// to "beacon randomness v1" so the digest can't collide with any
/// other 32-byte BLAKE3 hash in the codebase (committee draw seed,
/// pool draw seed, etc.).
const DOMAIN_BEACON_RANDOMNESS: &[u8] = b"hyperscale-beacon-randomness-v1";

/// Outcome of [`filter_and_roll_randomness`]. The borrowed `accepted`
/// slice lets [`super::witness::ingest_witnesses`] iterate the proposals
/// that survived the VRF check without re-running the filter.
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
/// jail proposers whose reveals were rejected.
///
/// `state.randomness` advances *always* — even when no proposal is
/// accepted, the BLAKE3 mix runs against the prior randomness alone.
/// An "all-rejected" epoch still advances randomness as a
/// deterministic function of `prev_randomness`. An adversary who can
/// suppress every VRF reveal can therefore predict the next epoch's
/// randomness from the previous one; the mitigation is the
/// jail-on-first-sighting cascade here plus committee resampling at
/// epoch boundaries.
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
        let output = prop.vrf_output();
        let proof = prop.vrf_proof();
        if vrf_verify(&pk, network, epoch, &output, &proof) {
            accepted_outputs.push(output);
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
    state.randomness = Randomness(*h.finalize().as_bytes());

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

    VrfStageOutcome {
        accepted,
        rejected_reveals,
        jailed,
    }
}

/// Transition `victim` to `Jailed { since_epoch, reason }` and run
/// the shared cleanup: clear any per-validator state scoped to their
/// old placement (currently [`BeaconState::miss_counters`]); if they
/// were `OnShard`, remove from that shard's committee and draw a
/// refill from the global pool.
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
    let prior_status = rec.status;
    rec.status = ValidatorStatus::Jailed {
        since_epoch,
        reason,
    };
    state.miss_counters.remove(&victim);
    if let ValidatorStatus::OnShard { shard, .. } = prior_status {
        if let Some(committee) = state.shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != victim);
        }
        pool_draw(state, shard);
    }
}
