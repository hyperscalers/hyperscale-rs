//! The one gate a fetched certificate passes on its way to the crypto
//! pool, whether it arrives alone or inside a finalization.
//!
//! Every contained certificate is held to the same four checks: the
//! halt-recovery freeze, the committee its anchor resolves, that
//! committee's quorum power, and its keys. What differs between the two
//! arrivals is what the slot is keyed by and what a refusal releases,
//! which is what [`Attested`] says.

use std::sync::Arc;

use hyperscale_core::FetchIds;
use hyperscale_types::{
    ConsensusPublicKey, ExecutionCertificate, Finalization, Hash, ScheduleLookup, TickId,
    TopologySchedule, Verifiable,
};

use crate::lookups::{
    committee_public_keys_for_shard, ec_has_shard_quorum_power, fetch_keys_covered,
};

/// A fetched artifact carrying certificates to verify: one, or a
/// finalization's several.
pub trait Attested {
    /// The content hash an in-flight verification is keyed by, so a
    /// byte-identical retransmit does not dispatch twice. Different
    /// aggregations of one logical certificate hash differently and
    /// each dispatch — a first with a bad signature may be followed by
    /// a valid one.
    fn slot(&self) -> Hash;

    /// The tick the artifact is about, for the log.
    fn tick_id(&self) -> &TickId;

    /// Every certificate the artifact carries, in the order the keys are
    /// returned in.
    fn certificates(&self) -> impl Iterator<Item = &ExecutionCertificate>;

    /// What refusing the artifact releases: it answers for nothing it
    /// claimed, so each claim goes back to being fetchable.
    fn abandon(&self) -> FetchIds;
}

impl Attested for Verifiable<ExecutionCertificate> {
    fn slot(&self) -> Hash {
        self.wire_hash()
    }

    fn tick_id(&self) -> &TickId {
        ExecutionCertificate::tick_id(self)
    }

    fn certificates(&self) -> impl Iterator<Item = &ExecutionCertificate> {
        std::iter::once(self.as_unverified())
    }

    fn abandon(&self) -> FetchIds {
        FetchIds::ExecutionCerts(fetch_keys_covered(self))
    }
}

impl Attested for Arc<Verifiable<Finalization>> {
    /// A tick can settle in more than one part, so identity is the
    /// finalization's own content.
    fn slot(&self) -> Hash {
        self.receipt_hash().into_raw()
    }

    fn tick_id(&self) -> &TickId {
        Finalization::tick_id(self)
    }

    fn certificates(&self) -> impl Iterator<Item = &ExecutionCertificate> {
        self.execution_certificates()
            .iter()
            .map(|ec| ec.as_unverified())
    }

    fn abandon(&self) -> FetchIds {
        FetchIds::Finalizations(vec![self.receipt_hash()])
    }
}

/// Why the gate did not hand back keys.
///
/// One vocabulary for both halves of the gate: what [`gate_certificate`]
/// answers for one certificate, and what an artifact's whole pass
/// answers for the several it carries. The artifact half adds
/// [`Self::InFlight`], which is a fact about the dispatch rather than
/// about any certificate, so a single certificate never meets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// A byte-identical dispatch is already running. Never answered for
    /// a single certificate.
    InFlight,
    /// This node's beacon has not reached the certificate's committee
    /// epoch, so the signing committee cannot be resolved yet. Pure
    /// catch-up: under lookahead the committee is already globally
    /// fixed, so the certificate is parked for replay rather than
    /// refused.
    BeaconBehind,
    /// Refused for good, with why.
    Refused(&'static str),
}

/// Hold one certificate to the checks every arrival passes before its
/// signature is worth verifying.
///
/// The halt-recovery freeze first: a certificate from a recovering
/// shard above the beacon-attested frontier is one the retained
/// beyond-f committee could only have produced after the halt. It
/// resolves the old committee at its stale anchor and its signatures
/// verify, so without this fence a forged finalization would export
/// cross-shard. Then the committee that attests its tick on its own
/// shard, which its anchor and height resolve: below the schedule floor
/// it is past its retention horizon, provably terminal everywhere and
/// never resolvable again, and in a window its shard had already left
/// nobody was seated to attest it. Then that committee's quorum power —
/// a single Byzantine signer produces a cryptographically valid
/// certificate — and its keys.
///
/// The fence stays ahead of the lookup although the lookup enforces it
/// too once the record clears — a replaced-committee certificate above
/// the frontier binds to the fresh committee and fails its signature —
/// because the fence's refusal is the diagnosis.
///
/// # Errors
///
/// The [`Gate`] the certificate did not pass — never [`Gate::InFlight`],
/// which is the dispatch's fact and not a certificate's.
pub fn gate_certificate(
    schedule: &TopologySchedule,
    ec: &ExecutionCertificate,
) -> Result<Vec<ConsensusPublicKey>, Gate> {
    let shard = ec.shard_id();
    if schedule.recovery_fences(shard, ec.block_height()) {
        return Err(Gate::Refused(
            "from a recovering shard past the freeze frontier",
        ));
    }
    let committee =
        match schedule.lookup_for_shard_anchored(shard, ec.vote_anchor_ts(), ec.block_height()) {
            (ScheduleLookup::Committee(committee), false) => committee,
            (ScheduleLookup::NotYetCommitted, _) => return Err(Gate::BeaconBehind),
            (ScheduleLookup::Evicted, false) => {
                return Err(Gate::Refused("committee epoch below the schedule floor"));
            }
            (_, true) => {
                return Err(Gate::Refused(
                    "anchored in a window its shard had already left",
                ));
            }
        };
    if !ec_has_shard_quorum_power(committee, ec) {
        return Err(Gate::Refused("lacks quorum power on its shard"));
    }
    committee_public_keys_for_shard(committee, shard).ok_or(Gate::Refused(
        "committee keys unresolvable — snapshot incomplete",
    ))
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{
        AggregateSignature, BlockHeight, CompletedRecovery, Epoch, GlobalReceiptRoot,
        NetworkDefinition, ShardId, Signer, SignerBitfield, TopologySnapshot, ValidatorId,
        ValidatorInfo, ValidatorSet, WeightedTimestamp,
    };

    use super::*;

    /// A certificate's committee is what its own anchor and height
    /// resolve, permanently: after a halt recovery has folded, one the
    /// replaced committee formed at the attested frontier still verifies
    /// against that committee's keys, and one above the frontier binds
    /// to the fresh committee's.
    #[test]
    fn a_folded_recovery_keeps_the_frontier_certificate_verifiable() {
        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::ROOT;
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let fresh: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let frontier = BlockHeight::new(5);
        let snap = |committee: &[ValidatorId]| {
            Arc::new(
                TopologySnapshot::with_shard_committees(
                    NetworkDefinition::simulator(),
                    1,
                    &set,
                    std::iter::once((shard, committee.to_vec())).collect(),
                )
                .with_completed_recoveries(
                    std::iter::once((
                        shard,
                        CompletedRecovery {
                            rotated_at: Epoch::new(20),
                            attested_frontier: frontier,
                        },
                    ))
                    .collect(),
                ),
            )
        };
        let mut schedule = TopologySchedule::new(1_000, Epoch::new(2), snap(&old));
        schedule.insert(Epoch::new(21), snap(&fresh));
        schedule.set_head(snap(&fresh));
        let keys_of = |committee: &[ValidatorId]| -> Vec<ConsensusPublicKey> {
            committee
                .iter()
                .map(|&v| schedule.head().public_key(v).expect("known validator"))
                .collect()
        };

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec_at = |height: BlockHeight| {
            ExecutionCertificate::new(
                TickId::new(shard, height),
                WeightedTimestamp::from_millis(2_500),
                GlobalReceiptRoot::ZERO,
                vec![],
                AggregateSignature::ZERO,
                signers.clone(),
            )
        };

        assert_eq!(
            gate_certificate(&schedule, &ec_at(frontier)),
            Ok(keys_of(&old)),
            "a frontier certificate keeps the committee that formed it",
        );
        assert_eq!(
            gate_certificate(&schedule, &ec_at(frontier.next())),
            Ok(keys_of(&fresh)),
            "a tail certificate is positional against the fresh committee",
        );
    }
}
