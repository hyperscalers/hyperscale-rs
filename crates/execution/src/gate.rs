//! The one gate an arriving certificate passes on its way to the crypto
//! pool, whether it arrives alone or inside a fetched finalization.
//!
//! Every certificate is held to the same four checks: the halt-recovery
//! band, the committee its anchor resolves, that committee's quorum
//! power, and its keys. What differs between the two arrivals is what
//! the slot is keyed by, which is what [`Attested`] says.

use hyperscale_types::{
    ConsensusPublicKey, ExecutionCertificate, Finalization, Hash, ScheduleLookup, TickId,
    TopologySchedule, Verifiable,
};

use crate::lookups::{committee_public_keys_for_shard, ec_has_shard_quorum_power};

/// An arrival carrying a certificate to verify: one alone, or a
/// finalization's own, which a legs half does not carry.
pub trait Attested {
    /// The content hash an in-flight verification is keyed by, so a
    /// byte-identical retransmit does not dispatch twice. Different
    /// aggregations of one logical certificate hash differently and
    /// each dispatch — a first with a bad signature may be followed by
    /// a valid one.
    fn slot(&self) -> Hash;

    /// The tick the artifact is about, for the log.
    fn tick_id(&self) -> &TickId;

    /// The certificate the artifact carries, if any.
    fn certificate(&self) -> Option<&ExecutionCertificate>;
}

impl Attested for Verifiable<ExecutionCertificate> {
    fn slot(&self) -> Hash {
        self.wire_hash()
    }

    fn tick_id(&self) -> &TickId {
        ExecutionCertificate::tick_id(self)
    }

    fn certificate(&self) -> Option<&ExecutionCertificate> {
        Some(self.as_unverified())
    }
}

impl Attested for Verifiable<Finalization> {
    /// A tick can settle in more than one part, so identity is the
    /// finalization's own content.
    fn slot(&self) -> Hash {
        self.receipt_hash().into_raw()
    }

    fn tick_id(&self) -> &TickId {
        Finalization::tick_id(self)
    }

    fn certificate(&self) -> Option<&ExecutionCertificate> {
        Finalization::certificate(self).map(Verifiable::as_unverified)
    }
}

/// Why the gate did not hand back keys.
///
/// One vocabulary for both halves of the gate: what [`gate_certificate`]
/// answers for one certificate, and what an artifact's whole pass
/// answers for the one it carries, if any. The artifact half adds
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
/// The recovery band first ([`TopologySchedule::recovery_orphaned`]): a
/// certificate anchored below a bridge of its shard's recovery, at a
/// height above that recovery's frontier, is the replaced committee's
/// over a tick the recovered chain discards, or one it certified after
/// the halt. Its anchor resolves the replaced committee and its
/// signatures verify, and it carries no block hash: the recovered chain
/// commits a new block at that height, whose tick has the same
/// [`TickId`], so past the band the stale certificate would stand as the
/// new tick's own, ending its votes and retries, and answering its late
/// voters, over outcomes the new tick never ran. The band is the only
/// refusal of such a certificate, during the recovery and after it, and
/// nothing else refuses a certificate anchored at or past the bridge:
/// that one resolves the fresh committee and verifies only under its
/// keys. Then the committee that attests its tick on its own shard,
/// which its anchor resolves: below the schedule floor it is past its
/// retention horizon, provably terminal everywhere and never resolvable
/// again, and in a window its shard had already left nobody was seated
/// to attest it. Then that committee's quorum power — a single Byzantine
/// signer produces a cryptographically valid certificate — and its keys.
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
    if schedule.recovery_orphaned(shard, ec.vote_anchor_ts(), ec.block_height()) {
        return Err(Gate::Refused(
            "anchored below a recovery's bridge above its frontier",
        ));
    }
    let committee = match schedule.lookup_for_shard(shard, ec.vote_anchor_ts()) {
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
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        AggregateSignature, BlockHeight, Epoch, EpochWindows, GlobalReceiptRoot, NetworkDefinition,
        RecoveryBinding, RecoveryCause, ShardId, ShardRecovery, Signer, SignerBitfield, TickId,
        TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, WeightedTimestamp,
    };

    use super::*;

    /// The recovered shard's frontier.
    const FRONTIER: BlockHeight = BlockHeight::new(5);

    /// A schedule of one-second windows over one shard recovered at
    /// [`FRONTIER`]: its replaced committee (validators 0 to 3) seated
    /// from epoch 2, the fresh one (4 to 7) at epoch 20, bridge 21, the
    /// recovery pending or its record cleared. Beside it, each
    /// committee's keys.
    fn recovered(
        pending: bool,
    ) -> (
        TopologySchedule,
        Vec<ConsensusPublicKey>,
        Vec<ConsensusPublicKey>,
    ) {
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
        let snap = |committee: &[ValidatorId]| {
            let mut snapshot = TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                1,
                &set,
                std::iter::once((shard, committee.to_vec())).collect(),
            )
            .with_recoveries(
                std::iter::once((
                    shard,
                    vec![RecoveryBinding {
                        rotated_at: Epoch::new(20),
                        attested_frontier: FRONTIER,
                        completed: !pending,
                    }],
                ))
                .collect(),
            );
            if pending {
                snapshot = snapshot.with_pending_recoveries(
                    std::iter::once((
                        shard,
                        ShardRecovery {
                            cause: RecoveryCause::Halt,
                            rotated_at: Epoch::new(20),
                            retained: Vec::new(),
                            attested_frontier: FRONTIER,
                        },
                    ))
                    .collect(),
                );
            }
            Arc::new(snapshot)
        };
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1_000), Epoch::new(2), snap(&old));
        schedule.insert(Epoch::new(21), snap(&fresh));
        schedule.set_head(snap(&fresh));
        let keys_of = |committee: &[ValidatorId]| -> Vec<ConsensusPublicKey> {
            committee
                .iter()
                .map(|&v| schedule.head().public_key(v).expect("known validator"))
                .collect()
        };
        let (old, fresh) = (keys_of(&old), keys_of(&fresh));
        (schedule, old, fresh)
    }

    /// A certificate of the recovered shard's tick at `height`, anchored
    /// at `anchor_ms`, signed by a quorum of the committee it addresses.
    fn certificate(height: BlockHeight, anchor_ms: u64) -> ExecutionCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, height),
            WeightedTimestamp::from_millis(anchor_ms),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        )
    }

    /// A certificate's committee is what its own anchor resolves,
    /// permanently: after a halt recovery has folded, one the replaced
    /// committee formed at the attested frontier still verifies against
    /// that committee's keys, and one above the frontier anchored below
    /// the bridge, the recovered chain's discarded tail, is refused.
    #[test]
    fn a_folded_recovery_keeps_the_frontier_certificate_verifiable() {
        let (schedule, old, _) = recovered(false);
        assert_eq!(
            gate_certificate(&schedule, &certificate(FRONTIER, 2_500)),
            Ok(old),
            "a frontier certificate keeps the committee that formed it",
        );
        assert!(
            matches!(
                gate_certificate(&schedule, &certificate(FRONTIER.next(), 2_500)),
                Err(Gate::Refused(_))
            ),
            "a tail certificate is refused",
        );
    }

    /// A certificate the replaced committee formed above the frontier and
    /// dated below the bridge is refused while the recovery is pending
    /// and once its record clears: one for a tick the crossing block
    /// discards, one for a tick of the tail the harvest lost, and one for
    /// an orphan extension the retained cohort certified after the halt,
    /// dated just under the bridge.
    #[test]
    fn a_replaced_committees_certificate_above_the_frontier_is_refused_once_the_record_clears() {
        for pending in [true, false] {
            let (schedule, _, _) = recovered(pending);
            for (label, height, anchor_ms) in [
                ("a discarded tick", 6, 2_500),
                ("a lost-tail tick", 30, 3_000),
                ("an orphan extension", 60, 20_900),
            ] {
                assert_eq!(
                    gate_certificate(&schedule, &certificate(BlockHeight::new(height), anchor_ms)),
                    Err(Gate::Refused(
                        "anchored below a recovery's bridge above its frontier"
                    )),
                    "pending {pending}: {label}",
                );
            }
        }
    }

    /// A certificate dated at or past the bridge resolves the fresh
    /// committee, whatever its height and whichever cohort signed it, so
    /// the replaced committee's signatures verify under no key it gets:
    /// while the recovery is pending a fresh certificate there passes the
    /// gate, and a replaced one re-dated there is held to the fresh keys.
    #[test]
    fn a_replaced_committees_certificate_dated_past_the_bridge_fails_its_keys() {
        for pending in [true, false] {
            let (schedule, old, fresh) = recovered(pending);
            let keys = gate_certificate(&schedule, &certificate(BlockHeight::new(60), 21_100));
            assert_eq!(keys.as_ref(), Ok(&fresh), "pending {pending}");
            assert_ne!(keys, Ok(old), "pending {pending}");
        }
    }
}
