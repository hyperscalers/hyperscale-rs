//! Beacon-proposal notification — one committee member's per-epoch
//! submission, unicast to the rest of the beacon committee.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{BeaconProposal, Epoch, MessageClass, NetworkMessage, ValidatorId, Verifiable};

/// One committee member's [`BeaconProposal`] sent to the rest of the
/// beacon committee for the current epoch.
///
/// The proposal is self-authenticating via its embedded VRF reveal —
/// `proposal.vrf_proof()` is a signature over `(network, epoch)`
/// verifiable under `sender`'s pubkey. Receivers gate admission on
/// the verify result; a tampered `sender` or `epoch` shifts the
/// signing bytes and the VRF check fails.
///
/// Wire decode lands the wrapper as `Verifiable::Unverified`;
/// locally-dispatched sends from a colocated proposer preserve
/// `Verifiable::Verified`.
///
/// `MessageClass::Consensus` — proposal arrival is round-blocking:
/// SPC's view-1 input vector commits to each peer's proposal, so a
/// silent peer drags the input toward `PcValueElement::BOTTOM` and degrades
/// agreement throughput until they show up or the view rotates.
///
/// Unicast (not gossip) because the audience is exactly the beacon
/// committee — bounded at `BEACON_SIGNER_COUNT`. Gossipsub's flood
/// overhead isn't justified at that fanout.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BeaconProposalNotification {
    /// Claimed sender. The VRF reveal and body signature inside
    /// `proposal` authenticate it — receivers verify both against this
    /// validator's pubkey.
    pub sender: ValidatorId,
    /// Epoch this proposal targets. Bound by the VRF reveal's
    /// `(network, epoch)` signing context.
    pub epoch: Epoch,
    /// The proposal: witnesses + VRF reveal.
    pub proposal: Arc<Verifiable<BeaconProposal>>,
}

impl BeaconProposalNotification {
    /// Wrap a [`BeaconProposal`] for committee-internal unicast.
    /// Accepts a raw proposal or a `Verified<BeaconProposal>` — the
    /// wrapper preserves the marker.
    #[must_use]
    pub fn new(
        sender: ValidatorId,
        epoch: Epoch,
        proposal: impl Into<Arc<Verifiable<BeaconProposal>>>,
    ) -> Self {
        Self {
            sender,
            epoch,
            proposal: proposal.into(),
        }
    }
}

impl NetworkMessage for BeaconProposalNotification {
    fn message_type_id() -> &'static str {
        "beacon.proposal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::VrfProof;

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::vrf_only(VrfProof::new([0x22; 96]))
    }

    #[test]
    fn hbor_round_trip() {
        let n = BeaconProposalNotification::new(
            ValidatorId::new(3),
            Epoch::new(7),
            Arc::new(Verifiable::from(sample_proposal())),
        );
        let bytes = hbor_to_vec(&n).unwrap();
        let decoded: BeaconProposalNotification = hbor_from_slice(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(BeaconProposalNotification::class(), MessageClass::Consensus);
    }
}
