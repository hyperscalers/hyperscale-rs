//! Beacon-proposal gossip — one committee member's per-epoch
//! submission.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{BeaconProposal, Epoch, MessageClass, NetworkMessage, ValidatorId};

/// One committee member's [`BeaconProposal`] gossiped to the rest of
/// the committee for the current beacon epoch.
///
/// The proposal is self-authenticating via its embedded VRF reveal —
/// `proposal.vrf_proof()` is a BLS signature over `(network, epoch)`
/// verifiable under `sender`'s pubkey. Receivers gate admission on
/// the verify result; a tampered `sender` or `epoch` shifts the
/// signing bytes and the VRF check fails.
///
/// `MessageClass::Consensus` — proposal arrival is round-blocking:
/// SPC's view-1 input vector commits to each peer's proposal, so a
/// silent peer drags the input toward `HASH_BOTTOM` and degrades
/// agreement throughput until they show up or the view rotates.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconProposalGossip {
    /// Claimed sender. The VRF reveal inside `proposal` authenticates
    /// it — receivers verify against this validator's pubkey.
    pub sender: ValidatorId,
    /// Epoch this proposal targets. Bound by the VRF reveal's
    /// `(network, epoch)` signing context.
    pub epoch: Epoch,
    /// The proposal: witnesses + VRF reveal.
    pub proposal: Arc<BeaconProposal>,
}

impl BeaconProposalGossip {
    /// Wrap a [`BeaconProposal`] for gossip broadcast.
    #[must_use]
    pub fn new(
        sender: ValidatorId,
        epoch: Epoch,
        proposal: impl Into<Arc<BeaconProposal>>,
    ) -> Self {
        Self {
            sender,
            epoch,
            proposal: proposal.into(),
        }
    }
}

impl NetworkMessage for BeaconProposalGossip {
    fn message_type_id() -> &'static str {
        "beacon.proposal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for BeaconProposalGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{VrfOutput, VrfProof};

    fn sample_proposal() -> BeaconProposal {
        BeaconProposal::vrf_only(VrfOutput([0x11; 32]), VrfProof([0x22; 96]))
    }

    #[test]
    fn sbor_round_trip() {
        let g = BeaconProposalGossip::new(ValidatorId::new(3), Epoch::new(7), sample_proposal());
        let bytes = basic_encode(&g).unwrap();
        let decoded: BeaconProposalGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(BeaconProposalGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(BeaconProposalGossip::SCOPE, TopicScope::Global));
    }
}
