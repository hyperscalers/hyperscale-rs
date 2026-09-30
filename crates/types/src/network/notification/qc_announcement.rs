//! QC announcement notification message.

use hyperscale_hbor::Hbor;

use crate::network::Signed;
use crate::signing::QcAnnouncementMessage;
use crate::{
    ConsensusSignature, MessageClass, NetworkDefinition, NetworkMessage, QuorumCertificate,
    ValidatorId, signed_bytes,
};

/// A just-formed QC, broadcast by the certified block's proposer to its
/// committee.
///
/// Votes reach only the block's proposer and the next two, so without it
/// the rest of the committee learns the QC only from the next header, and
/// a next leader that withholds both lets their round timers fire on a
/// round a quorum certified.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct QcAnnouncementNotification {
    /// The announced QC — self-authenticating, verified where adopted.
    pub qc: QuorumCertificate,
    /// The validator announcing it.
    pub sender: ValidatorId,
    /// The sender's signature over [`QcAnnouncementMessage`].
    pub sender_signature: ConsensusSignature,
}

impl Signed for QcAnnouncementNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &QcAnnouncementMessage {
                shard_id: self.qc.shard_id(),
                round: self.qc.round(),
                block_hash: self.qc.block_hash(),
            },
            network,
        )
    }
}

impl NetworkMessage for QcAnnouncementNotification {
    fn message_type_id() -> &'static str {
        "shard.qc"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}
