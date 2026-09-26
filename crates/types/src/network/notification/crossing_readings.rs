//! `CrossingReadingsNotification`: a producer's push of the crossing
//! records one of its blocks wrote, as self-proving claims.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    Anchor, ConsensusSignature, CrossingReadingsSenderMessage, MAX_STATE_CLAIMS_PER_BLOCK,
    MessageClass, NetworkDefinition, NetworkMessage, ShardId, Signed, StateClaim, ValidatorId,
    signed_bytes,
};

/// The readings one producer block wrote for one consumer shard.
///
/// Every claim sits at the writing block's own anchor, and a member of
/// the committee that proposed it signs the push. At most one block's
/// section: the consumer can carry no more at once.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct CrossingReadingsNotification {
    /// The readings, each a claim at the one anchor.
    pub claims: Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>,
    /// The shard whose committee the push is for: the one owning the
    /// consumer of every record carried.
    pub target_shard: ShardId,
    pub(crate) sender: ValidatorId,
    pub(crate) sender_signature: ConsensusSignature,
}

impl CrossingReadingsNotification {
    /// A push of `claims` to `target_shard`, signed by `sender`.
    #[must_use]
    pub const fn new(
        claims: Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>,
        target_shard: ShardId,
        sender: ValidatorId,
        sender_signature: ConsensusSignature,
    ) -> Self {
        Self {
            claims,
            target_shard,
            sender,
            sender_signature,
        }
    }

    /// The one anchor every claim sits at, or `None` for an empty push
    /// or one mixing anchors, neither of which a producer sends.
    #[must_use]
    pub fn anchor(&self) -> Option<Anchor> {
        let first = self.claims.first()?.anchor;
        self.claims
            .iter()
            .all(|claim| claim.anchor == first)
            .then_some(first)
    }

    /// The bytes the claims would cost a block, summed.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        self.claims.iter().map(StateClaim::wire_weight).sum()
    }
}

impl Signed for CrossingReadingsNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &CrossingReadingsSenderMessage::new(self.target_shard, &self.claims),
            network,
        )
    }
}

impl NetworkMessage for CrossingReadingsNotification {
    fn message_type_id() -> &'static str {
        "crossing.readings"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
