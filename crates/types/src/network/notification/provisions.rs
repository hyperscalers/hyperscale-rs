//! `ProvisionsNotification` message for cross-shard provisions.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    BlockHeight, ConsensusSignature, MAX_TXS_PER_BLOCK, MessageClass, NetworkDefinition,
    NetworkMessage, Provision, ProvisionsSenderMessage, ShardId, Signed, ValidatorId, Verifiable,
    signed_bytes,
};

/// Some of one source block's parts for one target shard, packed under
/// one signature.
///
/// Only the block proposer sends these. The sender signature authenticates
/// the notification, allowing receivers to reject forged parts before
/// doing expensive merkle proof verification. A block's parts for a
/// target ride in as many notifications as the frame needs; each part
/// stands on its own once it lands.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ProvisionsNotification {
    /// The shard the parts were produced on.
    pub source_shard: ShardId,
    /// The shard the parts serve.
    pub target_shard: ShardId,
    /// The source block the parts were read at.
    pub block_height: BlockHeight,
    /// The packed parts, each naming the scope above. Wire bytes always
    /// land in `Verifiable::Unverified`; local-dispatched sends from a
    /// colocated proposer preserve `Verifiable::Verified`.
    pub parts: Capped<Vec<Verifiable<Provision>>, MAX_TXS_PER_BLOCK>,
    /// The validator who sent this notification.
    pub(crate) sender: ValidatorId,
    /// Signature over the domain-separated signing message, by the sender.
    pub(crate) sender_signature: ConsensusSignature,
}

impl ProvisionsNotification {
    /// Create a new signed provisions notification.
    #[must_use]
    pub const fn new(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        parts: Capped<Vec<Verifiable<Provision>>, MAX_TXS_PER_BLOCK>,
        sender: ValidatorId,
        sender_signature: ConsensusSignature,
    ) -> Self {
        Self {
            source_shard,
            target_shard,
            block_height,
            parts,
            sender,
            sender_signature,
        }
    }

    /// Whether every packed part names the notification's own scope.
    #[must_use]
    pub fn is_uniform(&self) -> bool {
        self.parts.iter().all(|part| {
            let part = part.as_unverified();
            part.source_shard() == self.source_shard
                && part.target_shard() == self.target_shard
                && part.block_height() == self.block_height
        })
    }
}

impl Signed for ProvisionsNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &ProvisionsSenderMessage::new(
                self.source_shard,
                self.target_shard,
                self.block_height,
                self.parts.iter().map(Verifiable::as_unverified),
            ),
            network,
        )
    }
}

impl NetworkMessage for ProvisionsNotification {
    fn message_type_id() -> &'static str {
        "provisions.broadcast"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
