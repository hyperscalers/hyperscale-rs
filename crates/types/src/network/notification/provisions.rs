//! `ProvisionsNotification` message for cross-shard provisions.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{
    ConsensusSignature, MessageClass, NetworkDefinition, NetworkMessage, Provisions,
    ProvisionsSenderMessage, Signed, ValidatorId, Verifiable, signed_bytes,
};

/// Cross-shard state provisions for one (`source_block`, `target_shard`) pair.
///
/// Only the block proposer sends these. The sender signature authenticates
/// the notification, allowing receivers to reject forged provisions before
/// doing expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ProvisionsNotification {
    /// The provisions bundle being sent (one bundle per target shard).
    /// Wire bytes always land in `Verifiable::Unverified`;
    /// local-dispatched sends from a colocated proposer preserve
    /// `Verifiable::Verified`.
    pub provisions: Arc<Verifiable<Provisions>>,
    /// The validator who sent this notification.
    pub sender: ValidatorId,
    /// Signature over the domain-separated signing message, by the sender.
    pub sender_signature: ConsensusSignature,
}

impl ProvisionsNotification {
    /// Create a new signed provisions notification.
    #[must_use]
    pub fn new(
        provisions: impl Into<Arc<Verifiable<Provisions>>>,
        sender: ValidatorId,
        sender_signature: ConsensusSignature,
    ) -> Self {
        Self {
            provisions: provisions.into(),
            sender,
            sender_signature,
        }
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
            &ProvisionsSenderMessage::new(self.provisions.as_unverified()),
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
