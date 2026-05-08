//! `ProvisionsNotification` message for cross-shard provisions.

use sbor::prelude::BasicSbor;

use crate::{
    Bls12381G2Signature, MessageClass, NetworkMessage, Provisions, ValidatorId,
    state_provisions_message,
};

/// Cross-shard state provisions for one (`source_block`, `target_shard`) pair.
///
/// Only the block proposer sends these. The sender signature authenticates
/// the notification, allowing receivers to reject forged provisions before
/// doing expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ProvisionsNotification {
    /// The provisions bundle being sent (one bundle per target shard).
    pub provisions: Provisions,
    /// The validator who sent this notification.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ProvisionsNotification {
    /// Create a new signed provisions notification.
    #[must_use]
    pub const fn new(
        provisions: Provisions,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            provisions,
            sender,
            sender_signature,
        }
    }

    /// Build the canonical signing message for this notification.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        state_provisions_message(&self.provisions)
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
