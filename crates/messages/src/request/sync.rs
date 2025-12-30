//! Sync-related request messages.

use hyperscale_types::{
    BlockHeight, Bls12381G2Signature, MessagePriority, NetworkMessage, ShardMessage, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Broadcast that validator has caught up to network head and is ready to participate.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SyncCompleteAnnouncement {
    /// Height synced to
    pub synced_height: BlockHeight,

    /// Validator announcing sync completion
    pub validator: ValidatorId,

    /// Signature proving this is authentic (BLS for aggregatable consensus)
    pub signature: Bls12381G2Signature,
}

impl SyncCompleteAnnouncement {
    /// Create a new sync complete announcement.
    pub fn new(
        synced_height: BlockHeight,
        validator: ValidatorId,
        signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            synced_height,
            validator,
            signature,
        }
    }
}

// Network message implementation
impl NetworkMessage for SyncCompleteAnnouncement {
    fn message_type_id() -> &'static str {
        "sync.complete"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

impl ShardMessage for SyncCompleteAnnouncement {}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::zero_bls_signature;

    #[test]
    fn test_sync_complete_announcement() {
        let announcement =
            SyncCompleteAnnouncement::new(BlockHeight(100), ValidatorId(1), zero_bls_signature());
        assert_eq!(announcement.synced_height, BlockHeight(100));
        assert_eq!(announcement.validator, ValidatorId(1));
    }
}
