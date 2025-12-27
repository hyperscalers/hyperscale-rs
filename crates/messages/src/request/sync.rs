//! Sync-related request messages.

use hyperscale_types::{
    BlockHeight, MessagePriority, NetworkMessage, ShardMessage, Signature, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Broadcast that validator has caught up to network head and is ready to participate.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SyncCompleteAnnouncement {
    /// Height synced to
    pub synced_height: BlockHeight,

    /// Validator announcing sync completion
    pub validator: ValidatorId,

    /// Signature proving this is authentic
    pub signature: Signature,
}

impl SyncCompleteAnnouncement {
    /// Create a new sync complete announcement.
    pub fn new(synced_height: BlockHeight, validator: ValidatorId, signature: Signature) -> Self {
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

    #[test]
    fn test_sync_complete_announcement() {
        use hyperscale_types::Signature;
        let announcement =
            SyncCompleteAnnouncement::new(BlockHeight(100), ValidatorId(1), Signature::zero());
        assert_eq!(announcement.synced_height, BlockHeight(100));
        assert_eq!(announcement.validator, ValidatorId(1));
    }
}
