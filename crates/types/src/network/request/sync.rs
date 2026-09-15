//! Sync-related request messages.

use hyperscale_hbor::Hbor;

use crate::{BlockHeight, ConsensusSignature, MessageClass, NetworkMessage, ValidatorId};

/// Broadcast that validator has caught up to network head and is ready to participate.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SyncCompleteAnnouncement {
    /// Height synced to
    pub(crate) synced_height: BlockHeight,

    /// Validator announcing sync completion
    pub(crate) validator: ValidatorId,

    /// Signature proving this is authentic
    pub(crate) signature: ConsensusSignature,
}

impl SyncCompleteAnnouncement {
    /// Create a new sync complete announcement.
    #[must_use]
    pub const fn new(
        synced_height: BlockHeight,
        validator: ValidatorId,
        signature: ConsensusSignature,
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

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_complete_announcement() {
        let announcement = SyncCompleteAnnouncement::new(
            BlockHeight::new(100),
            ValidatorId::new(1),
            ConsensusSignature::ZERO,
        );
        assert_eq!(announcement.synced_height, BlockHeight::new(100));
        assert_eq!(announcement.validator, ValidatorId::new(1));
    }
}
