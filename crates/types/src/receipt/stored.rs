//! Persisted receipt — consensus portion plus optional local metadata.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{ConsensusReceipt, ExecutionMetadata, TxHash};

/// A persisted receipt: consensus-bound portion paired with optional
/// local-only metadata.
///
/// `metadata` is `None` when this receipt was received from a peer (sync
/// or catch-up) — peers don't ship their local logs/fees/errors. When
/// the local node executed the transaction, `metadata` is `Some`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StoredReceipt {
    /// Primary key in the per-tx receipt store and the join key against
    /// `WaveCertificate` outcomes during validation.
    pub tx_hash: TxHash,
    /// Shared via `Arc` so flowing a receipt through `PendingChain`,
    /// validation, and persistence is `Arc::clone`-cheap rather than
    /// deep-cloning the substate writes.
    pub consensus: Arc<ConsensusReceipt>,
    /// `Some` ⇔ this node executed the tx locally. Synced-from-peer and
    /// reconstructed receipts are `None` (peers don't ship metadata),
    /// and metadata may also be pruned earlier than the consensus
    /// portion since it's not consensus-critical.
    pub metadata: Option<ExecutionMetadata>,
}

impl StoredReceipt {
    /// Construct a synced receipt — consensus only, no local metadata.
    /// Use at sync-ingress sites where peer-shipped receipts arrive
    /// without their originator's logs/fees/errors.
    #[must_use]
    pub const fn synced(tx_hash: TxHash, consensus: Arc<ConsensusReceipt>) -> Self {
        Self {
            tx_hash,
            consensus,
            metadata: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_event_type_identifier;
    use crate::{
        ApplicationEvent, DatabaseUpdates, EventData, FeeSummary, GlobalReceiptHash, Hash,
    };

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: test_event_type_identifier(seed),
            data: EventData(vec![seed, seed + 1]),
        }
    }

    #[test]
    fn synced_receipt_has_no_metadata() {
        let synced = StoredReceipt::synced(
            TxHash::from_raw(Hash::from_bytes(b"synced_tx")),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: DatabaseUpdates::default(),
                application_events: vec![make_event(1)],
            }),
        );
        assert!(synced.metadata.is_none());
    }

    #[test]
    fn locally_executed_receipt_carries_metadata() {
        let local = StoredReceipt {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"local_tx")),
            consensus: Arc::new(ConsensusReceipt::Failed),
            metadata: Some(ExecutionMetadata::new(
                FeeSummary {
                    total_execution_cost: None,
                    total_royalty_cost: None,
                    total_storage_cost: None,
                    total_tipping_cost: None,
                },
                vec![],
                Some("test error".to_string()),
            )),
        };
        assert!(local.metadata.is_some());
        assert!(!local.consensus.is_success());
    }
}
