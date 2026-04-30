//! Persisted receipt — consensus portion plus optional local metadata.

use crate::{ConsensusReceipt, ExecutionMetadata, TxHash};

/// A persisted receipt: consensus-bound portion paired with optional
/// local-only metadata.
///
/// `metadata` is `None` when this receipt was received from a peer (sync
/// or catch-up) — peers don't ship their local logs/fees/errors. When
/// the local node executed the transaction, `metadata` is `Some`.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct StoredReceipt {
    /// Hash of the executed transaction this receipt belongs to.
    pub tx_hash: TxHash,
    /// Consensus-bound portion (transferable across peers, hash-stable).
    pub consensus: ConsensusReceipt,
    /// Local-only execution metadata (fees, logs, errors). Only
    /// populated for transactions this node executed locally.
    pub metadata: Option<ExecutionMetadata>,
}

impl StoredReceipt {
    /// Construct a synced receipt — consensus only, no local metadata.
    /// Use at sync-ingress sites where peer-shipped receipts arrive
    /// without their originator's logs/fees/errors.
    #[must_use]
    pub const fn synced(tx_hash: TxHash, consensus: ConsensusReceipt) -> Self {
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
    use crate::{ApplicationEvent, DatabaseUpdates, FeeSummary, GlobalReceiptHash, Hash};

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }
    }

    #[test]
    fn synced_receipt_has_no_metadata() {
        let synced = StoredReceipt {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"synced_tx")),
            consensus: ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: DatabaseUpdates::default(),
                application_events: vec![make_event(1)],
            },
            metadata: None,
        };
        assert!(synced.metadata.is_none());
    }

    #[test]
    fn locally_executed_receipt_carries_metadata() {
        let local = StoredReceipt {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"local_tx")),
            consensus: ConsensusReceipt::Failed,
            metadata: Some(ExecutionMetadata {
                fee_summary: FeeSummary {
                    total_execution_cost: vec![],
                    total_royalty_cost: vec![],
                    total_storage_cost: vec![],
                    total_tipping_cost: vec![],
                },
                log_messages: vec![],
                error_message: Some("test error".into()),
            }),
        };
        assert!(local.metadata.is_some());
        assert!(!local.consensus.is_success());
    }
}
