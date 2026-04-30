//! Persisted receipt — consensus portion plus optional local metadata.

use crate::{ConsensusReceipt, ExecutionMetadata, LocalExecutionEntry, TransactionOutcome, TxHash};

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

impl From<LocalExecutionEntry> for StoredReceipt {
    /// Bridge from the legacy engine-output shape during the
    /// `unify-receipt-types` migration. Removed in the legacy-cleanup commit.
    fn from(entry: LocalExecutionEntry) -> Self {
        let consensus = match entry.local_receipt.outcome {
            TransactionOutcome::Success => ConsensusReceipt::Succeeded {
                receipt_hash: entry.receipt_hash,
                database_updates: entry.local_receipt.database_updates,
                application_events: entry.local_receipt.application_events,
            },
            TransactionOutcome::Failure => ConsensusReceipt::Failed,
        };
        Self {
            tx_hash: entry.tx_hash,
            consensus,
            metadata: Some(entry.execution_output),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationEvent, DatabaseUpdates, GlobalReceiptHash, Hash};

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
            metadata: Some(ExecutionMetadata::failure(Some("test error".to_string()))),
        };
        assert!(local.metadata.is_some());
        assert!(!local.consensus.is_success());
    }
}
