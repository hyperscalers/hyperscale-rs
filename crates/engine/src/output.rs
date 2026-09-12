//! Per-transaction execution output.
//!
//! [`ExecutedTx`] is the canonical engine-side record. It carries the
//! consensus-bound portion ([`ConsensusReceipt`]) and the local-only
//! metadata ([`ExecutionMetadata`]) — same separation the rest of the
//! system uses (see [`StoredReceipt`](hyperscale_types::StoredReceipt)).

use hyperscale_types::{
    ConsensusReceipt, EscrowedValue, ExecutionMetadata, ExecutionOutcome, StoredReceipt, TxHash,
    TxOutcome,
};

/// Engine output for one transaction — a [`ConsensusReceipt`] paired with
/// its [`ExecutionMetadata`]. Convertible to [`StoredReceipt`] via [`From`].
#[derive(Debug, Clone)]
pub struct ExecutedTx {
    /// Identity of the executed transaction; primary key in downstream
    /// receipt stores and the join key against `Finalization` outcomes.
    pub tx_hash: TxHash,
    /// Hash-stable, peer-transferable portion. Signed over (indirectly,
    /// via `local_receipt_root`) and shipped on sync.
    pub consensus: ConsensusReceipt,
    /// Node-local diagnostics (fees, logs, error). Never crosses the wire;
    /// dropped when this record is forwarded to a peer.
    pub metadata: ExecutionMetadata,
    /// A receipt carrying the payer's fee debit and nothing else: the
    /// class charge of a failed or infeasible attempt, or the floor a
    /// cross-shard leg holds in reserve against a tick abort. Built
    /// beside the execution receipt because a transaction whose effects
    /// are discarded still owes its charge, and state moves only through
    /// receipts. Present only where this shard is the fee payer of an
    /// outcome that charges one.
    pub fee_receipt: Option<ConsensusReceipt>,
    /// What this execution escrowed out, one entry per departing edge.
    /// Empty for a member that ran the whole shape, which hands nothing
    /// to anyone.
    pub escrowed: Vec<EscrowedValue>,
}

impl ExecutedTx {
    /// Build a record from already-projected pieces. Most callers want
    /// [`project_to_shard`](crate::project_to_shard) (which projects a
    /// cached output onto one shard) or [`Self::failure`].
    #[must_use]
    pub const fn new(
        tx_hash: TxHash,
        consensus: ConsensusReceipt,
        metadata: ExecutionMetadata,
    ) -> Self {
        Self {
            tx_hash,
            consensus,
            metadata,
            fee_receipt: None,
            escrowed: Vec::new(),
        }
    }

    /// Canonical synthetic-failure record. Pure constructor; does not log.
    #[must_use]
    pub const fn failure(tx_hash: TxHash) -> Self {
        Self {
            tx_hash,
            consensus: ConsensusReceipt::Failed,
            metadata: ExecutionMetadata::empty(),
            fee_receipt: None,
            escrowed: Vec::new(),
        }
    }

    /// `true` iff `consensus` is [`ConsensusReceipt::Succeeded`].
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.consensus.is_success()
    }

    /// Project the small, copyable [`TxOutcome`] used in execution votes
    /// — drops `database_updates`, `application_events`, and metadata.
    #[must_use]
    pub fn outcome(&self) -> TxOutcome {
        let outcome = match &self.consensus {
            ConsensusReceipt::Succeeded { receipt_hash, .. } => ExecutionOutcome::Succeeded {
                receipt_hash: *receipt_hash,
            },
            ConsensusReceipt::Failed => ExecutionOutcome::Failed,
        };
        TxOutcome::new(self.tx_hash, outcome)
            .escrowing(self.escrowed.iter().map(|issued| issued.record))
    }
}

impl From<ExecutedTx> for StoredReceipt {
    /// `metadata: Some(_)` because engine-produced ⇒ locally executed.
    /// Sync-ingress sites use [`StoredReceipt::synced`] for the `None` case.
    fn from(tx: ExecutedTx) -> Self {
        Self {
            tx_hash: tx.tx_hash,
            consensus: std::sync::Arc::new(tx.consensus),
            metadata: Some(tx.metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, TxHash};

    use super::*;

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[byte]))
    }

    #[test]
    fn failure_marks_consensus_as_failed_and_carries_tx_hash() {
        let h = tx_hash(7);
        let exec = ExecutedTx::failure(h);

        assert_eq!(exec.tx_hash, h);
        assert!(!exec.is_success());
        assert!(matches!(exec.consensus, ConsensusReceipt::Failed));
    }

    #[test]
    fn failure_receipt_hash_is_canonical_across_failures() {
        // All failures share the canonical FAILED_RECEIPT_HASH; downstream
        // vote aggregation matches by tx_hash, not by receipt_hash.
        let a = ExecutedTx::failure(tx_hash(1));
        let b = ExecutedTx::failure(tx_hash(2));
        assert_eq!(a.consensus.receipt_hash(), b.consensus.receipt_hash());
        assert_ne!(a.tx_hash, b.tx_hash);
    }
}
