//! Per-batch and per-transaction execution outputs.
//!
//! [`ExecutionOutput`] is the value returned by every [`Engine`](crate::Engine)
//! call — one [`ExecutedTx`] per input transaction, in input order.
//!
//! [`ExecutedTx`] is the canonical engine-side record. It carries the
//! consensus-bound portion ([`ConsensusReceipt`]) and the local-only
//! metadata ([`ExecutionMetadata`]) — same separation the rest of the
//! system uses (see [`StoredReceipt`](hyperscale_types::StoredReceipt)).

use hyperscale_types::{
    ConsensusReceipt, ExecutionMetadata, ExecutionOutcome, StoredReceipt, TxHash, TxOutcome,
};

/// Output from executing a batch of transactions.
#[derive(Debug, Clone, Default)]
pub struct ExecutionOutput {
    /// Results for each transaction, in the same order as input.
    pub results: Vec<ExecutedTx>,
}

impl ExecutionOutput {
    /// Create a new execution output.
    #[must_use]
    pub const fn new(results: Vec<ExecutedTx>) -> Self {
        Self { results }
    }

    /// Create an empty output (no transactions).
    #[must_use]
    pub const fn empty() -> Self {
        Self { results: vec![] }
    }

    /// Get the number of results.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if the output is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterate over results.
    pub fn iter(&self) -> impl Iterator<Item = &ExecutedTx> {
        self.results.iter()
    }
}

/// Engine output for one transaction.
///
/// Holds the canonical fields produced by execution: the consensus
/// portion (variant-tagged outcome plus, on success, the precomputed
/// receipt hash and shard-filtered writes/events) and the local-only
/// metadata (logs, error, fees).
#[derive(Debug, Clone)]
pub struct ExecutedTx {
    /// Hash of the executed transaction.
    pub tx_hash: TxHash,
    /// Consensus-bound receipt portion (transferable across peers).
    pub consensus: ConsensusReceipt,
    /// Local-only execution metadata (logs, error, fees).
    pub metadata: ExecutionMetadata,
}

impl ExecutedTx {
    /// Build a record for an executed transaction.
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
        }
    }

    /// Build a canonical failure record for `tx_hash`.
    ///
    /// `error` is logged at the construction site (it does not flow
    /// downstream — neither vote aggregation nor receipt persistence
    /// carry the message).
    #[must_use]
    pub fn failure(tx_hash: TxHash, error: impl Into<String>) -> Self {
        let error = error.into();
        tracing::warn!(?tx_hash, %error, "transaction execution failed");
        Self {
            tx_hash,
            consensus: ConsensusReceipt::Failed,
            metadata: ExecutionMetadata::failure(None),
        }
    }

    /// Whether the transaction succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.consensus.is_success()
    }

    /// Project the wave-vote view ([`TxOutcome`]; small, copyable).
    #[must_use]
    pub const fn outcome(&self) -> TxOutcome {
        let outcome = match &self.consensus {
            ConsensusReceipt::Succeeded { receipt_hash, .. } => ExecutionOutcome::Succeeded {
                receipt_hash: *receipt_hash,
            },
            ConsensusReceipt::Failed => ExecutionOutcome::Failed,
        };
        TxOutcome {
            tx_hash: self.tx_hash,
            outcome,
        }
    }
}

impl From<ExecutedTx> for StoredReceipt {
    /// Bridge from engine output to storage shape: metadata is always
    /// present (the engine always produces it), so wrapped in `Some`.
    fn from(tx: ExecutedTx) -> Self {
        Self {
            tx_hash: tx.tx_hash,
            consensus: tx.consensus,
            metadata: Some(tx.metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Hash, TxHash};

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    #[test]
    fn execution_output_empty_is_zero_len() {
        let out = ExecutionOutput::empty();
        assert!(out.is_empty());
        assert_eq!(out.len(), 0);
        assert_eq!(out.iter().count(), 0);
    }

    #[test]
    fn execution_output_preserves_input_order() {
        let a = ExecutedTx::failure(tx_hash(1), "err-a");
        let b = ExecutedTx::failure(tx_hash(2), "err-b");
        let c = ExecutedTx::failure(tx_hash(3), "err-c");
        let out = ExecutionOutput::new(vec![a, b, c]);

        let hashes: Vec<TxHash> = out.iter().map(|e| e.tx_hash).collect();
        assert_eq!(hashes, vec![tx_hash(1), tx_hash(2), tx_hash(3)]);
        assert_eq!(out.len(), 3);
        assert!(!out.is_empty());
    }

    #[test]
    fn failure_marks_consensus_as_failed_and_carries_tx_hash() {
        let h = tx_hash(7);
        let exec = ExecutedTx::failure(h, "boom");

        assert_eq!(exec.tx_hash, h);
        assert!(!exec.is_success());
        assert!(matches!(exec.consensus, ConsensusReceipt::Failed));
    }

    #[test]
    fn failure_receipt_hash_is_canonical_across_failures() {
        // All failures share the canonical FAILED_RECEIPT_HASH; downstream
        // vote aggregation matches by tx_hash, not by receipt_hash.
        let a = ExecutedTx::failure(tx_hash(1), "err");
        let b = ExecutedTx::failure(tx_hash(2), "different");
        assert_eq!(a.consensus.receipt_hash(), b.consensus.receipt_hash());
        assert_ne!(a.tx_hash, b.tx_hash);
    }
}
