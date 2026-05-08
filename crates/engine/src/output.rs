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
    /// One [`ExecutedTx`] per input transaction, preserving input order so
    /// callers can zip results back against their request batch.
    pub results: Vec<ExecutedTx>,
}

#[allow(missing_docs)] // thin Vec wrapper; methods mirror Vec semantics
impl ExecutionOutput {
    #[must_use]
    pub const fn new(results: Vec<ExecutedTx>) -> Self {
        Self { results }
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self { results: vec![] }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.results.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ExecutedTx> {
        self.results.iter()
    }
}

/// Engine output for one transaction — a [`ConsensusReceipt`] paired with
/// its [`ExecutionMetadata`]. Convertible to [`StoredReceipt`] via [`From`].
#[derive(Debug, Clone)]
pub struct ExecutedTx {
    /// Identity of the executed transaction; primary key in downstream
    /// receipt stores and the join key against `WaveCertificate` outcomes.
    pub tx_hash: TxHash,
    /// Hash-stable, peer-transferable portion. Signed over (indirectly,
    /// via `local_receipt_root`) and shipped on sync.
    pub consensus: ConsensusReceipt,
    /// Node-local diagnostics (fees, logs, error). Never crosses the wire;
    /// dropped when this record is forwarded to a peer.
    pub metadata: ExecutionMetadata,
}

impl ExecutedTx {
    /// Build a record from already-projected pieces. Most callers want
    /// [`crate::receipt::build_executed_tx`] (which projects from a Radix
    /// `TransactionReceipt`) or [`Self::failure`] / [`Self::failure_with_log`].
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

    /// Canonical synthetic-failure record. Pure constructor; does not log.
    /// Use [`Self::failure_with_log`] when the failure has a diagnostic
    /// string that should hit the logs at the construction site (it does
    /// not flow downstream).
    #[must_use]
    pub const fn failure(tx_hash: TxHash) -> Self {
        Self {
            tx_hash,
            consensus: ConsensusReceipt::Failed,
            metadata: ExecutionMetadata::empty(),
        }
    }

    /// As [`Self::failure`], but emits a `warn!` carrying `error` first.
    /// The string is dropped after logging — neither the consensus
    /// receipt nor the metadata carry it downstream.
    #[must_use]
    pub fn failure_with_log(tx_hash: TxHash, error: impl AsRef<str>) -> Self {
        tracing::warn!(
            ?tx_hash,
            error = error.as_ref(),
            "transaction execution failed"
        );
        Self::failure(tx_hash)
    }

    /// `true` iff `consensus` is [`ConsensusReceipt::Succeeded`].
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.consensus.is_success()
    }

    /// Project the small, copyable [`TxOutcome`] used in execution votes
    /// — drops `database_updates`, `application_events`, and metadata.
    #[must_use]
    pub const fn outcome(&self) -> TxOutcome {
        let outcome = match &self.consensus {
            ConsensusReceipt::Succeeded { receipt_hash, .. } => ExecutionOutcome::Succeeded {
                receipt_hash: *receipt_hash,
            },
            ConsensusReceipt::Failed => ExecutionOutcome::Failed,
        };
        TxOutcome::new(self.tx_hash, outcome)
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
        let a = ExecutedTx::failure(tx_hash(1));
        let b = ExecutedTx::failure(tx_hash(2));
        let c = ExecutedTx::failure(tx_hash(3));
        let out = ExecutionOutput::new(vec![a, b, c]);

        let hashes: Vec<TxHash> = out.iter().map(|e| e.tx_hash).collect();
        assert_eq!(hashes, vec![tx_hash(1), tx_hash(2), tx_hash(3)]);
        assert_eq!(out.len(), 3);
        assert!(!out.is_empty());
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
