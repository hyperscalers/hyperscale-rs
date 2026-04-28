//! Execution result types.

use hyperscale_types::{
    ExecutionMetadata, ExecutionOutcome, GlobalReceiptHash, LocalExecutionEntry, LocalReceipt,
    TxHash, TxOutcome, WritesRoot,
};

/// Output from executing a batch of transactions.
#[derive(Debug, Clone)]
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

    /// Get a reference to the results.
    #[must_use]
    pub fn results(&self) -> &[ExecutedTx] {
        &self.results
    }
}

/// One executed transaction's consumer-shaped output.
///
/// `outcome` flows into wave vote aggregation (`ExecutionVote::tx_outcomes` →
/// `ExecutionCertificate`). `entry` flows into chain-state persistence
/// (receipts written when the wave's certificate is committed).
#[derive(Debug, Clone)]
pub struct ExecutedTx {
    /// Lightweight summary for vote aggregation.
    pub outcome: TxOutcome,
    /// Full local receipt + execution metadata for persistence.
    pub entry: LocalExecutionEntry,
}

impl ExecutedTx {
    /// Create a successful executed-tx record.
    #[must_use]
    pub const fn success(
        tx_hash: TxHash,
        receipt_hash: GlobalReceiptHash,
        local_receipt: LocalReceipt,
        execution_output: ExecutionMetadata,
    ) -> Self {
        Self {
            outcome: TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash,
                    success: true,
                },
            },
            entry: LocalExecutionEntry {
                tx_hash,
                receipt_hash,
                local_receipt,
                execution_output,
            },
        }
    }

    /// Create a failed executed-tx record.
    ///
    /// `error` is logged at the construction site (it does not flow downstream
    /// — neither vote aggregation nor receipt persistence carry the message).
    #[must_use]
    pub fn failure(tx_hash: TxHash, error: impl Into<String>) -> Self {
        let error = error.into();
        tracing::warn!(?tx_hash, %error, "transaction execution failed");
        let local_receipt = LocalReceipt::failure();
        // Failures have no writes, so writes_root is ZERO.
        let receipt_hash = local_receipt
            .global_receipt(WritesRoot::ZERO)
            .receipt_hash();
        Self {
            outcome: TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash,
                    success: false,
                },
            },
            entry: LocalExecutionEntry {
                tx_hash,
                receipt_hash,
                local_receipt,
                execution_output: ExecutionMetadata::failure(None),
            },
        }
    }
}
