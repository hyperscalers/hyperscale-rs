//! Execution result types used by the `ExecutionBackend` trait.
//!
//! These are framework-level types returned by execution backends.
//! `SingleTxResult<C>` carries full execution output including state updates
//! and receipts. `ExecutionOutput<C>` is a batch wrapper.

use hyperscale_types::{
    ConcreteConfig, DatabaseUpdates, Hash, LedgerTransactionReceipt, LocalTransactionExecution,
    TypeConfig,
};

/// Output from executing a batch of transactions.
pub struct ExecutionOutput<C: TypeConfig = ConcreteConfig> {
    /// Results for each transaction, in the same order as input.
    pub results: Vec<SingleTxResult<C>>,
}

impl<C: TypeConfig> std::fmt::Debug for ExecutionOutput<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionOutput")
            .field("count", &self.results.len())
            .finish()
    }
}

impl<C: TypeConfig> Clone for ExecutionOutput<C> {
    fn clone(&self) -> Self {
        Self {
            results: self.results.clone(),
        }
    }
}

impl<C: TypeConfig> ExecutionOutput<C> {
    /// Create a new execution output.
    pub fn new(results: Vec<SingleTxResult<C>>) -> Self {
        Self { results }
    }

    /// Create an empty output (no transactions).
    pub fn empty() -> Self {
        Self { results: vec![] }
    }

    /// Get the number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if the output is empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

/// Result of executing a single transaction.
pub struct SingleTxResult<C: TypeConfig = ConcreteConfig> {
    /// Hash of the executed transaction.
    pub tx_hash: Hash,

    /// Whether execution succeeded (committed).
    pub success: bool,

    /// Hash of ConsensusReceipt (outcome + event_root).
    pub receipt_hash: Hash,

    /// Full execution receipt.
    pub receipt: C::ExecutionReceipt,

    /// Local execution metadata (fees, logs, errors).
    pub local_execution: LocalTransactionExecution,

    /// State delta produced by execution.
    pub state_update: C::StateUpdate,

    /// Error message if execution failed.
    pub error: Option<String>,
}

impl<C: TypeConfig> std::fmt::Debug for SingleTxResult<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleTxResult")
            .field("tx_hash", &self.tx_hash)
            .field("success", &self.success)
            .field("receipt_hash", &self.receipt_hash)
            .field("error", &self.error)
            .finish()
    }
}

impl<C: TypeConfig> Clone for SingleTxResult<C> {
    fn clone(&self) -> Self {
        Self {
            tx_hash: self.tx_hash,
            success: self.success,
            receipt_hash: self.receipt_hash,
            receipt: self.receipt.clone(),
            local_execution: self.local_execution.clone(),
            state_update: self.state_update.clone(),
            error: self.error.clone(),
        }
    }
}

impl<C: TypeConfig> SingleTxResult<C> {
    /// Check if this is a successful execution.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if this is a failed execution.
    pub fn is_failure(&self) -> bool {
        !self.success
    }
}

/// Create a failure result with default receipt and empty state.
///
/// Available for any TypeConfig whose associated types match the Radix
/// concrete types (`LedgerTransactionReceipt`, `DatabaseUpdates`).
impl<C> SingleTxResult<C>
where
    C: TypeConfig<ExecutionReceipt = LedgerTransactionReceipt, StateUpdate = DatabaseUpdates>,
{
    /// Create a failed result with default empty receipt.
    pub fn failure(tx_hash: Hash, error: impl Into<String>) -> Self {
        Self {
            tx_hash,
            success: false,
            receipt_hash: LedgerTransactionReceipt::failure().receipt_hash(),
            receipt: LedgerTransactionReceipt::failure(),
            local_execution: LocalTransactionExecution::failure(None),
            state_update: Default::default(),
            error: Some(error.into()),
        }
    }
}

impl<C> From<SingleTxResult<C>> for hyperscale_types::ExecutionResult<C>
where
    C: TypeConfig,
{
    fn from(r: SingleTxResult<C>) -> Self {
        Self {
            tx_hash: r.tx_hash,
            receipt_hash: r.receipt_hash,
            database_updates: r.state_update,
            ledger_receipt: r.receipt,
            local_execution: r.local_execution,
        }
    }
}
