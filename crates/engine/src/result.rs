//! Execution result types.

use hyperscale_types::{Hash, SubstateWrite};

/// Output from executing a batch of transactions.
#[derive(Debug, Clone)]
pub struct ExecutionOutput {
    /// Results for each transaction, in the same order as input.
    pub results: Vec<SingleTxResult>,
}

impl ExecutionOutput {
    /// Create a new execution output.
    pub fn new(results: Vec<SingleTxResult>) -> Self {
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

    /// Iterate over results.
    pub fn iter(&self) -> impl Iterator<Item = &SingleTxResult> {
        self.results.iter()
    }

    /// Get a reference to the results.
    pub fn results(&self) -> &[SingleTxResult] {
        &self.results
    }
}

/// Result of executing a single transaction.
#[derive(Debug, Clone)]
pub struct SingleTxResult {
    /// Hash of the executed transaction.
    pub tx_hash: Hash,

    /// Whether execution succeeded (committed).
    pub success: bool,

    /// Deterministic hash-chain commitment over execution output writes.
    ///
    /// Used in the voting protocol to ensure all shards agree on results.
    /// For failed transactions, this is a zero hash.
    pub writes_commitment: Hash,

    /// State writes from execution (for certificate creation).
    ///
    /// Only populated for successful executions.
    pub state_writes: Vec<SubstateWrite>,

    /// Error message if execution failed.
    pub error: Option<String>,
}

impl SingleTxResult {
    /// Create a successful result.
    pub fn success(
        tx_hash: Hash,
        writes_commitment: Hash,
        state_writes: Vec<SubstateWrite>,
    ) -> Self {
        Self {
            tx_hash,
            success: true,
            writes_commitment,
            state_writes,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failure(tx_hash: Hash, error: impl Into<String>) -> Self {
        Self {
            tx_hash,
            success: false,
            writes_commitment: Hash::ZERO,
            state_writes: vec![],
            error: Some(error.into()),
        }
    }

    /// Check if this is a successful execution.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if this is a failed execution.
    pub fn is_failure(&self) -> bool {
        !self.success
    }
}
