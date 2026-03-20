//! Error types for execution.

use thiserror::Error;

/// Errors during transaction execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// Transaction preparation/validation failed.
    #[error("Transaction preparation failed: {0}")]
    Preparation(String),

    /// Transaction execution failed.
    #[error("Transaction execution failed: {0}")]
    Execution(String),

    /// Invalid provision data.
    #[error("Invalid provision: {0}")]
    InvalidProvision(String),

    /// Storage operation failed.
    #[error("Storage error: {0}")]
    Storage(String),
}
