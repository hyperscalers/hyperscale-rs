//! Execution result types.
//!
//! Re-exported from `hyperscale_core::result` for backward compatibility.

// Re-export the generic types from hyperscale_core::result
pub use hyperscale_core::result::{ExecutionOutput, SingleTxResult};

// The `From<SingleTxResult> for ExecutionResult` impl is defined in core
// and comes for free with the type re-export.
