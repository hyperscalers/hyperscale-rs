//! Execution result types.
//!
//! Re-exported from `hyperscale_core::result` for backward compatibility.

// Re-export the generic types with ConcreteConfig defaults
pub use hyperscale_core::result::{ExecutionOutput, SingleTxResult};

// The `From<SingleTxResult> for ExecutionResult` impl is defined in core
// and comes for free with the type re-export.
