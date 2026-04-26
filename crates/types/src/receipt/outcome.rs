//! Transaction outcome (success/failure) reported by the engine.

/// Whether a transaction committed successfully or was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub enum TransactionOutcome {
    /// Engine committed the transaction; state changes applied.
    Success,
    /// Engine rejected the transaction; no state changes applied.
    Failure,
}
