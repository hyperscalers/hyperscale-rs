//! Per-tx execution outcome ([`TxOutcome`]) and the [`ExecutionOutcome`] enum
//! carried inside execution certificates.

use crate::{GlobalReceiptHash, TxHash};
use sbor::prelude::*;

/// Per-transaction execution outcome within a wave.
///
/// Carried inside execution certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxOutcome {
    /// Transaction hash.
    pub tx_hash: TxHash,
    /// The execution outcome for this transaction.
    pub outcome: ExecutionOutcome,
}

impl TxOutcome {
    /// Whether this outcome is an abort.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self.outcome, ExecutionOutcome::Aborted)
    }
}

/// The outcome of executing a transaction on a single shard.
///
/// The variant tag IS the outcome — there is no separate `success: bool`
/// flag. Failed transactions carry no `receipt_hash` on the wire (the
/// canonical [`FAILED_RECEIPT_HASH`](crate::FAILED_RECEIPT_HASH) is
/// derivable at hash time).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ExecutionOutcome {
    /// Engine committed the transaction; state changes applied.
    Succeeded {
        /// Hash of the global receipt produced by this execution.
        receipt_hash: GlobalReceiptHash,
    },
    /// Engine rejected the transaction; no state changes applied.
    /// Carries no payload — every failure is consensus-equivalent.
    Failed,
    /// Transaction aborted before execution could complete.
    Aborted,
}

impl ExecutionOutcome {
    /// Whether the transaction was aborted.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted)
    }
}
