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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ExecutionOutcome {
    /// Transaction executed. `receipt_hash` is the hash of the execution receipt.
    /// `success=true` means the transaction's logic succeeded (writes applied).
    /// `success=false` means the transaction's logic failed (no writes).
    Executed {
        /// Hash of the global receipt produced by this execution.
        receipt_hash: GlobalReceiptHash,
        /// Whether the engine committed (`true`) or rejected (`false`) the tx.
        success: bool,
    },
    /// Transaction aborted before execution could complete.
    Aborted,
}

impl ExecutionOutcome {
    /// Whether execution succeeded (executed with success=true).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Executed { success: true, .. })
    }

    /// Whether the transaction was aborted.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted)
    }

    /// Get the receipt hash, or `GlobalReceiptHash::ZERO` for aborted outcomes.
    #[must_use]
    pub const fn receipt_hash_or_zero(&self) -> GlobalReceiptHash {
        match self {
            Self::Executed { receipt_hash, .. } => *receipt_hash,
            Self::Aborted => GlobalReceiptHash::ZERO,
        }
    }
}
