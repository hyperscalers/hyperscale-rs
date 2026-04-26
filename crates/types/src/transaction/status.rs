//! Transaction decision/status enums and the parser used by RPC string forms.

use crate::BlockHeight;
use sbor::prelude::*;
use thiserror::Error;

/// Final decision for a transaction after cross-shard coordination.
///
/// Decision priority: `Aborted > Reject > Accept`. If any shard reports
/// `Aborted`, the TC decision is `Aborted` regardless of other shards' results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionDecision {
    /// All shards successfully executed the transaction.
    Accept,
    /// At least one shard failed to execute the transaction (but none aborted).
    Reject,
    /// At least one shard aborted the transaction (e.g. timeout, livelock).
    /// Takes priority over Accept/Reject from other shards.
    Aborted,
}

/// Transaction status for lifecycle tracking.
///
/// Transactions progress through these states:
///
/// **Normal Flow** (both single-shard and cross-shard):
/// ```text
/// Pending → Committed → Executed → Completed
/// ```
///
/// # State Descriptions
///
/// - **Pending**: Transaction has been submitted but not yet included in a committed block
/// - **Committed**: Block containing transaction has been committed; execution is in progress
/// - **Executed**: Execution complete, certificate created (state NOT yet updated - waiting for block)
/// - **Completed**: Certificate committed in block, state updated, transaction done
///
/// # Note on Intermediate States
///
/// The execution state machine internally tracks finer-grained progress (provisioning,
/// executing, collecting votes/certificates), but the mempool only needs to know:
/// - Is the transaction holding state locks? (Committed, Executed)
/// - Is it done? (Completed, Aborted)
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionStatus {
    /// Transaction submitted, waiting to be included in a block.
    Pending,

    /// Block containing transaction has been committed.
    ///
    /// The transaction is now being executed. This state holds locks on all
    /// declared nodes until execution completes (Executed) or the transaction
    /// is aborted.
    ///
    /// For cross-shard transactions, this encompasses:
    /// - State provisioning (collecting state from other shards)
    /// - Execution (running the transaction logic)
    /// - Vote collection (gathering 2f+1 votes for execution certificate)
    /// - Certificate collection (gathering certificates from all shards)
    Committed(BlockHeight),

    /// Execution complete, wave certificate has been finalized.
    ///
    /// All shard execution proofs have been collected and the wave certificate
    /// has been created with per-tx Accept or Reject decisions.
    ///
    /// **Important**: State is NOT yet updated at this point. The wave certificate
    /// must be included in a block before state changes are applied. The
    /// transaction is waiting for its wave certificate to be committed.
    ///
    /// Still holds state locks until Completed.
    Executed {
        /// Wave-finalized decision for this tx (Accept / Reject / Aborted).
        decision: TransactionDecision,
        /// Block height when the transaction was originally committed.
        /// Preserved from Committed state for timeout tracking - cross-shard
        /// transactions can get stuck in Executed state if certificate inclusion
        /// fails on another shard.
        committed_at: BlockHeight,
    },

    /// Transaction has been fully processed and can be evicted.
    ///
    /// The wave certificate has been committed in a block. State changes
    /// have been applied (if accepted). This is the terminal state - the
    /// transaction can now be safely removed from the mempool.
    ///
    /// Contains the final decision (Accept/Reject/Aborted) from execution.
    Completed(TransactionDecision),
}

impl TransactionStatus {
    /// Check if transaction is in a final state (won't transition further).
    ///
    /// Terminal states:
    /// - `Completed`: Transaction executed and certificate committed
    #[must_use]
    pub fn is_final(&self) -> bool {
        matches!(self, TransactionStatus::Completed(_))
    }

    /// Check if transaction is ready to be included in a block.
    ///
    /// Only Pending transactions can be selected by the block proposer.
    #[must_use]
    pub fn is_ready_for_block(&self) -> bool {
        matches!(self, TransactionStatus::Pending)
    }

    /// Check if this status means the transaction holds state locks.
    ///
    /// State locks are acquired when a transaction is committed in a block and
    /// released when the wave certificate is committed in a block (Completed).
    ///
    /// The lock prevents conflicting transactions from being selected for blocks
    /// while this transaction is being executed.
    ///
    /// The following statuses do NOT hold locks:
    /// - Pending: not yet committed into a block
    /// - Completed: certificate committed, transaction done
    #[must_use]
    pub fn holds_state_lock(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Committed(_) | TransactionStatus::Executed { .. }
        )
    }
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Pending => write!(f, "pending"),
            TransactionStatus::Committed(height) => write!(f, "committed({})", height.0),
            TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                ..
            } => {
                write!(f, "executed(accept)")
            }
            TransactionStatus::Executed {
                decision: TransactionDecision::Reject,
                ..
            } => {
                write!(f, "executed(reject)")
            }
            TransactionStatus::Executed {
                decision: TransactionDecision::Aborted,
                ..
            } => {
                write!(f, "executed(aborted)")
            }
            TransactionStatus::Completed(TransactionDecision::Accept) => {
                write!(f, "completed(accept)")
            }
            TransactionStatus::Completed(TransactionDecision::Reject) => {
                write!(f, "completed(reject)")
            }
            TransactionStatus::Completed(TransactionDecision::Aborted) => {
                write!(f, "completed(aborted)")
            }
        }
    }
}

impl std::str::FromStr for TransactionStatus {
    type Err = TransactionStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle simple cases first
        if s == "pending" {
            return Ok(TransactionStatus::Pending);
        }

        // Parse status(value) format
        let (name, inner) = if let Some(paren_start) = s.find('(') {
            if !s.ends_with(')') {
                return Err(TransactionStatusParseError::InvalidFormat(s.to_string()));
            }
            let name = &s[..paren_start];
            let inner = &s[paren_start + 1..s.len() - 1];
            (name, Some(inner))
        } else {
            (s, None)
        };

        match name {
            "pending" => Ok(TransactionStatus::Pending),
            "committed" => {
                let height = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("committed".into()))?
                    .parse::<u64>()
                    .map_err(|_| TransactionStatusParseError::InvalidValue("height".into()))?;
                Ok(TransactionStatus::Committed(BlockHeight(height)))
            }
            "executed" => {
                let decision = parse_decision(inner.ok_or_else(|| {
                    TransactionStatusParseError::MissingValue("executed".into())
                })?)?;
                // Note: committed_at is not preserved in string representation as it's
                // internal state for timeout tracking. Use 0 as placeholder - this status
                // parsed from strings won't be used for timeout calculations anyway.
                Ok(TransactionStatus::Executed {
                    decision,
                    committed_at: BlockHeight(0),
                })
            }
            "completed" => {
                let decision = parse_decision(inner.ok_or_else(|| {
                    TransactionStatusParseError::MissingValue("completed".into())
                })?)?;
                Ok(TransactionStatus::Completed(decision))
            }
            _ => Err(TransactionStatusParseError::UnknownStatus(name.to_string())),
        }
    }
}

fn parse_decision(s: &str) -> Result<TransactionDecision, TransactionStatusParseError> {
    match s {
        "accept" => Ok(TransactionDecision::Accept),
        "reject" => Ok(TransactionDecision::Reject),
        "aborted" => Ok(TransactionDecision::Aborted),
        _ => Err(TransactionStatusParseError::InvalidValue("decision".into())),
    }
}

/// Error parsing a `TransactionStatus` from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatusParseError {
    /// Unknown status name.
    UnknownStatus(String),
    /// Invalid format (missing parentheses, etc).
    InvalidFormat(String),
    /// Missing required value in parentheses.
    MissingValue(String),
    /// Invalid value in parentheses.
    InvalidValue(String),
}

impl std::fmt::Display for TransactionStatusParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownStatus(s) => write!(f, "unknown status: {s}"),
            Self::InvalidFormat(s) => write!(f, "invalid format: {s}"),
            Self::MissingValue(s) => write!(f, "missing value for {s}"),
            Self::InvalidValue(s) => write!(f, "invalid {s}"),
        }
    }
}

impl std::error::Error for TransactionStatusParseError {}

/// Transaction error types.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// Transaction declares no writes (read-only transactions not supported).
    #[error("Transaction must declare at least one write")]
    NoWritesDeclared,

    /// A `NodeId` appears in both `declared_reads` and `declared_writes`.
    #[error("NodeId declared in both reads and writes")]
    DuplicateDeclaration,

    /// Failed to encode transaction.
    #[error("Failed to encode transaction: {0}")]
    EncodeFailed(String),

    /// Failed to decode transaction.
    #[error("Failed to decode transaction: {0}")]
    DecodeFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_decision() {
        assert_ne!(TransactionDecision::Accept, TransactionDecision::Reject);
    }
}
