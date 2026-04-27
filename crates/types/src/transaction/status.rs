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
/// ```text
/// Pending → Committed → Completed
/// ```
///
/// All transitions are driven by committed blocks: `Pending → Committed`
/// when the block containing the tx commits, and `Committed → Completed`
/// when a block whose `block.certificates` covers the tx commits (the wave
/// certificate carries the per-tx decision).
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionStatus {
    /// Transaction submitted, waiting to be included in a block.
    Pending,

    /// Block containing transaction has been committed; the tx is in flight,
    /// holding locks on its declared nodes until a committed block carries
    /// the wave certificate that decides it.
    ///
    /// For cross-shard transactions this encompasses:
    /// - State provisioning (collecting state from other shards)
    /// - Execution (running the transaction logic)
    /// - Vote collection (gathering 2f+1 votes for execution certificate)
    /// - Certificate collection (gathering certificates from all shards)
    Committed(BlockHeight),

    /// Wave certificate has been committed in a block; locks released.
    /// Carries the final decision from the wave's per-tx decisions.
    Completed(TransactionDecision),
}

impl TransactionStatus {
    /// Check if transaction is in a final state (won't transition further).
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Check if transaction is ready to be included in a block.
    #[must_use]
    pub const fn is_ready_for_block(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Whether this status holds state locks. Locks are taken on the
    /// `Pending → Committed` transition and released on
    /// `Committed → Completed`.
    #[must_use]
    pub const fn holds_state_lock(&self) -> bool {
        matches!(self, Self::Committed(_))
    }
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed(height) => write!(f, "committed({})", height.0),
            Self::Completed(TransactionDecision::Accept) => {
                write!(f, "completed(accept)")
            }
            Self::Completed(TransactionDecision::Reject) => {
                write!(f, "completed(reject)")
            }
            Self::Completed(TransactionDecision::Aborted) => {
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
            return Ok(Self::Pending);
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
            "pending" => Ok(Self::Pending),
            "committed" => {
                let height = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("committed".into()))?
                    .parse::<u64>()
                    .map_err(|_| TransactionStatusParseError::InvalidValue("height".into()))?;
                Ok(Self::Committed(BlockHeight(height)))
            }
            "completed" => {
                let decision = parse_decision(inner.ok_or_else(|| {
                    TransactionStatusParseError::MissingValue("completed".into())
                })?)?;
                Ok(Self::Completed(decision))
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
