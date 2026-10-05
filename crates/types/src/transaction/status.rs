//! Transaction decision/status enums and the parser used by RPC string forms.

use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::str::FromStr;

use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::BlockHeight;

/// Final decision for a transaction after cross-shard coordination.
///
/// Decision priority: `Aborted > Reject > Accept`. If any shard reports
/// `Aborted`, the TC decision is `Aborted` regardless of other shards' results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
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
/// Pending → Committed → LegFinalized → Completed
/// ```
///
/// `Pending → Committed` when the block containing the tx commits, and
/// `Committed → Completed` when a block commits a finalization that
/// decides it. A shard running one leg of a divided transaction commits
/// a finalization of its own that decides nothing — `Committed →
/// LegFinalized` — and the terminal follows the core's verdict: a
/// refusal heard off a core shard's certificate, or what this shard's
/// own chain closes the leg on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Hbor)]
pub enum TransactionStatus {
    /// Transaction submitted, waiting to be included in a block.
    Pending,

    /// Block containing transaction has been committed; the tx is in flight,
    /// holding locks on its declared nodes until a committed block carries
    /// the finalization that decides it.
    ///
    /// For cross-shard transactions this encompasses:
    /// - State provisioning (collecting state from other shards)
    /// - Execution (running the transaction logic)
    /// - Vote collection (gathering 2f+1 votes for execution certificate)
    /// - Certificate collection (gathering certificates from all shards)
    Committed(BlockHeight),

    /// A committed block carried this shard's own finalization of the
    /// transaction, and that finalization decides nothing: this shard
    /// ran one leg of a divided transaction, and the verdict is its
    /// core's. Locks released; the transaction is still pending its
    /// terminal.
    LegFinalized,

    /// A finalization that decides the transaction has been committed
    /// in a block — this shard's own, or, where this shard ran a leg,
    /// the chain closing it or a core shard's certificate refusing it;
    /// locks released. Carries the decision.
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
    /// `Pending → Committed` transition and released when the shard's
    /// own finalization commits, deciding or not.
    #[must_use]
    pub const fn holds_state_lock(&self) -> bool {
        matches!(self, Self::Committed(_))
    }
}

impl Display for TransactionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed(height) => write!(f, "committed({})", height.inner()),
            Self::LegFinalized => write!(f, "leg_finalized"),
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

impl FromStr for TransactionStatus {
    type Err = TransactionStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle simple cases first
        if s == "pending" {
            return Ok(Self::Pending);
        }
        if s == "leg_finalized" {
            return Ok(Self::LegFinalized);
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
            "leg_finalized" => Ok(Self::LegFinalized),
            "committed" => {
                let height = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("committed".into()))?
                    .parse::<u64>()
                    .map_err(|_| TransactionStatusParseError::InvalidValue("height".into()))?;
                Ok(Self::Committed(BlockHeight::new(height)))
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

/// What a committed finalization, or a core's refusal, settled about a
/// transaction a shard holds.
///
/// Derived by the execution coordinator, whose ledger froze each
/// transaction's classification and so knows what a finalization's
/// name means — a name that decides nothing is a leg finalizing, a
/// deciding success on a leg entry is the reclaim of what it issued —
/// and applied by the mempool to the entry's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxResolution {
    /// This shard's own finalization named the transaction and decides
    /// nothing: its leg finalized here.
    LegFinalized,
    /// This shard's chain decided it: a whole member's verdict, a
    /// failed leg's, a leg closed on every record it issued being
    /// taken, or the reclaim's.
    Decided(TransactionDecision),
    /// A core shard refused it, off that shard's certificate: a member
    /// that could not do its part ends the transaction, so no later
    /// certificate overturns this. A core's success is never relayed —
    /// every core certificate accepting is not the transaction accepted,
    /// since a core whose certificates never combined is abandoned all
    /// the same. This shard's own leg may not have finalized here yet,
    /// and the terminal lands once it has.
    CoreRefused(TransactionDecision),
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

impl Display for TransactionStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStatus(s) => write!(f, "unknown status: {s}"),
            Self::InvalidFormat(s) => write!(f, "invalid format: {s}"),
            Self::MissingValue(s) => write!(f, "missing value for {s}"),
            Self::InvalidValue(s) => write!(f, "invalid {s}"),
        }
    }
}

impl StdError for TransactionStatusParseError {}

/// Transaction error types.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// Transaction declares no writes (read-only transactions not supported).
    #[error("Transaction must declare at least one write")]
    NoWritesDeclared,

    /// A key appears in both `declared_reads` and `declared_writes`.
    #[error("key declared in both reads and writes")]
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

    /// Every status survives its own string form, and only the terminal
    /// one is final: a leg that finalized is still pending its verdict.
    #[test]
    fn every_status_round_trips_and_only_completed_is_final() {
        let statuses = [
            TransactionStatus::Pending,
            TransactionStatus::Committed(BlockHeight::new(7)),
            TransactionStatus::LegFinalized,
            TransactionStatus::Completed(TransactionDecision::Reject),
        ];
        for status in &statuses {
            assert_eq!(
                status.to_string().parse::<TransactionStatus>().as_ref(),
                Ok(status)
            );
        }
        assert_eq!(TransactionStatus::LegFinalized.to_string(), "leg_finalized");
        assert!(!TransactionStatus::LegFinalized.is_final());
        assert!(!TransactionStatus::LegFinalized.holds_state_lock());
        assert!(TransactionStatus::Completed(TransactionDecision::Accept).is_final());
    }
}
