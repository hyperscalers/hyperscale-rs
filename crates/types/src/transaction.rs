//! Transaction types for consensus.

use crate::{BlockHeight, CommitmentProof, Hash, NodeId, ShardGroupId, TypeConfig};
use hyperscale_codec as sbor;
use hyperscale_codec::prelude::*;
use std::collections::BTreeMap;
use thiserror::Error;

/// Final decision for a transaction after cross-shard coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionDecision {
    /// All shards successfully executed the transaction.
    Accept,
    /// At least one shard failed to execute the transaction.
    Reject,
}

// ============================================================================
// Livelock Prevention Types
// ============================================================================

/// Reason a transaction was deferred during cross-shard execution.
///
/// Used in `TransactionDefer` to explain why a transaction was temporarily
/// deferred and will be retried later.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum DeferReason {
    /// Transaction was part of a bidirectional cross-shard cycle.
    ///
    /// When two transactions form a cycle (A provisions to B while B provisions
    /// to A), the transaction with the higher hash loses and is deferred.
    /// The winner continues, and once complete, the loser is retried.
    LivelockCycle {
        /// Hash of the transaction that won the cycle (lower hash wins).
        winner_tx_hash: Hash,
    },
}

impl std::fmt::Display for DeferReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeferReason::LivelockCycle { winner_tx_hash } => {
                write!(f, "LivelockCycle(winner: {})", winner_tx_hash)
            }
        }
    }
}

/// A transaction deferral included in a block.
///
/// When a proposer detects that a transaction should be deferred (via cycle
/// detection during provisioning), they include this in the block. All
/// validators process it identically, releasing locks and queuing for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDefer {
    /// Hash of the transaction being deferred.
    pub tx_hash: Hash,

    /// Why the transaction was deferred.
    pub reason: DeferReason,

    /// Block height where this deferral is being committed.
    /// Used for timeout calculations on the retry.
    pub block_height: BlockHeight,

    /// Proof that the winner transaction was committed on another shard.
    ///
    /// Required for block validation. Validators verify this proof to ensure
    /// the deferral is justified without needing to have seen the same provisions.
    /// BFT rejects blocks containing deferrals without valid proofs.
    pub proof: CommitmentProof,
}

// ============================================================================
// Manual SBOR implementation for TransactionDefer (CommitmentProof contains Arc)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for TransactionDefer
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(4)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(&self.reason)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.proof)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for TransactionDefer
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 4 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 4,
                actual: length,
            });
        }

        let tx_hash: Hash = decoder.decode()?;
        let reason: DeferReason = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let proof: CommitmentProof = decoder.decode()?;

        Ok(Self {
            tx_hash,
            reason,
            block_height,
            proof,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for TransactionDefer {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for TransactionDefer {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("TransactionDefer", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

/// Reason a transaction was aborted.
///
/// Aborts are terminal - the transaction will not be retried and any held
/// resources are released.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum AbortReason {
    /// Transaction timed out waiting for execution to complete.
    ///
    /// Cross-shard transactions have a timeout period after which they are
    /// aborted if not finalized. This prevents transactions from holding
    /// locks indefinitely in N-way cycle scenarios.
    ExecutionTimeout {
        /// Block height when the transaction was originally committed.
        committed_at: BlockHeight,
    },

    /// Transaction exceeded maximum retry attempts.
    ///
    /// After a transaction is deferred due to livelock cycle detection, it gets
    /// retried when the winner completes. If it keeps getting deferred and
    /// exceeds the max retry count, it's permanently aborted.
    TooManyRetries {
        /// Number of retry attempts made.
        retry_count: u32,
    },

    /// Transaction was explicitly rejected during execution.
    ///
    /// The execution engine determined the transaction cannot succeed
    /// (e.g., insufficient balance, invalid state transition).
    ExecutionRejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
}

impl std::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbortReason::ExecutionTimeout { committed_at } => {
                write!(f, "timeout({})", committed_at.0)
            }
            AbortReason::TooManyRetries { retry_count } => {
                write!(f, "retries({})", retry_count)
            }
            AbortReason::ExecutionRejected { reason } => {
                write!(f, "rejected({})", reason)
            }
        }
    }
}

impl std::str::FromStr for AbortReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, inner) = if let Some(paren_start) = s.find('(') {
            if !s.ends_with(')') {
                return Err(format!("invalid abort reason format: {}", s));
            }
            let name = &s[..paren_start];
            let inner = &s[paren_start + 1..s.len() - 1];
            (name, inner)
        } else {
            return Err(format!("invalid abort reason format: {}", s));
        };

        match name {
            "timeout" => {
                let height = inner
                    .parse::<u64>()
                    .map_err(|_| format!("invalid height: {}", inner))?;
                Ok(AbortReason::ExecutionTimeout {
                    committed_at: BlockHeight(height),
                })
            }
            "retries" => {
                let count = inner
                    .parse::<u32>()
                    .map_err(|_| format!("invalid retry count: {}", inner))?;
                Ok(AbortReason::TooManyRetries { retry_count: count })
            }
            "rejected" => Ok(AbortReason::ExecutionRejected {
                reason: inner.to_string(),
            }),
            _ => Err(format!("unknown abort reason: {}", name)),
        }
    }
}

/// A transaction abort included in a block.
///
/// When a transaction times out or is rejected, the proposer includes this
/// abort record in a block. All validators process it identically, releasing
/// locks and marking the transaction as terminally failed.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionAbort {
    /// Hash of the transaction being aborted.
    pub tx_hash: Hash,

    /// Why the transaction was aborted.
    pub reason: AbortReason,

    /// Block height where this abort is being committed.
    pub block_height: BlockHeight,
}

impl TransactionAbort {
    /// Create a new transaction abort for execution timeout.
    pub fn execution_timeout(
        tx_hash: Hash,
        committed_at: BlockHeight,
        timeout_at: BlockHeight,
    ) -> Self {
        Self {
            tx_hash,
            reason: AbortReason::ExecutionTimeout { committed_at },
            block_height: timeout_at,
        }
    }

    /// Create a new transaction abort for too many retries.
    pub fn too_many_retries(tx_hash: Hash, block_height: BlockHeight, retry_count: u32) -> Self {
        Self {
            tx_hash,
            reason: AbortReason::TooManyRetries { retry_count },
            block_height,
        }
    }

    /// Create a new transaction abort for execution rejection.
    pub fn execution_rejected(tx_hash: Hash, block_height: BlockHeight, reason: String) -> Self {
        Self {
            tx_hash,
            reason: AbortReason::ExecutionRejected { reason },
            block_height,
        }
    }

    /// Check if this abort is due to a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self.reason, AbortReason::ExecutionTimeout { .. })
    }

    /// Check if this abort is due to rejection.
    pub fn is_rejected(&self) -> bool {
        matches!(self.reason, AbortReason::ExecutionRejected { .. })
    }
}

/// Details for a retry transaction created after deferral.
///
/// When a transaction is deferred due to a livelock cycle, a retry is created
/// with the same payload but a new hash (incorporating retry details).
/// This struct captures the lineage of the retry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub struct RetryDetails {
    /// Hash of the original transaction that was deferred.
    pub original_tx_hash: Hash,

    /// Which retry attempt this is (1 = first retry, 2 = second, etc.).
    pub retry_count: u32,

    /// Hash of the transaction that caused the deferral (the cycle winner).
    pub deferred_by: Hash,

    /// Block height where the deferral was committed.
    pub deferred_at: BlockHeight,
}

impl RetryDetails {
    /// Create details for the first retry of a transaction.
    pub fn first_retry(
        original_tx_hash: Hash,
        deferred_by: Hash,
        deferred_at: BlockHeight,
    ) -> Self {
        Self {
            original_tx_hash,
            retry_count: 1,
            deferred_by,
            deferred_at,
        }
    }

    /// Create details for a subsequent retry (bumping retry_count).
    pub fn next_retry(&self, deferred_by: Hash, deferred_at: BlockHeight) -> Self {
        Self {
            original_tx_hash: self.original_tx_hash,
            retry_count: self.retry_count + 1,
            deferred_by,
            deferred_at,
        }
    }

    /// Compute the additional bytes to include when hashing a retry transaction.
    ///
    /// The retry transaction hash = hash(original_payload || retry_details_bytes).
    /// This ensures each retry has a unique hash while maintaining a clear
    /// relationship to the original transaction.
    pub fn to_hash_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RETRY:");
        bytes.extend_from_slice(self.original_tx_hash.as_bytes());
        bytes.extend_from_slice(&self.retry_count.to_le_bytes());
        bytes.extend_from_slice(self.deferred_by.as_bytes());
        bytes.extend_from_slice(&self.deferred_at.0.to_le_bytes());
        bytes
    }
}

/// Transaction status for lifecycle tracking.
///
/// Transactions progress through these states:
///
/// **Normal Flow** (both single-shard and cross-shard):
/// ```text
/// Pending -> Committed -> Executed -> Completed
/// ```
///
/// **Cross-Shard with Conflict (Livelock Prevention)**:
/// ```text
/// Pending -> Committed -> [conflict detected] -> Deferred(by: winner)
///                                                      |
///                       [winner completes] -> Retried(new_tx: retry_hash)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionStatus {
    /// Transaction submitted, waiting to be included in a block.
    Pending,

    /// Block containing transaction has been committed.
    Committed(BlockHeight),

    /// Execution complete, TransactionCertificate has been created.
    Executed {
        decision: TransactionDecision,
        committed_at: BlockHeight,
    },

    /// Transaction has been fully processed and can be evicted.
    Completed(TransactionDecision),

    /// Transaction was deferred due to a cross-shard cycle.
    Deferred {
        /// Hash of the winning transaction we're waiting for.
        by: Hash,
    },

    /// Transaction has been superseded by a retry transaction.
    Retried {
        /// Hash of the retry transaction that supersedes this one.
        new_tx: Hash,
    },

    /// Transaction was aborted due to timeout or too many retries.
    Aborted {
        /// The reason for the abort.
        reason: AbortReason,
    },
}

impl TransactionStatus {
    /// Check if transaction is in a final state (won't transition further).
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Completed(_)
                | TransactionStatus::Retried { .. }
                | TransactionStatus::Aborted { .. }
        )
    }

    /// Check if transaction is ready to be included in a block.
    pub fn is_ready_for_block(&self) -> bool {
        matches!(self, TransactionStatus::Pending)
    }

    /// Check if this status means the transaction holds state locks.
    pub fn holds_state_lock(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Committed(_) | TransactionStatus::Executed { .. }
        )
    }

    /// Check if this transaction is deferred waiting for another transaction.
    pub fn is_deferred(&self) -> bool {
        matches!(self, TransactionStatus::Deferred { .. })
    }

    /// Get the hash of the blocking transaction if this transaction is deferred.
    pub fn deferred_by(&self) -> Option<&Hash> {
        match self {
            TransactionStatus::Deferred { by } => Some(by),
            _ => None,
        }
    }

    /// Check if this transaction has been superseded by a retry.
    pub fn is_retried(&self) -> bool {
        matches!(self, TransactionStatus::Retried { .. })
    }

    /// Get the hash of the retry transaction if this transaction was retried.
    pub fn retry_hash(&self) -> Option<&Hash> {
        match self {
            TransactionStatus::Retried { new_tx } => Some(new_tx),
            _ => None,
        }
    }

    /// Check if this transaction is in a state where it can be deferred.
    pub fn is_deferrable(&self) -> bool {
        matches!(self, TransactionStatus::Committed(_))
    }

    /// Returns a rough ordering value for the status in the normal lifecycle.
    pub fn ordinal(&self) -> u8 {
        match self {
            TransactionStatus::Pending => 0,
            TransactionStatus::Committed(_) => 1,
            TransactionStatus::Executed { .. } => 2,
            TransactionStatus::Completed(_) => 3,
            TransactionStatus::Deferred { .. } => 4,
            TransactionStatus::Retried { .. } => 5,
            TransactionStatus::Aborted { .. } => 6,
        }
    }

    /// Check if this transition is valid.
    pub fn can_transition_to(&self, next: &TransactionStatus) -> bool {
        use TransactionStatus::*;

        matches!(
            (self, next),
            (Pending, Committed(_))
                | (Pending, Retried { .. })
                | (Pending, Deferred { .. })
                | (Committed(_), Executed { .. })
                | (Committed(_), Deferred { .. })
                | (Committed(_), Retried { .. })
                | (Committed(_), Aborted { .. })
                | (Executed { .. }, Completed(_))
                | (Executed { .. }, Aborted { .. })
                | (Deferred { .. }, Retried { .. })
                | (Deferred { .. }, Aborted { .. })
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
            TransactionStatus::Completed(TransactionDecision::Accept) => {
                write!(f, "completed(accept)")
            }
            TransactionStatus::Completed(TransactionDecision::Reject) => {
                write!(f, "completed(reject)")
            }
            TransactionStatus::Deferred { by } => write!(f, "deferred({})", by),
            TransactionStatus::Retried { new_tx } => write!(f, "retried({})", new_tx),
            TransactionStatus::Aborted { reason } => write!(f, "aborted({})", reason),
        }
    }
}

impl std::str::FromStr for TransactionStatus {
    type Err = TransactionStatusParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "pending" {
            return Ok(TransactionStatus::Pending);
        }

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
            "deferred" => {
                let hash_str = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("deferred".into()))?;
                let hash = Hash::from_hex(hash_str)
                    .map_err(|_| TransactionStatusParseError::InvalidValue("hash".into()))?;
                Ok(TransactionStatus::Deferred { by: hash })
            }
            "retried" => {
                let hash_str = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("retried".into()))?;
                let hash = Hash::from_hex(hash_str)
                    .map_err(|_| TransactionStatusParseError::InvalidValue("hash".into()))?;
                Ok(TransactionStatus::Retried { new_tx: hash })
            }
            "aborted" => {
                let reason_str = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("aborted".into()))?;
                let reason = AbortReason::from_str(reason_str)
                    .map_err(|_| TransactionStatusParseError::InvalidValue("reason".into()))?;
                Ok(TransactionStatus::Aborted { reason })
            }
            _ => Err(TransactionStatusParseError::UnknownStatus(name.to_string())),
        }
    }
}

fn parse_decision(s: &str) -> Result<TransactionDecision, TransactionStatusParseError> {
    match s {
        "accept" => Ok(TransactionDecision::Accept),
        "reject" => Ok(TransactionDecision::Reject),
        _ => Err(TransactionStatusParseError::InvalidValue("decision".into())),
    }
}

/// Error parsing a TransactionStatus from a string.
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
            Self::UnknownStatus(s) => write!(f, "unknown status: {}", s),
            Self::InvalidFormat(s) => write!(f, "invalid format: {}", s),
            Self::MissingValue(s) => write!(f, "missing value for {}", s),
            Self::InvalidValue(s) => write!(f, "invalid {}", s),
        }
    }
}

impl std::error::Error for TransactionStatusParseError {}

/// Certificate proving transaction execution across all required shards.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionCertificate {
    /// Hash of the transaction this certificate finalizes.
    pub transaction_hash: Hash,

    /// Final decision: ACCEPT if all shards succeeded, REJECT otherwise.
    pub decision: TransactionDecision,

    /// Execution certificates from all participating shards, keyed by shard ID.
    pub shard_proofs: BTreeMap<ShardGroupId, crate::ExecutionCertificate>,
}

impl TransactionCertificate {
    /// Check if transaction was accepted.
    pub fn is_accepted(&self) -> bool {
        self.decision == TransactionDecision::Accept
    }

    /// Check if transaction was rejected.
    pub fn is_rejected(&self) -> bool {
        self.decision == TransactionDecision::Reject
    }

    /// Get number of shards involved.
    pub fn shard_count(&self) -> usize {
        self.shard_proofs.len()
    }

    /// Check if this is a single-shard transaction.
    pub fn is_single_shard(&self) -> bool {
        self.shard_proofs.len() <= 1
    }

    /// Check if this is a cross-shard transaction.
    pub fn is_cross_shard(&self) -> bool {
        self.shard_proofs.len() > 1
    }

    /// Get all shard IDs involved in this transaction.
    pub fn shard_ids(&self) -> Vec<ShardGroupId> {
        self.shard_proofs.keys().copied().collect()
    }

    /// Get certificate for a specific shard.
    pub fn certificate_for_shard(
        &self,
        shard_id: ShardGroupId,
    ) -> Option<&crate::ExecutionCertificate> {
        self.shard_proofs.get(&shard_id)
    }

    /// Get all read nodes across all shards.
    pub fn all_read_nodes(&self) -> Vec<NodeId> {
        self.shard_proofs
            .values()
            .flat_map(|cert| cert.read_nodes.iter().copied())
            .collect()
    }

    /// Check if all shards succeeded.
    pub fn all_shards_succeeded(&self) -> bool {
        self.shard_proofs.values().all(|cert| cert.success)
    }

    /// Get total number of read nodes across all shards.
    pub fn total_read_count(&self) -> usize {
        self.shard_proofs
            .values()
            .map(|cert| cert.read_nodes.len())
            .sum()
    }

    /// Combined receipt hash across all shards.
    pub fn receipt_hash(&self) -> Hash {
        let hashes: Vec<Hash> = self
            .shard_proofs
            .values()
            .map(|cert| cert.receipt_hash)
            .collect();
        match hashes.len() {
            0 => Hash::ZERO,
            1 => hashes[0],
            _ => crate::compute_merkle_root(&hashes),
        }
    }
}

/// Transaction error types.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// Transaction declares no writes (read-only transactions not supported).
    #[error("Transaction must declare at least one write")]
    NoWritesDeclared,

    /// A NodeId appears in both declared_reads and declared_writes.
    #[error("NodeId declared in both reads and writes")]
    DuplicateDeclaration,

    /// Failed to encode transaction.
    #[error("Failed to encode transaction: {0}")]
    EncodeFailed(String),

    /// Failed to decode transaction.
    #[error("Failed to decode transaction: {0}")]
    DecodeFailed(String),
}

/// Ready transactions organized by priority section.
///
/// Each section is sorted by transaction hash (from BTreeMap iteration order).
/// This structure allows block building without reclassification.
#[derive(Clone, Debug)]
pub struct ReadyTransactions<C: TypeConfig> {
    /// Retry transactions (highest priority, bypass soft limit).
    pub retries: Vec<std::sync::Arc<C::Transaction>>,
    /// Priority transactions (cross-shard with verified provisions, bypass soft limit).
    pub priority: Vec<std::sync::Arc<C::Transaction>>,
    /// Other transactions (subject to soft limit).
    pub others: Vec<std::sync::Arc<C::Transaction>>,
}

impl<C: TypeConfig> ReadyTransactions<C> {
    /// Total number of transactions across all sections.
    pub fn len(&self) -> usize {
        self.retries.len() + self.priority.len() + self.others.len()
    }

    /// Whether there are no transactions.
    pub fn is_empty(&self) -> bool {
        self.retries.is_empty() && self.priority.is_empty() && self.others.is_empty()
    }

    /// Iterate all transactions in priority order (retries, then priority, then others).
    pub fn iter(&self) -> impl Iterator<Item = &std::sync::Arc<C::Transaction>> {
        self.retries
            .iter()
            .chain(self.priority.iter())
            .chain(self.others.iter())
    }
}

impl<C: TypeConfig> Default for ReadyTransactions<C> {
    fn default() -> Self {
        Self {
            retries: Vec::new(),
            priority: Vec::new(),
            others: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_decision() {
        assert_ne!(TransactionDecision::Accept, TransactionDecision::Reject);
    }
}
