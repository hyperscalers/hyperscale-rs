//! Transaction types for consensus.

use crate::{BlockHeight, Hash, NodeId, ShardGroupId, StateCertificate, SubstateWrite};
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// A transaction with routing information.
///
/// Wraps a Radix `UserTransaction` with routing metadata for sharding.
pub struct RoutableTransaction {
    /// The underlying Radix transaction.
    transaction: UserTransaction,

    /// NodeIds that this transaction reads from.
    pub declared_reads: Vec<NodeId>,

    /// NodeIds that this transaction writes to.
    pub declared_writes: Vec<NodeId>,

    /// Retry details if this is a retry of a deferred transaction.
    ///
    /// When a transaction is deferred due to a cross-shard cycle, it is retried
    /// with the same payload but different retry_details, giving it a new hash.
    pub retry_details: Option<RetryDetails>,

    /// Cached hash (computed on first access).
    hash: Hash,

    /// Cached validated transaction (computed on first validation).
    /// This avoids re-validating signatures during execution.
    /// Not serialized - reconstructed on demand.
    /// Option because validation can theoretically fail (though shouldn't for RPC-validated txs).
    validated: OnceLock<Option<ValidatedUserTransaction>>,
}

// Manual PartialEq/Eq - compare by hash for efficiency
impl PartialEq for RoutableTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for RoutableTransaction {}

// Manual Clone - OnceLock doesn't implement Clone, and we don't want to clone the cached value
impl Clone for RoutableTransaction {
    fn clone(&self) -> Self {
        Self {
            transaction: self.transaction.clone(),
            declared_reads: self.declared_reads.clone(),
            declared_writes: self.declared_writes.clone(),
            retry_details: self.retry_details.clone(),
            hash: self.hash,
            validated: OnceLock::new(), // Don't clone cache - will be recomputed if needed
        }
    }
}

// Manual Debug - skip the validated field
impl std::fmt::Debug for RoutableTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutableTransaction")
            .field("hash", &self.hash)
            .field("declared_reads", &self.declared_reads)
            .field("declared_writes", &self.declared_writes)
            .field("retry_details", &self.retry_details)
            .finish_non_exhaustive()
    }
}

impl RoutableTransaction {
    /// Create a new routable transaction from a UserTransaction.
    pub fn new(
        transaction: UserTransaction,
        declared_reads: Vec<NodeId>,
        declared_writes: Vec<NodeId>,
    ) -> Self {
        Self::new_internal(transaction, declared_reads, declared_writes, None)
    }

    /// Internal constructor that handles retry_details.
    fn new_internal(
        transaction: UserTransaction,
        declared_reads: Vec<NodeId>,
        declared_writes: Vec<NodeId>,
        retry_details: Option<RetryDetails>,
    ) -> Self {
        // Hash includes transaction payload AND retry_details (if present)
        // This ensures retries have different hashes than originals
        let mut hasher = blake3::Hasher::new();
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");
        hasher.update(&payload);

        // Include retry_details in hash if present
        if let Some(details) = &retry_details {
            hasher.update(&details.to_hash_bytes());
        }

        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        Self {
            transaction,
            declared_reads,
            declared_writes,
            retry_details,
            hash,
            validated: OnceLock::new(),
        }
    }

    /// Get the transaction hash (content-addressed).
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /// Get a reference to the underlying Radix transaction.
    pub fn transaction(&self) -> &UserTransaction {
        &self.transaction
    }

    /// Consume self and return the underlying transaction.
    pub fn into_transaction(self) -> UserTransaction {
        self.transaction
    }

    /// Get or create a validated transaction.
    ///
    /// The first call validates the transaction and caches the result.
    /// Subsequent calls return the cached value, avoiding re-validation.
    ///
    /// Returns None if validation fails (should not happen for transactions
    /// that passed RPC validation).
    pub fn get_or_validate(
        &self,
        validator: &TransactionValidator,
    ) -> Option<&ValidatedUserTransaction> {
        self.validated
            .get_or_init(|| {
                self.transaction
                    .clone()
                    .prepare_and_validate(validator)
                    .ok()
            })
            .as_ref()
    }

    /// Check if this transaction has already been validated and cached.
    pub fn is_validated(&self) -> bool {
        self.validated.get().is_some()
    }

    /// Get the transaction as SBOR-encoded bytes.
    pub fn transaction_bytes(&self) -> Vec<u8> {
        manifest_encode(&self.transaction).expect("transaction should be encodable")
    }

    /// Check if this transaction is cross-shard for the given number of shards.
    pub fn is_cross_shard(&self, num_shards: u64) -> bool {
        if self.declared_writes.is_empty() {
            return false;
        }

        let first_shard = crate::shard_for_node(&self.declared_writes[0], num_shards);
        self.declared_writes
            .iter()
            .skip(1)
            .any(|node| crate::shard_for_node(node, num_shards) != first_shard)
    }

    /// All NodeIds this transaction declares access to.
    pub fn all_declared_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.declared_reads
            .iter()
            .chain(self.declared_writes.iter())
    }

    /// Create a retry of this transaction.
    ///
    /// The retry has the same underlying transaction and declared nodes,
    /// but different retry_details (and therefore a different hash).
    pub fn create_retry(&self, deferred_by: Hash, deferred_at: BlockHeight) -> Self {
        let details = match &self.retry_details {
            Some(existing) => existing.next_retry(deferred_by, deferred_at),
            None => RetryDetails::first_retry(self.hash(), deferred_by, deferred_at),
        };

        Self::new_internal(
            self.transaction.clone(),
            self.declared_reads.clone(),
            self.declared_writes.clone(),
            Some(details),
        )
    }

    /// Get the original transaction hash (before any retries).
    ///
    /// If this is a retry, returns the original_tx_hash from retry_details.
    /// If this is not a retry, returns this transaction's hash.
    pub fn original_hash(&self) -> Hash {
        self.retry_details
            .as_ref()
            .map(|d| d.original_tx_hash)
            .unwrap_or_else(|| self.hash())
    }

    /// Get the retry count (0 if this is not a retry).
    pub fn retry_count(&self) -> u32 {
        self.retry_details
            .as_ref()
            .map(|d| d.retry_count)
            .unwrap_or(0)
    }

    /// Check if this transaction has exceeded the maximum retry limit.
    pub fn exceeds_max_retries(&self, max_retries: u32) -> bool {
        self.retry_count() >= max_retries
    }

    /// Check if this is a retry transaction.
    pub fn is_retry(&self) -> bool {
        self.retry_details.is_some()
    }
}

// ============================================================================
// Manual SBOR implementation since UserTransaction uses ManifestSbor
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for RoutableTransaction
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(5)?; // 5 fields

        // Encode hash as [u8; 32]
        let hash_bytes: [u8; 32] = *self.hash.as_bytes();
        encoder.encode(&hash_bytes)?;

        // Encode transaction as bytes (using ManifestSbor)
        let tx_bytes = manifest_encode(&self.transaction)
            .map_err(|_| sbor::EncodeError::MaxDepthExceeded(0))?;
        encoder.encode(&tx_bytes)?;

        // Encode declared_reads
        encoder.encode(&self.declared_reads)?;

        // Encode declared_writes
        encoder.encode(&self.declared_writes)?;

        // Encode retry_details
        encoder.encode(&self.retry_details)?;

        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for RoutableTransaction
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 5 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 5,
                actual: length,
            });
        }

        // Decode hash (stored as [u8; 32])
        let hash_bytes: [u8; 32] = decoder.decode()?;
        let hash = Hash::from_hash_bytes(&hash_bytes);

        // Decode transaction bytes and convert to UserTransaction
        let tx_bytes: Vec<u8> = decoder.decode()?;
        let transaction: UserTransaction =
            manifest_decode(&tx_bytes).map_err(|_| sbor::DecodeError::InvalidCustomValue)?;

        // Decode declared_reads
        let declared_reads: Vec<NodeId> = decoder.decode()?;

        // Decode declared_writes
        let declared_writes: Vec<NodeId> = decoder.decode()?;

        // Decode retry_details
        let retry_details: Option<RetryDetails> = decoder.decode()?;

        Ok(Self {
            hash,
            transaction,
            declared_reads,
            declared_writes,
            retry_details,
            validated: OnceLock::new(),
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for RoutableTransaction {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for RoutableTransaction {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("RoutableTransaction", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

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
/// blocked and will be retried later.
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionDefer {
    /// Hash of the transaction being deferred.
    pub tx_hash: Hash,

    /// Why the transaction was deferred.
    pub reason: DeferReason,

    /// Block height where this deferral is being committed.
    /// Used for timeout calculations on the retry.
    pub block_height: BlockHeight,
}

impl TransactionDefer {
    /// Create a new transaction deferral for a livelock cycle.
    pub fn livelock_cycle(tx_hash: Hash, winner_tx_hash: Hash, block_height: BlockHeight) -> Self {
        Self {
            tx_hash,
            reason: DeferReason::LivelockCycle { winner_tx_hash },
            block_height,
        }
    }

    /// Get the winner transaction hash if this was a livelock cycle deferral.
    pub fn winner_hash(&self) -> Option<&Hash> {
        match &self.reason {
            DeferReason::LivelockCycle { winner_tx_hash } => Some(winner_tx_hash),
        }
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
/// Pending → Committed → Executed → Completed
/// ```
///
/// **Cross-Shard with Conflict (Livelock Prevention)**:
/// ```text
/// Pending → Committed → [conflict detected] → Blocked(by: winner)
///                                                      ↓
///                       [winner completes] → Retried(new_tx: retry_hash)
/// ```
///
/// # State Descriptions
///
/// - **Pending**: Transaction has been submitted but not yet included in a committed block
/// - **Committed**: Block containing transaction has been committed; execution is in progress
/// - **Executed**: Execution complete, certificate created (state NOT yet updated - waiting for block)
/// - **Completed**: Certificate committed in block, state updated, transaction done
/// - **Blocked**: Transaction was deferred due to cross-shard conflict, waiting for winner
/// - **Retried**: Transaction was superseded by a retry transaction (terminal)
///
/// # Note on Intermediate States
///
/// The execution state machine internally tracks finer-grained progress (provisioning,
/// executing, collecting votes/certificates), but the mempool only needs to know:
/// - Is the transaction holding state locks? (Committed, Executed)
/// - Is it done? (Completed, Retried)
/// - Is it blocked? (Blocked)
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub enum TransactionStatus {
    /// Transaction submitted, waiting to be included in a block.
    Pending,

    /// Block containing transaction has been committed.
    ///
    /// The transaction is now being executed. This state holds locks on all
    /// declared nodes until execution completes (Executed) or the transaction
    /// is deferred (Blocked/Retried).
    ///
    /// For cross-shard transactions, this encompasses:
    /// - State provisioning (collecting state from other shards)
    /// - Execution (running the transaction logic)
    /// - Vote collection (gathering 2f+1 votes for state certificate)
    /// - Certificate collection (gathering certificates from all shards)
    Committed(BlockHeight),

    /// Execution complete, TransactionCertificate has been created.
    ///
    /// All StateCertificates have been collected and aggregated into a
    /// TransactionCertificate with Accept or Reject decision.
    ///
    /// **Important**: State is NOT yet updated at this point. The certificate
    /// must be included in a block before state changes are applied. The
    /// transaction is waiting for the certificate to be committed.
    ///
    /// Still holds state locks until Completed.
    Executed(TransactionDecision),

    /// Transaction has been fully processed and can be evicted.
    ///
    /// The TransactionCertificate has been committed in a block. State changes
    /// have been applied (if accepted). This is the terminal state - the
    /// transaction can now be safely removed from the mempool.
    ///
    /// Contains the final decision (Accept/Reject) from execution.
    Completed(TransactionDecision),

    /// Transaction was deferred due to a cross-shard cycle.
    ///
    /// The transaction had a lower-hash transaction conflict with it across shards.
    /// It is waiting for the winning transaction to complete before being retried.
    /// This status does NOT hold state locks - locks are released when entering this state.
    Blocked {
        /// Hash of the winning transaction we're waiting for.
        by: Hash,
    },

    /// Transaction has been superseded by a retry transaction.
    ///
    /// This is a terminal state for the original TX - it will never execute.
    /// The new transaction (`new_tx`) has the same payload but a different hash.
    /// This status does NOT hold state locks.
    Retried {
        /// Hash of the retry transaction that supersedes this one.
        new_tx: Hash,
    },

    /// Transaction was aborted due to timeout or too many retries.
    ///
    /// This is a terminal state - the transaction will not be retried again.
    /// This status does NOT hold state locks.
    Aborted {
        /// The reason for the abort.
        reason: AbortReason,
    },
}

impl TransactionStatus {
    /// Check if transaction is in a final state (won't transition further).
    ///
    /// Terminal states:
    /// - `Completed`: Transaction executed and certificate committed
    /// - `Retried`: Transaction was superseded by a retry (original will never execute)
    /// - `Aborted`: Transaction was aborted due to timeout or too many retries
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Completed(_)
                | TransactionStatus::Retried { .. }
                | TransactionStatus::Aborted { .. }
        )
    }

    /// Check if transaction is ready to be included in a block.
    ///
    /// Only Pending transactions can be selected by the block proposer.
    pub fn is_ready_for_block(&self) -> bool {
        matches!(self, TransactionStatus::Pending)
    }

    /// Check if this status means the transaction holds state locks.
    ///
    /// State locks are acquired when a transaction is committed in a block and
    /// released when the TransactionCertificate is committed in a block (Completed),
    /// or when the transaction is deferred (Blocked/Retried).
    ///
    /// The lock prevents conflicting transactions from being selected for blocks
    /// while this transaction is being executed.
    ///
    /// The following statuses do NOT hold locks:
    /// - Pending: not yet committed into a block
    /// - Completed: certificate committed, transaction done
    /// - Blocked: deferred due to conflict, locks released
    /// - Retried: superseded by retry transaction, locks released
    /// - Aborted: transaction aborted, locks released
    pub fn holds_state_lock(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Committed(_) | TransactionStatus::Executed(_)
        )
    }

    /// Check if this transaction is blocked waiting for another transaction.
    pub fn is_blocked(&self) -> bool {
        matches!(self, TransactionStatus::Blocked { .. })
    }

    /// Get the hash of the blocking transaction if this transaction is blocked.
    pub fn blocked_by(&self) -> Option<&Hash> {
        match self {
            TransactionStatus::Blocked { by } => Some(by),
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
    ///
    /// Transactions can be deferred if they are in Committed state (executing).
    /// States that cannot be deferred:
    /// - Pre-lock states: Pending (no locks held yet)
    /// - Terminal states: Executed, Completed (too late to defer)
    /// - Already deferred: Blocked, Retried (already handled)
    pub fn is_deferrable(&self) -> bool {
        matches!(self, TransactionStatus::Committed(_))
    }

    /// Returns a rough ordering value for the status in the normal lifecycle.
    ///
    /// This is used to detect stale status updates (where we've already progressed
    /// past the incoming status). Note that this doesn't capture all valid transitions
    /// (e.g., Blocked/Retried can happen from multiple states), but it helps identify
    /// clearly stale updates.
    ///
    /// Ordering: Pending(0) < Committed(1) < Executed(2) < Completed(3)
    ///
    /// Blocked, Retried, and Aborted are terminal side-branches and get high ordinals (4, 5, 6).
    pub fn ordinal(&self) -> u8 {
        match self {
            TransactionStatus::Pending => 0,
            TransactionStatus::Committed(_) => 1,
            TransactionStatus::Executed(_) => 2,
            TransactionStatus::Completed(_) => 3,
            TransactionStatus::Blocked { .. } => 4,
            TransactionStatus::Retried { .. } => 5,
            TransactionStatus::Aborted { .. } => 6,
        }
    }

    /// Check if this transition is valid.
    pub fn can_transition_to(&self, next: &TransactionStatus) -> bool {
        use TransactionStatus::*;

        match (self, next) {
            // Pending → Committed
            (Pending, Committed(_)) => true,

            // Pending → Retried (if a retry arrived before original was committed)
            (Pending, Retried { .. }) => true,

            // Pending → Blocked (cross-shard livelock prevention)
            (Pending, Blocked { .. }) => true,

            // Committed → Executed (execution complete, certificate created)
            (Committed(_), Executed(_)) => true,

            // Committed → Blocked (deferred due to conflict)
            (Committed(_), Blocked { .. }) => true,

            // Committed → Retried (superseded by retry from another shard)
            (Committed(_), Retried { .. }) => true,

            // Committed → Aborted (timeout or too many retries)
            (Committed(_), Aborted { .. }) => true,

            // Executed → Completed (certificate committed in block)
            (Executed(_), Completed(_)) => true,

            // Executed → Aborted (execution rejected or timeout)
            (Executed(_), Aborted { .. }) => true,

            // Blocked → Retried (when winner completes, loser gets a retry)
            (Blocked { .. }, Retried { .. }) => true,

            // Blocked → Aborted (too many retries)
            (Blocked { .. }, Aborted { .. }) => true,

            // No other transitions are valid
            _ => false,
        }
    }
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Pending => write!(f, "pending"),
            TransactionStatus::Committed(height) => write!(f, "committed({})", height.0),
            TransactionStatus::Executed(TransactionDecision::Accept) => {
                write!(f, "executed(accept)")
            }
            TransactionStatus::Executed(TransactionDecision::Reject) => {
                write!(f, "executed(reject)")
            }
            TransactionStatus::Completed(TransactionDecision::Accept) => {
                write!(f, "completed(accept)")
            }
            TransactionStatus::Completed(TransactionDecision::Reject) => {
                write!(f, "completed(reject)")
            }
            TransactionStatus::Blocked { by } => write!(f, "blocked({})", by),
            TransactionStatus::Retried { new_tx } => write!(f, "retried({})", new_tx),
            TransactionStatus::Aborted { reason } => write!(f, "aborted({})", reason),
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
                Ok(TransactionStatus::Executed(decision))
            }
            "completed" => {
                let decision = parse_decision(inner.ok_or_else(|| {
                    TransactionStatusParseError::MissingValue("completed".into())
                })?)?;
                Ok(TransactionStatus::Completed(decision))
            }
            "blocked" => {
                let hash_str = inner
                    .ok_or_else(|| TransactionStatusParseError::MissingValue("blocked".into()))?;
                let hash = Hash::from_hex(hash_str)
                    .map_err(|_| TransactionStatusParseError::InvalidValue("hash".into()))?;
                Ok(TransactionStatus::Blocked { by: hash })
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

    /// State certificates from all participating shards, keyed by shard ID.
    /// Each certificate contains read_nodes, state_writes, signatures, etc.
    pub shard_proofs: BTreeMap<ShardGroupId, StateCertificate>,
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
    pub fn certificate_for_shard(&self, shard_id: ShardGroupId) -> Option<&StateCertificate> {
        self.shard_proofs.get(&shard_id)
    }

    /// Get all read nodes across all shards.
    pub fn all_read_nodes(&self) -> Vec<NodeId> {
        self.shard_proofs
            .values()
            .flat_map(|cert| cert.read_nodes.iter().copied())
            .collect()
    }

    /// Get all state writes across all shards.
    pub fn all_state_writes(&self) -> Vec<SubstateWrite> {
        self.shard_proofs
            .values()
            .flat_map(|cert| cert.state_writes.iter().cloned())
            .collect()
    }

    /// Check if all shards succeeded.
    pub fn all_shards_succeeded(&self) -> bool {
        self.shard_proofs.values().all(|cert| cert.success)
    }

    /// Get total number of state writes across all shards.
    pub fn total_write_count(&self) -> usize {
        self.shard_proofs
            .values()
            .map(|cert| cert.state_writes.len())
            .sum()
    }

    /// Get total number of read nodes across all shards.
    pub fn total_read_count(&self) -> usize {
        self.shard_proofs
            .values()
            .map(|cert| cert.read_nodes.len())
            .sum()
    }
}

// ============================================================================
// Transaction Signing Utilities
// ============================================================================

use radix_common::crypto::IsHash;
use radix_common::data::manifest::model::{ManifestGlobalAddress, ManifestPackageAddress};
use radix_common::network::NetworkDefinition;
use radix_common::prelude::Epoch;
use radix_transactions::model::{
    HasSignedTransactionIntentHash, HasTransactionIntentHash, InstructionV1, InstructionV2,
    IntentSignatureV1, IntentSignaturesV1, IntentV1, NotarizedTransactionV1,
    NotarizedTransactionV2, NotarySignatureV1, SignatureV1, SignatureWithPublicKeyV1,
    SignedIntentV1, TransactionHeaderV1, TransactionPayload,
};
use radix_transactions::prelude::{PreparationSettings, TransactionManifestV1};
use std::collections::HashSet;
use thiserror::Error;

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

// ============================================================================
// TryFrom implementations for NotarizedTransaction -> RoutableTransaction
// ============================================================================

/// Convert a `NotarizedTransactionV1` into a `RoutableTransaction`.
impl TryFrom<NotarizedTransactionV1> for RoutableTransaction {
    type Error = TransactionError;

    fn try_from(notarized: NotarizedTransactionV1) -> Result<Self, Self::Error> {
        let instructions = &notarized.signed_intent.intent.instructions.0;
        let (read_nodes, write_nodes) = analyze_instructions_v1(instructions);
        Ok(RoutableTransaction::new(
            UserTransaction::V1(notarized),
            read_nodes,
            write_nodes,
        ))
    }
}

/// Convert a `NotarizedTransactionV2` into a `RoutableTransaction`.
impl TryFrom<NotarizedTransactionV2> for RoutableTransaction {
    type Error = TransactionError;

    fn try_from(notarized: NotarizedTransactionV2) -> Result<Self, Self::Error> {
        let root_instructions = &notarized
            .signed_transaction_intent
            .transaction_intent
            .root_intent_core
            .instructions
            .0;

        let (mut read_nodes, mut write_nodes) = analyze_instructions_v2(root_instructions);

        // Also analyze all non-root subintents
        for subintent in &notarized
            .signed_transaction_intent
            .transaction_intent
            .non_root_subintents
            .0
        {
            let (sub_reads, sub_writes) =
                analyze_instructions_v2(&subintent.intent_core.instructions.0);
            read_nodes.extend(sub_reads);
            write_nodes.extend(sub_writes);
        }

        // Deduplicate
        let write_set: HashSet<_> = write_nodes.into_iter().collect();
        let read_set: HashSet<_> = read_nodes
            .into_iter()
            .filter(|n| !write_set.contains(n))
            .collect();

        Ok(RoutableTransaction::new(
            UserTransaction::V2(notarized),
            read_set.into_iter().collect(),
            write_set.into_iter().collect(),
        ))
    }
}

/// Convert a `UserTransaction` (V1 or V2) into a `RoutableTransaction`.
impl TryFrom<UserTransaction> for RoutableTransaction {
    type Error = TransactionError;

    fn try_from(transaction: UserTransaction) -> Result<Self, Self::Error> {
        match transaction {
            UserTransaction::V1(v1) => v1.try_into(),
            UserTransaction::V2(v2) => v2.try_into(),
        }
    }
}

// ============================================================================
// Instruction Analysis
// ============================================================================

/// Analyze V1 transaction instructions to extract accessed NodeIds.
fn analyze_instructions_v1(instructions: &[InstructionV1]) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions.iter() {
        extract_node_ids_from_instruction_v1(instruction, &mut reads, &mut writes);
    }

    filter_and_deduplicate(reads, writes)
}

/// Analyze V2 transaction instructions to extract accessed NodeIds.
fn analyze_instructions_v2(instructions: &[InstructionV2]) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions.iter() {
        extract_node_ids_from_instruction_v2(instruction, &mut reads, &mut writes);
    }

    filter_and_deduplicate(reads, writes)
}

/// Filter out system entities and deduplicate read/write sets.
fn filter_and_deduplicate(
    reads: HashSet<NodeId>,
    writes: HashSet<NodeId>,
) -> (Vec<NodeId>, Vec<NodeId>) {
    let writes: HashSet<NodeId> = writes
        .into_iter()
        .filter(|node_id| !is_system_entity(node_id))
        .collect();

    let reads: Vec<NodeId> = reads
        .into_iter()
        .filter(|node_id| !is_system_entity(node_id) && !writes.contains(node_id))
        .collect();

    (reads, writes.into_iter().collect())
}

/// Extract NodeIds from a single V1 instruction.
fn extract_node_ids_from_instruction_v1(
    instruction: &InstructionV1,
    reads: &mut HashSet<NodeId>,
    writes: &mut HashSet<NodeId>,
) {
    match instruction {
        InstructionV1::CallMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallRoyaltyMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
            }
        }
        InstructionV1::CallMetadataMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallRoleAssignmentMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV1::CallDirectVaultMethod(inner) => {
            let node_id = NodeId(inner.address.into_node_id().0);
            reads.insert(node_id);
            writes.insert(node_id);
        }
        InstructionV1::CallFunction(inner) => {
            if let Some(node_id) = manifest_package_to_node_id(&inner.package_address) {
                reads.insert(node_id);
            }
        }
        InstructionV1::TakeFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::TakeNonFungiblesFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::TakeAllFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContainsAny(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContains(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AssertWorktopContainsNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfAmount(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::CreateProofFromAuthZoneOfAll(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV1::AllocateGlobalAddress(inner) => {
            reads.insert(NodeId(inner.package_address.into_node_id().0));
        }
        _ => {}
    }
}

/// Extract NodeIds from a single V2 instruction.
fn extract_node_ids_from_instruction_v2(
    instruction: &InstructionV2,
    reads: &mut HashSet<NodeId>,
    writes: &mut HashSet<NodeId>,
) {
    match instruction {
        InstructionV2::CallMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallRoyaltyMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
            }
        }
        InstructionV2::CallMetadataMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallRoleAssignmentMethod(inner) => {
            if let Some(node_id) = manifest_address_to_node_id(&inner.address) {
                reads.insert(node_id);
                writes.insert(node_id);
            }
        }
        InstructionV2::CallDirectVaultMethod(inner) => {
            let node_id = NodeId(inner.address.into_node_id().0);
            reads.insert(node_id);
            writes.insert(node_id);
        }
        InstructionV2::CallFunction(inner) => {
            if let Some(node_id) = manifest_package_to_node_id(&inner.package_address) {
                reads.insert(node_id);
            }
        }
        InstructionV2::TakeFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::TakeNonFungiblesFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::TakeAllFromWorktop(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContainsAny(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContains(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AssertWorktopContainsNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfAmount(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfNonFungibles(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::CreateProofFromAuthZoneOfAll(inner) => {
            reads.insert(NodeId(inner.resource_address.into_node_id().0));
        }
        InstructionV2::AllocateGlobalAddress(inner) => {
            reads.insert(NodeId(inner.package_address.into_node_id().0));
        }
        InstructionV2::YieldToParent(_)
        | InstructionV2::YieldToChild(_)
        | InstructionV2::VerifyParent(_) => {}
        _ => {}
    }
}

/// Convert a manifest global address to a NodeId if possible.
fn manifest_address_to_node_id(address: &ManifestGlobalAddress) -> Option<NodeId> {
    match address {
        ManifestGlobalAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestGlobalAddress::Named(_) => None,
    }
}

/// Convert a manifest package address to a NodeId if possible.
fn manifest_package_to_node_id(address: &ManifestPackageAddress) -> Option<NodeId> {
    match address {
        ManifestPackageAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestPackageAddress::Named(_) => None,
    }
}

/// Check if a NodeId is a system entity that should be replicated to all shards.
fn is_system_entity(node_id: &NodeId) -> bool {
    is_system_package(node_id) || is_system_component(node_id) || is_system_resource(node_id)
}

/// Check if a NodeId belongs to a well-known system package.
fn is_system_package(node_id: &NodeId) -> bool {
    use radix_common::constants::*;

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_packages = [
        PACKAGE_PACKAGE,
        RESOURCE_PACKAGE,
        ACCOUNT_PACKAGE,
        IDENTITY_PACKAGE,
        CONSENSUS_MANAGER_PACKAGE,
        ACCESS_CONTROLLER_PACKAGE,
        POOL_PACKAGE,
        TRANSACTION_PROCESSOR_PACKAGE,
        METADATA_MODULE_PACKAGE,
        ROYALTY_MODULE_PACKAGE,
        ROLE_ASSIGNMENT_MODULE_PACKAGE,
        GENESIS_HELPER_PACKAGE,
        FAUCET_PACKAGE,
        TRANSACTION_TRACKER_PACKAGE,
        LOCKER_PACKAGE,
    ];

    well_known_packages
        .iter()
        .any(|pkg| pkg.as_node_id() == &radix_node_id)
}

/// Check if a NodeId belongs to a well-known system component.
fn is_system_component(node_id: &NodeId) -> bool {
    use radix_common::constants::*;

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_components = [
        CONSENSUS_MANAGER,
        GENESIS_HELPER,
        FAUCET,
        TRANSACTION_TRACKER,
    ];

    well_known_components
        .iter()
        .any(|comp| comp.as_node_id() == &radix_node_id)
}

/// Check if a NodeId belongs to a well-known system resource.
fn is_system_resource(node_id: &NodeId) -> bool {
    use radix_common::constants::*;

    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let well_known_resources = [
        XRD,
        SECP256K1_SIGNATURE_RESOURCE,
        ED25519_SIGNATURE_RESOURCE,
        SYSTEM_EXECUTION_RESOURCE,
        PACKAGE_OF_DIRECT_CALLER_RESOURCE,
        GLOBAL_CALLER_RESOURCE,
        PACKAGE_OWNER_BADGE,
        VALIDATOR_OWNER_BADGE,
        ACCOUNT_OWNER_BADGE,
        IDENTITY_OWNER_BADGE,
    ];

    well_known_resources
        .iter()
        .any(|res| res.as_node_id() == &radix_node_id)
}

/// Sign and notarize a transaction manifest.
///
/// This takes a pre-built manifest and signs it with the provided keypair,
/// producing a fully notarized transaction ready for conversion to `RoutableTransaction`.
///
/// # Arguments
///
/// * `manifest` - The transaction manifest built using `ManifestBuilder`
/// * `network` - The network definition
/// * `nonce` - Transaction nonce for replay protection
/// * `signer` - The keypair to sign with (acts as both signer and notary)
pub fn sign_and_notarize(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    signer: &crate::KeyPair,
) -> Result<NotarizedTransactionV1, TransactionError> {
    sign_and_notarize_with_options(
        manifest,
        network,
        nonce,
        0,              // tip_percentage
        Epoch::of(0),   // start_epoch
        Epoch::of(100), // end_epoch (Radix has ~100 epoch max range)
        signer,
    )
}

/// Sign and notarize a transaction manifest with full options.
///
/// This provides full control over transaction header parameters.
pub fn sign_and_notarize_with_options(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    tip_percentage: u16,
    start_epoch: Epoch,
    end_epoch: Epoch,
    signer: &crate::KeyPair,
) -> Result<NotarizedTransactionV1, TransactionError> {
    let (instructions, blobs) = manifest.for_intent();
    let notary_public_key = convert_public_key(signer.public_key());

    let intent = IntentV1 {
        header: TransactionHeaderV1 {
            network_id: network.id,
            start_epoch_inclusive: start_epoch,
            end_epoch_exclusive: end_epoch,
            nonce,
            notary_public_key,
            notary_is_signatory: true,
            tip_percentage,
        },
        instructions,
        blobs,
        message: radix_transactions::prelude::MessageV1::None,
    };

    // Prepare and sign the intent
    let prepared_intent = intent
        .prepare(&PreparationSettings::latest())
        .map_err(|e| TransactionError::EncodeFailed(format!("{:?}", e)))?;

    let intent_hash = *prepared_intent
        .transaction_intent_hash()
        .as_hash()
        .as_bytes();
    let intent_signature = sign_hash(signer, &intent_hash);

    let signed_intent = SignedIntentV1 {
        intent,
        intent_signatures: IntentSignaturesV1 {
            signatures: vec![IntentSignatureV1(intent_signature)],
        },
    };

    // Prepare and notarize the signed intent
    let prepared_signed = signed_intent
        .prepare(&PreparationSettings::latest())
        .map_err(|e| TransactionError::EncodeFailed(format!("{:?}", e)))?;

    let signed_intent_hash = *prepared_signed
        .signed_transaction_intent_hash()
        .as_hash()
        .as_bytes();
    let notary_signature = sign_hash_as_notary(signer, &signed_intent_hash);

    Ok(NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(notary_signature),
    })
}

/// Convert our PublicKey to Radix PublicKey.
fn convert_public_key(pk: crate::PublicKey) -> radix_common::crypto::PublicKey {
    match pk {
        crate::PublicKey::Ed25519(bytes) => {
            radix_common::crypto::PublicKey::Ed25519(radix_common::crypto::Ed25519PublicKey(bytes))
        }
        crate::PublicKey::Bls12381(_) => {
            panic!("BLS12-381 keys are not supported for Radix transactions")
        }
    }
}

/// Sign a hash and return a signature with public key.
fn sign_hash(signer: &crate::KeyPair, hash: &[u8; 32]) -> SignatureWithPublicKeyV1 {
    let sig = signer.sign(hash);
    let sig_bytes = sig.to_bytes();

    match signer.public_key() {
        crate::PublicKey::Ed25519(pk_bytes) => {
            let mut sig_array = [0u8; 64];
            let len = sig_bytes.len().min(64);
            sig_array[..len].copy_from_slice(&sig_bytes[..len]);

            SignatureWithPublicKeyV1::Ed25519 {
                public_key: radix_common::crypto::Ed25519PublicKey(pk_bytes),
                signature: radix_common::crypto::Ed25519Signature(sig_array),
            }
        }
        crate::PublicKey::Bls12381(_) => {
            panic!("BLS12-381 keys are not supported for Radix transactions")
        }
    }
}

/// Sign a hash for notarization (returns just the signature).
fn sign_hash_as_notary(signer: &crate::KeyPair, hash: &[u8; 32]) -> SignatureV1 {
    let sig = signer.sign(hash);
    let sig_bytes = sig.to_bytes();

    match signer.public_key() {
        crate::PublicKey::Ed25519(_) => {
            let mut sig_array = [0u8; 64];
            let len = sig_bytes.len().min(64);
            sig_array[..len].copy_from_slice(&sig_bytes[..len]);

            SignatureV1::Ed25519(radix_common::crypto::Ed25519Signature(sig_array))
        }
        crate::PublicKey::Bls12381(_) => {
            panic!("BLS12-381 keys are not supported for Radix transactions")
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
