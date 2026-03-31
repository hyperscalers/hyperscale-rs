//! Transaction types for consensus.

use crate::{
    BlockHeight, Hash, NodeId, ShardExecutionProof, ShardGroupId, TransactionInclusionProof,
};
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

    /// Cached hash (computed on first access).
    hash: Hash,

    /// Cached serialized transaction bytes.
    ///
    /// These are the SBOR-encoded bytes of the `UserTransaction`, captured during
    /// construction or deserialization. This avoids redundant re-serialization when:
    /// - Computing transaction merkle roots for block headers
    /// - Re-encoding for network transmission
    ///
    /// The hash is computed from these bytes.
    serialized_bytes: Vec<u8>,

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
            hash: self.hash,
            serialized_bytes: self.serialized_bytes.clone(),
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
        // Serialize the transaction payload - we keep these bytes for:
        // 1. Computing the hash (below)
        // 2. Efficient re-encoding for network/merkle (via serialized_bytes())
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");

        // Hash the transaction payload directly
        let mut hasher = blake3::Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        Self {
            transaction,
            declared_reads,
            declared_writes,
            hash,
            serialized_bytes: payload,
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

    /// Get the cached serialized transaction bytes.
    ///
    /// These are the SBOR-encoded bytes of the underlying `UserTransaction`,
    /// captured during construction or deserialization. Use this for:
    /// - Computing transaction merkle roots (avoids re-serialization)
    /// - Network encoding (bytes are ready to use)
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized_bytes
    }

    /// Get the transaction as SBOR-encoded bytes.
    ///
    /// This returns a clone of the cached serialized bytes. For read-only access,
    /// prefer `serialized_bytes()` which returns a reference.
    pub fn transaction_bytes(&self) -> Vec<u8> {
        self.serialized_bytes.clone()
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
        encoder.write_size(4)?; // 4 fields

        // Encode hash as [u8; 32]
        let hash_bytes: [u8; 32] = *self.hash.as_bytes();
        encoder.encode(&hash_bytes)?;

        // Encode transaction as bytes (using cached serialized_bytes)
        encoder.encode(&self.serialized_bytes)?;

        // Encode declared_reads
        encoder.encode(&self.declared_reads)?;

        // Encode declared_writes
        encoder.encode(&self.declared_writes)?;

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

        if length != 4 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 4,
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

        Ok(Self {
            hash,
            transaction,
            declared_reads,
            declared_writes,
            serialized_bytes: tx_bytes,
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

// ============================================================================
// Livelock Prevention Types
// ============================================================================

/// Reason a transaction was aborted.
///
/// Aborts are terminal - the transaction will not be retried and any held
/// resources are released. Abort reasons are carried in `AbortIntent` (block
/// level) and `TxExecutionOutcome::Aborted` (EC level). By TC level, the
/// reason has served its purpose — `TransactionDecision::Aborted` carries
/// no reason.
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

    /// Livelock cycle detected — this transaction is the loser (higher hash).
    ///
    /// When two transactions form a bidirectional cross-shard cycle, the
    /// transaction with the higher hash loses and is aborted. The winner
    /// (lower hash) continues normally.
    LivelockCycle {
        /// Hash of the transaction that won the cycle (lower hash wins).
        winner_tx_hash: Hash,
        /// Source shard where the winner transaction was committed.
        source_shard: ShardGroupId,
        /// Block height on the source shard where the winner was committed.
        source_block_height: BlockHeight,
        /// Merkle inclusion proof for the winner transaction in the source block.
        tx_inclusion_proof: TransactionInclusionProof,
    },
}

impl std::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbortReason::ExecutionTimeout { committed_at } => {
                write!(f, "timeout({})", committed_at.0)
            }
            AbortReason::LivelockCycle {
                winner_tx_hash,
                source_shard,
                ..
            } => {
                write!(
                    f,
                    "livelock(winner: {}, source: {})",
                    winner_tx_hash, source_shard.0
                )
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
            "livelock" => {
                // Display format is "livelock(winner: <hash>, source: <shard>)"
                // Best-effort parse: recovers winner_tx_hash and source_shard.
                // The inclusion proof is not round-trippable through strings, so we
                // use a dummy proof. This is sufficient for status display / logging.
                let parts: Vec<&str> = inner.splitn(2, ", source: ").collect();
                if parts.len() != 2 {
                    return Err(format!("invalid livelock format: {}", inner));
                }
                let winner_str = parts[0].strip_prefix("winner: ").ok_or_else(|| {
                    format!("missing 'winner: ' prefix in livelock reason: {}", inner)
                })?;
                let winner_tx_hash = Hash::from_hex(winner_str)
                    .map_err(|e| format!("invalid winner hash: {}", e))?;
                let source_shard = parts[1]
                    .parse::<u64>()
                    .map_err(|_| format!("invalid source shard: {}", parts[1]))?;
                Ok(AbortReason::LivelockCycle {
                    winner_tx_hash,
                    source_shard: ShardGroupId(source_shard),
                    source_block_height: BlockHeight(0),
                    tx_inclusion_proof: TransactionInclusionProof {
                        siblings: vec![],
                        leaf_index: 0,
                    },
                })
            }
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

    /// Check if this abort is due to a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self.reason, AbortReason::ExecutionTimeout { .. })
    }
}

/// An abort intent included in a block.
///
/// Abort intents are proposals to the execution voting process. They feed into
/// the execution accumulator but do not directly change mempool state. The
/// actual abort takes effect only when a Transaction Certificate confirms it.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct AbortIntent {
    /// Hash of the transaction to abort.
    pub tx_hash: Hash,

    /// Why the transaction should be aborted.
    pub reason: AbortReason,

    /// Block height where this intent is being committed.
    pub block_height: BlockHeight,
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

    /// Execution complete, TransactionCertificate has been created.
    ///
    /// All shard execution proofs have been collected and aggregated into a
    /// TransactionCertificate with Accept or Reject decision.
    ///
    /// **Important**: State is NOT yet updated at this point. The certificate
    /// must be included in a block before state changes are applied. The
    /// transaction is waiting for the certificate to be committed.
    ///
    /// Still holds state locks until Completed.
    Executed {
        decision: TransactionDecision,
        /// Block height when the transaction was originally committed.
        /// Preserved from Committed state for timeout tracking - cross-shard
        /// transactions can get stuck in Executed state if certificate inclusion
        /// fails on another shard.
        committed_at: BlockHeight,
    },

    /// Transaction has been fully processed and can be evicted.
    ///
    /// The TransactionCertificate has been committed in a block. State changes
    /// have been applied (if accepted). This is the terminal state - the
    /// transaction can now be safely removed from the mempool.
    ///
    /// Contains the final decision (Accept/Reject/Aborted) from execution.
    Completed(TransactionDecision),

    /// Transaction was aborted due to timeout or livelock.
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
    /// - `Aborted`: Transaction was aborted due to timeout or livelock
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Completed(_) | TransactionStatus::Aborted { .. }
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
    /// or when the transaction is aborted.
    ///
    /// The lock prevents conflicting transactions from being selected for blocks
    /// while this transaction is being executed.
    ///
    /// The following statuses do NOT hold locks:
    /// - Pending: not yet committed into a block
    /// - Completed: certificate committed, transaction done
    /// - Aborted: transaction aborted, locks released
    pub fn holds_state_lock(&self) -> bool {
        matches!(
            self,
            TransactionStatus::Committed(_) | TransactionStatus::Executed { .. }
        )
    }

    /// Returns a rough ordering value for the status in the normal lifecycle.
    ///
    /// This is used to detect stale status updates (where we've already progressed
    /// past the incoming status). Note that this doesn't capture all valid transitions,
    /// but it helps identify clearly stale updates.
    ///
    /// Ordering: Pending(0) < Committed(1) < Executed(2) < Completed(3)
    ///
    /// Aborted is a terminal side-branch and gets a high ordinal (4).
    pub fn ordinal(&self) -> u8 {
        match self {
            TransactionStatus::Pending => 0,
            TransactionStatus::Committed(_) => 1,
            TransactionStatus::Executed { .. } => 2,
            TransactionStatus::Completed(_) => 3,
            TransactionStatus::Aborted { .. } => 4,
        }
    }

    /// Check if this transition is valid.
    pub fn can_transition_to(&self, next: &TransactionStatus) -> bool {
        use TransactionStatus::*;

        match (self, next) {
            // Pending → Committed
            (Pending, Committed(_)) => true,

            // Committed → Executed (execution complete, certificate created)
            (Committed(_), Executed { .. }) => true,

            // Committed → Aborted (timeout or livelock)
            (Committed(_), Aborted { .. }) => true,

            // Executed → Completed (certificate committed in block)
            (Executed { .. }, Completed(_)) => true,

            // Executed → Aborted (timeout, livelock, or receipt mismatch)
            (Executed { .. }, Aborted { .. }) => true,

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
        "aborted" => Ok(TransactionDecision::Aborted),
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

    /// Execution proofs from all participating shards, keyed by shard ID.
    /// Each proof contains receipt_hash, success, and write_nodes.
    pub shard_proofs: BTreeMap<ShardGroupId, ShardExecutionProof>,
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

    /// Get proof for a specific shard.
    pub fn proof_for_shard(&self, shard_id: ShardGroupId) -> Option<&ShardExecutionProof> {
        self.shard_proofs.get(&shard_id)
    }

    /// Check if all shards succeeded.
    pub fn all_shards_succeeded(&self) -> bool {
        self.shard_proofs.values().all(|proof| proof.is_success())
    }

    /// Combined receipt hash across all shards.
    ///
    /// For single-shard transactions, returns the shard's receipt hash directly.
    /// For cross-shard transactions, computes a merkle root over each shard's
    /// receipt hash in shard ID order (deterministic via BTreeMap).
    /// Aborted shards contribute `Hash::ZERO` to the merkle computation.
    pub fn receipt_hash(&self) -> Hash {
        let hashes: Vec<Hash> = self
            .shard_proofs
            .values()
            .map(|proof| proof.receipt_hash_or_zero())
            .collect();
        match hashes.len() {
            0 => Hash::ZERO,
            1 => hashes[0],
            _ => crate::compute_merkle_root(&hashes),
        }
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
/// * `signer` - The Ed25519 private key to sign with (acts as both signer and notary)
///
/// Note: Only Ed25519 keys are supported for Radix transactions (not BLS).
pub fn sign_and_notarize(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    signer: &crate::Ed25519PrivateKey,
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
///
/// Note: Only Ed25519 keys are supported for Radix transactions (not BLS).
pub fn sign_and_notarize_with_options(
    manifest: TransactionManifestV1,
    network: &NetworkDefinition,
    nonce: u32,
    tip_percentage: u16,
    start_epoch: Epoch,
    end_epoch: Epoch,
    signer: &crate::Ed25519PrivateKey,
) -> Result<NotarizedTransactionV1, TransactionError> {
    let (instructions, blobs) = manifest.for_intent();
    let notary_public_key = radix_common::crypto::PublicKey::Ed25519(signer.public_key());

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
    let intent_sig = signer.sign(intent_hash);
    let intent_signature = SignatureWithPublicKeyV1::Ed25519 {
        public_key: signer.public_key(),
        signature: intent_sig,
    };

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
    let notary_sig = signer.sign(signed_intent_hash);
    let notary_signature = SignatureV1::Ed25519(notary_sig);

    Ok(NotarizedTransactionV1 {
        signed_intent,
        notary_signature: NotarySignatureV1(notary_signature),
    })
}

/// Ready transactions for block proposal.
///
/// Transactions are sorted by hash (from BTreeMap iteration order) for determinism.
/// All transactions are subject to the same backpressure limit.
#[derive(Clone, Debug, Default)]
pub struct ReadyTransactions {
    /// Transactions ready for inclusion, sorted by hash.
    pub transactions: Vec<std::sync::Arc<RoutableTransaction>>,
}

impl ReadyTransactions {
    /// Total number of transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether there are no transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Iterate all transactions.
    pub fn iter(&self) -> impl Iterator<Item = &std::sync::Arc<RoutableTransaction>> {
        self.transactions.iter()
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
