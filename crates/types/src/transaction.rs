//! Transaction types for consensus.

use crate::{BlockHeight, Hash, NodeId, TimestampRange, TxHash};
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;
use std::sync::OnceLock;

/// A transaction with routing information.
///
/// Wraps a Radix `UserTransaction` with routing metadata for sharding.
pub struct RoutableTransaction {
    /// The underlying Radix transaction.
    transaction: UserTransaction,

    /// `NodeIds` that this transaction reads from.
    pub declared_reads: Vec<NodeId>,

    /// `NodeIds` that this transaction writes to.
    pub declared_writes: Vec<NodeId>,

    /// Half-open `WeightedTimestamp` range during which this tx may be
    /// included in a block. Anchored on the parent QC's `weighted_timestamp`
    /// at every check site. Signer-chosen, chain-enforced.
    pub validity_range: TimestampRange,

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

    /// Cached full SBOR encoding of this `RoutableTransaction`.
    /// Set eagerly at construction/decode time so the commit thread
    /// never re-encodes — the bytes are ready for `cf_put_raw`.
    cached_sbor: Option<Vec<u8>>,
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
            validity_range: self.validity_range,
            hash: self.hash,
            serialized_bytes: self.serialized_bytes.clone(),
            validated: OnceLock::new(),
            cached_sbor: self.cached_sbor.clone(),
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
            .field("validity_range", &self.validity_range)
            .finish_non_exhaustive()
    }
}

impl RoutableTransaction {
    /// Create a new routable transaction from a `UserTransaction`.
    ///
    /// `validity_range` must be supplied explicitly — there is no chain-side
    /// default. The signer chooses the bounds; the chain enforces them.
    ///
    /// # Panics
    ///
    /// Panics if the `UserTransaction` cannot be SBOR-encoded — that
    /// indicates a programmer error since `UserTransaction` is a closed
    /// SBOR type and its encoding is infallible in practice.
    #[must_use]
    pub fn new(
        transaction: UserTransaction,
        declared_reads: Vec<NodeId>,
        declared_writes: Vec<NodeId>,
        validity_range: TimestampRange,
    ) -> Self {
        // Serialize the transaction payload - we keep these bytes for:
        // 1. Computing the hash (below)
        // 2. Efficient re-encoding for network/merkle (via serialized_bytes())
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");

        // Hash the transaction payload directly
        let mut hasher = blake3::Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let mut tx = Self {
            transaction,
            declared_reads,
            declared_writes,
            validity_range,
            hash,
            serialized_bytes: payload,
            validated: OnceLock::new(),
            cached_sbor: None,
        };
        tx.populate_cached_sbor();
        tx
    }

    /// Get the transaction hash (content-addressed).
    pub fn hash(&self) -> TxHash {
        TxHash::from_raw(self.hash)
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

    /// Pre-serialized SBOR bytes of the full `RoutableTransaction`.
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(sbor::basic_encode(self).expect("RoutableTransaction SBOR encode"));
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

    /// All `NodeIds` this transaction declares access to.
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
        encoder.write_size(5)?; // 5 fields

        // Encode hash as [u8; 32]
        let hash_bytes: [u8; 32] = *self.hash.as_bytes();
        encoder.encode(&hash_bytes)?;

        // Encode transaction as bytes (using cached serialized_bytes)
        encoder.encode(&self.serialized_bytes)?;

        // Encode declared_reads
        encoder.encode(&self.declared_reads)?;

        // Encode declared_writes
        encoder.encode(&self.declared_writes)?;

        // Encode validity_range
        encoder.encode(&self.validity_range)?;

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

        // Decode validity_range
        let validity_range: TimestampRange = decoder.decode()?;

        let mut tx = Self {
            hash,
            transaction,
            declared_reads,
            declared_writes,
            validity_range,
            serialized_bytes: tx_bytes,
            validated: OnceLock::new(),
            cached_sbor: None,
        };
        tx.populate_cached_sbor();
        Ok(tx)
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

// ============================================================================
// Conversion: notarized Radix transactions -> RoutableTransaction
// ============================================================================
//
// `validity_range` is required at every call site — there is no chain-side
// default. These helpers replace the previous `TryFrom` impls so the missing
// argument is a compile-time error rather than a silent default.

/// Convert a `NotarizedTransactionV1` into a `RoutableTransaction`.
///
/// # Errors
///
/// Currently infallible; the `Result` is reserved for future
/// validation paths (e.g. unsupported instruction kinds).
pub fn routable_from_notarized_v1(
    notarized: NotarizedTransactionV1,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    let instructions = &notarized.signed_intent.intent.instructions.0;
    let (read_nodes, write_nodes) = analyze_instructions_v1(instructions);
    Ok(RoutableTransaction::new(
        UserTransaction::V1(notarized),
        read_nodes,
        write_nodes,
        validity_range,
    ))
}

/// Convert a `NotarizedTransactionV2` into a `RoutableTransaction`.
///
/// # Errors
///
/// Currently infallible; the `Result` is reserved for future
/// validation paths (e.g. unsupported instruction kinds).
pub fn routable_from_notarized_v2(
    notarized: NotarizedTransactionV2,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
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
        validity_range,
    ))
}

/// Convert a `UserTransaction` (V1 or V2) into a `RoutableTransaction`.
///
/// # Errors
///
/// Forwards any error from
/// [`routable_from_notarized_v1`] / [`routable_from_notarized_v2`];
/// both are currently infallible.
pub fn routable_from_user_transaction(
    transaction: UserTransaction,
    validity_range: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    match transaction {
        UserTransaction::V1(v1) => routable_from_notarized_v1(v1, validity_range),
        UserTransaction::V2(v2) => routable_from_notarized_v2(v2, validity_range),
    }
}

// ============================================================================
// Instruction Analysis
// ============================================================================

/// Analyze V1 transaction instructions to extract accessed `NodeIds`.
fn analyze_instructions_v1(instructions: &[InstructionV1]) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions {
        extract_node_ids_from_instruction_v1(instruction, &mut reads, &mut writes);
    }

    filter_and_deduplicate(reads, writes)
}

/// Analyze V2 transaction instructions to extract accessed `NodeIds`.
fn analyze_instructions_v2(instructions: &[InstructionV2]) -> (Vec<NodeId>, Vec<NodeId>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for instruction in instructions {
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

    let mut reads: Vec<NodeId> = reads
        .into_iter()
        .filter(|node_id| !is_system_entity(node_id) && !writes.contains(node_id))
        .collect();
    reads.sort();

    let mut writes: Vec<NodeId> = writes.into_iter().collect();
    writes.sort();

    (reads, writes)
}

/// Extract `NodeIds` from a single V1 instruction.
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

/// Extract `NodeIds` from a single V2 instruction.
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
        // Yield/verify ops touch no state; remaining variants conservatively touch nothing.
        _ => {}
    }
}

/// Convert a manifest global address to a `NodeId` if possible.
fn manifest_address_to_node_id(address: &ManifestGlobalAddress) -> Option<NodeId> {
    match address {
        ManifestGlobalAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestGlobalAddress::Named(_) => None,
    }
}

/// Convert a manifest package address to a `NodeId` if possible.
fn manifest_package_to_node_id(address: &ManifestPackageAddress) -> Option<NodeId> {
    match address {
        ManifestPackageAddress::Static(addr) => Some(NodeId(addr.into_node_id().0)),
        ManifestPackageAddress::Named(_) => None,
    }
}

/// Check if a `NodeId` is a system entity that should be replicated to all shards.
fn is_system_entity(node_id: &NodeId) -> bool {
    is_system_package(node_id) || is_system_component(node_id) || is_system_resource(node_id)
}

/// Check if a `NodeId` belongs to a well-known system package.
fn is_system_package(node_id: &NodeId) -> bool {
    use radix_common::constants::{
        ACCESS_CONTROLLER_PACKAGE, ACCOUNT_PACKAGE, CONSENSUS_MANAGER_PACKAGE, FAUCET_PACKAGE,
        GENESIS_HELPER_PACKAGE, IDENTITY_PACKAGE, LOCKER_PACKAGE, METADATA_MODULE_PACKAGE,
        PACKAGE_PACKAGE, POOL_PACKAGE, RESOURCE_PACKAGE, ROLE_ASSIGNMENT_MODULE_PACKAGE,
        ROYALTY_MODULE_PACKAGE, TRANSACTION_PROCESSOR_PACKAGE, TRANSACTION_TRACKER_PACKAGE,
    };

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

/// Check if a `NodeId` belongs to a well-known system component.
fn is_system_component(node_id: &NodeId) -> bool {
    use radix_common::constants::{CONSENSUS_MANAGER, FAUCET, GENESIS_HELPER, TRANSACTION_TRACKER};

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

/// Check if a `NodeId` belongs to a well-known system resource.
fn is_system_resource(node_id: &NodeId) -> bool {
    use radix_common::constants::{
        ACCOUNT_OWNER_BADGE, ED25519_SIGNATURE_RESOURCE, GLOBAL_CALLER_RESOURCE,
        IDENTITY_OWNER_BADGE, PACKAGE_OF_DIRECT_CALLER_RESOURCE, PACKAGE_OWNER_BADGE,
        SECP256K1_SIGNATURE_RESOURCE, SYSTEM_EXECUTION_RESOURCE, VALIDATOR_OWNER_BADGE, XRD,
    };

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
///
/// # Errors
///
/// Forwards any error from [`sign_and_notarize_with_options`] (manifest
/// build / hashing / signing).
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
///
/// # Errors
///
/// Returns [`TransactionError`] if intent construction or hashing fails
/// (these only fire on programmer error today: malformed manifests).
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
        .map_err(|e| TransactionError::EncodeFailed(format!("{e:?}")))?;

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
        .map_err(|e| TransactionError::EncodeFailed(format!("{e:?}")))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_decision() {
        assert_ne!(TransactionDecision::Accept, TransactionDecision::Reject);
    }
}
