//! Radix-specific transaction types.

use hyperscale_codec as sbor;
use hyperscale_codec::prelude::*;
use hyperscale_types::{BlockHeight, ConsensusTransaction, Hash, NodeId, RetryDetails};
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use std::collections::HashSet;
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

    /// Cached serialized transaction bytes.
    ///
    /// These are the SBOR-encoded bytes of the `UserTransaction`, captured during
    /// construction or deserialization. This avoids redundant re-serialization when:
    /// - Computing transaction merkle roots for block headers
    /// - Re-encoding for network transmission
    ///
    /// The hash is computed from these bytes (plus retry_details if present).
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
            retry_details: self.retry_details.clone(),
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
        // Serialize the transaction payload - we keep these bytes for:
        // 1. Computing the hash (below)
        // 2. Efficient re-encoding for network/merkle (via serialized_bytes())
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");

        // Hash includes transaction payload AND retry_details (if present)
        // This ensures retries have different hashes than originals
        let mut hasher = blake3::Hasher::new();
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

        let first_shard = hyperscale_types::shard_for_node(&self.declared_writes[0], num_shards);
        self.declared_writes
            .iter()
            .skip(1)
            .any(|node| hyperscale_types::shard_for_node(node, num_shards) != first_shard)
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

impl ConsensusTransaction for RoutableTransaction {
    fn tx_hash(&self) -> Hash {
        self.hash()
    }

    fn reads(&self) -> Vec<NodeId> {
        self.declared_reads.clone()
    }

    fn writes(&self) -> Vec<NodeId> {
        self.declared_writes.clone()
    }

    fn is_retry(&self) -> bool {
        self.retry_details.is_some()
    }

    fn original_hash(&self) -> Hash {
        self.original_hash()
    }

    fn retry_count(&self) -> u32 {
        self.retry_count()
    }

    fn create_retry(&self, deferred_by: Hash, deferred_at: BlockHeight) -> Self {
        self.create_retry(deferred_by, deferred_at)
    }

    fn is_cross_shard(&self, num_shards: u64) -> bool {
        self.is_cross_shard(num_shards)
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

// ============================================================================
// TryFrom implementations for NotarizedTransaction -> RoutableTransaction
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

use crate::crypto::Ed25519PrivateKey;
use hyperscale_types::TransactionError;

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

// ============================================================================
// Transaction Signing Utilities
// ============================================================================

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
    signer: &Ed25519PrivateKey,
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
    signer: &Ed25519PrivateKey,
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
