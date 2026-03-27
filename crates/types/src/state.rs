//! State-related types for cross-shard execution.

use crate::{
    exec_vote_message, BlockHeight, Bls12381G2Signature, Hash, NodeId, ShardGroupId, ValidatorId,
};
use sbor::prelude::*;
use std::sync::Arc;

// ============================================================================
// State entry types with pre-computed storage keys
// ============================================================================

/// A state entry with pre-computed storage key for fast engine lookup.
///
/// This type stores the pre-computed storage key that can be used directly for
/// database lookups without any key transformation at the receiving shard.
///
/// The storage key format is: `db_node_key(50) + partition_num(1) + sort_key(var)`
/// where `db_node_key` is the SpreadPrefixKeyMapper hash (expensive to compute).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: db_node_key (50 bytes) + partition (1 byte) + sort_key
    pub storage_key: Vec<u8>,

    /// SBOR-encoded substate value (None if deleted/doesn't exist).
    pub value: Option<Vec<u8>>,
}

/// Hash prefix length in db_node_key (SpreadPrefixKeyMapper adds 20-byte hash)
const HASH_PREFIX_LEN: usize = 20;

impl StateEntry {
    /// Create a new DB state entry with pre-computed storage key.
    pub fn new(storage_key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
        Self { storage_key, value }
    }

    /// Extract the NodeId from the storage key.
    ///
    /// The storage key format is:
    /// - db_node_key (50 bytes: 20-byte hash prefix + 30-byte node_id)
    /// - partition_num (1 byte)
    /// - sort_key (variable)
    ///
    /// The NodeId is at bytes [20..50] (after hash prefix).
    pub fn node_id(&self) -> Option<NodeId> {
        let start = HASH_PREFIX_LEN;
        let end = start + 30;
        if self.storage_key.len() >= end {
            let mut id = [0u8; 30];
            id.copy_from_slice(&self.storage_key[start..end]);
            Some(NodeId(id))
        } else {
            None
        }
    }

    /// Compute hash of this entry for signing/verification.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(self.storage_key.len() + 32);
        data.extend_from_slice(&self.storage_key);

        match &self.value {
            Some(value_bytes) => {
                let value_hash = Hash::from_bytes(value_bytes);
                data.extend_from_slice(value_hash.as_bytes());
            }
            None => {
                data.extend_from_slice(&[0u8; 32]); // ZERO hash for deletion
            }
        }

        Hash::from_bytes(&data)
    }

    /// Create a test entry from a node ID (for testing only).
    ///
    /// Creates a storage key in the correct format so that `node_id()` can extract
    /// the node ID. Uses a dummy hash prefix (zeros) since tests don't need real
    /// SpreadPrefixKeyMapper hashes.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn test_entry(
        node_id: NodeId,
        partition: u8,
        sort_key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        // Format: hash_prefix (20) + node_id (30) + partition (1) + sort_key
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + sort_key.len());
        storage_key.extend_from_slice(&[0u8; 20]); // Dummy hash prefix
        storage_key.extend_from_slice(&node_id.0); // Node ID
        storage_key.push(partition); // Partition number
        storage_key.extend_from_slice(&sort_key); // Sort key
        Self { storage_key, value }
    }
}

/// Vote on execution state from a validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub struct ExecutionVote {
    /// Hash of the transaction.
    pub transaction_hash: Hash,

    /// Shard group that executed.
    pub shard_group_id: ShardGroupId,

    /// Hash of the ConsensusReceipt (outcome + event_root).
    pub receipt_hash: Hash,

    /// Whether execution succeeded.
    pub success: bool,

    /// NodeIds written during execution (for speculative invalidation).
    ///
    /// Deterministically ordered via BTreeSet so all validators within a
    /// shard produce identical write_nodes vectors from identical execution.
    pub write_nodes: Vec<NodeId>,

    /// Validator that executed and voted.
    pub validator: ValidatorId,

    /// Signature from the voting validator.
    pub signature: Bls12381G2Signature,
}

impl ExecutionVote {
    /// Compute hash of this vote for aggregation.
    pub fn vote_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(self.transaction_hash.as_bytes());
        data.extend_from_slice(&self.shard_group_id.0.to_le_bytes());
        data.extend_from_slice(self.receipt_hash.as_bytes());
        data.push(if self.success { 1 } else { 0 });

        Hash::from_bytes(&data)
    }

    /// Create the canonical message bytes for signing.
    ///
    /// Uses the centralized `exec_vote_message` function with the
    /// `DOMAIN_EXEC_VOTE` tag for domain separation.
    ///
    /// Note: With wave-based voting, per-tx BLS signatures are no longer used.
    /// This signing message is used only for ExecutionVote verification.
    pub fn signing_message(&self) -> Vec<u8> {
        exec_vote_message(
            &self.transaction_hash,
            &self.receipt_hash,
            self.shard_group_id,
            self.success,
        )
    }
}

/// Per-shard execution proof for a transaction.
///
/// Contains the execution outcome for a transaction on a single shard.
/// Stored in `TransactionCertificate.shard_proofs`. With wave-based voting,
/// BLS signatures are on the wave cert (not per-tx), so this type carries
/// only the execution outcome data.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardExecutionProof {
    /// Hash of the ConsensusReceipt (outcome + event_root).
    pub receipt_hash: Hash,
    /// Whether execution succeeded.
    pub success: bool,
    /// NodeIds written during execution.
    pub write_nodes: Vec<NodeId>,
}

/// State provision from a source shard to a target shard.
///
/// Only the block proposer sends these. Provisions are always transported
/// in a batch (per block) alongside a single aggregated verkle proof that
/// covers all entries across all provisions in that batch. The proof lives
/// at the batch level (e.g. `StateProvisionsNotification`) to avoid
/// duplicating it per provision during serialization.
#[derive(Debug, Clone)]
pub struct StateProvision {
    /// Hash of the transaction this provision is for.
    pub transaction_hash: Hash,

    /// Target shard (the shard executing the transaction).
    pub target_shard: ShardGroupId,

    /// Source shard (the shard providing the state).
    pub source_shard: ShardGroupId,

    /// Block height when this provision was created (= JVT version for verkle proofs).
    pub block_height: BlockHeight,

    /// Unix timestamp (milliseconds) of the block that triggered this provision.
    pub block_timestamp: u64,

    /// The state entries with pre-computed storage keys.
    /// Wrapped in Arc for efficient sharing when broadcasting to multiple shards.
    pub entries: Arc<Vec<StateEntry>>,
}

// Manual PartialEq (compare Arc contents, not pointer identity)
impl PartialEq for StateProvision {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash == other.transaction_hash
            && self.target_shard == other.target_shard
            && self.source_shard == other.source_shard
            && self.block_height == other.block_height
            && self.block_timestamp == other.block_timestamp
            && *self.entries == *other.entries
    }
}

impl Eq for StateProvision {}

// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for StateProvision
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(6)?;
        encoder.encode(&self.transaction_hash)?;
        encoder.encode(&self.target_shard)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.block_timestamp)?;
        encoder.encode(self.entries.as_ref())?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for StateProvision
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 6 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }

        let transaction_hash: Hash = decoder.decode()?;
        let target_shard: ShardGroupId = decoder.decode()?;
        let source_shard: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let block_timestamp: u64 = decoder.decode()?;
        let entries: Vec<StateEntry> = decoder.decode()?;

        Ok(Self {
            transaction_hash,
            target_shard,
            source_shard,
            block_height,
            block_timestamp,
            entries: Arc::new(entries),
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for StateProvision {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for StateProvision {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("StateProvision", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_state_entry_hash() {
        let entry = StateEntry::test_entry(
            NodeId([1u8; 30]),
            0,
            b"key".to_vec(),
            Some(b"value".to_vec()),
        );

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_shard_execution_proof() {
        let proof = ShardExecutionProof {
            receipt_hash: Hash::from_bytes(b"receipt"),
            success: true,
            write_nodes: vec![],
        };

        assert!(proof.success);
        assert!(proof.write_nodes.is_empty());
    }
}
