//! State-related types for cross-shard execution.

use crate::{
    exec_vote_message, state_provision_message, zero_bls_signature, BlockHeight,
    Bls12381G2Signature, Hash, NodeId, PartitionNumber, ShardGroupId, SignerBitfield, ValidatorId,
};
use sbor::prelude::*;
use std::sync::Arc;

/// A write to a substate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub struct SubstateWrite {
    /// The node being written to.
    pub node_id: NodeId,

    /// Partition within the node.
    pub partition: PartitionNumber,

    /// Key within the partition (sort key).
    pub sort_key: Vec<u8>,

    /// New value.
    pub value: Vec<u8>,
}

impl SubstateWrite {
    /// Create a new substate write.
    pub fn new(
        node_id: NodeId,
        partition: PartitionNumber,
        sort_key: Vec<u8>,
        value: Vec<u8>,
    ) -> Self {
        Self {
            node_id,
            partition,
            sort_key,
            value,
        }
    }
}

// ============================================================================
// State entry types with pre-computed storage keys
// ============================================================================

/// A state entry with pre-computed storage key for fast engine lookup.
///
/// This type stores the pre-computed storage key that can be used directly for
/// database lookups without any key transformation at the receiving shard.
///
/// The storage key format is: `RADIX_PREFIX + db_node_key + partition_num + sort_key`
/// where `db_node_key` is the SpreadPrefixKeyMapper hash (expensive to compute).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: RADIX_PREFIX (6 bytes) + db_node_key (50 bytes) + partition (1 byte) + sort_key
    pub storage_key: Vec<u8>,

    /// SBOR-encoded substate value (None if deleted/doesn't exist).
    pub value: Option<Vec<u8>>,
}

/// RADIX_PREFIX length (b"radix:" = 6 bytes)
const RADIX_PREFIX_LEN: usize = 6;

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
    /// - RADIX_PREFIX (6 bytes)
    /// - db_node_key (50 bytes: 20-byte hash prefix + 30-byte node_id)
    /// - partition_num (1 byte)
    /// - sort_key (variable)
    ///
    /// The NodeId is at bytes [26..56] (after RADIX_PREFIX and hash prefix).
    pub fn node_id(&self) -> Option<NodeId> {
        let start = RADIX_PREFIX_LEN + HASH_PREFIX_LEN;
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
        // Format: RADIX_PREFIX (6) + hash_prefix (20) + node_id (30) + partition (1) + sort_key
        let mut storage_key = Vec::with_capacity(6 + 20 + 30 + 1 + sort_key.len());
        storage_key.extend_from_slice(b"radix:"); // RADIX_PREFIX
        storage_key.extend_from_slice(&[0u8; 20]); // Dummy hash prefix
        storage_key.extend_from_slice(&node_id.0); // Node ID
        storage_key.push(partition); // Partition number
        storage_key.extend_from_slice(&sort_key); // Sort key
        Self { storage_key, value }
    }
}

/// State provision from a source shard to a target shard.
///
/// Contains pre-computed storage keys (`StateEntry`) for efficient execution.
/// The sending shard computes storage keys once, so the receiving shard can
/// use them directly without expensive hash computations.
///
/// The `entries` field uses `Arc<Vec<StateEntry>>` for efficient sharing when
/// broadcasting the same provision data to multiple target shards.
#[derive(Debug, Clone)]
pub struct StateProvision {
    /// Hash of the transaction this provision is for.
    pub transaction_hash: Hash,

    /// Target shard (the shard executing the transaction).
    pub target_shard: ShardGroupId,

    /// Source shard (the shard providing the state).
    pub source_shard: ShardGroupId,

    /// Block height when this provision was created.
    pub block_height: BlockHeight,

    /// Unix timestamp (milliseconds) of the block that triggered this provision.
    pub block_timestamp: u64,

    /// The state entries with pre-computed storage keys.
    /// Wrapped in Arc for efficient sharing when broadcasting to multiple shards.
    pub entries: Arc<Vec<StateEntry>>,

    /// Validator ID in source shard who created this provision.
    pub validator_id: ValidatorId,

    /// Signature from the source shard validator.
    pub signature: Bls12381G2Signature,
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
            && self.validator_id == other.validator_id
            && self.signature == other.signature
    }
}

impl Eq for StateProvision {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// We serialize/deserialize the inner Vec<StateEntry> directly.
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for StateProvision
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(8)?;
        encoder.encode(&self.transaction_hash)?;
        encoder.encode(&self.target_shard)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.block_timestamp)?;
        // Entries: encode the inner Vec directly (unwrap Arc)
        encoder.encode(self.entries.as_ref())?;
        encoder.encode(&self.validator_id)?;
        encoder.encode(&self.signature)?;
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

        if length != 8 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 8,
                actual: length,
            });
        }

        let transaction_hash: Hash = decoder.decode()?;
        let target_shard: ShardGroupId = decoder.decode()?;
        let source_shard: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let block_timestamp: u64 = decoder.decode()?;
        // Entries: decode Vec and wrap in Arc
        let entries: Vec<StateEntry> = decoder.decode()?;
        let validator_id: ValidatorId = decoder.decode()?;
        let signature: Bls12381G2Signature = decoder.decode()?;

        Ok(Self {
            transaction_hash,
            target_shard,
            source_shard,
            block_height,
            block_timestamp,
            entries: Arc::new(entries),
            validator_id,
            signature,
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

impl StateProvision {
    /// Create the canonical message bytes for signing.
    ///
    /// Uses the centralized `state_provision_message` function with the
    /// `DOMAIN_STATE_PROVISION` tag for domain separation.
    pub fn signing_message(&self) -> Vec<u8> {
        let entry_hashes: Vec<Hash> = self.entries.iter().map(|e| e.hash()).collect();
        state_provision_message(
            &self.transaction_hash,
            self.target_shard,
            self.source_shard,
            self.block_height,
            self.block_timestamp,
            &entry_hashes,
        )
    }

    /// Compute a hash of all entries for comparison purposes.
    pub fn entries_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for entry in self.entries.iter() {
            hasher.update(entry.hash().as_bytes());
        }
        Hash::from_bytes(hasher.finalize().as_bytes())
    }
}

/// Vote on execution state from a validator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, BasicSbor)]
pub struct StateVoteBlock {
    /// Hash of the transaction.
    pub transaction_hash: Hash,

    /// Shard group that executed.
    pub shard_group_id: ShardGroupId,

    /// Deterministic hash-chain commitment over execution output writes.
    pub writes_commitment: Hash,

    /// Whether execution succeeded.
    pub success: bool,

    /// State writes produced by execution.
    ///
    /// Used to populate StateCertificate.state_writes for speculative
    /// execution invalidation.
    pub state_writes: Vec<SubstateWrite>,

    /// Validator that executed and voted.
    pub validator: ValidatorId,

    /// Signature from the voting validator.
    pub signature: Bls12381G2Signature,
}

impl StateVoteBlock {
    /// Compute hash of this vote for aggregation.
    pub fn vote_hash(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(self.transaction_hash.as_bytes());
        data.extend_from_slice(&self.shard_group_id.0.to_le_bytes());
        data.extend_from_slice(self.writes_commitment.as_bytes());
        data.push(if self.success { 1 } else { 0 });

        Hash::from_bytes(&data)
    }

    /// Create the canonical message bytes for signing.
    ///
    /// Uses the centralized `exec_vote_message` function with the
    /// `DOMAIN_EXEC_VOTE` tag for domain separation.
    ///
    /// Note: StateCertificates aggregate signatures from StateVoteBlocks,
    /// so StateCertificate::signing_message() returns the same format.
    pub fn signing_message(&self) -> Vec<u8> {
        exec_vote_message(
            &self.transaction_hash,
            &self.writes_commitment,
            self.shard_group_id,
            self.success,
        )
    }
}

/// Certificate proving a shard agreed on execution state.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateCertificate {
    /// Hash of the transaction.
    pub transaction_hash: Hash,

    /// Shard that produced this certificate.
    pub shard_group_id: ShardGroupId,

    /// Node IDs that were READ during execution.
    pub read_nodes: Vec<NodeId>,

    /// Substate data that was WRITTEN during execution.
    pub state_writes: Vec<SubstateWrite>,

    /// Deterministic hash-chain commitment over execution output writes.
    pub writes_commitment: Hash,

    /// Whether execution succeeded.
    pub success: bool,

    /// Aggregated signature.
    pub aggregated_signature: Bls12381G2Signature,

    /// Which validators signed.
    pub signers: SignerBitfield,

    /// Total voting power of all signers.
    pub voting_power: u64,
}

impl StateCertificate {
    /// Get number of signers.
    pub fn signer_count(&self) -> usize {
        self.signers.count()
    }

    /// Get list of validator indices that signed.
    pub fn signer_indices(&self) -> Vec<usize> {
        self.signers.set_indices().collect()
    }

    /// Check if execution succeeded.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if execution failed.
    pub fn is_failure(&self) -> bool {
        !self.success
    }

    /// Get number of state reads.
    pub fn read_count(&self) -> usize {
        self.read_nodes.len()
    }

    /// Get number of state writes.
    pub fn write_count(&self) -> usize {
        self.state_writes.len()
    }

    /// Check if this certificate can be applied (has state writes).
    pub fn has_writes(&self) -> bool {
        !self.state_writes.is_empty()
    }

    /// Create a certificate for a single-shard transaction.
    pub fn single_shard(
        transaction_hash: Hash,
        writes_commitment: Hash,
        shard_group_id: ShardGroupId,
        success: bool,
    ) -> Self {
        Self {
            transaction_hash,
            shard_group_id,
            read_nodes: vec![],
            state_writes: vec![],
            writes_commitment,
            success,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::empty(),
            voting_power: 0,
        }
    }

    /// Create the canonical message bytes for signature verification.
    ///
    /// Uses the centralized `exec_vote_message` function with the
    /// `DOMAIN_EXEC_VOTE` tag for domain separation.
    ///
    /// Note: This returns the same message format as StateVoteBlock::signing_message()
    /// because StateCertificates aggregate signatures from StateVoteBlocks. The
    /// aggregated signature is verified against this same message.
    pub fn signing_message(&self) -> Vec<u8> {
        exec_vote_message(
            &self.transaction_hash,
            &self.writes_commitment,
            self.shard_group_id,
            self.success,
        )
    }
}

/// Result of executing a transaction.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionResult {
    /// Hash of the transaction.
    pub transaction_hash: Hash,

    /// Whether execution succeeded.
    pub success: bool,

    /// Merkle root of the state changes.
    pub state_root: Hash,

    /// Writes produced by the transaction.
    pub writes: Vec<SubstateWrite>,

    /// Error message if execution failed.
    pub error: Option<String>,
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
    fn test_single_shard_certificate() {
        let cert = StateCertificate::single_shard(
            Hash::from_bytes(b"tx"),
            Hash::from_bytes(b"root"),
            ShardGroupId(0),
            true,
        );

        assert!(cert.success);
        assert!(cert.signers.is_empty());
    }

    #[test]
    fn test_state_provision_sbor_roundtrip_preserves_signature() {
        use crate::{bls_keypair_from_seed, state_provision_message, verify_bls12381_v1};
        use std::sync::Arc;

        // Create test entries using StateEntry::test_entry
        let entries = vec![
            StateEntry::test_entry(NodeId([1u8; 30]), 1, vec![1, 2, 3], Some(vec![4, 5, 6])),
            StateEntry::test_entry(NodeId([2u8; 30]), 2, vec![7, 8, 9], None),
        ];

        // Create keypair
        let keypair = bls_keypair_from_seed(&[42u8; 32]);
        let public_key = keypair.public_key();

        let tx_hash = Hash::from_bytes(&[1u8; 32]);
        let target_shard = ShardGroupId(0);
        let source_shard = ShardGroupId(1);
        let block_height = BlockHeight(100);
        let block_timestamp = 1234567890u64;

        // Compute signing message
        let entry_hashes: Vec<Hash> = entries.iter().map(|e| e.hash()).collect();
        let msg = state_provision_message(
            &tx_hash,
            target_shard,
            source_shard,
            block_height,
            block_timestamp,
            &entry_hashes,
        );
        let signature = keypair.sign_v1(&msg);

        // Create provision
        let provision = StateProvision {
            transaction_hash: tx_hash,
            target_shard,
            source_shard,
            block_height,
            block_timestamp,
            entries: Arc::new(entries),
            validator_id: crate::ValidatorId(5),
            signature,
        };

        // Verify original
        let original_msg = provision.signing_message();
        assert!(
            verify_bls12381_v1(&original_msg, &public_key, &provision.signature),
            "Original should verify"
        );

        // SBOR encode
        let encoded = sbor::basic_encode(&provision).expect("encode failed");

        // SBOR decode
        let decoded: StateProvision = sbor::basic_decode(&encoded).expect("decode failed");

        // Verify decoded
        let decoded_msg = decoded.signing_message();
        assert_eq!(
            original_msg, decoded_msg,
            "Signing messages should match after roundtrip"
        );
        assert!(
            verify_bls12381_v1(&decoded_msg, &public_key, &decoded.signature),
            "Decoded should verify"
        );
    }
}
