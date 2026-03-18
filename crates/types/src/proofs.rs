//! Proof types for Byzantine-safe backpressure and livelock handling.
//!
//! This module contains cryptographic proof types that enable validators to verify
//! block contents without depending on having seen the same network messages.
//!
//! # Proof Types
//!
//! - [`CommitmentProof`]: Proves a transaction was committed on another shard
//!   (via QC-authenticated state root + merkle inclusion proofs)
//! - [`MerkleInclusionProof`]: Proves a substate's inclusion in a JMT at a given state root
//!
//! # Usage
//!
//! These proofs are attached to blocks to justify:
//! 1. Including cross-shard transactions that would otherwise be rejected by backpressure
//! 2. Deferring transactions due to livelock cycle detection
//!
//! Without proofs, validators might reject valid blocks simply because they haven't
//! received provisions yet, causing expensive view changes.

use crate::{BlockHeight, Hash, NodeId, QuorumCertificate, ShardGroupId, StateEntry};
use sbor::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

// ============================================================================
// MerkleInclusionProof
// ============================================================================

/// Proof of a substate's inclusion in the JMT at a given state root.
///
/// Serializable wrapper around the vendor `SparseMerkleProof` (which lacks SBOR derives).
/// Contains the sibling hashes needed to recompute the root hash bottom-up.
///
/// # Verification
///
/// To verify inclusion, call `verify(key, value_hash, expected_root)`:
/// 1. Compute leaf hash = blake3(leaf_key || leaf_value_hash)
/// 2. Walk up the tree using sibling hashes, with the key bits determining left/right
/// 3. Compare the computed root to `expected_root`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    /// Leaf key bytes (Some = inclusion, None = empty subtree / non-inclusion).
    pub leaf_key: Option<Vec<u8>>,
    /// Hash of the leaf value (Some = inclusion, None = empty subtree / non-inclusion).
    pub leaf_value_hash: Option<Hash>,
    /// Sibling hashes, bottom-to-top.
    pub siblings: Vec<Hash>,
}

// Manual SBOR implementation for MerkleInclusionProof
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for MerkleInclusionProof
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.leaf_key)?;
        encoder.encode(&self.leaf_value_hash)?;
        encoder.encode(&self.siblings)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for MerkleInclusionProof
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let leaf_key: Option<Vec<u8>> = decoder.decode()?;
        let leaf_value_hash: Option<Hash> = decoder.decode()?;
        let siblings: Vec<Hash> = decoder.decode()?;
        Ok(Self {
            leaf_key,
            leaf_value_hash,
            siblings,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for MerkleInclusionProof {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for MerkleInclusionProof {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("MerkleInclusionProof", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// ============================================================================
// SubstateInclusionProof
// ============================================================================

/// 3-tier JMT inclusion proof for a single substate.
///
/// The JMT has 3 tiers: Entity → Partition → Substate. A complete substate
/// proof requires proofs at ALL 3 tiers, chained together:
///
/// 1. **Entity proof**: proves the entity's partition-tier root hash against the global state root
/// 2. **Partition proof**: proves the partition's substate-tier root hash against the entity root
/// 3. **Substate proof**: proves the substate value hash against the partition root
///
/// Verification is done in the storage crate using Blake3 (the JMT's hash function).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstateInclusionProof {
    /// Entity-tier inclusion proof.
    pub entity: MerkleInclusionProof,
    /// Partition-tier inclusion proof.
    pub partition: MerkleInclusionProof,
    /// Substate-tier inclusion proof.
    pub substate: MerkleInclusionProof,
}

impl SubstateInclusionProof {
    /// Create a dummy proof for testing. Not cryptographically valid.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn dummy() -> Self {
        let tier = MerkleInclusionProof {
            leaf_key: None,
            leaf_value_hash: None,
            siblings: vec![],
        };
        Self {
            entity: tier.clone(),
            partition: tier.clone(),
            substate: tier,
        }
    }
}

// Manual SBOR implementation for SubstateInclusionProof
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for SubstateInclusionProof
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.entity)?;
        encoder.encode(&self.partition)?;
        encoder.encode(&self.substate)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for SubstateInclusionProof
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let entity: MerkleInclusionProof = decoder.decode()?;
        let partition: MerkleInclusionProof = decoder.decode()?;
        let substate: MerkleInclusionProof = decoder.decode()?;
        Ok(Self {
            entity,
            partition,
            substate,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for SubstateInclusionProof {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for SubstateInclusionProof {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("SubstateInclusionProof", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// ============================================================================
// CommitmentProof
// ============================================================================

/// Proof that a transaction was committed on another shard.
///
/// Uses QC-authenticated state root + merkle inclusion proofs. The trust chain is:
/// 1. QC proves 2f+1 validators agreed on block header (which contains state_root)
/// 2. Merkle proofs prove each entry's inclusion against that state_root
///
/// This enables:
/// 1. **Priority ordering**: TXs with proof are included BEFORE other TXs in blocks
/// 2. **Limit bypass**: TXs with proof can exceed the backpressure limit (1024 cross-shard TXs)
///
/// # Size Comparison
///
/// Before: N validators each send ~500 byte provision = ~50KB total
/// After: 1 proposer sends ~10KB (entries + merkle proofs), dramatically lower bandwidth
#[derive(Debug, Clone)]
pub struct CommitmentProof {
    /// The transaction that was committed elsewhere.
    pub tx_hash: Hash,

    /// Source shard that committed the transaction.
    pub source_shard: ShardGroupId,

    /// Target shard that received the provisions (prevents cross-shard replay).
    pub target_shard: ShardGroupId,

    /// Block height at which the tx was committed on the source shard.
    pub block_height: BlockHeight,

    /// Unix timestamp (milliseconds) of the block that triggered the provisions.
    pub block_timestamp: u64,

    /// State root from the committed block header (verified via QC).
    pub state_root: Hash,

    /// Quorum Certificate proving the state_root is correct (via block hash).
    pub qc: QuorumCertificate,

    /// The state entries with pre-computed storage keys.
    /// Needed for cycle detection (node overlap checking via StateEntry::node_id()).
    /// Wrapped in Arc for efficient sharing.
    pub entries: Arc<Vec<StateEntry>>,

    /// Merkle inclusion proofs, one per entry, proving each entry's value
    /// against the QC-committed state_root.
    /// Wrapped in Arc for efficient sharing.
    pub merkle_proofs: Arc<Vec<SubstateInclusionProof>>,
}

// Manual PartialEq (compare Arc contents, not pointer identity)
impl PartialEq for CommitmentProof {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash == other.tx_hash
            && self.source_shard == other.source_shard
            && self.target_shard == other.target_shard
            && self.block_height == other.block_height
            && self.block_timestamp == other.block_timestamp
            && self.state_root == other.state_root
            && self.qc == other.qc
            && *self.entries == *other.entries
            && *self.merkle_proofs == *other.merkle_proofs
    }
}

impl Eq for CommitmentProof {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for CommitmentProof
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(9)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.target_shard)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.block_timestamp)?;
        encoder.encode(&self.state_root)?;
        encoder.encode(&self.qc)?;
        encoder.encode(self.entries.as_ref())?;
        encoder.encode(self.merkle_proofs.as_ref())?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for CommitmentProof
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 9 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 9,
                actual: length,
            });
        }

        let tx_hash: Hash = decoder.decode()?;
        let source_shard: ShardGroupId = decoder.decode()?;
        let target_shard: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let block_timestamp: u64 = decoder.decode()?;
        let state_root: Hash = decoder.decode()?;
        let qc: QuorumCertificate = decoder.decode()?;
        let entries: Vec<StateEntry> = decoder.decode()?;
        let merkle_proofs: Vec<SubstateInclusionProof> = decoder.decode()?;

        Ok(Self {
            tx_hash,
            source_shard,
            target_shard,
            block_height,
            block_timestamp,
            state_root,
            qc,
            entries: Arc::new(entries),
            merkle_proofs: Arc::new(merkle_proofs),
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for CommitmentProof {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for CommitmentProof {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("CommitmentProof", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl CommitmentProof {
    /// Create a new commitment proof.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        block_timestamp: u64,
        state_root: Hash,
        qc: QuorumCertificate,
        entries: Arc<Vec<StateEntry>>,
        merkle_proofs: Arc<Vec<SubstateInclusionProof>>,
    ) -> Self {
        assert_eq!(
            entries.len(),
            merkle_proofs.len(),
            "CommitmentProof: entries and merkle_proofs must have the same length"
        );
        Self {
            tx_hash,
            source_shard,
            target_shard,
            block_height,
            block_timestamp,
            state_root,
            qc,
            entries,
            merkle_proofs,
        }
    }

    /// Get the nodes referenced in this proof.
    ///
    /// Used by livelock for cycle detection (node overlap checking).
    pub fn nodes(&self) -> HashSet<NodeId> {
        self.entries.iter().filter_map(|e| e.node_id()).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test StateEntry with a valid storage key format.
    fn test_entry(seed: u8) -> StateEntry {
        let mut storage_key = Vec::with_capacity(6 + 20 + 30 + 1 + 1);
        storage_key.extend_from_slice(b"radix:");
        storage_key.extend_from_slice(&[0u8; 20]);
        storage_key.extend_from_slice(&[seed; 30]);
        storage_key.push(0);
        storage_key.push(seed);

        StateEntry::new(storage_key, Some(vec![seed, seed + 1]))
    }

    fn test_qc() -> QuorumCertificate {
        QuorumCertificate::genesis()
    }

    #[test]
    fn test_commitment_proof_nodes() {
        let entries = vec![test_entry(1), test_entry(2), test_entry(3)];
        let proofs = vec![
            SubstateInclusionProof::dummy(),
            SubstateInclusionProof::dummy(),
            SubstateInclusionProof::dummy(),
        ];

        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(100),
            1000,
            Hash::from_bytes(b"state_root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(proofs),
        );

        let nodes = proof.nodes();
        assert_eq!(nodes.len(), 3);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
        assert!(nodes.contains(&NodeId([3; 30])));
    }

    #[test]
    fn test_commitment_proof_serialization_roundtrip() {
        let entries = vec![test_entry(1), test_entry(2)];
        let substate_proof = SubstateInclusionProof {
            entity: MerkleInclusionProof {
                leaf_key: Some(vec![1, 2, 3]),
                leaf_value_hash: Some(Hash::from_bytes(b"entity_val")),
                siblings: vec![Hash::from_bytes(b"e_sib1")],
            },
            partition: MerkleInclusionProof {
                leaf_key: Some(vec![0]),
                leaf_value_hash: Some(Hash::from_bytes(b"partition_val")),
                siblings: vec![Hash::from_bytes(b"p_sib1")],
            },
            substate: MerkleInclusionProof {
                leaf_key: Some(vec![4, 5]),
                leaf_value_hash: Some(Hash::from_bytes(b"substate_val")),
                siblings: vec![Hash::from_bytes(b"s_sib1"), Hash::from_bytes(b"s_sib2")],
            },
        };

        let original = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(50),
            1000,
            Hash::from_bytes(b"state_root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(vec![substate_proof.clone(), substate_proof]),
        );

        let bytes = sbor::basic_encode(&original).expect("encoding should succeed");
        let decoded: CommitmentProof = sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_entries_hash_deterministic() {
        let entries = vec![test_entry(1), test_entry(2)];
        let proofs = vec![
            SubstateInclusionProof::dummy(),
            SubstateInclusionProof::dummy(),
        ];
        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx"),
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(1),
            1000,
            Hash::from_bytes(b"root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(proofs),
        );

        let hash1 = proof.entries_hash();
        let hash2 = proof.entries_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_merkle_inclusion_proof_serialization_roundtrip() {
        let proof = MerkleInclusionProof {
            leaf_key: Some(vec![1, 2, 3, 4]),
            leaf_value_hash: Some(Hash::from_bytes(b"value_hash")),
            siblings: vec![
                Hash::from_bytes(b"sibling_0"),
                Hash::from_bytes(b"sibling_1"),
            ],
        };

        let bytes = sbor::basic_encode(&proof).expect("encoding should succeed");
        let decoded: MerkleInclusionProof =
            sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_merkle_inclusion_proof_none_leaf() {
        let proof = MerkleInclusionProof {
            leaf_key: None,
            leaf_value_hash: None,
            siblings: vec![],
        };

        let bytes = sbor::basic_encode(&proof).expect("encoding should succeed");
        let decoded: MerkleInclusionProof =
            sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(proof, decoded);
    }
}
