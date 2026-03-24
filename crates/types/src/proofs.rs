//! Proof types for Byzantine-safe backpressure and livelock handling.
//!
//! This module contains cryptographic proof types that enable validators to verify
//! block contents without depending on having seen the same network messages.
//!
//! # Proof Types
//!
//! - [`CommitmentProof`]: Proves a transaction was committed on another shard
//!   (via QC-authenticated state root + verkle inclusion proofs)
//! - [`VerkleInclusionProof`]: Proves a substate's inclusion in the state tree
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
// VerkleInclusionProof
// ============================================================================

/// Verkle proof of a substate's inclusion in a single tier of the state tree.
///
/// Opaque bytes containing a serialized JVT `VerkleProof`. Serialization and
/// verification are handled by the `state-tree` crate, which has the necessary
/// arkworks dependencies.
///
/// The proof contains:
/// - IPA-based multipoint proof (~576 bytes constant)
/// - Verifier queries (commitments + evaluation points + results)
/// - Key data (claimed key, value, stem, termination info)
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct VerkleInclusionProof(pub Vec<u8>);

impl VerkleInclusionProof {
    /// Create a new proof from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a dummy (empty) proof for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn dummy() -> Self {
        Self(Vec::new())
    }
}

// ============================================================================
// SubstateInclusionProof
// ============================================================================

/// Aggregated verkle inclusion proof covering multiple substates in a flat tree.
///
/// All substates live in a single JVT tree. This proof batches ALL entries
/// for a block into a single constant-size (~576 byte) multipoint proof.
/// The proof size is independent of the number of entries.
///
/// The JVT proof's key_data contains the actual keys and values, so the
/// verifier can match entries and confirm the state root in one operation.
pub type SubstateInclusionProof = VerkleInclusionProof;

// ============================================================================
// CommitmentProof
// ============================================================================

/// Proof that a transaction was committed on another shard.
///
/// Uses QC-authenticated state root + verkle inclusion proofs. The trust chain is:
/// 1. QC proves 2f+1 validators agreed on block header (which contains state_root)
/// 2. Verkle proofs prove each entry's inclusion against that state_root
///
/// This enables:
/// 1. **Priority ordering**: TXs with proof are included BEFORE other TXs in blocks
/// 2. **Limit bypass**: TXs with proof can exceed the backpressure limit (1024 cross-shard TXs)
///
/// # Size Comparison
///
/// Before: N validators each send ~500 byte provision = ~50KB total
/// After: 1 proposer sends proofs (~576 bytes per tier × 3 tiers per entry), dramatically lower bandwidth
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

    /// Aggregated verkle inclusion proof covering all entries, proving their values
    /// against the QC-committed state_root.
    /// Wrapped in Arc for efficient sharing.
    pub proof: Arc<SubstateInclusionProof>,
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
            && *self.proof == *other.proof
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
        encoder.encode(self.proof.as_ref())?;
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
        let proof: SubstateInclusionProof = decoder.decode()?;

        Ok(Self {
            tx_hash,
            source_shard,
            target_shard,
            block_height,
            block_timestamp,
            state_root,
            qc,
            entries: Arc::new(entries),
            proof: Arc::new(proof),
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
        proof: Arc<SubstateInclusionProof>,
    ) -> Self {
        Self {
            tx_hash,
            source_shard,
            target_shard,
            block_height,
            block_timestamp,
            state_root,
            qc,
            entries,
            proof,
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
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + 1);
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

        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(100),
            1000,
            Hash::from_bytes(b"state_root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(SubstateInclusionProof::dummy()),
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
        let substate_proof = VerkleInclusionProof::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let original = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(50),
            1000,
            Hash::from_bytes(b"state_root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(substate_proof),
        );

        let bytes = sbor::basic_encode(&original).expect("encoding should succeed");
        let decoded: CommitmentProof = sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_entries_hash_deterministic() {
        let entries = vec![test_entry(1), test_entry(2)];
        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx"),
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(1),
            1000,
            Hash::from_bytes(b"root"),
            test_qc(),
            Arc::new(entries),
            Arc::new(SubstateInclusionProof::dummy()),
        );

        let hash1 = proof.entries_hash();
        let hash2 = proof.entries_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verkle_inclusion_proof_serialization_roundtrip() {
        let proof = VerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = sbor::basic_encode(&proof).expect("encoding should succeed");
        let decoded: VerkleInclusionProof =
            sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_verkle_inclusion_proof_empty() {
        let proof = VerkleInclusionProof::dummy();
        let bytes = sbor::basic_encode(&proof).expect("encoding should succeed");
        let decoded: VerkleInclusionProof =
            sbor::basic_decode(&bytes).expect("decoding should succeed");
        assert_eq!(proof, decoded);
    }
}
