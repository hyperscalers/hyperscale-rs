//! Proof types for cross-shard provisioning and block validation.
//!
//! # Architecture
//!
//! Provision data has three natural levels:
//!
//! 1. **Source block** ([`SourceBlockAttestation`]): QC + state_root + verkle proof.
//!    Shared across all transactions from the same block. Serialized once.
//!
//! 2. **Transaction** ([`TxEntries`]): Per-transaction state entries.
//!    Lightweight — just a tx hash and the substates it touched.
//!
//! 3. **Routing**: Target shard, recipients. Handled at the network layer.
//!
//! [`ProvisionBatch`] bundles level 1 + level 2 together as the natural unit
//! of work. This eliminates the N× proof duplication that occurs when the
//! proof is flattened into each per-transaction struct.
//!
//! For blocks, [`CommitmentEntry`] references a [`SourceBlockAttestation`] by
//! index, avoiding duplication when many transactions reference the same
//! source block.

use crate::{BlockHeight, Hash, NodeId, QuorumCertificate, ShardGroupId, StateEntry};
use sbor::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

// ============================================================================
// VerkleInclusionProof
// ============================================================================

/// Verkle proof of substates' inclusion in the state tree.
///
/// Opaque bytes containing a serialized JVT `VerkleProof`. Serialization and
/// verification are handled by the `state-tree` crate, which has the necessary
/// arkworks dependencies.
///
/// The proof contains:
/// - IPA-based multipoint proof (~576 bytes constant core)
/// - Verifier queries (commitments + evaluation points + results, linear in key count)
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

/// Aggregated verkle inclusion proof covering multiple substates in a flat tree.
pub type SubstateInclusionProof = VerkleInclusionProof;

// ============================================================================
// SourceBlockAttestation
// ============================================================================

/// Attestation that a source block committed specific state.
///
/// Contains everything needed to independently verify that entries were part
/// of a committed block's state:
/// 1. QC proves 2f+1 validators agreed on block header (which contains state_root)
/// 2. Verkle proof proves each entry's inclusion against that state_root
///
/// Shared across all transactions from the same (source_shard, block_height).
/// Serialized once per source block, not per transaction.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SourceBlockAttestation {
    /// Source shard that committed this block.
    pub source_shard: ShardGroupId,

    /// Block height at which the state was committed.
    pub block_height: BlockHeight,

    /// Unix timestamp (milliseconds) of the source block.
    pub block_timestamp: u64,

    /// State root from the committed block header (verified via QC).
    pub state_root: Hash,

    /// Quorum Certificate proving the state_root is correct.
    pub qc: QuorumCertificate,

    /// Aggregated verkle proof covering all entries for this block.
    pub proof: SubstateInclusionProof,

    /// All state entries covered by this proof (sorted, deduped by storage_key).
    ///
    /// The verkle proof is a multipoint proof over these entries. Verification
    /// requires the full set — passing a subset will fail the proof check.
    /// Stored on the attestation so it forms a self-contained verifiable unit.
    pub entries: Vec<StateEntry>,
}

impl SourceBlockAttestation {
    /// Create a dummy attestation for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn dummy(source_shard: ShardGroupId, block_height: BlockHeight) -> Self {
        Self {
            source_shard,
            block_height,
            block_timestamp: 1000 + block_height.0,
            state_root: Hash::ZERO,
            qc: QuorumCertificate::genesis(),
            proof: SubstateInclusionProof::dummy(),
            entries: vec![],
        }
    }
}

// ============================================================================
// TxEntries
// ============================================================================

/// Per-transaction state entries within a provision batch.
///
/// Lightweight: just identifies which transaction and what state it touched
/// on the source shard.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxEntries {
    /// Hash of the transaction.
    pub tx_hash: Hash,

    /// The state entries this transaction touched on the source shard.
    pub entries: Vec<StateEntry>,
}

impl TxEntries {
    /// Get the node IDs referenced by this transaction's entries.
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries.iter().filter_map(|e| e.node_id()).collect()
    }
}

// ============================================================================
// ProvisionBatch
// ============================================================================

/// A batch of provisions from a single source block.
///
/// This is the natural unit of work. The attestation (including the verkle
/// proof) is shared via `Arc` across all transactions in the batch — and
/// across multiple target shards when broadcasting.
pub struct ProvisionBatch {
    /// Block-level attestation (QC + proof + state_root), shared.
    pub attestation: Arc<SourceBlockAttestation>,

    /// Per-transaction entries.
    pub transactions: Vec<TxEntries>,
}

impl ProvisionBatch {
    /// Source shard for this batch.
    pub fn source_shard(&self) -> ShardGroupId {
        self.attestation.source_shard
    }

    /// Block height for this batch.
    pub fn block_height(&self) -> BlockHeight {
        self.attestation.block_height
    }

    /// Get all node IDs across all transactions.
    pub fn all_node_ids(&self) -> HashSet<NodeId> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().filter_map(|e| e.node_id()))
            .collect()
    }

    /// Get all entries across all transactions, sorted and deduped by storage_key.
    pub fn all_entries_deduped(&self) -> Vec<StateEntry> {
        let mut entries: Vec<StateEntry> = self
            .transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().cloned())
            .collect();
        entries.sort_by(|a, b| a.storage_key.cmp(&b.storage_key));
        entries.dedup_by(|a, b| a.storage_key == b.storage_key);
        entries
    }

    /// Get transaction hashes in this batch.
    pub fn tx_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.tx_hash).collect()
    }
}

impl std::fmt::Debug for ProvisionBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionBatch")
            .field("source_shard", &self.attestation.source_shard)
            .field("block_height", &self.attestation.block_height)
            .field("transactions", &self.transactions.len())
            .finish()
    }
}

impl Clone for ProvisionBatch {
    fn clone(&self) -> Self {
        Self {
            attestation: Arc::clone(&self.attestation),
            transactions: self.transactions.clone(),
        }
    }
}

impl PartialEq for ProvisionBatch {
    fn eq(&self, other: &Self) -> bool {
        *self.attestation == *other.attestation && self.transactions == other.transactions
    }
}

impl Eq for ProvisionBatch {}

// Manual SBOR for ProvisionBatch (Arc field)
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for ProvisionBatch
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(self.attestation.as_ref())?;
        encoder.encode(&self.transactions)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for ProvisionBatch
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }

        let attestation: SourceBlockAttestation = decoder.decode()?;
        let transactions: Vec<TxEntries> = decoder.decode()?;

        Ok(Self {
            attestation: Arc::new(attestation),
            transactions,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for ProvisionBatch {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for ProvisionBatch {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("ProvisionBatch", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// ============================================================================
// CommitmentEntry
// ============================================================================

/// Per-transaction commitment data within a block.
///
/// References a [`SourceBlockAttestation`] by index into the block's
/// `source_attestations` array, avoiding duplication when multiple
/// transactions reference the same source block.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommitmentEntry {
    /// Hash of the committed transaction.
    pub tx_hash: Hash,

    /// Index into the block's `source_attestations` array.
    pub attestation_index: u16,

    /// Target shard that received the provisions (prevents cross-shard replay).
    pub target_shard: ShardGroupId,

    /// The state entries proving this transaction's state on the source shard.
    pub entries: Vec<StateEntry>,
}

impl CommitmentEntry {
    /// Get the node IDs referenced by this entry.
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries.iter().filter_map(|e| e.node_id()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(seed: u8) -> StateEntry {
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + 1);
        storage_key.extend_from_slice(&[0u8; 20]);
        storage_key.extend_from_slice(&[seed; 30]);
        storage_key.push(0);
        storage_key.push(seed);
        StateEntry::new(storage_key, Some(vec![seed, seed + 1]))
    }

    #[test]
    fn test_source_block_attestation_roundtrip() {
        let original = SourceBlockAttestation {
            source_shard: ShardGroupId(1),
            block_height: BlockHeight(42),
            block_timestamp: 1000,
            state_root: Hash::from_bytes(b"state_root"),
            qc: QuorumCertificate::genesis(),
            proof: VerkleInclusionProof::new(vec![1, 2, 3]),
            entries: vec![test_entry(1), test_entry(2)],
        };

        let bytes = sbor::basic_encode(&original).unwrap();
        let decoded: SourceBlockAttestation = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tx_entries_node_ids() {
        let tx = TxEntries {
            tx_hash: Hash::from_bytes(b"tx"),
            entries: vec![test_entry(1), test_entry(2)],
        };
        let nodes = tx.node_ids();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
    }

    #[test]
    fn test_provision_batch_roundtrip() {
        let attestation = SourceBlockAttestation::dummy(ShardGroupId(0), BlockHeight(10));
        let batch = ProvisionBatch {
            attestation: Arc::new(attestation),
            transactions: vec![TxEntries {
                tx_hash: Hash::from_bytes(b"tx1"),
                entries: vec![test_entry(1)],
            }],
        };

        let bytes = sbor::basic_encode(&batch).unwrap();
        let decoded: ProvisionBatch = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(batch, decoded);
    }

    #[test]
    fn test_provision_batch_all_entries_deduped() {
        let attestation = SourceBlockAttestation::dummy(ShardGroupId(0), BlockHeight(10));
        let entry = test_entry(1);
        let batch = ProvisionBatch {
            attestation: Arc::new(attestation),
            transactions: vec![
                TxEntries {
                    tx_hash: Hash::from_bytes(b"tx1"),
                    entries: vec![entry.clone()],
                },
                TxEntries {
                    tx_hash: Hash::from_bytes(b"tx2"),
                    entries: vec![entry, test_entry(2)],
                },
            ],
        };

        let deduped = batch.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_commitment_entry_roundtrip() {
        let entry = CommitmentEntry {
            tx_hash: Hash::from_bytes(b"tx"),
            attestation_index: 0,
            target_shard: ShardGroupId(1),
            entries: vec![test_entry(1)],
        };

        let bytes = sbor::basic_encode(&entry).unwrap();
        let decoded: CommitmentEntry = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_verkle_inclusion_proof_roundtrip() {
        let proof = VerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = sbor::basic_encode(&proof).unwrap();
        let decoded: VerkleInclusionProof = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
