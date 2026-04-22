//! Proof types for cross-shard provisioning and block validation.
//!
//! # Architecture
//!
//! Provision data has three natural levels:
//!
//! 1. **Source block** ([`SourceBlockAttestation`]): QC + state_root + merkle proof.
//!    Shared across all transactions from the same block. Serialized once.
//!
//! 2. **Transaction** ([`TxEntries`]): Per-transaction state entries.
//!    Lightweight — just a tx hash and the substates it touched.
//!
//! 3. **Routing**: Target shard, recipients. Handled at the network layer.
//!
//! [`Provision`] bundles level 1 + level 2 together as the natural unit
//! of work. This eliminates the N× proof duplication that occurs when the
//! proof is flattened into each per-transaction struct.

use crate::{BlockHeight, Hash, NodeId, ShardGroupId, StateEntry, TxHash};
use sbor::prelude::*;
use std::collections::HashSet;

// ============================================================================
// MerkleInclusionProof
// ============================================================================

/// Merkle multiproof authenticating substates' inclusion in the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`. Encoding,
/// decoding and verification are handled by the storage crate, which owns
/// the adapter between the JMT crate and on-wire SBOR types.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct MerkleInclusionProof(pub Vec<u8>);

impl MerkleInclusionProof {
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
// TxEntries
// ============================================================================

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction, what state it touched on the source shard,
/// and what nodes it needs from the target shard (for conflict detection).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxEntries {
    /// Hash of the transaction.
    pub tx_hash: TxHash,

    /// The state entries this transaction touched on the source shard.
    pub entries: Vec<StateEntry>,

    /// Node IDs this transaction needs from the target shard.
    ///
    /// Used for bidirectional conflict detection: a true deadlock requires
    /// overlap in both directions (source nodes vs local needs, AND target
    /// nodes vs local owns).
    pub target_nodes: Vec<NodeId>,
}

impl TxEntries {
    /// Get the node IDs referenced by this transaction's entries.
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries.iter().filter_map(|e| e.node_id()).collect()
    }
}

// ============================================================================
// Provision
// ============================================================================

/// A batch of provisions from a single source block.
///
/// Identifies the source block (for joining with `CommittedBlockHeader`)
/// and carries the merkle proof plus per-transaction state entries.
/// The QC and state_root are obtained from `CommittedBlockHeader` received
/// via gossip — they don't travel with the provision batch.
///
/// The content hash is computed eagerly at construction and on deserialization.
pub struct Provision {
    /// Source shard that committed this block.
    pub source_shard: ShardGroupId,

    /// Block height at which the state was committed.
    pub block_height: BlockHeight,

    /// Aggregated merkle multiproof covering all entries for this block.
    pub proof: MerkleInclusionProof,

    /// Per-transaction entries.
    pub transactions: Vec<TxEntries>,

    /// Cached content hash (blake3 over SBOR-encoded content fields).
    hash: Hash,
}

impl std::fmt::Debug for Provision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provision")
            .field("hash", &self.hash)
            .field("source_shard", &self.source_shard)
            .field("block_height", &self.block_height)
            .field("transactions", &self.transactions.len())
            .finish()
    }
}

impl Clone for Provision {
    fn clone(&self) -> Self {
        Self {
            source_shard: self.source_shard,
            block_height: self.block_height,
            proof: self.proof.clone(),
            transactions: self.transactions.clone(),
            hash: self.hash,
        }
    }
}

impl PartialEq for Provision {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Provision {}

// Manual SBOR: the cached hash is derived, not serialized.
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for Provision
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(4)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.proof)?;
        encoder.encode(&self.transactions)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for Provision
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
        let source_shard: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let proof: MerkleInclusionProof = decoder.decode()?;
        let transactions: Vec<TxEntries> = decoder.decode()?;
        let hash = Self::compute_hash(source_shard, &block_height, &proof, &transactions);
        Ok(Self {
            source_shard,
            block_height,
            proof,
            transactions,
            hash,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for Provision {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for Provision {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("Provision", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl Provision {
    /// Create a new provision batch, computing the content hash eagerly.
    pub fn new(
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: MerkleInclusionProof,
        transactions: Vec<TxEntries>,
    ) -> Self {
        let hash = Self::compute_hash(source_shard, &block_height, &proof, &transactions);
        Self {
            source_shard,
            block_height,
            proof,
            transactions,
            hash,
        }
    }

    /// Content hash (precomputed at construction / deserialization).
    pub fn hash(&self) -> Hash {
        self.hash
    }

    fn compute_hash(
        source_shard: ShardGroupId,
        block_height: &BlockHeight,
        proof: &MerkleInclusionProof,
        transactions: &[TxEntries],
    ) -> Hash {
        // Encode the content fields (excluding the hash itself) for hashing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &sbor::basic_encode(&source_shard)
                .expect("ShardGroupId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &sbor::basic_encode(block_height).expect("BlockHeight serialization should never fail"),
        );
        bytes.extend_from_slice(
            &sbor::basic_encode(proof)
                .expect("MerkleInclusionProof serialization should never fail"),
        );
        bytes.extend_from_slice(
            &sbor::basic_encode(transactions)
                .expect("Vec<TxEntries> serialization should never fail"),
        );
        Hash::from_bytes(&bytes)
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
    pub fn tx_hashes(&self) -> Vec<TxHash> {
        self.transactions.iter().map(|tx| tx.tx_hash).collect()
    }

    /// Create a dummy batch for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn dummy(source_shard: ShardGroupId, block_height: BlockHeight) -> Self {
        Self::new(
            source_shard,
            block_height,
            MerkleInclusionProof::dummy(),
            vec![],
        )
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
    fn test_provision_batch_fields_roundtrip() {
        let original = Provision::new(
            ShardGroupId(1),
            BlockHeight(42),
            MerkleInclusionProof::new(vec![1, 2, 3]),
            vec![],
        );

        let bytes = sbor::basic_encode(&original).unwrap();
        let decoded: Provision = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tx_entries_node_ids() {
        let tx = TxEntries {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            entries: vec![test_entry(1), test_entry(2)],
            target_nodes: vec![],
        };
        let nodes = tx.node_ids();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
    }

    #[test]
    fn test_provision_batch_roundtrip() {
        let batch = Provision::new(
            ShardGroupId(0),
            BlockHeight(10),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                entries: vec![test_entry(1)],
                target_nodes: vec![],
            }],
        );

        let bytes = sbor::basic_encode(&batch).unwrap();
        let decoded: Provision = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(batch, decoded);
    }

    #[test]
    fn test_provision_batch_all_entries_deduped() {
        let entry = test_entry(1);
        let mut batch = Provision::dummy(ShardGroupId(0), BlockHeight(10));
        batch.transactions = vec![
            TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                entries: vec![entry.clone()],
                target_nodes: vec![],
            },
            TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx2")),
                entries: vec![entry, test_entry(2)],
                target_nodes: vec![],
            },
        ];

        let deduped = batch.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merkle_inclusion_proof_roundtrip() {
        let proof = MerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = sbor::basic_encode(&proof).unwrap();
        let decoded: MerkleInclusionProof = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
