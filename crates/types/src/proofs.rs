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

use crate::{BlockHeight, Hash, NodeId, ShardGroupId, StateEntry};
use sbor::prelude::*;
use std::collections::HashSet;

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
/// Identifies the source block (for joining with `CommittedBlockHeader`)
/// and carries the verkle proof plus per-transaction state entries.
/// The QC and state_root are obtained from `CommittedBlockHeader` received
/// via gossip — they don't travel with the provision batch.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ProvisionBatch {
    /// Source shard that committed this block.
    pub source_shard: ShardGroupId,

    /// Block height at which the state was committed.
    pub block_height: BlockHeight,

    /// Aggregated verkle proof covering all entries for this block.
    pub proof: VerkleInclusionProof,

    /// Per-transaction entries.
    pub transactions: Vec<TxEntries>,
}

impl ProvisionBatch {
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

    /// Create a dummy batch for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn dummy(source_shard: ShardGroupId, block_height: BlockHeight) -> Self {
        Self {
            source_shard,
            block_height,
            proof: VerkleInclusionProof::dummy(),
            transactions: vec![],
        }
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
        let original = ProvisionBatch {
            source_shard: ShardGroupId(1),
            block_height: BlockHeight(42),
            proof: VerkleInclusionProof::new(vec![1, 2, 3]),
            transactions: vec![],
        };

        let bytes = sbor::basic_encode(&original).unwrap();
        let decoded: ProvisionBatch = sbor::basic_decode(&bytes).unwrap();
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
        let mut batch = ProvisionBatch::dummy(ShardGroupId(0), BlockHeight(10));
        batch.transactions = vec![TxEntries {
            tx_hash: Hash::from_bytes(b"tx1"),
            entries: vec![test_entry(1)],
        }];

        let bytes = sbor::basic_encode(&batch).unwrap();
        let decoded: ProvisionBatch = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(batch, decoded);
    }

    #[test]
    fn test_provision_batch_all_entries_deduped() {
        let entry = test_entry(1);
        let mut batch = ProvisionBatch::dummy(ShardGroupId(0), BlockHeight(10));
        batch.transactions = vec![
            TxEntries {
                tx_hash: Hash::from_bytes(b"tx1"),
                entries: vec![entry.clone()],
            },
            TxEntries {
                tx_hash: Hash::from_bytes(b"tx2"),
                entries: vec![entry, test_entry(2)],
            },
        ];

        let deduped = batch.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_verkle_inclusion_proof_roundtrip() {
        let proof = VerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = sbor::basic_encode(&proof).unwrap();
        let decoded: VerkleInclusionProof = sbor::basic_decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }
}
