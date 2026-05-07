//! Per-block bundle of transaction provisions with a shared merkle proof.

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use sbor::prelude::*;

use crate::{
    BlockHeight, BoundedVec, Hash, MAX_TXS_PER_BLOCK, MerkleInclusionProof, NodeId, ProvisionHash,
    RETENTION_HORIZON, ShardGroupId, StateEntry, TxEntries, TxHash, WeightedTimestamp,
};

/// All provisions from a single source block, scoped to a single target shard.
///
/// Identifies the (source block, target shard) pair: source identifies what
/// state was committed and where to verify it; target identifies which shard
/// the bundle is destined for. One `Provisions` per (`source_block`, `target_shard`)
/// — a source block contributing state to multiple target shards produces
/// multiple `Provisions`, each with its own merkle proof scoped to that
/// shard's slice of entries.
///
/// The QC and `state_root` are obtained from `CommittedBlockHeader` received
/// via gossip — they don't travel with the provisions.
///
/// The content hash is computed lazily on first call to [`Self::hash`] and
/// cached for the lifetime of the value.
#[derive(BasicSbor)]
pub struct Provisions {
    /// Source shard that committed this block.
    pub source_shard: ShardGroupId,

    /// Target shard the bundle is destined for.
    pub target_shard: ShardGroupId,

    /// Block height at which the state was committed.
    pub block_height: BlockHeight,

    /// Aggregated merkle multiproof covering all entries for this block.
    pub proof: MerkleInclusionProof,

    /// Per-transaction entries.
    pub transactions: BoundedVec<TxEntries, MAX_TXS_PER_BLOCK>,

    /// Lazily-computed content hash (blake3 over SBOR-encoded content fields).
    /// Populated on first [`Self::hash`] call; not on the wire.
    #[sbor(skip)]
    hash: OnceLock<ProvisionHash>,
}

impl Debug for Provisions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provision")
            .field("hash", &self.hash())
            .field("source_shard", &self.source_shard)
            .field("target_shard", &self.target_shard)
            .field("block_height", &self.block_height)
            .field("transactions", &self.transactions.len())
            .finish_non_exhaustive()
    }
}

impl Clone for Provisions {
    fn clone(&self) -> Self {
        let cloned_hash = OnceLock::new();
        if let Some(h) = self.hash.get() {
            let _ = cloned_hash.set(*h);
        }
        Self {
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            block_height: self.block_height,
            proof: self.proof.clone(),
            transactions: self.transactions.clone(),
            hash: cloned_hash,
        }
    }
}

impl PartialEq for Provisions {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Provisions {}

impl Provisions {
    /// Create a new provisions. The content hash is computed lazily on
    /// first call to [`Self::hash`].
    ///
    /// # Panics
    ///
    /// Panics if `transactions.len() > MAX_TXS_PER_BLOCK`.
    #[must_use]
    pub fn new(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: MerkleInclusionProof,
        transactions: Vec<TxEntries>,
    ) -> Self {
        Self {
            source_shard,
            target_shard,
            block_height,
            proof,
            transactions: transactions.into(),
            hash: OnceLock::new(),
        }
    }

    /// Content hash, computed on first call and cached.
    #[must_use]
    pub fn hash(&self) -> ProvisionHash {
        *self.hash.get_or_init(|| {
            Self::compute_hash(
                self.source_shard,
                self.target_shard,
                self.block_height,
                &self.proof,
                &self.transactions,
            )
        })
    }

    /// Deadline past which these provisions are provably useless on every
    /// shard.
    ///
    /// `source_weighted_ts` is the source block's QC `weighted_timestamp`,
    /// available from the paired remote header. Past
    /// `source_weighted_ts + RETENTION_HORIZON` every tx that could have
    /// referenced this data has expired its `validity_range` and
    /// completed (or aborted via the all-abort fallback) — no shard can
    /// still reference these provisions.
    #[must_use]
    pub fn deadline(&self, source_weighted_ts: WeightedTimestamp) -> WeightedTimestamp {
        source_weighted_ts.plus(RETENTION_HORIZON)
    }

    fn compute_hash(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: &MerkleInclusionProof,
        transactions: &[TxEntries],
    ) -> ProvisionHash {
        // Encode the content fields (excluding the hash itself) for hashing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &basic_encode(&source_shard).expect("ShardGroupId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(&target_shard).expect("ShardGroupId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(&block_height).expect("BlockHeight serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(proof).expect("MerkleInclusionProof serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(transactions).expect("Vec<TxEntries> serialization should never fail"),
        );
        ProvisionHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Get all node IDs across all transactions.
    #[must_use]
    pub fn all_node_ids(&self) -> HashSet<NodeId> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().filter_map(StateEntry::node_id))
            .collect()
    }

    /// Get all entries across all transactions, sorted and deduped by `storage_key`.
    #[must_use]
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

    /// Get the transaction hashes in these provisions.
    #[must_use]
    pub fn tx_hashes(&self) -> Vec<TxHash> {
        self.transactions.iter().map(|tx| tx.tx_hash).collect()
    }

    /// Create a dummy `Provisions` for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn dummy(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
    ) -> Self {
        Self::new(
            source_shard,
            target_shard,
            block_height,
            MerkleInclusionProof::dummy(),
            vec![],
        )
    }
}

#[cfg(test)]
mod tests {
    use sbor::{Categorize as _, DecodeError, Encoder as _, NoCustomValueKind, ValueKind};

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
    fn test_provision_deadline_is_source_ts_plus_retention_horizon() {
        let provisions = Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(100),
            MerkleInclusionProof::new(vec![]),
            vec![],
        );
        let source_ts = WeightedTimestamp::from_millis(1_000_000);
        assert_eq!(
            provisions.deadline(source_ts),
            source_ts.plus(RETENTION_HORIZON)
        );
    }

    #[test]
    fn test_provisions_fields_roundtrip() {
        let original = Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(42),
            MerkleInclusionProof::new(vec![1, 2, 3]),
            vec![],
        );

        let bytes = basic_encode(&original).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.target_shard, ShardGroupId::new(2));
    }

    #[test]
    fn test_tx_entries_node_ids() {
        let tx = TxEntries::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            vec![test_entry(1), test_entry(2)],
            vec![],
        );
        let nodes = tx.node_ids();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
    }

    #[test]
    fn test_provisions_roundtrip() {
        let provisions = Provisions::new(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![TxEntries::new(
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                vec![test_entry(1)],
                vec![],
            )],
        );

        let bytes = basic_encode(&provisions).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(provisions, decoded);
    }

    #[test]
    fn test_provisions_all_entries_deduped() {
        let entry = test_entry(1);
        let mut provisions = Provisions::dummy(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(10),
        );
        provisions.transactions = vec![
            TxEntries::new(
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                vec![entry.clone()],
                vec![],
            ),
            TxEntries::new(
                TxHash::from_raw(Hash::from_bytes(b"tx2")),
                vec![entry, test_entry(2)],
                vec![],
            ),
        ]
        .into();

        let deduped = provisions.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merkle_inclusion_proof_roundtrip() {
        let proof = MerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = basic_encode(&proof).unwrap();
        let decoded: MerkleInclusionProof = basic_decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn decode_rejects_oversized_transactions_count() {
        use sbor::{BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder};
        let mut buf = Vec::with_capacity(64);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            enc.encode(&ShardGroupId::new(1)).unwrap();
            enc.encode(&ShardGroupId::new(2)).unwrap();
            enc.encode(&BlockHeight::new(10)).unwrap();
            enc.encode(&MerkleInclusionProof::dummy()).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(TxEntries::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<Provisions>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK
                    && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
