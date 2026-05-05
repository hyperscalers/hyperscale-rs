//! Per-block bundle of transaction provisions with a shared merkle proof.

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{
    BlockHeight, Hash, MerkleInclusionProof, NodeId, ProvisionHash, RETENTION_HORIZON,
    ShardGroupId, StateEntry, TxEntries, TxHash, WeightedTimestamp,
};

/// Cap on per-tx entries carried in a single `Provisions` at decode time.
///
/// A `Provisions` covers tx-by-tx state transfers from a single source
/// block to a single target shard, so `transactions.len()` is bounded by
/// the source block's tx count. `MAX_TX_HASHES_PER_BLOCK` (`12_288` in
/// `hyperscale-bft`) is the global ceiling.
const MAX_TX_ENTRIES_PER_PROVISION: usize = 12_288;

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
/// The content hash is computed eagerly at construction and on deserialization.
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
    pub transactions: Vec<TxEntries>,

    /// Cached content hash (blake3 over SBOR-encoded content fields).
    hash: ProvisionHash,
}

impl Debug for Provisions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provision")
            .field("hash", &self.hash)
            .field("source_shard", &self.source_shard)
            .field("target_shard", &self.target_shard)
            .field("block_height", &self.block_height)
            .field("transactions", &self.transactions.len())
            .finish_non_exhaustive()
    }
}

impl Clone for Provisions {
    fn clone(&self) -> Self {
        Self {
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            block_height: self.block_height,
            proof: self.proof.clone(),
            transactions: self.transactions.clone(),
            hash: self.hash,
        }
    }
}

impl PartialEq for Provisions {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for Provisions {}

// Manual SBOR: the cached hash is derived, not serialized.
impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for Provisions {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(5)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.target_shard)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.proof)?;
        encoder.encode(&self.transactions)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for Provisions {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 5 {
            return Err(DecodeError::UnexpectedSize {
                expected: 5,
                actual: length,
            });
        }
        let source_shard: ShardGroupId = decoder.decode()?;
        let target_shard: ShardGroupId = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let proof: MerkleInclusionProof = decoder.decode()?;
        // Bounded inline rather than via SBOR's default Vec decoder, which
        // would honor a peer-supplied `len` up to the entire 10 MB libp2p
        // message budget.
        decoder.read_and_check_value_kind(ValueKind::Array)?;
        let element_kind = decoder.read_and_check_value_kind(TxEntries::value_kind())?;
        let transactions_len = decoder.read_size()?;
        if transactions_len > MAX_TX_ENTRIES_PER_PROVISION {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX_TX_ENTRIES_PER_PROVISION,
                actual: transactions_len,
            });
        }
        let mut transactions = Vec::with_capacity(transactions_len.min(1024));
        for _ in 0..transactions_len {
            transactions.push(decoder.decode_deeper_body_with_value_kind(element_kind)?);
        }
        let hash = Self::compute_hash(
            source_shard,
            target_shard,
            block_height,
            &proof,
            &transactions,
        );
        Ok(Self {
            source_shard,
            target_shard,
            block_height,
            proof,
            transactions,
            hash,
        })
    }
}

impl Categorize<NoCustomValueKind> for Provisions {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for Provisions {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("Provision", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

impl Provisions {
    /// Create a new provisions, computing the content hash eagerly.
    #[must_use]
    pub fn new(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: MerkleInclusionProof,
        transactions: Vec<TxEntries>,
    ) -> Self {
        let hash = Self::compute_hash(
            source_shard,
            target_shard,
            block_height,
            &proof,
            &transactions,
        );
        Self {
            source_shard,
            target_shard,
            block_height,
            proof,
            transactions,
            hash,
        }
    }

    /// Content hash (precomputed at construction / deserialization).
    #[must_use]
    pub const fn hash(&self) -> ProvisionHash {
        self.hash
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
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(100),
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
            ShardGroupId(1),
            ShardGroupId(2),
            BlockHeight(42),
            MerkleInclusionProof::new(vec![1, 2, 3]),
            vec![],
        );

        let bytes = basic_encode(&original).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.target_shard, ShardGroupId(2));
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
    fn test_provisions_roundtrip() {
        let provisions = Provisions::new(
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(10),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                entries: vec![test_entry(1)],
                target_nodes: vec![],
            }],
        );

        let bytes = basic_encode(&provisions).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(provisions, decoded);
    }

    #[test]
    fn test_provisions_all_entries_deduped() {
        let entry = test_entry(1);
        let mut provisions = Provisions::dummy(ShardGroupId(0), ShardGroupId(1), BlockHeight(10));
        provisions.transactions = vec![
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
            enc.encode(&ShardGroupId(1)).unwrap();
            enc.encode(&ShardGroupId(2)).unwrap();
            enc.encode(&BlockHeight(10)).unwrap();
            enc.encode(&MerkleInclusionProof::dummy()).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(TxEntries::value_kind()).unwrap();
            enc.write_size(MAX_TX_ENTRIES_PER_PROVISION + 1).unwrap();
        }
        let err = basic_decode::<Provisions>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TX_ENTRIES_PER_PROVISION
                    && actual == MAX_TX_ENTRIES_PER_PROVISION + 1
        ));
    }
}
