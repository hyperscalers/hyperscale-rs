//! State-related types for cross-shard execution.

use std::sync::Arc;

use sbor::prelude::*;

use crate::{
    BlockHeight, BoundedBytes, Hash, MAX_STATE_ENTRY_KEY_LEN, MAX_STATE_ENTRY_VALUE_LEN, NodeId,
    ShardGroupId, TxHash,
};

// ============================================================================
// State entry types with pre-computed storage keys
// ============================================================================

/// A state entry with pre-computed storage key for fast engine lookup.
///
/// This type stores the pre-computed storage key that can be used directly for
/// database lookups without any key transformation at the receiving shard.
///
/// The storage key format is: `db_node_key(50) + partition_num(1) + sort_key(var)`
/// where `db_node_key` is the `SpreadPrefixKeyMapper` hash (expensive to compute).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SubstateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: `db_node_key` (50 bytes) + partition (1 byte) + `sort_key`
    pub storage_key: BoundedBytes<MAX_STATE_ENTRY_KEY_LEN>,

    /// SBOR-encoded substate value (None if deleted/doesn't exist).
    pub value: Option<BoundedBytes<MAX_STATE_ENTRY_VALUE_LEN>>,
}

/// Hash prefix length in `db_node_key` (`SpreadPrefixKeyMapper` adds 20-byte hash)
const HASH_PREFIX_LEN: usize = 20;

impl SubstateEntry {
    /// Create a new DB state entry with pre-computed storage key.
    #[must_use]
    pub fn new(storage_key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
        Self {
            storage_key: storage_key.into(),
            value: value.map(Into::into),
        }
    }

    /// Extract the `NodeId` from the storage key.
    ///
    /// The storage key format is:
    /// - `db_node_key` (50 bytes: 20-byte hash prefix + 30-byte `node_id`)
    /// - `partition_num` (1 byte)
    /// - `sort_key` (variable)
    ///
    /// The `NodeId` is at bytes [20..50] (after hash prefix).
    #[must_use]
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
    #[must_use]
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
    /// `SpreadPrefixKeyMapper` hashes.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_entry(
        node_id: NodeId,
        partition: u8,
        sort_key: &[u8],
        value: Option<Vec<u8>>,
    ) -> Self {
        // Format: hash_prefix (20) + node_id (30) + partition (1) + sort_key
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + sort_key.len());
        storage_key.extend_from_slice(&[0u8; 20]); // Dummy hash prefix
        storage_key.extend_from_slice(&node_id.0); // Node ID
        storage_key.push(partition); // Partition number
        storage_key.extend_from_slice(sort_key); // Sort key
        Self::new(storage_key, value)
    }
}

/// Per-tx provision view used inside the execution path.
///
/// Built from a [`crate::Provisions`] bundle when it lands at the execution
/// coordinator: each `ProvisionEntry` in the bundle becomes one `StateProvision`
/// keyed to the tx, carrying the bundle's source/target shard and block
/// height alongside the tx's slice of state entries. Not on the wire.
#[derive(Debug, Clone)]
pub struct StateProvision {
    transaction_hash: TxHash,
    target_shard: ShardGroupId,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    entries: Arc<Vec<SubstateEntry>>,
}

impl StateProvision {
    /// Build a `StateProvision` from its parts.
    #[must_use]
    pub const fn new(
        transaction_hash: TxHash,
        target_shard: ShardGroupId,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        entries: Arc<Vec<SubstateEntry>>,
    ) -> Self {
        Self {
            transaction_hash,
            target_shard,
            source_shard,
            block_height,
            entries,
        }
    }

    /// Hash of the transaction this provision is for.
    #[must_use]
    pub const fn transaction_hash(&self) -> TxHash {
        self.transaction_hash
    }

    /// Target shard (the shard executing the transaction).
    #[must_use]
    pub const fn target_shard(&self) -> ShardGroupId {
        self.target_shard
    }

    /// Source shard (the shard providing the state).
    #[must_use]
    pub const fn source_shard(&self) -> ShardGroupId {
        self.source_shard
    }

    /// Block height when this provision was created (anchors merkle proofs).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// The state entries with pre-computed storage keys.
    #[must_use]
    pub const fn entries(&self) -> &Arc<Vec<SubstateEntry>> {
        &self.entries
    }
}

impl PartialEq for StateProvision {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash == other.transaction_hash
            && self.target_shard == other.target_shard
            && self.source_shard == other.source_shard
            && self.block_height == other.block_height
            && *self.entries == *other.entries
    }
}

impl Eq for StateProvision {}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    #[test]
    fn test_substate_entry_hash() {
        let entry =
            SubstateEntry::test_entry(NodeId([1u8; 30]), 0, b"key", Some(b"value".to_vec()));

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sbor_roundtrip_some_value() {
        let entry = SubstateEntry::test_entry(NodeId([7u8; 30]), 3, b"sort", Some(vec![9u8; 128]));
        let bytes = basic_encode(&entry).unwrap();
        let decoded: SubstateEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn sbor_roundtrip_none_value() {
        let entry = SubstateEntry::test_entry(NodeId([7u8; 30]), 3, b"sort", None);
        let bytes = basic_encode(&entry).unwrap();
        let decoded: SubstateEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// Encode an oversized `storage_key` directly (without going through
    /// `SubstateEntry::Encode`) and verify decode rejects it before allocation.
    #[test]
    fn decode_rejects_oversized_storage_key() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_STATE_ENTRY_KEY_LEN + 1).unwrap();
        let err = basic_decode::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRY_KEY_LEN,
                actual,
            } if actual == MAX_STATE_ENTRY_KEY_LEN + 1
        ));
    }

    /// Same shape as above, but for the `Some(value)` byte-vector field.
    #[test]
    fn decode_rejects_oversized_value() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        // Empty storage_key is fine; the bound check we want fires on `value`.
        enc.encode(&Vec::<u8>::new()).unwrap();
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(1).unwrap();
        enc.write_size(1).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_STATE_ENTRY_VALUE_LEN + 1).unwrap();
        let err = basic_decode::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRY_VALUE_LEN,
                actual,
            } if actual == MAX_STATE_ENTRY_VALUE_LEN + 1
        ));
    }
}
