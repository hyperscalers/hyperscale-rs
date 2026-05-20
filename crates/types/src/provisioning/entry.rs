//! Per-transaction state entries within a provision.

use std::collections::HashSet;

use sbor::prelude::*;

use crate::{
    BoundedVec, MAX_DECLARED_NODES_PER_TX, MAX_OWNED_NODES_PER_TX, MAX_STATE_ENTRIES_PER_TX,
    NodeId, SubstateEntry, TxHash,
};

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction, what state it touched on the source shard,
/// and what nodes it needs from the target shard (for conflict detection).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ProvisionEntry {
    /// Hash of the transaction.
    pub tx_hash: TxHash,

    /// The state entries this transaction touched on the source shard.
    pub entries: BoundedVec<SubstateEntry, MAX_STATE_ENTRIES_PER_TX>,

    /// Node IDs this transaction needs from the target shard.
    ///
    /// Used for bidirectional conflict detection: a true deadlock requires
    /// overlap in both directions (source nodes vs local needs, AND target
    /// nodes vs local owns).
    pub target_nodes: BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX>,

    /// Authoritative `(internal_node, owning_account)` pairs the source
    /// shard resolved for this transaction's declared accounts at
    /// `block_height`.
    ///
    /// Receivers consume this directly during cross-shard execution
    /// instead of rediscovering ownership by walking a possibly-partial
    /// merged view. Encoded in canonical key order so two source nodes
    /// resolving the same accounts produce byte-equal payloads.
    pub owned_nodes: BoundedVec<(NodeId, NodeId), MAX_OWNED_NODES_PER_TX>,
}

impl ProvisionEntry {
    /// Build a `ProvisionEntry` from raw `Vec`s — wraps each in its bounded type.
    #[must_use]
    pub fn new(
        tx_hash: TxHash,
        entries: Vec<SubstateEntry>,
        target_nodes: Vec<NodeId>,
        owned_nodes: Vec<(NodeId, NodeId)>,
    ) -> Self {
        Self {
            tx_hash,
            entries: entries.into(),
            target_nodes: target_nodes.into(),
            owned_nodes: owned_nodes.into(),
        }
    }

    /// Get the node IDs referenced by this transaction's entries.
    #[must_use]
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries
            .iter()
            .filter_map(SubstateEntry::node_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize as _, DecodeError,
        Encoder as _, NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::Hash;

    fn sample_entry(seed: u8) -> SubstateEntry {
        SubstateEntry::test_entry(NodeId([seed; 30]), 0, b"sort", Some(vec![seed]))
    }

    #[test]
    fn sbor_roundtrip() {
        let entry = ProvisionEntry::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            vec![sample_entry(1), sample_entry(2)],
            vec![NodeId([3u8; 30]), NodeId([4u8; 30])],
            vec![(NodeId([5u8; 30]), NodeId([3u8; 30]))],
        );
        let bytes = basic_encode(&entry).unwrap();
        let decoded: ProvisionEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn decode_rejects_oversized_entries() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(4).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(SubstateEntry::value_kind()).unwrap();
        enc.write_size(MAX_STATE_ENTRIES_PER_TX + 1).unwrap();
        let err = basic_decode::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRIES_PER_TX,
                actual,
            } if actual == MAX_STATE_ENTRIES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_target_nodes() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(4).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.encode(&Vec::<SubstateEntry>::new()).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(NodeId::value_kind()).unwrap();
        enc.write_size(MAX_DECLARED_NODES_PER_TX + 1).unwrap();
        let err = basic_decode::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DECLARED_NODES_PER_TX,
                actual,
            } if actual == MAX_DECLARED_NODES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_owned_nodes() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(4).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.encode(&Vec::<SubstateEntry>::new()).unwrap();
        enc.encode(&Vec::<NodeId>::new()).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(<(NodeId, NodeId)>::value_kind())
            .unwrap();
        enc.write_size(MAX_OWNED_NODES_PER_TX + 1).unwrap();
        let err = basic_decode::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_OWNED_NODES_PER_TX,
                actual,
            } if actual == MAX_OWNED_NODES_PER_TX + 1
        ));
    }
}
