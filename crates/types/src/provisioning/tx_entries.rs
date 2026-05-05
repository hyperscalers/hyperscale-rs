//! Per-transaction state entries within a provision.

use std::collections::HashSet;

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{MAX_DECLARED_NODES_PER_TX, MAX_STATE_ENTRIES_PER_TX, NodeId, StateEntry, TxHash};

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction, what state it touched on the source shard,
/// and what nodes it needs from the target shard (for conflict detection).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    #[must_use]
    pub fn node_ids(&self) -> HashSet<NodeId> {
        self.entries
            .iter()
            .filter_map(StateEntry::node_id)
            .collect()
    }
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for TxEntries {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(&self.entries)?;
        encoder.encode(&self.target_nodes)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for TxEntries {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let tx_hash: TxHash = decoder.decode()?;
        let entries = decode_bounded_vec::<_, StateEntry>(decoder, MAX_STATE_ENTRIES_PER_TX)?;
        let target_nodes = decode_bounded_vec::<_, NodeId>(decoder, MAX_DECLARED_NODES_PER_TX)?;
        Ok(Self {
            tx_hash,
            entries,
            target_nodes,
        })
    }
}

impl Categorize<NoCustomValueKind> for TxEntries {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for TxEntries {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("TxEntries", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

/// Decode a `Vec<T>` while rejecting peer-claimed lengths above `max_len`
/// before any allocation.
fn decode_bounded_vec<D, T>(decoder: &mut D, max_len: usize) -> Result<Vec<T>, DecodeError>
where
    D: Decoder<NoCustomValueKind>,
    T: Categorize<NoCustomValueKind> + Decode<NoCustomValueKind, D>,
{
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    let element_kind = decoder.read_and_check_value_kind(T::value_kind())?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    // Cap the with_capacity hint so a peer-claimed huge `len` can't
    // pre-allocate before the decode loop short-circuits on missing data.
    let mut out = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        out.push(decoder.decode_deeper_body_with_value_kind(element_kind)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
    };

    use super::*;
    use crate::Hash;

    fn sample_entry(seed: u8) -> StateEntry {
        StateEntry::test_entry(NodeId([seed; 30]), 0, b"sort", Some(vec![seed]))
    }

    #[test]
    fn sbor_roundtrip() {
        let tx_entries = TxEntries {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx")),
            entries: vec![sample_entry(1), sample_entry(2)],
            target_nodes: vec![NodeId([3u8; 30]), NodeId([4u8; 30])],
        };
        let bytes = basic_encode(&tx_entries).unwrap();
        let decoded: TxEntries = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, tx_entries);
    }

    #[test]
    fn decode_rejects_oversized_entries() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(StateEntry::value_kind()).unwrap();
        enc.write_size(MAX_STATE_ENTRIES_PER_TX + 1).unwrap();
        let err = basic_decode::<TxEntries>(&buf).unwrap_err();
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
        enc.write_size(3).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.encode(&Vec::<StateEntry>::new()).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(NodeId::value_kind()).unwrap();
        enc.write_size(MAX_DECLARED_NODES_PER_TX + 1).unwrap();
        let err = basic_decode::<TxEntries>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DECLARED_NODES_PER_TX,
                actual,
            } if actual == MAX_DECLARED_NODES_PER_TX + 1
        ));
    }
}
