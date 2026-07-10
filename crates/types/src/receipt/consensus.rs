//! Consensus-bound portion of an executed transaction's output.
//!
//! [`ConsensusReceipt`] is the part of an execution result that is
//! hash-stable, signed over by the receipt root, and transferable across
//! peers. The local-only portion (logs, errors, fees) lives separately in
//! [`ExecutionMetadata`](crate::ExecutionMetadata) — a node that received a
//! receipt via sync rather than by executing has the consensus part but
//! not the local metadata.
//!
//! The variant tag IS the outcome — there's no separate `Success/Failure`
//! flag and no zero-padded `database_updates`/`application_events` for
//! failed transactions.

use std::sync::LazyLock;

use radix_substate_store_interface::interface::PartitionDatabaseUpdates;
use sbor::prelude::basic_encode;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::sbor_codec::decode_bounded_vec;
use crate::{
    ApplicationEvent, BeaconWitnessEvent, BeaconWitnessRoot, BoundedVec, DatabaseUpdates,
    EventRoot, GlobalReceipt, GlobalReceiptHash, Hash, MAX_BEACON_WITNESS_EVENTS_PER_TX,
    MAX_OWNED_NODES_PER_TX, NodeId, OwnershipRoot, WritesRoot, compute_merkle_root,
};

/// Cap on `ConsensusReceipt::Succeeded.application_events` count at decode
/// time. Each event is bounded internally
/// (`MAX_APPLICATION_EVENT_FIELD_LEN`); this cap bounds how many a peer
/// can claim per receipt before iteration begins. Real receipts emit a
/// handful of events; 4096 is far above any legitimate workload and
/// rejects obviously oversized arrivals before allocation.
const MAX_APPLICATION_EVENTS_PER_TX: usize = 4_096;

// Variant tag bytes for SBOR encoding. Explicit rather than relying on
// derive so future additions don't renumber existing variants silently.
const RECEIPT_VARIANT_SUCCEEDED: u8 = 0;
const RECEIPT_VARIANT_FAILED: u8 = 1;

/// Canonical receipt hash for any failed transaction.
///
/// All failed transactions hash to the same value — derived from the fixed
/// `(success=false, EventRoot::ZERO, BeaconWitnessRoot::ZERO, WritesRoot::ZERO)`
/// tuple. Cached to avoid recomputing per failure.
pub static FAILED_RECEIPT_HASH: LazyLock<GlobalReceiptHash> = LazyLock::new(|| {
    GlobalReceipt::new(
        false,
        EventRoot::ZERO,
        BeaconWitnessRoot::ZERO,
        WritesRoot::ZERO,
        OwnershipRoot::ZERO,
    )
    .receipt_hash()
});

/// The consensus-bound portion of an execution result.
///
/// `Succeeded` carries the shard-filtered database updates and events
/// produced by the transaction, the beacon-witness events the engine
/// surfaced for the shard's accumulator, plus the precomputed
/// `receipt_hash` (which depends on a `writes_root` derived from
/// globally-filtered updates not stored here). `Failed` carries no
/// payload — every failure is consensus-equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusReceipt {
    /// Engine committed the tx; carries the precomputed receipt hash and
    /// the writes/events the local shard needs.
    Succeeded {
        /// Precomputed [`GlobalReceiptHash`] — cannot be recomputed from
        /// this variant alone, since it folds in `writes_root` derived
        /// from globally-filtered (not shard-filtered) updates that
        /// aren't carried here.
        receipt_hash: GlobalReceiptHash,
        /// Substate writes filtered to the local shard. The global
        /// `writes_root` on `receipt_hash` covers writes for all shards;
        /// this field is only what the local shard needs to apply.
        database_updates: DatabaseUpdates,
        /// `(internal_node, owning_global_ancestor)` pairs for the
        /// internal nodes (vaults, KV stores) appearing in
        /// `database_updates`. The JMT build owner-prefixes those nodes'
        /// leaves under their owner so the shard stays a clean prefix
        /// subtree; shipping the map (rather than rediscovering it at
        /// commit) keeps the keying identical on executor, verifier, and
        /// syncer. Canonical key order. Globals are absent (they key
        /// under themselves).
        owned_nodes: BoundedVec<(NodeId, NodeId), MAX_OWNED_NODES_PER_TX>,
        /// Identical across shards for the same tx — events come from
        /// user logic, which sees the same merged state on every shard.
        application_events: Vec<ApplicationEvent>,
        /// Beacon-witness events the engine surfaced for this tx. Folded
        /// into the shard's beacon-witness accumulator at block-assembly
        /// time; the root of those events is bound into `receipt_hash`
        /// via [`GlobalReceipt::beacon_witness_root`].
        beacon_witness_events: Vec<BeaconWitnessEvent>,
    },
    /// All failures collapse to one variant — the canonical
    /// [`FAILED_RECEIPT_HASH`] is derived at hash time, no payload needed.
    Failed,
}

/// True if any partition update in `updates` is a
/// [`PartitionDatabaseUpdates::Reset`].
///
/// Receipt updates are Delta-only. The engine's sole runtime Reset
/// producer — the transaction-tracker partition cycle — targets a system
/// entity that shard filtering drops, and genesis flash (which does carry
/// Resets) never flows through receipts. Storage relies on the invariant:
/// the JMT commit paths and the pending-chain overlay apply receipt
/// updates without enumerating a partition's pre-existing keys, which a
/// Reset over a non-empty partition would require to stay consistent
/// across the live and sync paths. [`ConsensusReceipt`] decode enforces
/// it on every receipt taken off the wire;
/// `hyperscale_engine::project_to_shard` asserts it at receipt build.
#[must_use]
pub fn has_partition_reset(updates: &DatabaseUpdates) -> bool {
    updates.node_updates.values().any(|node| {
        node.partition_updates
            .values()
            .any(|p| matches!(p, PartitionDatabaseUpdates::Reset { .. }))
    })
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for ConsensusReceipt {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Enum)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Self::Succeeded {
                receipt_hash,
                database_updates,
                owned_nodes,
                application_events,
                beacon_witness_events,
            } => {
                encoder.write_discriminator(RECEIPT_VARIANT_SUCCEEDED)?;
                encoder.write_size(5)?;
                encoder.encode(receipt_hash)?;
                encoder.encode(database_updates)?;
                encoder.encode(owned_nodes)?;
                encoder.encode(application_events)?;
                encoder.encode(beacon_witness_events)?;
            }
            Self::Failed => {
                encoder.write_discriminator(RECEIPT_VARIANT_FAILED)?;
                encoder.write_size(0)?;
            }
        }
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for ConsensusReceipt {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Enum)?;
        let discriminator = decoder.read_discriminator()?;
        let length = decoder.read_size()?;
        match discriminator {
            RECEIPT_VARIANT_SUCCEEDED => {
                if length != 5 {
                    return Err(DecodeError::UnexpectedSize {
                        expected: 5,
                        actual: length,
                    });
                }
                let receipt_hash: GlobalReceiptHash = decoder.decode()?;
                let database_updates: DatabaseUpdates = decoder.decode()?;
                // Receipt updates are Delta-only (see `has_partition_reset`);
                // a Reset here is a corrupt peer or a forged receipt.
                if has_partition_reset(&database_updates) {
                    return Err(DecodeError::InvalidCustomValue);
                }
                let owned_nodes: BoundedVec<(NodeId, NodeId), MAX_OWNED_NODES_PER_TX> =
                    decoder.decode()?;
                let application_events = decode_bounded_vec::<_, ApplicationEvent>(
                    decoder,
                    MAX_APPLICATION_EVENTS_PER_TX,
                )?;
                let beacon_witness_events = decode_bounded_vec::<_, BeaconWitnessEvent>(
                    decoder,
                    MAX_BEACON_WITNESS_EVENTS_PER_TX,
                )?;
                Ok(Self::Succeeded {
                    receipt_hash,
                    database_updates,
                    owned_nodes,
                    application_events,
                    beacon_witness_events,
                })
            }
            RECEIPT_VARIANT_FAILED => {
                if length != 0 {
                    return Err(DecodeError::UnexpectedSize {
                        expected: 0,
                        actual: length,
                    });
                }
                Ok(Self::Failed)
            }
            other => Err(DecodeError::UnknownDiscriminator(other)),
        }
    }
}

impl Categorize<NoCustomValueKind> for ConsensusReceipt {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Enum
    }
}

impl Describe<NoCustomTypeKind> for ConsensusReceipt {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("ConsensusReceipt", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

impl ConsensusReceipt {
    /// The consensus receipt hash. For [`Self::Failed`] this is the
    /// canonical [`FAILED_RECEIPT_HASH`].
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        match self {
            Self::Succeeded { receipt_hash, .. } => *receipt_hash,
            Self::Failed => *FAILED_RECEIPT_HASH,
        }
    }

    /// Whether the transaction committed successfully.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    /// The shard-filtered database updates, or `None` for `Failed`
    /// (failed transactions produce no writes).
    #[must_use]
    pub const fn database_updates(&self) -> Option<&DatabaseUpdates> {
        match self {
            Self::Succeeded {
                database_updates, ..
            } => Some(database_updates),
            Self::Failed => None,
        }
    }

    /// The `(internal_node, owning_global_ancestor)` pairs for the internal
    /// nodes in this receipt's `database_updates`, or empty for `Failed`.
    ///
    /// The JMT build merges these across a block's receipts to owner-prefix
    /// each internal node's leaf.
    #[must_use]
    pub fn owned_nodes(&self) -> &[(NodeId, NodeId)] {
        match self {
            Self::Succeeded { owned_nodes, .. } => &owned_nodes.0,
            Self::Failed => &[],
        }
    }

    /// Per-shard receipt hash used as a leaf in `local_receipt_root`.
    ///
    /// Hashes `outcome_byte || event_root || database_updates_hash ||
    /// owned_nodes_hash`. Folding the ownership map binds the keying used
    /// for this shard's owner-prefixed leaves into the block's
    /// `local_receipt_root`. `Failed` produces the same hash as a
    /// no-write/no-event/no-ownership failure.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of `database_updates` or `owned_nodes`
    /// fails — both are closed SBOR types and encoding is infallible in
    /// practice.
    #[must_use]
    pub fn local_receipt_hash(&self) -> Hash {
        let (outcome_byte, event_root, database_updates, owned_nodes) = match self {
            Self::Succeeded {
                database_updates,
                owned_nodes,
                application_events,
                ..
            } => {
                let event_hashes: Vec<Hash> = application_events
                    .iter()
                    .map(ApplicationEvent::hash)
                    .collect();
                let event_root = compute_merkle_root(&event_hashes);
                (
                    [1u8],
                    event_root,
                    database_updates.clone(),
                    owned_nodes.clone(),
                )
            }
            Self::Failed => (
                [0u8],
                Hash::ZERO,
                DatabaseUpdates::default(),
                BoundedVec::new(),
            ),
        };
        let updates_bytes = basic_encode(&database_updates).expect("encode should not fail");
        let updates_hash = Hash::from_bytes(&updates_bytes);
        let owned_bytes = basic_encode(&owned_nodes).expect("encode should not fail");
        let owned_hash = Hash::from_bytes(&owned_bytes);
        Hash::from_parts(&[
            &outcome_byte,
            event_root.as_bytes(),
            updates_hash.as_bytes(),
            owned_hash.as_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use sbor::prelude::basic_decode;
    use sbor::{BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder};

    use super::*;
    use crate::EventData;
    use crate::test_utils::test_event_type_identifier;

    fn sample_succeeded() -> ConsensusReceipt {
        ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")),
            database_updates: DatabaseUpdates::default(),
            owned_nodes: BoundedVec::new(),
            application_events: vec![ApplicationEvent {
                type_id: test_event_type_identifier(1),
                data: EventData(vec![4, 5, 6]),
            }],
            beacon_witness_events: Vec::new(),
        }
    }

    #[test]
    fn sbor_roundtrip_succeeded() {
        let receipt = sample_succeeded();
        let bytes = basic_encode(&receipt).unwrap();
        let decoded: ConsensusReceipt = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn sbor_roundtrip_failed() {
        let receipt = ConsensusReceipt::Failed;
        let bytes = basic_encode(&receipt).unwrap();
        let decoded: ConsensusReceipt = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, receipt);
    }

    /// Hand-roll a `Succeeded` payload whose `application_events` count
    /// exceeds the cap and verify decode rejects it before iterating.
    #[test]
    fn decode_rejects_oversized_application_events() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(RECEIPT_VARIANT_SUCCEEDED).unwrap();
        enc.write_size(5).unwrap();
        enc.encode(&GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")))
            .unwrap();
        enc.encode(&DatabaseUpdates::default()).unwrap();
        enc.encode(&BoundedVec::<(NodeId, NodeId), MAX_OWNED_NODES_PER_TX>::new())
            .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ApplicationEvent::value_kind())
            .unwrap();
        enc.write_size(MAX_APPLICATION_EVENTS_PER_TX + 1).unwrap();
        let err = basic_decode::<ConsensusReceipt>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_APPLICATION_EVENTS_PER_TX,
                actual,
            } if actual == MAX_APPLICATION_EVENTS_PER_TX + 1
        ));
    }

    /// Hand-roll a `Succeeded` payload whose `beacon_witness_events`
    /// count exceeds the cap and verify decode rejects it before
    /// iterating. Mirrors the application-events bound check.
    #[test]
    fn decode_rejects_oversized_beacon_witness_events() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(RECEIPT_VARIANT_SUCCEEDED).unwrap();
        enc.write_size(5).unwrap();
        enc.encode(&GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")))
            .unwrap();
        enc.encode(&DatabaseUpdates::default()).unwrap();
        enc.encode(&BoundedVec::<(NodeId, NodeId), MAX_OWNED_NODES_PER_TX>::new())
            .unwrap();
        enc.encode(&Vec::<ApplicationEvent>::new()).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(BeaconWitnessEvent::value_kind())
            .unwrap();
        enc.write_size(MAX_BEACON_WITNESS_EVENTS_PER_TX + 1)
            .unwrap();
        let err = basic_decode::<ConsensusReceipt>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_BEACON_WITNESS_EVENTS_PER_TX,
                actual,
            } if actual == MAX_BEACON_WITNESS_EVENTS_PER_TX + 1
        ));
    }

    /// A `Succeeded` receipt whose `database_updates` carries a partition
    /// Reset encodes (the encoder is symmetric) but must not decode —
    /// storage applies receipt updates without enumerating pre-existing
    /// keys, so a Reset would silently diverge the live and sync JMT roots.
    #[test]
    fn decode_rejects_partition_reset_updates() {
        use radix_substate_store_interface::interface::NodeDatabaseUpdates;
        use sbor::prelude::index_map_new;

        let mut node = NodeDatabaseUpdates::default();
        node.partition_updates.insert(
            0u8,
            PartitionDatabaseUpdates::Reset {
                new_substate_values: index_map_new(),
            },
        );
        let mut database_updates = DatabaseUpdates::default();
        database_updates.node_updates.insert(vec![1u8; 50], node);
        assert!(has_partition_reset(&database_updates));

        let receipt = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")),
            database_updates,
            owned_nodes: BoundedVec::new(),
            application_events: Vec::new(),
            beacon_witness_events: Vec::new(),
        };
        let bytes = basic_encode(&receipt).unwrap();
        let err = basic_decode::<ConsensusReceipt>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidCustomValue));
    }

    #[test]
    fn decode_rejects_unknown_discriminator() {
        let mut buf = Vec::with_capacity(8);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(99).unwrap();
        enc.write_size(0).unwrap();
        let err = basic_decode::<ConsensusReceipt>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::UnknownDiscriminator(99)));
    }
}
