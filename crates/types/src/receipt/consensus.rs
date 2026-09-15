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
//! flag and no zero-padded `writes`/`events` for failed transactions.

use std::sync::LazyLock;

use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder as HborDecoder, Encoder as HborEncoder, HborDecode, HborEncode, HborWidth, Sink,
    bounded as hbor_bounded, to_vec as hbor_to_vec,
};

use crate::receipt::event::EventExt;
use crate::transaction::vm::Derivation;
use crate::{
    BeaconWitnessEvent, BeaconWitnessRoot, Event, EventRoot, GlobalReceipt, GlobalReceiptHash,
    Hash, MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_EVENTS_PER_TX, StateWrites, WritesRoot,
    compute_merkle_root,
};

// Wire variant tag bytes. Explicit rather than relying on declaration
// order so future additions don't renumber existing variants silently.
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
    )
    .receipt_hash()
});

/// The consensus-bound portion of an execution result.
///
/// `Succeeded` carries the shard-filtered writes and events produced by
/// the transaction, the beacon-witness events the engine surfaced for
/// the shard's accumulator, plus the precomputed `receipt_hash`.
/// `Failed` carries no payload — every failure is consensus-equivalent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusReceipt {
    /// Engine committed the tx; carries the precomputed receipt hash and
    /// the writes/events the local shard needs.
    Succeeded {
        /// Precomputed [`GlobalReceiptHash`] — cannot be recomputed from
        /// this variant alone: under whole locality its writes root can
        /// cover more than the local slice.
        receipt_hash: GlobalReceiptHash,
        /// Substate writes filtered to the local shard — what this shard
        /// applies at settlement. For a cross-shard member this is also
        /// exactly what the `receipt_hash` writes root covers, since the
        /// delta is projected to the executing shard before hashing.
        writes: StateWrites,
        /// Beacon-witness events the engine surfaced for this tx. Folded
        /// into the shard's beacon-witness accumulator at block-assembly
        /// time; the root of those events is bound into `receipt_hash`
        /// via [`GlobalReceipt::beacon_witness_root`].
        beacon_witness_events: Vec<BeaconWitnessEvent>,
        /// Events whose emitting instance lives on this shard — and
        /// exactly what `receipt_hash` commits to through
        /// [`GlobalReceipt::event_root`]. These differ per shard by
        /// design: an event is stored where its emitter lives, and each
        /// shard attests its own.
        events: Vec<Event>,
    },
    /// All failures collapse to one variant — the canonical
    /// [`FAILED_RECEIPT_HASH`] is derived at hash time, no payload needed.
    Failed,
}

/// Offer every cell these committed receipts write to this node's
/// `derivation`, so its caches grow with the chain.
///
/// Called on both the live commit path and the sync path, which is the
/// point: a block's receipts are block content, so a replica that
/// replayed the block reaches the same cache as one that executed it.
/// Receipts are also the only thing that moves state, so nothing a
/// package cell could arrive through is missed here.
pub fn absorb_committed_cells<'a>(
    receipts: impl IntoIterator<Item = &'a ConsensusReceipt>,
    derivation: &dyn Derivation,
) {
    for receipt in receipts {
        let ConsensusReceipt::Succeeded { writes, .. } = receipt else {
            continue;
        };
        for (key, change) in &writes.cells {
            if let Some(value) = change {
                derivation.absorb_committed_cell(key.owner.to_bytes(), key.local.0, value);
            }
        }
    }
}

impl HborWidth for ConsensusReceipt {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for ConsensusReceipt {
    fn encode<S: Sink>(&self, encoder: &mut HborEncoder<S>) -> Result<(), HborEncodeError> {
        match self {
            Self::Succeeded {
                receipt_hash,
                writes,
                beacon_witness_events,
                events,
            } => {
                encoder.write_u8(RECEIPT_VARIANT_SUCCEEDED);
                encoder.nested(receipt_hash)?;
                encoder.nested(writes)?;
                hbor_bounded::check_encoded_len(
                    "beacon_witness_events",
                    beacon_witness_events.len(),
                    MAX_BEACON_WITNESS_EVENTS_PER_TX,
                )?;
                encoder.nested(beacon_witness_events)?;
                hbor_bounded::check_encoded_len("events", events.len(), MAX_EVENTS_PER_TX)?;
                encoder.nested(events)
            }
            Self::Failed => {
                encoder.write_u8(RECEIPT_VARIANT_FAILED);
                Ok(())
            }
        }
    }
}

impl HborDecode for ConsensusReceipt {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        match decoder.read_u8()? {
            RECEIPT_VARIANT_SUCCEEDED => {
                let receipt_hash: GlobalReceiptHash = decoder.nested()?;
                let writes: StateWrites = decoder.nested()?;
                let beacon_witness_events: Vec<BeaconWitnessEvent> =
                    decoder.descend(|decoder| {
                        hbor_bounded::decode_bounded_vec(decoder, MAX_BEACON_WITNESS_EVENTS_PER_TX)
                    })?;
                let events: Vec<Event> = decoder.descend(|decoder| {
                    hbor_bounded::decode_bounded_vec(decoder, MAX_EVENTS_PER_TX)
                })?;
                Ok(Self::Succeeded {
                    receipt_hash,
                    writes,
                    beacon_witness_events,
                    events,
                })
            }
            RECEIPT_VARIANT_FAILED => Ok(Self::Failed),
            other => Err(HborDecodeError::InvalidDiscriminant(other)),
        }
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

    /// The shard-filtered writes, or `None` for `Failed` (failed
    /// transactions produce no writes).
    #[must_use]
    pub const fn writes(&self) -> Option<&StateWrites> {
        match self {
            Self::Succeeded { writes, .. } => Some(writes),
            Self::Failed => None,
        }
    }

    /// Per-shard receipt hash used as a leaf in `local_receipt_root`.
    ///
    /// Hashes `outcome_byte || event_root || writes_hash` over what this
    /// shard keeps: its own writes and the events whose emitters it
    /// owns. `Failed` produces the same hash as a no-write/no-event
    /// failure.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding of `writes` fails — it is a closed wire
    /// type and encoding is infallible in practice.
    #[must_use]
    pub(crate) fn local_receipt_hash(&self) -> Hash {
        let (outcome_byte, event_root, writes) = match self {
            Self::Succeeded { writes, events, .. } => {
                let event_hashes: Vec<Hash> = events.iter().map(EventExt::hash).collect();
                ([1u8], compute_merkle_root(&event_hashes), writes.clone())
            }
            Self::Failed => ([0u8], Hash::ZERO, StateWrites::default()),
        };
        let writes_bytes = hbor_to_vec(&writes).expect("encode should not fail");
        let writes_hash = Hash::from_bytes(&writes_bytes);
        Hash::from_parts(&[&outcome_byte, event_root.as_bytes(), writes_hash.as_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint};
    use hyperscale_vm_types::Address;

    use super::*;
    use crate::AddressClass;

    fn sample_succeeded() -> ConsensusReceipt {
        ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")),
            writes: StateWrites::default(),
            beacon_witness_events: Vec::new(),
            events: vec![Event {
                emitter: Address::new([7; 31], AddressClass::Component),
                event_type: 1,
                payload: vec![4, 5, 6],
            }],
        }
    }

    #[test]
    fn hbor_roundtrip_succeeded() {
        let receipt = sample_succeeded();
        let bytes = hbor_to_vec(&receipt).unwrap();
        let decoded: ConsensusReceipt = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn hbor_roundtrip_failed() {
        let receipt = ConsensusReceipt::Failed;
        let bytes = hbor_to_vec(&receipt).unwrap();
        let decoded: ConsensusReceipt = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, receipt);
    }

    /// Hand-roll a `Succeeded` payload whose `beacon_witness_events`
    /// count exceeds the cap and verify decode rejects it before
    /// iterating.
    #[test]
    fn decode_rejects_oversized_beacon_witness_events() {
        let mut buf = vec![RECEIPT_VARIANT_SUCCEEDED];
        buf.extend_from_slice(
            &hbor_to_vec(&GlobalReceiptHash::from_raw(Hash::from_bytes(b"r"))).unwrap(),
        );
        buf.extend_from_slice(&hbor_to_vec(&StateWrites::default()).unwrap());
        varint::write(&mut buf, MAX_BEACON_WITNESS_EVENTS_PER_TX + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_BEACON_WITNESS_EVENTS_PER_TX + 1) * 64,
        ));
        let err = hbor_from_slice::<ConsensusReceipt>(&buf).unwrap_err();
        assert!(matches!(
            err,
            HborDecodeError::BoundExceeded { max, actual }
                if max == MAX_BEACON_WITNESS_EVENTS_PER_TX
                    && actual == MAX_BEACON_WITNESS_EVENTS_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_unknown_discriminator() {
        let buf = [99u8];
        let err = hbor_from_slice::<ConsensusReceipt>(&buf).unwrap_err();
        assert!(matches!(err, HborDecodeError::InvalidDiscriminant(99)));
    }
}
