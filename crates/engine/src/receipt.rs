//! The engine's execution output and its per-shard projection.
//!
//! Receipt projection runs in two stages:
//!
//! - the engine turns its own receipt into a [`CachedOutput`], whose
//!   receipt hash binds the beacon facts the executing shard keeps. For
//!   a batch with cross-shard members the writes and the event root
//!   carry that shard's projection too.
//! - [`project_to_shard`] consumes the cached output and a target shard
//!   to produce the final [`ExecutedTx`]. Only the `writes` slice, the
//!   events, and the beacon facts are shard-specific — a no-op on
//!   writes the executor already projected.

use hyperscale_hbor::{Capped, to_vec as hbor_to_vec};
use hyperscale_types::{
    Address, BeaconWitnessEvent, BeaconWitnessRoot, ConsensusReceipt, Event, EventExt, EventRoot,
    ExecutionMetadata, GlobalReceipt, GlobalReceiptHash, Hash, ShardId, ShardTrie, StateWrites,
    TxHash, compute_merkle_root,
};

use crate::output::ExecutedTx;
use crate::sharding::{filter_writes_for_shard, owned_by, writes_root};

/// Domain tag separating a receipt's beacon-fact leaf from every other
/// leaf preimage the codebase hashes.
const RECEIPT_WITNESS_LEAF_TAG: &[u8] = b"hyperscale.receipt_witness_leaf.v1";

/// The witness root for a [`GlobalReceipt`] over the beacon facts a
/// receipt carries, in the order it carries them: one leaf per fact, the
/// tag and the fact's canonical encoding. No facts commit to
/// [`BeaconWitnessRoot::ZERO`].
///
/// A receipt's own commitment, and nothing a header states: a block's
/// witness root is taken over the shard's whole window, under another
/// leaf.
///
/// # Panics
///
/// If a fact does not encode, which a closed wire type always does.
pub fn witness_root<'a>(
    facts: impl IntoIterator<Item = &'a BeaconWitnessEvent>,
) -> BeaconWitnessRoot {
    let leaves: Vec<Hash> = facts
        .into_iter()
        .map(|fact| {
            let bytes = hbor_to_vec(fact).expect("a beacon fact encodes");
            Hash::from_parts(&[RECEIPT_WITNESS_LEAF_TAG, &bytes])
        })
        .collect();
    BeaconWitnessRoot::from_raw(compute_merkle_root(&leaves))
}

/// A receipt's hash, recomputed from what the receipt carries.
///
/// `projected` is whether the batch that produced the receipt hashed
/// under this shard's own locality, which a batch with a member reaching
/// beyond the shard does and which the receipt does not record. Its
/// writes, events and beacon facts are then exactly what the three roots
/// were taken over, so the answer is the hash a quorum signed for an
/// honest receipt and some other hash for one altered since.
///
/// `None` for a success hashed under whole locality: its writes root can
/// cover more than the slice the receipt holds. Every failure is the one
/// canonical hash, whatever it ran under.
#[must_use]
pub fn receipt_hash_of(receipt: &ConsensusReceipt, projected: bool) -> Option<GlobalReceiptHash> {
    let ConsensusReceipt::Succeeded {
        writes,
        beacon_witness_events,
        events,
        ..
    } = receipt
    else {
        return Some(receipt.receipt_hash());
    };
    projected.then(|| {
        let event_hashes: Vec<Hash> = events.iter().map(EventExt::hash).collect();
        GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            witness_root(beacon_witness_events.iter()),
            writes_root(writes),
        )
        .receipt_hash()
    })
}

/// Cached projection of an execution receipt.
///
/// Carries everything needed to assemble an [`ExecutedTx`], for the
/// shard that executed: the receipt hash binds the beacon facts that
/// shard keeps, and under owned locality the writes and the event root
/// are its own as well.
/// The per-shard writes slice is *not* cached — it's re-derived per
/// call from `raw_writes` via [`project_to_shard`].
pub struct CachedOutput {
    metadata: ExecutionMetadata,
    body: CachedOutputBody,
}

#[allow(clippy::large_enum_variant)] // Succeeded is the common case; boxing penalises every hit
enum CachedOutputBody {
    /// A per-transaction abort, or a transaction that never reached the
    /// engine.
    Failed,
    /// A committed success: the folded absolute writes and the receipt
    /// hash over their canonical encoding.
    Succeeded {
        raw_writes: StateWrites,
        /// Events in emission order, unfiltered: the projection picks
        /// each shard's own by the emitter's home, and the event root
        /// covers the whole union.
        events: Vec<Event>,
        receipt_hash: GlobalReceiptHash,
        /// Beacon facts lifted from a recognised stake pool's events,
        /// each beside the emitter that produced it.
        ///
        /// A pair rather than an anchor node, because an emitter is a
        /// substate prefix: which shard keeps the fact is the same
        /// question — and the same answer — as which shard keeps the
        /// event it was read from.
        witnesses: Vec<(Address, BeaconWitnessEvent)>,
    },
}

impl CachedOutput {
    /// The success output: the folded absolute writes and the receipt
    /// hash over their canonical encoding. Keys carry their shard
    /// placement in the owner prefix, so no declared node set or
    /// ownership map exists.
    #[must_use]
    pub(crate) const fn succeeded(
        raw_writes: StateWrites,
        receipt_hash: GlobalReceiptHash,
        metadata: ExecutionMetadata,
        events: Vec<Event>,
        witnesses: Vec<(Address, BeaconWitnessEvent)>,
    ) -> Self {
        Self {
            metadata,
            body: CachedOutputBody::Succeeded {
                raw_writes,
                events,
                receipt_hash,
                witnesses,
            },
        }
    }

    /// The failure output — a per-transaction abort whose diagnostics
    /// ride the node-local metadata.
    #[must_use]
    pub(crate) const fn failed(metadata: ExecutionMetadata) -> Self {
        Self {
            metadata,
            body: CachedOutputBody::Failed,
        }
    }
}

/// Build an [`ExecutedTx`] for `local_shard` from a [`CachedOutput`].
///
/// Runs the per-shard step: `filter_writes_for_shard` over the cached
/// `raw_writes`, then assembles the `ExecutedTx`. The writes map is
/// canonically ordered by construction, so
/// `ConsensusReceipt::local_receipt_hash` is order-stable with no sort
/// step.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
#[must_use]
pub fn project_to_shard(
    cached: &CachedOutput,
    tx_hash: TxHash,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
) -> ExecutedTx {
    match &cached.body {
        CachedOutputBody::Failed => {
            ExecutedTx::new(tx_hash, ConsensusReceipt::Failed, cached.metadata.clone())
        }
        CachedOutputBody::Succeeded {
            raw_writes,
            events,
            receipt_hash,
            witnesses,
        } => {
            let owned = owned_by(local_shard, shard_trie);
            let writes = filter_writes_for_shard(raw_writes, owned);
            // A fact's emitter is a substate prefix, so the shard that
            // keeps the fact is the one that keeps the event it was read
            // from — the same rule applied a few lines below, and the
            // whole of what decides which shard reports a fact. The
            // beacon folds each one exactly once because exactly one
            // shard owns its emitter. The receipt hash's witness root
            // covers exactly these.
            let beacon_witness_events: Vec<BeaconWitnessEvent> = witnesses
                .iter()
                .filter(|(emitter, _)| owned(*emitter))
                .map(|(_, event)| event.clone())
                .collect();
            // An event is stored where its emitter lives, so each shard
            // keeps its own and the rest are another shard's to hold. The
            // receipt hash's event root covers exactly these, so what is
            // stored is what was signed over.
            let events: Vec<Event> = events
                .iter()
                .filter(|event| owned(event.emitter))
                .cloned()
                .collect();
            let consensus = ConsensusReceipt::Succeeded {
                receipt_hash: *receipt_hash,
                writes,
                beacon_witness_events: Capped::new(beacon_witness_events)
                    .expect("a list under the cap its source already met"),
                events: Capped::new(events).expect("a list under the cap its source already met"),
            };
            ExecutedTx::new(tx_hash, consensus, cached.metadata.clone())
        }
    }
}
