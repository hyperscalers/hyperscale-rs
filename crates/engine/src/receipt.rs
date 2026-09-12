//! The engine's execution output and its per-shard projection.
//!
//! Receipt projection runs in two stages:
//!
//! - the engine turns its own receipt into a [`CachedOutput`]. For a
//!   whole-locality batch every field is shard-invariant; for a batch
//!   with cross-shard members the writes and the receipt hash already
//!   carry the executing shard's projection.
//! - [`project_to_shard`] consumes the cached output and a target shard
//!   to produce the final [`ExecutedTx`]. Only the `writes` slice, the
//!   events, and the beacon facts are shard-specific — a no-op on
//!   writes the executor already projected.

use hyperscale_types::{
    Address, BeaconWitnessEvent, ConsensusReceipt, EscrowedValue, Event, ExecutionMetadata,
    GlobalReceiptHash, ShardId, ShardTrie, StateWrites, TxHash,
};

use crate::output::ExecutedTx;
use crate::sharding::{filter_writes_for_shard, owned_by};

/// Cached projection of an execution receipt.
///
/// Carries everything needed to assemble an [`ExecutedTx`]. Under whole
/// locality every field is identical on every shard that executes the
/// same transaction, and the output serves any target; under owned
/// locality the writes and the receipt hash are the executing shard's
/// own, and the output serves only that shard.
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
        /// What the execution escrowed out, per departing edge.
        escrowed: Vec<EscrowedValue>,
    },
}

impl CachedOutput {
    /// The success output: the folded absolute writes and the receipt
    /// hash over their canonical encoding. Keys carry their shard
    /// placement in the owner prefix, so no declared node set or
    /// ownership map exists.
    #[must_use]
    pub const fn succeeded(
        raw_writes: StateWrites,
        receipt_hash: GlobalReceiptHash,
        metadata: ExecutionMetadata,
        events: Vec<Event>,
        witnesses: Vec<(Address, BeaconWitnessEvent)>,
        escrowed: Vec<EscrowedValue>,
    ) -> Self {
        Self {
            metadata,
            body: CachedOutputBody::Succeeded {
                raw_writes,
                events,
                receipt_hash,
                witnesses,
                escrowed,
            },
        }
    }

    /// The failure output — a per-transaction abort whose diagnostics
    /// ride the node-local metadata.
    #[must_use]
    pub const fn failed(metadata: ExecutionMetadata) -> Self {
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
            escrowed,
        } => {
            let owned = owned_by(local_shard, shard_trie);
            let writes = filter_writes_for_shard(raw_writes, owned);
            // A fact's emitter is a substate prefix, so the shard that
            // keeps the fact is the one that keeps the event it was read
            // from — the same rule applied a few lines below, and the
            // whole of what decides which shard reports a fact. The
            // beacon folds each one exactly once because exactly one
            // shard owns its emitter.
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
                beacon_witness_events,
                events,
            };
            let mut executed = ExecutedTx::new(tx_hash, consensus, cached.metadata.clone());
            executed.escrowed.clone_from(escrowed);
            executed
        }
    }
}
