//! Per-shard receipt with shard-filtered writes (Tier 2) and the engine output
//! that travels alongside an `ExecutionVote` from the thread pool to the state
//! machine.

use crate::{
    ApplicationEvent, DatabaseUpdates, EventRoot, ExecutionMetadata, GlobalReceipt,
    GlobalReceiptHash, Hash, TransactionOutcome, TxHash, WritesRoot, compute_merkle_root,
};

/// Per-shard receipt with shard-filtered database updates and events.
///
/// Stored per-shard — `database_updates` contain only writes for the local
/// shard (already filtered by `filter_updates_for_shard` during execution).
///
/// Feeds `state_root` computation via JMT. Per-tx attribution committed via
/// `local_receipt_root` in the block header.
///
/// Held in-memory in `FinalizedWave` until block commit, then written
/// atomically with block metadata.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct LocalReceipt {
    /// Whether the engine committed or rejected the transaction.
    pub outcome: TransactionOutcome,
    /// Shard-filtered substate writes produced by this transaction.
    pub database_updates: DatabaseUpdates,
    /// Application events emitted during execution.
    pub application_events: Vec<ApplicationEvent>,
}

impl LocalReceipt {
    /// Derive the global receipt from this local receipt with pre-computed `writes_root`.
    ///
    /// `writes_root` must be computed separately from unfiltered (global) writes
    /// via `filter_updates_for_global_receipt()`, since this local receipt only
    /// contains shard-filtered writes.
    #[must_use]
    pub fn global_receipt(&self, writes_root: WritesRoot) -> GlobalReceipt {
        let event_hashes: Vec<Hash> = self
            .application_events
            .iter()
            .map(ApplicationEvent::hash)
            .collect();
        GlobalReceipt {
            outcome: self.outcome,
            event_root: EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            writes_root,
        }
    }

    /// Compute a deterministic hash of this local receipt for `local_receipt_root`.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of `database_updates` fails — `DatabaseUpdates`
    /// is a closed SBOR type and encoding is infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> Hash {
        let outcome_byte = match self.outcome {
            TransactionOutcome::Success => [1u8],
            TransactionOutcome::Failure => [0u8],
        };
        let event_hashes: Vec<Hash> = self
            .application_events
            .iter()
            .map(ApplicationEvent::hash)
            .collect();
        let event_root = compute_merkle_root(&event_hashes);
        // Include database_updates hash so local_receipt_root commits to per-tx state deltas.
        let updates_bytes =
            sbor::prelude::basic_encode(&self.database_updates).expect("encode should not fail");
        let updates_hash = Hash::from_bytes(&updates_bytes);
        Hash::from_parts(&[
            &outcome_byte,
            event_root.as_bytes(),
            updates_hash.as_bytes(),
        ])
    }

    /// Create a failure receipt with no database updates or events.
    #[must_use]
    pub fn failure() -> Self {
        Self {
            outcome: TransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        }
    }
}

/// Execution output that travels alongside an `ExecutionVote` through the
/// `ProtocolEvent` boundary from the thread pool to the state machine.
///
/// The state machine holds receipts in-memory until block commit;
/// `DatabaseUpdates` live on the local receipt. Outcome is determined from
/// the receipt's `outcome` field rather than a separate flag — the engine
/// produces `LocalExecutionEntry` directly alongside a `TxOutcome` for
/// vote aggregation (see `hyperscale_engine::ExecutedTx`).
#[derive(Debug, Clone)]
pub struct LocalExecutionEntry {
    /// Hash of the executed transaction.
    pub tx_hash: TxHash,
    /// Pre-computed global receipt hash (outcome + `event_root` + `writes_root`).
    /// Computed on the execution thread pool to avoid recomputation on the state machine.
    pub receipt_hash: GlobalReceiptHash,
    /// Full local receipt with shard-filtered database updates and events.
    pub local_receipt: LocalReceipt,
    /// Local execution metadata (fees, logs, errors).
    pub execution_output: ExecutionMetadata,
}
