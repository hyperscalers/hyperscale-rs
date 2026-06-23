//! Per-shard consensus subsystem.
//!
//! Colocates everything block-consensus the shard driver touches: the
//! per-shard [`ConsensusState`] (block-sync FSM + certified-header
//! verification batch), the block-sync FSM [`binding`](block), its inbound
//! [`serve`](block_serve) responder, the `impl ShardLoop` [`glue`](block_sync)
//! that drives fetches and delivers synced blocks to consensus, and the
//! certified-header [`gossip`] handler that feeds cross-shard provisioning.

mod block;
mod block_serve;
mod block_sync;
mod gossip;

use std::sync::Arc;
use std::time::Instant;

pub use block::{
    BlockSync, BlockSyncConfig, BlockSyncInput, BlockSyncOutput, BlockSyncStateKind,
    BlockSyncStatus,
};
pub use block_serve::serve_block_request;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlockHeader, ValidatorId, Verifiable,
};

use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;

/// A certified header pending sender-signature verification, queued in
/// [`ConsensusState::certified_header_batch`] and drained on the crypto pool.
///
/// The wrapper carries verification state across the in-process gossip
/// boundary — wire arrivals land as `Verifiable::Unverified` per SBOR
/// rules, local-dispatched arrivals from a colocated proposer ride as
/// `Verifiable::Verified` so the flush step can fast-path them past the
/// sender-signature batch.
pub type CertifiedHeaderVerificationItem = (
    Arc<Verifiable<CertifiedBlockHeader>>,
    ValidatorId,
    Bls12381G1PublicKey,
    Bls12381G2Signature,
);

/// Per-shard consensus subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct ConsensusState {
    /// Block-sync state machine: catch the shard chain up to a target
    /// height by fetching and committing missing blocks.
    pub block_sync: BlockSync,

    /// Pending remote-certified header gossip awaiting batched BLS
    /// sender-signature verification on the crypto pool.
    pub certified_header_batch: BatchAccumulator<CertifiedHeaderVerificationItem>,
}

impl ConsensusState {
    /// Build consensus state for a freshly hosted shard.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        let b = &config.batch;
        Self {
            block_sync: BlockSync::new(config.block_sync.clone()),
            certified_header_batch: BatchAccumulator::new(
                b.certified_header_max,
                b.certified_header_window,
            ),
        }
    }

    /// True if block-sync has heights parked behind a backoff or is
    /// actively syncing. Keeps the `FetchTick` timer alive so deferred
    /// heights eventually retry and an active sync keeps emitting fetches
    /// even if its consumer is slow to admit.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.block_sync.has_deferred() || self.block_sync.is_syncing()
    }

    /// Drive the block-sync FSM's periodic tick. Returns the outputs the
    /// I/O loop should dispatch (block fetches, deliveries, sync-complete).
    pub fn block_tick(&mut self, now: Instant) -> Vec<BlockSyncOutput> {
        self.block_sync.handle(BlockSyncInput::Tick { now })
    }
}
