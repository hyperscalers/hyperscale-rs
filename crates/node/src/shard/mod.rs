//! Per-shard I/O state hosted by the `IoLoop`.
//!
//! One [`ShardIo`] per hosted shard. Same-shard `Vnode`s share their
//! `ShardIo`; cross-shard `Vnode`s live independently. Shard-scoped
//! state (storage, fetch host, sync host, block-commit pipeline,
//! request-serving caches, batch accumulators) lives here so that
//! multi-vnode hosting captures the natural sharing structure without
//! leaking state across `IoLoop`s.

pub mod block_commit;
pub mod caches;
pub mod fetch;
pub mod phase_times;
pub mod sync;
pub mod verify;

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader, RoutableTransaction, TxHash,
    ValidatorId,
};

use crate::batch_accumulator::BatchAccumulator;
use crate::shard::block_commit::BlockCommitCoordinator;
pub use crate::shard::caches::SharedCaches;
use crate::shard::fetch::FetchHost;
use crate::shard::sync::SyncHost;

/// A committed header pending sender-signature verification, queued in
/// `ShardIo::committed_header_batch` and drained on the crypto pool.
pub type CommittedHeaderVerificationItem = (
    Arc<CommittedBlockHeader>,
    ValidatorId,
    Bls12381G1PublicKey,
    Bls12381G2Signature,
);

/// Per-shard I/O state hosted by the `IoLoop`.
pub struct ShardIo<S: Storage> {
    /// Persistent block / receipt / JMT store for this shard. `Arc` so
    /// delegated closures (block-commit, fetch-serve, sync) can read
    /// it from thread pools without crossing back to the pinned thread.
    pub storage: Arc<S>,

    /// Chain-anchored pending state. Indexed by block hash; reads
    /// happen through `PendingChain::view_at(parent_block_hash)` which
    /// walks the parent chain back to the committed tip. Orphaned
    /// blocks are not ancestors and are structurally invisible to
    /// anchored views.
    pub pending_chain: Arc<PendingChain<S>>,

    /// Block commit pipeline: accumulates commits, applies persistence
    /// backpressure, and drains them into a single async closure that
    /// runs on the execution pool. Owns the prepared-commit cache
    /// shared with delegated dispatch closures.
    pub block_commit: BlockCommitCoordinator<S>,

    /// Inbound request-serving caches plus the cross-thread tx-status
    /// view shared with external RPC consumers.
    pub caches: SharedCaches,

    /// Per-payload fetch state machines (transactions, exec certs,
    /// provisions, finalized waves, local provisions).
    pub fetches: FetchHost,

    /// Sync state machines: block-sync (catch up the shard chain) and
    /// remote-header sync (track other shards' committed headers for
    /// cross-shard data dependencies).
    pub syncs: SyncHost,

    /// Hashes currently in the validation pipeline — either sitting in
    /// `validation_batch` or being verified off-thread. Acts as a
    /// dedup guard so duplicate gossip / re-submits don't enqueue
    /// twice. Entries are removed by `TransactionValidated` /
    /// `TransactionValidationsFailed` handlers.
    pub pending_validation: HashSet<TxHash>,

    /// Subset of `pending_validation` that originated from a local
    /// RPC / sim submission rather than gossip. Carried through
    /// validation so the resulting `TransactionValidated` event can
    /// flag `submitted_locally = true` for mempool admission
    /// accounting.
    pub locally_submitted: HashSet<TxHash>,

    /// Pending transactions awaiting batched signature / format /
    /// declared-shard verification on the `tx_validation` pool.
    pub validation_batch: BatchAccumulator<Arc<RoutableTransaction>>,

    /// Pending remote-committed-header gossip awaiting batched BLS
    /// sender-signature verification on the crypto pool.
    pub committed_header_batch: BatchAccumulator<CommittedHeaderVerificationItem>,
}
