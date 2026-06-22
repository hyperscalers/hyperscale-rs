//! Per-shard I/O state hosted by the `NodeHost`.
//!
//! One [`ShardIo`] per hosted shard. Same-shard `Vnode`s share their
//! `ShardIo`; cross-shard `Vnode`s live independently. Shard-scoped
//! state (storage, fetch host, sync host, block-commit pipeline,
//! request-serving caches, batch accumulators) lives here so that
//! multi-vnode hosting captures the natural sharing structure without
//! leaking state across `NodeHost`s.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlockHeader, LocalTimestamp,
    RoutableTransaction, TxHash, ValidatorId, Verifiable,
};

use crate::batch_accumulator::BatchAccumulator;
use crate::fetch::FetchHost;
use crate::shard::caches::SharedCaches;
use crate::shard::commit::BlockCommitCoordinator;
use crate::shard::phase_times::TxPhaseTimesCache;
use crate::shard::settled_set::SettledWavesAcquisitionHost;
use crate::sync::SyncHost;

/// A certified header pending sender-signature verification, queued in
/// `ShardIo::certified_header_batch` and drained on the crypto pool.
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

/// Per-shard I/O state hosted by the `NodeHost`.
pub struct ShardIo<S: ShardStorage> {
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
    pub block_commit: BlockCommitCoordinator,

    /// Inbound request-serving caches plus the cross-thread tx-status
    /// view shared with external RPC consumers.
    pub caches: SharedCaches,

    /// Per-payload fetch state machines (transactions, exec certs,
    /// provisions, finalized waves, local provisions).
    pub fetches: FetchHost,

    /// Sync state machines: block-sync (catch up the shard chain) and
    /// remote-header sync (track other shards' certified headers for
    /// cross-shard data dependencies).
    pub syncs: SyncHost,

    /// Settled-waves acquisition drivers — one per past-terminal remote
    /// shard whose `S_P` this node is acquiring for the split-boundary
    /// fence.
    pub settled_set_sync: SettledWavesAcquisitionHost,

    /// Hashes currently in the validation pipeline — either sitting in
    /// `validation_batch` or being verified off-thread. Acts as a
    /// dedup guard so duplicate gossip / re-submits don't enqueue
    /// twice. Entries are removed by `TransactionValidated` /
    /// `TransactionValidationsFailed` handlers.
    pub pending_validation: HashSet<TxHash>,

    /// Subset of `pending_validation` for which this shard is the
    /// designated source for a locally-submitted tx — i.e. it received
    /// `AdmitAndGossipTransaction`. Carried through validation so the
    /// resulting `TransactionValidated` event flags
    /// `submitted_locally = true` for mempool admission accounting.
    ///
    /// At most one hosted shard per node enters a given tx hash here,
    /// so the finalization metric fires exactly once per node per
    /// locally-submitted tx even when multiple co-hosted shards touch
    /// it. Passive co-hosts admit via `AdmitTransaction` without
    /// inserting; gossip-only hosts via `GossipTransaction` don't
    /// admit at all.
    pub locally_submitted: HashSet<TxHash>,

    /// Pending transactions awaiting batched signature / format /
    /// declared-shard verification on the `tx_validation` pool.
    pub validation_batch: BatchAccumulator<Arc<RoutableTransaction>>,

    /// Pending remote-certified header gossip awaiting batched BLS
    /// sender-signature verification on the crypto pool.
    pub certified_header_batch: BatchAccumulator<CertifiedHeaderVerificationItem>,

    /// Per-tx phase-time stamps for the slow-tx finalization log.
    /// Populated from `EmitTransactionStatus` and `RecordTxEcCreated`
    /// actions emitted by this shard's vnodes; entries are dropped on
    /// terminal status. Per-shard so each hosted shard logs its own
    /// locally-submitted finalization latencies independently.
    pub tx_phase_times: TxPhaseTimesCache,

    /// Last time this shard emitted a "transaction finalization exceeded
    /// 10s" warning. Rate-limited to avoid log floods during cross-shard
    /// latency spikes; per-shard so co-hosted shards don't suppress
    /// each other's warnings.
    pub last_slow_tx_warn: LocalTimestamp,
}
