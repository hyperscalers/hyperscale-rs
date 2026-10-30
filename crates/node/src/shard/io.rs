//! Per-shard I/O state, one per hosted shard.
//!
//! One [`ShardIo`] per hosted shard, owned by that shard's loop and its
//! one replica. Shard-scoped state is grouped by subsystem —
//! [`ConsensusState`], [`CrossShardState`], [`MempoolState`] — over the
//! shard's infra (storage, pending chain,
//! block-commit pipeline, request-serving caches), and none of it leaks
//! across shards.

use std::sync::Arc;

use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::{PendingChain, ShardStorage, TickChain};
use hyperscale_types::{BlockHeight, LocalTimestamp};

use crate::shard::boundary_pins::BoundaryPins;
use crate::shard::caches::SharedCaches;
use crate::shard::commit::BlockCommitCoordinator;
use crate::shard::consensus::{BlockSyncStatus, ConsensusState};
use crate::shard::cross_shard::CrossShardState;
use crate::shard::mempool::MempoolState;
use crate::shard::phase_times::TxPhaseTimesCache;

/// Per-shard I/O state hosted by the `NodeHost`.
pub struct ShardIo<S: ShardStorage> {
    /// Persistent block / receipt / JMT store for this shard. `Arc` so
    /// delegated closures (block-commit, fetch-serve, sync) can read
    /// it from thread pools without crossing back to the pinned thread.
    pub(crate) storage: Arc<S>,

    /// Chain-anchored pending state. Indexed by block hash; reads
    /// happen through `PendingChain::view_at(parent_block_hash)` which
    /// walks the parent chain back to the committed tip. Orphaned
    /// blocks are not ancestors and are structurally invisible to
    /// anchored views.
    pub(crate) pending_chain: Arc<PendingChain<S>>,

    /// Execution-baseline tick outputs. The execute handler appends and
    /// reads views; the shard loop applies tick resolutions and prunes
    /// on persistence. Never feeds state-root verification.
    pub(crate) tick_chain: Arc<TickChain<S>>,

    /// Block commit pipeline: accumulates commits, applies persistence
    /// backpressure, and drains them into a single async closure that
    /// runs on the execution pool. Owns the prepared-commit cache
    /// shared with delegated dispatch closures.
    pub(crate) block_commit: BlockCommitCoordinator,

    /// The store's boundary pins under the node's retention rule, shared
    /// with the block-commit pipeline's boundary trigger.
    pub(crate) boundary_pins: Arc<BoundaryPins<S>>,

    /// The oldest pin and the attested anchor the chain floor was last
    /// moved against; `None` until it first moves. The floor is moved
    /// again only once either changes.
    pub(crate) floor_pins: Option<(Option<BlockHeight>, Option<BlockHeight>)>,

    /// Inbound request-serving caches plus the cross-thread tx-status
    /// view shared with external RPC consumers.
    pub(crate) caches: SharedCaches,

    /// Per-shard consensus subsystem state (block-sync FSM, certified-header
    /// verification batch).
    pub(crate) consensus: ConsensusState,

    /// Per-shard cross-shard subsystem state (remote-header sync, cross-shard
    /// fetch instances/stores, settled-transaction acquisition).
    pub(crate) cross_shard: CrossShardState,

    /// Per-shard mempool subsystem state (transaction fetch, validation
    /// tracking sets + batch, outbound tx-gossip accumulators).
    pub(crate) mempool: MempoolState,

    /// Per-tx phase-time stamps for the slow-tx finalization log.
    /// Populated from `EmitTransactionStatus` and `RecordTxEcCreated`
    /// actions emitted by this shard's replica; entries are dropped on
    /// terminal status, and the cache is bounded for those that never
    /// reach one. Per-shard so each hosted shard logs its own
    /// locally-submitted finalization latencies independently.
    pub(crate) tx_phase_times: TxPhaseTimesCache,

    /// Last time this shard emitted a "transaction finalization exceeded
    /// 10s" warning. Rate-limited to avoid log floods during cross-shard
    /// latency spikes; per-shard so co-hosted shards don't suppress
    /// each other's warnings.
    pub(crate) last_slow_tx_warn: LocalTimestamp,
}

impl<S: ShardStorage> ShardIo<S> {
    /// This shard's persistent store. The cross-crate read surface for
    /// harnesses that serve fetches or sample committed state directly off
    /// storage; node-internal code uses the field.
    #[must_use]
    pub const fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Chain-anchored pending state, for serving block / witness-history
    /// requests off a non-committee host.
    #[must_use]
    pub const fn pending_chain(&self) -> &Arc<PendingChain<S>> {
        &self.pending_chain
    }

    /// The provision store backing block-serve responses.
    #[must_use]
    pub const fn provision_store(&self) -> &Arc<ProvisionStore> {
        &self.caches.provision_store
    }

    /// Snapshot of this shard's block-sync FSM, for RPC sync-status reporting.
    #[must_use]
    pub fn block_sync_status(&self) -> BlockSyncStatus {
        self.consensus.block_sync.block_sync_status()
    }

    /// Snapshot per-binding fetch counts across the transaction fetch on
    /// [`MempoolState`] and the cross-shard fetch instances on
    /// [`CrossShardState`], for the shard's metrics emission.
    #[must_use]
    pub(crate) fn fetch_metrics(&self) -> FetchMetrics {
        let x = &self.cross_shard;
        let m = &self.mempool;
        FetchMetrics {
            transaction_in_flight: m.transaction.in_flight_count(),
            transaction_pending: m.transaction.pending_count(),
            transaction_oldest_in_flight_age_ms: m.transaction.oldest_in_flight_age_ms(),
            local_provision_in_flight: x.local_provision.in_flight_count(),
            local_provision_pending: x.local_provision.pending_count(),
            local_provision_oldest_in_flight_age_ms: x.local_provision.oldest_in_flight_age_ms(),
            finalization_in_flight: x.finalization.in_flight_count(),
            finalization_pending: x.finalization.pending_count(),
            finalization_oldest_in_flight_age_ms: x.finalization.oldest_in_flight_age_ms(),
            provision_in_flight: x.provision.in_flight_count(),
            provision_pending: x.provision.pending_count(),
            provision_oldest_in_flight_age_ms: x.provision.oldest_in_flight_age_ms(),
        }
    }
}

/// Cheap aggregate of per-binding fetch counts (all payloads). Built by
/// [`ShardIo::fetch_metrics`] from the transaction fetch on
/// [`MempoolState`] and the cross-shard fetch instances on
/// [`CrossShardState`]; read by the shard's metrics emission.
///
/// `_oldest_in_flight_age_ms` is `0` when nothing is in flight; otherwise
/// the age (in milliseconds) of the longest-running in-flight entry.
/// Alerting on this rising past tens of seconds catches admission paths
/// that silently dropped a response without notifying the FSM.
pub struct FetchMetrics {
    pub transaction_in_flight: usize,
    pub transaction_pending: usize,
    pub transaction_oldest_in_flight_age_ms: u64,
    pub local_provision_in_flight: usize,
    pub local_provision_pending: usize,
    pub local_provision_oldest_in_flight_age_ms: u64,
    pub finalization_in_flight: usize,
    pub finalization_pending: usize,
    pub finalization_oldest_in_flight_age_ms: u64,
    pub provision_in_flight: usize,
    pub provision_pending: usize,
    pub provision_oldest_in_flight_age_ms: u64,
}
