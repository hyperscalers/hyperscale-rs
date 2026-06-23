//! Per-shard I/O state hosted by the `NodeHost`.
//!
//! One [`ShardIo`] per hosted shard. Same-shard `Vnode`s share their
//! `ShardIo`; cross-shard `Vnode`s live independently. Shard-scoped state
//! is grouped by subsystem — [`ConsensusState`], [`CrossShardState`],
//! [`MempoolState`], [`BeaconFetchState`] — over genuinely-shared infra
//! (storage, pending chain, block-commit pipeline, request-serving caches),
//! so multi-vnode hosting captures the natural sharing structure without
//! leaking state across `NodeHost`s.

use std::sync::Arc;

use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::LocalTimestamp;

use crate::beacon::BeaconFetchState;
use crate::shard::caches::SharedCaches;
use crate::shard::commit::BlockCommitCoordinator;
use crate::shard::consensus::ConsensusState;
use crate::shard::cross_shard::CrossShardState;
use crate::shard::mempool::MempoolState;
use crate::shard::phase_times::TxPhaseTimesCache;

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

    /// Per-shard consensus subsystem state (block-sync FSM, certified-header
    /// verification batch).
    pub consensus: ConsensusState,

    /// Per-shard cross-shard subsystem state (remote-header sync, cross-shard
    /// fetch instances/stores, settled-waves acquisition).
    pub cross_shard: CrossShardState,

    /// Per-shard mempool subsystem state (transaction fetch, validation
    /// tracking sets + batch, outbound tx-gossip accumulators).
    pub mempool: MempoolState,

    /// Per-shard beacon fetch instances (missing proposals, shard-witness
    /// leaves) the beacon coordinator drives for this shard.
    pub beacon_fetch: BeaconFetchState,

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

impl<S: ShardStorage> ShardIo<S> {
    /// Snapshot per-binding fetch counts across the transaction fetch on
    /// [`MempoolState`], the cross-shard fetch instances on
    /// [`CrossShardState`], and the beacon fetch instances on
    /// [`BeaconFetchState`]. The I/O loop flattens this into the larger
    /// `MetricsSnapshot`.
    #[must_use]
    pub fn fetch_metrics(&self) -> FetchMetrics {
        let b = &self.beacon_fetch;
        let x = &self.cross_shard;
        let m = &self.mempool;
        FetchMetrics {
            transaction_in_flight: m.transaction.in_flight_count(),
            transaction_pending: m.transaction.pending_count(),
            transaction_oldest_in_flight_age_ms: m.transaction.oldest_in_flight_age_ms(),
            local_provision_in_flight: x.local_provision.in_flight_count(),
            local_provision_pending: x.local_provision.pending_count(),
            local_provision_oldest_in_flight_age_ms: x.local_provision.oldest_in_flight_age_ms(),
            finalized_wave_in_flight: x.finalized_wave.in_flight_count(),
            finalized_wave_pending: x.finalized_wave.pending_count(),
            finalized_wave_oldest_in_flight_age_ms: x.finalized_wave.oldest_in_flight_age_ms(),
            provision_in_flight: x.provision.in_flight_count(),
            provision_pending: x.provision.pending_count(),
            provision_oldest_in_flight_age_ms: x.provision.oldest_in_flight_age_ms(),
            exec_cert_in_flight: x.exec_cert.in_flight_count(),
            exec_cert_pending: x.exec_cert.pending_count(),
            exec_cert_oldest_in_flight_age_ms: x.exec_cert.oldest_in_flight_age_ms(),
            shard_witness_in_flight: b.shard_witness.in_flight_count(),
            shard_witness_pending: b.shard_witness.pending_count(),
            shard_witness_oldest_in_flight_age_ms: b.shard_witness.oldest_in_flight_age_ms(),
            beacon_proposal_in_flight: b.beacon_proposal.in_flight_count(),
            beacon_proposal_pending: b.beacon_proposal.pending_count(),
            beacon_proposal_oldest_in_flight_age_ms: b.beacon_proposal.oldest_in_flight_age_ms(),
        }
    }
}

/// Cheap aggregate of per-binding fetch counts (all payloads). Built by
/// [`ShardIo::fetch_metrics`] from the transaction fetch on
/// [`MempoolState`], the cross-shard fetch instances on [`CrossShardState`],
/// and the beacon fetch instances on [`BeaconFetchState`]; flattened into
/// the broader `MetricsSnapshot` by the I/O loop.
///
/// `_oldest_in_flight_age_ms` is `0` when nothing is in flight; otherwise
/// the age (in milliseconds) of the longest-running in-flight entry.
/// Alerting on this rising past tens of seconds catches admission paths
/// that silently dropped a response without notifying the FSM.
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct FetchMetrics {
    pub transaction_in_flight: usize,
    pub transaction_pending: usize,
    pub transaction_oldest_in_flight_age_ms: u64,
    pub local_provision_in_flight: usize,
    pub local_provision_pending: usize,
    pub local_provision_oldest_in_flight_age_ms: u64,
    pub finalized_wave_in_flight: usize,
    pub finalized_wave_pending: usize,
    pub finalized_wave_oldest_in_flight_age_ms: u64,
    pub provision_in_flight: usize,
    pub provision_pending: usize,
    pub provision_oldest_in_flight_age_ms: u64,
    pub exec_cert_in_flight: usize,
    pub exec_cert_pending: usize,
    pub exec_cert_oldest_in_flight_age_ms: u64,
    pub shard_witness_in_flight: usize,
    pub shard_witness_pending: usize,
    pub shard_witness_oldest_in_flight_age_ms: u64,
    pub beacon_proposal_in_flight: usize,
    pub beacon_proposal_pending: usize,
    pub beacon_proposal_oldest_in_flight_age_ms: u64,
}
