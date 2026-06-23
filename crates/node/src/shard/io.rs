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
use crate::fetch::{FetchHost, FetchMetrics};
use crate::shard::caches::SharedCaches;
use crate::shard::commit::BlockCommitCoordinator;
use crate::shard::cross_shard::CrossShardState;
use crate::shard::phase_times::TxPhaseTimesCache;
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

    /// Per-shard cross-shard subsystem state (remote-header sync, cross-shard
    /// fetch instances/stores, settled-waves acquisition).
    pub cross_shard: CrossShardState,

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

impl<S: ShardStorage> ShardIo<S> {
    /// Snapshot per-binding fetch counts across both the `FetchHost` payloads
    /// (transaction, shard-witness, beacon-proposal) and the cross-shard fetch
    /// instances on [`CrossShardState`]. The I/O loop flattens this into the
    /// larger `MetricsSnapshot`.
    #[must_use]
    pub fn fetch_metrics(&self) -> FetchMetrics {
        let f = &self.fetches;
        let x = &self.cross_shard;
        FetchMetrics {
            transaction_in_flight: f.transaction.in_flight_count(),
            transaction_pending: f.transaction.pending_count(),
            transaction_oldest_in_flight_age_ms: f.transaction.oldest_in_flight_age_ms(),
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
            shard_witness_in_flight: f.shard_witness.in_flight_count(),
            shard_witness_pending: f.shard_witness.pending_count(),
            shard_witness_oldest_in_flight_age_ms: f.shard_witness.oldest_in_flight_age_ms(),
            beacon_proposal_in_flight: f.beacon_proposal.in_flight_count(),
            beacon_proposal_pending: f.beacon_proposal.pending_count(),
            beacon_proposal_oldest_in_flight_age_ms: f.beacon_proposal.oldest_in_flight_age_ms(),
        }
    }
}
