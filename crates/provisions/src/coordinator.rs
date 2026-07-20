//! Centralized provision coordination.
//!
//! Tracks all cross-shard provisions, manages QC + merkle proof verification,
//! and emits verification events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts `ProvisionsNotification` messages
//! carrying JMT inclusion proofs. The target shard joins with remote block
//! headers, then dispatches `VerifyProvisions` to verify the QC signature
//! once and merkle proofs per state entry against the committed state root.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchAbandon, ProtocolEvent};
use hyperscale_types::{
    BlockHeight, BlockManifest, CertifiedBlock, CertifiedBlockHeader, LocalTimestamp,
    ProvisionHash, Provisions, ProvisionsVerifyError, RETENTION_HORIZON, ShardId, Verified,
};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::committed_tombstones::CommittedProvisionTombstones;
use crate::expected::{ExpectedProvisionTracker, TimeoutEffect};
use crate::pipeline::ProvisionPipeline;
use crate::queue::QueuedProvisionBuffer;
use crate::store::ProvisionStore;
use crate::verification::build_verify_action;
use crate::verified_headers::VerifiedHeaderBuffer;

/// Default minimum dwell time verified provisions sit in the queue before
/// the proposer can include them in a block. Gives shard peers time to
/// receive and verify the same provisions via gossip, so they don't have
/// to fetch later. Also buys headroom for the fetch-serving cache since
/// peers hit local state instead of requesting back.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(500);

/// Provision coordinator configuration.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ProvisionConfig {
    /// Minimum time verified provisions must sit in the proposal queue
    /// before they become eligible for inclusion. Entries younger than
    /// this are skipped by `queued_provisions()` but remain in the queue.
    ///
    /// Set to zero to disable.
    #[serde(default = "default_min_dwell_time")]
    pub min_dwell_time: Duration,
}

const fn default_min_dwell_time() -> Duration {
    DEFAULT_MIN_DWELL_TIME
}

impl Default for ProvisionConfig {
    fn default() -> Self {
        Self {
            min_dwell_time: DEFAULT_MIN_DWELL_TIME,
        }
    }
}

/// Provision coordinator memory statistics for monitoring collection sizes.
#[allow(missing_docs)] // flat counters; field names are the documentation
#[derive(Clone, Copy, Debug, Default)]
pub struct ProvisionMemoryStats {
    pub verified_remote_headers: usize,
    pub pending_provisions: usize,
    pub verified_provisions: usize,
    pub expected_provisions: usize,
    pub provisions_by_hash: usize,
    pub queued_provisions: usize,
}

/// Centralized provision coordination.
///
/// Responsibilities:
/// - Receive provisions from the source shard proposer
/// - Join provisions with remote block headers
/// - Dispatch QC + merkle proof verification (QC once per source block,
///   merkle proofs per state entry)
/// - Queue verified provisions for block inclusion
/// - Request missing provisions after timeout (fallback recovery)
pub struct ProvisionCoordinator {
    // ═══════════════════════════════════════════════════════════════════
    // Verified Remote Block Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers from remote shards. All entries have
    /// passed QC verification by the `RemoteHeaderCoordinator`; this buffer
    /// is the join point for matching provisions against their source
    /// state root.
    headers: Arc<VerifiedHeaderBuffer>,

    // ═══════════════════════════════════════════════════════════════════
    // Provision Verification Pipeline
    // ═══════════════════════════════════════════════════════════════════
    /// Pending → verified → store lifecycle for inbound provisions. Owns
    /// the `Arc<ProvisionStore>` shared with the io-loop's
    /// `local_provision.request` handler.
    pipeline: ProvisionPipeline,

    // ═══════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (fallback detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Outstanding expectations driven by remote header arrivals. Owns
    /// the local committed `local_ts` anchor every other sub-machine reads
    /// through.
    expected: ExpectedProvisionTracker,

    // ═══════════════════════════════════════════════════════════════════
    // Proposal Queue
    // ═══════════════════════════════════════════════════════════════════
    /// Verified provisions eligible for inclusion in the next block
    /// proposal, gated by a configured dwell window so peers have time to
    /// receive the same provisions via gossip.
    queue: QueuedProvisionBuffer,

    // ═══════════════════════════════════════════════════════════════════
    // Committed-Provision Tombstones
    // ═══════════════════════════════════════════════════════════════════
    /// Content-hash tombstones for batches already committed locally.
    /// Mirrors the shard-side `CommitDedupIndex::provision_retention`
    /// window so a late re-arrival can't slip past the
    /// `(source_shard, block_height)`-keyed pipeline guards and
    /// re-enter the proposer queue (which would then propose a batch
    /// the validator side rejects, causing view changes).
    committed_tombstones: CommittedProvisionTombstones,

    /// This validator's home shard. Used to gate inbound provisions:
    /// only batches whose target shard matches ours are admitted.
    local_shard: ShardId,
}

impl std::fmt::Debug for ProvisionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionCoordinator")
            .field("verified_remote_headers", &self.headers.len())
            .field("verified_provisions", &self.pipeline.verified_len())
            .finish_non_exhaustive()
    }
}

impl ProvisionCoordinator {
    /// Create a new `ProvisionCoordinator` with default config and a fresh
    /// local [`ProvisionStore`].
    #[must_use]
    pub fn new(local_shard: ShardId) -> Self {
        Self::with_config_and_store(
            local_shard,
            ProvisionConfig::default(),
            Arc::new(ProvisionStore::new()),
        )
    }

    /// Create a new `ProvisionCoordinator` with the given config and a fresh
    /// local [`ProvisionStore`].
    #[must_use]
    pub fn with_config(local_shard: ShardId, config: ProvisionConfig) -> Self {
        Self::with_config_and_store(local_shard, config, Arc::new(ProvisionStore::new()))
    }

    /// Create a new `ProvisionCoordinator` wired to an externally-owned
    /// [`ProvisionStore`]. Production nodes share the store with the
    /// io-loop so `local_provision.request` handlers read from the same
    /// source of truth this coordinator writes to.
    #[must_use]
    pub fn with_config_and_store(
        local_shard: ShardId,
        config: ProvisionConfig,
        store: Arc<ProvisionStore>,
    ) -> Self {
        let queue = QueuedProvisionBuffer::new(config.min_dwell_time);
        Self {
            headers: Arc::new(VerifiedHeaderBuffer::new()),
            pipeline: ProvisionPipeline::new(store),
            expected: ExpectedProvisionTracker::new(),
            queue,
            committed_tombstones: CommittedProvisionTombstones::new(),
            local_shard,
        }
    }

    /// Shared verified-header buffer — same `Arc` the io-loop request
    /// handler reads from to bundle the matching source header into each
    /// `local_provision.request` response.
    #[must_use]
    pub const fn verified_headers(&self) -> &Arc<VerifiedHeaderBuffer> {
        &self.headers
    }

    /// Get provision coordinator memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> ProvisionMemoryStats {
        ProvisionMemoryStats {
            verified_remote_headers: self.headers.len(),
            pending_provisions: self.pipeline.pending_len(),
            verified_provisions: self.pipeline.verified_len(),
            expected_provisions: self.expected.len(),
            provisions_by_hash: self.pipeline.store().len(),
            queued_provisions: self.queue.queue_len(),
        }
    }

    /// Handle block committed.
    ///
    /// Orchestration order matters:
    /// 1. `expected.record_block_committed` updates the local anchor and
    ///    retro-stamps pre-genesis entries. Must precede any sweep that
    ///    reads `local_ts`.
    /// 2. `queue.on_block_committed` drops committed provisions from the
    ///    proposer queue so we don't re-include them next round.
    /// 3. `committed_tombstones.register` mirrors the shard consensus
    ///    `CommitDedupIndex` window so a late re-arrival can't slip past
    ///    `pipeline.verified` (which evicts at `source_block_ts +
    ///    RETENTION_HORIZON`) and re-enter the queue.
    /// 4. Orphan cleanup evicts expectations whose fallback never resolved
    ///    and prunes their matching headers.
    /// 5. `drop_past_deadline` sweeps verified entries past their deadline.
    /// 6. Timeout sweep emits fallback fetches for late expectations.
    pub fn on_block_committed(&mut self, certified: &CertifiedBlock) -> Vec<Action> {
        let mut actions: Vec<Action> = Vec::new();
        let block = certified.block();
        let new_ts = certified.block().header().parent_qc().weighted_timestamp();
        self.expected.record_block_committed(new_ts);
        let local_ts = self.expected.local_ts();

        // Drop provisions committed in this block from the proposer queue
        // so we don't re-include the same provisions in the next proposal,
        // and tombstone them so a late re-arrival (gossip retransmit,
        // fetch fall-through, range-sync delivery) is dropped at receipt
        // rather than re-entering the queue and forcing a view change at
        // the shard validation gate. Sourced from the block's manifest so a
        // `Block::Sealed` reaching this path still enumerates its hashes
        // via the manifest's `provision_hashes`.
        let manifest = BlockManifest::from_block(block);
        let committed: std::collections::HashSet<ProvisionHash> =
            manifest.provision_hashes().iter().copied().collect();
        self.queue.on_block_committed(&committed);
        for hash in manifest.provision_hashes().iter() {
            self.committed_tombstones.register(*hash, new_ts);
        }
        self.committed_tombstones.prune(new_ts);

        // Single retention cutoff for the orphan sweep — `local_ts -
        // RETENTION_HORIZON` is the conservative point past which any
        // expectation is provably useless on every shard.
        let retention_cutoff = local_ts.minus(RETENTION_HORIZON);

        // Drop truly orphaned expectations (and their headers) whose
        // fallback fetch never resolved within `RETENTION_HORIZON`. Under
        // normal operation a header is retained exactly while its provisions
        // are outstanding; this only catches entries that would otherwise
        // leak indefinitely. Each dropped key emits an `AbandonFetch` so
        // the io_loop's `ProvisionBinding` clears the matching in-flight.
        for (source_shard, block_height) in self.expected.cleanup_orphans(retention_cutoff) {
            self.headers.remove((source_shard, block_height));
            actions.push(Action::AbandonFetch(FetchAbandon::RemoteProvisions {
                source_shard,
                block_height,
            }));
        }

        // Drop provisions whose deadline has passed but never reached
        // commit. Without this, verified provisions whose source data has
        // aged past `RETENTION_HORIZON` linger indefinitely in the proposer
        // queue and end up in proposals that peers cannot verify (their
        // paired remote header is gone). Drives the cluster into endless
        // view changes.
        if let Some(abandon) = self.drop_past_deadline() {
            actions.push(abandon);
        }

        // Lift each timed-out expectation into a fallback fetch action,
        // attaching the source shard's committee from topology.
        actions.extend(
            self.expected
                .check_timeouts(local_ts)
                .into_iter()
                .map(TimeoutEffect::into_fetch_action),
        );
        actions
    }

    /// Drop every artefact whose deadline has passed `local_committed_ts`.
    ///
    /// The deadline is `source_block_ts + RETENTION_HORIZON` — past that
    /// point every tx in the source block has expired its `validity_range`
    /// and terminated, so no shard can still reference the data. Each
    /// store carries the source ts (or a conservative receipt-time anchor
    /// for `pending_provisions`, which is provably no earlier than the
    /// source ts).
    ///
    /// Without this sweep verified provisions whose deadline has passed
    /// stay in the proposer queue forever (the existing commit-driven
    /// prune only fires when they land in a locally committed block —
    /// which they can't, because peers no longer have the matching remote
    /// header to verify them). Proposers then keep including them and the
    /// cluster falls into endless view changes around the failing
    /// proposal.
    fn drop_past_deadline(&mut self) -> Option<Action> {
        let now = self.expected.local_ts();

        self.queue.drop_past_deadline(now);

        // Pending evictions correspond to buffered payloads — both gossip-
        // and fetch-arrived — that aged out before their paired remote
        // header verified them. Any in-flight local-DA fetch on that hash
        // would otherwise sit pinned forever; the returned abandon clears it.
        let sweep = self.pipeline.drop_past_deadline(now);
        for key in sweep.evicted_keys {
            self.headers.remove(key);
        }
        (!sweep.evicted_pending.is_empty()).then(|| {
            Action::AbandonFetch(FetchAbandon::LocalProvisions {
                hashes: sweep.evicted_pending,
            })
        })
    }

    /// Immediately emit `Action::Fetch(FetchRequest::RemoteProvisions)` for all outstanding expected
    /// provisions, bypassing the normal liveness timeout.
    ///
    /// Called when urgency overrides the default patience — sync completion
    /// (validator needs to catch up before `WAVE_TIMEOUT` runs out) and the
    /// execution advance gate stalling on missing data.
    pub fn flush_expected_provisions(&mut self) -> Vec<Action> {
        self.expected
            .flush_all()
            .into_iter()
            .map(|effect| {
                info!(
                    source_shard = effect.source_shard.inner(),
                    block_height = effect.block_height.inner(),
                    "Eager fetch — immediately requesting missing provisions"
                );
                effect.into_fetch_action()
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a verified remote header from the `RemoteHeaderCoordinator`.
    ///
    /// Called when `RemoteHeaderAdmitted` is received. The header has already
    /// passed QC verification, so we store it directly as verified and:
    /// 1. Register expected provisions if waves target our shard
    /// 2. Join with any buffered provisions waiting for this header
    pub fn on_verified_remote_header(
        &mut self,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let height = certified_header.height();
        let key = (shard, height);

        // Ignore headers from our own shard.
        if shard == self.local_shard {
            return vec![];
        }

        // Only store headers that target our shard (i.e., we expect provisions).
        let local_shard = self.local_shard;
        let targets_us = certified_header
            .header()
            .waves()
            .iter()
            .any(|w| w.remote_shards().contains(&local_shard));

        if targets_us {
            // Store as verified (QC already checked by coordinator).
            self.headers.insert(key, Arc::clone(certified_header));

            let proposer = certified_header.header().proposer();
            let source_block_ts = certified_header.header().parent_qc().weighted_timestamp();
            debug!(
                shard = shard.inner(),
                height = height.inner(),
                proposer = proposer.inner(),
                "Tracking expected provisions (verified remote block targets our shard)"
            );
            self.expected
                .register(shard, height, proposer, source_block_ts);
        }

        // Join with buffered provisions waiting for this header. Drop any
        // entries whose deadline has already passed — without this gate a
        // late header arrival can reanimate provisions the local commit
        // sweep already evicted and re-enqueue them for inclusion.
        let mut actions = vec![];
        let drained = self.pipeline.drain_pending_for_key(key);
        if !drained.is_empty() {
            debug!(
                shard = shard.inner(),
                height = height.inner(),
                pending_count = drained.len(),
                "Found buffered provisions for verified header"
            );
            let local_ts = self.expected.local_ts();
            let source_block_ts = certified_header.header().parent_qc().weighted_timestamp();
            for provisions in drained {
                let provisions_hash = provisions.hash();
                if self.committed_tombstones.contains(&provisions_hash) {
                    debug!(
                        shard = shard.inner(),
                        height = height.inner(),
                        "Dropping drained provisions: already committed"
                    );
                    actions.push(Action::AbandonFetch(FetchAbandon::LocalProvisions {
                        hashes: vec![provisions_hash],
                    }));
                    continue;
                }
                if provisions.deadline(source_block_ts) <= local_ts {
                    debug!(
                        shard = shard.inner(),
                        height = height.inner(),
                        "Dropping drained provisions past deadline"
                    );
                    actions.push(Action::AbandonFetch(FetchAbandon::LocalProvisions {
                        hashes: vec![provisions_hash],
                    }));
                    continue;
                }
                actions.extend(build_verify_action(
                    self.local_shard,
                    provisions,
                    Arc::clone(certified_header),
                ));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle provisions that arrived already verified — emitted by a
    /// colocated source-shard proposer through the local-dispatch fast
    /// path (see [`ProtocolEvent::VerifiedProvisionsReceived`]). Applies
    /// the same admission guards as the unverified path and, if the
    /// matching remote header is present, admits the bundle directly
    /// without dispatching [`Action::VerifyProvisions`].
    ///
    /// Fast-path is conditional on the remote header having reached the
    /// verified state. When the header is still pending (race against
    /// `Action::VerifyRemoteHeaderQc`), the bundle falls back to the raw
    /// buffer and will re-run merkle verification once the header lands —
    /// correct, but suboptimal until the parallel remote-header
    /// preservation lands.
    pub fn on_verified_state_provisions_received(
        &mut self,
        provisions: Arc<Verified<Provisions>>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        if provisions.transactions().is_empty() {
            return vec![];
        }

        let source_shard = provisions.source_shard();
        let block_height = provisions.block_height();

        if source_shard == self.local_shard {
            return vec![];
        }

        if provisions.target_shard() != self.local_shard {
            warn!(
                source_shard = source_shard.inner(),
                target_shard = provisions.target_shard().inner(),
                local_shard = self.local_shard.inner(),
                block_height = block_height.inner(),
                "Dropping verified provisions: target_shard does not match local shard"
            );
            return vec![];
        }

        if self.committed_tombstones.contains(&provisions.hash()) {
            return vec![];
        }

        if self.pipeline.has_verified(&provisions.hash()) {
            return vec![];
        }

        let key = (source_shard, block_height);

        if let Some(verified_header) = self.headers.get(key) {
            let deadline =
                provisions.deadline(verified_header.header().parent_qc().weighted_timestamp());
            if deadline <= self.expected.local_ts() {
                debug!(
                    source_shard = source_shard.inner(),
                    block_height = block_height.inner(),
                    "Dropping verified provisions past deadline at receipt"
                );
                return vec![];
            }
            // Admit directly via the verified path; reuses the
            // tombstone, queue, and `ProvisionsAdmitted` emission logic.
            let header = Arc::clone(&verified_header);
            return self.on_state_provisions_verified(Ok(provisions), &header, now);
        }

        // Header not yet verified — fall back to the raw buffer; the
        // marker is dropped because the bundle will be re-verified
        // once the header arrives. This is the rare race path.
        debug!(
            source_shard = source_shard.inner(),
            block_height = block_height.inner(),
            count = provisions.transactions().len(),
            "Buffering verified provisions as raw (waiting for remote header)"
        );
        self.pipeline.buffer_pending(
            key,
            Arc::unwrap_or_clone(provisions).into_inner(),
            self.expected.local_ts(),
        );
        vec![]
    }

    /// Handle provisions received from a source shard proposer.
    ///
    /// All transactions in the entry share the same
    /// `(source_shard, block_height)` via the entry's proof. Joins with
    /// the corresponding verified remote block header:
    /// - If a verified header exists: emit verification with single candidate
    /// - If no header yet: buffer the provisions until
    ///   `on_verified_remote_header` delivers it
    pub fn on_state_provisions_received(&mut self, provisions: Provisions) -> Vec<Action> {
        if provisions.transactions().is_empty() {
            return vec![];
        }

        let source_shard = provisions.source_shard();
        let block_height = provisions.block_height();

        debug!(
            source_shard = source_shard.inner(),
            block_height = block_height.inner(),
            count = provisions.transactions().len(),
            "Provisions received"
        );

        // Ignore provisions from our own shard
        if source_shard == self.local_shard {
            return vec![];
        }

        // Reject provisions not destined for our shard. Indicates a proposer
        // bug, a network misroute, or an adversarial attempt — log loudly so
        // it's visible but don't propagate.
        if provisions.target_shard() != self.local_shard {
            warn!(
                source_shard = source_shard.inner(),
                target_shard = provisions.target_shard().inner(),
                local_shard = self.local_shard.inner(),
                block_height = block_height.inner(),
                "Dropping provisions: target_shard does not match local shard"
            );
            return vec![];
        }

        // Drop re-arrivals of already-committed batches. Mirrors the
        // window of `CommitDedupIndex` in the shard coordinator so a late delivery (gossip
        // retransmit, fetch fall-through, range-sync) can't slip past
        // the `(source_shard, block_height)`-keyed pipeline guards
        // after they've evicted at `source_block_ts + RETENTION_HORIZON`
        // — the shard commit window runs to `local_committed_ts +
        // RETENTION_HORIZON`, which is strictly later.
        if self.committed_tombstones.contains(&provisions.hash()) {
            return vec![];
        }

        let key = (source_shard, block_height);

        // Skip if this specific batch is already verified (duplicate
        // gossip / fetch arrival) — avoids re-dispatching verification
        // work for content we've already processed. Keyed by content
        // hash so a different proposal round at the same
        // `(shard, height)` is treated as a fresh batch, not a dup.
        if self.pipeline.has_verified(&provisions.hash()) {
            return vec![];
        }

        // Look for matching verified remote header (pre-verified by RemoteHeaderCoordinator).
        if let Some(verified_header) = self.headers.get(key) {
            // Reject if the source block has aged past `RETENTION_HORIZON` —
            // every tx in it has expired and no shard can still need this data.
            let deadline =
                provisions.deadline(verified_header.header().parent_qc().weighted_timestamp());
            if deadline <= self.expected.local_ts() {
                debug!(
                    source_shard = source_shard.inner(),
                    block_height = block_height.inner(),
                    "Dropping provisions past deadline at receipt"
                );
                return vec![];
            }
            return build_verify_action(self.local_shard, provisions, verified_header)
                .into_iter()
                .collect();
        }

        // No verified header yet — buffer the provisions
        debug!(
            source_shard = source_shard.inner(),
            block_height = block_height.inner(),
            count = provisions.transactions().len(),
            "Buffering provisions (waiting for remote header)"
        );
        self.pipeline
            .buffer_pending(key, provisions, self.expected.local_ts());
        vec![]
    }

    /// Handle the verification result for a provisions entry.
    ///
    /// If valid: store, queue, emit events.
    /// Uses the verified header returned by the action handler directly (no re-lookup).
    pub fn on_state_provisions_verified(
        &mut self,
        result: Result<Arc<Verified<Provisions>>, (Arc<Provisions>, ProvisionsVerifyError)>,
        certified_header: &Arc<Verified<CertifiedBlockHeader>>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let mut actions = vec![];

        // Clear the expectation tracker so the in-flight fallback fetch
        // (if any) is drained — once one batch verifies the shard consensus
        // expectation is satisfied. The `ProvisionsAdmitted` continuation
        // emitted below drives that drain via `FetchInput::Admitted` in
        // `drive_fetch_admission`. Explicit `AbandonFetch` is reserved
        // for paths where no admission event fires (orphan cleanup in
        // `on_block_committed`).
        //
        // The matching header stays in `self.headers` until
        // `drop_past_deadline` evicts it alongside the pipeline's
        // verified entry. Source-shard validators can broadcast distinct
        // Provisions batches for the same `(source_shard, source_height,
        // target_shard)` key — competing rounds, JMT history coverage,
        // proof generation order — and any of them may be the one a
        // remote proposer later commits. Keeping the header lets every
        // distinct batch verify against it, so the pending-block lookup
        // can find whichever hash the proposer committed.
        self.expected
            .on_provisions_verified(certified_header.shard_id(), certified_header.height());

        let verified = match result {
            Ok(v) => v,
            Err((raw, err)) => {
                warn!(
                    source_shard = raw.source_shard().inner(),
                    tx_count = raw.transactions().len(),
                    error = ?err,
                    "Provisions verification failed"
                );
                return actions;
            }
        };
        let source_block_ts = certified_header.header().parent_qc().weighted_timestamp();
        let provisions_hash = verified.hash();
        let source_shard = verified.source_shard();

        // The verify path is async: the action was dispatched at receipt,
        // before the same batch may have been committed in another block.
        // Re-enqueueing a tombstoned batch lets the proposer re-include it,
        // and peers reject the proposal at the shard dedup gate ("already
        // committed within its retention window"), forcing a view change.
        // The receipt-side tombstone check (`on_state_provisions_received`)
        // only catches arrivals that haven't started verifying yet — this
        // catches the verify-completes-after-commit race.
        if self.committed_tombstones.contains(&provisions_hash) {
            debug!(
                source_shard = source_shard.inner(),
                provisions_hash = ?provisions_hash,
                "Dropping post-commit verify result — batch already committed"
            );
            return actions;
        }

        let provisions = self.pipeline.insert_verified(verified, source_block_ts);

        // Queue for inclusion in the next block proposal. Timestamp drives
        // the dwell-time filter in `queued_provisions()` — peers need time
        // to receive/verify the provisions via gossip before the proposer
        // commits them.
        self.queue
            .enqueue(Arc::clone(&provisions), source_block_ts, now);

        debug!(
            source_shard = source_shard.inner(),
            tx_count = provisions.transactions().len(),
            "Provisions verified and queued"
        );

        // Emit ProvisionsAdmitted for downstream consumption. The source
        // block timestamp anchors retention in the io-loop provision cache.
        // Wrap as verified so the marker rides through the event into the
        // in-process consumers.
        let provisions_verifiable = Arc::new((*provisions).clone().into());
        actions.push(Action::Continuation(ProtocolEvent::ProvisionsAdmitted {
            provisions: provisions_verifiable,
            source_block_ts,
        }));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Methods (for other modules)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get queued provisions eligible for inclusion in a block
    /// proposal. Skips batches that haven't met `min_dwell_time` yet — they
    /// stay queued for a later call. Batches remain in the underlying queue
    /// until pruned on block commit.
    #[must_use]
    pub fn queued_provisions(&self, now: LocalTimestamp) -> Vec<Arc<Verified<Provisions>>> {
        self.queue.queued(now, self.expected.local_ts())
    }

    /// Look up verified provisions by their content hash. Reads the
    /// pipeline's verified map (not the raw wire-store), so callers
    /// receive the typed handle when the bundle has cleared verification.
    #[must_use]
    pub fn get_provisions_by_hash(&self, hash: ProvisionHash) -> Option<Arc<Verified<Provisions>>> {
        self.pipeline.get_provisions_by_hash(hash)
    }

    /// Shared provision store — same `Arc` the io-loop request handler
    /// reads from to serve `local_provision.request` responses.
    #[must_use]
    pub const fn store(&self) -> &Arc<ProvisionStore> {
        self.pipeline.store()
    }

    /// Look up a verified remote committed block header by shard and height.
    #[must_use]
    pub fn get_remote_header(
        &self,
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        self.headers.get((shard, height))
    }

    /// Get the number of verified remote headers.
    #[must_use]
    pub fn verified_remote_header_count(&self) -> usize {
        self.headers.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_core::FetchRequest;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BoundedVec,
        CertificateRoot, ChainOrigin, Hash, InFlightCount, LocalReceiptRoot, MerkleInclusionProof,
        ProposerTimestamp, ProvisionEntry, ProvisionTxRoot, ProvisionsRoot, QuorumCertificate,
        Round, ShardId, SignerBitfield, StateRoot, TransactionRoot, TxHash, ValidatorId,
        Verifiable, WaveId, WeightedTimestamp, WitnessSources, compute_merkle_root,
        zero_bls_signature,
    };
    use proptest::bool::ANY as ANY_BOOL;
    use proptest::collection::vec as prop_vec;

    use super::*;

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking Tests (Unverified Buffer)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a `CertifiedBlockHeader` with waves targeting `ShardId::leaf(2, 0)`
    /// (the local shard in most tests) so it gets stored in `verified_remote_headers`.
    fn make_certified_header(
        shard: ShardId,
        height: BlockHeight,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        make_certified_header_with_targets(shard, height, vec![ShardId::leaf(2, 0)])
    }

    /// Build a `CertifiedBlockHeader` whose `provision_tx_roots[local_shard]`
    /// commits to the provided tx hashes — used by tests that fire matching
    /// provisions through `on_state_provisions_received`.
    fn make_certified_header_committing(
        shard: ShardId,
        height: BlockHeight,
        local_shard: ShardId,
        tx_hashes: &[TxHash],
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let header_arc = make_certified_header_with_targets(shard, height, vec![local_shard]);
        let raw: Vec<Hash> = tx_hashes.iter().map(|h| h.into_raw()).collect();
        let root = ProvisionTxRoot::from_raw(compute_merkle_root(&raw));
        let (header, qc) = Arc::unwrap_or_clone(header_arc).into_inner().into_parts();
        let mut roots = header.provision_tx_roots().clone().into_inner();
        roots.insert(local_shard, root);
        let header = BlockHeader::new(
            header.shard_id(),
            header.height(),
            header.parent_block_hash(),
            header.parent_qc().clone(),
            header.proposer(),
            header.timestamp(),
            header.round(),
            header.is_fallback(),
            header.state_root(),
            header.transaction_root(),
            header.certificate_root(),
            header.local_receipt_root(),
            header.provision_root(),
            header.waves().clone().into_inner(),
            roots,
            header.in_flight(),
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    #[test]
    fn test_remote_header_stored_in_verified_buffer() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));
        let actions = coordinator.on_verified_remote_header(&header);
        assert!(actions.is_empty());

        // Should be in verified buffer (pre-verified by RemoteHeaderCoordinator)
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert!(
            coordinator
                .get_remote_header(ShardId::leaf(2, 1), BlockHeight::new(10))
                .is_some()
        );
    }

    #[test]
    fn test_remote_header_from_own_shard_ignored() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header = make_certified_header(ShardId::leaf(2, 0), BlockHeight::new(10));
        coordinator.on_verified_remote_header(&header);

        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        coordinator.on_verified_remote_header(&make_certified_header(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
        ));
        coordinator.on_verified_remote_header(&make_certified_header(
            ShardId::leaf(2, 1),
            BlockHeight::new(11),
        ));
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator.on_verified_remote_header(&make_certified_header(
            ShardId::leaf(2, 2),
            BlockHeight::new(10),
        ));

        assert_eq!(coordinator.verified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_overwrites() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header1 = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));
        let header2 = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));

        // Two verified headers for same (shard, height) — last wins
        coordinator.on_verified_remote_header(&header1);
        coordinator.on_verified_remote_header(&header2);

        // Only one entry per (shard, height) in verified map
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        coordinator.on_verified_remote_header(&make_certified_header(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
        ));
        coordinator.on_verified_remote_header(&make_certified_header(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
        ));

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a Provision for testing with a single transaction.
    fn make_provisions(
        tx_hash: TxHash,
        source_shard: ShardId,
        target_shard: ShardId,
        height: BlockHeight,
    ) -> Provisions {
        make_provisions_multi(vec![tx_hash], source_shard, target_shard, height)
    }

    /// Build a Provision for testing with multiple transactions.
    fn make_provisions_multi(
        tx_hashes: Vec<TxHash>,
        source_shard: ShardId,
        target_shard: ShardId,
        height: BlockHeight,
    ) -> Provisions {
        let transactions = tx_hashes
            .into_iter()
            .map(|tx_hash| ProvisionEntry::new(tx_hash, vec![], vec![], vec![]))
            .collect();
        Provisions::new(
            source_shard,
            target_shard,
            height,
            MerkleInclusionProof::dummy(),
            transactions,
        )
    }

    #[test]
    fn test_provision_received_with_header_emits_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // First: header arrives (commits to the single tx we'll send).
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);

        // Then: provisions arrives — should emit VerifyProvisions
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { provisions, .. } if provisions.transactions()[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Batch arrives before header — should buffer
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Batch arrives first — buffered
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions);

        // Then header arrives (commits to the buffered tx) — should trigger verification
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        let actions = coordinator.on_verified_remote_header(&header);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { provisions, .. } if provisions.transactions()[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            ShardId::leaf(2, 0), // own shard
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Setup: header + provisions + verification.
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        // A duplicate provisions for the same (shard, height) must short-circuit —
        // no verification action, no buffering.
        let batch2 = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(batch2);
        assert!(actions.is_empty());
        assert_eq!(coordinator.pipeline.pending_len(), 0);
    }

    #[test]
    fn test_provision_verified_emits_provisions_verified() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Setup
        let header = make_certified_header(source_shard, BlockHeight::new(10));
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());

        // Verify
        let actions = coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        // Should emit ProvisionsAdmitted
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { provisions, .. })
            if provisions.transactions()[0].tx_hash == tx_hash
        )));
    }

    #[test]
    fn test_provision_verified_invalid_does_not_emit() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        let header = make_certified_header(source_shard, BlockHeight::new(10));
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());

        // Verification fails — no certified_header returned
        let actions = coordinator.on_state_provisions_verified(
            Err((Arc::new(provisions), ProvisionsVerifyError::BadInclusion)),
            &header,
            LocalTimestamp::ZERO,
        );

        // Should NOT emit ProvisionsAdmitted
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { .. })
        )));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch Verification Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_batch_emits_single_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);

        // Send provisions with 3 transactions from the same block; header commits to them.
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| TxHash::from_raw(Hash::from_bytes(format!("tx{i}").as_bytes())))
            .collect();
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_hashes,
        );
        coordinator.on_verified_remote_header(&header);

        let provisions = make_provisions_multi(
            tx_hashes,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );

        let actions = coordinator.on_state_provisions_received(provisions);

        // Should emit exactly ONE VerifyProvisions action with all 3 transactions
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvisions { provisions, .. } => {
                assert_eq!(provisions.transactions().len(), 3);
            }
            other => panic!("Expected VerifyProvisions, got {other:?}"),
        }
    }

    #[test]
    fn test_provision_uses_single_verified_candidate() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        // Verified header from coordinator (commits to the tx we'll send).
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { certified_header, .. }
                if certified_header.height() == BlockHeight::new(10)
        ));
    }

    #[test]
    fn test_provision_header_usable_while_batch_outstanding() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);

        // Batch arrives while the header is live — verification dispatches.
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { certified_header, .. }
                if certified_header.height() == BlockHeight::new(10)
        ));
    }

    #[test]
    fn test_partial_provision_batch_rejected() {
        // Proposer's broadcast path drops a tx from a provisions. The source block
        // header commits to the full tx set; the arriving provisions contains only
        // a subset. Completeness check must reject so the fallback fetch
        // refetches a complete provisions from a peer.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_full = vec![
            TxHash::from_raw(Hash::from_bytes(b"tx_a")),
            TxHash::from_raw(Hash::from_bytes(b"tx_b")),
            TxHash::from_raw(Hash::from_bytes(b"tx_c")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_full,
        );
        coordinator.on_verified_remote_header(&header);

        // Arriving provisions is missing tx_c.
        let partial = make_provisions_multi(
            tx_full[..2].to_vec(),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(partial);

        assert!(
            actions.is_empty(),
            "partial provisions must be rejected, not dispatched"
        );
    }

    #[test]
    fn test_batch_with_missing_header_entry_rejected() {
        // Source block has no provision_tx_roots entry for our shard, yet a
        // provisions arrived claiming to target us — reject.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        // Header targets our shard via waves but has no provision_tx_roots
        // entry for us — mismatched commitment shape.
        let header = make_certified_header(source_shard, BlockHeight::new(10));
        coordinator.on_verified_remote_header(&header);

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_batch_invalid_does_not_emit() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hashes = vec![
            TxHash::from_raw(Hash::from_bytes(b"tx_ok")),
            TxHash::from_raw(Hash::from_bytes(b"tx_bad")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_hashes,
        );
        coordinator.on_verified_remote_header(&header);

        let provisions = make_provisions_multi(
            tx_hashes,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );

        coordinator.on_state_provisions_received(provisions.clone());

        // Entire provisions fails verification
        let actions = coordinator.on_state_provisions_verified(
            Err((Arc::new(provisions), ProvisionsVerifyError::BadInclusion)),
            &header,
            LocalTimestamp::ZERO,
        );

        // Verification failed — no ProvisionsAdmitted emitted
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { .. })
        )));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (Fallback Detection) Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a `CertifiedBlockHeader` that claims provisions target the given shards.
    fn make_certified_header_with_targets(
        shard: ShardId,
        height: BlockHeight,
        provision_targets: Vec<ShardId>,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        // Each target shard gets its own single-dependency wave so that
        // `provision_targets()` on the resulting header yields the input set.
        let waves: Vec<WaveId> = provision_targets
            .into_iter()
            .map(|s| WaveId::new(shard, height, std::collections::BTreeSet::from([s])))
            .collect();
        let header = BlockHeader::new(
            shard,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::leaf(2, 0), ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1000 + height.inner()),
            Round::INITIAL,
            false,
            StateRoot::from_raw(Hash::from_bytes(
                format!("root_{shard}_{height}").as_bytes(),
            )),
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            waves,
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            shard,
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// Nominal block spacing used by tests to synthesize `weighted_timestamp_ms`
    /// from block heights. Ratios against timeout constants below preserve the
    /// old "block count" intuition when reading the tests.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    /// A genesis-shaped QC carrying `weighted_ts_ms`. The commit clock reads a
    /// block's `parent_qc` weighted timestamp, so fixtures anchor their time
    /// there while keeping the QC genesis-shaped (so `is_genesis()` holds).
    fn genesis_qc_at(shard: ShardId, weighted_ts_ms: u64) -> QuorumCertificate {
        let g = QuorumCertificate::genesis(shard, ChainOrigin::ROOT);
        QuorumCertificate::new(
            g.block_hash(),
            g.shard_id(),
            g.height(),
            g.parent_block_hash(),
            g.round(),
            g.signers().clone(),
            g.aggregated_signature(),
            WeightedTimestamp::from_millis(weighted_ts_ms),
        )
    }

    /// Make a minimal `Block` at the given height for `on_block_committed` calls.
    /// The block's `parent_qc` weighted timestamp is `height * TEST_BLOCK_INTERVAL_MS`.
    fn make_block(height: BlockHeight) -> CertifiedBlock {
        let header = BlockHeader::new(
            ShardId::leaf(2, 0),
            height,
            BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            genesis_qc_at(ShardId::leaf(2, 0), height.inner() * TEST_BLOCK_INTERVAL_MS),
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block = Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = {
            let __qc = QuorumCertificate::genesis(ShardId::leaf(2, 0), ChainOrigin::ROOT);
            QuorumCertificate::new(
                block.hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(height.inner() * TEST_BLOCK_INTERVAL_MS),
            )
        };
        CertifiedBlock::new_unchecked(block, qc)
    }

    #[test]
    fn test_expected_provision_tracked_when_header_targets_local_shard() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Remote shard 1 block targets shard 0 (our shard)
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);

        // Should have one expected provision
        assert_eq!(coordinator.expected.len(), 1);
    }

    #[test]
    fn test_expected_provision_not_tracked_when_header_does_not_target_local_shard() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Remote shard 1 block targets shard 2 (NOT our shard)
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 2)],
        );
        coordinator.on_verified_remote_header(&header);

        // Header should NOT be stored (not expecting provisions from it)
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected.len(), 0);
    }

    #[test]
    fn test_expected_provision_cleared_on_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let header = make_certified_header_with_targets(
            source_shard,
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.expected.len(), 1);

        // Batch arrives and is verified
        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        // Expected provision should be cleared
        assert_eq!(coordinator.expected.len(), 0);
    }

    #[test]
    fn test_timeout_emits_request_missing_provisions() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime local clock with a first commit so the expected-provision
        // entry stamped below gets a real baseline (not the zero sentinel).
        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        // Remote header arrives targeting our shard; discovered_at stamped at ts=500ms.
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);

        // Advance blocks — should not emit before the timeout threshold.
        // discovered_at = 500ms; fires when now_ms - 500 >= 5000 → h = 11.
        for h in 2..=10 {
            let block = make_block(BlockHeight::new(h));
            let actions = coordinator.on_block_committed(&block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 11, age = 5500 - 500 = 5000 >= PROVISION_FALLBACK_TIMEOUT → fires.
        let block = make_block(BlockHeight::new(11));
        let actions = coordinator.on_block_committed(&block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Fetch(FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                preferred,
                ..
            }) if *source_shard == ShardId::leaf(2, 1)
                && *block_height == BlockHeight::new(10)
                && *preferred == Some(ValidatorId::new(0))
        ));
    }

    #[test]
    fn test_pregenesis_header_retrostamped_on_first_commit() {
        // Regression: without retro-stamping, an expected_provisions entry
        // recorded while `local_committed_ts == 0` would report a ~epoch-ms
        // age on the very next commit and trigger an immediate fallback,
        // bypassing PROVISION_FALLBACK_TIMEOUT entirely.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Remote header arrives BEFORE any local block commits.
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.expected.len(), 1);

        // First local commit at ts=500ms. Should NOT fire — the pre-genesis
        // entry has just been retro-stamped to 500ms.
        let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(1)));
        assert!(
            actions.is_empty(),
            "Pre-genesis entry must be retro-stamped, not fire immediately"
        );

        // Fires on schedule from the retro-stamp baseline, not absolute zero.
        for h in 2..=10 {
            let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
            assert!(actions.is_empty(), "Should not emit at height {h}");
        }
        let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(11)));
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_no_re_emission_after_initial_request() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
            assert!(
                actions.is_empty(),
                "Should never re-emit after initial request (height {h})"
            );
        }
    }

    #[test]
    fn test_no_timeout_when_provision_verified_in_time() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let header = make_certified_header_with_targets(
            source_shard,
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        // Batch arrives and is verified before timeout
        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
            assert!(
                actions.is_empty(),
                "Should not request at height {h} (provision already verified)"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Verified-provisions clear expected tracking
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verified_provisions_clear_expected_tracking() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);

        let header = make_certified_header_with_targets(
            source_shard,
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.expected.len(), 1);

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        // Expected-tracking entry is cleared; the io_loop's
        // `ProvisionsAdmitted` interception drives any in-flight fetch
        // admission downstream.
        assert_eq!(coordinator.expected.len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Committed-provision tombstone (re-admission protection)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a `CertifiedBlock` at `height` carrying a single provisions
    /// batch — needed to exercise `on_block_committed`'s tombstone path
    /// which reads `block.provisions()`.
    fn make_block_with_provisions(
        height: BlockHeight,
        provisions: Arc<Provisions>,
    ) -> CertifiedBlock {
        let header = BlockHeader::new(
            ShardId::leaf(2, 0),
            height,
            BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            genesis_qc_at(ShardId::leaf(2, 0), height.inner() * TEST_BLOCK_INTERVAL_MS),
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let provisions_verifiable: Arc<Verifiable<Provisions>> =
            Arc::new(Arc::unwrap_or_clone(provisions).into());
        let block = Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::from(vec![provisions_verifiable])),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::leaf(2, 0),
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(height.inner() * TEST_BLOCK_INTERVAL_MS),
        );
        CertifiedBlock::new_unchecked(block, qc)
    }

    /// Regression: under cross-shard packed hosting, the local-serve
    /// fall-through in `Network::request` re-routes a fetch through a
    /// peer when the co-located vnode's local store has aged out the
    /// requested batch. Without the tombstone, that wire arrival lands
    /// in `on_state_provisions_received` past `pipeline.verified`'s
    /// `source_block_ts + RETENTION_HORIZON` eviction, sails through the
    /// `has_verified` guard, re-enters the proposer queue, and the next
    /// proposal includes a batch the shard consensus
    /// `validate_no_duplicate_provisions` window still rejects —
    /// triggering a view-change loop.
    #[test]
    fn test_committed_tombstone_drops_re_arrival_after_pipeline_eviction() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime the local clock so the expected-provision entry stamps a
        // real baseline rather than the zero sentinel.
        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let source_height = BlockHeight::new(10);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let provisions = make_provisions(tx_hash, source_shard, ShardId::leaf(2, 0), source_height);
        let provisions_hash = provisions.hash();

        // Header arrives — its QC carries ts=0 (`make_certified_header_*`
        // hard-codes `WeightedTimestamp::ZERO`), so `pipeline.verified`
        // evicts at `local_ts > 0 + RETENTION_HORIZON`.
        let header = make_certified_header_committing(
            source_shard,
            source_height,
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);

        // First arrival → queued.
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions.clone(),
            ))),
            &header,
            LocalTimestamp::ZERO,
        );
        assert_eq!(coordinator.queue.queue_len(), 1);

        // Walk forward many blocks before committing the batch, so the
        // local-commit-ts anchor for the tombstone sits well after the
        // source-block-ts anchor for `pipeline.verified`. Without this
        // gap the two evict at near-identical local-ts values and the
        // race window the tombstone closes wouldn't be observable in a
        // unit test.
        for h in 2..=100 {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        // Commit a block containing this batch at h=101 — queue drains,
        // tombstone registers anchored on this block's commit ts
        // (~50_500ms with TEST_BLOCK_INTERVAL_MS=500).
        let commit_h = BlockHeight::new(101);
        let committing_block = make_block_with_provisions(commit_h, Arc::new(provisions.clone()));
        coordinator.on_block_committed(&committing_block);
        assert_eq!(coordinator.queue.queue_len(), 0);
        assert!(coordinator.committed_tombstones.contains(&provisions_hash));

        // Walk to a height where `pipeline.verified` (deadline = 0 +
        // RETENTION_HORIZON) has evicted but the tombstone (deadline =
        // commit_ts + RETENTION_HORIZON) is still live. Pick the
        // midpoint: `RETENTION_HORIZON_blocks + commit_h/2`.
        let retention_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        let mid_h = retention_blocks + commit_h.inner() / 2;
        for h in 102..=mid_h {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }
        assert_eq!(
            coordinator.pipeline.verified_len(),
            0,
            "pipeline.verified should have evicted by now"
        );
        assert!(
            coordinator.committed_tombstones.contains(&provisions_hash),
            "tombstone should outlive pipeline.verified eviction"
        );

        // Late re-arrival (e.g. fetch fall-through, gossip retransmit).
        // The tombstone must drop it before it reaches the verify path
        // and re-enters the queue.
        let actions = coordinator.on_state_provisions_received(provisions);
        assert!(actions.is_empty(), "re-arrival should be dropped silently");
        assert_eq!(
            coordinator.queue.queue_len(),
            0,
            "re-arrival must not re-enter the proposer queue"
        );
    }

    #[test]
    fn test_committed_tombstone_drops_pending_drain_re_arrival() {
        // Variant: provisions arrive twice while header is missing
        // (buffered as pending). After the first pair commits, a later
        // header re-arrival drains pending — the drain path must check
        // the tombstone too.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let source_height = BlockHeight::new(10);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let provisions = make_provisions(tx_hash, source_shard, ShardId::leaf(2, 0), source_height);
        let provisions_hash = provisions.hash();

        let header = make_certified_header_committing(
            source_shard,
            source_height,
            ShardId::leaf(2, 0),
            &[tx_hash],
        );

        // First lifecycle: header, receive, verify, commit.
        coordinator.on_verified_remote_header(&header);
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions.clone(),
            ))),
            &header,
            LocalTimestamp::ZERO,
        );
        let committing_block =
            make_block_with_provisions(BlockHeight::new(2), Arc::new(provisions.clone()));
        coordinator.on_block_committed(&committing_block);
        assert!(coordinator.committed_tombstones.contains(&provisions_hash));

        // Second lifecycle: provisions re-arrive before any header. The
        // receipt-time tombstone guard short-circuits at receipt — no
        // pending buffering, no drain work, no re-enqueue.
        coordinator.on_state_provisions_received(provisions);
        let actions = coordinator.on_verified_remote_header(&header);
        assert!(
            actions.is_empty(),
            "tombstoned re-arrival should be dropped at receipt — no drain work"
        );
        assert_eq!(coordinator.queue.queue_len(), 0);
        let _ = provisions_hash;
    }

    #[test]
    fn test_orphan_cleanup_emits_abandon_fetch() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime local clock so the expected-provision entry gets a real
        // baseline rather than the zero sentinel retro-stamped on first commit.
        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let block_height = BlockHeight::new(10);

        let header = make_certified_header_with_targets(
            source_shard,
            block_height,
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);

        // The orphan sweep keys on the source block's weighted timestamp.
        // This synthetic header carries a genesis (zero) parent-QC timestamp,
        // so the entry ages out the first commit whose retention cutoff goes
        // positive — i.e. once the local clock passes RETENTION_HORIZON.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;

        // Walk up to (but not past) the orphan cutoff — no Abandon yet.
        for h in 2..=orphan_cutoff_blocks {
            let actions = coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
            assert!(
                !actions.iter().any(|a| matches!(a, Action::AbandonFetch(_))),
                "AbandonFetch fired before orphan cutoff at h={h}"
            );
        }

        // One past the cutoff — orphan sweep drops the expected entry and
        // emits AbandonFetch for the dropped key.
        let actions =
            coordinator.on_block_committed(&make_block(BlockHeight::new(orphan_cutoff_blocks + 1)));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::RemoteProvisions {
                    source_shard: s,
                    block_height: h,
                }) if *s == source_shard && *h == block_height
            )),
            "Expected AbandonFetch from orphan cleanup, got: {actions:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Header Retention Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_header_retained_while_batch_outstanding() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Advance local well past any old time-based cutoff but short of the
        // orphan threshold. Header stays because its provisions hasn't verified yet.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 1..=(orphan_cutoff_blocks / 2) {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        assert_eq!(
            coordinator.verified_remote_header_count(),
            1,
            "Header must be retained while expected_provisions entry is live"
        );
    }

    #[test]
    fn test_header_retained_after_first_batch_verification() {
        // Source-shard validators can broadcast distinct `Provisions` batches
        // for the same `(source_shard, source_height, target_shard)` key —
        // competing rounds, JMT history coverage, proof generation order.
        // Each verifies against the same remote header, and any of them may
        // be the one a remote proposer later commits. The header must stay
        // available so a second-arriving batch can verify against it.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );

        assert_eq!(
            coordinator.verified_remote_header_count(),
            1,
            "Header must stay until retention deadline so additional batches \
             for the same source key can verify against it"
        );
    }

    #[test]
    fn test_orphan_header_dropped_after_cutoff() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime local clock so the expected-provision entry gets a real
        // baseline rather than the zero sentinel retro-stamped on first commit.
        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        // Header arrives but the provisions never does — this is the orphan case
        // the long-horizon sweep guards against.
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        coordinator.on_verified_remote_header(&header);
        assert_eq!(coordinator.expected.len(), 1);

        // Not yet past the orphan cutoff — still retained. The sweep keys on
        // the source block's weighted timestamp, which for this synthetic
        // header is the genesis (zero) parent-QC timestamp, so the entry ages
        // out once the local clock first passes RETENTION_HORIZON.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 2..=orphan_cutoff_blocks {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.expected.len(), 1);

        // One past — orphan sweep drops header and expected entry together.
        coordinator.on_block_committed(&make_block(BlockHeight::new(orphan_cutoff_blocks + 1)));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected.len(), 0);
    }

    #[test]
    fn test_queued_batch_dropped_when_source_aged_past_horizon() {
        // Reproduces the cluster deadlock: a provisions verified long ago whose
        // source data has aged past `RETENTION_HORIZON` must be evicted from
        // the proposer queue, otherwise it gets re-proposed forever and
        // peers without the matching remote header view-change endlessly.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Verify a provisions sourced from shard 1 at height 10
        // (weighted_ts = 5_000ms in the test clock).
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"old-tx"));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            LocalTimestamp::ZERO,
        );
        assert_eq!(coordinator.queue.queue_len(), 1);
        assert_eq!(coordinator.pipeline.verified_len(), 1);

        // Advance local commits until past `source_block_ts + RETENTION_HORIZON`.
        // Source ts = 10 * 500ms = 5_000ms. Deadline = 5_000ms + 324_000ms.
        let deadline_height = (u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS)
            + 11;
        for h in 100..=deadline_height + 1 {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        assert_eq!(
            coordinator.queue.queue_len(),
            0,
            "queued provisions past deadline must be evicted"
        );
        assert_eq!(
            coordinator.pipeline.verified_len(),
            0,
            "verified provisions past deadline must be evicted"
        );
    }

    #[test]
    fn test_receive_drops_batch_when_paired_header_aged_out() {
        // Header arrived long ago; receiving a fresh provisions for that
        // already-aged source must short-circuit instead of dispatching a
        // verification that no peer can use.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx-old"));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&header);

        // Advance local commits well past the source's deadline.
        let deadline_height = (u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS)
            + 11;
        for h in 100..=deadline_height + 1 {
            coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
        }

        // The header itself has been swept by the orphan path; re-add it so
        // the receipt path can see it for the test.
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        coordinator
            .headers
            .insert((ShardId::leaf(2, 1), BlockHeight::new(10)), header);

        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(provisions);
        assert!(
            actions.is_empty(),
            "past-deadline provisions must be dropped without dispatching verification"
        );
    }

    #[test]
    fn test_pending_buffer_evicted_when_received_too_long_ago() {
        // Batch buffered waiting for a header that never arrives; once
        // `received_at + RETENTION_HORIZON` is past `local_committed_ts`
        // the entry must be evicted by the deadline sweep — and its hash
        // surfaced as an `AbandonFetch::LocalProvisions` so any pinned
        // local-DA fetch on that hash releases its slot.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime local clock so received_at is non-zero.
        coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx-pending"));
        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let provisions_hash = provisions.hash();
        coordinator.on_state_provisions_received(provisions);
        assert_eq!(coordinator.pipeline.pending_len(), 1);

        // Advance past the deadline horizon measured from received_at,
        // accumulating actions so the eviction commit's abandon surfaces
        // regardless of which iteration crosses the threshold.
        let cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        let mut sweep_actions = Vec::new();
        for h in 2..=cutoff_blocks + 3 {
            sweep_actions.extend(coordinator.on_block_committed(&make_block(BlockHeight::new(h))));
        }

        assert_eq!(
            coordinator.pipeline.pending_len(),
            0,
            "pending entry past `received_at + RETENTION_HORIZON` must be evicted"
        );
        let abandon = sweep_actions.iter().find_map(|a| match a {
            Action::AbandonFetch(FetchAbandon::LocalProvisions { hashes }) => Some(hashes),
            _ => None,
        });
        assert_eq!(
            abandon,
            Some(&vec![provisions_hash]),
            "deadline sweep must abandon the pinned local-DA fetch for the dropped hash"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Dwell-time Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Helper: verify a provisions through the coordinator, stamping `added_at`
    /// at `now`.
    fn verify_batch_into_queue(
        coordinator: &mut ProvisionCoordinator,
        source_shard: ShardId,
        height: BlockHeight,
        tx_hash: TxHash,
        now: LocalTimestamp,
    ) {
        let header =
            make_certified_header_committing(source_shard, height, ShardId::leaf(2, 0), &[tx_hash]);
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(tx_hash, source_shard, ShardId::leaf(2, 0), height);
        coordinator.on_state_provisions_received(provisions.clone());
        coordinator.on_state_provisions_verified(
            Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                provisions,
            ))),
            &header,
            now,
        );
    }

    #[test]
    fn test_dwell_time_zero_yields_immediately() {
        let mut coordinator = ProvisionCoordinator::with_config(
            ShardId::leaf(2, 0),
            ProvisionConfig {
                min_dwell_time: Duration::ZERO,
            },
        );
        let now = LocalTimestamp::from_millis(1_000);
        verify_batch_into_queue(
            &mut coordinator,
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            now,
        );

        assert_eq!(
            coordinator.queued_provisions(now).len(),
            1,
            "Zero dwell time should expose the provisions immediately"
        );
    }

    #[test]
    fn test_dwell_time_filters_young_batch() {
        let mut coordinator = ProvisionCoordinator::with_config(
            ShardId::leaf(2, 0),
            ProvisionConfig {
                min_dwell_time: Duration::from_millis(500),
            },
        );

        // Verify at t=1.0s
        verify_batch_into_queue(
            &mut coordinator,
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            LocalTimestamp::from_millis(1_000),
        );

        // t=1.2s — dwell not met (200ms < 500ms)
        assert_eq!(
            coordinator
                .queued_provisions(LocalTimestamp::from_millis(1_200))
                .len(),
            0,
            "Batch younger than min_dwell_time must be skipped"
        );

        // t=1.5s — exactly at dwell
        assert_eq!(
            coordinator
                .queued_provisions(LocalTimestamp::from_millis(1_500))
                .len(),
            1,
            "Batch at min_dwell_time must become eligible"
        );
    }

    #[test]
    fn test_dwell_time_mixed_eligibility() {
        let mut coordinator = ProvisionCoordinator::with_config(
            ShardId::leaf(2, 0),
            ProvisionConfig {
                min_dwell_time: Duration::from_millis(200),
            },
        );

        // t=1.0s: verify old provisions
        verify_batch_into_queue(
            &mut coordinator,
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            TxHash::from_raw(Hash::from_bytes(b"tx_old")),
            LocalTimestamp::from_millis(1_000),
        );

        // t=1.3s: verify young provisions
        verify_batch_into_queue(
            &mut coordinator,
            ShardId::leaf(2, 1),
            BlockHeight::new(11),
            TxHash::from_raw(Hash::from_bytes(b"tx_young")),
            LocalTimestamp::from_millis(1_300),
        );

        // t=1.4s: old provisions dwelled 400ms (eligible), young provisions dwelled
        // 100ms (still blocked).
        let eligible = coordinator.queued_provisions(LocalTimestamp::from_millis(1_400));
        assert_eq!(eligible.len(), 1);
        assert_eq!(
            eligible[0].transactions()[0].tx_hash,
            TxHash::from_raw(Hash::from_bytes(b"tx_old"))
        );
    }

    proptest::proptest! {
        /// After enough commits to push `local_committed_ts` past every
        /// inserted provisions's deadline, every retention store must be empty.
        /// Reproduces the cluster-deadlock invariant in property form: no
        /// matter the mix of (verified, queued, pending) batches and their
        /// source heights, the sweep eventually drains them.
        #[test]
        fn prop_all_stores_empty_after_advancing_past_every_deadline(
            // Up to 16 batches, each with a source height in [1, 50] —
            // their source ts (height * 500ms) anchors the deadline.
            source_heights in prop_vec(1u64..=50, 0..=16),
            // Some batches will be left pending (no header arrives), some
            // will be verified. A bool per provisions picks the path.
            verify_path in prop_vec(ANY_BOOL, 0..=16),
        ) {
            let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
            // Prime so received_at is non-zero on pending entries.
            coordinator.on_block_committed(&make_block(BlockHeight::new(1)));

            let n = source_heights.len().min(verify_path.len());
            for i in 0..n {
                let source_height = BlockHeight::new(source_heights[i]);
                let tx_hash =
                    TxHash::from_raw(Hash::from_bytes(format!("tx-{i}").as_bytes()));
                let provisions = make_provisions(
                    tx_hash,
                    ShardId::leaf(2, 1),
                    ShardId::leaf(2, 0),
                    source_height,
                );

                if verify_path[i] {
                    // Verified path: header arrives, then the provisions.
                    let header = make_certified_header_committing(
                        ShardId::leaf(2, 1),
                        source_height,
                        ShardId::leaf(2, 0),
                        &[tx_hash],
                    );
                    coordinator.on_verified_remote_header(&header);
                    coordinator.on_state_provisions_received(provisions.clone());
                    coordinator.on_state_provisions_verified(
                        Ok(Arc::new(Verified::<Provisions>::new_unchecked_for_test(
                            provisions,
                        ))),
                        &header,
                        LocalTimestamp::ZERO,
                    );
                } else {
                    // Pending path: provisions arrives without header.
                    coordinator.on_state_provisions_received(provisions);
                }
            }

            // Advance well past `RETENTION_HORIZON` from the latest
            // possible source ts (50 * 500ms = 25_000ms = 25s).
            let cutoff_ms =
                25_000 + u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX) + 5 * TEST_BLOCK_INTERVAL_MS;
            let cutoff_height = cutoff_ms / TEST_BLOCK_INTERVAL_MS;
            for h in 2..=cutoff_height {
                coordinator.on_block_committed(&make_block(BlockHeight::new(h)));
            }

            proptest::prop_assert_eq!(coordinator.queue.queue_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.verified_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.pending_len(), 0);
        }
    }
}
