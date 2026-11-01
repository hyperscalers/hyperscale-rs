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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchIds, ProtocolEvent, ProvisionVerdict};
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_storage::CommittedProvisions;
use hyperscale_types::{
    Anchor, BlockHeight, BlockManifest, CertifiedBlock, CertifiedBlockHeader, CommittedClock,
    ForkFence, LocalTimestamp, Provision, ProvisionCount, ProvisionHash, RETENTION_HORIZON,
    ShardId, TopologySchedule, Verified,
};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::expected::{ExpectedProvisionTracker, Held, Released};
use crate::pipeline::ProvisionPipeline;
use crate::queue::QueuedProvisionBuffer;
use crate::store::ProvisionStore;
use crate::verification::{build_verify_actions, judge_owed, refused};
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

impl ProvisionMemoryStats {
    /// Every readout as a `(field, value)` pair for the metrics backend.
    ///
    /// The destructure is the drift guard: a field added above does not
    /// compile here until it is given a gauge.
    #[must_use]
    pub fn gauges(&self) -> Vec<(&'static str, usize)> {
        let Self {
            verified_remote_headers,
            pending_provisions,
            verified_provisions,
            expected_provisions,
            provisions_by_hash,
            queued_provisions,
        } = *self;
        vec![
            ("verified_remote_headers", verified_remote_headers),
            ("pending_provisions", pending_provisions),
            ("verified_provisions", verified_provisions),
            ("expected_provisions", expected_provisions),
            ("provisions_by_hash", provisions_by_hash),
            ("queued_provisions", queued_provisions),
        ]
    }
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
    /// The shard's committed-provision window, shared rather than
    /// mirrored. Chain-lifetime: seeded from the store on recovery, so a
    /// restarted node drops an already-committed re-arrival instead of
    /// re-verifying it for a whole retention horizon.
    committed_provisions: Arc<CommittedProvisions>,

    /// This validator's home shard. Used to gate inbound provisions:
    /// only batches whose target shard matches ours are admitted.
    local_shard: ShardId,

    /// The node's gossip-timed fork fence, engaged and cleared by the node:
    /// provisions from a fenced shard at or above its forked height are
    /// dropped like the attested recovery fence — but engaged on gossip,
    /// not the beacon record. Held until the shard's recovery completes;
    /// the attested
    /// [`recovery_fences`](hyperscale_types::TopologySchedule::recovery_fences)
    /// govern validity over the fold-to-completion window.
    fork_fence: ForkFence,

    /// Each shard's effective fence frontier as of its last purge sweep —
    /// the min of the attested recovery frontier and any engaged fork
    /// fence. The commit sweep re-purges a shard only when this changes;
    /// receipt-time fencing handles everything that arrives in between.
    /// Entries drop when the shard leaves both fence sources.
    purged_fences: BTreeMap<ShardId, BlockHeight>,
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
        Self::with_config(local_shard, ProvisionConfig::default())
    }

    /// Create a new `ProvisionCoordinator` with the given config and a fresh
    /// local [`ProvisionStore`].
    #[must_use]
    pub fn with_config(local_shard: ShardId, config: ProvisionConfig) -> Self {
        Self::with_config_and_store(
            local_shard,
            config,
            Arc::new(ProvisionStore::new()),
            Arc::new(CommittedProvisions::new()),
            CommittedClock::default(),
            ForkFence::new(),
        )
    }

    /// Create a new `ProvisionCoordinator` wired to an externally-owned
    /// [`ProvisionStore`]. Production nodes share the store with the
    /// io-loop so `local_provision.request` handlers read from the same
    /// source of truth this coordinator writes to. `clock` and
    /// `fork_fence` are the node's own, shared with the coordinators
    /// beside this one.
    #[must_use]
    pub fn with_config_and_store(
        local_shard: ShardId,
        config: ProvisionConfig,
        store: Arc<ProvisionStore>,
        committed_provisions: Arc<CommittedProvisions>,
        clock: CommittedClock,
        fork_fence: ForkFence,
    ) -> Self {
        let queue = QueuedProvisionBuffer::new(config.min_dwell_time);
        Self {
            headers: Arc::new(VerifiedHeaderBuffer::new()),
            pipeline: ProvisionPipeline::new(store),
            expected: ExpectedProvisionTracker::new(clock),
            queue,
            committed_provisions,
            local_shard,
            fork_fence,
            purged_fences: BTreeMap::new(),
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
    /// 3. Orphan cleanup evicts expectations whose fallback never resolved
    ///    and prunes their matching headers.
    /// 4. `drop_past_deadline` sweeps verified entries past their deadline.
    /// 5. Recovery-fence sweep purges artifacts from shards whose pending
    ///    recovery fences them above the attested frontier.
    /// 7. Timeout sweep emits fallback fetches for late expectations.
    pub fn on_block_committed(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let mut actions: Vec<Action> = Vec::new();
        let block = certified.block();
        let new_ts = certified.block().header().parent_qc().weighted_timestamp();
        self.expected
            .record_block_committed(new_ts, topology_schedule.windows().origin());
        let local_ts = self.expected.local_ts();

        // Drop provisions committed in this block from the proposer queue
        // so we don't re-include the same provisions in the next proposal.
        // Sourced from the block's manifest so a `Block::Sealed` reaching
        // this path still enumerates its hashes via the manifest's
        // `provision_hashes`.
        //
        // The committed-provision window itself is written by the shard
        // coordinator on the same commit and only read here: one writer,
        // because a window two coordinators both maintain is two windows
        // that have to agree.
        let manifest = BlockManifest::from_block(block);
        let committed: std::collections::HashSet<ProvisionHash> =
            manifest.provision_hashes().iter().copied().collect();
        self.queue.on_block_committed(&committed);
        // Single retention cutoff for the orphan sweep, one span for
        // every source block. A crossing an outbound leg consumes is
        // owed to that consumer past this, but what carries it there is
        // the issuer offering it again off a fresh block — a fresh
        // header, a fresh expectation — and not this one waiting.
        let retention_cutoff = local_ts.minus(RETENTION_HORIZON);

        // Drop truly orphaned expectations (and their headers) whose
        // fallback fetch never resolved inside that span. Under normal
        // operation a header is retained exactly while its provisions
        // are outstanding; this only catches entries that would otherwise
        // leak indefinitely, an index nobody can build among them. Each
        // dropped key abandons every index it asked for, so the shard
        // loop's `ProvisionBinding` clears the matching in-flight.
        let orphaned = self.expected.cleanup_orphans(retention_cutoff);
        for released in &orphaned {
            self.headers
                .remove((released.source_shard, released.block_height));
        }
        actions.extend(self.abandon(&orphaned));

        // Drop provisions whose deadline has passed but never reached
        // commit. Without this, verified provisions whose source data has
        // aged past `RETENTION_HORIZON` linger indefinitely in the proposer
        // queue and end up in proposals that peers cannot verify (their
        // paired remote header is gone). Drives the cluster into endless
        // view changes.
        if let Some(abandon) = self.drop_past_deadline() {
            actions.push(abandon);
        }

        // Purge artifacts fenced by a pending recovery or a gossip-timed
        // fork fence: above the effective frontier the fenced content can
        // never verify (INV-SEC-8 for the attested fence; both conflicting
        // branches for the fork fence), so parked bundles, pre-admitted
        // headers, and queued provisions only burn proposal rounds.
        // Watermarked per shard: receipt-time fencing already drops late
        // arrivals, so the sweep re-runs only when a shard's effective
        // frontier changes — a recovery folding, a fence engaging or
        // tightening — not four retains per fence per commit.
        let head = topology_schedule.head();
        let mut frontiers: BTreeMap<ShardId, BlockHeight> = head
            .pending_recoveries()
            .iter()
            .map(|(&shard, recovery)| (shard, recovery.attested_frontier))
            .collect();
        for (shard, frontier) in self.fork_fence.engaged() {
            frontiers
                .entry(shard)
                .and_modify(|effective| *effective = (*effective).min(frontier))
                .or_insert(frontier);
        }
        self.purged_fences
            .retain(|shard, _| frontiers.contains_key(shard));
        for (shard, frontier) in frontiers {
            if self.purged_fences.get(&shard) != Some(&frontier) {
                self.purged_fences.insert(shard, frontier);
                actions.extend(self.purge_fenced_shard(shard, frontier));
            }
        }

        // Lift each timed-out expectation into a fallback fetch action,
        // attaching the source shard's committee from topology.
        actions.extend(
            self.expected
                .check_timeouts(local_ts)
                .into_iter()
                .map(|effect| effect.into_fetch_action(self.local_shard)),
        );
        actions
    }

    /// Drop every held artifact from `shard` strictly above `frontier` —
    /// headers, queued provisions, parked bundles, and expectations —
    /// returning the `AbandonFetch`es for any in-flight fetches this
    /// stranded. Idempotent; shared by the attested recovery fence and the
    /// gossip-timed fork fence.
    fn purge_fenced_shard(&mut self, shard: ShardId, frontier: BlockHeight) -> Vec<Action> {
        let mut actions = Vec::new();
        self.headers.remove_above(shard, frontier);
        self.queue.purge_fenced(shard, frontier);
        let evicted = self.pipeline.purge_fenced(shard, frontier);
        if !evicted.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::LocalProvisions(evicted)));
        }
        let stranded = self.expected.purge_fenced(shard, frontier);
        actions.extend(self.abandon(&stranded));
        actions
    }

    /// The `AbandonFetch` letting go of every index `released` asked for,
    /// if any.
    fn abandon(&self, released: &[Released]) -> Option<Action> {
        let ids: Vec<_> = released
            .iter()
            .flat_map(|released| released.ids(self.local_shard))
            .collect();
        (!ids.is_empty()).then(|| Action::AbandonFetch(FetchIds::RemoteProvisions(ids)))
    }

    /// The fetch actions holding one leaf calls for: letting go of a
    /// completed expectation's asks, and asking for the rest of one that
    /// just learned its count.
    fn follow(&self, held: Held) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(released) = held.completed {
            actions.extend(self.abandon(&[released]));
        }
        if let Some(ask) = held.ask {
            actions.push(ask.into_fetch_action(self.local_shard));
        }
        actions
    }

    /// The node engaged its fork fence for `shard` at `frontier`: purge
    /// what already got through above it, rather than wait for the next
    /// commit's sweep. Content arriving later is refused at receipt.
    pub fn on_fork_fenced(&mut self, shard: ShardId, frontier: BlockHeight) -> Vec<Action> {
        self.purge_fenced_shard(shard, frontier)
    }

    /// Whether a provision from `(shard, height)` is fenced — by the
    /// attested recovery record (validity, resolved from the head) or the
    /// local gossip-timed fork fence (quiesce). Either drops it before
    /// admission so no block depending on it can assemble.
    fn is_fenced(
        &self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> bool {
        topology_schedule.recovery_fences(shard, height) || self.fork_fence.is_fenced(shard, height)
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
        (!sweep.evicted_pending.is_empty())
            .then(|| Action::AbandonFetch(FetchIds::LocalProvisions(sweep.evicted_pending)))
    }

    /// Release every fetch a part this coordinator is dropping was wanted
    /// by.
    ///
    /// A drop has to satisfy the asker. Admission releases two bindings —
    /// the local one keyed by content hash and the remote one keyed by
    /// `(source, target, height, index)` — so a path that drops the part
    /// instead has to release both, or the ids outlive every reason for
    /// them: `Fetch::handle_request` keeps an unanswered id pending for
    /// the process's life, and the matching remote header is pinned with
    /// it until the orphan cleanup a full retention horizon later.
    fn retire_fetches_for(part: &Provision) -> Vec<Action> {
        vec![
            Action::AbandonFetch(FetchIds::LocalProvisions(vec![part.hash()])),
            Action::AbandonFetch(FetchIds::RemoteProvisions(vec![(
                part.source_shard(),
                part.target_shard(),
                part.block_height(),
                part.leaf().index,
            )])),
        ]
    }

    /// Retire `part` as already held — committed or already verified —
    /// which counts its leaf as held toward its expectation. Only a part
    /// whose leaf has walked to its header's root reaches here: a
    /// committed one through the voters that admitted it, a verified one
    /// through this node.
    fn retire_held(&mut self, part: &Provision) -> Vec<Action> {
        let held = self.hold(part);
        let mut actions = Self::retire_fetches_for(part);
        actions.extend(self.follow(held));
        actions
    }

    /// Count `part`'s leaf as held toward its expectation.
    fn hold(&mut self, part: &Provision) -> Held {
        self.expected.on_part_held(
            part.source_shard(),
            part.block_height(),
            part.leaf().index,
            part.leaf().count,
        )
    }

    /// Immediately emit an `Action::Fetch` of remote provisions for all outstanding expected
    /// provisions, bypassing the normal liveness timeout.
    ///
    /// Called when urgency overrides the default patience — sync completion
    /// (validator needs to catch up before `MAX_FINALIZATION_DELAY` runs out) and the
    /// execution advance gate stalling on missing data.
    pub fn flush_expected_provisions(&mut self) -> Vec<Action> {
        let local_shard = self.local_shard;
        self.expected
            .flush_all()
            .into_iter()
            .map(|effect| {
                info!(
                    source_shard = effect.source_shard.inner(),
                    block_height = effect.block_height.inner(),
                    "Eager fetch — immediately requesting missing provisions"
                );
                effect.into_fetch_action(local_shard)
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a verified remote header from the `RemoteHeaderCoordinator`.
    ///
    /// Called when `RemoteHeaderAdmitted` is received. Certification only
    /// arms the expectation tracker (the fallback fetch); the header opens
    /// for provision verification on [`Self::on_committed_remote_header`],
    /// once its commit proof is held — a bare QC does not establish that
    /// the source shard canonicalized the block, and an f+1..2f corrupt
    /// committee can certify a sibling that never commits.
    pub fn on_verified_remote_header(
        &mut self,
        certified_header: &Verified<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let height = certified_header.height();

        // Ignore headers from our own shard.
        if shard == self.local_shard {
            return vec![];
        }

        // Only track headers that owe us a bundle. The commitment is the
        // header's own `provision_tx_roots` entry — ticks can name our
        // shard without the source owing state (a counterpart with
        // nothing to attest), and an expectation keyed on tick naming
        // would fetch a bundle that never exists.
        let targets_us = certified_header
            .header()
            .provision_tx_roots()
            .contains_key(&self.local_shard);

        if targets_us {
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

        vec![]
    }

    /// Handle a commit-proven remote header from the `RemoteHeaderCoordinator`.
    ///
    /// Called when `RemoteHeaderCommitted` is received: the header's
    /// committing structure is held, so its provisions become consumable.
    /// Stores the header (opening verification for later arrivals) and
    /// drains bundles parked on it. Consults the recovery fence first — a
    /// header above a recovering shard's attested frontier is rejected
    /// network-wide, whatever its proof status.
    pub fn on_committed_remote_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified_header: &Verified<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let height = certified_header.height();
        let key = (shard, height);

        // Ignore headers from our own shard.
        if shard == self.local_shard {
            return vec![];
        }

        if self.is_fenced(topology_schedule, shard, height) {
            let hashes = self.pipeline.drain_pending_for_key(key);
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                dropped = hashes.len(),
                "Dropping commit-proven remote header above a pending recovery's attested frontier"
            );
            let hashes: Vec<_> = hashes.iter().map(Provision::hash).collect();
            if hashes.is_empty() {
                return vec![];
            }
            return vec![Action::AbandonFetch(FetchIds::LocalProvisions(hashes))];
        }

        // Only store headers that owe us a bundle — the same
        // `provision_tx_roots` predicate the expectation tracker keys on.
        let targets_us = certified_header
            .header()
            .provision_tx_roots()
            .contains_key(&self.local_shard);

        let mut actions = vec![];
        if targets_us {
            // Store as verified (QC + commit proof already checked by the
            // remote-header coordinator).
            self.headers.insert(key, certified_header.clone());
            // A count witness that arrived first is checked now.
            if let Some(count) = self.expected.take_parked_count(shard, height) {
                actions.extend(self.check_count(certified_header, count));
            }
        }

        // Join with buffered provisions waiting for this header. Drop any
        // entries whose deadline has already passed — without this gate a
        // late header arrival can reanimate provisions the local commit
        // sweep already evicted and re-enqueue them for inclusion.
        let drained = self.pipeline.drain_pending_for_key(key);
        if !drained.is_empty() {
            debug!(
                shard = shard.inner(),
                height = height.inner(),
                pending_count = drained.len(),
                "Found buffered provisions for commit-proven header"
            );
            let local_ts = self.expected.local_ts();
            let source_block_ts = certified_header.header().parent_qc().weighted_timestamp();
            let mut owed = Vec::with_capacity(drained.len());
            for part in drained {
                if self.committed_provisions.contains(&part.hash()) {
                    debug!(
                        shard = shard.inner(),
                        height = height.inner(),
                        "Dropping drained part: already committed"
                    );
                    actions.extend(self.retire_held(&part));
                    continue;
                }
                if part.deadline(source_block_ts) <= local_ts {
                    debug!(
                        shard = shard.inner(),
                        height = height.inner(),
                        "Dropping drained part past deadline"
                    );
                    actions.extend(Self::retire_fetches_for(&part));
                    continue;
                }
                owed.push(part);
            }
            actions.extend(build_verify_actions(
                self.local_shard,
                owed,
                certified_header,
            ));
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether a part from `(source_shard, block_height)` addressed to
    /// `target_shard` is one this coordinator takes at all: from another
    /// shard, owed to this one, and not fenced. Every part names exactly
    /// one transaction, so an engagement echo with no entries passes.
    fn takes(
        &self,
        topology_schedule: &TopologySchedule,
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
    ) -> bool {
        if source_shard == self.local_shard {
            return false;
        }
        if target_shard != self.local_shard {
            // A proposer bug, a network misroute, or an adversarial
            // attempt — log loudly so it's visible but don't propagate.
            warn!(
                source_shard = source_shard.inner(),
                target_shard = target_shard.inner(),
                local_shard = self.local_shard.inner(),
                block_height = block_height.inner(),
                "Dropping provision: target_shard does not match local shard"
            );
            return false;
        }
        // Recovery fence: parts from a recovering shard above its
        // attested frontier are rejected network-wide — buffering them
        // would park garbage that can never verify.
        if self.is_fenced(topology_schedule, source_shard, block_height) {
            warn!(
                source_shard = source_shard.inner(),
                block_height = block_height.inner(),
                "Dropping provision above a pending recovery's attested frontier"
            );
            return false;
        }
        true
    }

    /// Handle parts that arrived already verified — emitted by a
    /// colocated source-shard proposer through the local-dispatch fast
    /// path (see [`ProtocolEvent::VerifiedProvisionsReceived`]). Applies
    /// the same admission guards as the unverified path and, if the
    /// matching remote header is present, admits each part directly
    /// without dispatching [`ProvisionAction::VerifyProvisions`](hyperscale_core::ProvisionAction::VerifyProvisions).
    ///
    /// Fast-path is conditional on the remote header having reached the
    /// verified state. When the header is still pending (race against
    /// `ConsensusAction::VerifyRemoteHeaderQc`), a part falls back to the
    /// raw buffer and will re-run merkle verification once the header
    /// lands.
    pub fn on_verified_state_provisions_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        parts: Vec<Verified<Provision>>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for part in parts {
            let source_shard = part.source_shard();
            let block_height = part.block_height();
            if !self.takes(
                topology_schedule,
                source_shard,
                part.target_shard(),
                block_height,
            ) {
                continue;
            }

            if self.committed_provisions.contains(&part.hash())
                || self.pipeline.has_verified(&part.hash())
            {
                actions.extend(self.retire_held(&part));
                continue;
            }

            let key = (source_shard, block_height);

            if let Some(verified_header) = self.headers.get(key) {
                let deadline =
                    part.deadline(verified_header.header().parent_qc().weighted_timestamp());
                if deadline <= self.expected.local_ts() {
                    debug!(
                        source_shard = source_shard.inner(),
                        block_height = block_height.inner(),
                        "Dropping verified part past deadline at receipt"
                    );
                    actions.extend(Self::retire_fetches_for(&part));
                    continue;
                }
                // This host built the part, but a proposer replaying its
                // block after a restart skips transactions it never
                // routed and builds parts on a short leaf list, so each
                // meets the header's root like any other.
                let anchor = Anchor::of(&verified_header);
                let verdict = match judge_owed(self.local_shard, &part, &verified_header) {
                    Ok(()) => Ok(part),
                    Err(refusal) => Err((part.into_inner(), refusal)),
                };
                if verdict.is_err() {
                    actions.push(refused(vec![verdict], anchor));
                    continue;
                }
                // Admit directly via the verified path; reuses the
                // tombstone, queue, and `ProvisionsAdmitted` emission logic.
                actions.extend(self.on_state_provisions_verified(vec![verdict], anchor, now));
                continue;
            }

            // Header not yet verified — fall back to the raw buffer; the
            // marker is dropped because the part will be re-verified
            // once the header arrives. This is the rare race path.
            debug!(
                source_shard = source_shard.inner(),
                block_height = block_height.inner(),
                "Buffering verified part as raw (waiting for remote header)"
            );
            // A refusal at the ceiling needs no cancellation: an in-flight
            // fetch for this part is still wanted, and a part nobody
            // fetched is re-acquired by the expectation the commit-proven
            // header registers.
            let _buffered =
                self.pipeline
                    .buffer_pending(key, part.into_inner(), self.expected.local_ts());
        }
        actions
    }

    /// Handle parts received from a source shard, by gossip or fetch.
    ///
    /// Each part stands alone. Those whose source header is commit-proven
    /// are judged against it and verified together, one action per
    /// source block; the rest are buffered until
    /// `on_committed_remote_header` delivers their header.
    pub fn on_state_provisions_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        parts: Vec<Provision>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut by_block: BTreeMap<(ShardId, BlockHeight), Vec<Provision>> = BTreeMap::new();
        for part in parts {
            let source_shard = part.source_shard();
            let block_height = part.block_height();
            if !self.takes(
                topology_schedule,
                source_shard,
                part.target_shard(),
                block_height,
            ) {
                continue;
            }

            // Drop re-arrivals of already-committed parts. Mirrors the
            // window of `CommitDedupIndex` in the shard coordinator so a
            // late delivery (gossip retransmit, fetch fall-through,
            // range-sync) can't slip past the `(source_shard,
            // block_height)`-keyed pipeline guards after they've evicted
            // at `source_block_ts + RETENTION_HORIZON` — the shard commit
            // window runs to `local_committed_ts + RETENTION_HORIZON`,
            // which is strictly later. And skip a part already verified
            // (duplicate gossip / fetch arrival), keyed by content hash.
            if self.committed_provisions.contains(&part.hash())
                || self.pipeline.has_verified(&part.hash())
            {
                actions.extend(self.retire_held(&part));
                continue;
            }
            by_block
                .entry((source_shard, block_height))
                .or_default()
                .push(part);
        }

        for (key, parts) in by_block {
            // Look for the matching commit-proven remote header.
            let Some(verified_header) = self.headers.get(key) else {
                debug!(
                    source_shard = key.0.inner(),
                    block_height = key.1.inner(),
                    count = parts.len(),
                    "Buffering provisions (waiting for remote header)"
                );
                // A refusal at the ceiling needs no cancellation: an
                // in-flight fetch for a part is still wanted, and a part
                // nobody fetched is re-acquired by the expectation the
                // commit-proven header registers.
                for part in parts {
                    let _buffered =
                        self.pipeline
                            .buffer_pending(key, part, self.expected.local_ts());
                }
                continue;
            };
            // Reject if the source block has aged past `RETENTION_HORIZON`
            // — every tx in it has expired and no shard can still need
            // this data.
            let source_ts = verified_header.header().parent_qc().weighted_timestamp();
            if source_ts.plus(RETENTION_HORIZON) <= self.expected.local_ts() {
                debug!(
                    source_shard = key.0.inner(),
                    block_height = key.1.inner(),
                    "Dropping provisions past deadline at receipt"
                );
                for part in &parts {
                    actions.extend(Self::retire_fetches_for(part));
                }
                continue;
            }
            actions.extend(build_verify_actions(
                self.local_shard,
                parts,
                &verified_header,
            ));
        }
        actions
    }

    /// Handle the verdicts for parts checked against `anchor`.
    ///
    /// Each verified part is stored, queued and announced, keyed by the
    /// `anchor` it was checked against (no re-lookup), and its leaf
    /// counts as held. A refusal leaves the expectation armed so another
    /// peer's part can still satisfy it.
    pub fn on_state_provisions_verified(
        &mut self,
        results: Vec<ProvisionVerdict>,
        anchor: Anchor,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let mut actions = vec![];
        for result in results {
            // A refused part satisfies nothing, whether its leaf missed
            // the header's root or its entries their proof: the
            // expectation stays armed, so a fallback fetch not yet sent
            // still goes out on its timeout. The node releases an
            // in-flight fetch for the part as failed on this same result,
            // which retries it off the peer that answered.
            let verified = match result {
                Ok(v) => v,
                Err((raw, err)) => {
                    warn!(
                        source_shard = raw.source_shard().inner(),
                        block_height = raw.block_height().inner(),
                        tx_hash = %raw.tx_hash(),
                        error = ?err,
                        "Provision refused"
                    );
                    continue;
                }
            };
            actions.extend(self.admit(verified, anchor, now));
        }
        actions
    }

    /// Handle a fetch answer's count witness for what the block at
    /// `(source_shard, block_height)` owes `target_shard`.
    ///
    /// It teaches only the count, and only once checked: the stated count
    /// and merkle root must wrap to the commit-proven header's root for
    /// this shard. One arriving before that header is held for it. One
    /// that wraps to anything else is refused and teaches nothing.
    pub fn on_provision_count(
        &mut self,
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        count: ProvisionCount,
    ) -> Vec<Action> {
        if target_shard != self.local_shard
            || source_shard == self.local_shard
            || !self.expected.wants_count(source_shard, block_height)
        {
            return Vec::new();
        }
        let Some(header) = self.headers.get((source_shard, block_height)) else {
            self.expected.park_count(source_shard, block_height, count);
            return Vec::new();
        };
        self.check_count(&header, count)
    }

    /// Hold `count` to `header`'s root for this shard, asking for what a
    /// true one teaches is missing.
    fn check_count(
        &mut self,
        header: &Verified<CertifiedBlockHeader>,
        count: ProvisionCount,
    ) -> Vec<Action> {
        let owed = header
            .header()
            .provision_tx_roots()
            .get(&self.local_shard)
            .copied();
        if owed != Some(count.root()) {
            warn!(
                source_shard = header.shard_id().inner(),
                block_height = header.height().inner(),
                count = count.count,
                "Provision count witness refused: it does not wrap to the header's root"
            );
            record_fetch_response_refused("provision", "count_mismatch");
            return Vec::new();
        }
        self.expected
            .on_count_checked(header.shard_id(), header.height(), count.count)
            .map(|ask| ask.into_fetch_action(self.local_shard))
            .into_iter()
            .collect()
    }

    /// Admit one verified part.
    ///
    /// The in-flight fallback fetch (if any) drains on the
    /// `ProvisionsAdmitted` continuation emitted below.
    ///
    /// The matching header stays in `self.headers` until
    /// `drop_past_deadline` evicts it alongside the pipeline's verified
    /// entry. Source-shard validators can broadcast distinct parts for
    /// the same leaf — JMT history coverage, proof generation order — and
    /// any of them may be the one a remote proposer later commits.
    /// Keeping the header lets every distinct part verify against it, so
    /// the pending-block lookup can find whichever hash the proposer
    /// committed.
    fn admit(
        &mut self,
        verified: Verified<Provision>,
        anchor: Anchor,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let source_block_ts = anchor.ts;
        let provision_hash = verified.hash();
        let source_shard = verified.source_shard();

        // The verify path is async: the action was dispatched at receipt,
        // before the same part may have been committed in another block.
        // Re-enqueueing a tombstoned part lets the proposer re-include it,
        // and peers reject the proposal at the shard dedup gate ("already
        // committed within its retention window"), forcing a view change.
        // The receipt-side tombstone check (`on_state_provisions_received`)
        // only catches arrivals that haven't started verifying yet — this
        // catches the verify-completes-after-commit race.
        if self.committed_provisions.contains(&provision_hash) {
            debug!(
                source_shard = source_shard.inner(),
                provision_hash = ?provision_hash,
                "Dropping post-commit verify result — part already committed"
            );
            return self.retire_held(&verified);
        }

        let held = self.hold(&verified);
        let mut actions = self.follow(held);
        let provision = self.pipeline.insert_verified(verified, source_block_ts);

        // Queue for inclusion in the next block proposal. Timestamp drives
        // the dwell-time filter in `queued_provisions()` — peers need time
        // to receive/verify the part via gossip before the proposer
        // commits it.
        self.queue.enqueue(provision.clone(), source_block_ts, now);

        debug!(
            source_shard = source_shard.inner(),
            tx_hash = %provision.tx_hash(),
            "Provision verified and queued"
        );

        // Emit ProvisionsAdmitted for downstream consumption. The source
        // block timestamp anchors retention in the io-loop provision cache.
        // Wrap as verified so the marker rides through the event into the
        // in-process consumers.
        actions.push(Action::Continuation(ProtocolEvent::ProvisionsAdmitted {
            provision: provision.into(),
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
    pub fn queued_provisions(&self, now: LocalTimestamp) -> Vec<Verified<Provision>> {
        self.queue.queued(now, self.expected.local_ts())
    }

    /// The earliest instant strictly after `now` at which a queued batch
    /// [`Self::queued_provisions`] withholds for its dwell becomes
    /// eligible. `None` when no live batch dwells.
    #[must_use]
    pub fn next_eligible_at(&self, now: LocalTimestamp) -> Option<LocalTimestamp> {
        self.queue.next_eligible_at(now, self.expected.local_ts())
    }

    /// Look up verified provisions by their content hash. Reads the
    /// pipeline's verified map (not the raw wire-store), so callers
    /// receive the typed handle when the bundle has cleared verification.
    #[must_use]
    pub fn get_provisions_by_hash(&self, hash: ProvisionHash) -> Option<Verified<Provision>> {
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
    ) -> Option<Verified<CertifiedBlockHeader>> {
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
    use hyperscale_core::{FetchRequest, ProvisionAction, ProvisionRefusal};
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        AggregateSignature, Anchor, Block, BlockHash, BlockHeader, BlockHeaderParts, ChainOrigin,
        Hash, LeafPath, MerkleInclusionProof, NetworkDefinition, ProposerTimestamp, ProvisionParts,
        ProvisionTxRoot, ProvisionVerifyError, QuorumCertificate, RETENTION_HORIZON, Round,
        ShardId, SignerBitfield, StateRoot, TopologySnapshot, TxHash, ValidatorId, ValidatorSet,
        Verifiable, WeightedTimestamp, WitnessSources, provision_leaf,
    };
    use proptest::bool::ANY as ANY_BOOL;
    use proptest::collection::vec as prop_vec;

    use super::*;

    /// A minimal head-only schedule with no pending recoveries — the
    /// unfenced ordinary case every non-fence test runs under.
    fn sched() -> TopologySchedule {
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        )))
    }

    /// Deliver a header the way the orchestrator does once its commit proof
    /// is held: admission (arms the expectation tracker), then the committed
    /// event (opens the header for verification and drains parked bundles).
    fn deliver_committed_header(
        coordinator: &mut ProvisionCoordinator,
        header: &Verified<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let mut actions = coordinator.on_verified_remote_header(header);
        actions.extend(coordinator.on_committed_remote_header(&sched(), header));
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking Tests (Unverified Buffer)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a `CertifiedBlockHeader` with ticks targeting `ShardId::leaf(2, 0)`
    /// (the local shard in most tests) so it gets stored in `verified_remote_headers`.
    fn make_certified_header(
        shard: ShardId,
        height: BlockHeight,
    ) -> Verified<CertifiedBlockHeader> {
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
    ) -> Verified<CertifiedBlockHeader> {
        let certified = make_certified_header_with_targets(shard, height, vec![local_shard]);
        let leaves: Vec<Hash> = tx_hashes.iter().map(|h| provision_leaf(*h)).collect();
        let root = ProvisionTxRoot::over(&leaves);
        let (header, qc) = certified.into_inner().into_parts();
        let mut roots = header.provision_tx_roots().clone();
        roots
            .insert(local_shard, root)
            .expect("a list written out in a test");
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: header.shard_id(),
            height: header.height(),
            parent_block_hash: header.parent_block_hash(),
            parent_qc: header.parent_qc().clone().into(),
            proposer: header.proposer(),
            timestamp: header.timestamp(),
            round: header.round(),
            is_fallback: header.is_fallback(),
            state_root: header.state_root(),
            body_root: header.body_root(),
            provision_tx_roots: roots,
            txs_in_flight: header.txs_in_flight(),
            ..Default::default()
        });
        Verified::new_unchecked_for_test(CertifiedBlockHeader::new(header, qc))
    }

    #[test]
    fn test_remote_header_stored_in_verified_buffer() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));
        let actions = deliver_committed_header(&mut coordinator, &header);
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
        deliver_committed_header(&mut coordinator, &header);

        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        coordinator.on_committed_remote_header(
            &sched(),
            &make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10)),
        );
        coordinator.on_committed_remote_header(
            &sched(),
            &make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(11)),
        );
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator.on_committed_remote_header(
            &sched(),
            &make_certified_header(ShardId::leaf(2, 2), BlockHeight::new(10)),
        );

        assert_eq!(coordinator.verified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_overwrites() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let header1 = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));
        let header2 = make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10));

        // Two verified headers for same (shard, height) — last wins
        coordinator.on_committed_remote_header(&sched(), &header1);
        coordinator.on_committed_remote_header(&sched(), &header2);

        // Only one entry per (shard, height) in verified map
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        coordinator.on_committed_remote_header(
            &sched(),
            &make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10)),
        );
        coordinator.on_committed_remote_header(
            &sched(),
            &make_certified_header(ShardId::leaf(2, 1), BlockHeight::new(10)),
        );

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Commit-proof and recovery-fence tests
    // ═══════════════════════════════════════════════════════════════════════

    /// A head-only schedule whose `shard` is under a pending recovery
    /// fenced at `frontier`.
    fn sched_recovering(shard: ShardId, frontier: BlockHeight) -> TopologySchedule {
        use hyperscale_types::{Epoch, RecoveryCause, ShardRecovery};
        TopologySchedule::single(Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(Vec::new()),
            )
            .with_pending_recoveries(
                std::iter::once((
                    shard,
                    ShardRecovery {
                        cause: RecoveryCause::Halt,
                        rotated_at: Epoch::new(2),
                        retained: Vec::new(),
                        attested_frontier: frontier,
                    },
                ))
                .collect(),
            ),
        ))
    }

    #[test]
    fn provisions_park_until_the_source_block_is_commit_proven() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        let height = BlockHeight::new(10);
        let tx_hash = TxHash::from(Hash::from_bytes(b"parked_tx"));
        let header =
            make_certified_header_committing(source, height, ShardId::leaf(2, 0), &[tx_hash]);

        // Admission (a bare QC) arms the expectation but opens nothing.
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(tx_hash, source, ShardId::leaf(2, 0), height);
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Provisions(ProvisionAction::VerifyProvisions { .. })
            )),
            "a merely-certified source block must not open provision verification"
        );

        // The commit proof arrives — the parked bundle drains into
        // verification.
        let actions = coordinator.on_committed_remote_header(&sched(), &header);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Provisions(ProvisionAction::VerifyProvisions { .. })
            )),
            "the committed event must drain the parked bundle"
        );
    }

    #[test]
    fn fenced_provisions_dropped_at_receipt() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        let frontier = BlockHeight::new(5);
        let recovering = sched_recovering(source, frontier);

        // Above the frontier: dropped outright, nothing parked.
        let above = make_provisions(
            TxHash::from(Hash::from_bytes(b"above")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(6),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&recovering, vec![above])
                .is_empty()
        );
        assert_eq!(coordinator.memory_stats().pending_provisions, 0);

        // At the frontier: legitimate history, parked awaiting its header.
        let at = make_provisions(
            TxHash::from(Hash::from_bytes(b"at")),
            source,
            ShardId::leaf(2, 0),
            frontier,
        );
        coordinator.on_state_provisions_received(&recovering, vec![at]);
        assert_eq!(coordinator.memory_stats().pending_provisions, 1);
    }

    #[test]
    fn fenced_committed_header_is_rejected_and_drops_parked_bundles() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        let height = BlockHeight::new(10);
        let tx_hash = TxHash::from(Hash::from_bytes(b"fenced_tx"));
        let header =
            make_certified_header_committing(source, height, ShardId::leaf(2, 0), &[tx_hash]);

        // Parked before the recovery folded.
        coordinator.on_verified_remote_header(&header);
        let provisions = make_provisions(tx_hash, source, ShardId::leaf(2, 0), height);
        coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        // The recovery folds below the header; its committed event must not
        // open verification, and the parked bundle is abandoned.
        let recovering = sched_recovering(source, BlockHeight::new(5));
        let actions = coordinator.on_committed_remote_header(&recovering, &header);
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Provisions(ProvisionAction::VerifyProvisions { .. })
            )),
            "a fenced header must not open verification"
        );
        assert!(
            actions.iter().any(|a| matches!(a, Action::AbandonFetch(_))),
            "parked bundles above the frontier are abandoned"
        );
        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn recovery_fold_purges_fenced_artifacts_on_commit() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        let frontier = BlockHeight::new(5);
        let above = BlockHeight::new(9);
        let tx_hash = TxHash::from(Hash::from_bytes(b"purged_tx"));
        let header =
            make_certified_header_committing(source, above, ShardId::leaf(2, 0), &[tx_hash]);

        // Header opened and a bundle parked at another height pre-fold.
        deliver_committed_header(&mut coordinator, &header);
        let parked = make_provisions(
            TxHash::from(Hash::from_bytes(b"parked_other")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(8),
        );
        coordinator.on_state_provisions_received(&sched(), vec![parked]);
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.memory_stats().pending_provisions, 1);
        assert_eq!(coordinator.memory_stats().expected_provisions, 1);

        // The recovery folds; the next commit sweep purges everything the
        // fence rejects.
        let recovering = sched_recovering(source, frontier);
        let actions = coordinator.on_block_committed(&recovering, &make_block(BlockHeight::new(1)));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.memory_stats().pending_provisions, 0);
        assert_eq!(coordinator.memory_stats().expected_provisions, 0);
        assert!(
            actions.iter().any(|a| matches!(a, Action::AbandonFetch(_))),
            "purged fetches must be abandoned"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Gossip-timed fork fence
    // ═══════════════════════════════════════════════════════════════════════

    /// Engage the node's fence the way the node does: on the shared
    /// handle, then the coordinator's purge.
    fn engage(
        coordinator: &mut ProvisionCoordinator,
        shard: ShardId,
        fork_height: BlockHeight,
    ) -> Vec<Action> {
        coordinator
            .fork_fence
            .engage(shard, fork_height, None)
            .map_or_else(Vec::new, |frontier| {
                coordinator.on_fork_fenced(shard, frontier)
            })
    }

    #[test]
    fn fork_fence_drops_at_and_above_fork_and_admits_below() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        // Fork at height 5: content at or above 5 is fenced.
        assert!(
            engage(&mut coordinator, source, BlockHeight::new(5)).is_empty(),
            "nothing held yet to purge"
        );

        // At the fork height → dropped (abstention: a block depending on it
        // can never assemble, so the replica never votes on it).
        let at_fork = make_provisions(
            TxHash::from(Hash::from_bytes(b"at_fork")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(5),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&sched(), vec![at_fork])
                .is_empty()
        );
        // Above the fork → dropped.
        let above = make_provisions(
            TxHash::from(Hash::from_bytes(b"above")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(9),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&sched(), vec![above])
                .is_empty()
        );
        assert_eq!(coordinator.memory_stats().pending_provisions, 0);

        // Below the fork — pre-fork history, unaffected — parks normally.
        let below = make_provisions(
            TxHash::from(Hash::from_bytes(b"below")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(4),
        );
        coordinator.on_state_provisions_received(&sched(), vec![below]);
        assert_eq!(coordinator.memory_stats().pending_provisions, 1);

        // A different shard is untouched.
        let other = make_provisions(
            TxHash::from(Hash::from_bytes(b"other")),
            ShardId::leaf(2, 2),
            ShardId::leaf(2, 0),
            BlockHeight::new(9),
        );
        coordinator.on_state_provisions_received(&sched(), vec![other]);
        assert_eq!(coordinator.memory_stats().pending_provisions, 2);
    }

    #[test]
    fn engaging_fork_fence_purges_already_admitted_content() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from(Hash::from_bytes(b"purge_tx"));
        let header = make_certified_header_committing(
            source,
            BlockHeight::new(9),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );

        // A header opened and a bundle parked before the fence engages.
        deliver_committed_header(&mut coordinator, &header);
        let parked = make_provisions(
            TxHash::from(Hash::from_bytes(b"parked")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(8),
        );
        coordinator.on_state_provisions_received(&sched(), vec![parked]);
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.memory_stats().pending_provisions, 1);

        // Engaging the fence purges everything above the fork frontier.
        let actions = engage(&mut coordinator, source, BlockHeight::new(5));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.memory_stats().pending_provisions, 0);
        assert!(actions.iter().any(|a| matches!(a, Action::AbandonFetch(_))));
    }

    /// A head-only schedule whose `shard` carries a completed recovery.
    fn sched_recovered(shard: ShardId, frontier: BlockHeight) -> TopologySchedule {
        use hyperscale_types::{Epoch, RecoveryBinding};
        TopologySchedule::single(Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(Vec::new()),
            )
            .with_recoveries(
                std::iter::once((
                    shard,
                    vec![RecoveryBinding {
                        rotated_at: Epoch::new(2),
                        attested_frontier: frontier,
                        completed: true,
                    }],
                ))
                .collect(),
            ),
        ))
    }

    #[test]
    fn fork_fence_holds_through_the_fold_and_lifts_on_completion() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let source = ShardId::leaf(2, 1);
        engage(&mut coordinator, source, BlockHeight::new(5));

        // While fenced, an above-fork provision is dropped.
        let during = make_provisions(
            TxHash::from(Hash::from_bytes(b"during")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(6),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&sched(), vec![during])
                .is_empty()
        );

        // The attested recovery folds — the local fence holds through the
        // recovery window, so the same height is still dropped.
        let recovering = sched_recovering(source, BlockHeight::new(4));
        coordinator.on_block_committed(&recovering, &make_block(BlockHeight::new(1)));
        let mid_window = make_provisions(
            TxHash::from(Hash::from_bytes(b"mid_window")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(6),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&sched(), vec![mid_window])
                .is_empty()
        );

        // The recovery completes (the fresh committee's first crossing) —
        // the node clears its fence, and the same height parks normally.
        let recovered = sched_recovered(source, BlockHeight::new(4));
        assert_eq!(
            coordinator
                .fork_fence
                .clear_completed(|shard| recovered.head().latest_completed_recovery(shard)),
            vec![source]
        );
        coordinator.on_block_committed(&recovered, &make_block(BlockHeight::new(2)));
        let after = make_provisions(
            TxHash::from(Hash::from_bytes(b"after")),
            source,
            ShardId::leaf(2, 0),
            BlockHeight::new(6),
        );
        coordinator.on_state_provisions_received(&sched(), vec![after]);
        assert_eq!(coordinator.memory_stats().pending_provisions, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// The one part of a block owing `target_shard` a single transaction.
    fn make_provisions(
        tx_hash: TxHash,
        source_shard: ShardId,
        target_shard: ShardId,
        height: BlockHeight,
    ) -> Provision {
        Provision::dummy(source_shard, target_shard, height, tx_hash)
    }

    /// The parts of a block owing `target_shard` `tx_hashes`, each at its
    /// leaf under the root over all of them.
    fn make_provisions_multi(
        tx_hashes: Vec<TxHash>,
        source_shard: ShardId,
        target_shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Provision> {
        let leaves: Vec<Hash> = tx_hashes.iter().map(|tx| provision_leaf(*tx)).collect();
        tx_hashes
            .into_iter()
            .zip(LeafPath::all(&leaves))
            .map(|(tx_hash, leaf)| {
                Provision::new(ProvisionParts {
                    source_shard,
                    target_shard,
                    block_height: height,
                    source_block_ts: WeightedTimestamp::ZERO,
                    tx_hash,
                    entries: Capped::empty(),
                    proof: MerkleInclusionProof::new(Vec::new()),
                    leaf,
                })
            })
            .collect()
    }

    /// Every part as checked and verified.
    fn verified(parts: Vec<Provision>) -> Vec<ProvisionVerdict> {
        parts
            .into_iter()
            .map(|part| Ok(Verified::<Provision>::new_unchecked_for_test(part)))
            .collect()
    }

    #[test]
    fn test_provision_received_with_header_emits_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // First: header arrives (commits to the single tx we'll send).
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);

        // Then: provisions arrives — should emit VerifyProvisions
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Provisions(ProvisionAction::VerifyProvisions { parts, .. })
                if parts[0].tx_hash() == tx_hash
        ));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Batch arrives before header — should buffer
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Batch arrives first — buffered
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        // Then header arrives (commits to the buffered tx) — should trigger verification
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        let actions = deliver_committed_header(&mut coordinator, &header);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Provisions(ProvisionAction::VerifyProvisions { parts, .. })
                if parts[0].tx_hash() == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            ShardId::leaf(2, 0), // own shard
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        assert!(actions.is_empty());
    }

    /// Every path that drops a bundle must release both fetch bindings
    /// admission would have released — the local one keyed by content
    /// hash and the remote one keyed by `(source, target, height)`.
    /// Asserting merely that a drop is silent is what let the leak stand:
    /// an unanswered id stays pending for the life of the process.
    fn assert_abandons_both(actions: &[Action]) {
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::LocalProvisions(_)))),
            "the local-provisions fetch was not released: {actions:?}",
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::RemoteProvisions(_)))),
            "the remote-provisions fetch was not released: {actions:?}",
        );
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Setup: header + provisions + verification.
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
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
        // Short-circuited — no verification action, no buffering — but the
        // drop still satisfies whoever asked for it.
        let actions = coordinator.on_state_provisions_received(&sched(), vec![batch2]);
        assert!(
            actions.iter().all(|a| matches!(a, Action::AbandonFetch(_))),
            "a dropped duplicate dispatches no work",
        );
        assert_abandons_both(&actions);
        assert_eq!(coordinator.pipeline.pending_len(), 0);
    }

    #[test]
    fn test_provision_verified_emits_provisions_verified() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        // Setup
        let header = make_certified_header(source_shard, BlockHeight::new(10));
        deliver_committed_header(&mut coordinator, &header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);

        // Verify
        let actions = coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );

        // Should emit ProvisionsAdmitted
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { provision, .. })
            if provision.tx_hash() == tx_hash
        )));
    }

    #[test]
    fn test_provision_verified_invalid_does_not_emit() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let source_shard = ShardId::leaf(2, 1);

        let header = make_certified_header(source_shard, BlockHeight::new(10));
        deliver_committed_header(&mut coordinator, &header);
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);

        // Verification fails — no certified_header returned
        let actions = coordinator.on_state_provisions_verified(
            vec![Err((
                provisions,
                ProvisionRefusal::Unproven(ProvisionVerifyError::BadInclusion),
            ))],
            Anchor::of(&header),
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

    /// One message's parts for one source block verify in one action.
    #[test]
    fn test_provision_batch_emits_single_verification() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);

        // Send provisions with 3 transactions from the same block; header commits to them.
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| TxHash::from(Hash::from_bytes(format!("tx{i}").as_bytes())))
            .collect();
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_hashes,
        );
        deliver_committed_header(&mut coordinator, &header);

        let provisions = make_provisions_multi(
            tx_hashes,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );

        let actions = coordinator.on_state_provisions_received(&sched(), provisions);

        // Should emit exactly ONE VerifyProvisions action with all 3 parts
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Provisions(ProvisionAction::VerifyProvisions { parts, .. }) => {
                assert_eq!(parts.len(), 3);
            }
            other => panic!("Expected VerifyProvisions, got {other:?}"),
        }
    }

    #[test]
    fn test_provision_uses_single_verified_candidate() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));

        // Verified header from coordinator (commits to the tx we'll send).
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Provisions(ProvisionAction::VerifyProvisions { anchor, .. })
                if anchor.height == BlockHeight::new(10)
        ));
    }

    #[test]
    fn test_provision_header_usable_while_batch_outstanding() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));

        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);

        // Batch arrives while the header is live — verification dispatches.
        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Provisions(ProvisionAction::VerifyProvisions { anchor, .. })
                if anchor.height == BlockHeight::new(10)
        ));
    }

    #[test]
    fn test_partial_provision_batch_rejected() {
        // A source builds its parts over a leaf list missing a transaction.
        // The header commits to the full list and its count, so no part
        // built over the short one walks to it: each is refused and the
        // fallback fetch asks a peer.
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_full = vec![
            TxHash::from(Hash::from_bytes(b"tx_a")),
            TxHash::from(Hash::from_bytes(b"tx_b")),
            TxHash::from(Hash::from_bytes(b"tx_c")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_full,
        );
        deliver_committed_header(&mut coordinator, &header);

        // Arriving provisions is missing tx_c.
        let partial = make_provisions_multi(
            tx_full[..2].to_vec(),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), partial);

        assert_eq!(
            refusal_of(&actions),
            Some(&ProvisionRefusal::ContentMismatch),
            "partial provisions must be refused, not dispatched"
        );
    }

    /// The refusal every verdict of a single emitted refusal carries, if
    /// that is all `actions` holds.
    fn refusal_of(actions: &[Action]) -> Option<&ProvisionRefusal> {
        let [Action::Continuation(ProtocolEvent::StateProvisionsVerified { results, .. })] =
            actions
        else {
            return None;
        };
        let refusals: Vec<&ProvisionRefusal> = results
            .iter()
            .map(|result| result.as_ref().err().map(|(_, refusal)| refusal))
            .collect::<Option<_>>()?;
        let first = *refusals.first()?;
        refusals
            .iter()
            .all(|refusal| *refusal == first)
            .then_some(first)
    }

    /// A bundle parked for a header that owes this shard nothing is
    /// refused as not owed once the header lands.
    #[test]
    fn a_bundle_its_header_does_not_owe_is_refused() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        assert!(
            coordinator
                .on_state_provisions_received(&sched(), vec![provisions])
                .is_empty()
        );

        let header =
            make_certified_header_with_targets(source_shard, BlockHeight::new(10), Vec::new());
        let actions = deliver_committed_header(&mut coordinator, &header);

        assert_eq!(refusal_of(&actions), Some(&ProvisionRefusal::NotOwed));
    }

    /// A bundle whose transactions miss the header's root is refused with
    /// a verdict that leaves the expectation armed, and the honest bundle
    /// that follows is admitted.
    #[test]
    fn a_mismatching_bundle_is_refused_and_the_honest_one_admitted() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_full = vec![
            TxHash::from(Hash::from_bytes(b"tx_a")),
            TxHash::from(Hash::from_bytes(b"tx_b")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_full,
        );
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.expected.len(), 1);

        let short = make_provisions_multi(
            tx_full[..1].to_vec(),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let mut actions = coordinator.on_state_provisions_received(&sched(), short);
        assert_eq!(
            refusal_of(&actions),
            Some(&ProvisionRefusal::ContentMismatch)
        );
        let Some(Action::Continuation(ProtocolEvent::StateProvisionsVerified { results, anchor })) =
            actions.pop()
        else {
            unreachable!("a refusal was matched above");
        };
        let after = coordinator.on_state_provisions_verified(results, anchor, LocalTimestamp::ZERO);
        assert!(after.is_empty());
        assert_eq!(coordinator.expected.len(), 1, "the expectation stays armed");

        let honest = make_provisions_multi(
            tx_full,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), honest.clone());
        assert!(matches!(
            actions.as_slice(),
            [Action::Provisions(ProvisionAction::VerifyProvisions { .. })]
        ));
        let admitted = coordinator.on_state_provisions_verified(
            verified(honest),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        assert!(admitted.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { .. })
        )));
        assert_eq!(coordinator.expected.len(), 0);
    }

    /// A colocated host's bundle meets the header root too: a short one
    /// is refused and admits nothing, and the whole one is admitted.
    #[test]
    fn a_colocated_bundle_missing_the_root_is_refused() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_full = vec![
            TxHash::from(Hash::from_bytes(b"tx_a")),
            TxHash::from(Hash::from_bytes(b"tx_b")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_full,
        );
        deliver_committed_header(&mut coordinator, &header);

        let short = make_provisions_multi(
            tx_full[..1].to_vec(),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_verified_state_provisions_received(
            &sched(),
            short
                .into_iter()
                .map(Verified::<Provision>::new_unchecked_for_test)
                .collect(),
            LocalTimestamp::ZERO,
        );
        assert_eq!(
            refusal_of(&actions),
            Some(&ProvisionRefusal::ContentMismatch)
        );
        assert_eq!(coordinator.expected.len(), 1);

        let whole = make_provisions_multi(
            tx_full,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_verified_state_provisions_received(
            &sched(),
            whole
                .into_iter()
                .map(Verified::<Provision>::new_unchecked_for_test)
                .collect(),
            LocalTimestamp::ZERO,
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAdmitted { .. })
        )));
    }

    #[test]
    fn test_batch_invalid_does_not_emit() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let tx_hashes = vec![
            TxHash::from(Hash::from_bytes(b"tx_ok")),
            TxHash::from(Hash::from_bytes(b"tx_bad")),
        ];
        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &tx_hashes,
        );
        deliver_committed_header(&mut coordinator, &header);

        let provisions = make_provisions_multi(
            tx_hashes,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );

        coordinator.on_state_provisions_received(&sched(), provisions.clone());

        // Every part fails verification
        let actions = coordinator.on_state_provisions_verified(
            provisions
                .into_iter()
                .map(|part| {
                    Err((
                        part,
                        ProvisionRefusal::Unproven(ProvisionVerifyError::BadInclusion),
                    ))
                })
                .collect(),
            Anchor::of(&header),
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
    ) -> Verified<CertifiedBlockHeader> {
        // Each target shard gets a placeholder `provision_tx_roots` entry —
        // the commitment the expectation tracker keys on. Tests that fire
        // matching bundles overwrite the entry with a real root via
        // `make_certified_header_committing`.
        let provision_tx_roots: BTreeMap<ShardId, ProvisionTxRoot> = provision_targets
            .into_iter()
            .map(|s| {
                (
                    s,
                    ProvisionTxRoot::from_raw(Hash::from_bytes(b"placeholder-tx-root")),
                )
            })
            .collect();
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(
                ShardId::leaf(2, 0),
                ChainOrigin::root(WeightedTimestamp::ZERO),
            )
            .into(),
            timestamp: ProposerTimestamp::from_millis(1000 + height.inner()),
            state_root: StateRoot::from_raw(Hash::from_bytes(
                format!("root_{shard}_{height}").as_bytes(),
            )),
            provision_tx_roots: Capped::new(provision_tx_roots)
                .expect("a list written out in a test"),
            ..Default::default()
        });
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            shard,
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        Verified::new_unchecked_for_test(CertifiedBlockHeader::new(header, qc))
    }

    /// Nominal block spacing used by tests to synthesize `weighted_timestamp_ms`
    /// from block heights. Ratios against timeout constants below preserve the
    /// old "block count" intuition when reading the tests.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    /// A genesis-shaped QC carrying `weighted_ts_ms`. The commit clock reads a
    /// block's `parent_qc` weighted timestamp, so fixtures anchor their time
    /// there while keeping the QC genesis-shaped (so `is_genesis()` holds).
    fn genesis_qc_at(shard: ShardId, weighted_ts_ms: u64) -> QuorumCertificate {
        let g = QuorumCertificate::genesis(shard, ChainOrigin::root(WeightedTimestamp::ZERO));
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
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(2, 0),
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            parent_qc: genesis_qc_at(ShardId::leaf(2, 0), height.inner() * TEST_BLOCK_INTERVAL_MS)
                .into(),
            ..Default::default()
        });
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = {
            let __qc = QuorumCertificate::genesis(
                ShardId::leaf(2, 0),
                ChainOrigin::root(WeightedTimestamp::ZERO),
            );
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

    /// A coordinator on `leaf(2, 0)` whose node clock resumes at `at`.
    fn resumed(at: WeightedTimestamp) -> ProvisionCoordinator {
        ProvisionCoordinator::with_config_and_store(
            ShardId::leaf(2, 0),
            ProvisionConfig::default(),
            Arc::new(ProvisionStore::new()),
            Arc::new(CommittedProvisions::new()),
            CommittedClock::seeded(at),
            ForkFence::new(),
        )
    }

    /// A restart resumes a chain whose clock is already far past the
    /// retention horizon. Provisions gossip that lands before the first
    /// post-restart commit parks in the pending buffer, stamped with
    /// whatever the coordinator reads as "now" — and the first commit
    /// sweeps that buffer against the chain's real clock.
    #[test]
    fn a_bundle_parked_before_the_first_commit_after_a_restart_survives_it() {
        let resumed_at = BlockHeight::new(100_000);
        let mut coordinator = resumed(WeightedTimestamp::from_millis(
            resumed_at.inner() * TEST_BLOCK_INTERVAL_MS,
        ));

        // No paired header yet, so the bundle parks.
        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"parked")),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(99_999),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        assert_eq!(coordinator.pipeline.pending_len(), 1, "the bundle parks");

        // The first commit after the restart, one block on.
        let actions = coordinator.on_block_committed(&sched(), &make_block(resumed_at.next()));
        assert_eq!(
            coordinator.pipeline.pending_len(),
            1,
            "a bundle parked a block ago is not past its deadline"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::LocalProvisions(_)))),
            "and nothing releases the fetch that is still wanted"
        );
    }

    /// The receipt gate drops a bundle whose source block has aged past
    /// the retention horizon, and the drop releases whatever fetched it.
    /// A restarted coordinator reads the same clock its peers do, so it
    /// drops the same bundles.
    #[test]
    fn a_bundle_past_its_deadline_is_refused_at_receipt_after_a_restart() {
        let mut coordinator = resumed(WeightedTimestamp::from_millis(
            100_000 * TEST_BLOCK_INTERVAL_MS,
        ));

        // The fixture header's QC carries `WeightedTimestamp::ZERO`, so
        // the bundle's deadline is one retention horizon past zero —
        // decades below the clock the restart resumed at.
        let tx_hash = TxHash::from(Hash::from_bytes(b"stale"));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);

        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        assert!(
            actions.iter().all(|a| matches!(a, Action::AbandonFetch(_))),
            "a bundle past its retention horizon dispatches no verification work"
        );
        assert_abandons_both(&actions);

        let actions = coordinator.on_verified_state_provisions_received(
            &sched(),
            vec![Verified::<Provision>::new_unchecked_for_test(provisions)],
            LocalTimestamp::ZERO,
        );
        assert!(
            actions.iter().all(|a| matches!(a, Action::AbandonFetch(_))),
            "nor does one that arrived already verified"
        );
        assert_abandons_both(&actions);
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
        deliver_committed_header(&mut coordinator, &header);

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
        deliver_committed_header(&mut coordinator, &header);

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
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // Batch arrives and is verified
        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
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
        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        // Remote header arrives targeting our shard; discovered_at stamped at ts=500ms.
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        deliver_committed_header(&mut coordinator, &header);

        // Advance blocks — should not emit before the timeout threshold.
        // discovered_at = 500ms; fires when now_ms - 500 >= 5000 → h = 11.
        for h in 2..=10 {
            let block = make_block(BlockHeight::new(h));
            let actions = coordinator.on_block_committed(&sched(), &block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 11, age = 5500 - 500 = 5000 >= PROVISION_FALLBACK_TIMEOUT → fires.
        let block = make_block(BlockHeight::new(11));
        let actions = coordinator.on_block_committed(&sched(), &block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::RemoteProvisions(wanted),
                shard,
                preferred,
                ..
            }) if *shard == ShardId::leaf(2, 1)
                // Both ends: the source the provisions come from, and
                // this coordinator's own shard they are owed to. The
                // count is not yet known, so index 0 alone is asked.
                && wanted.as_slice()
                    == [(
                        ShardId::leaf(2, 1),
                        ShardId::leaf(2, 0),
                        BlockHeight::new(10),
                        0,
                    )]
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
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // First local commit at ts=500ms. Should NOT fire — the pre-genesis
        // entry has just been retro-stamped to 500ms.
        let actions = coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));
        assert!(
            actions.is_empty(),
            "Pre-genesis entry must be retro-stamped, not fire immediately"
        );

        // Fires on schedule from the retro-stamp baseline, not absolute zero.
        for h in 2..=10 {
            let actions =
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
            assert!(actions.is_empty(), "Should not emit at height {h}");
        }
        let actions = coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(11)));
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
        deliver_committed_header(&mut coordinator, &header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions =
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
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
        deliver_committed_header(&mut coordinator, &header);

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }

        // Batch arrives and is verified before timeout
        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions =
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
            assert!(
                actions.is_empty(),
                "Should not request at height {h} (provision already verified)"
            );
        }
    }

    /// A bundle that fails its proof leaves the expectation armed: the
    /// fallback fetch still goes out on its timeout, where a cleared
    /// expectation would leave nothing to ask for the bundle again.
    #[test]
    fn a_bundle_failing_its_proof_leaves_the_fallback_armed() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        let source_shard = ShardId::leaf(2, 1);
        let header = make_certified_header_with_targets(
            source_shard,
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        deliver_committed_header(&mut coordinator, &header);
        for h in 1..=5 {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }

        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            vec![Err((
                provisions,
                ProvisionRefusal::Unproven(ProvisionVerifyError::BadInclusion),
            ))],
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        assert_eq!(coordinator.expected.len(), 1);

        let asked = (6..=15).any(|h| {
            coordinator
                .on_block_committed(&sched(), &make_block(BlockHeight::new(h)))
                .iter()
                .any(|action| {
                    matches!(
                        action,
                        Action::Fetch(FetchRequest::Ask {
                            ids: FetchIds::RemoteProvisions(_),
                            ..
                        })
                    )
                })
        });
        assert!(asked, "the fallback fetch fires on its timeout");
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
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.expected.len(), 1);

        let provisions = make_provisions(
            TxHash::from(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );

        // Expected-tracking entry is cleared; the shard loop's
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
    fn make_block_with_provisions(height: BlockHeight, provisions: Provision) -> CertifiedBlock {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(2, 0),
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            parent_qc: genesis_qc_at(ShardId::leaf(2, 0), height.inner() * TEST_BLOCK_INTERVAL_MS)
                .into(),
            ..Default::default()
        });
        let provisions_verifiable: Verifiable<Provision> = provisions.into();
        let block = Block::Live {
            header,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::from_array([provisions_verifiable])),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::leaf(2, 0),
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(height.inner() * TEST_BLOCK_INTERVAL_MS),
        );
        CertifiedBlock::new_unchecked(block, qc)
    }

    /// Regression: under cross-shard packed hosting, the local-serve
    /// fall-through in `Network::request` re-routes a fetch through a
    /// peer when the co-located replica's local store has aged out the
    /// requested batch. Without the tombstone, that wire arrival lands
    /// in `on_state_provisions_received` past `pipeline.verified`'s
    /// `source_block_ts + RETENTION_HORIZON` eviction, sails through the
    /// `has_verified` guard, re-enters the proposer queue, and the next
    /// proposal includes a batch the shard consensus
    /// `validate_no_duplicate_provisions` window still rejects —
    /// triggering a view-change loop.
    /// What the shard coordinator does on the same commit.
    ///
    /// The committed-provision window has one writer, and it is not this
    /// coordinator — these tests stand in for it. The shard registers
    /// under its *clamped* committed clock; the clock is monotone in these
    /// tests, so the block's own anchor is that value.
    fn shard_registers_committed(coordinator: &ProvisionCoordinator, block: &Block) {
        let ts = block.header().parent_qc().weighted_timestamp();
        coordinator.committed_provisions.register(
            BlockManifest::from_block(block)
                .provision_hashes()
                .iter()
                .copied(),
            ts,
        );
        coordinator.committed_provisions.prune(ts);
    }

    #[test]
    fn test_committed_tombstone_drops_re_arrival_after_pipeline_eviction() {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));

        // Prime the local clock so the expected-provision entry stamps a
        // real baseline rather than the zero sentinel.
        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let source_height = BlockHeight::new(10);
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
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
        deliver_committed_header(&mut coordinator, &header);

        // First arrival → queued.
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions.clone()]),
            Anchor::of(&header),
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
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }

        // Commit a block containing this batch at h=101 — queue drains,
        // tombstone registers anchored on this block's commit ts
        // (~50_500ms with TEST_BLOCK_INTERVAL_MS=500).
        let commit_h = BlockHeight::new(101);
        let committing_block = make_block_with_provisions(commit_h, provisions.clone());
        coordinator.on_block_committed(&sched(), &committing_block);
        shard_registers_committed(&coordinator, committing_block.block());
        assert_eq!(coordinator.queue.queue_len(), 0);
        assert!(coordinator.committed_provisions.contains(&provisions_hash));

        // Walk to a height where `pipeline.verified` (deadline = 0 +
        // RETENTION_HORIZON) has evicted but the tombstone (deadline =
        // commit_ts + RETENTION_HORIZON) is still live. Pick the
        // midpoint: `RETENTION_HORIZON_blocks + commit_h/2`.
        let retention_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        let mid_h = retention_blocks + commit_h.inner() / 2;
        for h in 102..=mid_h {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }
        assert_eq!(
            coordinator.pipeline.verified_len(),
            0,
            "pipeline.verified should have evicted by now"
        );
        assert!(
            coordinator.committed_provisions.contains(&provisions_hash),
            "tombstone should outlive pipeline.verified eviction"
        );

        // Late re-arrival (e.g. fetch fall-through, gossip retransmit).
        // The tombstone must drop it before it reaches the verify path
        // and re-enters the queue.
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        assert!(
            actions.iter().all(|a| matches!(a, Action::AbandonFetch(_))),
            "a tombstoned re-arrival dispatches no verification work",
        );
        assert_abandons_both(&actions);
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

        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let source_height = BlockHeight::new(10);
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));
        let provisions = make_provisions(tx_hash, source_shard, ShardId::leaf(2, 0), source_height);
        let provisions_hash = provisions.hash();

        let header = make_certified_header_committing(
            source_shard,
            source_height,
            ShardId::leaf(2, 0),
            &[tx_hash],
        );

        // First lifecycle: header, receive, verify, commit.
        deliver_committed_header(&mut coordinator, &header);
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions.clone()]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        let committing_block = make_block_with_provisions(BlockHeight::new(2), provisions.clone());
        coordinator.on_block_committed(&sched(), &committing_block);
        shard_registers_committed(&coordinator, committing_block.block());
        assert!(coordinator.committed_provisions.contains(&provisions_hash));

        // Second lifecycle: provisions re-arrive before any header. The
        // receipt-time tombstone guard short-circuits at receipt — no
        // pending buffering, no drain work, no re-enqueue.
        coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        let actions = deliver_committed_header(&mut coordinator, &header);
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
        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        let source_shard = ShardId::leaf(2, 1);
        let block_height = BlockHeight::new(10);

        let header = make_certified_header_with_targets(
            source_shard,
            block_height,
            vec![ShardId::leaf(2, 0)],
        );
        deliver_committed_header(&mut coordinator, &header);

        // The orphan sweep keys on the source block's weighted timestamp.
        // This synthetic header carries a genesis (zero) parent-QC timestamp,
        // so the entry ages out the first commit whose retention cutoff goes
        // positive — i.e. once the local clock passes the retention span.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;

        // Walk up to (but not past) the orphan cutoff — no Abandon yet.
        for h in 2..=orphan_cutoff_blocks {
            let actions =
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
            assert!(
                !actions.iter().any(|a| matches!(a, Action::AbandonFetch(_))),
                "AbandonFetch fired before orphan cutoff at h={h}"
            );
        }

        // One past the cutoff — orphan sweep drops the expected entry and
        // emits AbandonFetch for the dropped key.
        let actions = coordinator.on_block_committed(
            &sched(),
            &make_block(BlockHeight::new(orphan_cutoff_blocks + 1)),
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::RemoteProvisions(ids))
                    if ids.iter().any(|(s, _, h, index)| {
                        *s == source_shard && *h == block_height && *index == 0
                    })
            )),
            "Expected AbandonFetch from orphan cleanup, got: {actions:?}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Per-index expectation tests
    // ═══════════════════════════════════════════════════════════════════════

    /// A coordinator holding a commit-proven header from leaf (2, 1) at
    /// height 10 that owes leaf (2, 0) one part each for `txs`.
    fn expecting(txs: &[TxHash]) -> (ProvisionCoordinator, Verified<CertifiedBlockHeader>) {
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            txs,
        );
        deliver_committed_header(&mut coordinator, &header);
        (coordinator, header)
    }

    fn txs(n: u8) -> Vec<TxHash> {
        (0..n)
            .map(|i| TxHash::from(Hash::from_bytes(&[i, 0x7E])))
            .collect()
    }

    /// The indices every fetch ask in `actions` names.
    fn asked(actions: &[Action]) -> Vec<u32> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::RemoteProvisions(ids),
                    ..
                }) => Some(ids.iter().map(|(.., index)| *index).collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// The indices every abandon in `actions` lets go of.
    fn abandoned(actions: &[Action]) -> Vec<u32> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::AbandonFetch(FetchIds::RemoteProvisions(ids)) => {
                    Some(ids.iter().map(|(.., index)| *index).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// The count witness of `txs`, as a holder of the block states it.
    fn witness_of(txs: &[TxHash]) -> ProvisionCount {
        let leaves: Vec<Hash> = txs.iter().map(|tx| provision_leaf(*tx)).collect();
        ProvisionCount::over(&leaves)
    }

    /// Parts arriving by gossip across several notifications ask for
    /// nothing: the expectation completes on the last of them, and no
    /// fetch goes out then or after the timeout.
    #[test]
    fn gossip_in_several_notifications_sends_no_fetch() {
        let txs = txs(3);
        let (mut coordinator, header) = expecting(&txs);
        let parts = make_provisions_multi(
            txs,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let mut actions = Vec::new();
        for pack in [&parts[..2], &parts[2..]] {
            actions.extend(coordinator.on_state_provisions_received(&sched(), pack.to_vec()));
            actions.extend(coordinator.on_state_provisions_verified(
                verified(pack.to_vec()),
                Anchor::of(&header),
                LocalTimestamp::ZERO,
            ));
        }
        assert!(asked(&actions).is_empty());
        assert!(
            abandoned(&actions).is_empty(),
            "nothing was asked to let go of"
        );
        assert_eq!(coordinator.expected.len(), 0);
        for h in 1..=30 {
            let actions =
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
            assert!(asked(&actions).is_empty(), "no fetch at height {h}");
        }
    }

    /// The witness teaches the count without index 0 ever arriving, and
    /// the indices past it are asked; the expectation then waits on index
    /// 0 alone, which the orphan sweep lets go of with every other ask.
    #[test]
    fn a_count_witness_teaches_the_count_when_index_zero_never_arrives() {
        let txs = txs(4);
        let (mut coordinator, header) = expecting(&txs);
        assert_eq!(asked(&coordinator.flush_expected_provisions()), vec![0]);

        let actions = coordinator.on_provision_count(
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
            witness_of(&txs),
        );
        assert_eq!(asked(&actions), vec![1, 2, 3]);

        let parts = make_provisions_multi(
            txs,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let rest = parts[1..].to_vec();
        coordinator.on_state_provisions_received(&sched(), rest.clone());
        let admitted = coordinator.on_state_provisions_verified(
            verified(rest),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        assert_eq!(
            admitted
                .iter()
                .filter(|a| matches!(
                    a,
                    Action::Continuation(ProtocolEvent::ProvisionsAdmitted { .. })
                ))
                .count(),
            3
        );
        assert_eq!(coordinator.expected.len(), 1, "index 0 is still owed");

        let orphan_after = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS
            + 1;
        let actions =
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(orphan_after)));
        let mut released = abandoned(&actions);
        released.sort_unstable();
        assert_eq!(released, vec![0, 1, 2, 3]);
        assert_eq!(coordinator.expected.len(), 0);
    }

    /// A witness that does not wrap to the header's root is refused and
    /// teaches nothing; the true one, after it, does.
    #[test]
    fn a_count_witness_off_the_header_root_teaches_nothing() {
        let txs = txs(3);
        let (mut coordinator, _) = expecting(&txs);
        let _ = coordinator.flush_expected_provisions();

        let honest = witness_of(&txs);
        for lie in [
            ProvisionCount { count: 2, ..honest },
            ProvisionCount { count: 5, ..honest },
            ProvisionCount {
                merkle_root: Hash::from_bytes(b"another root"),
                ..honest
            },
        ] {
            let actions = coordinator.on_provision_count(
                ShardId::leaf(2, 1),
                ShardId::leaf(2, 0),
                BlockHeight::new(10),
                lie,
            );
            assert!(actions.is_empty(), "{lie:?} teaches nothing");
        }
        let actions = coordinator.on_provision_count(
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
            honest,
        );
        assert_eq!(asked(&actions), vec![1, 2]);
    }

    /// A witness arriving before its header is commit-proven waits for
    /// it, and is checked when it lands.
    #[test]
    fn a_count_witness_before_its_header_is_checked_when_it_lands() {
        let txs = txs(2);
        let mut coordinator = ProvisionCoordinator::new(ShardId::leaf(2, 0));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &txs,
        );
        coordinator.on_verified_remote_header(&header);
        let _ = coordinator.flush_expected_provisions();
        let early = coordinator.on_provision_count(
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
            witness_of(&txs),
        );
        assert!(early.is_empty());
        let actions = coordinator.on_committed_remote_header(&sched(), &header);
        assert_eq!(asked(&actions), vec![1]);
    }

    /// An index whose part was committed before it was admitted here
    /// counts as held, and the expectation completes on the rest,
    /// letting go of every index it asked for.
    #[test]
    fn a_committed_index_counts_as_held() {
        let txs = txs(2);
        let (mut coordinator, header) = expecting(&txs);
        let parts = make_provisions_multi(
            txs,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let _ = coordinator.flush_expected_provisions();
        coordinator
            .committed_provisions
            .register([parts[0].hash()], WeightedTimestamp::from_millis(1_000));

        let retired = coordinator.on_state_provisions_received(&sched(), vec![parts[0].clone()]);
        assert!(
            retired
                .iter()
                .all(|a| matches!(a, Action::AbandonFetch(_) | Action::Fetch(_))),
            "a committed part dispatches no verification",
        );
        assert_eq!(
            asked(&retired),
            vec![1],
            "the count it teaches asks for the rest"
        );
        assert_eq!(coordinator.expected.len(), 1);

        coordinator.on_state_provisions_received(&sched(), vec![parts[1].clone()]);
        let actions = coordinator.on_state_provisions_verified(
            verified(vec![parts[1].clone()]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        assert_eq!(coordinator.expected.len(), 0, "the committed index counted");
        let mut released = abandoned(&actions);
        released.sort_unstable();
        assert_eq!(released, vec![0, 1]);
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
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Advance local well past any old time-based cutoff but short of the
        // orphan threshold. Header stays because its provisions hasn't verified yet.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 1..=(orphan_cutoff_blocks / 2) {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
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
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx1"));

        let header = make_certified_header_committing(
            source_shard,
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        let provisions = make_provisions(
            tx_hash,
            source_shard,
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
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
        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        // Header arrives but the provisions never does — this is the orphan case
        // the long-horizon sweep guards against.
        let header = make_certified_header_with_targets(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            vec![ShardId::leaf(2, 0)],
        );
        deliver_committed_header(&mut coordinator, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // Not yet past the orphan cutoff — still retained. The sweep keys on
        // the source block's weighted timestamp, which for this synthetic
        // header is the genesis (zero) parent-QC timestamp, so the entry ages
        // out once the local clock first passes the span an owed crossing's
        // bundle is still wanted in.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 2..=orphan_cutoff_blocks {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
        }
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.expected.len(), 1);

        // One past — orphan sweep drops header and expected entry together.
        coordinator.on_block_committed(
            &sched(),
            &make_block(BlockHeight::new(orphan_cutoff_blocks + 1)),
        );
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
        let tx_hash = TxHash::from(Hash::from_bytes(b"old-tx"));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);
        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
            LocalTimestamp::ZERO,
        );
        assert_eq!(coordinator.queue.queue_len(), 1);
        assert_eq!(coordinator.pipeline.verified_len(), 1);

        // Advance local commits until past `source_block_ts + RETENTION_HORIZON`.
        // Source ts is height 10 at `TEST_BLOCK_INTERVAL_MS` apiece.
        let deadline_height = (u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS)
            + 11;
        for h in 100..=deadline_height + 1 {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
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

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx-old"));
        let header = make_certified_header_committing(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ShardId::leaf(2, 0),
            &[tx_hash],
        );
        deliver_committed_header(&mut coordinator, &header);

        // Advance local commits well past the source's deadline.
        let deadline_height = (u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS)
            + 11;
        for h in 100..=deadline_height + 1 {
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
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
        let actions = coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        assert!(
            actions.iter().all(|a| matches!(a, Action::AbandonFetch(_))),
            "past-deadline provisions must be dropped without dispatching verification"
        );
        assert_abandons_both(&actions);
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
        coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

        let tx_hash = TxHash::from(Hash::from_bytes(b"tx-pending"));
        let provisions = make_provisions(
            tx_hash,
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 0),
            BlockHeight::new(10),
        );
        let provisions_hash = provisions.hash();
        coordinator.on_state_provisions_received(&sched(), vec![provisions]);
        assert_eq!(coordinator.pipeline.pending_len(), 1);

        // Advance past the deadline horizon measured from received_at,
        // accumulating actions so the eviction commit's abandon surfaces
        // regardless of which iteration crosses the threshold.
        let cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        let mut sweep_actions = Vec::new();
        for h in 2..=cutoff_blocks + 3 {
            sweep_actions
                .extend(coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h))));
        }

        assert_eq!(
            coordinator.pipeline.pending_len(),
            0,
            "pending entry past `received_at + RETENTION_HORIZON` must be evicted"
        );
        let abandon = sweep_actions.iter().find_map(|a| match a {
            Action::AbandonFetch(FetchIds::LocalProvisions(hashes)) => Some(hashes),
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
        deliver_committed_header(coordinator, &header);
        let provisions = make_provisions(tx_hash, source_shard, ShardId::leaf(2, 0), height);
        coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
        coordinator.on_state_provisions_verified(
            verified(vec![provisions]),
            Anchor::of(&header),
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
            TxHash::from(Hash::from_bytes(b"tx1")),
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
            TxHash::from(Hash::from_bytes(b"tx1")),
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
            TxHash::from(Hash::from_bytes(b"tx_old")),
            LocalTimestamp::from_millis(1_000),
        );

        // t=1.3s: verify young provisions
        verify_batch_into_queue(
            &mut coordinator,
            ShardId::leaf(2, 1),
            BlockHeight::new(11),
            TxHash::from(Hash::from_bytes(b"tx_young")),
            LocalTimestamp::from_millis(1_300),
        );

        // t=1.4s: old provisions dwelled 400ms (eligible), young provisions dwelled
        // 100ms (still blocked).
        let eligible = coordinator.queued_provisions(LocalTimestamp::from_millis(1_400));
        assert_eq!(eligible.len(), 1);
        assert_eq!(
            eligible[0].tx_hash(),
            TxHash::from(Hash::from_bytes(b"tx_old"))
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
            coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(1)));

            let n = source_heights.len().min(verify_path.len());
            for i in 0..n {
                let source_height = BlockHeight::new(source_heights[i]);
                let tx_hash =
                    TxHash::from(Hash::from_bytes(format!("tx-{i}").as_bytes()));
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
                    deliver_committed_header(&mut coordinator, &header);
                    coordinator.on_state_provisions_received(&sched(), vec![provisions.clone()]);
                    coordinator.on_state_provisions_verified(
                        verified(vec![provisions]),
                        Anchor::of(&header),
                        LocalTimestamp::ZERO,
                    );
                } else {
                    // Pending path: provisions arrives without header.
                    coordinator.on_state_provisions_received(&sched(), vec![provisions]);
                }
            }

            // Advance well past `RETENTION_HORIZON` from the latest
            // possible source ts (50 * 500ms = 25_000ms = 25s).
            let cutoff_ms =
                25_000 + u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX) + 5 * TEST_BLOCK_INTERVAL_MS;
            let cutoff_height = cutoff_ms / TEST_BLOCK_INTERVAL_MS;
            for h in 2..=cutoff_height {
                coordinator.on_block_committed(&sched(), &make_block(BlockHeight::new(h)));
            }

            proptest::prop_assert_eq!(coordinator.queue.queue_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.verified_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.pending_len(), 0);
        }
    }
}
