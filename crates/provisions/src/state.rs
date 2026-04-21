//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages QC + merkle proof verification, and emits
//! verification events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts a `StateProvision` batch containing JMT
//! inclusion proofs. The target shard joins with remote block headers, then
//! dispatches `VerifyStateProvision` to verify the QC signature once and
//! merkle proofs per provision against the committed state root.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    compute_padded_merkle_root, BlockHeight, CommittedBlockHeader, Hash, Provision, ShardGroupId,
    TopologySnapshot, ValidatorId, WAVE_TIMEOUT,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default minimum dwell time a verified provision batch sits in the queue
/// before the proposer can include it in a block. Gives shard peers time to
/// receive and verify the same batch via gossip, so they don't have to fetch
/// it later. Also buys headroom for the fetch-serving cache since peers hit
/// local state instead of requesting back.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(500);

/// How long to wait before falling back to peer-fetch for missing
/// provisions. Proposers include provisions inline in `Block::Live` during
/// assembly, so this timeout only triggers when gossip dropped a batch —
/// in which case we fetch from a shard peer. Measured against the BFT-
/// authenticated `weighted_timestamp_ms` of locally committed blocks.
const PROVISION_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to retain a committed provision in the in-memory cache. After
/// this window past its commit, the provision is dropped — the block it
/// served has aged past the cross-shard execution window, so no peer can
/// still need it as part of a `Block::Live` serving response.
///
/// Defined as `WAVE_TIMEOUT * 2` so the `>= WAVE_TIMEOUT` invariant is
/// structural: any change to the execution window automatically keeps the
/// serving-cache window ahead of it. Anchored on the committing QC's
/// `weighted_timestamp_ms`.
const COMMITTED_PROVISION_RETENTION: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() * 2);

/// How long past `expected.discovered_at_ts_ms` before an unmatched header
/// is treated as orphaned and dropped. Headers are otherwise retained while
/// their batch is still outstanding — this guards only against truly stuck
/// entries whose fallback fetches never resolved. Sized generously since
/// a leaked entry is harmless for correctness; the concern is only memory.
const ORPHAN_HEADER_CUTOFF: Duration = Duration::from_secs(300);

/// How long to retain batch-hash tombstones after commit. Prevents re-queueing
/// duplicate gossip that lingers past commit. Sized above the gossip-retry
/// window; anchored on the committing QC's `weighted_timestamp_ms`.
const BATCH_TOMBSTONE_RETENTION: Duration = Duration::from_secs(60);

/// Provision coordinator configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisionConfig {
    /// Minimum time a verified provision batch must sit in the proposal queue
    /// before it becomes eligible for inclusion. Batches younger than this are
    /// skipped by `queued_provisions()` but remain in the queue.
    ///
    /// Set to zero to disable.
    #[serde(default = "default_min_dwell_time")]
    pub min_dwell_time: Duration,
}

fn default_min_dwell_time() -> Duration {
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
#[derive(Clone, Copy, Debug, Default)]
pub struct ProvisionMemoryStats {
    pub verified_remote_headers: usize,
    pub pending_provisions: usize,
    pub verified_batches: usize,
    pub expected_provisions: usize,
    pub batches_by_hash: usize,
    pub queued_provision_batches: usize,
    pub committed_batch_tombstones: usize,
}

/// Tracks an expected provision that hasn't arrived yet.
///
/// Created when a remote block header's `waves` field targets our shard.
/// Emits a single `FetchProvisionRemote` after the timeout; the fetch
/// protocol owns retries from that point.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    /// Local weighted timestamp (ms) when we first expected this provision.
    /// Used as the liveness baseline for both fallback-fetch and orphan
    /// eviction.
    discovered_at_ts_ms: u64,
    requested: bool,
    proposer: ValidatorId,
}

/// A verified provision batch queued for inclusion, timestamped for dwell-time
/// filtering at proposal time.
#[derive(Debug, Clone)]
struct QueuedProvision {
    batch: Arc<Provision>,
    added_at: Duration,
}

/// Centralized provision coordination.
///
/// Responsibilities:
/// - Receive provision batches from the source shard proposer
/// - Join provisions with remote block headers
/// - Dispatch QC + merkle proof verification (QC once per batch, proofs per provision)
/// - Queue verified batches for block inclusion
/// - Request missing provisions after timeout (fallback recovery)
pub struct ProvisionCoordinator {
    // ═══════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════
    config: ProvisionConfig,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Remote Block Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers from remote shards.
    ///
    /// Populated exclusively via `on_verified_remote_header()` from the
    /// `RemoteHeaderCoordinator`. All headers here have passed QC verification.
    /// Used to join with provision batches for merkle proof verification.
    verified_remote_headers: HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Provision
    // ═══════════════════════════════════════════════════════════════════
    /// Provision batches waiting for their corresponding remote block header.
    /// Keyed by (source_shard, block_height) since that's how we match to headers.
    pending_provisions: HashMap<(ShardGroupId, BlockHeight), Vec<Provision>>,

    /// Verified provision batches keyed by (source_shard, block_height).
    /// Stored whole after proof verification — no per-tx decomposition.
    verified_batches: BTreeMap<(ShardGroupId, BlockHeight), Arc<Provision>>,

    /// Hash-keyed index into verified batches for O(1) lookup by content hash.
    /// Populated alongside `verified_batches`. Used by `get_batch_by_hash()`
    /// and for efficient pruning in `on_block_committed`.
    batches_by_hash: HashMap<Hash, Arc<Provision>>,

    // ═══════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (fallback detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp (ms) of the last locally
    /// committed block. "Now" reference for liveness timeouts so they're
    /// independent of local block production rate and deterministic across
    /// validators.
    local_committed_ts_ms: u64,

    /// Expected provisions that haven't arrived yet.
    /// Keyed by `(source_shard, block_height)`. Populated when a remote
    /// header's `waves` field targets our shard. Cleared when
    /// provisions are verified or the associated transactions are cleaned up.
    expected_provisions: BTreeMap<(ShardGroupId, BlockHeight), ExpectedProvision>,

    // ═══════════════════════════════════════════════════════════════════
    // Proposal Queue + Tombstones
    // ═══════════════════════════════════════════════════════════════════
    /// Provision batches received from remote shards, queued for inclusion
    /// in the next block proposal. Proposer drains this queue when building
    /// a proposal. Every validator queues (any might become next proposer).
    /// Each entry is timestamped so `queued_provisions()` can apply the
    /// configured `min_dwell_time`.
    queued_provision_batches: Vec<QueuedProvision>,

    /// Tombstone set: hashes of provision batches that have been committed.
    /// Prevents re-queueing if a duplicate batch arrives via gossip after commit.
    /// Maps hash → committing QC's `weighted_timestamp_ms` for age-based
    /// pruning anchored on BFT-authenticated time.
    committed_batch_tombstones: HashMap<Hash, u64>,

    /// Committed provision hashes grouped by the local weighted timestamp
    /// (ms) at which they committed. Drives deferred eviction: entries
    /// retained until `commit_ts_ms + COMMITTED_PROVISION_RETENTION` falls
    /// behind the local tip ts, at which point they're dropped. Ensures
    /// peers catching up can still receive `Block::Live` (with inline
    /// provisions) for any block within the cross-shard execution window.
    committed_retention: BTreeMap<u64, Vec<Hash>>,

    // ═══════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════
    /// Current time.
    now: Duration,
}

impl std::fmt::Debug for ProvisionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionCoordinator")
            .field(
                "verified_remote_headers",
                &self.verified_remote_headers.len(),
            )
            .field("verified_batches", &self.verified_batches.len())
            .finish()
    }
}

impl Default for ProvisionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionCoordinator {
    /// Create a new ProvisionCoordinator with default config.
    pub fn new() -> Self {
        Self::with_config(ProvisionConfig::default())
    }

    /// Create a new ProvisionCoordinator with the given config.
    pub fn with_config(config: ProvisionConfig) -> Self {
        Self {
            config,
            verified_remote_headers: HashMap::new(),
            pending_provisions: HashMap::new(),
            verified_batches: BTreeMap::new(),
            batches_by_hash: HashMap::new(),
            local_committed_height: BlockHeight(0),
            local_committed_ts_ms: 0,
            expected_provisions: BTreeMap::new(),
            queued_provision_batches: Vec::new(),
            committed_batch_tombstones: HashMap::new(),
            committed_retention: BTreeMap::new(),
            now: Duration::ZERO,
        }
    }

    /// Get provision coordinator memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ProvisionMemoryStats {
        ProvisionMemoryStats {
            verified_remote_headers: self.verified_remote_headers.len(),
            pending_provisions: self.pending_provisions.len(),
            verified_batches: self.verified_batches.len(),
            expected_provisions: self.expected_provisions.len(),
            batches_by_hash: self.batches_by_hash.len(),
            queued_provision_batches: self.queued_provision_batches.len(),
            committed_batch_tombstones: self.committed_batch_tombstones.len(),
        }
    }

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Handle block committed - check for timed-out expected provisions.
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        certified: &hyperscale_types::CertifiedBlock,
    ) -> Vec<Action> {
        let block = &certified.block;
        let new_ts_ms = certified.qc.weighted_timestamp.as_millis();
        let first_commit = self.local_committed_ts_ms == 0;
        self.local_committed_height = block.height();
        self.local_committed_ts_ms = new_ts_ms;

        // Retro-stamp `expected_provisions` entries recorded before the first
        // local commit. Remote headers can arrive and register expectations
        // while `local_committed_ts_ms` is still zero; without this, every
        // such entry would report a ~57-year age on the next commit and
        // trigger a fallback fetch storm.
        if first_commit {
            for expected in self.expected_provisions.values_mut() {
                if expected.discovered_at_ts_ms == 0 {
                    expected.discovered_at_ts_ms = new_ts_ms;
                }
            }
        }

        // Record provision batches committed in this block, but don't
        // evict them yet — peers catching up within the cross-shard
        // execution window still need them attached to `Block::Live`
        // sync responses. Eviction happens below once they age out.
        let committed: std::collections::HashSet<Hash> =
            block.provisions().iter().map(|p| p.hash()).collect();
        if !committed.is_empty() {
            for h in &committed {
                // Tombstone: prevent re-queueing if duplicate gossip arrives later.
                self.committed_batch_tombstones
                    .insert(*h, self.local_committed_ts_ms);
            }
            self.committed_retention
                .entry(self.local_committed_ts_ms)
                .or_default()
                .extend(committed.iter().copied());
            self.queued_provision_batches
                .retain(|q| !committed.contains(&q.batch.hash()));
        }

        // Evict committed provisions whose commit timestamp has aged past
        // the retention window. `split_off` partitions by the first retained
        // ts, leaving aged-out entries in `aged` for cleanup.
        let retention_ms = COMMITTED_PROVISION_RETENTION.as_millis() as u64;
        let retention_cutoff_ms = self.local_committed_ts_ms.saturating_sub(retention_ms);
        let still_retained = self.committed_retention.split_off(&retention_cutoff_ms);
        let aged = std::mem::replace(&mut self.committed_retention, still_retained);
        for (_ts_ms, hashes) in aged {
            for h in hashes {
                if let Some(batch) = self.batches_by_hash.remove(&h) {
                    let key = (batch.source_shard, batch.block_height);
                    self.verified_batches.remove(&key);
                    // Header no longer needed once the provision is evicted.
                    self.verified_remote_headers.remove(&key);
                }
            }
        }

        // Drop truly orphaned `expected_provisions` entries (and their headers)
        // whose fallback fetch never resolved after a long horizon. Under normal
        // operation a header is retained exactly while its batch is outstanding;
        // this only catches entries that would otherwise leak indefinitely.
        let orphan_cutoff_ms = self
            .local_committed_ts_ms
            .saturating_sub(ORPHAN_HEADER_CUTOFF.as_millis() as u64);
        if orphan_cutoff_ms > 0 {
            let before = self.expected_provisions.len();
            self.expected_provisions
                .retain(|_, exp| exp.discovered_at_ts_ms >= orphan_cutoff_ms);
            if self.expected_provisions.len() != before {
                // Drop matching headers — they're useless without an expected batch.
                let live: std::collections::HashSet<_> =
                    self.expected_provisions.keys().copied().collect();
                self.verified_remote_headers
                    .retain(|key, _| live.contains(key));
            }
        }

        // Prune tombstones past their retention window, measured against
        // BFT-authenticated time.
        let tombstone_cutoff_ms = self
            .local_committed_ts_ms
            .saturating_sub(BATCH_TOMBSTONE_RETENTION.as_millis() as u64);
        self.committed_batch_tombstones
            .retain(|_, committed_at_ts_ms| *committed_at_ts_ms > tombstone_cutoff_ms);

        // Check for timed-out expected provisions and emit fallback requests
        let mut actions = vec![];
        let now_ms = self.local_committed_ts_ms;
        let timeout_ms = PROVISION_FALLBACK_TIMEOUT.as_millis() as u64;

        for (&(source_shard, block_height), expected) in self.expected_provisions.iter_mut() {
            if expected.requested {
                continue;
            }

            let age_ms = now_ms.saturating_sub(expected.discovered_at_ts_ms);
            if age_ms < timeout_ms {
                continue;
            }

            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                age_ms,
                "Provision timeout — requesting missing provisions via fallback"
            );

            expected.requested = true;
            actions.push(Action::FetchProvisionRemote {
                source_shard,
                block_height,
                proposer: expected.proposer,
                peers: topology.committee_for_shard(source_shard).to_vec(),
            });
        }

        actions
    }

    /// Immediately emit `FetchProvisionRemote` for all outstanding expected
    /// provisions, bypassing the normal `PROVISION_FALLBACK_TIMEOUT`.
    ///
    /// Called when urgency overrides the default patience — sync completion
    /// (validator needs to catch up before `WAVE_TIMEOUT` runs out) and the
    /// execution advance gate stalling on missing data.
    pub fn flush_expected_provisions(
        &mut self,
        topology: &hyperscale_types::TopologySnapshot,
    ) -> Vec<Action> {
        let mut actions = vec![];
        for (&(source_shard, block_height), expected) in self.expected_provisions.iter_mut() {
            if expected.requested {
                continue;
            }
            info!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Eager fetch — immediately requesting missing provisions"
            );
            expected.requested = true;
            actions.push(Action::FetchProvisionRemote {
                source_shard,
                block_height,
                proposer: expected.proposer,
                peers: topology.committee_for_shard(source_shard).to_vec(),
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a verified remote header from the RemoteHeaderCoordinator.
    ///
    /// Called when `RemoteHeaderVerified` is received. The header has already
    /// passed QC verification, so we store it directly as verified and:
    /// 1. Register expected provisions if waves target our shard
    /// 2. Join with any buffered provision batches waiting for this header
    pub fn on_verified_remote_header(
        &mut self,
        topology: &TopologySnapshot,
        committed_header: Arc<CommittedBlockHeader>,
    ) -> Vec<Action> {
        let shard = committed_header.shard_group_id();
        let height = committed_header.height();
        let key = (shard, height);

        // Ignore headers from our own shard.
        if shard == topology.local_shard() {
            return vec![];
        }

        // Only store headers that target our shard (i.e., we expect provisions).
        let local_shard = topology.local_shard();
        let targets_us = committed_header
            .header
            .waves
            .iter()
            .any(|w| w.remote_shards.contains(&local_shard));

        if targets_us {
            // Store as verified (QC already checked by coordinator).
            self.verified_remote_headers
                .insert(key, Arc::clone(&committed_header));

            let proposer = committed_header.header.proposer;
            self.expected_provisions.entry(key).or_insert_with(|| {
                debug!(
                    shard = shard.0,
                    height = height.0,
                    proposer = proposer.0,
                    "Tracking expected provision (verified remote block targets our shard)"
                );
                ExpectedProvision {
                    discovered_at_ts_ms: self.local_committed_ts_ms,
                    requested: false,
                    proposer,
                }
            });
        }

        // Join with buffered provision batches waiting for this header.
        let mut actions = vec![];
        if let Some(batches) = self.pending_provisions.remove(&key) {
            debug!(
                shard = shard.0,
                height = height.0,
                pending_count = batches.len(),
                "Found buffered provision batches for verified header"
            );
            for batch in batches {
                actions.extend(self.emit_provision_verification(
                    topology,
                    batch,
                    committed_header.clone(),
                ));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a provision batch received from a source shard proposer.
    ///
    /// All transactions in a batch share the same `(source_shard, block_height)`
    /// via the batch's proof.
    /// Joins with the corresponding verified remote block header:
    /// - If a verified header exists: emit verification with single candidate
    /// - If no header yet: buffer the batch until `on_verified_remote_header` delivers it
    pub fn on_state_provisions_received(
        &mut self,
        topology: &TopologySnapshot,
        batch: Provision,
    ) -> Vec<Action> {
        if batch.transactions.is_empty() {
            return vec![];
        }

        let source_shard = batch.source_shard;
        let block_height = batch.block_height;

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = batch.transactions.len(),
            "Provision batch received"
        );

        // Ignore provisions from our own shard
        if source_shard == topology.local_shard() {
            return vec![];
        }

        let key = (source_shard, block_height);

        // Skip if this key was already verified (duplicate gossip/fetch) or
        // already committed (tombstoned by hash). Avoids re-dispatching
        // verification work and buffering stale duplicates in
        // `pending_provisions`.
        if self.verified_batches.contains_key(&key)
            || self.committed_batch_tombstones.contains_key(&batch.hash())
        {
            return vec![];
        }

        // Look for matching verified remote header (pre-verified by RemoteHeaderCoordinator).
        if let Some(verified_header) = self.verified_remote_headers.get(&key).cloned() {
            return self.emit_provision_verification(topology, batch, verified_header);
        }

        // No verified header yet — buffer the batch
        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = batch.transactions.len(),
            "Buffering provision batch (waiting for remote header)"
        );
        self.pending_provisions.entry(key).or_default().push(batch);
        vec![]
    }

    /// Emit a `VerifyProvision` action for async merkle proof verification.
    ///
    /// Runs the provision-batch completeness check first: the source block's
    /// `provision_tx_roots[local_shard]` commits to the ordered tx hashes the
    /// target shard is meant to receive. A mismatch means the proposer
    /// dropped txs on the broadcast path (or the batch was tampered with) —
    /// reject the batch entirely so the 10-block fallback timer refetches a
    /// complete one from a peer.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator`, so the
    /// downstream `VerifyProvision` action only needs to check merkle proofs
    /// against the committed state root.
    fn emit_provision_verification(
        &self,
        topology: &TopologySnapshot,
        batch: Provision,
        committed_header: Arc<CommittedBlockHeader>,
    ) -> Vec<Action> {
        let local_shard = topology.local_shard();
        let Some(expected_root) = committed_header
            .header
            .provision_tx_roots
            .get(&local_shard)
            .copied()
        else {
            warn!(
                source_shard = batch.source_shard.0,
                block_height = batch.block_height.0,
                local_shard = local_shard.0,
                "Dropping provision batch: source header has no provision_tx_root for us"
            );
            return vec![];
        };

        let leaves: Vec<Hash> = batch.transactions.iter().map(|t| t.tx_hash).collect();
        let computed_root = compute_padded_merkle_root(&leaves);

        if computed_root != expected_root {
            warn!(
                source_shard = batch.source_shard.0,
                block_height = batch.block_height.0,
                local_shard = local_shard.0,
                tx_count = batch.transactions.len(),
                ?expected_root,
                ?computed_root,
                "Rejecting incomplete provision batch — tx-root mismatch; \
                 fallback fetch will request a complete batch"
            );
            return vec![];
        }

        vec![Action::VerifyProvision {
            batch,
            committed_header,
        }]
    }

    /// Handle batch-level provision verification result.
    ///
    /// If valid: store per-tx entries, emit events.
    /// Uses the verified header returned by the action handler directly (no re-lookup).
    pub fn on_state_provisions_verified(
        &mut self,
        _topology: &TopologySnapshot,
        batch: Provision,
        committed_header: Option<Arc<CommittedBlockHeader>>,
        valid: bool,
    ) -> Vec<Action> {
        let mut actions = vec![];
        let source_shard = batch.source_shard;

        // Clear expected-provision tracking and the matching header. The
        // header's only job — verify this batch — is done; hanging on to it
        // wastes memory. Cancel any in-flight fallback fetch to prevent
        // duplicate delivery.
        if let Some(ref header) = committed_header {
            let shard = header.header.shard_group_id;
            let height = header.header.height;
            let key = (shard, height);

            if self.expected_provisions.remove(&key).is_some() {
                self.verified_remote_headers.remove(&key);
                actions.push(Action::CancelProvisionFetch {
                    source_shard: shard,
                    block_height: height,
                });
            }
        }

        if !valid {
            warn!(
                source_shard = source_shard.0,
                tx_count = batch.transactions.len(),
                "Provision batch verification failed"
            );
            return actions;
        }

        let Some(ref _header) = committed_header else {
            warn!(
                source_shard = source_shard.0,
                "Provision batch marked valid but no committed header"
            );
            return actions;
        };

        // Store the verified batch whole
        let batch_key = (source_shard, batch.block_height);
        let batch = Arc::new(batch);
        let batch_hash = batch.hash();

        // Skip if this batch was already committed (duplicate gossip after commit).
        if self.committed_batch_tombstones.contains_key(&batch_hash) {
            debug!(
                source_shard = source_shard.0,
                batch_hash = ?batch_hash,
                "Skipping already-committed provision batch (tombstoned)"
            );
            return actions;
        }

        self.verified_batches.insert(batch_key, Arc::clone(&batch));
        self.batches_by_hash.insert(batch_hash, Arc::clone(&batch));

        // Queue for inclusion in the next block proposal. Timestamp drives
        // the dwell-time filter in `queued_provisions()` — peers need time to
        // receive/verify the batch via gossip before the proposer commits it.
        self.queued_provision_batches.push(QueuedProvision {
            batch: Arc::clone(&batch),
            added_at: self.now,
        });

        debug!(
            source_shard = source_shard.0,
            tx_count = batch.transactions.len(),
            "Provision batch verified and queued"
        );

        // Emit ProvisionVerified for downstream consumption.
        actions.push(Action::Continuation(ProtocolEvent::ProvisionVerified {
            batch: Arc::clone(&batch),
        }));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Methods (for other modules)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get queued provision batches eligible for inclusion in a block
    /// proposal. Skips batches that haven't met `min_dwell_time` yet — they
    /// stay queued for a later call. Batches remain in the underlying queue
    /// until pruned on block commit.
    pub fn queued_provisions(&self) -> Vec<Arc<Provision>> {
        let min_dwell = self.config.min_dwell_time;
        self.queued_provision_batches
            .iter()
            .filter(|q| self.now.saturating_sub(q.added_at) >= min_dwell)
            .map(|q| Arc::clone(&q.batch))
            .collect()
    }

    /// Look up a verified provision batch by its content hash.
    pub fn get_batch_by_hash(&self, hash: &Hash) -> Option<Arc<Provision>> {
        self.batches_by_hash.get(hash).cloned()
    }

    /// Look up a verified remote committed block header by shard and height.
    pub fn get_remote_header(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<CommittedBlockHeader>> {
        self.verified_remote_headers.get(&(shard, height))
    }

    /// Get the number of verified remote headers.
    pub fn verified_remote_header_count(&self) -> usize {
        self.verified_remote_headers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        bls_keypair_from_seed, BlockHeader, Bls12381G1PrivateKey, Hash, MerkleInclusionProof,
        QuorumCertificate, TopologySnapshot, TxEntries, ValidatorInfo, ValidatorSet, WaveId,
        WeightedTimestamp,
    };

    fn make_test_topology(local_shard: ShardGroupId) -> TopologySnapshot {
        // Create deterministic BLS keypairs for 6 validators (2 shards × 3 validators)
        let keypairs: Vec<Bls12381G1PrivateKey> = (0..6)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[1] = 42; // Fixed seed for determinism
                bls_keypair_from_seed(&seed)
            })
            .collect();

        let validators: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: kp.public_key(),
                voting_power: 1,
            })
            .collect();

        TopologySnapshot::with_local_shard(
            ValidatorId(local_shard.0 * 3), // First validator in shard
            local_shard,
            2,
            ValidatorSet::new(validators),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking Tests (Unverified Buffer)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader with waves targeting ShardGroupId(0)
    /// (the local shard in most tests) so it gets stored in verified_remote_headers.
    fn make_committed_header(shard: ShardGroupId, height: u64) -> Arc<CommittedBlockHeader> {
        make_committed_header_with_targets(shard, height, vec![ShardGroupId(0)])
    }

    /// Build a CommittedBlockHeader whose `provision_tx_roots[local_shard]`
    /// commits to the provided tx hashes — used by tests that fire matching
    /// provision batches through `on_state_provisions_received`.
    fn make_committed_header_committing(
        shard: ShardGroupId,
        height: u64,
        local_shard: ShardGroupId,
        tx_hashes: &[Hash],
    ) -> Arc<CommittedBlockHeader> {
        let mut header_arc = make_committed_header_with_targets(shard, height, vec![local_shard]);
        let header = Arc::get_mut(&mut header_arc).unwrap();
        let root = hyperscale_types::compute_padded_merkle_root(tx_hashes);
        header.header.provision_tx_roots.insert(local_shard, root);
        header_arc
    }

    #[test]
    fn test_remote_header_stored_in_verified_buffer() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(1), 10);
        let actions = coordinator.on_verified_remote_header(&topology, header);
        assert!(actions.is_empty());

        // Should be in verified buffer (pre-verified by RemoteHeaderCoordinator)
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert!(coordinator
            .get_remote_header(ShardGroupId(1), BlockHeight(10))
            .is_some());
    }

    #[test]
    fn test_remote_header_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(0), 10);
        coordinator.on_verified_remote_header(&topology, header);

        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let _sender = ValidatorId(3);
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 11));
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(2), 10));

        assert_eq!(coordinator.verified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header1 = make_committed_header(ShardGroupId(1), 10);
        let header2 = make_committed_header(ShardGroupId(1), 10);

        // Two verified headers for same (shard, height) — last wins
        coordinator.on_verified_remote_header(&topology, header1);
        coordinator.on_verified_remote_header(&topology, header2);

        // Only one entry per (shard, height) in verified map
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let _sender = ValidatorId(3);
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a Provision for testing with a single transaction.
    fn make_batch(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        _target_shard: ShardGroupId,
        height: u64,
    ) -> Provision {
        make_batch_multi(vec![tx_hash], source_shard, height)
    }

    /// Build a Provision for testing with multiple transactions.
    fn make_batch_multi(
        tx_hashes: Vec<Hash>,
        source_shard: ShardGroupId,
        height: u64,
    ) -> Provision {
        let transactions = tx_hashes
            .into_iter()
            .map(|tx_hash| TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            })
            .collect();
        Provision::new(
            source_shard,
            BlockHeight(height),
            MerkleInclusionProof::dummy(),
            transactions,
        )
    }

    #[test]
    fn test_provision_received_with_header_emits_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // First: header arrives (commits to the single tx we'll send).
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(&topology, header);

        // Then: batch arrives — should emit VerifyProvision
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { batch, .. } if batch.transactions[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Batch arrives before header — should buffer
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Batch arrives first — buffered
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch);

        // Then header arrives (commits to the buffered tx) — should trigger verification
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        let actions = coordinator.on_verified_remote_header(&topology, header);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { batch, .. } if batch.transactions[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let batch = make_batch(
            Hash::from_bytes(b"tx1"),
            ShardGroupId(0), // own shard
            ShardGroupId(1),
            10,
        );
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup: header + batch + verification.
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // A duplicate batch for the same (shard, height) must short-circuit —
        // no verification action, no buffering.
        let batch2 = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch2);
        assert!(actions.is_empty());
        assert!(coordinator.pending_provisions.is_empty());
    }

    #[test]
    fn test_provision_verified_emits_provisions_verified() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Verify
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Should emit ProvisionVerified
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionVerified { batch })
            if batch.transactions[0].tx_hash == tx_hash
        )));
    }

    #[test]
    fn test_provision_verified_invalid_does_not_emit() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Verification fails — no committed_header returned
        let actions = coordinator.on_state_provisions_verified(&topology, batch, None, false);

        // Should NOT emit ProvisionVerified
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionVerified { .. })
        )));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch Verification Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_batch_emits_single_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);

        // Send batch with 3 transactions from the same block; header commits to them.
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| Hash::from_bytes(format!("tx{i}").as_bytes()))
            .collect();
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &tx_hashes);
        coordinator.on_verified_remote_header(&topology, header);

        let batch = make_batch_multi(tx_hashes, source_shard, 10);

        let actions = coordinator.on_state_provisions_received(&topology, batch);

        // Should emit exactly ONE VerifyProvision action with all 3 transactions
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvision { batch, .. } => {
                assert_eq!(batch.transactions.len(), 3);
            }
            other => panic!("Expected VerifyProvision, got {:?}", other),
        }
    }

    #[test]
    fn test_provision_uses_single_verified_candidate() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hash = Hash::from_bytes(b"tx1");

        // Verified header from coordinator (commits to the tx we'll send).
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_provision_header_usable_while_batch_outstanding() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hash = Hash::from_bytes(b"tx1");

        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(&topology, header);

        // Batch arrives while the header is live — verification dispatches.
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_partial_provision_batch_rejected() {
        // Proposer's broadcast path drops a tx from a batch. The source block
        // header commits to the full tx set; the arriving batch contains only
        // a subset. Completeness check must reject so the fallback fetch
        // refetches a complete batch from a peer.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_full = vec![
            Hash::from_bytes(b"tx_a"),
            Hash::from_bytes(b"tx_b"),
            Hash::from_bytes(b"tx_c"),
        ];
        let header = make_committed_header_committing(source_shard, 10, ShardGroupId(0), &tx_full);
        coordinator.on_verified_remote_header(&topology, header);

        // Arriving batch is missing tx_c.
        let partial = make_batch_multi(tx_full[..2].to_vec(), source_shard, 10);
        let actions = coordinator.on_state_provisions_received(&topology, partial);

        assert!(
            actions.is_empty(),
            "partial batch must be rejected, not dispatched"
        );
    }

    #[test]
    fn test_batch_with_missing_header_entry_rejected() {
        // Source block has no provision_tx_roots entry for our shard, yet a
        // batch arrived claiming to target us — reject.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        // Header targets our shard via waves but has no provision_tx_roots
        // entry for us — mismatched commitment shape.
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);

        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_batch_invalid_does_not_emit() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hashes = vec![Hash::from_bytes(b"tx_ok"), Hash::from_bytes(b"tx_bad")];
        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &tx_hashes);
        coordinator.on_verified_remote_header(&topology, header.clone());

        let batch = make_batch_multi(tx_hashes, source_shard, 10);

        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Entire batch fails verification
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), false);

        // Verification failed — no ProvisionVerified emitted
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionVerified { .. })
        )));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (Fallback Detection) Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader that claims provisions target the given shards.
    fn make_committed_header_with_targets(
        shard: ShardGroupId,
        height: u64,
        provision_targets: Vec<ShardGroupId>,
    ) -> Arc<CommittedBlockHeader> {
        // Each target shard gets its own single-dependency wave so that
        // `provision_targets()` on the resulting header yields the input set.
        let waves: Vec<WaveId> = provision_targets
            .into_iter()
            .map(|s| WaveId {
                shard_group_id: shard,
                block_height: height,
                remote_shards: std::collections::BTreeSet::from([s]),
            })
            .collect();
        let header = BlockHeader {
            shard_group_id: shard,
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: hyperscale_types::ProposerTimestamp(1000 + height),
            round: 0,
            is_fallback: false,
            state_root: Hash::from_bytes(format!("root_{shard}_{height}").as_bytes()),
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves,
            provision_tx_roots: std::collections::BTreeMap::new(),
            in_flight: 0,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        Arc::new(CommittedBlockHeader::new(header, qc))
    }

    /// Nominal block spacing used by tests to synthesize `weighted_timestamp_ms`
    /// from block heights. Ratios against timeout constants below preserve the
    /// old "block count" intuition when reading the tests.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    /// Make a minimal Block at the given height for on_block_committed calls.
    /// The attached QC's `weighted_timestamp_ms` is `height * TEST_BLOCK_INTERVAL_MS`.
    fn make_block(height: u64) -> hyperscale_types::CertifiedBlock {
        let mut header =
            hyperscale_types::BlockHeader::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO);
        header.height = BlockHeight(height);
        let block = hyperscale_types::Block::Live {
            header,
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = hyperscale_types::QuorumCertificate {
            block_hash: block.hash(),
            weighted_timestamp: WeightedTimestamp(height * TEST_BLOCK_INTERVAL_MS),
            ..hyperscale_types::QuorumCertificate::genesis()
        };
        hyperscale_types::CertifiedBlock::new_unchecked(block, qc)
    }

    #[test]
    fn test_expected_provision_tracked_when_header_targets_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 0 (our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Should have one expected provision
        assert_eq!(coordinator.expected_provisions.len(), 1);
    }

    #[test]
    fn test_expected_provision_not_tracked_when_header_does_not_target_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 2 (NOT our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(2)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Header should NOT be stored (not expecting provisions from it)
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_expected_provision_cleared_on_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Batch arrives and is verified
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Expected provision should be cleared
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_timeout_emits_request_missing_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Prime local clock with a first commit so the expected-provision
        // entry stamped below gets a real baseline (not the zero sentinel).
        coordinator.on_block_committed(&topology, &make_block(1));

        // Remote header arrives targeting our shard; discovered_at stamped at ts=500ms.
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance blocks — should not emit before the timeout threshold.
        // discovered_at = 500ms; fires when now_ms - 500 >= 5000 → h = 11.
        for h in 2..=10 {
            let block = make_block(h);
            let actions = coordinator.on_block_committed(&topology, &block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 11, age = 5500 - 500 = 5000 >= PROVISION_FALLBACK_TIMEOUT → fires.
        let block = make_block(11);
        let actions = coordinator.on_block_committed(&topology, &block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::FetchProvisionRemote {
                source_shard,
                block_height,
                proposer,
                ..
            } if *source_shard == ShardGroupId(1)
                && *block_height == BlockHeight(10)
                && *proposer == ValidatorId(0)
        ));
    }

    #[test]
    fn test_pregenesis_header_retrostamped_on_first_commit() {
        // Regression: without retro-stamping, an expected_provisions entry
        // recorded while `local_committed_ts_ms == 0` would report a ~epoch-ms
        // age on the very next commit and trigger an immediate fallback,
        // bypassing PROVISION_FALLBACK_TIMEOUT entirely.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote header arrives BEFORE any local block commits.
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // First local commit at ts=500ms. Should NOT fire — the pre-genesis
        // entry has just been retro-stamped to 500ms.
        let actions = coordinator.on_block_committed(&topology, &make_block(1));
        assert!(
            actions.is_empty(),
            "Pre-genesis entry must be retro-stamped, not fire immediately"
        );

        // Fires on schedule from the retro-stamp baseline, not absolute zero.
        for h in 2..=10 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h));
            assert!(actions.is_empty(), "Should not emit at height {h}");
        }
        let actions = coordinator.on_block_committed(&topology, &make_block(11));
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_no_re_emission_after_initial_request() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&topology, &make_block(h));
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h));
            assert!(
                actions.is_empty(),
                "Should never re-emit after initial request (height {h})"
            );
        }
    }

    #[test]
    fn test_no_timeout_when_provision_verified_in_time() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&topology, &make_block(h));
        }

        // Batch arrives and is verified before timeout
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h));
            assert!(
                actions.is_empty(),
                "Should not request at height {h} (provision already verified)"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CancelProvisionFetch Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verified_provisions_emit_cancel_fetch() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);

        // Remote header targeting our shard — creates expected_provision entry
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Batch arrives and is verified
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Should emit CancelProvisionFetch action
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::CancelProvisionFetch {
                    source_shard: s,
                    block_height: h,
                } if *s == source_shard && *h == BlockHeight(10)
            )),
            "Should emit CancelProvisionFetch when expected provision is verified"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Header Retention Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_header_retained_while_batch_outstanding() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Advance local well past any old time-based cutoff but short of the
        // orphan threshold. Header stays because its batch hasn't verified yet.
        let orphan_cutoff_blocks = ORPHAN_HEADER_CUTOFF.as_millis() as u64 / TEST_BLOCK_INTERVAL_MS;
        for h in 1..=(orphan_cutoff_blocks / 2) {
            coordinator.on_block_committed(&topology, &make_block(h));
        }

        assert_eq!(
            coordinator.verified_remote_header_count(),
            1,
            "Header must be retained while expected_provisions entry is live"
        );
    }

    #[test]
    fn test_header_dropped_on_batch_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hash = Hash::from_bytes(b"tx1");

        let header =
            make_committed_header_committing(source_shard, 10, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        assert_eq!(
            coordinator.verified_remote_header_count(),
            0,
            "Header must be dropped once its batch is verified"
        );
    }

    #[test]
    fn test_orphan_header_dropped_after_cutoff() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Prime local clock so the expected-provision entry gets a real
        // baseline rather than the zero sentinel retro-stamped on first commit.
        coordinator.on_block_committed(&topology, &make_block(1));

        // Header arrives but the batch never does — this is the orphan case
        // the long-horizon sweep guards against.
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Not yet past the orphan cutoff — still retained.
        // discovered_at was stamped at ts=500ms (the priming commit).
        let orphan_cutoff_blocks = ORPHAN_HEADER_CUTOFF.as_millis() as u64 / TEST_BLOCK_INTERVAL_MS;
        for h in 2..=orphan_cutoff_blocks + 1 {
            coordinator.on_block_committed(&topology, &make_block(h));
        }
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // One past — orphan sweep drops header and expected entry together.
        coordinator.on_block_committed(&topology, &make_block(orphan_cutoff_blocks + 2));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Dwell-time Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Helper: verify a batch through the coordinator, returning the queue
    /// size. Stamps `added_at` at `coordinator.now`.
    fn verify_batch_into_queue(
        coordinator: &mut ProvisionCoordinator,
        topology: &TopologySnapshot,
        source_shard: ShardGroupId,
        height: u64,
        tx_hash: Hash,
    ) {
        let header =
            make_committed_header_committing(source_shard, height, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), height);
        coordinator.on_state_provisions_received(topology, batch.clone());
        coordinator.on_state_provisions_verified(topology, batch, Some(header), true);
    }

    #[test]
    fn test_dwell_time_zero_yields_immediately() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::ZERO,
        });
        coordinator.set_time(Duration::from_secs(1));
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            10,
            Hash::from_bytes(b"tx1"),
        );

        assert_eq!(
            coordinator.queued_provisions().len(),
            1,
            "Zero dwell time should expose the batch immediately"
        );
    }

    #[test]
    fn test_dwell_time_filters_young_batch() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::from_millis(500),
        });

        // Verify at t=1.0s
        coordinator.set_time(Duration::from_secs(1));
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            10,
            Hash::from_bytes(b"tx1"),
        );

        // t=1.2s — dwell not met (200ms < 500ms)
        coordinator.set_time(Duration::from_millis(1200));
        assert_eq!(
            coordinator.queued_provisions().len(),
            0,
            "Batch younger than min_dwell_time must be skipped"
        );

        // t=1.5s — exactly at dwell
        coordinator.set_time(Duration::from_millis(1500));
        assert_eq!(
            coordinator.queued_provisions().len(),
            1,
            "Batch at min_dwell_time must become eligible"
        );
    }

    #[test]
    fn test_dwell_time_mixed_eligibility() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::from_millis(200),
        });

        // t=1.0s: verify old batch
        coordinator.set_time(Duration::from_secs(1));
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            10,
            Hash::from_bytes(b"tx_old"),
        );

        // t=1.3s: verify young batch
        coordinator.set_time(Duration::from_millis(1300));
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            11,
            Hash::from_bytes(b"tx_young"),
        );

        // t=1.4s: old batch dwelled 400ms (eligible), young batch dwelled
        // 100ms (still blocked).
        coordinator.set_time(Duration::from_millis(1400));
        let eligible = coordinator.queued_provisions();
        assert_eq!(eligible.len(), 1);
        assert_eq!(
            eligible[0].transactions[0].tx_hash,
            Hash::from_bytes(b"tx_old")
        );
    }
}
