//! Centralized provision coordination.
//!
//! Tracks all cross-shard provisions, manages QC + merkle proof verification,
//! and emits verification events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts `StateProvisions` notifications
//! carrying JMT inclusion proofs. The target shard joins with remote block
//! headers, then dispatches `VerifyStateProvision` to verify the QC
//! signature once and merkle proofs per state entry against the committed
//! state root.

use crate::expected::ExpectedProvisionTracker;
use crate::pipeline::ProvisionPipeline;
use crate::queue::QueuedProvisionBuffer;
use crate::store::ProvisionStore;
use crate::verified_headers::VerifiedHeaderBuffer;
use hyperscale_core::{Action, FetchRequest, ProtocolEvent};
use hyperscale_types::{
    BlockHeight, CommittedBlockHeader, Hash, LocalTimestamp, ProvisionHash, ProvisionTxRoot,
    Provisions, RETENTION_HORIZON, ShardGroupId, TopologySnapshot, compute_padded_merkle_root,
};
#[cfg(test)]
use hyperscale_types::{
    CertificateRoot, LocalReceiptRoot, ProvisionsRoot, StateRoot, TransactionRoot, TxHash,
    ValidatorId,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

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
    pub committed_tombstones: usize,
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
    headers: VerifiedHeaderBuffer,

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
    /// the local committed anchor every other sub-machine reads through
    /// (`local_ts`, `local_height`).
    expected: ExpectedProvisionTracker,

    // ═══════════════════════════════════════════════════════════════════
    // Proposal Queue + Tombstones
    // ═══════════════════════════════════════════════════════════════════
    /// Verified provisions eligible for inclusion in the next block
    /// proposal, gated by a configured dwell window so peers have time to
    /// receive the same provisions via gossip. Tombstones for committed
    /// provisions gate duplicate gossip after commit.
    queue: QueuedProvisionBuffer,
}

impl std::fmt::Debug for ProvisionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionCoordinator")
            .field("verified_remote_headers", &self.headers.len())
            .field("verified_provisions", &self.pipeline.verified_len())
            .finish_non_exhaustive()
    }
}

impl Default for ProvisionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionCoordinator {
    /// Create a new `ProvisionCoordinator` with default config and a fresh
    /// local [`ProvisionStore`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config_and_store(ProvisionConfig::default(), Arc::new(ProvisionStore::new()))
    }

    /// Create a new `ProvisionCoordinator` with the given config and a fresh
    /// local [`ProvisionStore`].
    #[must_use]
    pub fn with_config(config: ProvisionConfig) -> Self {
        Self::with_config_and_store(config, Arc::new(ProvisionStore::new()))
    }

    /// Create a new `ProvisionCoordinator` wired to an externally-owned
    /// [`ProvisionStore`]. Production nodes share the store with the
    /// io-loop so `local_provision.request` handlers read from the same
    /// source of truth this coordinator writes to.
    #[must_use]
    pub fn with_config_and_store(config: ProvisionConfig, store: Arc<ProvisionStore>) -> Self {
        let queue = QueuedProvisionBuffer::new(config.min_dwell_time);
        Self {
            headers: VerifiedHeaderBuffer::new(),
            pipeline: ProvisionPipeline::new(store),
            expected: ExpectedProvisionTracker::new(),
            queue,
        }
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
            committed_tombstones: self.queue.tombstone_len(),
        }
    }

    /// Handle block committed.
    ///
    /// Orchestration order matters:
    /// 1. `expected.record_block_committed` updates the local anchor and
    ///    retro-stamps pre-genesis entries. Must precede any sweep that
    ///    reads `local_ts`.
    /// 2. `queue.on_block_committed` tombstones committed provisions and
    ///    drops them from the proposer queue.
    /// 3. Orphan cleanup evicts expectations whose fallback never resolved
    ///    and prunes their matching headers.
    /// 4. `queue.prune_tombstones` and `drop_past_deadline` use the same
    ///    `local_ts` cutoff for retention sweeps.
    /// 5. Timeout sweep emits fallback fetches for late expectations.
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        certified: &hyperscale_types::CertifiedBlock,
    ) -> Vec<Action> {
        let block = &certified.block;
        let new_ts = certified.qc.weighted_timestamp;
        self.expected.record_block_committed(block.height(), new_ts);
        let local_ts = self.expected.local_ts();

        // Tombstone provisions committed in this block to prevent re-queueing
        // if duplicate gossip arrives later, and drop them from the proposer
        // queue so we don't re-include the same provisions in the next
        // proposal. The deadline sweep below evicts the provisions themselves
        // from the pipeline / store once the source has aged past
        // `RETENTION_HORIZON`.
        let committed: std::collections::HashSet<ProvisionHash> =
            block.provisions().iter().map(|p| p.hash()).collect();
        self.queue.on_block_committed(&committed, local_ts);

        // Single retention cutoff for orphan and tombstone sweeps —
        // `local_ts - RETENTION_HORIZON` is the conservative point past
        // which any expectation, tombstone, or queued/verified entry is
        // provably useless on every shard.
        let retention_cutoff = local_ts.minus(RETENTION_HORIZON);

        // Drop truly orphaned expectations (and their headers) whose
        // fallback fetch never resolved within `RETENTION_HORIZON`. Under
        // normal operation a header is retained exactly while its provisions
        // are outstanding; this only catches entries that would otherwise
        // leak indefinitely.
        for key in self.expected.cleanup_orphans(retention_cutoff) {
            self.headers.remove(key);
        }

        // Prune tombstones past `RETENTION_HORIZON`, measured against
        // BFT-authenticated time.
        self.queue.prune_tombstones(retention_cutoff);

        // Drop provisions whose deadline has passed but never reached
        // commit. Without this, verified provisions whose source data has
        // aged past `RETENTION_HORIZON` linger indefinitely in the proposer
        // queue and end up in proposals that peers cannot verify (their
        // paired remote header is gone). Drives the cluster into endless
        // view changes.
        self.drop_past_deadline();

        // Lift each timed-out expectation into a fallback fetch action,
        // attaching the source shard's committee from topology.
        self.expected
            .check_timeouts(local_ts)
            .into_iter()
            .map(|effect| {
                Action::Fetch(FetchRequest::RemoteProvisions {
                    source_shard: effect.source_shard,
                    block_height: effect.block_height,
                    proposer: effect.proposer,
                    peers: topology.committee_for_shard(effect.source_shard).to_vec(),
                })
            })
            .collect()
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
    fn drop_past_deadline(&mut self) {
        let now = self.expected.local_ts();

        self.queue.drop_past_deadline(now);

        let evicted_keys = self.pipeline.drop_past_deadline(now);
        for key in evicted_keys {
            self.headers.remove(key);
        }
    }

    /// Immediately emit `FetchProvisionsRemote` for all outstanding expected
    /// provisions, bypassing the normal liveness timeout.
    ///
    /// Called when urgency overrides the default patience — sync completion
    /// (validator needs to catch up before `WAVE_TIMEOUT` runs out) and the
    /// execution advance gate stalling on missing data.
    pub fn flush_expected_provisions(
        &mut self,
        topology: &hyperscale_types::TopologySnapshot,
    ) -> Vec<Action> {
        self.expected
            .flush_all()
            .into_iter()
            .map(|effect| {
                info!(
                    source_shard = effect.source_shard.0,
                    block_height = effect.block_height.0,
                    "Eager fetch — immediately requesting missing provisions"
                );
                Action::Fetch(FetchRequest::RemoteProvisions {
                    source_shard: effect.source_shard,
                    block_height: effect.block_height,
                    proposer: effect.proposer,
                    peers: topology.committee_for_shard(effect.source_shard).to_vec(),
                })
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a verified remote header from the `RemoteHeaderCoordinator`.
    ///
    /// Called when `RemoteHeaderVerified` is received. The header has already
    /// passed QC verification, so we store it directly as verified and:
    /// 1. Register expected provisions if waves target our shard
    /// 2. Join with any buffered provisions waiting for this header
    pub fn on_verified_remote_header(
        &mut self,
        topology: &TopologySnapshot,
        committed_header: &Arc<CommittedBlockHeader>,
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
            self.headers.insert(key, Arc::clone(committed_header));

            let proposer = committed_header.header.proposer;
            debug!(
                shard = shard.0,
                height = height.0,
                proposer = proposer.0,
                "Tracking expected provisions (verified remote block targets our shard)"
            );
            self.expected.register(shard, height, proposer);
        }

        // Join with buffered provisions waiting for this header.
        let mut actions = vec![];
        let drained = self.pipeline.drain_pending_for_key(key);
        if !drained.is_empty() {
            debug!(
                shard = shard.0,
                height = height.0,
                pending_count = drained.len(),
                "Found buffered provisions for verified header"
            );
            for provisions in drained {
                actions.extend(Self::emit_provision_verification(
                    topology,
                    provisions,
                    Arc::clone(committed_header),
                ));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle provisions received from a source shard proposer.
    ///
    /// All transactions in the entry share the same
    /// `(source_shard, block_height)` via the entry's proof. Joins with
    /// the corresponding verified remote block header:
    /// - If a verified header exists: emit verification with single candidate
    /// - If no header yet: buffer the provisions until
    ///   `on_verified_remote_header` delivers it
    pub fn on_state_provisions_received(
        &mut self,
        topology: &TopologySnapshot,
        provisions: Provisions,
    ) -> Vec<Action> {
        if provisions.transactions.is_empty() {
            return vec![];
        }

        let source_shard = provisions.source_shard;
        let block_height = provisions.block_height;

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = provisions.transactions.len(),
            "Provisions received"
        );

        // Ignore provisions from our own shard
        if source_shard == topology.local_shard() {
            return vec![];
        }

        // Reject provisions not destined for our shard. Indicates a proposer
        // bug, a network misroute, or an adversarial attempt — log loudly so
        // it's visible but don't propagate.
        if provisions.target_shard != topology.local_shard() {
            warn!(
                source_shard = source_shard.0,
                target_shard = provisions.target_shard.0,
                local_shard = topology.local_shard().0,
                block_height = block_height.0,
                "Dropping provisions: target_shard does not match local shard"
            );
            return vec![];
        }

        let key = (source_shard, block_height);

        // Skip if this key was already verified (duplicate gossip/fetch) or
        // already committed (tombstoned by hash). Avoids re-dispatching
        // verification work and buffering stale duplicates.
        if self.pipeline.has_verified(key) || self.queue.is_tombstoned(&provisions.hash()) {
            return vec![];
        }

        // Look for matching verified remote header (pre-verified by RemoteHeaderCoordinator).
        if let Some(verified_header) = self.headers.get(key).cloned() {
            // Reject if the source block has aged past `RETENTION_HORIZON` —
            // every tx in it has expired and no shard can still need this data.
            let deadline = provisions.deadline(verified_header.qc.weighted_timestamp);
            if deadline <= self.expected.local_ts() {
                debug!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    "Dropping provisions past deadline at receipt"
                );
                return vec![];
            }
            return Self::emit_provision_verification(topology, provisions, verified_header);
        }

        // No verified header yet — buffer the provisions
        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = provisions.transactions.len(),
            "Buffering provisions (waiting for remote header)"
        );
        self.pipeline
            .buffer_pending(key, provisions, self.expected.local_ts());
        vec![]
    }

    /// Emit a `VerifyProvisions` action for async merkle proof verification.
    ///
    /// Runs the provisions completeness check first: the source block's
    /// `provision_tx_roots[local_shard]` commits to the ordered tx hashes the
    /// target shard is meant to receive. A mismatch means the proposer
    /// dropped txs on the broadcast path (or the provisions were tampered
    /// with) — reject entirely so the 10-block fallback timer refetches a
    /// complete set from a peer.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator`, so the
    /// downstream `VerifyProvisions` action only needs to check merkle proofs
    /// against the committed state root.
    fn emit_provision_verification(
        topology: &TopologySnapshot,
        provisions: Provisions,
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
                source_shard = provisions.source_shard.0,
                block_height = provisions.block_height.0,
                local_shard = local_shard.0,
                "Dropping provisions: source header has no provision_tx_root for us"
            );
            return vec![];
        };

        let leaves: Vec<Hash> = provisions
            .transactions
            .iter()
            .map(|t| t.tx_hash.into_raw())
            .collect();
        let computed_root = ProvisionTxRoot::from_raw(compute_padded_merkle_root(&leaves));

        if computed_root != expected_root {
            warn!(
                source_shard = provisions.source_shard.0,
                block_height = provisions.block_height.0,
                local_shard = local_shard.0,
                tx_count = provisions.transactions.len(),
                ?expected_root,
                ?computed_root,
                "Rejecting incomplete provisions — tx-root mismatch; \
                 fallback fetch will request a complete set"
            );
            return vec![];
        }

        vec![Action::VerifyProvisions {
            provisions,
            committed_header,
        }]
    }

    /// Handle the verification result for a provisions entry.
    ///
    /// If valid: store, queue, emit events.
    /// Uses the verified header returned by the action handler directly (no re-lookup).
    pub fn on_state_provisions_verified(
        &mut self,
        _topology: &TopologySnapshot,
        provisions: Provisions,
        committed_header: Option<&Arc<CommittedBlockHeader>>,
        valid: bool,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let mut actions = vec![];
        let source_shard = provisions.source_shard;

        // Clear expected-provision tracking and the matching header. The
        // header's only job — verify these provisions — is done; hanging on
        // to it wastes memory. Any in-flight fallback fetch self-cancels
        // via the `ProvisionsVerified` continuation, which the io_loop
        // turns into an admission signal on the provision fetch protocol.
        if let Some(header) = committed_header {
            let shard = header.header.shard_group_id;
            let height = header.header.height;
            let key = (shard, height);

            if self.expected.on_provisions_verified(shard, height) {
                self.headers.remove(key);
            }
        }

        if !valid {
            warn!(
                source_shard = source_shard.0,
                tx_count = provisions.transactions.len(),
                "Provisions verification failed"
            );
            return actions;
        }

        let Some(header) = committed_header else {
            warn!(
                source_shard = source_shard.0,
                "Provisions marked valid but no committed header"
            );
            return actions;
        };
        let source_block_ts = header.qc.weighted_timestamp;

        // Skip if these provisions were already committed (duplicate gossip after commit).
        if self.queue.is_tombstoned(&provisions.hash()) {
            debug!(
                source_shard = source_shard.0,
                provision_hash = ?provisions.hash(),
                "Skipping already-committed provisions (tombstoned)"
            );
            return actions;
        }

        let provisions = self.pipeline.insert_verified(provisions, source_block_ts);

        // Queue for inclusion in the next block proposal. Timestamp drives
        // the dwell-time filter in `queued_provisions()` — peers need time
        // to receive/verify the provisions via gossip before the proposer
        // commits them.
        self.queue
            .enqueue(Arc::clone(&provisions), source_block_ts, now);

        debug!(
            source_shard = source_shard.0,
            tx_count = provisions.transactions.len(),
            "Provisions verified and queued"
        );

        // Emit ProvisionsVerified for downstream consumption. The source
        // block timestamp anchors retention in the io-loop provision cache.
        actions.push(Action::Continuation(ProtocolEvent::ProvisionsVerified {
            provisions: Arc::clone(&provisions),
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
    pub fn queued_provisions(&self, now: LocalTimestamp) -> Vec<Arc<Provisions>> {
        self.queue.queued(now)
    }

    /// Look up verified provisions by their content hash.
    #[must_use]
    pub fn get_provisions_by_hash(&self, hash: &ProvisionHash) -> Option<Arc<Provisions>> {
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
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<CommittedBlockHeader>> {
        self.headers.get((shard, height))
    }

    /// Get the number of verified remote headers.
    #[must_use]
    pub fn verified_remote_header_count(&self) -> usize {
        self.headers.len()
    }

    /// Whether cross-shard provisions for `(source_shard, block_height)` are
    /// currently expected — i.e. a verified remote header has registered an
    /// expectation that hasn't yet been satisfied.
    #[must_use]
    pub fn is_expected(&self, source_shard: ShardGroupId, block_height: BlockHeight) -> bool {
        self.expected.contains(source_shard, block_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHash, BlockHeader, Bls12381G1PrivateKey, Hash, MerkleInclusionProof,
        QuorumCertificate, Round, TopologySnapshot, TxEntries, ValidatorInfo, ValidatorSet, WaveId,
        WeightedTimestamp, bls_keypair_from_seed,
    };

    fn make_test_topology(local_shard: ShardGroupId) -> TopologySnapshot {
        // Create deterministic BLS keypairs for 6 validators (2 shards × 3 validators)
        let keypairs: Vec<Bls12381G1PrivateKey> = (0u8..6)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i;
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

    /// Build a `CommittedBlockHeader` with waves targeting `ShardGroupId(0)`
    /// (the local shard in most tests) so it gets stored in `verified_remote_headers`.
    fn make_committed_header(
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Arc<CommittedBlockHeader> {
        make_committed_header_with_targets(shard, height, vec![ShardGroupId(0)])
    }

    /// Build a `CommittedBlockHeader` whose `provision_tx_roots[local_shard]`
    /// commits to the provided tx hashes — used by tests that fire matching
    /// provisions through `on_state_provisions_received`.
    fn make_committed_header_committing(
        shard: ShardGroupId,
        height: BlockHeight,
        local_shard: ShardGroupId,
        tx_hashes: &[TxHash],
    ) -> Arc<CommittedBlockHeader> {
        let mut header_arc = make_committed_header_with_targets(shard, height, vec![local_shard]);
        let header = Arc::get_mut(&mut header_arc).unwrap();
        let raw: Vec<Hash> = tx_hashes.iter().map(|h| h.into_raw()).collect();
        let root = ProvisionTxRoot::from_raw(hyperscale_types::compute_padded_merkle_root(&raw));
        header.header.provision_tx_roots.insert(local_shard, root);
        header_arc
    }

    #[test]
    fn test_remote_header_stored_in_verified_buffer() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(1), BlockHeight(10));
        let actions = coordinator.on_verified_remote_header(&topology, &header);
        assert!(actions.is_empty());

        // Should be in verified buffer (pre-verified by RemoteHeaderCoordinator)
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert!(
            coordinator
                .get_remote_header(ShardGroupId(1), BlockHeight(10))
                .is_some()
        );
    }

    #[test]
    fn test_remote_header_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(0), BlockHeight(10));
        coordinator.on_verified_remote_header(&topology, &header);

        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        coordinator.on_verified_remote_header(
            &topology,
            &make_committed_header(ShardGroupId(1), BlockHeight(10)),
        );
        coordinator.on_verified_remote_header(
            &topology,
            &make_committed_header(ShardGroupId(1), BlockHeight(11)),
        );
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator.on_verified_remote_header(
            &topology,
            &make_committed_header(ShardGroupId(2), BlockHeight(10)),
        );

        assert_eq!(coordinator.verified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header1 = make_committed_header(ShardGroupId(1), BlockHeight(10));
        let header2 = make_committed_header(ShardGroupId(1), BlockHeight(10));

        // Two verified headers for same (shard, height) — last wins
        coordinator.on_verified_remote_header(&topology, &header1);
        coordinator.on_verified_remote_header(&topology, &header2);

        // Only one entry per (shard, height) in verified map
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        coordinator.on_verified_remote_header(
            &topology,
            &make_committed_header(ShardGroupId(1), BlockHeight(10)),
        );
        coordinator.on_verified_remote_header(
            &topology,
            &make_committed_header(ShardGroupId(1), BlockHeight(10)),
        );

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a Provision for testing with a single transaction.
    fn make_provisions(
        tx_hash: TxHash,
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        height: BlockHeight,
    ) -> Provisions {
        make_provisions_multi(vec![tx_hash], source_shard, target_shard, height)
    }

    /// Build a Provision for testing with multiple transactions.
    fn make_provisions_multi(
        tx_hashes: Vec<TxHash>,
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        height: BlockHeight,
    ) -> Provisions {
        let transactions = tx_hashes
            .into_iter()
            .map(|tx_hash| TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            })
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        // First: header arrives (commits to the single tx we'll send).
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Then: provisions arrives — should emit VerifyProvisions
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { provisions, .. } if provisions.transactions[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        // Batch arrives before header — should buffer
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        // Batch arrives first — buffered
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions);

        // Then header arrives (commits to the buffered tx) — should trigger verification
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        let actions = coordinator.on_verified_remote_header(&topology, &header);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { provisions, .. } if provisions.transactions[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            ShardGroupId(0), // own shard
            ShardGroupId(1),
            BlockHeight(10),
        );
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        // Setup: header + provisions + verification.
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        // A duplicate provisions for the same (shard, height) must short-circuit —
        // no verification action, no buffering.
        let batch2 = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, batch2);
        assert!(actions.is_empty());
        assert_eq!(coordinator.pipeline.pending_len(), 0);
    }

    #[test]
    fn test_provision_verified_emits_provisions_verified() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        // Setup
        let header = make_committed_header(source_shard, BlockHeight(10));
        coordinator.on_verified_remote_header(&topology, &header);
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions.clone());

        // Verify
        let actions = coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        // Should emit ProvisionsVerified
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsVerified { provisions, .. })
            if provisions.transactions[0].tx_hash == tx_hash
        )));
    }

    #[test]
    fn test_provision_verified_invalid_does_not_emit() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let source_shard = ShardGroupId(1);

        let header = make_committed_header(source_shard, BlockHeight(10));
        coordinator.on_verified_remote_header(&topology, &header);
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions.clone());

        // Verification fails — no committed_header returned
        let actions = coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            None,
            false,
            LocalTimestamp::ZERO,
        );

        // Should NOT emit ProvisionsVerified
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsVerified { .. })
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

        // Send provisions with 3 transactions from the same block; header commits to them.
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| TxHash::from_raw(Hash::from_bytes(format!("tx{i}").as_bytes())))
            .collect();
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &tx_hashes,
        );
        coordinator.on_verified_remote_header(&topology, &header);

        let provisions =
            make_provisions_multi(tx_hashes, source_shard, ShardGroupId(0), BlockHeight(10));

        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        // Should emit exactly ONE VerifyProvisions action with all 3 transactions
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvisions { provisions, .. } => {
                assert_eq!(provisions.transactions.len(), 3);
            }
            other => panic!("Expected VerifyProvisions, got {other:?}"),
        }
    }

    #[test]
    fn test_provision_uses_single_verified_candidate() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        // Verified header from coordinator (commits to the tx we'll send).
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_provision_header_usable_while_batch_outstanding() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Batch arrives while the header is live — verification dispatches.
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisions { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_partial_provision_batch_rejected() {
        // Proposer's broadcast path drops a tx from a provisions. The source block
        // header commits to the full tx set; the arriving provisions contains only
        // a subset. Completeness check must reject so the fallback fetch
        // refetches a complete provisions from a peer.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_full = vec![
            TxHash::from_raw(Hash::from_bytes(b"tx_a")),
            TxHash::from_raw(Hash::from_bytes(b"tx_b")),
            TxHash::from_raw(Hash::from_bytes(b"tx_c")),
        ];
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &tx_full,
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Arriving provisions is missing tx_c.
        let partial = make_provisions_multi(
            tx_full[..2].to_vec(),
            source_shard,
            ShardGroupId(0),
            BlockHeight(10),
        );
        let actions = coordinator.on_state_provisions_received(&topology, partial);

        assert!(
            actions.is_empty(),
            "partial provisions must be rejected, not dispatched"
        );
    }

    #[test]
    fn test_batch_with_missing_header_entry_rejected() {
        // Source block has no provision_tx_roots entry for our shard, yet a
        // provisions arrived claiming to target us — reject.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        // Header targets our shard via waves but has no provision_tx_roots
        // entry for us — mismatched commitment shape.
        let header = make_committed_header(source_shard, BlockHeight(10));
        coordinator.on_verified_remote_header(&topology, &header);

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardGroupId(0),
            BlockHeight(10),
        );
        let actions = coordinator.on_state_provisions_received(&topology, provisions);

        assert!(actions.is_empty());
    }

    #[test]
    fn test_batch_invalid_does_not_emit() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let tx_hashes = vec![
            TxHash::from_raw(Hash::from_bytes(b"tx_ok")),
            TxHash::from_raw(Hash::from_bytes(b"tx_bad")),
        ];
        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &tx_hashes,
        );
        coordinator.on_verified_remote_header(&topology, &header);

        let provisions =
            make_provisions_multi(tx_hashes, source_shard, ShardGroupId(0), BlockHeight(10));

        coordinator.on_state_provisions_received(&topology, provisions.clone());

        // Entire provisions fails verification
        let actions = coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            false,
            LocalTimestamp::ZERO,
        );

        // Verification failed — no ProvisionsVerified emitted
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsVerified { .. })
        )));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (Fallback Detection) Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a `CommittedBlockHeader` that claims provisions target the given shards.
    fn make_committed_header_with_targets(
        shard: ShardGroupId,
        height: BlockHeight,
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
            height,
            parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: hyperscale_types::ProposerTimestamp(1000 + height.0),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::from_raw(Hash::from_bytes(
                format!("root_{shard}_{height}").as_bytes(),
            )),
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
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

    /// Make a minimal `Block` at the given height for `on_block_committed` calls.
    /// The attached QC's `weighted_timestamp_ms` is `height * TEST_BLOCK_INTERVAL_MS`.
    fn make_block(height: BlockHeight) -> hyperscale_types::CertifiedBlock {
        let mut header = hyperscale_types::BlockHeader::genesis(
            ShardGroupId(0),
            ValidatorId(0),
            StateRoot::ZERO,
        );
        header.height = height;
        let block = hyperscale_types::Block::Live {
            header,
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = hyperscale_types::QuorumCertificate {
            block_hash: block.hash(),
            weighted_timestamp: WeightedTimestamp(height.0 * TEST_BLOCK_INTERVAL_MS),
            ..hyperscale_types::QuorumCertificate::genesis()
        };
        hyperscale_types::CertifiedBlock::new_unchecked(block, qc)
    }

    #[test]
    fn test_expected_provision_tracked_when_header_targets_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 0 (our shard)
        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Should have one expected provision
        assert_eq!(coordinator.expected.len(), 1);
    }

    #[test]
    fn test_expected_provision_not_tracked_when_header_does_not_target_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 2 (NOT our shard)
        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(2)],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Header should NOT be stored (not expecting provisions from it)
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected.len(), 0);
    }

    #[test]
    fn test_expected_provision_cleared_on_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(
            source_shard,
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // Batch arrives and is verified
        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardGroupId(0),
            BlockHeight(10),
        );
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        // Expected provision should be cleared
        assert_eq!(coordinator.expected.len(), 0);
    }

    #[test]
    fn test_timeout_emits_request_missing_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Prime local clock with a first commit so the expected-provision
        // entry stamped below gets a real baseline (not the zero sentinel).
        coordinator.on_block_committed(&topology, &make_block(BlockHeight(1)));

        // Remote header arrives targeting our shard; discovered_at stamped at ts=500ms.
        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Advance blocks — should not emit before the timeout threshold.
        // discovered_at = 500ms; fires when now_ms - 500 >= 5000 → h = 11.
        for h in 2..=10 {
            let block = make_block(BlockHeight(h));
            let actions = coordinator.on_block_committed(&topology, &block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 11, age = 5500 - 500 = 5000 >= PROVISION_FALLBACK_TIMEOUT → fires.
        let block = make_block(BlockHeight(11));
        let actions = coordinator.on_block_committed(&topology, &block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Fetch(FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                proposer,
                ..
            }) if *source_shard == ShardGroupId(1)
                && *block_height == BlockHeight(10)
                && *proposer == ValidatorId(0)
        ));
    }

    #[test]
    fn test_pregenesis_header_retrostamped_on_first_commit() {
        // Regression: without retro-stamping, an expected_provisions entry
        // recorded while `local_committed_ts == 0` would report a ~epoch-ms
        // age on the very next commit and trigger an immediate fallback,
        // bypassing PROVISION_FALLBACK_TIMEOUT entirely.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote header arrives BEFORE any local block commits.
        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // First local commit at ts=500ms. Should NOT fire — the pre-genesis
        // entry has just been retro-stamped to 500ms.
        let actions = coordinator.on_block_committed(&topology, &make_block(BlockHeight(1)));
        assert!(
            actions.is_empty(),
            "Pre-genesis entry must be retro-stamped, not fire immediately"
        );

        // Fires on schedule from the retro-stamp baseline, not absolute zero.
        for h in 2..=10 {
            let actions = coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
            assert!(actions.is_empty(), "Should not emit at height {h}");
        }
        let actions = coordinator.on_block_committed(&topology, &make_block(BlockHeight(11)));
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_no_re_emission_after_initial_request() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions = coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
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
        let header = make_committed_header_with_targets(
            source_shard,
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
        }

        // Batch arrives and is verified before timeout
        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardGroupId(0),
            BlockHeight(10),
        );
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);

        let header = make_committed_header_with_targets(
            source_shard,
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.expected.len(), 1);

        let provisions = make_provisions(
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            source_shard,
            ShardGroupId(0),
            BlockHeight(10),
        );
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        // Expected-tracking entry is cleared; the io_loop's
        // `ProvisionsVerified` interception drives any in-flight fetch
        // admission downstream.
        assert_eq!(coordinator.expected.len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Header Retention Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_header_retained_while_batch_outstanding() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Advance local well past any old time-based cutoff but short of the
        // orphan threshold. Header stays because its provisions hasn't verified yet.
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 1..=(orphan_cutoff_blocks / 2) {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
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
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));

        let header = make_committed_header_committing(
            source_shard,
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
            LocalTimestamp::ZERO,
        );

        assert_eq!(
            coordinator.verified_remote_header_count(),
            0,
            "Header must be dropped once its provisions is verified"
        );
    }

    #[test]
    fn test_orphan_header_dropped_after_cutoff() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Prime local clock so the expected-provision entry gets a real
        // baseline rather than the zero sentinel retro-stamped on first commit.
        coordinator.on_block_committed(&topology, &make_block(BlockHeight(1)));

        // Header arrives but the provisions never does — this is the orphan case
        // the long-horizon sweep guards against.
        let header = make_committed_header_with_targets(
            ShardGroupId(1),
            BlockHeight(10),
            vec![ShardGroupId(0)],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        assert_eq!(coordinator.expected.len(), 1);

        // Not yet past the orphan cutoff — still retained.
        // discovered_at was stamped at ts=500ms (the priming commit).
        let orphan_cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 2..=orphan_cutoff_blocks + 1 {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
        }
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert_eq!(coordinator.expected.len(), 1);

        // One past — orphan sweep drops header and expected entry together.
        coordinator.on_block_committed(
            &topology,
            &make_block(BlockHeight(orphan_cutoff_blocks + 2)),
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Verify a provisions sourced from shard 1 at height 10
        // (weighted_ts = 5_000ms in the test clock).
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"old-tx"));
        let header = make_committed_header_committing(
            ShardGroupId(1),
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);
        let provisions =
            make_provisions(tx_hash, ShardGroupId(1), ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions.clone());
        coordinator.on_state_provisions_verified(
            &topology,
            provisions,
            Some(&header),
            true,
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
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx-old"));
        let header = make_committed_header_committing(
            ShardGroupId(1),
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator.on_verified_remote_header(&topology, &header);

        // Advance local commits well past the source's deadline.
        let deadline_height = (u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS)
            + 11;
        for h in 100..=deadline_height + 1 {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
        }

        // The header itself has been swept by the orphan path; re-add it so
        // the receipt path can see it for the test.
        let header = make_committed_header_committing(
            ShardGroupId(1),
            BlockHeight(10),
            ShardGroupId(0),
            &[tx_hash],
        );
        coordinator
            .headers
            .insert((ShardGroupId(1), BlockHeight(10)), header);

        let provisions =
            make_provisions(tx_hash, ShardGroupId(1), ShardGroupId(0), BlockHeight(10));
        let actions = coordinator.on_state_provisions_received(&topology, provisions);
        assert!(
            actions.is_empty(),
            "past-deadline provisions must be dropped without dispatching verification"
        );
    }

    #[test]
    fn test_pending_buffer_evicted_when_received_too_long_ago() {
        // Batch buffered waiting for a header that never arrives; once
        // `received_at + RETENTION_HORIZON` is past `local_committed_ts`
        // the entry must be evicted by the deadline sweep.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Prime local clock so received_at is non-zero.
        coordinator.on_block_committed(&topology, &make_block(BlockHeight(1)));

        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx-pending"));
        let provisions =
            make_provisions(tx_hash, ShardGroupId(1), ShardGroupId(0), BlockHeight(10));
        coordinator.on_state_provisions_received(&topology, provisions);
        assert_eq!(coordinator.pipeline.pending_len(), 1);

        // Advance past the deadline horizon measured from received_at.
        let cutoff_blocks = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX)
            / TEST_BLOCK_INTERVAL_MS;
        for h in 2..=cutoff_blocks + 3 {
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
        }

        assert_eq!(
            coordinator.pipeline.pending_len(),
            0,
            "pending entry past `received_at + RETENTION_HORIZON` must be evicted"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Dwell-time Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Helper: verify a provisions through the coordinator, stamping `added_at`
    /// at `now`.
    fn verify_batch_into_queue(
        coordinator: &mut ProvisionCoordinator,
        topology: &TopologySnapshot,
        source_shard: ShardGroupId,
        height: BlockHeight,
        tx_hash: TxHash,
        now: LocalTimestamp,
    ) {
        let header =
            make_committed_header_committing(source_shard, height, ShardGroupId(0), &[tx_hash]);
        coordinator.on_verified_remote_header(topology, &header);
        let provisions = make_provisions(tx_hash, source_shard, ShardGroupId(0), height);
        coordinator.on_state_provisions_received(topology, provisions.clone());
        coordinator.on_state_provisions_verified(topology, provisions, Some(&header), true, now);
    }

    #[test]
    fn test_dwell_time_zero_yields_immediately() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::ZERO,
        });
        let now = LocalTimestamp::from_millis(1_000);
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            BlockHeight(10),
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::from_millis(500),
        });

        // Verify at t=1.0s
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            BlockHeight(10),
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
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::with_config(ProvisionConfig {
            min_dwell_time: Duration::from_millis(200),
        });

        // t=1.0s: verify old provisions
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            BlockHeight(10),
            TxHash::from_raw(Hash::from_bytes(b"tx_old")),
            LocalTimestamp::from_millis(1_000),
        );

        // t=1.3s: verify young provisions
        verify_batch_into_queue(
            &mut coordinator,
            &topology,
            ShardGroupId(1),
            BlockHeight(11),
            TxHash::from_raw(Hash::from_bytes(b"tx_young")),
            LocalTimestamp::from_millis(1_300),
        );

        // t=1.4s: old provisions dwelled 400ms (eligible), young provisions dwelled
        // 100ms (still blocked).
        let eligible = coordinator.queued_provisions(LocalTimestamp::from_millis(1_400));
        assert_eq!(eligible.len(), 1);
        assert_eq!(
            eligible[0].transactions[0].tx_hash,
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
            source_heights in proptest::collection::vec(1u64..=50, 0..=16),
            // Some batches will be left pending (no header arrives), some
            // will be verified. A bool per provisions picks the path.
            verify_path in proptest::collection::vec(proptest::bool::ANY, 0..=16),
        ) {
            let topology = make_test_topology(ShardGroupId(0));
            let mut coordinator = ProvisionCoordinator::new();
            // Prime so received_at is non-zero on pending entries.
            coordinator.on_block_committed(&topology, &make_block(BlockHeight(1)));

            let n = source_heights.len().min(verify_path.len());
            for i in 0..n {
                let source_height = BlockHeight(source_heights[i]);
                let tx_hash =
                    TxHash::from_raw(Hash::from_bytes(format!("tx-{i}").as_bytes()));
                let provisions = make_provisions(
                    tx_hash,
                    ShardGroupId(1),
                    ShardGroupId(0),
                    source_height,
                );

                if verify_path[i] {
                    // Verified path: header arrives, then the provisions.
                    let header = make_committed_header_committing(
                        ShardGroupId(1),
                        source_height,
                        ShardGroupId(0),
                        &[tx_hash],
                    );
                    coordinator.on_verified_remote_header(&topology, &header);
                    coordinator.on_state_provisions_received(&topology, provisions.clone());
                    coordinator.on_state_provisions_verified(
                        &topology,
                        provisions,
                        Some(&header),
                        true,
                        LocalTimestamp::ZERO,
                    );
                } else {
                    // Pending path: provisions arrives without header.
                    coordinator.on_state_provisions_received(&topology, provisions);
                }
            }

            // Advance well past `RETENTION_HORIZON` from the latest
            // possible source ts (50 * 500ms = 25_000ms = 25s).
            let cutoff_ms =
                25_000 + u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX) + 5 * TEST_BLOCK_INTERVAL_MS;
            let cutoff_height = cutoff_ms / TEST_BLOCK_INTERVAL_MS;
            for h in 2..=cutoff_height {
                coordinator.on_block_committed(&topology, &make_block(BlockHeight(h)));
            }

            proptest::prop_assert_eq!(coordinator.queue.queue_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.verified_len(), 0);
            proptest::prop_assert_eq!(coordinator.pipeline.pending_len(), 0);
        }
    }
}
