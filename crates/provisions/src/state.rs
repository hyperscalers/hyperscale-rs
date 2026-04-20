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
    BlockHeight, CommittedBlockHeader, Hash, Provision, ShardGroupId, TopologySnapshot, ValidatorId,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Number of local committed blocks to wait before falling back to
/// peer-fetch for missing provisions. Proposers include provisions inline
/// in `Block::Live` during assembly, so this timeout only triggers when
/// gossip dropped a batch — in which case we fetch from a shard peer.
const PROVISION_FALLBACK_TIMEOUT_BLOCKS: u64 = 10;

/// Number of local committed blocks to retain a committed provision in the
/// in-memory cache. After this many blocks past its commit, the provision
/// is dropped — the block it served has aged past the cross-shard execution
/// window (`WAVE_TIMEOUT_BLOCKS`), so no peer can still need it as part of
/// a `Block::Live` serving response. Must be `>= WAVE_TIMEOUT_BLOCKS`.
const COMMITTED_PROVISION_RETENTION_BLOCKS: u64 = 32;

/// Number of local committed blocks to retain verified remote headers.
/// Headers older than this have either been matched with provisions (and can be
/// discarded) or are stale (the source shard has moved far ahead).
const VERIFIED_HEADER_RETENTION_BLOCKS: u64 = 100;

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
    discovered_at: BlockHeight,
    requested: bool,
    proposer: ValidatorId,
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
    queued_provision_batches: Vec<Arc<Provision>>,

    /// Tombstone set: hashes of provision batches that have been committed.
    /// Prevents re-queueing if a duplicate batch arrives via gossip after commit.
    /// Maps hash → commit height for age-based pruning.
    committed_batch_tombstones: HashMap<Hash, BlockHeight>,

    /// Committed provision hashes grouped by the local block height at which
    /// they committed. Drives deferred eviction: `batches_by_hash` and
    /// `verified_batches` retain these entries until `commit_height +
    /// COMMITTED_PROVISION_RETENTION_BLOCKS` falls behind the local tip, at
    /// which point they're dropped. Ensures peers catching up can still
    /// receive `Block::Live` (with inline provisions) for any block within
    /// the cross-shard execution window.
    committed_retention: BTreeMap<BlockHeight, Vec<Hash>>,

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
    /// Create a new ProvisionCoordinator.
    pub fn new() -> Self {
        Self {
            verified_remote_headers: HashMap::new(),
            pending_provisions: HashMap::new(),
            verified_batches: BTreeMap::new(),
            batches_by_hash: HashMap::new(),
            local_committed_height: BlockHeight(0),
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
        block: &hyperscale_types::Block,
        committed_provision_hashes: &[Hash],
    ) -> Vec<Action> {
        // Update local committed height
        self.local_committed_height = block.height();

        // Record provision batches committed in this block, but don't
        // evict them yet — peers catching up within the cross-shard
        // execution window still need them attached to `Block::Live`
        // sync responses. Eviction happens below once they age out.
        if !committed_provision_hashes.is_empty() {
            let committed: std::collections::HashSet<Hash> =
                committed_provision_hashes.iter().copied().collect();
            for h in &committed {
                // Tombstone: prevent re-queueing if duplicate gossip arrives later.
                self.committed_batch_tombstones
                    .insert(*h, self.local_committed_height);
            }
            self.committed_retention
                .entry(self.local_committed_height)
                .or_default()
                .extend(committed.iter().copied());
            self.queued_provision_batches
                .retain(|b| !committed.contains(&b.hash()));
        }

        // Evict committed provisions whose block has aged past the
        // retention window. `split_off` partitions by the first retained
        // height, leaving aged-out entries in `aged` for cleanup.
        let retention_cutoff = BlockHeight(
            self.local_committed_height
                .0
                .saturating_sub(COMMITTED_PROVISION_RETENTION_BLOCKS),
        );
        let still_retained = self.committed_retention.split_off(&retention_cutoff);
        let aged = std::mem::replace(&mut self.committed_retention, still_retained);
        for (_height, hashes) in aged {
            for h in hashes {
                if let Some(batch) = self.batches_by_hash.remove(&h) {
                    let key = (batch.source_shard, batch.block_height);
                    self.verified_batches.remove(&key);
                    // Header no longer needed once the provision is evicted.
                    self.verified_remote_headers.remove(&key);
                }
            }
        }

        // Prune stale verified remote headers that were never matched with
        // provisions (e.g. source shard sent header but no provisions for us).
        // Use local committed height as a proxy — headers arriving far in the
        // past relative to our chain are safe to discard.
        let header_cutoff = self
            .local_committed_height
            .0
            .saturating_sub(VERIFIED_HEADER_RETENTION_BLOCKS);
        if header_cutoff > 0 {
            self.verified_remote_headers
                .retain(|&(_, h), _| h.0 > header_cutoff);
        }

        // Prune old tombstones (committed more than 100 blocks ago).
        let tombstone_cutoff = self.local_committed_height.0.saturating_sub(100);
        self.committed_batch_tombstones
            .retain(|_, height| height.0 > tombstone_cutoff);

        // Check for timed-out expected provisions and emit fallback requests
        let mut actions = vec![];
        let current_height = self.local_committed_height.0;

        for (&(source_shard, block_height), expected) in self.expected_provisions.iter_mut() {
            if expected.requested {
                continue;
            }

            let age = current_height.saturating_sub(expected.discovered_at.0);
            if age < PROVISION_FALLBACK_TIMEOUT_BLOCKS {
                continue;
            }

            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                age_blocks = age,
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
    /// provisions, bypassing the normal 10-block timeout.
    ///
    /// Called when urgency overrides the default patience — sync completion
    /// (validator needs to catch up before `WAVE_TIMEOUT_BLOCKS` runs out)
    /// and the execution advance gate stalling on missing data.
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
            .keys()
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
                    discovered_at: self.local_committed_height,
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
                actions.extend(self.emit_provision_verification(batch, committed_header.clone()));
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

        // Look for matching verified remote header (pre-verified by RemoteHeaderCoordinator).
        let key = (source_shard, block_height);
        if let Some(verified_header) = self.verified_remote_headers.get(&key).cloned() {
            return self.emit_provision_verification(batch, verified_header);
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
    /// The QC was already verified by `RemoteHeaderCoordinator`, so only merkle
    /// proofs need checking against the committed header's state root.
    fn emit_provision_verification(
        &self,
        batch: Provision,
        committed_header: Arc<CommittedBlockHeader>,
    ) -> Vec<Action> {
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

        // Promote the verified header if we have one
        if let Some(ref header) = committed_header {
            let shard = header.header.shard_group_id;
            let height = header.header.height;
            let key = (shard, height);

            // Header already in verified_remote_headers from coordinator.
            // Ensure it's there (idempotent insert).
            self.verified_remote_headers
                .entry(key)
                .or_insert_with(|| header.clone());

            // Clear expected provision tracking — provisions arrived and verified.
            // Cancel any in-flight fallback fetch to prevent duplicate delivery.
            if self.expected_provisions.remove(&key).is_some() {
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

        // Queue for inclusion in the next block proposal.
        self.queued_provision_batches.push(Arc::clone(&batch));

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

    /// Get queued provision batches for inclusion in a block proposal.
    /// Batches remain in the queue until pruned on block commit.
    pub fn queued_provisions(&self) -> Vec<Arc<Provision>> {
        self.queued_provision_batches.clone()
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

        // First: header arrives
        let header = make_committed_header(source_shard, 10);
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

        // Then header arrives — should trigger verification of buffered batch
        let header = make_committed_header(source_shard, 10);
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

        // Setup: header + batch + verification
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Simulate successful verification
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Second batch for same (tx, shard) goes through verification again
        // (proof must be verified as a whole — no per-tx pre-filtering).
        // Duplicate entries are harmlessly re-inserted by on_state_provisions_verified.
        let batch2 = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::VerifyProvision { .. })));
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
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);

        // Send batch with 3 transactions from the same block
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| Hash::from_bytes(format!("tx{i}").as_bytes()))
            .collect();
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

        // Verified header from coordinator
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_provision_uses_verified_header_when_available() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());

        // First batch verifies (promotes header to verified)
        let batch1 = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch1.clone());
        coordinator.on_state_provisions_verified(&topology, batch1, Some(header.clone()), true);

        // Second batch for different tx at same (shard, height)
        let batch2 = make_batch(Hash::from_bytes(b"tx2"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch2);

        // Should send the verified header
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvision { committed_header, .. }
                if committed_header.height() == BlockHeight(10)
        ));
    }

    #[test]
    fn test_batch_invalid_does_not_emit() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());

        let batch = make_batch_multi(
            vec![Hash::from_bytes(b"tx_ok"), Hash::from_bytes(b"tx_bad")],
            source_shard,
            10,
        );

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
        // Convert flat provision targets into waves: each target shard becomes
        // its own single-dependency wave. This preserves the test semantics
        // (provision_targets() returns the same set). Values are placeholder
        // zero hashes — these tests don't exercise root verification.
        let waves: std::collections::BTreeMap<WaveId, Hash> = provision_targets
            .into_iter()
            .map(|s| {
                (
                    WaveId {
                        shard_group_id: shard,
                        block_height: height,
                        remote_shards: std::collections::BTreeSet::from([s]),
                    },
                    Hash::ZERO,
                )
            })
            .collect();
        let header = BlockHeader {
            shard_group_id: shard,
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1000 + height,
            round: 0,
            is_fallback: false,
            state_root: Hash::from_bytes(format!("root_{shard}_{height}").as_bytes()),
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves,
            in_flight: 0,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        Arc::new(CommittedBlockHeader::new(header, qc))
    }

    /// Make a minimal Block at the given height for on_block_committed calls.
    fn make_block(height: u64) -> hyperscale_types::Block {
        let mut header =
            hyperscale_types::BlockHeader::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO);
        header.height = BlockHeight(height);
        hyperscale_types::Block::Live {
            header,
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        }
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

        // Remote header arrives targeting our shard at local height 0
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance blocks — should not emit before the timeout threshold (10 blocks)
        for h in 1..=9 {
            let block = make_block(h);
            let actions = coordinator.on_block_committed(&topology, &block, &[]);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 10, age = 10 - 0 = 10 >= PROVISION_FALLBACK_TIMEOUT_BLOCKS → fires
        let block = make_block(10);
        let actions = coordinator.on_block_committed(&topology, &block, &[]);
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
    fn test_no_re_emission_after_initial_request() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&topology, &make_block(h), &[]);
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h), &[]);
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
            coordinator.on_block_committed(&topology, &make_block(h), &[]);
        }

        // Batch arrives and is verified before timeout
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h), &[]);
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
}
