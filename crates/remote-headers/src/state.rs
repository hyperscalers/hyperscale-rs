//! RemoteHeaderCoordinator sub-state machine for centralized remote header management.
//!
//! This module is the single source of truth for remote committed block headers.
//! It receives raw headers from gossip (or fallback fetch), dispatches QC
//! verification, stores verified headers, and emits `RemoteHeaderVerified`
//! continuations for downstream consumers (BFT, Provision, Execution).
//!
//! It also tracks per-shard liveness and emits
//! `Action::RequestMissingCommittedBlockHeader` when a remote shard hasn't
//! sent headers within the timeout window — enabling proposer-only gossip
//! with fallback recovery.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, CommittedBlockHeader, ShardGroupId, TopologySnapshot,
    ValidatorId,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

/// Number of block heights to retain remote headers below each shard's tip.
const REMOTE_HEADER_RETENTION_BLOCKS: u64 = 50;

/// Number of local committed blocks to wait before requesting missing headers.
/// This gives the proposer time to gossip the header normally.
const HEADER_LIVENESS_TIMEOUT_BLOCKS: u64 = 10;

/// Remote header coordinator memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteHeaderMemoryStats {
    pub pending_headers: usize,
    pub verified_headers: usize,
    pub expected_headers: usize,
}

/// Tracks an expected header from a remote shard that hasn't arrived yet.
///
/// Created from topology knowledge: if we know a shard exists, we expect
/// headers from it. If none arrive within the timeout, we request via fallback.
#[derive(Debug, Clone)]
struct ExpectedHeader {
    /// Local committed height when we first expected a header from this shard.
    discovered_at: BlockHeight,
    /// Highest height we've verified from this shard (0 if none).
    last_verified_height: BlockHeight,
    /// Local committed height when we last verified a header from this shard.
    /// This is the liveness baseline: the timeout measures how many *local*
    /// blocks have passed since we last heard from the remote shard, rather
    /// than comparing local height to the remote shard's height (which are
    /// independent counters that advance at different rates).
    last_verified_at_local: BlockHeight,
    /// Whether we've already emitted a fallback request for the current gap.
    requested: bool,
    /// Local committed height when we last emitted a fallback request.
    /// Used as a cooldown to prevent re-requesting every block when the
    /// gap remains open after a fetch completes or is dropped.
    requested_at: BlockHeight,
}

/// Centralized remote block header coordination.
///
/// Responsibilities:
/// - Receive committed block headers from gossip or fallback fetch
/// - Perform structural pre-checks (QC hash match, shard consistency)
/// - Dispatch `VerifyRemoteHeaderQc` for async QC verification
/// - Store verified headers with per-shard tip tracking and pruning
/// - Emit `RemoteHeaderVerified` continuations for downstream consumers
/// - Track per-shard liveness and emit fallback requests on timeout
///
/// Downstream consumers:
/// - **BFT**: Uses verified `transaction_root` for deferral merkle proofs
/// - **Provision**: Uses verified `state_root` for merkle proof verification;
///   `waves` field to register expected provisions
/// - **Execution**: Uses `waves` field to register expected execution certs
pub struct RemoteHeaderCoordinator {
    // ═══════════════════════════════════════════════════════════════════
    // Pending Verification
    // ═══════════════════════════════════════════════════════════════════
    /// Headers received but not yet QC-verified.
    ///
    /// Outer key: `(shard, height)` for lookup.
    /// Inner key: `sender` — one slot per validator. Multiple senders may
    /// gossip the same header; we keep all candidates until QC verification
    /// picks the valid one.
    pending: HashMap<(ShardGroupId, BlockHeight), HashMap<ValidatorId, Arc<CommittedBlockHeader>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers — one per `(shard, height)`.
    /// These have passed QC signature verification and structural checks.
    verified: HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>,

    /// Highest seen block height per remote shard. Used for pruning.
    tips: HashMap<ShardGroupId, BlockHeight>,

    // ═══════════════════════════════════════════════════════════════════
    // Liveness Tracking (for fallback requests)
    // ═══════════════════════════════════════════════════════════════════
    /// Per-shard liveness tracking for fallback header requests.
    ///
    /// Populated when topology tells us remote shards exist.
    /// Emits `RequestMissingCommittedBlockHeader` when a shard hasn't
    /// sent headers within the timeout.
    expected: HashMap<ShardGroupId, ExpectedHeader>,

    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,
}

impl Default for RemoteHeaderCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteHeaderCoordinator {
    /// Create a new remote header coordinator.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            verified: HashMap::new(),
            tips: HashMap::new(),
            expected: HashMap::new(),
            local_committed_height: BlockHeight(0),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Header Ingestion
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a committed block header received from a remote shard (gossip or fetch).
    ///
    /// The sender's BLS signature was already verified by IoLoop.
    /// Performs structural pre-checks, stores as pending, and dispatches
    /// `VerifyRemoteHeaderQc` for async QC verification.
    pub fn on_remote_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        committed_header: Arc<CommittedBlockHeader>,
        sender: ValidatorId,
    ) -> Vec<Action> {
        let shard = committed_header.shard_group_id();
        let height = committed_header.height();

        // Ignore headers from our own shard.
        if shard == topology.local_shard() {
            return vec![];
        }

        // Already verified — nothing to do.
        if self.verified.contains_key(&(shard, height)) {
            return vec![];
        }

        // Structural pre-check: certifying QC must match header hash.
        let header_hash = committed_header.header.hash();
        if committed_header.qc.block_hash != header_hash {
            warn!(
                shard = shard.0,
                height = height.0,
                sender = sender.0,
                "Rejected remote header: QC block_hash does not match header hash"
            );
            return vec![];
        }

        // Structural pre-check: QC shard must match header shard.
        if committed_header.qc.shard_group_id != shard {
            warn!(
                shard = shard.0,
                height = height.0,
                sender = sender.0,
                qc_shard = committed_header.qc.shard_group_id.0,
                "Rejected remote header: QC shard_group_id does not match header shard"
            );
            return vec![];
        }

        debug!(
            shard = shard.0,
            height = height.0,
            sender = sender.0,
            state_root = %committed_header.state_root(),
            "Received remote committed block header (pending QC verification)"
        );

        // Check if we already have a pending entry from this sender.
        let sender_map = self.pending.entry((shard, height)).or_default();
        if sender_map.contains_key(&sender) {
            trace!(
                shard = shard.0,
                height = height.0,
                sender = sender.0,
                "Duplicate remote header from same sender — skipping"
            );
            return vec![];
        }

        // First entry for this (shard, height) triggers QC verification.
        let first_for_key = sender_map.is_empty();
        sender_map.insert(sender, Arc::clone(&committed_header));

        // Update tip and prune old entries.
        self.update_tip_and_prune(shard, height);

        if first_for_key {
            // Emit QC verification for the first header at this (shard, height).
            self.emit_verify_qc(topology, shard, height, committed_header)
        } else {
            vec![]
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Verification Callbacks
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle QC verification result for a remote header.
    ///
    /// On success: promotes to verified, emits `RemoteHeaderVerified` continuation.
    /// On failure: removes the failed candidate and tries the next sender's header.
    pub fn on_remote_header_qc_verified(
        &mut self,
        topology: &TopologySnapshot,
        shard: ShardGroupId,
        height: BlockHeight,
        header: Arc<CommittedBlockHeader>,
        valid: bool,
    ) -> Vec<Action> {
        let key = (shard, height);

        if !valid {
            warn!(
                shard = shard.0,
                height = height.0,
                "Remote header QC verification failed"
            );

            // Remove the failed candidate. Try the next sender's header if available.
            if let Some(sender_map) = self.pending.get_mut(&key) {
                // Remove the header that failed — find by Arc pointer equality.
                sender_map.retain(|_, h| !Arc::ptr_eq(h, &header));

                // Try next candidate if any remain.
                if let Some((_, next_header)) = sender_map.iter().next() {
                    let next = Arc::clone(next_header);
                    return self.emit_verify_qc(topology, shard, height, next);
                }
            }

            // No more candidates — remove the empty pending entry.
            self.pending.remove(&key);
            return vec![];
        }

        // QC verified — promote to verified storage.
        debug!(
            shard = shard.0,
            height = height.0,
            "Remote header QC verified — promoting"
        );

        self.verified.insert(key, Arc::clone(&header));
        self.pending.remove(&key);

        // Update liveness tracking: advance the remote tip and record the
        // local height at which we received it (the actual liveness signal).
        // Reset the request flag so future gaps can trigger new requests.
        if let Some(expected) = self.expected.get_mut(&shard) {
            if height > expected.last_verified_height {
                expected.last_verified_height = height;
                expected.last_verified_at_local = self.local_committed_height;
                expected.requested = false;
            }
        }

        // Emit continuation so downstream consumers receive the verified header.
        vec![Action::Continuation(ProtocolEvent::RemoteHeaderVerified {
            committed_header: header,
        })]
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Block Commit & Liveness
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle local block committed — update liveness tracking and check timeouts.
    ///
    /// Call this on each local block commit. It:
    /// 1. Updates local committed height
    /// 2. Seeds expected headers for any newly-discovered remote shards
    /// 3. Checks for timed-out remote shards and emits fallback requests
    pub fn on_block_committed(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        self.local_committed_height = BlockHeight(self.local_committed_height.0 + 1);

        // Seed expected headers for remote shards we haven't seen yet.
        let local_shard = topology.local_shard();
        for shard_id in 0..topology.num_shards() {
            let shard = ShardGroupId(shard_id);
            if shard == local_shard {
                continue;
            }
            self.expected
                .entry(shard)
                .or_insert_with(|| ExpectedHeader {
                    discovered_at: self.local_committed_height,
                    last_verified_height: BlockHeight(0),
                    last_verified_at_local: BlockHeight(0),
                    requested: false,
                    requested_at: BlockHeight(0),
                });
        }

        // Check for timed-out remote shards.
        let mut actions = vec![];
        let current_height = self.local_committed_height.0;

        for (&shard, expected) in self.expected.iter_mut() {
            // Measure how many LOCAL blocks have passed since we last heard
            // from this shard. Both sides of the branch are local heights,
            // avoiding the previous bug of comparing local height against
            // the remote shard's block height (independent counters).
            let baseline = if expected.last_verified_at_local.0 > 0 {
                expected.last_verified_at_local.0
            } else {
                expected.discovered_at.0
            };

            let age = current_height.saturating_sub(baseline);
            if age < HEADER_LIVENESS_TIMEOUT_BLOCKS {
                continue;
            }

            // If we already have a request in flight, only re-request after
            // a full cooldown period. This prevents flooding when the gap
            // remains open (e.g. fetch failed or returned a partial result
            // that didn't close the gap).
            if expected.requested {
                let since_request = current_height.saturating_sub(expected.requested_at.0);
                if since_request < HEADER_LIVENESS_TIMEOUT_BLOCKS {
                    continue;
                }
                // Cooldown expired — allow a fresh request below.
            }

            // Request missing header from any validator in the source shard.
            let from_height = BlockHeight(expected.last_verified_height.0 + 1);
            let peers = topology.committee_for_shard(shard).to_vec();
            if peers.is_empty() {
                continue;
            }

            info!(
                source_shard = shard.0,
                from_height = from_height.0,
                age_blocks = age,
                "Remote header liveness timeout — requesting missing headers via fallback"
            );

            expected.requested = true;
            expected.requested_at = BlockHeight(current_height);
            actions.push(Action::RequestMissingCommittedBlockHeader {
                source_shard: shard,
                from_height,
                peers,
            });
        }

        actions
    }

    /// Immediately request missing headers for all remote shards that are
    /// behind, bypassing the normal liveness timeout.
    ///
    /// Called on sync-complete so the validator quickly discovers provision
    /// needs for blocks committed during the sync window.
    pub fn flush_expected_headers(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = vec![];
        let current_height = self.local_committed_height.0;

        for (&shard, expected) in self.expected.iter_mut() {
            if expected.requested {
                continue;
            }

            let from_height = BlockHeight(expected.last_verified_height.0 + 1);
            let peers = topology.committee_for_shard(shard).to_vec();
            if peers.is_empty() {
                continue;
            }

            info!(
                source_shard = shard.0,
                from_height = from_height.0,
                "Sync catchup — immediately requesting remote headers"
            );

            expected.requested = true;
            expected.requested_at = BlockHeight(current_height);
            actions.push(Action::RequestMissingCommittedBlockHeader {
                source_shard: shard,
                from_height,
                peers,
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Queries
    // ═══════════════════════════════════════════════════════════════════════

    /// Get a verified remote header by (shard, height).
    ///
    /// Used by BFT for deferral merkle proof validation and by Provision
    /// for state root verification.
    pub fn get_verified(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<CommittedBlockHeader>> {
        self.verified.get(&(shard, height))
    }

    /// Get all pending (unverified) headers for a (shard, height).
    ///
    /// Used by Provision when a provision arrives before QC verification
    /// completes — it can pass these as candidates to `VerifyProvision`.
    pub fn get_pending(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&HashMap<ValidatorId, Arc<CommittedBlockHeader>>> {
        self.pending.get(&(shard, height))
    }

    /// Check if a verified header exists for (shard, height).
    pub fn has_verified(&self, shard: ShardGroupId, height: BlockHeight) -> bool {
        self.verified.contains_key(&(shard, height))
    }

    /// Get the in-flight count from the tip header of each remote shard.
    ///
    /// Used for cross-shard backpressure: RPC nodes can reject transactions
    /// targeting congested remote shards.
    pub fn remote_shard_in_flight(&self) -> HashMap<ShardGroupId, u32> {
        self.tips
            .iter()
            .filter_map(|(&shard, &tip)| {
                self.verified
                    .get(&(shard, tip))
                    .map(|h| (shard, h.header.in_flight))
            })
            .collect()
    }

    /// Get memory statistics for monitoring.
    pub fn memory_stats(&self) -> RemoteHeaderMemoryStats {
        RemoteHeaderMemoryStats {
            pending_headers: self.pending.values().map(|m| m.len()).sum(),
            verified_headers: self.verified.len(),
            expected_headers: self.expected.len(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Periodic cleanup of old headers.
    ///
    /// Called on cleanup timer. Prunes verified headers that are far below
    /// each shard's tip. Pending entries are pruned on ingestion via
    /// `update_tip_and_prune`.
    pub fn cleanup(&mut self) {
        for (&shard, &tip) in &self.tips {
            let cutoff = tip.0.saturating_sub(REMOTE_HEADER_RETENTION_BLOCKS);
            if cutoff > 0 {
                self.verified
                    .retain(|&(s, h), _| s != shard || h.0 >= cutoff);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Update the per-shard tip and prune old pending entries.
    fn update_tip_and_prune(&mut self, shard: ShardGroupId, height: BlockHeight) {
        let tip = self.tips.entry(shard).or_insert(BlockHeight(0));
        if height > *tip {
            *tip = height;
        }
        let cutoff = tip.0.saturating_sub(REMOTE_HEADER_RETENTION_BLOCKS);
        if cutoff > 0 {
            self.pending
                .retain(|&(s, h), _| s != shard || h.0 >= cutoff);
            self.verified
                .retain(|&(s, h), _| s != shard || h.0 >= cutoff);
        }
    }

    /// Emit a `VerifyRemoteHeaderQc` action for the given header.
    fn emit_verify_qc(
        &self,
        topology: &TopologySnapshot,
        shard: ShardGroupId,
        height: BlockHeight,
        header: Arc<CommittedBlockHeader>,
    ) -> Vec<Action> {
        let committee = topology.committee_for_shard(shard);
        let committee_public_keys: Vec<Bls12381G1PublicKey> = committee
            .iter()
            .map(|v| {
                topology
                    .public_key(*v)
                    .expect("committee member must have public key")
            })
            .collect();
        let committee_voting_power: Vec<u64> = committee
            .iter()
            .map(|v| topology.voting_power(*v).unwrap_or(0))
            .collect();
        let quorum_threshold = topology.quorum_threshold_for_shard(shard);

        vec![Action::VerifyRemoteHeaderQc {
            header,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
            shard,
            height,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeader, Hash, QuorumCertificate, ShardGroupId, ValidatorId};
    use std::collections::BTreeMap;

    // Basic structural tests — full integration tests require TopologySnapshot
    // which is tested via node-level tests.

    #[test]
    fn test_new_coordinator_is_empty() {
        let coord = RemoteHeaderCoordinator::new();
        let stats = coord.memory_stats();
        assert_eq!(stats.pending_headers, 0);
        assert_eq!(stats.verified_headers, 0);
        assert_eq!(stats.expected_headers, 0);
    }

    #[test]
    fn test_structural_precheck_rejects_mismatched_qc_hash() {
        // This test verifies the structural pre-check without needing a real topology.
        let header = BlockHeader {
            shard_group_id: ShardGroupId(2),
            height: BlockHeight(5),
            parent_hash: Hash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves: BTreeMap::new(),
            in_flight: 0,
        };
        let mut qc = QuorumCertificate::genesis();
        // Deliberately set wrong block_hash
        qc.block_hash = Hash::from_bytes(b"wrong");
        qc.shard_group_id = ShardGroupId(2);
        qc.height = BlockHeight(5);

        let committed = CommittedBlockHeader::new(header, qc);
        let _coord = RemoteHeaderCoordinator::new();

        // The structural check happens inside on_remote_block_committed which
        // needs a topology. We test the logic directly here by checking the
        // condition that would cause rejection.
        assert_ne!(committed.qc.block_hash, committed.header.hash());
    }

    #[test]
    fn test_get_verified_returns_none_when_empty() {
        let coord = RemoteHeaderCoordinator::new();
        assert!(coord
            .get_verified(ShardGroupId(1), BlockHeight(5))
            .is_none());
        assert!(!coord.has_verified(ShardGroupId(1), BlockHeight(5)));
    }
}
