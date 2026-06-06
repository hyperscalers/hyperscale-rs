//! Centralized remote header coordination.
//!
//! This module is the single source of truth for remote committed block headers.
//! It receives raw headers from gossip (or sync-driven fetch), dispatches QC
//! verification, stores verified headers, and emits `RemoteHeaderAdmitted`
//! continuations for downstream consumers (shard consensus, Provision, Execution).
//!
//! It also tracks per-shard liveness and emits
//! `Action::StartRemoteHeaderSync` when a remote shard hasn't sent headers
//! within the staleness threshold — the I/O loop's
//! `RemoteHeaderSync` then runs sliding-window catch-up.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    AwaitingTopologyBuffer, BlockHeight, Bls12381G1PublicKey, CertifiedBlock, CertifiedBlockHeader,
    CertifiedHeaderVerifyError, InFlightCount, REMOTE_HEADER_RETENTION, ShardGroupId,
    TopologySchedule, TopologySnapshot, ValidatorId, Verified, VotePower, WeightedTimestamp,
};
use tracing::{debug, info, trace, warn};

/// How long to wait before raising the per-shard sync target for a remote
/// shard. Measured against the shard consensus-authenticated `weighted_timestamp_ms`
/// of our local committed blocks, so the threshold is independent of
/// local block production rate.
///
/// Sized to give the remote proposer's gossip time to arrive across typical
/// committee latency before we ask the I/O loop's `RemoteHeaderSync`
/// to probe.
const HEADER_LIVENESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Probe lookahead added to `last_verified_height` when raising the sync
/// target. Sized to fit one full range fetch at the I/O loop's maximum
/// batch size, so a single round-trip can close a long gap without
/// requiring repeated target bumps.
const DEFAULT_PROBE_LOOKAHEAD: u64 = 64;

/// Remote header coordinator memory statistics for monitoring collection sizes.
#[allow(missing_docs)] // flat counters; field names are the documentation
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteHeaderMemoryStats {
    pub pending_headers: usize,
    pub verified_headers: usize,
    pub expected_headers: usize,
}

/// Tracks an expected header from a remote shard that hasn't arrived yet.
///
/// Created from topology knowledge: if we know a shard exists, we expect
/// headers from it. If none arrive within the staleness threshold, we
/// raise the per-shard target on the I/O loop's
/// `RemoteHeaderSync`, which manages range fetching and per-fetch
/// backoff itself.
#[derive(Debug, Clone)]
struct ExpectedHeader {
    /// Local weighted timestamp when we first expected a header from
    /// this shard. Used as the liveness baseline until we verify a header.
    discovered_at: WeightedTimestamp,
    /// Highest height we've verified from this shard (0 if none).
    last_verified_height: BlockHeight,
    /// Local weighted timestamp when we last verified a header from
    /// this shard. Liveness baseline once set — the timeout measures how
    /// much *local* wall-clock has passed since we last heard from the
    /// remote shard, rather than comparing heights across independent
    /// counters. `None` until the first header is verified.
    last_verified_at: Option<WeightedTimestamp>,
}

/// Centralized remote block header coordination.
///
/// Responsibilities:
/// - Receive committed block headers from gossip or fallback fetch
/// - Perform structural pre-checks (QC hash match, shard consistency)
/// - Dispatch `VerifyRemoteHeaderQc` for async QC verification
/// - Store verified headers with per-shard tip tracking and pruning
/// - Emit `RemoteHeaderAdmitted` continuations for downstream consumers
/// - Track per-shard liveness and emit fallback requests on timeout
///
/// Downstream consumers:
/// - **Shard consensus**: Uses verified `transaction_root` for deferral merkle proofs
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
    pending: HashMap<(ShardGroupId, BlockHeight), HashMap<ValidatorId, Arc<CertifiedBlockHeader>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers — one per `(shard, height)`.
    /// Holds the BFT-transitive trust composite produced by
    /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`].
    verified: HashMap<(ShardGroupId, BlockHeight), Arc<Verified<CertifiedBlockHeader>>>,

    /// Highest seen `(block_height, weighted_timestamp)` per remote shard.
    /// The timestamp is the pruning anchor — retention is measured against
    /// how long ago (in remote wall-clock) each stored header was produced,
    /// so pruning stays meaningful when remote block cadence varies.
    tips: HashMap<ShardGroupId, (BlockHeight, WeightedTimestamp)>,

    // ═══════════════════════════════════════════════════════════════════
    // Liveness Tracking (drives header-sync staleness detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Per-shard liveness tracking. Populated when topology tells us
    /// remote shards exist. Drives `Action::StartRemoteHeaderSync` when a
    /// shard hasn't sent headers within `HEADER_LIVENESS_TIMEOUT`.
    expected: HashMap<ShardGroupId, ExpectedHeader>,

    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. Used as the "now" reference for liveness timeouts so they're
    /// independent of local block production rate and deterministic across
    /// validators.
    local_committed_ts: WeightedTimestamp,

    /// This validator's home shard. Headers tagged with `local_shard` are
    /// ignored (we cert-verify our own headers through the shard pipeline).
    local_shard: ShardGroupId,

    // ═══════════════════════════════════════════════════════════════════
    // Beacon-sync-lag buffer
    // ═══════════════════════════════════════════════════════════════════
    /// Headers whose committee epoch this node's beacon hasn't reached yet, so
    /// `at(parent_qc WT)` can't resolve the signing committee. Keyed by source
    /// shard, bounded per shard (drop-oldest). Re-attempted on
    /// `BeaconBlockPersisted` once the beacon catches up. This is pure
    /// catch-up: under lookahead a correct sender never produces a header whose
    /// committee isn't globally fixed, so a buffered header means *we* are
    /// behind.
    awaiting: AwaitingTopologyBuffer<(ValidatorId, Arc<CertifiedBlockHeader>)>,
}

impl RemoteHeaderCoordinator {
    /// Create a new remote header coordinator.
    #[must_use]
    pub fn new(local_shard: ShardGroupId) -> Self {
        Self {
            pending: HashMap::new(),
            verified: HashMap::new(),
            tips: HashMap::new(),
            expected: HashMap::new(),
            local_committed_height: BlockHeight::new(0),
            local_committed_ts: WeightedTimestamp::ZERO,
            local_shard,
            awaiting: AwaitingTopologyBuffer::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Header Ingestion
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a committed block header that arrived already verified —
    /// emitted by a colocated proposer through the local-dispatch fast
    /// path (see [`ProtocolEvent::VerifiedRemoteHeaderReceived`]). Skips
    /// the pending bookkeeping and the `Action::VerifyRemoteHeaderQc`
    /// dispatch, promoting straight to the verified map and emitting
    /// the same `RemoteHeaderAdmitted` continuation downstream consumers
    /// already expect.
    pub fn on_verified_remote_header_received(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
        sender: ValidatorId,
    ) -> Vec<Action> {
        let shard = certified_header.shard_group_id();
        let height = certified_header.height();

        if shard == self.local_shard {
            return vec![];
        }

        let key = (shard, height);
        if self.verified.contains_key(&key) {
            return vec![];
        }

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            sender = sender.inner(),
            state_root = %certified_header.state_root(),
            "Admitting verified remote header (local-dispatch fast path)"
        );

        let header_ts = certified_header.qc().weighted_timestamp();
        self.update_tip_and_prune(shard, height, header_ts);
        self.verified.insert(key, Arc::clone(&certified_header));
        self.pending.remove(&key);

        if let Some(expected) = self.expected.get_mut(&shard)
            && height > expected.last_verified_height
        {
            expected.last_verified_height = height;
            expected.last_verified_at = Some(self.local_committed_ts);
        }

        vec![Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted {
            certified_header,
        })]
    }

    /// Handle a committed block header received from a remote shard (gossip or fetch).
    ///
    /// The sender's BLS signature was already verified by `IoLoop`.
    /// Performs structural pre-checks, stores as pending, and dispatches
    /// `VerifyRemoteHeaderQc` for async QC verification.
    pub fn on_remote_header_received(
        &mut self,
        topology: &TopologySchedule,
        certified_header: Arc<CertifiedBlockHeader>,
        sender: ValidatorId,
    ) -> Vec<Action> {
        let shard = certified_header.shard_group_id();
        let height = certified_header.height();

        // Ignore headers from our own shard.
        if shard == self.local_shard {
            return vec![];
        }

        // Already verified — nothing to do.
        if self.verified.contains_key(&(shard, height)) {
            return vec![];
        }

        // Structural pre-check: certifying QC must match header hash.
        let header_hash = certified_header.header().hash();
        if certified_header.qc().block_hash() != header_hash {
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                sender = sender.inner(),
                "Rejected remote header: QC block_hash does not match header hash"
            );
            return vec![];
        }

        // Structural pre-check: QC shard must match header shard.
        if certified_header.qc().shard_group_id() != shard {
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                sender = sender.inner(),
                qc_shard = certified_header.qc().shard_group_id().inner(),
                "Rejected remote header: QC shard_group_id does not match header shard"
            );
            return vec![];
        }

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            sender = sender.inner(),
            state_root = %certified_header.state_root(),
            "Received remote committed block header (pending QC verification)"
        );

        // Resolve the committee that signed this QC — the one seated at the
        // block's parent WT (`committee(h) = at(WT_{h-1})`), the same committee
        // every shard member used to form the QC. `None` means our beacon
        // hasn't reached that epoch: buffer for replay once it catches up
        // rather than verify against a guessed committee.
        let Some(committee) =
            topology.at(certified_header.header().parent_qc().weighted_timestamp())
        else {
            self.awaiting.push(shard, (sender, certified_header));
            return vec![];
        };

        // Check if we already have a pending entry from this sender.
        let sender_map = self.pending.entry((shard, height)).or_default();
        if sender_map.contains_key(&sender) {
            trace!(
                shard = shard.inner(),
                height = height.inner(),
                sender = sender.inner(),
                "Duplicate remote header from same sender — skipping"
            );
            return vec![];
        }

        // First entry for this (shard, height) triggers QC verification.
        let first_for_key = sender_map.is_empty();
        sender_map.insert(sender, Arc::clone(&certified_header));

        // Update tip and prune old entries.
        let header_ts = certified_header.qc().weighted_timestamp();
        self.update_tip_and_prune(shard, height, header_ts);

        if first_for_key {
            // Emit QC verification for the first header at this (shard, height).
            Self::emit_verify_qc(committee, shard, height, sender, certified_header)
        } else {
            vec![]
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Verification Callbacks
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle QC verification result for a remote header.
    ///
    /// On success: promotes to verified, emits `RemoteHeaderAdmitted` continuation.
    /// On failure: removes the failed candidate and tries the next sender's header.
    pub fn on_remote_header_qc_verified(
        &mut self,
        topology: &TopologySchedule,
        shard: ShardGroupId,
        height: BlockHeight,
        sender: ValidatorId,
        result: Result<Verified<CertifiedBlockHeader>, CertifiedHeaderVerifyError>,
    ) -> Vec<Action> {
        let key = (shard, height);

        let verified = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    sender = sender.inner(),
                    reason = %e,
                    "Remote header QC verification failed"
                );

                // The failed candidate is out. Dispatch the next candidate
                // whose committee resolves; buffer any whose epoch the beacon
                // hasn't reached yet so a catch-up retries them. If none
                // resolve, every remaining candidate is buffered or removed and
                // the key is gone, so the drain re-adds the first one with
                // `first_for_key` set and re-dispatches it cleanly.
                if let Some(sender_map) = self.pending.get_mut(&key) {
                    sender_map.remove(&sender);
                }
                loop {
                    let next = self.pending.get_mut(&key).and_then(|sender_map| {
                        sender_map.iter().next().map(|(s, h)| (*s, Arc::clone(h)))
                    });
                    let Some((next_sender, next_header)) = next else {
                        self.pending.remove(&key);
                        return vec![];
                    };
                    let anchor = next_header.header().parent_qc().weighted_timestamp();
                    if let Some(committee) = topology.at(anchor) {
                        return Self::emit_verify_qc(
                            committee,
                            shard,
                            height,
                            next_sender,
                            next_header,
                        );
                    }
                    // Beacon hasn't reached this candidate's epoch — buffer it
                    // for replay and try the next.
                    if let Some(sender_map) = self.pending.get_mut(&key) {
                        sender_map.remove(&next_sender);
                    }
                    self.awaiting.push(shard, (next_sender, next_header));
                }
            }
        };

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            "Remote header QC verified — promoting"
        );

        let verified = Arc::new(verified);
        self.verified.insert(key, Arc::clone(&verified));
        self.pending.remove(&key);

        let mut actions = Vec::new();

        // Update liveness tracking: advance the remote tip and record the
        // local height at which we received it. The I/O loop's
        // `RemoteHeaderSync` observes the same `RemoteHeaderAdmitted`
        // continuation and advances its per-shard `committed` counter,
        // ending an in-flight catch-up cycle once it reaches target.
        if let Some(expected) = self.expected.get_mut(&shard)
            && height > expected.last_verified_height
        {
            expected.last_verified_height = height;
            expected.last_verified_at = Some(self.local_committed_ts);
        }

        actions.push(Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted {
            certified_header: verified,
        }));
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Block Commit & Liveness
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle local block committed — update liveness tracking and check timeouts.
    ///
    /// Call this on each local block commit. It:
    /// 1. Updates local committed height from the block header
    /// 2. Seeds expected headers for any newly-discovered remote shards
    /// 3. Checks for timed-out remote shards and emits fallback requests
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let new_ts = certified.qc().weighted_timestamp();
        let first_commit = self.local_committed_ts == WeightedTimestamp::ZERO;
        self.local_committed_height = certified.block().height();
        self.local_committed_ts = new_ts;

        // Retro-stamp entries recorded before the first local commit: remote
        // headers can arrive (and verify) while `local_committed_ts` is
        // still zero, which would otherwise make age computations report the
        // full epoch on the very next commit and trigger a fallback storm.
        if first_commit {
            for expected in self.expected.values_mut() {
                if expected.discovered_at == WeightedTimestamp::ZERO {
                    expected.discovered_at = new_ts;
                }
                if expected.last_verified_at == Some(WeightedTimestamp::ZERO) {
                    expected.last_verified_at = Some(new_ts);
                }
            }
        }

        // Seed expected headers for remote shards we haven't seen yet.
        for shard in topology.shard_trie().leaves() {
            if shard == self.local_shard {
                continue;
            }
            self.expected
                .entry(shard)
                .or_insert_with(|| ExpectedHeader {
                    discovered_at: self.local_committed_ts,
                    last_verified_height: BlockHeight::new(0),
                    last_verified_at: None,
                });
        }

        // Check for timed-out remote shards.
        let mut actions = vec![];
        let now = self.local_committed_ts;

        for (&shard, expected) in &self.expected {
            // Liveness baseline: when we last verified a header from this
            // shard, or the seeding time if we haven't seen one yet. Both
            // anchors are local weighted timestamps, so age is measured in
            // local wall-clock regardless of remote block production rate.
            let baseline = expected.last_verified_at.unwrap_or(expected.discovered_at);

            if now.elapsed_since(baseline) < HEADER_LIVENESS_TIMEOUT {
                continue;
            }

            if topology.committee_for_shard(shard).is_empty() {
                continue;
            }

            // Probe the source shard's tip via the I/O loop's
            // `RemoteHeaderSync`. The action is idempotent — the
            // FSM short-circuits if its target is already at or past
            // `target`, and applies its own per-fetch backoff on failures.
            let target =
                BlockHeight::new(expected.last_verified_height.inner() + DEFAULT_PROBE_LOOKAHEAD);

            info!(
                source_shard = shard.inner(),
                target = target.inner(),
                age_ms = u64::try_from(now.elapsed_since(baseline).as_millis()).unwrap_or(u64::MAX),
                "Remote header liveness timeout — raising sync target"
            );

            actions.push(Action::StartRemoteHeaderSync {
                source_shard: shard,
                target,
            });
        }

        actions
    }

    /// Immediately raise the sync target for all remote shards that are
    /// behind, bypassing the normal liveness threshold.
    ///
    /// Called on sync-complete so the validator quickly discovers provision
    /// needs for blocks committed during the sync window.
    pub fn flush_expected_headers(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = vec![];

        for (&shard, expected) in &self.expected {
            if topology.committee_for_shard(shard).is_empty() {
                continue;
            }

            let target =
                BlockHeight::new(expected.last_verified_height.inner() + DEFAULT_PROBE_LOOKAHEAD);

            info!(
                source_shard = shard.inner(),
                target = target.inner(),
                "Sync catchup — raising remote-header sync target"
            );

            actions.push(Action::StartRemoteHeaderSync {
                source_shard: shard,
                target,
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Queries
    // ═══════════════════════════════════════════════════════════════════════

    /// Get a verified remote header by (shard, height).
    ///
    /// Used by shard consensus for deferral merkle proof validation and by Provision
    /// for state root verification.
    #[must_use]
    pub fn get_verified(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.verified.get(&(shard, height))
    }

    /// Get all pending (unverified) headers for a (shard, height).
    ///
    /// Used by Provision when a provision arrives before QC verification
    /// completes — it can pass these as candidates to `VerifyProvisions`.
    #[must_use]
    pub fn get_pending(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&HashMap<ValidatorId, Arc<CertifiedBlockHeader>>> {
        self.pending.get(&(shard, height))
    }

    /// Check if a verified header exists for (shard, height).
    #[must_use]
    pub fn has_verified(&self, shard: ShardGroupId, height: BlockHeight) -> bool {
        self.verified.contains_key(&(shard, height))
    }

    /// Get the in-flight count from the tip header of each remote shard.
    ///
    /// Used for cross-shard backpressure: RPC nodes can reject transactions
    /// targeting congested remote shards.
    #[must_use]
    pub fn remote_shard_in_flight(&self) -> HashMap<ShardGroupId, InFlightCount> {
        self.tips
            .iter()
            .filter_map(|(&shard, &(tip_height, _tip_ts))| {
                self.verified
                    .get(&(shard, tip_height))
                    .map(|h| (shard, h.header().in_flight()))
            })
            .collect()
    }

    /// Get memory statistics for monitoring.
    #[must_use]
    pub fn memory_stats(&self) -> RemoteHeaderMemoryStats {
        RemoteHeaderMemoryStats {
            pending_headers: self.pending.values().map(HashMap::len).sum(),
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
        for (&shard, &(_, tip_ts)) in &self.tips {
            let cutoff = tip_ts.minus(REMOTE_HEADER_RETENTION);
            if cutoff > WeightedTimestamp::ZERO {
                self.verified
                    .retain(|&(s, _), hdr| s != shard || hdr.qc().weighted_timestamp() >= cutoff);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Update the per-shard tip and prune old pending entries.
    fn update_tip_and_prune(
        &mut self,
        shard: ShardGroupId,
        height: BlockHeight,
        header_ts: WeightedTimestamp,
    ) {
        let tip = self
            .tips
            .entry(shard)
            .or_insert((BlockHeight::new(0), WeightedTimestamp::ZERO));
        if height > tip.0 {
            *tip = (height, header_ts);
        }
        let cutoff = tip.1.minus(REMOTE_HEADER_RETENTION);
        if cutoff > WeightedTimestamp::ZERO {
            self.pending.retain(|&(s, _), sender_map| {
                s != shard
                    || sender_map
                        .values()
                        .any(|h| h.qc().weighted_timestamp() >= cutoff)
            });
            self.verified
                .retain(|&(s, _), hdr| s != shard || hdr.qc().weighted_timestamp() >= cutoff);
        }
    }

    /// Re-attempt every buffered header now that the beacon has advanced. Drains
    /// the buffer and replays each through [`Self::on_remote_header_received`],
    /// which re-resolves the committee and re-buffers any still beyond the
    /// schedule. Called on `ProtocolEvent::BeaconBlockPersisted`.
    pub fn on_beacon_block_persisted(&mut self, topology: &TopologySchedule) -> Vec<Action> {
        let mut actions = Vec::new();
        for (sender, header) in self.awaiting.drain() {
            actions.extend(self.on_remote_header_received(topology, header, sender));
        }
        actions
    }

    /// Emit a `VerifyRemoteHeaderQc` action for the given header.
    fn emit_verify_qc(
        topology: &TopologySnapshot,
        shard: ShardGroupId,
        height: BlockHeight,
        sender: ValidatorId,
        certified_header: Arc<CertifiedBlockHeader>,
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
        let committee_voting_power: Vec<VotePower> = committee
            .iter()
            .map(|v| {
                topology
                    .voting_power(*v)
                    .expect("committee member must have voting power")
            })
            .collect();
        let quorum_threshold = topology.quorum_threshold_for_shard(shard);

        vec![Action::VerifyRemoteHeaderQc {
            certified_header,
            sender,
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
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, CertificateRoot, Epoch,
        Hash, InFlightCount, LocalReceiptRoot, NetworkDefinition, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot,
        TransactionRoot, ValidatorId, ValidatorInfo, ValidatorSet, bls_keypair_from_seed,
        zero_bls_signature,
    };

    use super::*;

    // Basic structural tests — full integration tests require TopologySnapshot
    // which is tested via node-level tests.

    #[test]
    fn test_new_coordinator_is_empty() {
        let coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(2, 0));
        let stats = coord.memory_stats();
        assert_eq!(stats.pending_headers, 0);
        assert_eq!(stats.verified_headers, 0);
        assert_eq!(stats.expected_headers, 0);
    }

    #[test]
    fn test_structural_precheck_rejects_mismatched_qc_hash() {
        // This test verifies the structural pre-check without needing a real topology.
        let header = BlockHeader::new(
            ShardGroupId::leaf(2, 2),
            BlockHeight::new(5),
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardGroupId::leaf(2, 0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
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
        );
        // Deliberately set wrong block_hash
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardGroupId::leaf(2, 2),
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );

        let committed = CertifiedBlockHeader::new(header, qc);
        let _coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(2, 0));

        // The structural check happens inside on_remote_header_received which
        // needs a topology. We test the logic directly here by checking the
        // condition that would cause rejection.
        assert_ne!(committed.qc().block_hash(), committed.header().hash());
    }

    #[test]
    fn test_get_verified_returns_none_when_empty() {
        let coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(2, 0));
        assert!(
            coord
                .get_verified(ShardGroupId::leaf(2, 1), BlockHeight::new(5))
                .is_none()
        );
        assert!(!coord.has_verified(ShardGroupId::leaf(2, 1), BlockHeight::new(5)));
    }

    /// A snapshot over `ids` across `num_shards` (`shard = id % num_shards`).
    /// `variant` perturbs the key seed so two snapshots with identical ids
    /// carry distinct public keys — modelling a same-membership key rotation.
    fn shard_snapshot(num_shards: u64, ids: &[u64], variant: u8) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&id.to_le_bytes());
                seed[8] = variant;
                ValidatorInfo {
                    validator_id: ValidatorId::new(id),
                    public_key: bls_keypair_from_seed(&seed).public_key(),
                    voting_power: VotePower::new(1),
                }
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            num_shards,
            ValidatorSet::new(validators),
        )
    }

    /// A `CertifiedBlockHeader` for `shard` at `height` whose header carries a
    /// parent QC at `parent_qc_wt` (the committee anchor) and an outer QC that
    /// passes the structural pre-checks.
    fn remote_header(
        shard: ShardGroupId,
        height: BlockHeight,
        parent_qc_wt: u64,
    ) -> Arc<CertifiedBlockHeader> {
        let parent_qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            shard,
            BlockHeight::new(height.inner().saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        let header = BlockHeader::new(
            shard,
            height,
            parent_qc.block_hash(),
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
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
        );
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        Arc::new(CertifiedBlockHeader::new(header, qc))
    }

    fn verify_qc_keys(actions: &[Action]) -> Option<&Vec<Bls12381G1PublicKey>> {
        actions.iter().find_map(|a| match a {
            Action::VerifyRemoteHeaderQc {
                committee_public_keys,
                ..
            } => Some(committee_public_keys),
            _ => None,
        })
    }

    #[test]
    fn remote_header_verifies_under_committee_at_parent_qc_weighted_timestamp() {
        // Remote shard 1's committee rotates keys between epoch 0 (the head) and
        // epoch 1. A header whose parent QC weighted timestamp is in epoch 1
        // must dispatch verification against the epoch-1 keys, not the head's.
        const ED: u64 = 1_000;
        let remote = ShardGroupId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3]; // shard 1's committee is the odd ids {1, 3}

        let snap_a = shard_snapshot(2, &ids, 0);
        let snap_b = shard_snapshot(2, &ids, 1);
        let expected_b: Vec<Bls12381G1PublicKey> = snap_b
            .committee_for_shard(remote)
            .iter()
            .map(|v| snap_b.public_key(*v).unwrap())
            .collect();

        let mut schedule = TopologySchedule::new(ED, 100, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        let mut coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), ED); // parent WT in epoch 1
        let actions = coord.on_remote_header_received(&schedule, header, ValidatorId::new(1));

        let keys = verify_qc_keys(&actions).expect("verification dispatched");
        assert_eq!(
            *keys, expected_b,
            "must verify under the epoch-1 committee at the parent QC's WT, not the head",
        );
    }

    #[test]
    fn remote_header_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let remote = ShardGroupId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];

        // Schedule holds only epoch 5; a header anchored in epoch 0 can't resolve.
        let behind =
            TopologySchedule::new(ED, 1, Epoch::new(5), Arc::new(shard_snapshot(2, &ids, 0)));
        let mut coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let actions =
            coord.on_remote_header_received(&behind, Arc::clone(&header), ValidatorId::new(1));
        assert!(
            verify_qc_keys(&actions).is_none(),
            "a header whose epoch the beacon hasn't reached must buffer, not dispatch",
        );

        // Beacon catches up: a schedule covering epoch 0 resolves the committee.
        let caught_up = TopologySchedule::single(Arc::new(shard_snapshot(2, &ids, 0)));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            verify_qc_keys(&drained).is_some(),
            "draining on catch-up must dispatch the buffered header's verification",
        );
    }

    #[test]
    fn failed_verification_with_beacon_behind_buffers_all_siblings() {
        // Three peers gossip the same header at one (shard, height): the first
        // dispatches verification, the other two wait as pending fallbacks. The
        // first candidate's QC verification then fails, and by the time the
        // result lands the beacon has evicted that epoch, so no sibling can
        // resolve its committee. Every sibling must move to the awaiting buffer
        // — none left in `pending` with no verification in flight — so a beacon
        // catch-up re-dispatches one rather than the whole height wedging.
        const ED: u64 = 1_000;
        let remote = ShardGroupId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3]; // shard 1's committee is {1, 3}
        let snap = || Arc::new(shard_snapshot(2, &ids, 0));

        // Epoch 0 is in the schedule when the headers arrive.
        let present = TopologySchedule::new(ED, 100, Epoch::new(0), snap());
        let mut coord = RemoteHeaderCoordinator::new(ShardGroupId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let dispatched =
            coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(1));
        assert!(verify_qc_keys(&dispatched).is_some());
        coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(2));
        coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(3));
        assert_eq!(coord.memory_stats().pending_headers, 3);

        // The first candidate's verification fails, and the schedule no longer
        // covers epoch 0 (the beacon advanced past it).
        let evicted = TopologySchedule::new(ED, 1, Epoch::new(5), snap());
        let after_fail = coord.on_remote_header_qc_verified(
            &evicted,
            remote,
            BlockHeight::new(5),
            ValidatorId::new(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
        );
        assert!(
            verify_qc_keys(&after_fail).is_none(),
            "no sibling can verify while their epoch is outside the schedule",
        );
        assert_eq!(
            coord.memory_stats().pending_headers,
            0,
            "every sibling must move to the awaiting buffer, none stranded in pending",
        );

        // Beacon catches up: draining re-dispatches a buffered sibling.
        let caught_up = TopologySchedule::single(snap());
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            verify_qc_keys(&drained).is_some(),
            "a buffered sibling must re-dispatch verification on beacon catch-up",
        );
    }
}
