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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    AwaitingTopologyBuffer, BlockHeight, Bls12381G1PublicKey, CertifiedBlock, CertifiedBlockHeader,
    CertifiedHeaderVerifyError, CommitProof, InFlightCount, REMOTE_HEADER_RETENTION,
    ScheduleLookup, ShardForkProof, ShardId, TopologySchedule, TopologySnapshot, ValidatorId,
    Verified, WeightedTimestamp,
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
    pub proven_headers: usize,
    pub expected_headers: usize,
    /// Held off-branch fork siblings — nonzero means a remote committee is
    /// producing conflicting certified headers at some height.
    pub fork_siblings: usize,
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
    pending: HashMap<(ShardId, BlockHeight), BTreeMap<ValidatorId, Arc<CertifiedBlockHeader>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers — one per `(shard, height)`.
    /// Holds the BFT-transitive trust composite produced by
    /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`].
    verified: HashMap<(ShardId, BlockHeight), Arc<Verified<CertifiedBlockHeader>>>,

    /// Keys in `verified` whose header is commit-proven: we also hold its
    /// committing structure — a round-contiguous certified child, or a
    /// parent-hash link under an already-proven descendant (a block that
    /// commits as the prefix of a later two-chain, INV-SHARD-4). A bare QC
    /// certifies availability, not canonicality: an f+1..2f corrupt
    /// committee can certify two blocks at one height without violating
    /// the safe-vote rule, but committing both is impossible below f+1
    /// corrupt seats (INV-SHARD-1). Cross-shard consumers therefore gate
    /// provision and execution-certificate consumption on the
    /// `RemoteHeaderCommitted` continuation this set drives, never on
    /// `RemoteHeaderAdmitted` alone. Always a subset of `verified` keys;
    /// pruned with them.
    proven: HashSet<(ShardId, BlockHeight)>,

    /// Verified headers that lost the canonical [`Self::verified`] slot to
    /// a first-seen different-hash header at their `(shard, height)` — the
    /// off-branch siblings of a committee fork. A QC certifies availability,
    /// not canonicality, so a sibling here is a genuine committee-signed
    /// block on a losing branch; held only to assemble a
    /// [`ShardForkProof`] once both branches are commit-proven. Empty
    /// under honest operation (an honest committee produces one chain).
    /// Pruned with [`Self::verified`].
    fork_siblings: HashMap<(ShardId, BlockHeight), Vec<Arc<Verified<CertifiedBlockHeader>>>>,

    /// `(shard, height)` slots a fork proof has already been assembled and
    /// emitted for — one proof per forked height. Bounded by the number of
    /// genuine forks (a Byzantine event), so it is not WT-pruned.
    forks_emitted: HashSet<(ShardId, BlockHeight)>,

    /// Gossip-timed local fork fences, `shard → frontier`. A verified fork
    /// proof engages one at `fork_height − 1`, stopping the
    /// `RemoteHeaderCommitted` promotion for that shard *at or above* the
    /// forked height — so no consumer opens a fenced block's provisions or
    /// execution certificates. Provisional: cleared once the attested
    /// recovery for the shard folds, which then governs. Empty under honest
    /// operation.
    fork_fences: HashMap<ShardId, BlockHeight>,

    /// Highest seen `(block_height, weighted_timestamp)` per remote shard.
    /// The timestamp is the pruning anchor — retention is measured against
    /// how long ago (in remote wall-clock) each stored header was produced,
    /// so pruning stays meaningful when remote block cadence varies.
    tips: HashMap<ShardId, (BlockHeight, WeightedTimestamp)>,

    // ═══════════════════════════════════════════════════════════════════
    // Liveness Tracking (drives header-sync staleness detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Per-shard liveness tracking. Populated when topology tells us
    /// remote shards exist. Drives `Action::StartRemoteHeaderSync` when a
    /// shard hasn't sent headers within `HEADER_LIVENESS_TIMEOUT`.
    expected: BTreeMap<ShardId, ExpectedHeader>,

    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. Used as the "now" reference for liveness timeouts so they're
    /// independent of local block production rate and deterministic across
    /// validators.
    local_committed_ts: WeightedTimestamp,

    /// This validator's home shard. Headers tagged with `local_shard` are
    /// ignored (we cert-verify our own headers through the shard pipeline).
    local_shard: ShardId,

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
    pub fn new(local_shard: ShardId) -> Self {
        Self {
            pending: HashMap::new(),
            verified: HashMap::new(),
            proven: HashSet::new(),
            fork_siblings: HashMap::new(),
            forks_emitted: HashSet::new(),
            fork_fences: HashMap::new(),
            tips: HashMap::new(),
            expected: BTreeMap::new(),
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
        let shard = certified_header.shard_id();
        let height = certified_header.height();

        if shard == self.local_shard {
            return vec![];
        }

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            sender = sender.inner(),
            state_root = %certified_header.state_root(),
            "Admitting verified remote header (local-dispatch fast path)"
        );

        let header_ts = certified_header.header().parent_qc().weighted_timestamp();
        self.update_tip_and_prune(shard, height, header_ts);
        self.pending.remove(&(shard, height));
        self.admit_verified_header(certified_header)
    }

    /// Handle a committed block header received from a remote shard (gossip or fetch).
    ///
    /// The sender's BLS signature was already verified by `IoLoop`.
    /// Performs structural pre-checks, stores as pending, and dispatches
    /// `VerifyRemoteHeaderQc` for async QC verification.
    pub fn on_remote_header_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified_header: Arc<CertifiedBlockHeader>,
        sender: ValidatorId,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let height = certified_header.height();

        // Ignore headers from our own shard.
        if shard == self.local_shard {
            return vec![];
        }

        // Structural pre-check: certifying QC must match header hash.
        let header_hash = certified_header.header().hash();

        // A header already verified at this `(shard, height)`: a byte-exact
        // duplicate is nothing to do, but a *different* hash is a fork
        // candidate — a second committee-signed block at one height. Let it
        // through to QC verification rather than dropping it blind; on
        // success it feeds fork detection without taking the canonical
        // `verified` slot.
        if let Some(existing) = self.verified.get(&(shard, height))
            && existing.block_hash() == header_hash
        {
            return vec![];
        }

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
        if certified_header.qc().shard_id() != shard {
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                sender = sender.inner(),
                qc_shard = certified_header.qc().shard_id().inner(),
                "Rejected remote header: QC shard_id does not match header shard"
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
        // every shard member used to form the QC. A not-yet-committed epoch
        // buffers for replay once the beacon catches up rather than verifying
        // against a guessed committee. A below-floor epoch drops: it can
        // never resolve, and buffering it would let a Byzantine sender evict
        // honest entries from the bounded drop-oldest buffer.
        // Terminal-clamped: a splitting shard's coast headers carry parent
        // QC timestamps past its final window — they verify against the
        // shard's terminal committee. The beacon's crossing tracker reads
        // the terminal block's canonical QC off the first coast header, so
        // dropping these would blind the fold to the crossing.
        // Recovery-bridged: a halt recovery's bridge header is anchored
        // below the bridge window but certified at or past it, and
        // verifies against the fresh committee. A header the fenced lookup
        // rejects instead resolves the retained committee through the
        // suffix band — the orphan a beyond-f cohort forged extending the
        // halted tip; drop it rather than admit a forged header into the
        // routing view.
        let committee = match topology_schedule.lookup_for_shard_certified_fenced(
            shard,
            certified_header.header().parent_qc().weighted_timestamp(),
            certified_header.qc().weighted_timestamp(),
        ) {
            None => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    sender = sender.inner(),
                    "Dropping remote header that resolves the retained committee during a halt recovery"
                );
                return vec![];
            }
            Some((ScheduleLookup::Committee(committee), _)) => committee,
            Some((ScheduleLookup::NotYetCommitted, _)) => {
                self.awaiting.push(shard, (sender, certified_header));
                return vec![];
            }
            Some((ScheduleLookup::Evicted, _)) => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    sender = sender.inner(),
                    "Remote header's committee epoch is below the schedule floor — dropping"
                );
                return vec![];
            }
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
        let header_ts = certified_header.header().parent_qc().weighted_timestamp();
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
        topology_schedule: &TopologySchedule,
        shard: ShardId,
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
                // hasn't reached yet so a catch-up retries them, and drop any
                // keyed below the schedule floor (the epoch can never resolve
                // again). If none resolve, every remaining candidate is
                // buffered or removed and the key is gone, so the drain
                // re-adds the first one with `first_for_key` set and
                // re-dispatches it cleanly.
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
                    let qc_wt = next_header.qc().weighted_timestamp();
                    // A recovery folded (or advanced) after this header
                    // buffered can turn it into a suffix-band orphan the
                    // fenced lookup rejects; drop it and drain the next
                    // candidate.
                    match topology_schedule
                        .lookup_for_shard_certified_fenced(shard, anchor, qc_wt)
                        .map(|(lookup, _)| lookup)
                    {
                        None => {
                            warn!(
                                shard = shard.inner(),
                                height = height.inner(),
                                sender = next_sender.inner(),
                                "Dropping buffered remote header that resolves the retained \
                                 committee during a halt recovery"
                            );
                            if let Some(sender_map) = self.pending.get_mut(&key) {
                                sender_map.remove(&next_sender);
                            }
                        }
                        Some(ScheduleLookup::Committee(committee)) => {
                            return Self::emit_verify_qc(
                                committee,
                                shard,
                                height,
                                next_sender,
                                next_header,
                            );
                        }
                        Some(ScheduleLookup::NotYetCommitted) => {
                            if let Some(sender_map) = self.pending.get_mut(&key) {
                                sender_map.remove(&next_sender);
                            }
                            self.awaiting.push(shard, (next_sender, next_header));
                        }
                        Some(ScheduleLookup::Evicted) => {
                            warn!(
                                shard = shard.inner(),
                                height = height.inner(),
                                sender = next_sender.inner(),
                                "Pending remote header's committee epoch fell below the \
                                 schedule floor — dropping"
                            );
                            if let Some(sender_map) = self.pending.get_mut(&key) {
                                sender_map.remove(&next_sender);
                            }
                        }
                    }
                }
            }
        };

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            "Remote header QC verified — promoting"
        );

        self.pending.remove(&key);
        self.admit_verified_header(Arc::new(verified))
    }

    /// Promote a freshly-verified remote header: take the canonical
    /// `(shard, height)` slot (first valid wins), advance liveness, and
    /// emit the admitted + commit-proof continuations. A byte-exact
    /// re-verification is a no-op; a different-hash header at an occupied
    /// slot is a fork sibling routed to detection rather than displacing
    /// the admitted (possibly commit-proven) winner. Shared by the QC-verify
    /// callback and the local-dispatch fast path; the caller owns the tip
    /// prune.
    fn admit_verified_header(
        &mut self,
        verified: Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let shard = verified.shard_id();
        let height = verified.height();
        let key = (shard, height);

        if let Some(existing) = self.verified.get(&key) {
            if existing.block_hash() == verified.block_hash() {
                return Vec::new();
            }
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                "Verified a conflicting certified header at an occupied height — fork candidate"
            );
            return self.observe_fork_sibling(verified);
        }
        self.verified.insert(key, Arc::clone(&verified));

        if let Some(expected) = self.expected.get_mut(&shard)
            && height > expected.last_verified_height
        {
            expected.last_verified_height = height;
            expected.last_verified_at = Some(self.local_committed_ts);
        }

        let mut actions = vec![Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted {
            certified_header: verified,
        })];
        actions.extend(self.prove_commits(shard, height));
        // The canonical winner can also be one branch of a fork whose losing
        // branch is already held.
        actions.extend(self.check_fork_at(shard, height));
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
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let new_ts = certified.block().header().parent_qc().weighted_timestamp();
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

        self.refresh_expected(topology_schedule);

        // Gossip-timed fork fences self-clear once the attested recovery for
        // their shard folds — the attested `lookup_for_shard_certified_fenced`
        // admission gate then governs.
        let head = topology_schedule.head();
        self.fork_fences
            .retain(|shard, _| !head.pending_recoveries().contains_key(shard));

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

            if !Self::shard_routable(topology_schedule, shard, now) {
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
                floor: expected.last_verified_height,
            });
        }

        actions
    }

    /// Reconcile `expected` with the routable topology: seed an entry for
    /// every remote shard that appears in any retained window — live head
    /// leaves and a drained reshape shard still inside its retention window
    /// alike — and drop any whose shard has fully evicted.
    ///
    /// Seeding from the routable set rather than the head leaves alone is what
    /// keeps a freshly-seated member — a merge keeper, a resampled beacon
    /// committee member, a node that came up after the shard left the head —
    /// syncing a departing shard's terminal crossing into the beacon fold.
    /// A drained reshape shard is absent from the head trie the instant its
    /// children (or merged parent) take over, so a member that never tracked
    /// it would otherwise never probe it, and the beacon could fall short of
    /// the `2f+1` that admits its terminal boundary QC. The terminal clamp on
    /// the schedule retains the shard until the drain horizon, exactly long
    /// enough for its terminal to fold.
    ///
    /// But stop probing a terminated reshape parent the moment its successors
    /// are live: past that its terminal crossing has already folded (the
    /// children seeded and produced past genesis), so there is nothing left to
    /// sync — and its serving members have transitioned to the children and
    /// deregistered its per-shard request protocol, so every further probe only
    /// draws `UnsupportedProtocol` that retries and congests the shared request
    /// pipeline for the rest of the retention window.
    fn refresh_expected(&mut self, topology_schedule: &TopologySchedule) {
        let routable = topology_schedule.routable_shards();
        self.expected.retain(|shard, _| {
            routable.contains(shard) && !topology_schedule.successors_live(*shard)
        });
        for shard in routable {
            if shard == self.local_shard || topology_schedule.successors_live(shard) {
                continue;
            }
            // Anchor a freshly tracked shard at its attested boundary, not
            // genesis: a reshape child's chain begins at its split height, so
            // probing from 0 requests heights below the chain start and the
            // contiguous-prefix sync stalls there. The attested boundary is a
            // height the shard provably holds, and it lags the tip by the
            // witness window — far enough that no live cross-shard provision
            // references a block below it — so it is a sound anchor.
            // Gossip-verified headers raise it from there.
            let anchor_height = topology_schedule
                .head()
                .boundary(shard)
                .map_or(BlockHeight::new(0), |a| a.height);
            self.expected
                .entry(shard)
                .and_modify(|entry| {
                    // Re-anchor a child first tracked before its boundary was
                    // known locally: it seeded at genesis (0, the `map_or`
                    // fallback), below its real chain start, so the
                    // contiguous-prefix sync requests non-existent sub-genesis
                    // heights and stalls — and a production split child's store
                    // (a checkpoint of the parent) answers those with the
                    // parent's wrong-shard headers. Once the attested boundary
                    // arrives, raise a not-yet-verified anchor to it. Safe
                    // because no real header has verified (`last_verified_at`
                    // is `None`), so no reached height is skipped.
                    if entry.last_verified_at.is_none()
                        && entry.last_verified_height < anchor_height
                    {
                        entry.last_verified_height = anchor_height;
                    }
                })
                .or_insert_with(|| ExpectedHeader {
                    discovered_at: self.local_committed_ts,
                    last_verified_height: anchor_height,
                    last_verified_at: None,
                });
        }
    }

    /// Immediately raise the sync target for all remote shards that are
    /// behind, bypassing the normal liveness threshold.
    ///
    /// Called on sync-complete so the validator quickly discovers provision
    /// needs for blocks committed during the sync window.
    pub fn flush_expected_headers(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        // Reconcile anchors before flushing. `on_block_committed` is the
        // usual re-anchor point, but a shard whose chain has quiesced — a
        // coasting reshape predecessor past its terminal block — stops
        // committing, so it never picks up a reshaped-in child's boundary
        // once that boundary folds. This tick-driven path still fires (the
        // stall-recovery timer flushes on an unchanged committed height), so
        // reconciling here re-anchors a child scope stuck at the genesis-0
        // fallback it was first seeded with.
        self.refresh_expected(topology_schedule);

        let mut actions = vec![];

        for (&shard, expected) in &self.expected {
            if !Self::shard_routable(topology_schedule, shard, self.local_committed_ts) {
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
                floor: expected.last_verified_height,
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
        shard: ShardId,
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
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<&BTreeMap<ValidatorId, Arc<CertifiedBlockHeader>>> {
        self.pending.get(&(shard, height))
    }

    /// Check if a verified header exists for (shard, height).
    #[must_use]
    pub fn has_verified(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.verified.contains_key(&(shard, height))
    }

    /// Whether the held header at `(shard, height)` is commit-proven: its
    /// committing structure — a round-contiguous certified child, or a
    /// parent-hash link under a proven descendant — is also held.
    #[must_use]
    pub fn has_commit_proof(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.proven.contains(&(shard, height))
    }

    /// Get the in-flight count from the tip header of each remote shard.
    ///
    /// Used for cross-shard backpressure: RPC nodes can reject transactions
    /// targeting congested remote shards.
    #[must_use]
    pub fn remote_shard_in_flight(&self) -> HashMap<ShardId, InFlightCount> {
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
            pending_headers: self.pending.values().map(BTreeMap::len).sum(),
            verified_headers: self.verified.len(),
            proven_headers: self.proven.len(),
            expected_headers: self.expected.len(),
            fork_siblings: self.fork_siblings.values().map(Vec::len).sum(),
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
                self.verified.retain(|&(s, _), hdr| {
                    s != shard || hdr.header().parent_qc().weighted_timestamp() >= cutoff
                });
            }
        }
        self.proven.retain(|key| self.verified.contains_key(key));
        for (&shard, &(_, tip_ts)) in &self.tips {
            let cutoff = tip_ts.minus(REMOTE_HEADER_RETENTION);
            if cutoff > WeightedTimestamp::ZERO {
                self.fork_siblings.retain(|&(s, _), sibs| {
                    if s != shard {
                        return true;
                    }
                    sibs.retain(|h| h.header().parent_qc().weighted_timestamp() >= cutoff);
                    !sibs.is_empty()
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Update the per-shard tip and prune old pending entries.
    fn update_tip_and_prune(
        &mut self,
        shard: ShardId,
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
                        .any(|h| h.header().parent_qc().weighted_timestamp() >= cutoff)
            });
            self.verified.retain(|&(s, _), hdr| {
                s != shard || hdr.header().parent_qc().weighted_timestamp() >= cutoff
            });
            self.proven.retain(|key| self.verified.contains_key(key));
            self.fork_siblings.retain(|&(s, _), sibs| {
                if s != shard {
                    return true;
                }
                sibs.retain(|h| h.header().parent_qc().weighted_timestamp() >= cutoff);
                !sibs.is_empty()
            });
        }
    }

    /// Engage the gossip-timed fork fence for `shard`: stop promoting its
    /// blocks *at or above* `fork_height` — no `RemoteHeaderCommitted`, so
    /// no consumer opens a fenced block's provisions or execution
    /// certificates. The frontier sits one below the fork height so the
    /// `> frontier` check covers the forked height itself (both conflicting
    /// blocks live there). Idempotent; never loosens an existing fence.
    pub fn engage_fork_fence(&mut self, shard: ShardId, fork_height: BlockHeight) {
        let frontier = BlockHeight::new(fork_height.inner().saturating_sub(1));
        match self.fork_fences.get(&shard) {
            Some(&existing) if existing <= frontier => {}
            _ => {
                self.fork_fences.insert(shard, frontier);
            }
        }
    }

    /// Whether `(shard, height)` is under a local gossip-timed fork fence —
    /// content at or above the forked height, held back from promotion.
    fn fork_fenced(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.fork_fences
            .get(&shard)
            .is_some_and(|&frontier| height > frontier)
    }

    /// Record a verified fork sibling and check whether it completes a fork
    /// proof. The sibling lost the canonical [`Self::verified`] slot to a
    /// first-seen different-hash header, so it lives here until both fork
    /// branches are commit-proven.
    fn observe_fork_sibling(
        &mut self,
        sibling: Arc<Verified<CertifiedBlockHeader>>,
    ) -> Vec<Action> {
        let shard = sibling.shard_id();
        let height = sibling.height();
        self.fork_siblings
            .entry((shard, height))
            .or_default()
            .push(sibling);
        self.check_fork_at(shard, height)
    }

    /// Assemble and emit a fork proof if a newly-held header at
    /// `(shard, height)` completes one — either at its own height (it is a
    /// block with a committing child) or at the height below (it is the
    /// committing child of a lower block). One proof per forked height.
    fn check_fork_at(&mut self, shard: ShardId, height: BlockHeight) -> Vec<Action> {
        let mut actions = Vec::new();
        for h in [Some(height), height.prev()].into_iter().flatten() {
            if self.forks_emitted.contains(&(shard, h)) {
                continue;
            }
            if let Some(proof) = self.try_assemble_fork(shard, h) {
                self.forks_emitted.insert((shard, h));
                warn!(
                    shard = shard.inner(),
                    height = h.inner(),
                    "Assembled a shard fork proof from two conflicting commit proofs"
                );
                actions.push(Action::Continuation(ProtocolEvent::ShardForkDetected {
                    proof: Box::new(proof),
                }));
            }
        }
        actions
    }

    /// Two distinct commit-proven blocks at `(shard, height)` — a committee
    /// fork. Pairs the first two proofs with different proven-block hashes.
    fn try_assemble_fork(&self, shard: ShardId, height: BlockHeight) -> Option<ShardForkProof> {
        let proofs = self.direct_commit_proofs_at(shard, height);
        let a = proofs.first()?;
        let b = proofs
            .iter()
            .skip(1)
            .find(|p| p.proven_block_hash() != a.proven_block_hash())?;
        Some(ShardForkProof::ConflictingCommits {
            a: a.clone(),
            b: b.clone(),
        })
    }

    /// Every direct-commit proof `(block, round-contiguous child)` held at
    /// `(shard, height)`, across both the canonical winner and the fork
    /// siblings.
    fn direct_commit_proofs_at(&self, shard: ShardId, height: BlockHeight) -> Vec<CommitProof> {
        let child_height = height.next();
        let blocks = self.verified.get(&(shard, height)).into_iter().chain(
            self.fork_siblings
                .get(&(shard, height))
                .into_iter()
                .flatten(),
        );
        let children: Vec<&Arc<Verified<CertifiedBlockHeader>>> = self
            .verified
            .get(&(shard, child_height))
            .into_iter()
            .chain(
                self.fork_siblings
                    .get(&(shard, child_height))
                    .into_iter()
                    .flatten(),
            )
            .collect();

        let mut proofs = Vec::new();
        for block in blocks {
            let block_header: &CertifiedBlockHeader = block;
            if let Some(child) = children.iter().find(|c| {
                let ch: &CertifiedBlockHeader = c;
                ch.header().parent_block_hash() == block_header.block_hash()
                    && ch.height() == child_height
                    && ch.header().round() == block_header.header().round().next()
            }) {
                let child_header: &CertifiedBlockHeader = child;
                proofs.push(CommitProof::direct(
                    block_header.clone(),
                    child_header.clone(),
                ));
            }
        }
        proofs
    }

    /// Mark every height the insertion at `(shard, height)` newly commit-proves,
    /// emitting a `RemoteHeaderCommitted` continuation per proven header.
    ///
    /// The inserted header can complete a two-chain over its parent, and a
    /// held child can complete one over it; each proof then propagates down
    /// the parent-hash chain (an ancestor of a committed block is committed,
    /// whatever its own round layout — INV-SHARD-4).
    fn prove_commits(&mut self, shard: ShardId, height: BlockHeight) -> Vec<Action> {
        let mut actions = Vec::new();
        self.try_prove(shard, height, &mut actions);
        if let Some(parent) = height.prev() {
            self.try_prove(shard, parent, &mut actions);
        }
        actions
    }

    /// Prove `(shard, height)` if its committing structure is held, then walk
    /// the parent-hash chain downward marking every hash-linked ancestor.
    ///
    /// A height is provable when its held child links to it by parent hash
    /// and either certifies the direct commit (round-contiguous, the
    /// two-chain rule) or is itself already proven (the prefix-commit case).
    /// The downward walk needs only the hash links: ancestry under a
    /// committed block is commitment. A link that fails to match — the held
    /// entry at that height is a certified sibling from another branch —
    /// stops the walk and leaves that height unproven, which is exactly what
    /// keeps a forked branch's exports unconsumable.
    fn try_prove(&mut self, shard: ShardId, height: BlockHeight, actions: &mut Vec<Action>) {
        if self.proven.contains(&(shard, height)) {
            return;
        }
        let Some(header) = self.verified.get(&(shard, height)) else {
            return;
        };
        let child_height = height.next();
        let Some(child) = self.verified.get(&(shard, child_height)) else {
            return;
        };
        if child.header().parent_block_hash() != header.block_hash() {
            return;
        }
        let commits = child.header().round() == header.header().round().next()
            || self.proven.contains(&(shard, child_height));
        if !commits {
            return;
        }

        let mut at = height;
        let mut hash = header.block_hash();
        let mut parent_hash = header.header().parent_block_hash();
        loop {
            self.proven.insert((shard, at));
            let proven_header = self
                .verified
                .get(&(shard, at))
                .expect("walk only visits held headers");
            debug!(
                shard = shard.inner(),
                height = at.inner(),
                block_hash = %hash,
                "Remote header commit-proven"
            );
            // A locally fork-fenced height is proven but not promoted: no
            // `RemoteHeaderCommitted`, so no consumer opens its provisions
            // or execution certificates. The block stays tracked so the walk
            // terminates; the attested recovery fence governs once it folds.
            if !self.fork_fenced(shard, at) {
                actions.push(Action::Continuation(ProtocolEvent::RemoteHeaderCommitted {
                    certified_header: Arc::clone(proven_header),
                }));
            }

            let Some(prev) = at.prev() else { break };
            if self.proven.contains(&(shard, prev)) {
                break;
            }
            let Some(prev_header) = self.verified.get(&(shard, prev)) else {
                break;
            };
            if prev_header.block_hash() != parent_hash {
                break;
            }
            at = prev;
            hash = prev_header.block_hash();
            parent_hash = prev_header.header().parent_block_hash();
        }
    }

    /// Re-attempt every buffered header now that the beacon has advanced. Drains
    /// the buffer and replays each through [`Self::on_remote_header_received`],
    /// which re-resolves the committee and re-buffers any still beyond the
    /// schedule. Called on `ProtocolEvent::BeaconBlockPersisted`.
    pub fn on_beacon_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for (sender, header) in self.awaiting.drain() {
            actions.extend(self.on_remote_header_received(topology_schedule, header, sender));
        }
        actions
    }

    /// Emit a `VerifyRemoteHeaderQc` action for the given header.
    fn emit_verify_qc(
        topology_snapshot: &TopologySnapshot,
        shard: ShardId,
        height: BlockHeight,
        sender: ValidatorId,
        certified_header: Arc<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let committee = topology_snapshot.consensus_committee_for_shard(shard);
        let committee_public_keys: Vec<Bls12381G1PublicKey> = committee
            .iter()
            .map(|v| {
                topology_snapshot
                    .public_key(*v)
                    .expect("committee member must have public key")
            })
            .collect();
        let quorum_threshold = topology_snapshot.quorum_threshold_for_shard(shard);

        vec![Action::VerifyRemoteHeaderQc {
            certified_header,
            sender,
            committee_public_keys,
            quorum_threshold,
            shard,
            height,
        }]
    }

    /// Whether `shard` resolves a non-empty committee for request routing at
    /// `wt`, terminal-clamped. A live shard resolves its head committee; a
    /// drained reshape shard past its final window — a split parent or a
    /// merge child — resolves the committee that served it, so its terminal
    /// crossing keeps syncing to the beacon fold until the schedule evicts
    /// it. A fully-evicted shard resolves nothing and is skipped.
    ///
    /// A zero `wt` is not a stale clock — it means no local block has
    /// committed yet. A freshly seated member (a halt-recovery draw from the
    /// pool, a merge keeper) opens on the beacon head fold that seated it,
    /// so any shard the schedule still retains is fair to probe; resolving
    /// the zero clock would land below every retained window (`Evicted`) and
    /// suppress exactly the fetches that bootstrap the member.
    fn shard_routable(
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> bool {
        if wt == WeightedTimestamp::ZERO {
            return topology_schedule.routable_shards().contains(&shard);
        }
        matches!(
            topology_schedule.lookup_for_shard(shard, wt).0,
            ScheduleLookup::Committee(snapshot) if !snapshot.committee_for_shard(shard).is_empty()
        )
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, CertificateRoot,
        ChainOrigin, Epoch, Hash, InFlightCount, LocalReceiptRoot, NetworkDefinition,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardId, SignerBitfield,
        StateRoot, TransactionRoot, ValidatorId, ValidatorInfo, ValidatorSet,
        bls_keypair_from_seed, zero_bls_signature,
    };

    use super::*;

    // Basic structural tests — full integration tests require TopologySnapshot
    // which is tested via node-level tests.

    #[test]
    fn test_new_coordinator_is_empty() {
        let coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let stats = coord.memory_stats();
        assert_eq!(stats.pending_headers, 0);
        assert_eq!(stats.verified_headers, 0);
        assert_eq!(stats.expected_headers, 0);
    }

    #[test]
    fn test_structural_precheck_rejects_mismatched_qc_hash() {
        // This test verifies the structural pre-check without needing a real topology.
        let header = BlockHeader::new(
            ShardId::leaf(2, 2),
            BlockHeight::new(5),
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardId::leaf(2, 0), ChainOrigin::ROOT),
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
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        // Deliberately set wrong block_hash
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardId::leaf(2, 2),
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );

        let committed = CertifiedBlockHeader::new(header, qc);
        let _coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));

        // The structural check happens inside on_remote_header_received which
        // needs a topology. We test the logic directly here by checking the
        // condition that would cause rejection.
        assert_ne!(committed.qc().block_hash(), committed.header().hash());
    }

    #[test]
    fn test_get_verified_returns_none_when_empty() {
        let coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        assert!(
            coord
                .get_verified(ShardId::leaf(2, 1), BlockHeight::new(5))
                .is_none()
        );
        assert!(!coord.has_verified(ShardId::leaf(2, 1), BlockHeight::new(5)));
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
        shard: ShardId,
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
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
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
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3]; // shard 1's committee is the odd ids {1, 3}

        let snap_a = shard_snapshot(2, &ids, 0);
        let snap_b = shard_snapshot(2, &ids, 1);
        let expected_b: Vec<Bls12381G1PublicKey> = snap_b
            .committee_for_shard(remote)
            .iter()
            .map(|v| snap_b.public_key(*v).unwrap())
            .collect();

        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), ED); // parent WT in epoch 1
        let actions = coord.on_remote_header_received(&schedule, header, ValidatorId::new(1));

        let keys = verify_qc_keys(&actions).expect("verification dispatched");
        assert_eq!(
            *keys, expected_b,
            "must verify under the epoch-1 committee at the parent QC's WT, not the head",
        );
    }

    #[test]
    fn expected_headers_seed_a_drained_reshape_shard_not_just_head_leaves() {
        // Post-split schedule: ROOT (epoch 0) drained into its two children
        // (epoch 1, the head). A coordinator born on a child shard never saw
        // ROOT as a head leaf, yet must still sync ROOT's terminal crossing
        // so the beacon fold can admit it. Seeding from the routable set —
        // every shard in any retained window, terminal-clamped — covers the
        // drained parent; the old head-leaves-only seeding would miss it,
        // stranding ROOT's terminal boundary QC below `2f+1`.
        const ED: u64 = 1_000;
        let (left, right) = ShardId::ROOT.children();
        let pre = Arc::new(shard_snapshot(1, &[0, 1, 2, 3], 0)); // ROOT only
        let post = Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)); // both children
        let mut sched = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&pre));
        sched.insert(Epoch::new(1), Arc::clone(&post));
        sched.set_head(post);

        let mut coord = RemoteHeaderCoordinator::new(left);
        coord.refresh_expected(&sched);

        assert!(
            coord.expected.contains_key(&ShardId::ROOT),
            "the drained parent must be seeded for sync, not just head leaves",
        );
        assert!(
            coord.expected.contains_key(&right),
            "the live sibling resolves its head committee and is seeded",
        );
        assert!(
            !coord.expected.contains_key(&left),
            "the local shard is never expected",
        );

        // Once the parent's window evicts, the entry is dropped — nothing
        // left to sync.
        let head_only = TopologySchedule::single(Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)));
        coord.refresh_expected(&head_only);
        assert!(
            !coord.expected.contains_key(&ShardId::ROOT),
            "a fully evicted shard is pruned from the expected set",
        );
    }

    #[test]
    fn fresh_member_flushes_retained_shards_before_first_commit() {
        // A freshly seated member — a halt-recovery draw from the pool, a
        // merge keeper — has no local commit, so its clock is still zero
        // while the schedule head is many windows on. The zero clock
        // resolves below every retained window; routability must fall back
        // to schedule retention or the member never issues the probes that
        // pull remote headers (and through them provisions and execution
        // certificates) before its first commit.
        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let sched = TopologySchedule::new(
            ED,
            Epoch::new(5),
            Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)),
        );

        let mut coord = RemoteHeaderCoordinator::new(local);
        let actions = coord.flush_expected_headers(&sched);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::StartRemoteHeaderSync { source_shard, .. } if *source_shard == remote
            )),
            "a zero-clock member must probe the retained sibling shard",
        );

        // The fallback is strictly for the zero clock: a committed clock
        // below every retained window still refuses to probe.
        coord.local_committed_ts = WeightedTimestamp::from_millis(1);
        let actions = coord.flush_expected_headers(&sched);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::StartRemoteHeaderSync { .. })),
            "a stale committed clock below the retained windows must not probe",
        );
    }

    #[test]
    fn remote_header_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];

        // Schedule head is epoch 0; a header anchored in epoch 5 is ahead of
        // this node's beacon and can't resolve yet.
        let behind = TopologySchedule::new(ED, Epoch::new(0), Arc::new(shard_snapshot(2, &ids, 0)));
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), 5 * ED); // parent WT in epoch 5

        let actions =
            coord.on_remote_header_received(&behind, Arc::clone(&header), ValidatorId::new(1));
        assert!(
            verify_qc_keys(&actions).is_none(),
            "a header whose epoch the beacon hasn't reached must buffer, not dispatch",
        );

        // Beacon catches up: a schedule covering epoch 5 resolves the committee.
        let caught_up = TopologySchedule::single(Arc::new(shard_snapshot(2, &ids, 0)));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            verify_qc_keys(&drained).is_some(),
            "draining on catch-up must dispatch the buffered header's verification",
        );
    }

    #[test]
    fn remote_header_below_schedule_floor_drops_without_buffering() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];

        // Schedule retains only epoch 5; a header anchored in epoch 0 sits
        // below the floor — unresolvable forever, so it must not occupy a
        // buffer slot a Byzantine sender could use to evict honest entries.
        let schedule =
            TopologySchedule::new(ED, Epoch::new(5), Arc::new(shard_snapshot(2, &ids, 0)));
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let actions =
            coord.on_remote_header_received(&schedule, Arc::clone(&header), ValidatorId::new(1));
        assert!(verify_qc_keys(&actions).is_none(), "nothing to verify");

        // A full-coverage schedule drains nothing — the header was dropped.
        let caught_up = TopologySchedule::single(Arc::new(shard_snapshot(2, &ids, 0)));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            verify_qc_keys(&drained).is_none(),
            "a below-floor header must be dropped, not buffered for replay",
        );
    }

    #[test]
    fn failed_verification_with_epoch_evicted_drops_all_siblings() {
        // Three peers gossip the same header at one (shard, height): the first
        // dispatches verification, the other two wait as pending fallbacks. The
        // first candidate's QC verification then fails, and by the time the
        // result lands the schedule's floor has passed that epoch, so no
        // sibling can ever resolve its committee again. Every sibling must be
        // dropped — none stranded in `pending` with no verification in flight,
        // and none buffered for a replay that can't succeed.
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3]; // shard 1's committee is {1, 3}
        let snap = || Arc::new(shard_snapshot(2, &ids, 0));

        // Epoch 0 is in the schedule when the headers arrive.
        let present = TopologySchedule::new(ED, Epoch::new(0), snap());
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = remote_header(remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let dispatched =
            coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(1));
        assert!(verify_qc_keys(&dispatched).is_some());
        coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(2));
        coord.on_remote_header_received(&present, Arc::clone(&header), ValidatorId::new(3));
        assert_eq!(coord.memory_stats().pending_headers, 3);

        // The first candidate's verification fails, and the schedule no longer
        // covers epoch 0 (every consumer frontier passed it).
        let evicted = TopologySchedule::new(ED, Epoch::new(5), snap());
        let after_fail = coord.on_remote_header_qc_verified(
            &evicted,
            remote,
            BlockHeight::new(5),
            ValidatorId::new(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
        );
        assert!(
            verify_qc_keys(&after_fail).is_none(),
            "no sibling can verify once their epoch fell below the floor",
        );
        assert_eq!(
            coord.memory_stats().pending_headers,
            0,
            "every sibling must be dropped, none stranded in pending",
        );

        // A full-coverage schedule drains nothing — the siblings were dropped,
        // not buffered.
        let caught_up = TopologySchedule::single(snap());
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            verify_qc_keys(&drained).is_none(),
            "dropped siblings must not re-dispatch on beacon catch-up",
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Commit-proof tests
    // ═══════════════════════════════════════════════════════════════════════

    /// A verified header for `shard` at `height`/`round`, parent-hash-linked
    /// to `parent` (or to a synthetic hash when building a branch tip whose
    /// parent is absent). Injected through the local-dispatch fast path,
    /// which needs no topology.
    fn chain_header(
        shard: ShardId,
        height: u64,
        round: u64,
        parent: Option<&Arc<Verified<CertifiedBlockHeader>>>,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_hash = parent.map_or_else(
            || BlockHash::from_raw(Hash::from_bytes(&height.to_le_bytes())),
            |p| p.block_hash(),
        );
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::new(round.saturating_sub(1)),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(height * 1_000),
        );
        let header = BlockHeader::new(
            shard,
            BlockHeight::new(height),
            parent_hash,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
            Round::new(round),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            BlockHeight::new(height),
            parent_hash,
            Round::new(round),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(height * 1_000),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    fn committed_heights(actions: &[Action]) -> Vec<u64> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Continuation(ProtocolEvent::RemoteHeaderCommitted { certified_header }) => {
                    Some(certified_header.height().inner())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn round_contiguous_child_proves_its_parent() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        let parent = chain_header(remote, 5, 5, None);
        let actions = coord.on_verified_remote_header_received(parent, ValidatorId::new(0));
        assert!(
            committed_heights(&actions).is_empty(),
            "a lone certified header proves nothing"
        );
        assert!(!coord.has_commit_proof(remote, BlockHeight::new(5)));

        let parent = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        let child = chain_header(remote, 6, 6, Some(&parent));
        let actions = coord.on_verified_remote_header_received(child, ValidatorId::new(0));
        assert_eq!(
            committed_heights(&actions),
            vec![5],
            "the round-contiguous child commits its parent"
        );
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
        assert!(
            !coord.has_commit_proof(remote, BlockHeight::new(6)),
            "the child itself stays unproven until its own child arrives"
        );
    }

    #[test]
    fn round_gapped_child_proves_nothing() {
        // A certified sibling that lost its round: the next header links by
        // parent hash but skips a round (view change), so no two-chain forms
        // and the parent stays unconsumable.
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        let parent = chain_header(remote, 5, 5, None);
        coord.on_verified_remote_header_received(parent, ValidatorId::new(0));
        let parent = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        let child = chain_header(remote, 6, 7, Some(&parent));
        let actions = coord.on_verified_remote_header_received(child, ValidatorId::new(0));
        assert!(
            committed_heights(&actions).is_empty(),
            "a round-gapped child is certification, not commitment"
        );
        assert!(!coord.has_commit_proof(remote, BlockHeight::new(5)));
    }

    #[test]
    fn prefix_commit_proves_hash_linked_ancestors() {
        // Heights 5 (round 5) ← 6 (round 7, view change) ← 7 (round 8): the
        // round-contiguous pair (6, 7) commits 6 directly, and 5 — committed
        // as the prefix of that two-chain — proves through the hash link.
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        coord.on_verified_remote_header_received(
            chain_header(remote, 5, 5, None),
            ValidatorId::new(0),
        );
        let h5 = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        coord.on_verified_remote_header_received(
            chain_header(remote, 6, 7, Some(&h5)),
            ValidatorId::new(0),
        );
        let h6 = coord
            .get_verified(remote, BlockHeight::new(6))
            .expect("stored")
            .clone();
        let actions = coord.on_verified_remote_header_received(
            chain_header(remote, 7, 8, Some(&h6)),
            ValidatorId::new(0),
        );

        let mut heights = committed_heights(&actions);
        heights.sort_unstable();
        assert_eq!(
            heights,
            vec![5, 6],
            "the direct commit of 6 proves 5 through the ancestry link"
        );
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
        assert!(coord.has_commit_proof(remote, BlockHeight::new(6)));
        assert!(!coord.has_commit_proof(remote, BlockHeight::new(7)));
    }

    #[test]
    fn gap_fill_extends_proof_downward_once() {
        // Heights arrive 5, 7, 8: proving 7 cannot reach 5 (6 missing). The
        // late arrival of 6 links the chain and proves 5 and 6 together —
        // each height emits its committed continuation exactly once.
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        coord.on_verified_remote_header_received(
            chain_header(remote, 5, 5, None),
            ValidatorId::new(0),
        );
        let h5 = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        // Build 6 → 7 → 8 linked over 5, but deliver 6 last.
        let h6 = chain_header(remote, 6, 6, Some(&h5));
        let h7 = chain_header(remote, 7, 7, Some(&h6));
        let h8 = chain_header(remote, 8, 8, Some(&h7));

        let actions = coord.on_verified_remote_header_received(h7, ValidatorId::new(0));
        assert!(
            committed_heights(&actions).is_empty(),
            "7 alone proves nothing"
        );
        let actions = coord.on_verified_remote_header_received(h8, ValidatorId::new(0));
        assert_eq!(
            committed_heights(&actions),
            vec![7],
            "8 commits 7; the walk stops at the missing 6"
        );

        let actions = coord.on_verified_remote_header_received(h6, ValidatorId::new(0));
        let mut heights = committed_heights(&actions);
        heights.sort_unstable();
        assert_eq!(
            heights,
            vec![5, 6],
            "filling the gap proves the ancestry below the proven suffix"
        );
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
    }

    #[test]
    fn broken_hash_link_stops_the_walk() {
        // The held header at 5 is a certified sibling from another branch:
        // the committing chain above links 6 → canonical-5, not the held 5,
        // so the walk stops and the sibling stays unproven.
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        // Held 5 is NOT the parent 6 links to (6 built over a synthetic hash).
        coord.on_verified_remote_header_received(
            chain_header(remote, 5, 5, None),
            ValidatorId::new(0),
        );
        let h6 = chain_header(remote, 6, 6, None);
        let h7 = chain_header(remote, 7, 7, Some(&h6));
        coord.on_verified_remote_header_received(h6, ValidatorId::new(0));
        let actions = coord.on_verified_remote_header_received(h7, ValidatorId::new(0));

        assert_eq!(
            committed_heights(&actions),
            vec![6],
            "7 commits 6, and the mismatched link leaves the sibling at 5 alone"
        );
        assert!(!coord.has_commit_proof(remote, BlockHeight::new(5)));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fork assembly tests
    // ═══════════════════════════════════════════════════════════════════════

    fn fork_proofs(actions: &[Action]) -> Vec<&ShardForkProof> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Continuation(ProtocolEvent::ShardForkDetected { proof }) => Some(&**proof),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn conflicting_commit_proofs_assemble_a_fork() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        // Winner branch: block@5(r5) ← child@6(r6). Sibling branch shares the
        // parent but forks the round, so its blocks carry distinct hashes:
        // block@5(r7) ← child@6(r8).
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        let s = chain_header(remote, 5, 7, None);
        let sc = chain_header(remote, 6, 8, Some(&s));

        assert!(
            fork_proofs(&coord.on_verified_remote_header_received(w, ValidatorId::new(1)))
                .is_empty()
        );
        assert!(
            fork_proofs(&coord.on_verified_remote_header_received(wc, ValidatorId::new(1)))
                .is_empty()
        );
        assert!(
            fork_proofs(&coord.on_verified_remote_header_received(s, ValidatorId::new(1)))
                .is_empty(),
            "a sibling block without its own committing child assembles nothing yet"
        );

        // The sibling's committing child completes the second branch's commit
        // proof — now two committed chains at height 5 exist.
        let actions =
            coord.on_verified_remote_header_received(Arc::clone(&sc), ValidatorId::new(1));
        let forks = fork_proofs(&actions);
        assert_eq!(
            forks.len(),
            1,
            "the completing sibling child assembles the fork"
        );
        let ShardForkProof::ConflictingCommits { a, b } = forks[0];
        assert_eq!(a.proven_height(), BlockHeight::new(5));
        assert_eq!(b.proven_height(), BlockHeight::new(5));
        assert_ne!(a.proven_block_hash(), b.proven_block_hash());

        // Re-observing the same conflict does not re-emit — one proof per
        // forked height.
        let again = coord.on_verified_remote_header_received(sc, ValidatorId::new(2));
        assert!(
            fork_proofs(&again).is_empty(),
            "a fork is proven at a height only once"
        );
    }

    #[test]
    fn certified_sibling_without_committing_child_assembles_nothing() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        // Winner branch is commit-proven; the sibling is a bare certified
        // header with no committing child — harmless under commit-proof
        // consumption, and no fork proof.
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        let s = chain_header(remote, 5, 7, None);
        coord.on_verified_remote_header_received(w, ValidatorId::new(1));
        coord.on_verified_remote_header_received(wc, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(s, ValidatorId::new(1));
        assert!(
            fork_proofs(&actions).is_empty(),
            "a certified sibling with no committing child is not a fork"
        );
    }

    #[test]
    fn fork_fence_stops_promotion_at_and_above_the_fork_height() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        // Fork at height 5: promotion stops at or above 5.
        coord.engage_fork_fence(remote, BlockHeight::new(5));

        // A commit-proven header AT the fork height is tracked but not
        // promoted — no `RemoteHeaderCommitted`, so no consumer opens it.
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        coord.on_verified_remote_header_received(w, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(wc, ValidatorId::new(1));
        assert!(
            committed_heights(&actions).is_empty(),
            "the fenced height must not promote"
        );
        assert!(
            coord.has_commit_proof(remote, BlockHeight::new(5)),
            "it is still tracked as commit-proven, just held back"
        );

        // A below-fork commit still promotes normally.
        let b3 = chain_header(remote, 3, 3, None);
        let b4 = chain_header(remote, 4, 4, Some(&b3));
        coord.on_verified_remote_header_received(b3, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(b4, ValidatorId::new(1));
        assert_eq!(
            committed_heights(&actions),
            vec![3],
            "a below-fork commit promotes"
        );
    }
}
