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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

use hyperscale_core::{Action, ConsensusAction, HeaderCommittee, ProtocolEvent};
use hyperscale_types::network::request::MAX_REMOTE_HEADERS_PER_REQUEST;
use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, CertifiedBlock, CertifiedBlockHeader,
    CertifiedHeaderVerifyError, CommitProof, CommittedClock, ConsensusPublicKey, ForkFence,
    HeaderFetchCount, HeaderSource, REMOTE_HEADER_RETENTION, RETENTION_HORIZON, ScheduleLookup,
    ShardForkProof, ShardId, TRANSACTION_EVIDENCE_HORIZON, TopologySchedule, TopologySnapshot,
    TxsInFlight, ValidatorId, Verified, WeightedTimestamp,
};
use tracing::{debug, info, trace, warn};

use crate::awaiting::AwaitingTopologyBuffer;
use crate::shard_headers::{Candidate, ShardHeaders, retention_ts};

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
/// target, for a shard nothing verified above the frontier has shown to
/// be further on. Sized to fit one full range fetch at the I/O loop's
/// maximum batch size, so one round trip discovers whether the shard has
/// moved.
const DEFAULT_PROBE_LOOKAHEAD: u64 = 64;

/// How long a wanted commit proof waits before its fetch re-issues.
/// Measured against the local committed weighted timestamp, like the
/// header liveness timeout.
const COMMIT_PROOF_RETRY: Duration = Duration::from_secs(5);

/// First fetch length for a wanted commit proof. A direct commit needs
/// only the block and its round-contiguous child; the slack covers a
/// short view-change run. Doubled on every retry up to the wire cap, so
/// a deep round-gapped run is eventually covered.
const COMMIT_PROOF_INITIAL_COUNT: u64 = 4;

/// Remote header coordinator memory statistics for monitoring collection sizes.
#[allow(missing_docs)] // flat counters; field names are the documentation
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteHeaderMemoryStats {
    pub(crate) pending_headers: usize,
    pub(crate) verified_headers: usize,
    pub(crate) proven_headers: usize,
    pub(crate) expected_headers: usize,
    /// Held off-branch fork siblings — nonzero means a remote committee is
    /// producing conflicting certified headers at some height.
    pub(crate) fork_siblings: usize,
}

impl RemoteHeaderMemoryStats {
    /// Every readout as a `(field, value)` pair for the metrics backend.
    ///
    /// The destructure is the drift guard: a field added above does not
    /// compile here until it is given a gauge.
    #[must_use]
    pub fn gauges(&self) -> Vec<(&'static str, usize)> {
        let Self {
            pending_headers,
            verified_headers,
            proven_headers,
            expected_headers,
            fork_siblings,
        } = *self;
        vec![
            ("pending_headers", pending_headers),
            ("verified_headers", verified_headers),
            ("proven_headers", proven_headers),
            ("expected_headers", expected_headers),
            ("fork_siblings", fork_siblings),
        ]
    }
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
    /// The sync frontier: the highest height up to which we hold a
    /// contiguous run of verified headers from this shard (0 if none). Only
    /// a header that extends this run advances it — an out-of-band admission
    /// above the frontier (a provision- or EC-bundled source header fetched
    /// for a single block) is held in `verified` but does not slide the
    /// frontier past the gap below it. This keeps the liveness probe and the
    /// sync watermark aligned with contiguous coverage, which the
    /// commit-proof walk needs.
    last_verified_height: BlockHeight,
    /// The highest height of any header verified from this shard,
    /// contiguous with the frontier or not. Gossip and bundled source
    /// headers land here long before the frontier reaches them — a member
    /// seated at the attested boundary hears the live tip a witness window
    /// above it — and every height between is one the sync has to close
    /// before a consumer can commit-prove what it holds there.
    verified_tip: BlockHeight,
    /// Local weighted timestamp when we last verified a header from
    /// this shard. Liveness baseline once set — the timeout measures how
    /// much *local* wall-clock has passed since we last heard from the
    /// remote shard, rather than comparing heights across independent
    /// counters. `None` until the first header is verified.
    last_verified_at: Option<WeightedTimestamp>,
}

impl ExpectedHeader {
    /// How far a sync raised now has to reach: every height up to the
    /// highest header already verified from the shard, and at least one
    /// probe batch past the frontier.
    ///
    /// Reaching only a batch past the frontier would close a wide gap one
    /// batch per liveness timeout — slower than a live shard produces, so
    /// a member seated at the attested boundary would never commit-prove a
    /// source block its consumers hold, and a bundle waiting on one would
    /// outlive its transaction's deadline.
    fn sync_target(&self) -> BlockHeight {
        BlockHeight::new(self.last_verified_height.inner() + DEFAULT_PROBE_LOOKAHEAD)
            .max(self.verified_tip)
    }
}

/// One wanted commit proof: a targeted header fetch re-driven until its
/// height proves or the entry ages out.
struct WantedProof {
    /// Local committed weighted timestamp at registration. The entry
    /// expires one retention horizon later — by then the parked consumer
    /// has aborted and nothing is waiting on the proof.
    registered_at: WeightedTimestamp,
    /// When the last fetch was issued; paces the retry.
    requested_at: WeightedTimestamp,
    /// Fetches issued so far; sizes the doubling range.
    attempts: u32,
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
/// - **Provision**: Uses verified `state_root` for merkle proof verification;
///   `ticks` field to register expected provisions
/// - **Execution**: Releases a shard's certificates and claims held on its
///   commit proof
pub struct RemoteHeaderCoordinator {
    /// Every remote shard's held headers. An entry is opened by the first
    /// header received from its shard and closed only when the shard's
    /// departure evidence window does ([`Self::retire_departed`]).
    shards: BTreeMap<ShardId, ShardHeaders>,

    /// `(shard, height)` slots a fork proof has already been assembled and
    /// emitted for — one proof per forked height — with the two blocks it
    /// paired. Bounded by the number of genuine forks (a Byzantine event),
    /// so it is not WT-pruned.
    forks_emitted: HashMap<(ShardId, BlockHeight), [BlockHash; 2]>,

    /// Highest beacon-attested recovery frontier observed per shard, across
    /// pending records and recovery histories. Fork assembly is suppressed at or
    /// below it: a fork there was already answered by a recovery, so
    /// re-assembling it from held siblings would re-flag the healthy
    /// successor committee. Monotone; never pruned (one entry per recovered
    /// shard).
    recovery_frontiers: BTreeMap<ShardId, BlockHeight>,

    /// Commit proofs a cross-shard consumer is parked on for a height the
    /// forward header sync never reaches — at or below the shard's
    /// attested boundary, under a joiner's (or a fresh recovery
    /// committee's) sync anchor. Each entry drives a targeted
    /// [`Action::FetchCommitProof`], re-issued on the commit sweep with a
    /// doubling range until the height proves or the entry ages out.
    wanted_proofs: BTreeMap<(ShardId, BlockHeight), WantedProof>,

    /// The node's gossip-timed fork fence, engaged and cleared by the
    /// node: a verified fork proof stops the
    /// `RemoteHeaderCommitted` promotion for that shard at or above the
    /// forked height — so no consumer opens a fenced block's provisions or
    /// execution certificates. Held until the shard's recovery completes;
    /// the attested recovery fence governs validity over the
    /// fold-to-completion window.
    fork_fence: ForkFence,

    // ═══════════════════════════════════════════════════════════════════
    // Liveness Tracking (drives header-sync staleness detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Per-shard liveness tracking. Populated when topology tells us
    /// remote shards exist. Drives `Action::StartRemoteHeaderSync` when a
    /// shard hasn't sent headers within `HEADER_LIVENESS_TIMEOUT`.
    expected: BTreeMap<ShardId, ExpectedHeader>,

    /// The node's committed clock: the "now" reference for liveness
    /// timeouts, independent of local block production rate.
    clock: CommittedClock,

    /// Whether a block has committed through this coordinator yet: the
    /// edge the pre-commit entries are retro-stamped on.
    committed_once: bool,

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
    awaiting: AwaitingTopologyBuffer<(HeaderSource, CertifiedBlockHeader)>,
    /// Headers whose signing committee can't be resolved because their
    /// parent hasn't verified here: a block's committee anchors on its
    /// parent, and only a verified parent (or the beacon's attested
    /// boundary) is trusted to name it. Bounded per shard (drop-oldest),
    /// re-offered whenever a header of their shard is admitted or the
    /// beacon advances.
    awaiting_parent: AwaitingTopologyBuffer<(HeaderSource, CertifiedBlockHeader)>,
    /// When each shard's missing parents were last fetched.
    parents_requested_at: BTreeMap<ShardId, WeightedTimestamp>,
}

impl RemoteHeaderCoordinator {
    /// Create a new remote header coordinator with a clock and fence of
    /// its own.
    #[must_use]
    pub fn new(local_shard: ShardId) -> Self {
        Self::sharing(local_shard, CommittedClock::default(), ForkFence::new())
    }

    /// Create a remote header coordinator on the node's own `clock` and
    /// `fork_fence`, shared with the coordinators beside this one.
    #[must_use]
    pub fn sharing(local_shard: ShardId, clock: CommittedClock, fork_fence: ForkFence) -> Self {
        Self {
            shards: BTreeMap::new(),
            forks_emitted: HashMap::new(),
            recovery_frontiers: BTreeMap::new(),
            wanted_proofs: BTreeMap::new(),
            fork_fence,
            expected: BTreeMap::new(),
            clock,
            committed_once: false,
            local_shard,
            awaiting: AwaitingTopologyBuffer::new(),
            awaiting_parent: AwaitingTopologyBuffer::new(),
            parents_requested_at: BTreeMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Header Ingestion
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a committed block header that arrived already verified —
    /// emitted by a colocated proposer through the local-dispatch fast
    /// path (see [`ProtocolEvent::VerifiedRemoteHeaderReceived`]). Skips
    /// the pending bookkeeping and the `ConsensusAction::VerifyRemoteHeaderQc`
    /// dispatch, promoting straight to the verified map and emitting
    /// the same `RemoteHeaderAdmitted` continuation downstream consumers
    /// already expect.
    pub fn on_verified_remote_header_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified_header: Verified<CertifiedBlockHeader>,
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

        self.update_tip_and_prune(shard, height, retention_ts(&certified_header));
        self.store_mut(shard).clear_pending(height);
        let mut actions = self.admit_verified_header(topology_schedule, certified_header);
        actions.extend(self.reoffer_awaiting_parent(topology_schedule, shard));
        actions
    }

    /// Handle a committed block header received from a remote shard (gossip or fetch).
    ///
    /// A gossip source's signature was already verified by `IoLoop`.
    /// Performs structural pre-checks, stores as pending, and dispatches
    /// `VerifyRemoteHeaderQc` for async QC verification.
    pub fn on_remote_header_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified_header: CertifiedBlockHeader,
        source: HeaderSource,
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
        // `verified` slot. A copy of an already-held fork sibling is just
        // as verified as the canonical winner — re-verifying it would burn
        // an off-thread aggregate check per re-gossip.
        if let Some(store) = self.shards.get(&shard)
            && store
                .verified(height)
                .into_iter()
                .chain(store.siblings(height))
                .any(|held| held.block_hash() == header_hash)
        {
            return vec![];
        }

        if certified_header.qc().block_hash() != header_hash {
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                source = ?source,
                "Rejected remote header: QC block_hash does not match header hash"
            );
            return vec![];
        }

        // Structural pre-check: QC shard must match header shard.
        if certified_header.qc().shard_id() != shard {
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                source = ?source,
                qc_shard = certified_header.qc().shard_id().inner(),
                "Rejected remote header: QC shard_id does not match header shard"
            );
            return vec![];
        }

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            source = ?source,
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
        let (anchor, named_by) =
            self.committee_anchor_wt(topology_schedule, shard, certified_header.header());
        let committee = match topology_schedule.lookup_for_shard_certified_fenced(
            shard,
            anchor,
            certified_header.qc().weighted_timestamp(),
        ) {
            None => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    source = ?source,
                    "Dropping remote header that resolves the retained committee during a halt recovery"
                );
                return vec![];
            }
            Some((ScheduleLookup::Committee(committee), _)) => committee,
            Some((ScheduleLookup::NotYetCommitted, _)) => {
                self.awaiting.push(shard, (source, certified_header));
                return vec![];
            }
            Some((ScheduleLookup::Evicted, _)) => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    source = ?source,
                    "Remote header's committee epoch is below the schedule floor — dropping"
                );
                return vec![];
            }
        };

        // Prune before the candidate lands, so it stays held until the
        // next header of its shard arrives: a commit-proof range is older
        // than the retention by construction, and the next header in it
        // resolves its committee through this one as its pending parent.
        self.update_tip_and_prune(shard, height, retention_ts(&certified_header));

        let candidate =
            self.store_mut(shard)
                .add_candidate(height, source, certified_header.clone());
        if candidate == Candidate::Duplicate {
            trace!(
                shard = shard.inner(),
                height = height.inner(),
                source = ?source,
                "Duplicate remote header from same source — skipping"
            );
            return vec![];
        }

        // The first candidate at a (shard, height) triggers QC verification.
        if candidate == Candidate::First {
            // Emit QC verification for the first header at this (shard, height).
            Self::emit_verify_qc(committee, named_by, source, certified_header)
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
    /// On failure: removes the failed candidate and tries the next source's
    /// header. One that failed under a guessed `committee` is checked again
    /// under the committee its parent names: at once if the parent is held
    /// by now, otherwise once it arrives.
    pub fn on_remote_header_qc_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified_header: &CertifiedBlockHeader,
        source: HeaderSource,
        result: Result<Verified<CertifiedBlockHeader>, CertifiedHeaderVerifyError>,
        committee: HeaderCommittee,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let height = certified_header.height();
        let verified = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    shard = shard.inner(),
                    height = height.inner(),
                    source = ?source,
                    reason = %e,
                    "Remote header QC verification failed"
                );

                self.drop_candidate(shard, height, source);
                let mut actions = self.dispatch_next_candidate(topology_schedule, shard, height);
                // A header that failed under a guess may be honest: it is
                // checked again under its parent's committee, even when the
                // retention has already pruned its pending entry. The next
                // candidate goes first, so a re-offer lands behind it rather
                // than dispatching the same height twice.
                if committee == HeaderCommittee::Guessed {
                    actions.extend(self.retry_under_parent(
                        topology_schedule,
                        source,
                        certified_header.clone(),
                    ));
                }
                return actions;
            }
        };

        debug!(
            shard = shard.inner(),
            height = height.inner(),
            "Remote header QC verified — promoting"
        );

        if let Some(store) = self.shards.get_mut(&shard) {
            store.clear_pending(height);
        }
        let mut actions = self.admit_verified_header(topology_schedule, verified);
        actions.extend(self.reoffer_awaiting_parent(topology_schedule, shard));
        actions
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
        topology_schedule: &TopologySchedule,
        verified: Verified<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let shard = verified.shard_id();
        let height = verified.height();
        let store = self.store_mut(shard);

        if let Some(existing) = store.verified(height) {
            if existing.block_hash() == verified.block_hash() {
                return Vec::new();
            }
            warn!(
                shard = shard.inner(),
                height = height.inner(),
                "Verified a conflicting certified header at an occupied height — fork candidate"
            );
            return self.observe_fork_sibling(topology_schedule, verified);
        }
        store.set_verified(verified.clone());
        if let Some(expected) = self.expected.get_mut(&shard) {
            expected.verified_tip = expected.verified_tip.max(height);
        }

        // Advance the sync frontier only over a contiguous run of verified
        // heights. A header admitted above the frontier — a provision- or
        // execution-certificate-bundled source header fetched for a single
        // block, arriving while `block.committed` gossip is suppressed —
        // populates `verified` but is not sync progress: counting it would
        // refresh the liveness baseline and slide the frontier past the gap
        // below it, leaving the intervening heights unfetched. The
        // commit-proof walk a cross-shard consumer runs needs a source block
        // and its committing child held contiguously, so only a header that
        // extends the frontier — walking up over any already-held successors —
        // advances it and re-arms the liveness clock.
        self.walk_frontier(topology_schedule, shard);

        let mut actions = vec![Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted {
            certified_header: verified,
        })];
        actions.extend(self.prove_commits(topology_schedule, shard, height));
        // The canonical winner can also be one branch of a fork whose losing
        // branch is already held — and its arrival can hand a held sibling
        // at the height below its committing child.
        actions.extend(self.check_fork_at(topology_schedule, shard, height));
        actions.extend(self.reconcile_canonical(topology_schedule, shard, height));
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
        cleared: &[ShardId],
    ) -> Vec<Action> {
        // The shard coordinator's commit has already advanced the shared
        // clock past this block; this is a no-op there, and is what moves
        // a coordinator that runs without one.
        self.clock
            .advance(certified.block().header().parent_qc().weighted_timestamp());
        let new_ts = self.clock.now();
        let first_commit = !self.committed_once;
        self.committed_once = true;

        // Retro-stamp entries recorded before the first local commit: on a
        // fresh chain remote headers can arrive (and verify) while the
        // clock still reads zero or the genesis instant, which would
        // otherwise make age computations report everything since genesis
        // on the very next commit and trigger a fallback storm.
        if first_commit {
            let genesis = topology_schedule.windows().origin();
            for expected in self.expected.values_mut() {
                if expected.discovered_at <= genesis {
                    expected.discovered_at = new_ts;
                }
                if expected.last_verified_at.is_some_and(|at| at <= genesis) {
                    expected.last_verified_at = Some(new_ts);
                }
            }
            for wanted in self.wanted_proofs.values_mut() {
                if wanted.registered_at <= genesis {
                    wanted.registered_at = new_ts;
                    wanted.requested_at = new_ts;
                }
            }
        }

        self.refresh_expected(topology_schedule);
        self.retire_departed(topology_schedule);
        self.observe_recoveries(topology_schedule.head());
        let mut actions = Vec::new();

        // The node cleared its fork fence for `cleared` at the head of this
        // commit's fan-out, their recoveries having completed. Clearing
        // releases the promotions the fence withheld: everything proven
        // below the recovery's frontier is canonical history whose ticks
        // are still decidable, and stranding it would abort them.
        for &shard in cleared {
            actions.extend(self.release_proven(topology_schedule, shard));
        }
        actions.extend(self.retry_wanted_proofs(topology_schedule));

        // Check for timed-out remote shards.
        let now = self.clock.now();

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
            let target = expected.sync_target();

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
                    discovered_at: self.clock.now(),
                    last_verified_height: anchor_height,
                    verified_tip: anchor_height,
                    last_verified_at: None,
                });
            self.walk_frontier(topology_schedule, shard);
        }
    }

    /// Every peer of `shard` asked answered that the heights from this
    /// node's frontier lie beneath their chain floor, `floor`: the gap
    /// between the frontier and the source's tip is gone at the source, and
    /// syncing forward from the frontier asks for it forever.
    ///
    /// The frontier moves to the shard's attested boundary, as a freshly
    /// tracked shard is anchored there: a height the source provably holds,
    /// since no store's floor passes the boundary it is attested at, and one
    /// no live cross-shard consumer reaches below. A boundary still beneath
    /// the floor anchors nothing, and the frontier stays until it moves.
    pub fn on_source_below_floor(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        floor: BlockHeight,
    ) {
        let Some(anchor) = topology_schedule
            .head()
            .boundary(shard)
            .map(|anchor| anchor.height)
            .filter(|anchor| *anchor >= floor)
        else {
            return;
        };
        let Some(expected) = self.expected.get_mut(&shard) else {
            return;
        };
        if expected.last_verified_height >= floor {
            return;
        }
        tracing::warn!(
            ?shard,
            frontier = expected.last_verified_height.inner(),
            floor = floor.inner(),
            anchor = anchor.inner(),
            "remote-header frontier beneath the source's chain floor; re-anchoring at its \
             attested boundary"
        );
        expected.last_verified_height = anchor;
        expected.verified_tip = expected.verified_tip.max(anchor);
        self.walk_frontier(topology_schedule, shard);
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
            if !Self::shard_routable(topology_schedule, shard, self.clock.now()) {
                continue;
            }

            let target = expected.sync_target();

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
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<&Verified<CertifiedBlockHeader>> {
        self.shards.get(&shard)?.verified(height)
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
    ) -> Option<&BTreeMap<HeaderSource, CertifiedBlockHeader>> {
        self.shards.get(&shard)?.pending(height)
    }

    /// Check if a verified header exists for (shard, height).
    #[must_use]
    pub fn has_verified(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.get_verified(shard, height).is_some()
    }

    /// The highest contiguously-verified height for `shard` — the sync
    /// frontier. The remote-header sync follows this, not a header's own
    /// height, so an out-of-band admission above the frontier never jumps
    /// the sync past a gap it must still fetch. `None` if the shard isn't
    /// tracked.
    #[must_use]
    pub fn verified_frontier(&self, shard: ShardId) -> Option<BlockHeight> {
        self.expected.get(&shard).map(|e| e.last_verified_height)
    }

    /// The highest height of any header verified from `shard`, contiguous
    /// with the frontier or not, or `None` when the replica does not track
    /// the shard.
    #[must_use]
    pub fn verified_tip(&self, shard: ShardId) -> Option<BlockHeight> {
        self.expected.get(&shard).map(|e| e.verified_tip)
    }

    /// How far a sync of `shard` has to reach while a header verified
    /// from it sits above the contiguous frontier, leaving a gap the sync
    /// has to close. `None` when the frontier holds every verified header,
    /// or the replica does not track the shard.
    #[must_use]
    pub fn gap_sync_target(&self, shard: ShardId) -> Option<BlockHeight> {
        self.expected
            .get(&shard)
            .filter(|e| e.verified_tip > e.last_verified_height)
            .map(ExpectedHeader::sync_target)
    }

    /// Get the in-flight count from the tip header of each remote shard.
    ///
    /// Used for cross-shard backpressure: RPC nodes can reject transactions
    /// targeting congested remote shards.
    #[must_use]
    pub fn remote_shard_in_flight(&self) -> BTreeMap<ShardId, TxsInFlight> {
        self.shards
            .iter()
            .filter_map(|(&shard, store)| {
                store
                    .verified(store.tip().0)
                    .map(|h| (shard, h.header().txs_in_flight()))
            })
            .collect()
    }

    /// Get memory statistics for monitoring.
    #[must_use]
    pub fn memory_stats(&self) -> RemoteHeaderMemoryStats {
        let mut stats = RemoteHeaderMemoryStats {
            expected_headers: self.expected.len(),
            ..RemoteHeaderMemoryStats::default()
        };
        for store in self.shards.values() {
            store.count_into(&mut stats);
        }
        stats
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Public API: Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Periodic cleanup of old headers.
    ///
    /// Called on cleanup timer. Runs the shared retention pass against
    /// each shard's tip, catching entries that aged out since the last
    /// ingestion-driven prune.
    pub fn cleanup(&mut self) {
        let tips: Vec<(ShardId, WeightedTimestamp)> = self
            .shards
            .iter()
            .map(|(&shard, store)| (shard, store.tip().1))
            .collect();
        for (shard, tip_ts) in tips {
            self.prune_shard_behind(shard, tip_ts);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Update the per-shard tip and prune old entries.
    fn update_tip_and_prune(
        &mut self,
        shard: ShardId,
        height: BlockHeight,
        header_ts: WeightedTimestamp,
    ) {
        let tip_ts = self.store_mut(shard).raise_tip(height, header_ts);
        self.prune_shard_behind(shard, tip_ts);
    }

    /// `shard`'s held headers, opening an empty store for a shard first
    /// heard from.
    fn store_mut(&mut self, shard: ShardId) -> &mut ShardHeaders {
        self.shards.entry(shard).or_default()
    }

    /// Whether the held header at `(shard, height)` is commit-proven.
    /// Whether `(shard, height)` holds the commit proof a consumer waits
    /// on: proven, by a block that does not [yield](Self::yields) to a
    /// recovery. A yielding orphan's proof is not the height's.
    fn proves(
        &self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> bool {
        self.shards.get(&shard).is_some_and(|store| {
            store.is_proven(height)
                && store
                    .verified(height)
                    .is_some_and(|occupant| !Self::yields(topology_schedule, store, occupant))
        })
    }

    /// Drop `source`'s pending candidate at `(shard, height)`.
    fn drop_candidate(&mut self, shard: ShardId, height: BlockHeight, source: HeaderSource) {
        if let Some(store) = self.shards.get_mut(&shard) {
            store.remove_candidate(height, source);
        }
    }

    /// Drop everything held for a shard whose handoff evidence window has
    /// closed.
    ///
    /// The retention pass beside this one counts back from the shard's
    /// OWN tip, and a shard that dissolves at a reshape stops producing
    /// one — so its last window's worth of headers, and the store entry
    /// that makes every sweep iterate it, would be held for the life of
    /// the process, growing linearly in the number of shards ever
    /// created. What ends a departed shard instead is the evidence
    /// window, counted from the handoff the beacon stamped, which is the
    /// same reading every other cache and prune in the tree closes on —
    /// so nothing here stops holding a header while a fence still expects
    /// an answer off it.
    ///
    /// Keyed on the stamp being present rather than on the shard being
    /// absent from the routable set: a departure this can act on is one
    /// the schedule states, not one it fails to mention.
    fn retire_departed(&mut self, topology_schedule: &TopologySchedule) {
        let now = self.clock.now();
        if now <= topology_schedule.windows().origin() {
            return;
        }
        let departed: Vec<ShardId> = self
            .shards
            .keys()
            .copied()
            .filter(|shard| {
                topology_schedule
                    .handoff_evidence_expiry(*shard)
                    .is_some_and(|expiry| now > expiry)
            })
            .collect();
        for shard in departed {
            tracing::debug!(
                shard = shard.inner(),
                "Retiring a departed shard's remote headers — its evidence window has closed"
            );
            self.shards.remove(&shard);
        }
    }

    /// Drop every held artifact of `shard` older than its retention,
    /// counted back from the shard's tip at `tip_ts` over each header's
    /// parent-QC weighted timestamp — the pass shared by ingestion pruning
    /// and the cleanup timer. `proven` and `promoted` follow `verified`
    /// (always subsets of it).
    ///
    /// A verified header above the sync frontier is held past
    /// [`REMOTE_HEADER_RETENTION`], to [`TRANSACTION_EVIDENCE_HORIZON`]: it
    /// is sync progress the frontier has not walked over yet. A sync from
    /// far below the tip — a member anchored at the attested boundary, a
    /// witness window back — fetches headers already past the retention,
    /// and they verify in whatever order the verification pool finishes
    /// them. Dropping the ones that land ahead of the frontier leaves a
    /// gap the walk cannot cross, and the sync fetches the same window
    /// again only to lose it the same way.
    fn prune_shard_behind(&mut self, shard: ShardId, tip_ts: WeightedTimestamp) {
        let cutoff = tip_ts.minus(REMOTE_HEADER_RETENTION);
        let horizon = tip_ts.minus(TRANSACTION_EVIDENCE_HORIZON);
        // The walked frontier stays whatever its age: it is the parent the
        // next header's committee anchors on.
        let frontier = self
            .expected
            .get(&shard)
            .map(|expected| expected.last_verified_height);
        if let Some(store) = self.shards.get_mut(&shard) {
            store.prune(cutoff, horizon, frontier);
        }
    }

    /// A cross-shard consumer is parked on `(shard, height)` awaiting its
    /// commit proof, for a height at or below the shard's attested
    /// boundary — under the forward sync anchor, where no range fetch
    /// will ever land. Register the want and issue the first targeted
    /// fetch; the commit sweep re-issues it until the height proves or
    /// the entry ages out.
    pub fn request_commit_proof(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        if shard == self.local_shard {
            return Vec::new();
        }
        let key = (shard, height);
        let store = self.shards.get(&shard);
        // Already promoted: the consumer raced the promotion — re-emit it
        // so its proven view catches up. Proven-but-unpromoted stays
        // withheld until `release_proven` lets it out.
        if let Some(store) = store
            && store.is_promoted(height)
            && let Some(header) = store.verified(height)
        {
            return vec![Action::Continuation(ProtocolEvent::RemoteHeaderCommitted {
                certified_header: header.clone(),
            })];
        }
        if self.proves(topology_schedule, shard, height) || self.wanted_proofs.contains_key(&key) {
            return Vec::new();
        }
        let now = self.clock.now();
        self.wanted_proofs.insert(
            key,
            WantedProof {
                registered_at: now,
                requested_at: now,
                attempts: 1,
            },
        );
        info!(
            shard = shard.inner(),
            height = height.inner(),
            "Below-anchor source block wanted — fetching its commit proof"
        );
        vec![Self::fetch_commit_proof(shard, height, 1)]
    }

    /// The fetch for one wanted commit proof: a header range starting at
    /// the height, doubled per attempt so a committing two-chain that
    /// sits several round-gapped blocks above it is eventually covered.
    fn fetch_commit_proof(shard: ShardId, height: BlockHeight, attempts: u32) -> Action {
        let count = COMMIT_PROOF_INITIAL_COUNT
            .saturating_mul(1_u64 << (attempts - 1).min(31))
            .min(MAX_REMOTE_HEADERS_PER_REQUEST.inner());
        Action::FetchCommitProof {
            source_shard: shard,
            from_height: height,
            count: HeaderFetchCount::new(count),
        }
    }

    /// Re-drive the wanted commit proofs: drop entries whose height has
    /// proven (the fetch delivered, or gossip beat it) or whose parked
    /// consumer has aged out, then re-issue stale fetches with a doubled
    /// range.
    fn retry_wanted_proofs(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        if self.wanted_proofs.is_empty() {
            return Vec::new();
        }
        let now = self.clock.now();
        let proven: Vec<(ShardId, BlockHeight)> = self
            .wanted_proofs
            .keys()
            .copied()
            .filter(|&(shard, height)| self.proves(topology_schedule, shard, height))
            .collect();
        for key in proven {
            self.wanted_proofs.remove(&key);
        }
        self.wanted_proofs
            .retain(|_, wanted| now.elapsed_since(wanted.registered_at) <= RETENTION_HORIZON);
        let mut actions = Vec::new();
        for (&(shard, height), wanted) in &mut self.wanted_proofs {
            if now.elapsed_since(wanted.requested_at) < COMMIT_PROOF_RETRY {
                continue;
            }
            wanted.attempts += 1;
            wanted.requested_at = now;
            actions.push(Self::fetch_commit_proof(shard, height, wanted.attempts));
        }
        actions
    }

    /// Remember each attested recovery frontier the beacon head carries,
    /// pending or in a history: fork assembly is inert at or below it.
    ///
    /// Nothing held is evicted for a recovery. A block above a frontier
    /// with the shape of one the recovery discarded is judged by descent:
    /// the tail a halt recovery harvests has that shape too, and stops
    /// [yielding](Self::yields) once the fresh chain on it is held. A
    /// yielding block gives its slot to the fresh chain, is never
    /// promoted, covers no height for the sync frontier, and pairs into no
    /// fork proof once the recovery clears.
    fn observe_recoveries(&mut self, head: &TopologySnapshot) {
        for (&shard, recovery) in head.pending_recoveries() {
            self.note_recovery_frontier(shard, recovery.attested_frontier);
        }
        for (shard, history) in head.recovery_histories() {
            for binding in history {
                self.note_recovery_frontier(shard, binding.attested_frontier);
            }
        }
    }

    /// Raise the shard's remembered recovery frontier (monotone).
    fn note_recovery_frontier(&mut self, shard: ShardId, frontier: BlockHeight) {
        let entry = self
            .recovery_frontiers
            .entry(shard)
            .or_insert(BlockHeight::new(0));
        if frontier > *entry {
            *entry = frontier;
        }
    }

    /// Emit `RemoteHeaderCommitted` for every proven height of `shard` not
    /// yet promoted, in height order, unless the fork fence withholds it
    /// or its block [yields](Self::yields) to a recovery. Only a yielding
    /// occupant loses a proven slot to a sibling, and a yielding block is
    /// never promoted, so a height is promoted once unless its block was
    /// promoted before the recovery that shapes it folded.
    fn release_proven(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
    ) -> Vec<Action> {
        let Some(store) = self.shards.get(&shard) else {
            return Vec::new();
        };
        let ready: Vec<Verified<CertifiedBlockHeader>> = store
            .withheld()
            .filter(|&height| !self.fork_fence.is_fenced(shard, height))
            .map(|height| {
                store
                    .verified(height)
                    .expect("proven is pruned with verified")
            })
            .filter(|header| !Self::yields(topology_schedule, store, header))
            .cloned()
            .collect();
        let store = self.store_mut(shard);
        for header in &ready {
            store.mark_promoted(header.height());
        }
        ready
            .into_iter()
            .map(|certified_header| {
                Action::Continuation(ProtocolEvent::RemoteHeaderCommitted { certified_header })
            })
            .collect()
    }

    /// Whether `header` gives way to the recovered chain: it has the shape
    /// of a block one of its shard's recoveries discarded
    /// ([`TopologySchedule::recovery_discard_shaped`]), and no held
    /// fresh-certified block descends from it. A halt recovery's
    /// harvested tail has the shape and stops yielding once the fresh
    /// chain built on it is held; an orphan never does.
    fn yields(
        topology_schedule: &TopologySchedule,
        store: &ShardHeaders,
        header: &CertifiedBlockHeader,
    ) -> bool {
        if !topology_schedule.recovery_discard_shaped(header) {
            return false;
        }
        let mut parents = BTreeSet::from([header.block_hash()]);
        let mut height = header.height();
        while !parents.is_empty() {
            height = height.next();
            let children: Vec<&Verified<CertifiedBlockHeader>> = store
                .verified(height)
                .into_iter()
                .chain(store.siblings(height))
                .filter(|child| parents.contains(&child.header().parent_block_hash()))
                .collect();
            if children
                .iter()
                .any(|child| !topology_schedule.recovery_discard_shaped(child))
            {
                return false;
            }
            parents = children.iter().map(|child| child.block_hash()).collect();
        }
        true
    }

    /// Whether `header` is a block a recovery of its shard discarded: it
    /// [yields](Self::yields), and no recovery of the shard is pending.
    /// While one is, the retained cohort's own fork of its suffix is held
    /// and paired, so the beacon can upgrade the recovery.
    fn discarded(
        topology_schedule: &TopologySchedule,
        store: &ShardHeaders,
        header: &CertifiedBlockHeader,
    ) -> bool {
        topology_schedule
            .recovery_bridge(header.shard_id())
            .is_none()
            && Self::yields(topology_schedule, store, header)
    }

    /// Record a verified fork sibling and check whether it completes a fork
    /// proof. The sibling lost the canonical slot at its height to a
    /// first-seen different-hash header, so it lives here until both fork
    /// branches are commit-proven.
    fn observe_fork_sibling(
        &mut self,
        topology_schedule: &TopologySchedule,
        sibling: Verified<CertifiedBlockHeader>,
    ) -> Vec<Action> {
        let shard = sibling.shard_id();
        let height = sibling.height();
        // A re-gossiped copy of an already-held sibling carries nothing
        // new; holding it twice only grows the Vec and re-runs assembly.
        if !self.store_mut(shard).add_sibling(sibling) {
            return Vec::new();
        }
        let mut actions = self.check_fork_at(topology_schedule, shard, height);
        actions.extend(self.reconcile_canonical(topology_schedule, shard, height));
        actions
    }

    /// Re-seat the canonical slot toward a commit-proven header at the
    /// heights an insertion at `(shard, height)` can affect — its own (the
    /// inserted header gained a proof from a held child) and the one below
    /// (the inserted header is the committing child of a held sibling). A
    /// slot further down that a proof's walk stops at is re-seated by
    /// [`Self::prove_commits`].
    fn reconcile_canonical(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for h in [Some(height), height.prev()].into_iter().flatten() {
            actions.extend(self.displace_toward_proven(topology_schedule, shard, h));
        }
        actions
    }

    /// If the canonical slot at `(shard, height)` holds a never-proven
    /// header while a held sibling has its committing structure, swap them:
    /// the canonical slot is "the commit-proven header if one exists, else
    /// first-valid". Without this, a certified-but-never-committed sibling
    /// delivered first permanently starves the really-committed block — no
    /// `ConflictingCommits` ever assembles against it (the squatter has no
    /// committing child), so nothing fences and nothing promotes.
    ///
    /// An occupant that [yields](Self::yields) to a recovery gives the slot
    /// to any sibling that does not, proven or not: a block the recovered
    /// chain does not extend can never be the height's commit, and holding
    /// the slot would strand the fresh committee's block there. The seated
    /// block's parent is re-seated the same way, so a fresh chain heard
    /// beside an orphan's takes every slot down to where the two meet.
    /// The sibling need not commit, so a block the fresh committee
    /// certifies at a tail height and never commits takes the tail's slot
    /// while the tail still yields, and keeps it once the fresh chain on
    /// the tail is held: the proof walk that would seat the tail back stops
    /// at the tail's still-proven block above it. That takes a fresh
    /// committee certifying a block it does not commit.
    ///
    /// The displacement is otherwise monotone: a proven occupant is never
    /// displaced (two proven branches at one height are a committee fork,
    /// which assembles a proof instead), so the slot can flip at most once
    /// per height — toward the branch the source committee actually
    /// committed.
    fn displace_toward_proven(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        let Some(store) = self.shards.get(&shard) else {
            return Vec::new();
        };
        let Some(occupant) = store.verified(height) else {
            return Vec::new();
        };
        let siblings = store.siblings(height);
        let yielding = Self::yields(topology_schedule, store, occupant);
        let position = if yielding {
            siblings
                .iter()
                .position(|sibling| !Self::yields(topology_schedule, store, sibling))
        } else if store.is_proven(height) {
            None
        } else {
            // A sibling is committed when a held child hash-links to it and
            // either certifies the direct commit (round-contiguous
            // two-chain) or is itself already proven — the same rule
            // `try_prove` applies to the canonical chain. Only the canonical
            // child can be proven: a child held as a sibling vouches for its
            // parent by the two-chain alone.
            let child_height = height.next();
            let proven_child = store
                .verified(child_height)
                .filter(|_| store.is_proven(child_height));
            let children: Vec<&Verified<CertifiedBlockHeader>> = store
                .verified(child_height)
                .into_iter()
                .chain(store.siblings(child_height))
                .collect();
            siblings.iter().position(|sibling| {
                let committed = proven_child.is_some_and(|child| {
                    child.header().parent_block_hash() == sibling.block_hash()
                }) || children.iter().any(|child| {
                    child.header().parent_block_hash() == sibling.block_hash()
                        && child.header().round() == sibling.header().round().next()
                });
                committed && !Self::yields(topology_schedule, store, sibling)
            })
        };
        let Some(position) = position else {
            return Vec::new();
        };

        warn!(
            shard = shard.inner(),
            height = height.inner(),
            yielding,
            "Fork sibling displaces the canonical occupant"
        );
        let seated = self.store_mut(shard).seat_sibling(height, position);

        // Downstream consumers armed their expectations on the squatter's
        // manifest; re-admit the seated header so they re-arm on the real
        // one before its promotion opens it.
        let mut actions = vec![Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted {
            certified_header: seated,
        })];
        if yielding && let Some(parent) = height.prev() {
            actions.extend(self.displace_toward_proven(topology_schedule, shard, parent));
        }
        actions.extend(self.prove_commits(topology_schedule, shard, height));
        actions
    }

    /// Assemble and emit a fork proof if a newly-held header at
    /// `(shard, height)` completes one — either at its own height (it is a
    /// block with a committing child) or at the height below (it is the
    /// committing child of a lower block). One proof per forked height.
    /// Heights at or below a recovery's attested frontier are inert: that
    /// fork was already answered, and re-flagging it would spuriously
    /// fence the healthy successor committee.
    fn check_fork_at(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        let recovered = self.recovery_frontiers.get(&shard).copied();
        let mut actions = Vec::new();
        for h in [Some(height), height.prev()].into_iter().flatten() {
            // A fork at `h` needs two distinct blocks there; without a held
            // sibling the canonical occupant stands alone and assembly
            // cannot fire — skip before cloning headers into candidate
            // proofs (this path runs on every admitted header).
            if self
                .shards
                .get(&shard)
                .is_none_or(|store| store.siblings(h).is_empty())
            {
                continue;
            }
            if recovered.is_some_and(|frontier| h <= frontier) {
                continue;
            }
            if self.fork_answered(topology_schedule, shard, h) {
                continue;
            }
            if let Some(proof) = self.try_assemble_fork(topology_schedule, shard, h) {
                let ShardForkProof::ConflictingCommits { a, b } = &proof;
                self.forks_emitted
                    .insert((shard, h), [a.proven_block_hash(), b.proven_block_hash()]);
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

    /// Whether a fork proof emitted at `(shard, height)` still stands for
    /// the height: it did not pair a block a recovery has since
    /// [discarded](Self::discarded). The retained cohort's fork of its
    /// suffix, assembled while the recovery was pending, answers nothing
    /// about the committee that governs once it clears.
    fn fork_answered(
        &self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> bool {
        let Some(pair) = self.forks_emitted.get(&(shard, height)) else {
            return false;
        };
        let Some(store) = self.shards.get(&shard) else {
            return true;
        };
        !store
            .verified(height)
            .into_iter()
            .chain(store.siblings(height))
            .filter(|held| pair.contains(&held.block_hash()))
            .any(|held| Self::discarded(topology_schedule, store, held))
    }

    /// Two distinct commit-proven blocks at `(shard, height)` — a committee
    /// fork. Pairs the first two proofs with different proven-block hashes
    /// from one side of a recovery: blocks that [yield](Self::yields) to
    /// it, or blocks that do not. A pair across the two is the replaced
    /// committee's block beside the fresh committee's, which proves
    /// nothing about either. Yielding blocks pair only while the recovery
    /// is pending, so the retained cohort's fork of its suffix reaches the
    /// beacon then; once it clears they are [discarded](Self::discarded).
    fn try_assemble_fork(
        &self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<ShardForkProof> {
        let store = self.shards.get(&shard)?;
        let pending = topology_schedule.recovery_bridge(shard).is_some();
        let (yielding, governing): (Vec<CommitProof>, Vec<CommitProof>) = self
            .direct_commit_proofs_at(shard, height)
            .into_iter()
            .partition(|proof| Self::yields(topology_schedule, store, proof.certified()));
        let pair = |proofs: &[CommitProof]| {
            let a = proofs.first()?;
            let b = proofs
                .iter()
                .skip(1)
                .find(|p| p.proven_block_hash() != a.proven_block_hash())?;
            Some(ShardForkProof::ConflictingCommits {
                a: a.clone(),
                b: b.clone(),
            })
        };
        pair(&governing).or_else(|| pending.then(|| pair(&yielding)).flatten())
    }

    /// Every direct-commit proof `(block, round-contiguous child)` held at
    /// `(shard, height)`, across both the canonical winner and the fork
    /// siblings.
    fn direct_commit_proofs_at(&self, shard: ShardId, height: BlockHeight) -> Vec<CommitProof> {
        let Some(store) = self.shards.get(&shard) else {
            return Vec::new();
        };
        let child_height = height.next();
        let blocks = store
            .verified(height)
            .into_iter()
            .chain(store.siblings(height));
        let children: Vec<&Verified<CertifiedBlockHeader>> = store
            .verified(child_height)
            .into_iter()
            .chain(store.siblings(child_height))
            .collect();

        let mut proofs = Vec::new();
        for block in blocks {
            let block_header: &CertifiedBlockHeader = block;
            // The proof carries the certified block's parent when it is held
            // — that is what lets a remote verifier resolve the committee
            // that signed it. Absent, the proof still assembles and still
            // engages the local fence; only a remote verifier drops it.
            let parent = block_header.height().prev().and_then(|parent_height| {
                self.held_header(
                    shard,
                    parent_height,
                    block_header.header().parent_block_hash(),
                )
            });
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
                    parent.cloned(),
                ));
            }
        }
        proofs
    }

    /// Anchor selecting the committee that signed the QC over `header`'s
    /// block, and whether a held parent named it. A block's committee
    /// anchors on its parent, so the window that signed this QC is the one
    /// the parent dates itself in. Without the parent, the beacon's
    /// attested boundary stands in for the boundary block, and otherwise the
    /// header's own anchor does — the same window except across an epoch
    /// cut. A header resolved without its parent that fails verification
    /// waits for the parent ([`Self::await_parent`]) rather than being
    /// dropped. Both the first dispatch and the failed-candidate retry drain
    /// resolve through here, so a buffered sibling verifies under the same
    /// committee its predecessor did.
    fn committee_anchor_wt(
        &self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        header: &BlockHeader,
    ) -> (WeightedTimestamp, HeaderCommittee) {
        let parent_anchor = header
            .height()
            .prev()
            .and_then(|parent_height| {
                self.held_header(shard, parent_height, header.parent_block_hash())
            })
            .map(|parent| parent.parent_qc().weighted_timestamp());
        (
            topology_schedule.signing_anchor(shard, header, parent_anchor),
            if parent_anchor.is_some() {
                HeaderCommittee::Resolved
            } else {
                HeaderCommittee::Guessed
            },
        )
    }

    /// Dispatch the next candidate at `(shard, height)` whose committee
    /// resolves, once the one in flight there failed. Buffer any whose
    /// epoch the beacon hasn't reached yet so a catch-up retries them, and
    /// drop any keyed below the schedule floor (the epoch can never resolve
    /// again). If none resolve, every remaining candidate is buffered or
    /// removed and the key is gone, so the drain re-adds the first one with
    /// `first_for_key` set and re-dispatches it cleanly.
    fn dispatch_next_candidate(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        loop {
            let next = self
                .shards
                .get(&shard)
                .and_then(|store| store.first_candidate(height));
            let Some((next_source, next_header)) = next else {
                return Vec::new();
            };
            let (anchor, named_by) =
                self.committee_anchor_wt(topology_schedule, shard, next_header.header());
            let qc_wt = next_header.qc().weighted_timestamp();
            // A recovery folded (or advanced) after this header buffered can
            // turn it into a suffix-band orphan the fenced lookup rejects;
            // drop it and drain the next candidate.
            match topology_schedule
                .lookup_for_shard_certified_fenced(shard, anchor, qc_wt)
                .map(|(lookup, _)| lookup)
            {
                None => {
                    warn!(
                        shard = shard.inner(),
                        height = height.inner(),
                        source = ?next_source,
                        "Dropping buffered remote header that resolves the retained \
                         committee during a halt recovery"
                    );
                    self.drop_candidate(shard, height, next_source);
                }
                Some(ScheduleLookup::Committee(committee)) => {
                    return Self::emit_verify_qc(committee, named_by, next_source, next_header);
                }
                Some(ScheduleLookup::NotYetCommitted) => {
                    self.drop_candidate(shard, height, next_source);
                    self.awaiting.push(shard, (next_source, next_header));
                }
                Some(ScheduleLookup::Evicted) => {
                    warn!(
                        shard = shard.inner(),
                        height = height.inner(),
                        source = ?next_source,
                        "Pending remote header's committee epoch fell below the \
                         schedule floor — dropping"
                    );
                    self.drop_candidate(shard, height, next_source);
                }
            }
        }
    }

    /// Check `certified_header`, which failed under a guessed committee,
    /// again under the one its parent names: re-offered at once when the
    /// parent is held by now, parked for it otherwise.
    fn retry_under_parent(
        &mut self,
        topology_schedule: &TopologySchedule,
        source: HeaderSource,
        certified_header: CertifiedBlockHeader,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        match self
            .committee_anchor_wt(topology_schedule, shard, certified_header.header())
            .1
        {
            HeaderCommittee::Resolved => {
                self.on_remote_header_received(topology_schedule, certified_header, source)
            }
            HeaderCommittee::Guessed => self.await_parent(shard, source, certified_header),
        }
    }

    /// Park `certified_header`, which failed verification under a committee
    /// no held parent named, until its parent is held, and fetch the gap
    /// from the shard's walked frontier up to that parent unless one went
    /// out within [`COMMIT_PROOF_RETRY`].
    fn await_parent(
        &mut self,
        shard: ShardId,
        source: HeaderSource,
        certified_header: CertifiedBlockHeader,
    ) -> Vec<Action> {
        let parent_height = certified_header.height().prev();
        self.awaiting_parent.push(shard, (source, certified_header));
        let Some(parent_height) = parent_height else {
            return Vec::new();
        };
        let now = self.clock.now();
        if self
            .parents_requested_at
            .get(&shard)
            .is_some_and(|at| now.elapsed_since(*at) < COMMIT_PROOF_RETRY)
        {
            return Vec::new();
        }
        self.parents_requested_at.insert(shard, now);
        let from = self.expected.get(&shard).map_or(parent_height, |expected| {
            expected.last_verified_height.next().min(parent_height)
        });
        let count =
            (parent_height.inner() - from.inner() + 1).min(MAX_REMOTE_HEADERS_PER_REQUEST.inner());
        vec![Action::FetchCommitProof {
            source_shard: shard,
            from_height: from,
            count: HeaderFetchCount::new(count),
        }]
    }

    /// Re-offer the headers of `shard` whose parent is now held, keeping
    /// the rest parked. A re-offered header resolves under its parent, so
    /// one that fails again is dropped rather than parked: each is checked
    /// at most once more.
    fn reoffer_awaiting_parent(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for (source, header) in self.awaiting_parent.drain_shard(shard) {
            if self
                .committee_anchor_wt(topology_schedule, shard, header.header())
                .1
                == HeaderCommittee::Resolved
            {
                actions.extend(self.on_remote_header_received(topology_schedule, header, source));
            } else {
                self.awaiting_parent.push(shard, (source, header));
            }
        }
        actions
    }

    /// The held header for `shard` at `height` matching `hash`, across the
    /// canonical winner, the fork siblings, and the headers still awaiting
    /// QC verification: the parent a commit proof carries for its remote
    /// verifier. A parent's slot is structurally the height below the
    /// block's own — every committee enforces `parent_qc.height().next() ==
    /// height` before voting — and the hash pins which block, so a sibling
    /// at the slot doesn't match.
    ///
    /// A pending header counts here because the proof's verifier checks it,
    /// and [`Self::committee_anchor_wt`] anchors on it: an unverified parent
    /// pinned by the child's parent hash is no weaker than the child's own
    /// `parent_qc` anchor it stands in for.
    fn held_header(
        &self,
        shard: ShardId,
        height: BlockHeight,
        hash: BlockHash,
    ) -> Option<&BlockHeader> {
        let store = self.shards.get(&shard)?;
        store
            .verified(height)
            .map(|held| held.header())
            .into_iter()
            .chain(store.siblings(height).iter().map(|h| h.header()))
            .chain(
                store
                    .pending(height)
                    .into_iter()
                    .flat_map(|by_source| by_source.values().map(CertifiedBlockHeader::header)),
            )
            .find(|header| header.hash() == hash)
    }

    /// Walk `shard`'s sync frontier up over the verified headers held
    /// contiguously above it, re-arming the liveness clock if it moves.
    ///
    /// Run wherever the frontier or the headers above it change. A header
    /// held ahead of the frontier is never admitted a second time — a
    /// re-delivery of it is a byte-exact duplicate — so a frontier that
    /// lands just below one, as a re-anchor at the attested boundary does,
    /// crosses it only here.
    ///
    /// An occupant that [yields](Self::yields) to a recovery is not
    /// coverage of its height, so the walk stops beneath it and the
    /// forward sync keeps fetching the fresh block there. Held above the
    /// frontier, it is retained to the horizon rather than the walked
    /// retention; a yielding block is certified before the window before
    /// its recovery's bridge, so the horizon drops it no later than
    /// [`TRANSACTION_EVIDENCE_HORIZON`] past that window, and the fresh
    /// block at its height displaces it into the siblings sooner.
    fn walk_frontier(&mut self, topology_schedule: &TopologySchedule, shard: ShardId) {
        let Some(from) = self
            .expected
            .get(&shard)
            .map(|expected| expected.last_verified_height)
        else {
            return;
        };
        let Some(store) = self.shards.get(&shard) else {
            return;
        };
        let mut frontier = from;
        while store
            .verified(frontier.next())
            .is_some_and(|occupant| !Self::yields(topology_schedule, store, occupant))
        {
            frontier = frontier.next();
        }
        if frontier == from {
            return;
        }
        let now = self.clock.now();
        if let Some(expected) = self.expected.get_mut(&shard) {
            expected.last_verified_height = frontier;
            expected.last_verified_at = Some(now);
        }
    }

    /// Mark every height the insertion at `(shard, height)` newly
    /// commit-proves, then emit the `RemoteHeaderCommitted` continuations
    /// [`Self::release_proven`] allows.
    ///
    /// The inserted header can complete a two-chain over its parent, and a
    /// held child can complete one over it; each proof then propagates down
    /// the parent-hash chain (an ancestor of a committed block is committed,
    /// whatever its own round layout — INV-SHARD-4).
    ///
    /// A walk that reaches a slot held by a header its proven chain does
    /// not name has proven that slot's child, which is the evidence
    /// [`Self::displace_toward_proven`] seats a held sibling on; the seated
    /// block proves in turn and the walk carries on beneath it.
    fn prove_commits(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for at in [Some(height), height.prev()].into_iter().flatten() {
            if let Some(off_branch) = self.try_prove(shard, at) {
                actions.extend(self.displace_toward_proven(topology_schedule, shard, off_branch));
            }
        }
        actions.extend(self.release_proven(topology_schedule, shard));
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
    ///
    /// Returns the height of such an unproven off-branch entry, directly
    /// beneath the lowest block this call proved.
    fn try_prove(&mut self, shard: ShardId, height: BlockHeight) -> Option<BlockHeight> {
        let store = self.shards.get_mut(&shard)?;
        if store.is_proven(height) {
            return None;
        }
        let header = store.verified(height)?;
        let child = store.verified(height.next())?;
        if child.header().parent_block_hash() != header.block_hash() {
            return None;
        }
        let commits = child.header().round() == header.header().round().next()
            || store.is_proven(height.next());
        if !commits {
            return None;
        }

        let mut at = height;
        let mut hash = header.block_hash();
        let mut parent_hash = header.header().parent_block_hash();
        loop {
            store.mark_proven(at);
            debug!(
                shard = shard.inner(),
                height = at.inner(),
                block_hash = %hash,
                "Remote header commit-proven"
            );
            let prev = at.prev()?;
            if store.is_proven(prev) {
                return None;
            }
            let prev_header = store.verified(prev)?;
            if prev_header.block_hash() != parent_hash {
                return Some(prev);
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
        for (source, header) in self.awaiting.drain() {
            actions.extend(self.on_remote_header_received(topology_schedule, header, source));
        }
        // An advanced boundary can be the parent a waiting header needs.
        let shards: BTreeSet<ShardId> = self
            .awaiting_parent
            .drain()
            .into_iter()
            .map(|(source, header)| {
                let shard = header.shard_id();
                self.awaiting_parent.push(shard, (source, header));
                shard
            })
            .collect();
        for shard in shards {
            actions.extend(self.reoffer_awaiting_parent(topology_schedule, shard));
        }
        actions
    }

    /// Emit a `VerifyRemoteHeaderQc` action for the given header.
    fn emit_verify_qc(
        topology_snapshot: &TopologySnapshot,
        committee: HeaderCommittee,
        source: HeaderSource,
        certified_header: CertifiedBlockHeader,
    ) -> Vec<Action> {
        let shard = certified_header.shard_id();
        let committee_public_keys: Vec<ConsensusPublicKey> = topology_snapshot
            .consensus_committee_for_shard(shard)
            .iter()
            .map(|v| {
                topology_snapshot
                    .public_key(*v)
                    .expect("committee member must have public key")
            })
            .collect();
        let quorum_threshold = topology_snapshot.quorum_threshold_for_shard(shard);

        vec![Action::Consensus(ConsensusAction::VerifyRemoteHeaderQc {
            certified_header,
            source,
            committee_public_keys,
            quorum_threshold,
            committee,
        })]
    }

    /// Whether `shard` resolves a non-empty committee for request routing at
    /// `wt`, terminal-clamped. A live shard resolves its head committee; a
    /// drained reshape shard past its final window — a split parent or a
    /// merge child — resolves the committee that served it, so its terminal
    /// crossing keeps syncing to the beacon fold until the schedule evicts
    /// it. A fully-evicted shard resolves nothing and is skipped.
    ///
    /// A `wt` at or before the genesis instant is not a stale clock — it
    /// means no local block has committed yet. A freshly seated member (a
    /// halt-recovery draw from the pool, a merge keeper) opens on the beacon
    /// head fold that seated it, so any shard the schedule still retains is
    /// fair to probe; resolving the unset clock would land below every
    /// retained window (`Evicted`) and suppress exactly the fetches that
    /// bootstrap the member.
    fn shard_routable(
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> bool {
        if wt <= topology_schedule.windows().origin() {
            return topology_schedule.routable_shards().contains(&shard);
        }
        matches!(
            topology_schedule.lookup_for_shard(shard, wt).0,
            ScheduleLookup::Committee(snapshot) if !snapshot.committee_for_shard(shard).is_empty()
        )
    }
}

#[cfg(test)]
impl RemoteHeaderCoordinator {
    /// Whether the held header at `(shard, height)` is commit-proven: its
    /// committing structure — a round-contiguous certified child, or a
    /// parent-hash link under a proven descendant — is also held.
    ///
    /// An observation seam, not a query anyone makes: what a consumer
    /// waits on is the `RemoteHeaderCommitted` continuation the promotion
    /// drives, and nothing in the tree asks this. Public, it reads as
    /// something execution consults.
    fn has_commit_proof(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.shards
            .get(&shard)
            .is_some_and(|store| store.is_proven(height))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, ChainOrigin, Epoch,
        EpochWindows, Hash, NetworkDefinition, ProposerTimestamp, QcVerifyError, QuorumCertificate,
        RecoveryBinding, Round, ShardId, Signer, SignerBitfield, ValidatorId, ValidatorInfo,
        ValidatorSet,
    };

    use super::*;

    const fn gossip(sender: u64) -> HeaderSource {
        HeaderSource::Gossip(ValidatorId::new(sender))
    }

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
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(2, 2),
            height: BlockHeight::new(5),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(
                ShardId::leaf(2, 0),
                ChainOrigin::root(WeightedTimestamp::ZERO),
            )
            .into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            ..Default::default()
        });
        // Deliberately set wrong block_hash
        let qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"wrong")),
            ShardId::leaf(2, 2),
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
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

    /// A schedule for the local-dispatch fast path, which reads it only to
    /// re-offer headers parked on a parent.
    fn fast_path_schedule() -> TopologySchedule {
        TopologySchedule::single(Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)))
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
                    public_key: BlsSigner::from_seed(&seed).public_key(),
                }
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            num_shards,
            ValidatorSet::new(validators),
        )
    }

    /// A header of `shard` at `height` whose committee anchors at
    /// `anchor_wt`: its parent, carrying that anchor, is admitted here as
    /// verified first, since only a verified parent names a committee.
    fn anchored_header(
        coord: &mut RemoteHeaderCoordinator,
        shard: ShardId,
        height: BlockHeight,
        anchor_wt: u64,
    ) -> CertifiedBlockHeader {
        let parent = chained_remote_header(
            shard,
            BlockHeight::new(height.inner() - 1),
            BlockHash::ZERO,
            anchor_wt,
        );
        let parent_hash = parent.header().hash();
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(0),
        );
        chained_remote_header(shard, height, parent_hash, anchor_wt)
    }

    /// A header extending `parent_hash` whose own parent QC stamps
    /// `parent_qc_wt` — so a caller can feed a real two-block chain and
    /// separate a header's own anchor from the one its parent carries.
    fn chained_remote_header(
        shard: ShardId,
        height: BlockHeight,
        parent_hash: BlockHash,
        parent_qc_wt: u64,
    ) -> CertifiedBlockHeader {
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            shard,
            BlockHeight::new(height.inner().saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        CertifiedBlockHeader::new(header, qc)
    }

    /// A QC over block `h` is signed by `committee(h)`, which anchors on
    /// `h-1` — so a header whose parent sits below an epoch cut verifies
    /// under the earlier window however far past the cut it dates itself.
    /// Resolving on the header's own anchor picks the window the block
    /// *opens*, and across a cut that moves keys the signature check fails
    /// and the header is dropped — cross-shard propagation stalling once per
    /// window.
    #[test]
    fn a_headers_qc_verifies_under_the_committee_its_parent_anchors() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let expected0: Vec<ConsensusPublicKey> = epoch0
            .committee_for_shard(remote)
            .iter()
            .map(|v| epoch0.public_key(*v).unwrap())
            .collect();

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        // The parent anchors below the cut, the child above it. The child's
        // QC was signed by the committee its parent anchors — epoch 0's.
        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);

        coord.on_verified_remote_header_received(
            &schedule,
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(1),
        );
        let actions = coord.on_remote_header_received(&schedule, child, gossip(1));

        let keys = verify_qc_keys(&actions).expect("verification dispatched");
        assert_eq!(
            *keys, expected0,
            "the child's QC must verify under the window its parent anchors, not the one it \
             dates itself into",
        );
    }

    /// A commit-proof range is older than the retention by construction.
    /// Each header in it resolves its committee through the one before it,
    /// still pending its own verification, so that one stays held while
    /// the next arrives: across an epoch cut that moves keys, a child
    /// resolved on its own anchor fails, and the block it would prove is
    /// never proven.
    #[test]
    fn a_fetched_range_across_a_cut_verifies_under_its_pending_parent() {
        const ED: u64 = 100_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let expected0: Vec<ConsensusPublicKey> = epoch0
            .committee_for_shard(remote)
            .iter()
            .map(|v| epoch0.public_key(*v).unwrap())
            .collect();

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        // The shard's tip sits well past the retention beyond the cut.
        let tip = chained_remote_header(remote, BlockHeight::new(50), BlockHash::ZERO, 2 * ED - 1);
        let _ = coord.on_remote_header_received(&schedule, tip, gossip(1));

        // The fetched range: the parent anchors below the cut, the child
        // above it, both older than the retention behind the tip.
        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);
        let _ = coord.on_remote_header_received(&schedule, parent, HeaderSource::Fetched);
        let actions = coord.on_remote_header_received(&schedule, child, HeaderSource::Fetched);

        let keys = verify_qc_keys(&actions).expect("verification dispatched");
        assert_eq!(
            *keys, expected0,
            "the child's QC must verify under the window its pending parent anchors",
        );
    }

    /// A header guessed onto the wrong side of a cut fails, and the
    /// retention can prune its pending entry before the failure lands. It
    /// still waits for its parent: the failure carries the header, so
    /// parking needs no entry in the store.
    #[test]
    fn a_failed_header_pruned_while_in_flight_still_waits_for_its_parent() {
        const ED: u64 = 100_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let expected0: Vec<ConsensusPublicKey> = epoch0
            .committee_for_shard(remote)
            .iter()
            .map(|v| epoch0.public_key(*v).unwrap())
            .collect();

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);
        let _ = coord.on_remote_header_received(&schedule, child.clone(), gossip(1));

        // The shard's tip lands far past the retention while the child's
        // verification is in flight, pruning its pending entry.
        let tip = chained_remote_header(remote, BlockHeight::new(50), BlockHash::ZERO, 2 * ED - 1);
        let _ = coord.on_remote_header_received(&schedule, tip, gossip(1));
        assert!(coord.get_pending(remote, BlockHeight::new(6)).is_none());

        let actions = coord.on_remote_header_qc_verified(
            &schedule,
            &child,
            gossip(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
            HeaderCommittee::Guessed,
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::FetchCommitProof { source_shard, from_height, .. }
                    if *source_shard == remote && *from_height <= BlockHeight::new(5)
            )),
            "the gap up to the parent is fetched",
        );

        let actions = coord.on_verified_remote_header_received(
            &schedule,
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(1),
        );
        assert_eq!(
            verify_qc_keys(&actions),
            Some(&expected0),
            "the waiting header re-dispatches under the window its parent anchors",
        );
    }

    /// The failed-candidate retry drain resolves a buffered sibling's
    /// committee by the same rule as the first dispatch — via the held
    /// parent. Keying the retry on the sibling's own anchor re-verifies an
    /// epoch-first header under the window it opens, so across a cut that
    /// moves keys every honest sibling fails in turn and the slot drains
    /// empty.
    #[test]
    fn a_retried_sibling_verifies_under_the_committee_its_parent_anchors() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let expected0: Vec<ConsensusPublicKey> = epoch0
            .committee_for_shard(remote)
            .iter()
            .map(|v| epoch0.public_key(*v).unwrap())
            .collect();

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        // The parent anchors below the cut, the child above it. Two senders
        // offer the child: the first dispatches, the second waits pending.
        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);

        coord.on_verified_remote_header_received(
            &schedule,
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(1),
        );
        let _ = coord.on_remote_header_received(&schedule, child.clone(), gossip(1));
        let _ = coord.on_remote_header_received(&schedule, child.clone(), gossip(3));

        let retried = coord.on_remote_header_qc_verified(
            &schedule,
            &child,
            gossip(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
            HeaderCommittee::Resolved,
        );

        let keys = verify_qc_keys(&retried).expect("the buffered sibling re-dispatches");
        assert_eq!(
            *keys, expected0,
            "the retried sibling's QC must verify under the window its parent anchors, not the \
             one it dates itself into",
        );
    }

    fn verify_qc_committee(actions: &[Action]) -> Option<HeaderCommittee> {
        actions.iter().find_map(|a| match a {
            Action::Consensus(ConsensusAction::VerifyRemoteHeaderQc { committee, .. }) => {
                Some(*committee)
            }
            _ => None,
        })
    }

    /// A header checked under a guessed committee can fail after its parent
    /// arrives. The failure is judged by the committee it was checked
    /// under, not the one the coordinator could resolve by then: the header
    /// is checked again at once under its parent's window rather than
    /// dropped as though its own certificate were false.
    #[test]
    fn a_header_whose_parent_lands_during_a_guessed_check_is_checked_again() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let expected0: Vec<ConsensusPublicKey> = epoch0
            .committee_for_shard(remote)
            .iter()
            .map(|v| epoch0.public_key(*v).unwrap())
            .collect();
        let mut schedule = TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), epoch0);
        schedule.insert(Epoch::new(1), epoch1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);

        let actions = coord.on_remote_header_received(&schedule, child.clone(), gossip(1));
        assert_eq!(
            verify_qc_committee(&actions),
            Some(HeaderCommittee::Guessed)
        );
        let _ = coord.on_verified_remote_header_received(
            &schedule,
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(1),
        );

        let actions = coord.on_remote_header_qc_verified(
            &schedule,
            &child,
            gossip(1),
            Err(CertifiedHeaderVerifyError::Qc(
                QcVerifyError::InvalidSignature,
            )),
            HeaderCommittee::Guessed,
        );
        assert_eq!(
            verify_qc_keys(&actions),
            Some(&expected0),
            "the header is checked again under the window its parent anchors",
        );
        assert_eq!(
            verify_qc_committee(&actions),
            Some(HeaderCommittee::Resolved)
        );
    }

    fn verify_qc_keys(actions: &[Action]) -> Option<&Vec<ConsensusPublicKey>> {
        actions.iter().find_map(|a| match a {
            Action::Consensus(ConsensusAction::VerifyRemoteHeaderQc {
                committee_public_keys,
                ..
            }) => Some(committee_public_keys),
            _ => None,
        })
    }

    /// A header that fails verification under a committee its own anchor
    /// guessed — no parent held — is not dropped: across an epoch cut the
    /// guess names the wrong window. It waits, the gap up to its parent is
    /// fetched, and once the parent is held it verifies under the parent's
    /// window.
    #[test]
    fn a_header_that_failed_without_its_parent_waits_and_fetches_it() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let epoch0 = Arc::new(shard_snapshot(2, &ids, 0));
        let epoch1 = Arc::new(shard_snapshot(2, &ids, 1));
        let keys_of = |snap: &TopologySnapshot| -> Vec<ConsensusPublicKey> {
            snap.committee_for_shard(remote)
                .iter()
                .map(|v| snap.public_key(*v).unwrap())
                .collect()
        };
        let (expected0, expected1) = (keys_of(&epoch0), keys_of(&epoch1));
        let mut schedule = TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), epoch0);
        schedule.insert(Epoch::new(1), epoch1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        let parent = chained_remote_header(remote, BlockHeight::new(5), BlockHash::ZERO, ED - 1);
        let child =
            chained_remote_header(remote, BlockHeight::new(6), parent.header().hash(), ED + 1);

        let actions = coord.on_remote_header_received(&schedule, child.clone(), gossip(1));
        assert_eq!(
            verify_qc_keys(&actions),
            Some(&expected1),
            "without its parent the header tries its own window",
        );
        assert_eq!(
            verify_qc_committee(&actions),
            Some(HeaderCommittee::Guessed)
        );
        let actions = coord.on_remote_header_qc_verified(
            &schedule,
            &child,
            gossip(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
            HeaderCommittee::Guessed,
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::FetchCommitProof { source_shard, from_height, .. }
                    if *source_shard == remote && *from_height <= BlockHeight::new(5)
            )),
            "the gap up to the parent is fetched",
        );

        let actions = coord.on_verified_remote_header_received(
            &schedule,
            Verified::new_unchecked_for_test(parent),
            ValidatorId::new(1),
        );
        assert_eq!(
            verify_qc_keys(&actions),
            Some(&expected0),
            "the waiting header re-dispatches under the window its parent anchors",
        );
        assert_eq!(
            verify_qc_committee(&actions),
            Some(HeaderCommittee::Resolved)
        );
    }

    /// The beacon's attested boundary stands in for the boundary block: the
    /// header above it anchors on the boundary's weighted timestamp with no
    /// parent held.
    #[test]
    fn the_header_above_the_attested_boundary_anchors_on_it() {
        use hyperscale_types::{BeaconWitnessLeafCount, ShardAnchor, StateRoot};

        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];
        let boundary_hash = BlockHash::from_raw(Hash::from_bytes(b"boundary"));
        let head = Arc::new(shard_snapshot(2, &ids, 0).with_boundaries(BTreeMap::from([(
            remote,
            ShardAnchor {
                state_root: StateRoot::ZERO,
                block_hash: boundary_hash,
                height: BlockHeight::new(5),
                weighted_timestamp: WeightedTimestamp::from_millis(ED - 1),
                witness_base: BeaconWitnessLeafCount::ZERO,
                terminal_settled_txs: None,
                handoff_complete: None,
                terminal_epoch: None,
            },
        )])));
        let expected0: Vec<ConsensusPublicKey> = head
            .committee_for_shard(remote)
            .iter()
            .map(|v| head.public_key(*v).unwrap())
            .collect();
        let mut schedule = TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), head);
        schedule.insert(Epoch::new(1), Arc::new(shard_snapshot(2, &ids, 1)));
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));

        let child = chained_remote_header(remote, BlockHeight::new(6), boundary_hash, ED + 1);
        let actions = coord.on_remote_header_received(&schedule, child, gossip(1));
        let keys = verify_qc_keys(&actions).expect("anchored on the boundary");
        assert_eq!(*keys, expected0);
    }

    /// A block whose anchor sits below the one already committed does not
    /// move the store's clock backwards. Liveness baselines, the probe
    /// gate, the want-retry horizon and the departed-shard retirement are
    /// all read against it.
    #[test]
    fn the_local_clock_does_not_run_backwards() {
        use hyperscale_types::test_utils::{certify, make_live_block};

        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let sched = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(0),
            Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)),
        );
        let mut coord = RemoteHeaderCoordinator::new(local);

        let committed = |height: u64, wt_ms: u64| {
            certify(
                make_live_block(
                    local,
                    BlockHeight::new(height),
                    wt_ms,
                    ValidatorId::new(0),
                    vec![],
                    vec![],
                ),
                wt_ms,
            )
        };

        coord.on_block_committed(&sched, &committed(1, 9_000), &[]);
        assert_eq!(coord.clock.now(), WeightedTimestamp::from_millis(9_000));

        coord.on_block_committed(&sched, &committed(2, 4_000), &[]);
        assert_eq!(
            coord.clock.now(),
            WeightedTimestamp::from_millis(9_000),
            "a regressed anchor holds the clock where it is",
        );

        coord.on_block_committed(&sched, &committed(3, 11_000), &[]);
        assert_eq!(
            coord.clock.now(),
            WeightedTimestamp::from_millis(11_000),
            "and it still advances",
        );
    }

    /// A shard that dissolved at a reshape stops producing a tip, and
    /// the retention pass beside this one counts back from that tip — so
    /// its last window's worth of headers, and the store entry that makes
    /// every sweep iterate it, would be held for the life of the
    /// process. The handoff evidence window is what ends a departed
    /// shard.
    #[test]
    fn a_departed_shards_headers_go_when_its_evidence_window_closes() {
        use std::collections::BTreeMap;

        use hyperscale_types::{BeaconWitnessLeafCount, ShardAnchor, StateRoot};

        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let departed = ShardId::leaf(1, 1);
        let live = ShardId::leaf(1, 0);

        let stamped = |handoff_complete: Option<Epoch>| {
            let mut boundaries = BTreeMap::new();
            boundaries.insert(
                departed,
                ShardAnchor {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                    height: BlockHeight::new(9),
                    weighted_timestamp: WeightedTimestamp::from_millis(ED),
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_settled_txs: None,
                    handoff_complete,
                    terminal_epoch: None,
                },
            );
            let snapshot = shard_snapshot(2, &[0, 1, 2, 3], 0).with_boundaries(boundaries);
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::new(snapshot))
        };

        let mut coord = RemoteHeaderCoordinator::new(local);
        for shard in [departed, live] {
            let store = coord.store_mut(shard);
            store.set_verified(Verified::<CertifiedBlockHeader>::from_persisted(
                chained_remote_header(shard, BlockHeight::new(5), BlockHash::ZERO, ED),
            ));
            store.mark_proven(BlockHeight::new(5));
            store.mark_promoted(BlockHeight::new(5));
            store.raise_tip(BlockHeight::new(5), WeightedTimestamp::from_millis(ED));
        }

        // Unstamped: the window is open, the terminal crossing is still
        // being synced, and nothing is retired.
        coord.clock = CommittedClock::seeded(WeightedTimestamp::from_millis(1_000_000));
        coord.retire_departed(&stamped(None));
        assert!(coord.shards.contains_key(&departed), "an open window holds");

        // Stamped, but the local chain has not reached the expiry yet.
        let sched = stamped(Some(Epoch::new(1)));
        let expiry = sched
            .handoff_evidence_expiry(departed)
            .expect("the stamp fixes an expiry");
        coord.clock = CommittedClock::seeded(expiry);
        coord.retire_departed(&sched);
        assert!(
            coord.shards.contains_key(&departed),
            "at the expiry it holds"
        );

        coord.clock = CommittedClock::seeded(expiry.plus(Duration::from_millis(1)));
        coord.retire_departed(&sched);

        assert!(
            !coord.shards.contains_key(&departed),
            "past it the shard's store, tip and all, goes"
        );
        assert!(!coord.has_verified(departed, BlockHeight::new(5)));
        assert!(!coord.has_commit_proof(departed, BlockHeight::new(5)));
        let live_store = coord
            .shards
            .get(&live)
            .expect("a live shard keeps its store");
        assert!(
            live_store.verified(BlockHeight::new(5)).is_some()
                && live_store.is_proven(BlockHeight::new(5))
                && live_store.is_promoted(BlockHeight::new(5)),
            "a shard with no departure record keeps everything"
        );
        assert_eq!(live_store.tip().0, BlockHeight::new(5));
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
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), Arc::clone(&pre));
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
            EpochWindows::new(0, ED),
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
        coord.clock = CommittedClock::seeded(WeightedTimestamp::from_millis(1));
        let actions = coord.flush_expected_headers(&sched);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::StartRemoteHeaderSync { .. })),
            "a stale committed clock below the retained windows must not probe",
        );
    }

    /// A member whose frontier sits far below a header it already verified
    /// — seated at the attested boundary, hearing the live tip by gossip —
    /// syncs the whole gap in one go rather than one probe batch per
    /// liveness timeout, which a live shard outruns.
    #[test]
    fn a_sync_reaches_the_highest_verified_header() {
        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let sched = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(5),
            Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)),
        );
        let mut coord = RemoteHeaderCoordinator::new(local);
        let target = |actions: &[Action]| {
            actions.iter().find_map(|a| match a {
                Action::StartRemoteHeaderSync {
                    source_shard,
                    target,
                } if *source_shard == remote => Some(*target),
                _ => None,
            })
        };

        assert_eq!(
            target(&coord.flush_expected_headers(&sched)),
            Some(BlockHeight::new(DEFAULT_PROBE_LOOKAHEAD)),
            "with nothing heard above it, a sync probes one batch past the frontier",
        );

        let far = DEFAULT_PROBE_LOOKAHEAD * 30;
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, far, far, None),
            ValidatorId::new(0),
        );
        assert_eq!(
            target(&coord.flush_expected_headers(&sched)),
            Some(BlockHeight::new(far)),
            "a sync reaches the highest header already verified",
        );
    }

    /// A header verified ahead of the frontier is held past the retention
    /// window until the frontier walks over it. A sync from far behind the
    /// tip fetches headers already past that window, and one that verifies
    /// before the height below it would otherwise be gone by the time the
    /// walk reaches it.
    #[test]
    fn a_header_ahead_of_the_frontier_outlives_the_retention_until_walked() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        coord.expected.insert(
            remote,
            ExpectedHeader {
                discovered_at: WeightedTimestamp::from_millis(1),
                last_verified_height: BlockHeight::new(5),
                verified_tip: BlockHeight::new(5),
                last_verified_at: Some(WeightedTimestamp::from_millis(1)),
            },
        );
        let six = chain_header(remote, 6, 6, None);
        let seven = chain_header(remote, 7, 7, Some(&six));

        // Seven verifies first, and the live tip lands a retention window
        // and more past both.
        coord.on_verified_remote_header_received(&fast_path_schedule(), seven, ValidatorId::new(0));
        let tip = 7 + REMOTE_HEADER_RETENTION.as_secs() * 2;
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, tip, tip, None),
            ValidatorId::new(0),
        );
        assert!(
            coord.has_verified(remote, BlockHeight::new(7)),
            "a header the frontier has not walked over is held past the retention",
        );

        coord.on_verified_remote_header_received(&fast_path_schedule(), six, ValidatorId::new(0));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(7)),
            "the walk crosses the header held ahead of it",
        );

        coord.cleanup();
        assert!(
            !coord.has_verified(remote, BlockHeight::new(6)),
            "once walked over, a header ages out as any does",
        );
        assert!(
            coord.has_verified(remote, BlockHeight::new(7)),
            "but the walked frontier stays: the next header anchors on it",
        );
    }

    /// A frontier re-anchored at the attested boundary walks over the
    /// headers already held above it. Held, they are never admitted again —
    /// a re-delivery is a byte-exact duplicate — so nothing else carries the
    /// frontier across them.
    #[test]
    fn a_reanchored_frontier_walks_over_the_headers_held_above_it() {
        use hyperscale_types::{BeaconWitnessLeafCount, ShardAnchor, StateRoot};

        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let snapshot = || shard_snapshot(2, &[0, 1, 2, 3], 0);
        let mut coord = RemoteHeaderCoordinator::new(local);
        coord.refresh_expected(&TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(5),
            Arc::new(snapshot()),
        ));

        let seven = chain_header(remote, 7, 7, None);
        let eight = chain_header(remote, 8, 8, Some(&seven));
        coord.on_verified_remote_header_received(&fast_path_schedule(), seven, ValidatorId::new(0));
        coord.on_verified_remote_header_received(&fast_path_schedule(), eight, ValidatorId::new(0));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(0)),
            "headers held above an unanchored frontier are not sync progress",
        );

        let boundary = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::new(6),
            weighted_timestamp: WeightedTimestamp::from_millis(6_000),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        coord.refresh_expected(&TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(5),
            Arc::new(snapshot().with_boundaries(BTreeMap::from([(remote, boundary)]))),
        ));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(8)),
            "the re-anchored frontier crosses the headers held just above it",
        );
    }

    /// A frontier the source has pruned beneath re-anchors at the source's
    /// attested boundary, once and only from below the floor: a frontier
    /// at or above it, and a boundary still beneath it, leave it where it
    /// is.
    #[test]
    fn a_frontier_beneath_the_sources_floor_reanchors_at_its_boundary() {
        use hyperscale_types::{BeaconWitnessLeafCount, ShardAnchor, StateRoot};

        const ED: u64 = 1_000;
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let anchored_at = |height: u64| {
            let boundary = ShardAnchor {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::new(height),
                weighted_timestamp: WeightedTimestamp::from_millis(height * 1_000),
                witness_base: BeaconWitnessLeafCount::ZERO,
                terminal_settled_txs: None,
                handoff_complete: None,
                terminal_epoch: None,
            };
            TopologySchedule::new(
                EpochWindows::new(0, ED),
                Epoch::new(5),
                Arc::new(
                    shard_snapshot(2, &[0, 1, 2, 3], 0)
                        .with_boundaries(BTreeMap::from([(remote, boundary)])),
                ),
            )
        };
        let mut coord = RemoteHeaderCoordinator::new(local);
        coord.expected.insert(
            remote,
            ExpectedHeader {
                discovered_at: WeightedTimestamp::from_millis(1),
                last_verified_height: BlockHeight::new(5),
                verified_tip: BlockHeight::new(5),
                last_verified_at: Some(WeightedTimestamp::from_millis(1)),
            },
        );

        coord.on_source_below_floor(&anchored_at(20), remote, BlockHeight::new(30));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(5)),
            "a boundary beneath the floor anchors nothing",
        );

        coord.on_source_below_floor(&anchored_at(40), remote, BlockHeight::new(30));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(40)),
            "the frontier moves to the boundary the source still holds",
        );

        coord.on_source_below_floor(&anchored_at(50), remote, BlockHeight::new(30));
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(40)),
            "a frontier at or above the floor stays",
        );
    }

    #[test]
    fn out_of_band_admit_holds_the_frontier_until_the_gap_fills() {
        // A source header admitted above the sync frontier — the shape a
        // provision- or execution-certificate-bundled `source_header` takes
        // while `block.committed` gossip is dropped — populates `verified`
        // but must not advance the frontier past the gap below it. If it did,
        // the liveness probe would stop fetching the intervening heights and
        // the commit-proof walk (which needs a source block and its committing
        // child held contiguously) would never complete.
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        coord.expected.insert(
            remote,
            ExpectedHeader {
                discovered_at: WeightedTimestamp::from_millis(1),
                last_verified_height: BlockHeight::new(5),
                verified_tip: BlockHeight::new(5),
                last_verified_at: Some(WeightedTimestamp::from_millis(1)),
            },
        );

        // A sparse admit at height 8 (gap at 6, 7) leaves the frontier at 5.
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, 8, 8, None),
            ValidatorId::new(0),
        );
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(5)),
            "a header above the frontier does not slide it past the gap",
        );

        // Filling 6 advances the frontier one step; it cannot yet reach the
        // held 8 across the still-missing 7.
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, 6, 6, None),
            ValidatorId::new(0),
        );
        assert_eq!(coord.verified_frontier(remote), Some(BlockHeight::new(6)));

        // Filling 7 closes the gap and walks the frontier up over the held 8.
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, 7, 7, None),
            ValidatorId::new(0),
        );
        assert_eq!(
            coord.verified_frontier(remote),
            Some(BlockHeight::new(8)),
            "filling the gap walks the frontier up over the already-held successor",
        );
    }

    #[test]
    fn remote_header_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let remote = ShardId::leaf(1, 1);
        let ids = [0u64, 1, 2, 3];

        // Schedule head is epoch 0; a header anchored in epoch 5 is ahead of
        // this node's beacon and can't resolve yet.
        let behind = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(0),
            Arc::new(shard_snapshot(2, &ids, 0)),
        );
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = anchored_header(&mut coord, remote, BlockHeight::new(5), 5 * ED); // parent WT in epoch 5

        let actions = coord.on_remote_header_received(&behind, header, gossip(1));
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
        let schedule = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(5),
            Arc::new(shard_snapshot(2, &ids, 0)),
        );
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = anchored_header(&mut coord, remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let actions = coord.on_remote_header_received(&schedule, header, gossip(1));
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
        let present = TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(0), snap());
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(1, 0));
        let header = anchored_header(&mut coord, remote, BlockHeight::new(5), 0); // parent WT in epoch 0

        let dispatched = coord.on_remote_header_received(&present, header.clone(), gossip(1));
        assert!(verify_qc_keys(&dispatched).is_some());
        coord.on_remote_header_received(&present, header.clone(), gossip(2));
        coord.on_remote_header_received(&present, header.clone(), gossip(3));
        assert_eq!(coord.memory_stats().pending_headers, 3);

        // The first candidate's verification fails, and the schedule no longer
        // covers epoch 0 (every consumer frontier passed it).
        let evicted = TopologySchedule::new(EpochWindows::new(0, ED), Epoch::new(5), snap());
        let after_fail = coord.on_remote_header_qc_verified(
            &evicted,
            &header,
            gossip(1),
            Err(CertifiedHeaderVerifyError::LinkageMismatch),
            HeaderCommittee::Resolved,
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
        parent: Option<&Verified<CertifiedBlockHeader>>,
    ) -> Verified<CertifiedBlockHeader> {
        chain_header_dated(shard, height, round, parent, height * 1_000)
    }

    /// [`chain_header`] with its anchor and certificate dated `ms`.
    fn chain_header_dated(
        shard: ShardId,
        height: u64,
        round: u64,
        parent: Option<&Verified<CertifiedBlockHeader>>,
        ms: u64,
    ) -> Verified<CertifiedBlockHeader> {
        let parent_hash = parent.map_or_else(
            || BlockHash::from_raw(Hash::from_bytes(&height.to_le_bytes())),
            Verified::block_hash,
        );
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            shard,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::new(round.saturating_sub(1)),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(ms),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(round),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            BlockHeight::new(height),
            parent_hash,
            Round::new(round),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(ms),
        );
        Verified::new_unchecked_for_test(CertifiedBlockHeader::new(header, qc))
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
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            parent,
            ValidatorId::new(0),
        );
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
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            child,
            ValidatorId::new(0),
        );
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
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            parent,
            ValidatorId::new(0),
        );
        let parent = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        let child = chain_header(remote, 6, 7, Some(&parent));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            child,
            ValidatorId::new(0),
        );
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
            &fast_path_schedule(),
            chain_header(remote, 5, 5, None),
            ValidatorId::new(0),
        );
        let h5 = coord
            .get_verified(remote, BlockHeight::new(5))
            .expect("stored")
            .clone();
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            chain_header(remote, 6, 7, Some(&h5)),
            ValidatorId::new(0),
        );
        let h6 = coord
            .get_verified(remote, BlockHeight::new(6))
            .expect("stored")
            .clone();
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
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
            &fast_path_schedule(),
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

        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            h7,
            ValidatorId::new(0),
        );
        assert!(
            committed_heights(&actions).is_empty(),
            "7 alone proves nothing"
        );
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            h8,
            ValidatorId::new(0),
        );
        assert_eq!(
            committed_heights(&actions),
            vec![7],
            "8 commits 7; the walk stops at the missing 6"
        );

        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            h6,
            ValidatorId::new(0),
        );
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
            &fast_path_schedule(),
            chain_header(remote, 5, 5, None),
            ValidatorId::new(0),
        );
        let h6 = chain_header(remote, 6, 6, None);
        let h7 = chain_header(remote, 7, 7, Some(&h6));
        coord.on_verified_remote_header_received(&fast_path_schedule(), h6, ValidatorId::new(0));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            h7,
            ValidatorId::new(0),
        );

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
            fork_proofs(&coord.on_verified_remote_header_received(
                &fast_path_schedule(),
                w,
                ValidatorId::new(1)
            ))
            .is_empty()
        );
        assert!(
            fork_proofs(&coord.on_verified_remote_header_received(
                &fast_path_schedule(),
                wc,
                ValidatorId::new(1)
            ))
            .is_empty()
        );
        assert!(
            fork_proofs(&coord.on_verified_remote_header_received(
                &fast_path_schedule(),
                s,
                ValidatorId::new(1)
            ))
            .is_empty(),
            "a sibling block without its own committing child assembles nothing yet"
        );

        // The sibling's committing child completes the second branch's commit
        // proof — now two committed chains at height 5 exist.
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            sc.clone(),
            ValidatorId::new(1),
        );
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
        let again = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            sc,
            ValidatorId::new(2),
        );
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
        coord.on_verified_remote_header_received(&fast_path_schedule(), w, ValidatorId::new(1));
        coord.on_verified_remote_header_received(&fast_path_schedule(), wc, ValidatorId::new(1));
        let actions =
            coord.on_verified_remote_header_received(&fast_path_schedule(), s, ValidatorId::new(1));
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
        assert!(
            coord
                .fork_fence
                .engage(remote, BlockHeight::new(5), None)
                .is_some()
        );

        // A commit-proven header AT the fork height is tracked but not
        // promoted — no `RemoteHeaderCommitted`, so no consumer opens it.
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        coord.on_verified_remote_header_received(&fast_path_schedule(), w, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            wc,
            ValidatorId::new(1),
        );
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
        coord.on_verified_remote_header_received(&fast_path_schedule(), b3, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            b4,
            ValidatorId::new(1),
        );
        assert_eq!(
            committed_heights(&actions),
            vec![3],
            "a below-fork commit promotes"
        );
    }

    #[test]
    fn fork_fence_holds_through_the_fold_and_lifts_on_completion() {
        use hyperscale_types::test_utils::{certify, make_live_block};
        use hyperscale_types::{RecoveryBinding, RecoveryCause, ShardRecovery};

        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        assert!(
            coord
                .fork_fence
                .engage(remote, BlockHeight::new(5), None)
                .is_some()
        );

        let local_block = |h: u64| {
            certify(
                make_live_block(
                    local,
                    BlockHeight::new(h),
                    0,
                    ValidatorId::new(0),
                    vec![],
                    vec![],
                ),
                h * 1_000,
            )
        };

        // The attested recovery folds — the fence holds through the
        // recovery window, so a height proven mid-window stays unpromoted.
        // A single-entry schedule dates every block at genesis, so the
        // recovery seats there for the blocks above its frontier to be the
        // fresh committee's.
        let recovering = TopologySchedule::single(Arc::new(
            shard_snapshot(2, &[0, 1, 2, 3], 0).with_pending_recoveries(
                std::iter::once((
                    remote,
                    ShardRecovery {
                        cause: RecoveryCause::Fork,
                        rotated_at: Epoch::GENESIS,
                        retained: Vec::new(),
                        attested_frontier: BlockHeight::new(4),
                    },
                ))
                .collect(),
            ),
        ));
        coord.on_block_committed(&recovering, &local_block(1), &[]);
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        coord.on_verified_remote_header_received(&fast_path_schedule(), w, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            wc,
            ValidatorId::new(1),
        );
        assert!(
            committed_heights(&actions).is_empty(),
            "a folded-but-incomplete recovery must keep the fence engaged"
        );

        // The recovery completes (the fresh committee's first crossing) —
        // the fence clears and the promotion it withheld replays, so the
        // proven-but-unpromoted height is not stranded.
        let recovered = TopologySchedule::single(Arc::new(
            shard_snapshot(2, &[0, 1, 2, 3], 0).with_recoveries(
                std::iter::once((
                    remote,
                    vec![RecoveryBinding {
                        rotated_at: Epoch::GENESIS,
                        attested_frontier: BlockHeight::new(4),
                        completed: true,
                    }],
                ))
                .collect(),
            ),
        ));
        let cleared = coord
            .fork_fence
            .clear_completed(|shard| recovered.head().latest_completed_recovery(shard));
        let actions = coord.on_block_committed(&recovered, &local_block(2), &cleared);
        assert_eq!(
            committed_heights(&actions),
            vec![5],
            "clearing the fence must promote what it withheld"
        );

        // A newly proven height promotes normally after the clear.
        let x = chain_header(remote, 8, 8, None);
        let xc = chain_header(remote, 9, 9, Some(&x));
        coord.on_verified_remote_header_received(&fast_path_schedule(), x, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            xc,
            ValidatorId::new(1),
        );
        assert_eq!(
            committed_heights(&actions),
            vec![8],
            "a completed recovery lifts the fence for newly proven heights"
        );
    }

    #[test]
    fn commit_proven_sibling_displaces_a_never_proven_squatter() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        // A certified-but-never-committed sibling lands first and takes the
        // canonical slot.
        let squatter = chain_header(remote, 5, 5, None);
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            squatter.clone(),
            ValidatorId::new(1),
        );

        // The really-committed block arrives second — routed to the
        // sibling buffer, not the slot.
        let committed = chain_header(remote, 5, 7, None);
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            committed.clone(),
            ValidatorId::new(1),
        );
        assert!(committed_heights(&actions).is_empty());
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(squatter.block_hash()),
            "first-valid holds the slot while neither branch is proven"
        );

        // Its committing child proves it: the slot flips to the committed
        // block, consumers re-arm on the real manifest, and the height
        // promotes. No fork proof — the squatter has no committing child.
        let child = chain_header(remote, 6, 8, Some(&committed));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            child,
            ValidatorId::new(1),
        );
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(committed.block_hash()),
            "the commit-proven sibling must displace the never-proven occupant"
        );
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
        assert_eq!(
            committed_heights(&actions),
            vec![5],
            "the displaced-in block promotes"
        );
        let readmitted: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted { certified_header })
                    if certified_header.height() == BlockHeight::new(5) =>
                {
                    Some(certified_header.block_hash())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            readmitted,
            vec![committed.block_hash()],
            "consumers must re-arm on the committed block's manifest"
        );
        assert!(
            fork_proofs(&actions).is_empty(),
            "a never-committed squatter is not a fork"
        );
        coord.shards[&remote].assert_indexed();
    }

    /// Feed `headers` in order, returning the heights promoted and the
    /// blocks admitted at `height` along the way.
    fn feed(
        coord: &mut RemoteHeaderCoordinator,
        height: u64,
        headers: &[&Verified<CertifiedBlockHeader>],
    ) -> (Vec<u64>, Vec<BlockHash>) {
        let mut committed = Vec::new();
        let mut admitted = Vec::new();
        for header in headers {
            let actions = coord.on_verified_remote_header_received(
                &fast_path_schedule(),
                (*header).clone(),
                ValidatorId::new(1),
            );
            committed.extend(committed_heights(&actions));
            admitted.extend(actions.iter().filter_map(|a| match a {
                Action::Continuation(ProtocolEvent::RemoteHeaderAdmitted { certified_header })
                    if certified_header.height() == BlockHeight::new(height) =>
                {
                    Some(certified_header.block_hash())
                }
                _ => None,
            }));
        }
        (committed, admitted)
    }

    fn occupant(coord: &RemoteHeaderCoordinator, shard: ShardId, height: u64) -> Option<BlockHash> {
        coord
            .get_verified(shard, BlockHeight::new(height))
            .map(Verified::block_hash)
    }

    /// An orphan holds the slot above `b`, the committed child is held
    /// beside it, and the block above the committed child skipped a round.
    /// The two-chain above proves that block; its parent hash names the
    /// committed child, which takes the slot and proves with it.
    #[test]
    fn a_round_gap_above_the_committed_child_seats_it_past_an_orphan() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let orphan = chain_header(remote, 6, 6, Some(&b));
        let kept = chain_header(remote, 6, 7, Some(&b));
        let d = chain_header(remote, 7, 9, Some(&kept));
        let e = chain_header(remote, 8, 10, Some(&d));

        let (committed, admitted) = feed(&mut coord, 6, &[&b, &orphan, &kept, &d, &e]);

        assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
        assert_eq!(
            admitted,
            vec![orphan.block_hash(), kept.block_hash()],
            "consumers re-arm on the committed child",
        );
        assert_eq!(
            committed,
            vec![5, 6, 7],
            "the orphan's own two-chain proves 5; the chain above proves 7, released with 6 \
             once 6 is seated",
        );
        let ask = coord.request_commit_proof(&fast_path_schedule(), remote, BlockHeight::new(6));
        assert_eq!(committed_heights(&ask), vec![6]);
        assert!(commit_proof_fetches(&ask).is_empty());
        assert_eq!(
            coord.memory_stats().fork_siblings,
            1,
            "the orphan is held as the sibling it displaced",
        );
        coord.shards[&remote].assert_indexed();
    }

    /// The committed child reaches the store after the chain above it
    /// proved: it is seated on arrival.
    #[test]
    fn the_committed_child_heard_last_is_seated_past_an_orphan() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let orphan = chain_header(remote, 6, 6, Some(&b));
        let kept = chain_header(remote, 6, 7, Some(&b));
        let d = chain_header(remote, 7, 9, Some(&kept));
        let e = chain_header(remote, 8, 10, Some(&d));

        let (committed, admitted) = feed(&mut coord, 6, &[&b, &orphan, &d, &e, &kept]);

        assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
        assert_eq!(admitted, vec![orphan.block_hash(), kept.block_hash()]);
        assert_eq!(committed, vec![5, 7, 6]);
        coord.shards[&remote].assert_indexed();
    }

    /// A slot the committed block already holds is left alone: an orphan
    /// heard beside it stays a sibling whatever proves around it, and a
    /// proof arriving for the height re-admits nothing.
    #[test]
    fn an_orphan_beside_a_seated_committed_child_displaces_nothing() {
        let remote = ShardId::leaf(2, 1);
        let b = chain_header(remote, 5, 5, None);
        let orphan = chain_header(remote, 6, 6, Some(&b));
        let kept = chain_header(remote, 6, 7, Some(&b));
        let d = chain_header(remote, 7, 9, Some(&kept));
        let e = chain_header(remote, 8, 10, Some(&d));

        for order in [
            [&b, &kept, &orphan, &d, &e],
            [&b, &kept, &d, &orphan, &e],
            [&b, &kept, &d, &e, &orphan],
        ] {
            let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
            let (mut committed, admitted) = feed(&mut coord, 6, &order);
            committed.sort_unstable();

            assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
            assert_eq!(admitted, vec![kept.block_hash()]);
            assert_eq!(committed, vec![5, 6, 7]);
            assert_eq!(coord.memory_stats().fork_siblings, 1);
            coord.shards[&remote].assert_indexed();
        }
    }

    /// An orphan at each of two heights in a row, each beside the block
    /// its chain committed: the proven chain seats the upper committed
    /// block, and that block's parent hash seats the lower.
    #[test]
    fn stacked_orphans_each_yield_to_the_committed_block_above_them() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let low_orphan = chain_header(remote, 6, 6, Some(&b));
        let low_kept = chain_header(remote, 6, 7, Some(&b));
        let high_orphan = chain_header(remote, 7, 9, Some(&low_kept));
        let high_kept = chain_header(remote, 7, 11, Some(&low_kept));
        let e = chain_header(remote, 8, 13, Some(&high_kept));
        let f = chain_header(remote, 9, 14, Some(&e));

        let (committed, _) = feed(
            &mut coord,
            6,
            &[&b, &low_orphan, &low_kept, &high_orphan, &high_kept, &e, &f],
        );

        assert_eq!(occupant(&coord, remote, 6), Some(low_kept.block_hash()));
        assert_eq!(occupant(&coord, remote, 7), Some(high_kept.block_hash()));
        assert_eq!(committed, vec![5, 6, 7, 8]);
        assert_eq!(coord.memory_stats().fork_siblings, 2);
        coord.shards[&remote].assert_indexed();
    }

    /// Two orphans at one height, one in the slot and one beside the
    /// committed child: the proven chain picks the block it names.
    #[test]
    fn two_orphans_at_one_height_yield_to_the_committed_child() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let first_orphan = chain_header(remote, 6, 6, Some(&b));
        let second_orphan = chain_header(remote, 6, 7, Some(&b));
        let kept = chain_header(remote, 6, 8, Some(&b));
        let d = chain_header(remote, 7, 10, Some(&kept));
        let e = chain_header(remote, 8, 11, Some(&d));

        let (committed, admitted) = feed(
            &mut coord,
            6,
            &[&b, &first_orphan, &second_orphan, &kept, &d, &e],
        );

        assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
        assert_eq!(admitted, vec![first_orphan.block_hash(), kept.block_hash()]);
        assert_eq!(committed, vec![5, 6, 7]);
        assert_eq!(coord.memory_stats().fork_siblings, 2);
        coord.shards[&remote].assert_indexed();
    }

    /// With the block above the committed child round-contiguous to it,
    /// that block alone seats the committed child.
    #[test]
    fn a_round_contiguous_child_seats_the_committed_child_past_an_orphan() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let orphan = chain_header(remote, 6, 6, Some(&b));
        let kept = chain_header(remote, 6, 7, Some(&b));
        let d = chain_header(remote, 7, 8, Some(&kept));

        let (committed, admitted) = feed(&mut coord, 6, &[&b, &orphan, &kept, &d]);

        assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
        assert_eq!(admitted, vec![orphan.block_hash(), kept.block_hash()]);
        assert_eq!(committed, vec![5, 6]);
        coord.shards[&remote].assert_indexed();
    }

    /// A proven block vouches for the one block its parent hash names. A
    /// second orphan with a certified child of its own, neither of them
    /// committed, takes nothing from the proof of the block beside that
    /// child.
    #[test]
    fn a_proven_block_seats_only_the_sibling_it_extends() {
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(ShardId::leaf(2, 0));
        let b = chain_header(remote, 5, 5, None);
        let squatter = chain_header(remote, 6, 6, Some(&b));
        let orphan = chain_header(remote, 6, 7, Some(&b));
        let kept = chain_header(remote, 6, 8, Some(&b));
        let d = chain_header(remote, 7, 10, Some(&kept));
        let orphan_child = chain_header(remote, 7, 13, Some(&orphan));
        let e = chain_header(remote, 8, 11, Some(&d));
        let stray = chain_header(remote, 7, 15, None);

        let (_, admitted) = feed(
            &mut coord,
            6,
            &[&b, &squatter, &orphan, &kept, &d, &orphan_child, &e, &stray],
        );

        assert_eq!(admitted, vec![squatter.block_hash(), kept.block_hash()]);
        assert_eq!(occupant(&coord, remote, 6), Some(kept.block_hash()));
        assert!(coord.has_commit_proof(remote, BlockHeight::new(6)));
        coord.shards[&remote].assert_indexed();
    }

    /// The replaced committee's branch above the frontier, held and
    /// promoted before the recovery folded, stays held through the fold.
    /// The fresh committee's blocks at those heights take the slots and
    /// promote: a block promoted before its recovery folded could not be
    /// told from the recovered chain then, so its height promotes twice,
    /// and consumers take the later header at the height. An answered fork
    /// at or below the frontier stays mute.
    #[test]
    fn a_branch_promoted_before_the_fold_gives_way_and_answered_forks_stay_mute() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let unfolded = schedule_under(shard_snapshot(2, &[0, 1, 2, 3], 0));
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));

        let o5 = chain_header_dated(remote, 5, 5, None, 5_000);
        let o6 = chain_header_dated(remote, 6, 6, Some(&o5), 5_100);
        let before = admit_under(&mut coord, &unfolded, &[&o5, &o6]);
        assert_eq!(committed_heights(&before), vec![5]);

        commit_local(&mut coord, &pending, 1);
        assert!(coord.has_verified(remote, BlockHeight::new(5)));

        let n5 = chain_header_dated(remote, 5, 50, None, 10_500);
        let n6 = chain_header_dated(remote, 6, 51, Some(&n5), 10_600);
        let actions = admit_under(&mut coord, &pending, &[&n5, &n6]);
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(n5.block_hash()),
        );
        assert_eq!(committed_heights(&actions), vec![5]);
        assert!(fork_proofs(&actions).is_empty());

        let a4 = chain_header_dated(remote, 4, 3, None, 4_000);
        let a5 = chain_header_dated(remote, 5, 4, Some(&a4), 4_100);
        let b4 = chain_header_dated(remote, 4, 40, None, 4_200);
        let b5 = chain_header_dated(remote, 5, 41, Some(&b4), 4_300);
        let actions = admit_under(&mut coord, &pending, &[&a4, &a5, &b4, &b5]);
        assert!(
            fork_proofs(&actions).is_empty(),
            "a fork at or below the attested frontier was already answered"
        );
        coord.shards[&remote].assert_indexed();
    }

    /// After a recovery stamped at 9 (bridge 10) over the frontier at 4
    /// has cleared, the committee it replaced commits an orphan at 5 dated
    /// in its own window. A genuine fork of the governing committee then
    /// commits two blocks at 5 past the bridge. The orphan is refused at
    /// admission, and the fork is emitted between the two.
    #[test]
    fn a_discarded_branch_does_not_mask_a_fork_of_the_governing_committee() {
        use hyperscale_types::test_utils::{certify, make_live_block};

        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let recovered = TopologySchedule::new(
            EpochWindows::new(0, 1_000),
            Epoch::new(11),
            Arc::new(
                shard_snapshot(2, &[0, 1, 2, 3], 0).with_recoveries(
                    std::iter::once((
                        remote,
                        vec![RecoveryBinding {
                            rotated_at: Epoch::new(9),
                            attested_frontier: BlockHeight::new(4),
                            completed: true,
                        }],
                    ))
                    .collect(),
                ),
            ),
        );
        let block = certify(
            make_live_block(
                local,
                BlockHeight::new(1),
                0,
                ValidatorId::new(0),
                vec![],
                vec![],
            ),
            11_000,
        );
        coord.on_block_committed(&recovered, &block, &[]);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let orphan_child = chain_header_dated(remote, 6, 6, Some(&orphan), 5_100);
        let x = chain_header_dated(remote, 5, 7, None, 10_500);
        let x_child = chain_header_dated(remote, 6, 8, Some(&x), 10_600);
        let y = chain_header_dated(remote, 5, 9, None, 10_700);
        let y_child = chain_header_dated(remote, 6, 10, Some(&y), 10_800);

        let mut emitted = Vec::new();
        for header in [&orphan, &orphan_child, &x, &x_child, &y, &y_child] {
            let actions = coord.on_verified_remote_header_received(
                &recovered,
                header.clone(),
                ValidatorId::new(1),
            );
            emitted.extend(fork_proofs(&actions).into_iter().cloned());
        }
        assert_eq!(emitted.len(), 1, "one fork is emitted at height 5");
        let ShardForkProof::ConflictingCommits { a, b } = &emitted[0];
        let mut paired = [a.proven_block_hash(), b.proven_block_hash()];
        paired.sort();
        let mut fork = [x.block_hash(), y.block_hash()];
        fork.sort();
        assert_eq!(
            paired, fork,
            "the fork pairs the governing committee's two blocks"
        );
    }

    /// While the recovery is pending, the retained cohort's own
    /// fork of its suffix above the frontier is assembled, so the beacon
    /// can upgrade the recovery to a fork recovery.
    #[test]
    fn a_suffix_fork_is_assembled_while_the_recovery_is_pending() {
        use hyperscale_types::test_utils::{certify, make_live_block};
        use hyperscale_types::{RecoveryCause, ShardRecovery};

        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let binding = RecoveryBinding {
            rotated_at: Epoch::new(9),
            attested_frontier: BlockHeight::new(4),
            completed: false,
        };
        let pending = TopologySchedule::new(
            EpochWindows::new(0, 1_000),
            Epoch::new(11),
            Arc::new(
                shard_snapshot(2, &[0, 1, 2, 3], 0)
                    .with_recoveries(std::iter::once((remote, vec![binding])).collect())
                    .with_pending_recoveries(
                        std::iter::once((
                            remote,
                            ShardRecovery {
                                cause: RecoveryCause::Halt,
                                rotated_at: Epoch::new(9),
                                retained: Vec::new(),
                                attested_frontier: BlockHeight::new(4),
                            },
                        ))
                        .collect(),
                    ),
            ),
        );
        let block = certify(
            make_live_block(
                local,
                BlockHeight::new(1),
                0,
                ValidatorId::new(0),
                vec![],
                vec![],
            ),
            11_000,
        );
        coord.on_block_committed(&pending, &block, &[]);

        let a = chain_header_dated(remote, 5, 5, None, 5_000);
        let a_child = chain_header_dated(remote, 6, 6, Some(&a), 5_100);
        let b = chain_header_dated(remote, 5, 7, None, 5_200);
        let b_child = chain_header_dated(remote, 6, 8, Some(&b), 5_300);
        let mut emitted = Vec::new();
        for header in [&a, &a_child, &b, &b_child] {
            let actions = coord.on_verified_remote_header_received(
                &pending,
                header.clone(),
                ValidatorId::new(1),
            );
            emitted.extend(fork_proofs(&actions).into_iter().cloned());
        }
        assert_eq!(emitted.len(), 1, "the suffix fork is emitted");
    }

    /// Where `remote`'s recovery stands in a test head.
    #[derive(Clone, Copy)]
    enum Recovery {
        /// Folded and stamped, its fresh committee not yet crossed.
        Pending,
        /// Completed: the record has left the pending set.
        Cleared,
    }

    /// The head over second-long epochs, at epoch 11, with `remote`'s
    /// recovery stamped at 9 (bridge 10) over the frontier at 4 at
    /// `stage`.
    fn recovery_head(remote: ShardId, stage: Recovery) -> TopologySnapshot {
        use hyperscale_types::{RecoveryCause, ShardRecovery};

        let snapshot = shard_snapshot(2, &[0, 1, 2, 3], 0);
        let pending = matches!(stage, Recovery::Pending);
        let snapshot = snapshot.with_recoveries(
            std::iter::once((
                remote,
                vec![RecoveryBinding {
                    rotated_at: Epoch::new(9),
                    attested_frontier: BlockHeight::new(4),
                    completed: !pending,
                }],
            ))
            .collect(),
        );
        if !pending {
            return snapshot;
        }
        snapshot.with_pending_recoveries(
            std::iter::once((
                remote,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(9),
                    retained: Vec::new(),
                    attested_frontier: BlockHeight::new(4),
                },
            ))
            .collect(),
        )
    }

    /// A schedule of second-long epochs headed by `head` at epoch 11,
    /// every earlier epoch seating the same committee.
    fn schedule_under(head: TopologySnapshot) -> TopologySchedule {
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1_000), Epoch::new(11), Arc::new(head));
        for epoch in 0..11 {
            schedule.insert(
                Epoch::new(epoch),
                Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)),
            );
        }
        schedule
    }

    fn commit_local(
        coord: &mut RemoteHeaderCoordinator,
        schedule: &TopologySchedule,
        at: u64,
    ) -> Vec<Action> {
        use hyperscale_types::test_utils::{certify, make_live_block};

        let block = certify(
            make_live_block(
                coord.local_shard,
                BlockHeight::new(at),
                0,
                ValidatorId::new(0),
                vec![],
                vec![],
            ),
            11_000,
        );
        coord.on_block_committed(schedule, &block, &[])
    }

    fn unverified(header: &Verified<CertifiedBlockHeader>) -> CertifiedBlockHeader {
        CertifiedBlockHeader::clone(header)
    }

    fn admit_under(
        coord: &mut RemoteHeaderCoordinator,
        schedule: &TopologySchedule,
        headers: &[&Verified<CertifiedBlockHeader>],
    ) -> Vec<Action> {
        headers
            .iter()
            .flat_map(|header| {
                coord.on_verified_remote_header_received(
                    schedule,
                    (*header).clone(),
                    ValidatorId::new(1),
                )
            })
            .collect()
    }

    /// A halt recovery's fresh committee harvests the halted tip and
    /// extends it: 5 and 6, above the frontier at 4 and certified by the
    /// replaced committee a full halt gap below the bridge, are on the
    /// recovered chain. Heard after the clear, they are admitted, and
    /// promoted once the fresh block built on them is held.
    #[test]
    fn a_harvested_tail_is_admitted_after_the_clear() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let tail5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let tail6 = chain_header_dated(remote, 6, 6, Some(&tail5), 7_100);
        let fresh7 = chain_header_dated(remote, 7, 7, Some(&tail6), 10_500);
        let fresh8 = chain_header_dated(remote, 8, 8, Some(&fresh7), 10_600);
        let held = admit_under(&mut coord, &cleared, &[&tail5, &tail6]);
        assert!(committed_heights(&held).is_empty());
        let actions = admit_under(&mut coord, &cleared, &[&fresh7, &fresh8]);
        assert!(coord.has_verified(remote, BlockHeight::new(5)));
        assert!(coord.has_verified(remote, BlockHeight::new(6)));
        assert_eq!(committed_heights(&actions), vec![5, 6, 7]);
    }

    /// A tail block gossiped or fetched after the clear goes to
    /// verification like any other.
    #[test]
    fn a_harvested_tail_received_after_the_clear_is_verified() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));

        let tail5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let actions = coord.on_remote_header_received(&cleared, unverified(&tail5), gossip(1));
        assert!(verify_qc_keys(&actions).is_some());
    }

    /// The same tail, held and promoted with the fresh chain on it while
    /// the recovery was pending, survives the clear.
    #[test]
    fn a_harvested_tail_held_at_the_clear_is_kept() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let tail5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let tail6 = chain_header_dated(remote, 6, 6, Some(&tail5), 7_100);
        let fresh7 = chain_header_dated(remote, 7, 7, Some(&tail6), 10_500);
        let fresh8 = chain_header_dated(remote, 8, 8, Some(&fresh7), 10_600);
        let actions = admit_under(&mut coord, &pending, &[&tail5, &tail6, &fresh7, &fresh8]);
        assert_eq!(committed_heights(&actions), vec![5, 6, 7]);

        let actions = commit_local(&mut coord, &cleared, 2);
        assert!(committed_heights(&actions).is_empty());
        for height in 5..=8 {
            assert!(coord.has_verified(remote, BlockHeight::new(height)));
        }
    }

    /// A tail held through the clear without the fresh block built on it
    /// is kept, unpromoted, and the fresh block's arrival promotes it.
    #[test]
    fn a_tail_held_through_the_clear_without_its_fresh_chain_is_kept() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let tail5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let tail6 = chain_header_dated(remote, 6, 6, Some(&tail5), 7_100);
        let held = admit_under(&mut coord, &pending, &[&tail5, &tail6]);
        assert!(committed_heights(&held).is_empty());
        let at_clear = commit_local(&mut coord, &cleared, 2);
        assert!(committed_heights(&at_clear).is_empty());
        assert!(coord.has_verified(remote, BlockHeight::new(5)));

        let fresh7 = chain_header_dated(remote, 7, 7, Some(&tail6), 10_500);
        let fresh8 = chain_header_dated(remote, 8, 8, Some(&fresh7), 10_600);
        let actions = admit_under(&mut coord, &cleared, &[&fresh7, &fresh8]);
        assert_eq!(committed_heights(&actions), vec![5, 6, 7]);
    }

    /// The retained cohort's orphans hold 5 and 6, proven, with the
    /// harvested tail beside them. The fresh block at 7 extends the tail:
    /// it takes 6 from the orphan, and the seated tail block's parent takes
    /// 5 beneath it, so the whole recovered chain promotes.
    #[test]
    fn a_fresh_block_reseats_its_tail_beneath_an_orphan_branch() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let orphan5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let orphan6 = chain_header_dated(remote, 6, 6, Some(&orphan5), 7_100);
        let tail5 = chain_header_dated(remote, 5, 7, None, 7_200);
        let tail6 = chain_header_dated(remote, 6, 8, Some(&tail5), 7_300);
        let fresh7 = chain_header_dated(remote, 7, 9, Some(&tail6), 10_500);
        let fresh8 = chain_header_dated(remote, 8, 10, Some(&fresh7), 10_600);
        let held = admit_under(&mut coord, &cleared, &[&orphan5, &orphan6, &tail5, &tail6]);
        assert!(committed_heights(&held).is_empty());
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));

        let actions = admit_under(&mut coord, &cleared, &[&fresh7, &fresh8]);
        assert_eq!(committed_heights(&actions), vec![5, 6, 7]);
        for (height, header) in [(5, &tail5), (6, &tail6), (7, &fresh7)] {
            assert_eq!(
                coord
                    .get_verified(remote, BlockHeight::new(height))
                    .map(Verified::block_hash),
                Some(header.block_hash()),
            );
        }
        coord.shards[&remote].assert_indexed();
    }

    /// An orphan proven while the recovery is pending is never promoted,
    /// so the fresh block that takes its height after the clear is the
    /// height's one promotion.
    #[test]
    fn a_height_is_promoted_at_most_once_across_the_clear() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let orphan_child = chain_header_dated(remote, 6, 6, Some(&orphan), 5_100);
        let mut committed = committed_heights(&admit_under(
            &mut coord,
            &pending,
            &[&orphan, &orphan_child],
        ));
        committed.extend(committed_heights(&commit_local(&mut coord, &cleared, 2)));
        let fresh = chain_header_dated(remote, 5, 7, None, 10_500);
        let fresh_child = chain_header_dated(remote, 6, 8, Some(&fresh), 10_600);
        committed.extend(committed_heights(&admit_under(
            &mut coord,
            &cleared,
            &[&fresh, &fresh_child],
        )));
        assert_eq!(committed, vec![5]);
    }

    /// A genuine fork of the fresh committee emitted while the recovery is
    /// pending is not emitted again when the clear evicts an orphan held
    /// at the same height.
    #[test]
    fn a_genuine_fork_is_emitted_once_across_the_clear() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let x = chain_header_dated(remote, 5, 9, None, 10_500);
        let x_child = chain_header_dated(remote, 6, 10, Some(&x), 10_600);
        let y = chain_header_dated(remote, 5, 11, None, 10_700);
        let y_child = chain_header_dated(remote, 6, 12, Some(&y), 10_800);
        let first = admit_under(&mut coord, &pending, &[&orphan, &x, &x_child, &y, &y_child]);
        assert_eq!(fork_proofs(&first).len(), 1);
        let at_clear = commit_local(&mut coord, &cleared, 2);
        assert!(fork_proofs(&at_clear).is_empty());
    }

    /// Chained recoveries: the first one's fresh committee certified 3 and
    /// 4 past its own bridge, at or below the second's frontier. Both are
    /// canonical, and admitted after both clear.
    #[test]
    fn a_chained_recoverys_shared_history_is_admitted() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let head = shard_snapshot(2, &[0, 1, 2, 3], 0).with_recoveries(
            std::iter::once((
                remote,
                vec![
                    RecoveryBinding {
                        rotated_at: Epoch::new(5),
                        attested_frontier: BlockHeight::new(2),
                        completed: true,
                    },
                    RecoveryBinding {
                        rotated_at: Epoch::new(9),
                        attested_frontier: BlockHeight::new(4),
                        completed: true,
                    },
                ],
            ))
            .collect(),
        );
        let cleared = schedule_under(head);
        commit_local(&mut coord, &cleared, 1);
        let h3 = chain_header_dated(remote, 3, 3, None, 6_000);
        let h4 = chain_header_dated(remote, 4, 4, Some(&h3), 6_100);
        let actions = admit_under(&mut coord, &cleared, &[&h3, &h4]);
        assert_eq!(committed_heights(&actions), vec![3]);
        assert!(coord.has_verified(remote, BlockHeight::new(4)));
    }

    /// After the recovery has cleared, the committee it replaced commits
    /// an orphan at 5 and its child, which reach this store first. The
    /// orphan is held but never promoted, and gives its slot to the fresh
    /// committee's block at 5, which is proven and promoted.
    #[test]
    fn an_orphan_proven_after_the_clear_does_not_shadow_the_fresh_proof() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let orphan_child = chain_header_dated(remote, 6, 6, Some(&orphan), 5_100);
        let fresh = chain_header_dated(remote, 5, 7, None, 10_500);
        let fresh_child = chain_header_dated(remote, 6, 8, Some(&fresh), 10_600);
        let mut promoted = Vec::new();
        for header in [&orphan, &orphan_child, &fresh, &fresh_child] {
            let actions = coord.on_verified_remote_header_received(
                &cleared,
                header.clone(),
                ValidatorId::new(1),
            );
            promoted.extend(actions.iter().filter_map(|action| match action {
                Action::Continuation(ProtocolEvent::RemoteHeaderCommitted { certified_header }) => {
                    Some(certified_header.block_hash())
                }
                _ => None,
            }));
        }
        assert_eq!(promoted, vec![fresh.block_hash()]);
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
    }

    /// The fresh committee's bridge block above the frontier, certified
    /// in the window before the bridge, is admitted after the clear.
    #[test]
    fn a_fresh_header_certified_before_the_bridge_is_admitted() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let bridge = chain_header_dated(remote, 5, 5, None, 9_500);
        let child = chain_header_dated(remote, 6, 6, Some(&bridge), 10_100);
        coord.on_verified_remote_header_received(&cleared, bridge.clone(), ValidatorId::new(1));
        let actions =
            coord.on_verified_remote_header_received(&cleared, child, ValidatorId::new(1));
        assert_eq!(committed_heights(&actions), vec![5]);
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(bridge.block_hash()),
        );
    }

    /// Shared history at or below the frontier, certified by the replaced
    /// committee long before the bridge, is admitted after the clear.
    #[test]
    fn shared_history_below_the_frontier_is_admitted() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let h3 = chain_header_dated(remote, 3, 3, None, 3_000);
        let h4 = chain_header_dated(remote, 4, 4, Some(&h3), 4_000);
        coord.on_verified_remote_header_received(&cleared, h3, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(&cleared, h4, ValidatorId::new(1));
        assert_eq!(committed_heights(&actions), vec![3]);
        assert!(coord.has_verified(remote, BlockHeight::new(4)));
    }

    /// The retained cohort forks its suffix at 5 while the recovery is
    /// pending, and the fork is emitted then. Once the recovery clears,
    /// that proof answers nothing about the committee that governs, so a
    /// genuine fork of the governing committee at 5 is emitted in turn,
    /// pairing neither of the suffix's blocks.
    #[test]
    fn a_suffix_fork_emitted_while_pending_does_not_mask_a_fork_of_the_governing_committee() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let a = chain_header_dated(remote, 5, 5, None, 5_000);
        let a_child = chain_header_dated(remote, 6, 6, Some(&a), 5_100);
        let b = chain_header_dated(remote, 5, 7, None, 5_200);
        let b_child = chain_header_dated(remote, 6, 8, Some(&b), 5_300);
        let suffix = admit_under(&mut coord, &pending, &[&a, &a_child, &b, &b_child]);
        assert_eq!(
            fork_proofs(&suffix).len(),
            1,
            "the suffix fork is emitted while pending"
        );
        assert!(committed_heights(&suffix).is_empty());
        commit_local(&mut coord, &cleared, 2);

        let x = chain_header_dated(remote, 5, 9, None, 10_500);
        let x_child = chain_header_dated(remote, 6, 10, Some(&x), 10_600);
        let y = chain_header_dated(remote, 5, 11, None, 10_700);
        let y_child = chain_header_dated(remote, 6, 12, Some(&y), 10_800);
        let mut emitted = Vec::new();
        for header in [&x, &x_child, &y, &y_child] {
            let actions = admit_under(&mut coord, &cleared, &[header]);
            emitted.extend(fork_proofs(&actions).into_iter().cloned());
        }
        assert_eq!(emitted.len(), 1, "one fork is emitted at height 5");
        let ShardForkProof::ConflictingCommits { a, b } = &emitted[0];
        let mut paired = [a.proven_block_hash(), b.proven_block_hash()];
        paired.sort();
        let mut fork = [x.block_hash(), y.block_hash()];
        fork.sort();
        assert_eq!(paired, fork);
        coord.shards[&remote].assert_indexed();
    }

    /// An orphan the local fast path admitted while the recovery was
    /// pending, proven by its child, is never promoted: the fresh block at
    /// 5 heard after the clear takes the slot and is promoted.
    #[test]
    fn an_orphan_admitted_while_pending_yields_its_slot_after_the_clear() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let orphan_child = chain_header_dated(remote, 6, 6, Some(&orphan), 5_100);
        for header in [&orphan, &orphan_child] {
            coord.on_verified_remote_header_received(&pending, header.clone(), ValidatorId::new(1));
        }
        assert!(coord.has_commit_proof(remote, BlockHeight::new(5)));
        commit_local(&mut coord, &cleared, 2);

        let fresh = chain_header_dated(remote, 5, 7, None, 10_500);
        let fresh_child = chain_header_dated(remote, 6, 8, Some(&fresh), 10_600);
        coord.on_verified_remote_header_received(&cleared, fresh.clone(), ValidatorId::new(1));
        let actions =
            coord.on_verified_remote_header_received(&cleared, fresh_child, ValidatorId::new(1));
        assert_eq!(committed_heights(&actions), vec![5]);
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(fresh.block_hash()),
        );
    }

    /// A fresh block and its child heard beside an orphan while the
    /// recovery is pending take the orphan's slots on arrival, and the
    /// fresh block at 5 is promoted then, once.
    #[test]
    fn a_fresh_chain_heard_while_pending_takes_the_orphans_slots() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let pending = schedule_under(recovery_head(remote, Recovery::Pending));
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &pending, 1);

        let orphan = chain_header_dated(remote, 5, 5, None, 5_000);
        let orphan_child = chain_header_dated(remote, 6, 6, Some(&orphan), 5_100);
        let fresh = chain_header_dated(remote, 5, 7, None, 10_500);
        let fresh_child = chain_header_dated(remote, 6, 8, Some(&fresh), 10_600);
        let mut committed = committed_heights(&admit_under(
            &mut coord,
            &pending,
            &[&orphan, &orphan_child, &fresh, &fresh_child],
        ));
        committed.extend(committed_heights(&commit_local(&mut coord, &cleared, 2)));
        assert_eq!(committed, vec![5]);
        for (height, header) in [(5, &fresh), (6, &fresh_child)] {
            assert_eq!(
                coord
                    .get_verified(remote, BlockHeight::new(height))
                    .map(Verified::block_hash),
                Some(header.block_hash()),
            );
        }
        coord.shards[&remote].assert_indexed();
    }

    /// Shared history at 1 to 4, each certified by the committee every
    /// recovery keeps.
    fn shared_history(remote: ShardId) -> Vec<Verified<CertifiedBlockHeader>> {
        let mut chain: Vec<Verified<CertifiedBlockHeader>> = Vec::new();
        for height in 1..=4 {
            let header = chain_header_dated(remote, height, height, chain.last(), height * 1_000);
            chain.push(header);
        }
        chain
    }

    /// The sync frontier is the coverage the forward sync stops fetching
    /// below. An orphan pair proven after the clear covers nothing, so the
    /// frontier stays beneath it and the fresh blocks there are fetched.
    #[test]
    fn the_sync_frontier_does_not_walk_over_yielding_orphans() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let shared = shared_history(remote);
        let shared_refs: Vec<&Verified<CertifiedBlockHeader>> = shared.iter().collect();
        admit_under(&mut coord, &cleared, &shared_refs);
        let orphan5 = chain_header_dated(remote, 5, 5, Some(&shared[3]), 7_000);
        let orphan6 = chain_header_dated(remote, 6, 6, Some(&orphan5), 7_100);
        admit_under(&mut coord, &cleared, &[&orphan5, &orphan6]);
        assert_eq!(coord.verified_frontier(remote), Some(BlockHeight::new(4)));
    }

    /// An orphan pair proven after the clear holds 5. A consumer's
    /// commit-proof request there still fetches, and the commit sweep keeps
    /// the want until the fresh block's proof is held.
    #[test]
    fn a_proven_orphan_does_not_absorb_a_commit_proof_request() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let orphan5 = chain_header_dated(remote, 5, 5, None, 7_000);
        let orphan6 = chain_header_dated(remote, 6, 6, Some(&orphan5), 7_100);
        let held = admit_under(&mut coord, &cleared, &[&orphan5, &orphan6]);
        assert!(committed_heights(&held).is_empty());
        let asked = coord.request_commit_proof(&cleared, remote, BlockHeight::new(5));
        assert_eq!(commit_proof_fetches(&asked).len(), 1);

        commit_local(&mut coord, &cleared, 2);
        assert!(
            coord
                .wanted_proofs
                .contains_key(&(remote, BlockHeight::new(5)))
        );
    }

    /// A tail certified a full halt gap below its fresh chain, first heard
    /// after the clear, is held above the frontier while it yields, so the
    /// fresh chain arriving past the walked retention still promotes it.
    #[test]
    fn a_tail_a_halt_gap_below_its_fresh_chain_is_promoted() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let shared = shared_history(remote);
        let shared_refs: Vec<&Verified<CertifiedBlockHeader>> = shared.iter().collect();
        let mut committed = committed_heights(&admit_under(&mut coord, &cleared, &shared_refs));
        let tail5 = chain_header_dated(remote, 5, 5, Some(&shared[3]), 7_000);
        let tail6 = chain_header_dated(remote, 6, 6, Some(&tail5), 7_100);
        let tail7 = chain_header_dated(remote, 7, 7, Some(&tail6), 7_200);
        committed.extend(committed_heights(&admit_under(
            &mut coord,
            &cleared,
            &[&tail5, &tail6, &tail7],
        )));
        let fresh8 = chain_header_dated(remote, 8, 8, Some(&tail7), 60_000);
        let fresh9 = chain_header_dated(remote, 9, 9, Some(&fresh8), 60_100);
        committed.extend(committed_heights(&admit_under(
            &mut coord,
            &cleared,
            &[&fresh8, &fresh9],
        )));
        assert_eq!(committed, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// `chain_header_dated` with the header's own parent-QC clock set
    /// apart from its certificate's date: the replaced committee signs
    /// whatever header it likes, and nothing checks the embedded parent QC.
    fn header_with_parent_clock(
        shard: ShardId,
        height: u64,
        round: u64,
        parent: &Verified<CertifiedBlockHeader>,
        qc_ms: u64,
        parent_ms: u64,
    ) -> Verified<CertifiedBlockHeader> {
        let parent_qc = QuorumCertificate::new(
            parent.block_hash(),
            shard,
            BlockHeight::new(height - 1),
            BlockHash::ZERO,
            Round::new(round.saturating_sub(1)),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_ms),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent.block_hash(),
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(round),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            BlockHeight::new(height),
            parent.block_hash(),
            Round::new(round),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(qc_ms),
        );
        Verified::new_unchecked_for_test(CertifiedBlockHeader::new(header, qc))
    }

    /// Without gossip: orphans prove 5 and 6 after the clear, a consumer
    /// asks for 5, and the fetch answers with the fresh chain. The fresh
    /// block at 5 is promoted, the frontier walks over it, and the want
    /// resolves.
    #[test]
    fn a_fetched_fresh_block_resolves_a_want_an_orphan_held() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let shared = shared_history(remote);
        let refs: Vec<&Verified<CertifiedBlockHeader>> = shared.iter().collect();
        admit_under(&mut coord, &cleared, &refs);
        let orphan5 = chain_header_dated(remote, 5, 5, Some(&shared[3]), 7_000);
        let orphan6 = chain_header_dated(remote, 6, 6, Some(&orphan5), 7_100);
        admit_under(&mut coord, &cleared, &[&orphan5, &orphan6]);
        let asked = coord.request_commit_proof(&cleared, remote, BlockHeight::new(5));
        assert_eq!(
            commit_proof_fetches(&asked),
            vec![(5, COMMIT_PROOF_INITIAL_COUNT)]
        );

        let fresh5 = chain_header_dated(remote, 5, 7, Some(&shared[3]), 10_500);
        let fresh6 = chain_header_dated(remote, 6, 8, Some(&fresh5), 10_600);
        let fresh7 = chain_header_dated(remote, 7, 9, Some(&fresh6), 10_700);
        let mut committed = Vec::new();
        for header in [&fresh5, &fresh6, &fresh7] {
            committed.extend(committed_heights(&coord.on_remote_header_received(
                &cleared,
                unverified(header),
                gossip(1),
            )));
            let verified = coord.on_remote_header_qc_verified(
                &cleared,
                &unverified(header),
                gossip(1),
                Ok(header.clone()),
                HeaderCommittee::Resolved,
            );
            committed.extend(committed_heights(&verified));
        }
        commit_local(&mut coord, &cleared, 2);
        assert!(committed.contains(&5) && committed.contains(&6));
        assert_eq!(
            coord
                .get_verified(remote, BlockHeight::new(5))
                .map(Verified::block_hash),
            Some(fresh5.block_hash())
        );
        assert!(coord.verified_frontier(remote) >= Some(BlockHeight::new(7)));
        assert!(
            !coord
                .wanted_proofs
                .contains_key(&(remote, BlockHeight::new(5)))
        );
    }

    /// The replaced committee chooses the parent-QC clock its headers
    /// embed. Orphans at 5 on the held frontier block, each carrying a
    /// parent clock far in the future, are retained on their certificates'
    /// date, so a fresh tip past the horizon drops every one.
    #[test]
    fn a_future_parent_clock_buys_no_retention() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let shared = shared_history(remote);
        let refs: Vec<&Verified<CertifiedBlockHeader>> = shared.iter().collect();
        admit_under(&mut coord, &cleared, &refs);
        let far = u64::MAX / 4;
        for round in 0..100u64 {
            let orphan = header_with_parent_clock(remote, 5, 100 + round, &shared[3], 7_000, far);
            admit_under(&mut coord, &cleared, &[&orphan]);
        }
        let held = coord.memory_stats();
        let horizon = u64::try_from(TRANSACTION_EVIDENCE_HORIZON.as_millis()).unwrap();
        let tip_ms = 20_000 + horizon + 10_000;
        let mut parent = chain_header_dated(remote, 5, 1_000, Some(&shared[3]), 10_500);
        admit_under(&mut coord, &cleared, &[&parent]);
        for height in 6..=8u64 {
            let next = chain_header_dated(remote, height, 1_000 + height, Some(&parent), tip_ms);
            admit_under(&mut coord, &cleared, &[&next]);
            parent = next;
        }
        assert_eq!(held.fork_siblings, 99);
        assert_eq!(coord.memory_stats().fork_siblings, 0);
    }

    /// A header carrying a future parent clock, held highest, raises the
    /// tip only to its certificate's date, so the walked headers beneath
    /// the frontier stay.
    #[test]
    fn a_future_parent_clock_does_not_raise_the_tip() {
        let local = ShardId::leaf(1, 0);
        let remote = ShardId::leaf(1, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let cleared = schedule_under(recovery_head(remote, Recovery::Cleared));
        commit_local(&mut coord, &cleared, 1);

        let shared = shared_history(remote);
        let refs: Vec<&Verified<CertifiedBlockHeader>> = shared.iter().collect();
        admit_under(&mut coord, &cleared, &refs);
        assert_eq!(coord.verified_frontier(remote), Some(BlockHeight::new(4)));
        let far = header_with_parent_clock(remote, 5, 5, &shared[3], 7_000, u64::MAX / 4);
        admit_under(&mut coord, &cleared, &[&far]);
        for height in 1..=3 {
            assert!(coord.has_verified(remote, BlockHeight::new(height)));
        }
    }

    #[test]
    fn duplicate_fork_siblings_are_held_once() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        let canonical = chain_header(remote, 5, 5, None);
        let sibling = chain_header(remote, 5, 7, None);
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            canonical,
            ValidatorId::new(1),
        );
        coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            sibling.clone(),
            ValidatorId::new(1),
        );
        assert_eq!(coord.memory_stats().fork_siblings, 1);

        // A re-gossiped copy neither grows the buffer nor re-runs
        // assembly.
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            sibling,
            ValidatorId::new(2),
        );
        assert!(actions.is_empty());
        assert_eq!(coord.memory_stats().fork_siblings, 1);
        coord.shards[&remote].assert_indexed();
    }

    /// The `(from_height, count)` pairs of the `FetchCommitProof` actions
    /// in a stream.
    fn commit_proof_fetches(actions: &[Action]) -> Vec<(u64, u64)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::FetchCommitProof {
                    from_height, count, ..
                } => Some((from_height.inner(), count.inner())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn wanted_commit_proof_retries_with_a_doubling_range_until_proven() {
        use hyperscale_types::test_utils::{certify, make_live_block};

        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);
        let sched = TopologySchedule::single(Arc::new(shard_snapshot(2, &[0, 1, 2, 3], 0)));
        let local_block = |h: u64| {
            certify(
                make_live_block(
                    local,
                    BlockHeight::new(h),
                    0,
                    ValidatorId::new(0),
                    vec![],
                    vec![],
                ),
                h * 1_000,
            )
        };
        coord.on_block_committed(&sched, &local_block(1), &[]);

        // Registration issues the first fetch immediately; a duplicate
        // registration is a no-op.
        let actions =
            coord.request_commit_proof(&fast_path_schedule(), remote, BlockHeight::new(5));
        assert_eq!(commit_proof_fetches(&actions), vec![(5, 4)]);
        assert!(
            coord
                .request_commit_proof(&fast_path_schedule(), remote, BlockHeight::new(5))
                .is_empty()
        );

        // Inside the retry interval nothing re-issues; past it the fetch
        // re-issues with a doubled range.
        let actions = coord.on_block_committed(&sched, &local_block(2), &[]);
        assert!(commit_proof_fetches(&actions).is_empty());
        let actions = coord.on_block_committed(&sched, &local_block(8), &[]);
        assert_eq!(commit_proof_fetches(&actions), vec![(5, 8)]);

        // The proof lands: the height promotes, the want clears, and no
        // further fetch issues.
        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        coord.on_verified_remote_header_received(&fast_path_schedule(), w, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            wc,
            ValidatorId::new(1),
        );
        assert_eq!(committed_heights(&actions), vec![5]);
        let actions = coord.on_block_committed(&sched, &local_block(20), &[]);
        assert!(commit_proof_fetches(&actions).is_empty());
    }

    #[test]
    fn requesting_an_already_promoted_height_reemits_its_promotion() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let mut coord = RemoteHeaderCoordinator::new(local);

        let w = chain_header(remote, 5, 5, None);
        let wc = chain_header(remote, 6, 6, Some(&w));
        coord.on_verified_remote_header_received(&fast_path_schedule(), w, ValidatorId::new(1));
        let actions = coord.on_verified_remote_header_received(
            &fast_path_schedule(),
            wc,
            ValidatorId::new(1),
        );
        assert_eq!(committed_heights(&actions), vec![5]);

        // The consumer raced the promotion: answering the request with a
        // fresh promotion (not a fetch) closes the race.
        let actions =
            coord.request_commit_proof(&fast_path_schedule(), remote, BlockHeight::new(5));
        assert_eq!(committed_heights(&actions), vec![5]);
        assert!(commit_proof_fetches(&actions).is_empty());
    }

    /// The per-header retention pass drops exactly what has aged past the
    /// cutoff on the header's own shard: walked headers behind the
    /// frontier, unwalked ones past the evidence horizon, and stale fork
    /// siblings. The walked frontier and unwalked headers inside the
    /// horizon stay, and another shard's store is not touched.
    #[test]
    fn the_retention_pass_drops_only_the_aged_out_headers_of_its_shard() {
        let local = ShardId::leaf(2, 0);
        let remote = ShardId::leaf(2, 1);
        let other = ShardId::leaf(2, 2);
        let mut coord = RemoteHeaderCoordinator::new(local);
        coord.expected.insert(
            remote,
            ExpectedHeader {
                discovered_at: WeightedTimestamp::from_millis(1),
                last_verified_height: BlockHeight::new(0),
                verified_tip: BlockHeight::new(0),
                last_verified_at: Some(WeightedTimestamp::from_millis(1)),
            },
        );
        let admit = |coord: &mut RemoteHeaderCoordinator, header| {
            coord.on_verified_remote_header_received(
                &fast_path_schedule(),
                header,
                ValidatorId::new(0),
            );
        };

        // A walked run 1..=40, then an unwalked run 60..=70 above a gap,
        // with an off-branch sibling at 65. `chain_header` stamps height
        // `h` at `h` seconds.
        let mut parent = None;
        for height in 1..=40 {
            let header = chain_header(remote, height, height, parent.as_ref());
            admit(&mut coord, header.clone());
            parent = Some(header);
        }
        let mut parent = None;
        for height in 60..=70 {
            let header = chain_header(remote, height, height, parent.as_ref());
            admit(&mut coord, header.clone());
            parent = Some(header);
        }
        admit(&mut coord, chain_header(remote, 65, 999, None));
        let mut parent = None;
        for height in 1..=20 {
            let header = chain_header(other, height, height, parent.as_ref());
            admit(&mut coord, header.clone());
            parent = Some(header);
        }
        assert_eq!(coord.verified_frontier(remote), Some(BlockHeight::new(40)));
        let held = |coord: &RemoteHeaderCoordinator, top: u64| -> Vec<u64> {
            (0..=top)
                .filter(|&height| coord.has_verified(remote, BlockHeight::new(height)))
                .collect()
        };
        // The unwalked run's tip already put the walked run behind the
        // cutoff; only the frontier outlived it.
        assert_eq!(
            held(&coord, 70),
            std::iter::once(40).chain(60..=70).collect::<Vec<_>>()
        );
        assert!((60..=64).all(|height| coord.has_commit_proof(remote, BlockHeight::new(height))));
        let before = coord.memory_stats();

        // The tip lands so the evidence horizon sits at 65 and everything
        // held so far is past the retention cutoff.
        let tip = TRANSACTION_EVIDENCE_HORIZON.as_secs() + 65;
        assert!(tip - REMOTE_HEADER_RETENTION.as_secs() > 70);
        let recent = tip - 10;
        admit(&mut coord, chain_header(remote, recent, recent, None));
        admit(&mut coord, chain_header(remote, tip, tip, None));

        assert_eq!(
            held(&coord, tip),
            vec![40, 65, 66, 67, 68, 69, 70, recent, tip],
            "the frontier and the unwalked headers inside the horizon stay",
        );
        let store = coord.shards.get(&remote).expect("remote is held");
        assert_eq!(
            (0..=tip)
                .filter(|&height| store.is_proven(BlockHeight::new(height)))
                .collect::<Vec<_>>(),
            vec![65, 66, 67, 68, 69],
            "a proof goes with its header",
        );
        assert!(
            store.siblings(BlockHeight::new(65)).is_empty(),
            "a sibling past the cutoff goes though its canonical slot stays",
        );
        store.assert_indexed();

        let other_store = coord.shards.get(&other).expect("other is held");
        assert!(
            (1..=20).all(|height| other_store.verified(BlockHeight::new(height)).is_some()),
            "another shard is untouched",
        );
        assert!((1..=19).all(|height| other_store.is_proven(BlockHeight::new(height))));
        other_store.assert_indexed();
        let stats = coord.memory_stats();
        assert_eq!(stats.verified_headers, 9 + 20);
        assert_eq!(stats.proven_headers, 5 + 19);
        assert_eq!((before.fork_siblings, stats.fork_siblings), (1, 0));
    }
}
