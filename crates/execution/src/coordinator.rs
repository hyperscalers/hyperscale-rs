//! Execution state machine: what this shard runs of each committed
//! transaction, and what it owes once it has.
//!
//! Transactions are grouped into ticks — one provision dependency set
//! within a block — and each tick runs its lifecycle inside a
//! [`TickState`](crate::TickState). What a shard runs of a transaction
//! is its [`Member`], frozen against the trie its committing block
//! carried and read off the [`Classified`] star.
//!
//! # What a shard runs
//!
//! - **Whole.** A transaction on one shard, or one that reaches several
//!   and does not divide: every participant runs every node and settles
//!   on every participant's certificate.
//! - **Divided.** The star is a core with legs around it. A leg runs
//!   where its own state lives and certifies alone; the core bears the
//!   verdict; value between them crosses as an escrow record the
//!   consumer claims. A shard with legs on both sides of the core runs
//!   two members — one issuing at the commit, one delivering once the
//!   core's output has crossed back.
//! - **Settling.** No node at all: a reclaim taking back a crossing
//!   nobody claimed, a retirement deleting records whose claims
//!   committed, or an inherited record a reshape seat decides from the
//!   leaf alone.
//!
//! # How a tick settles
//!
//! A block commits, its cross-shard members are provisioned, and the
//! whole tick dispatches atomically. Validators vote; the tick leader
//! aggregates 2f+1 agreeing on one receipt hash into an execution
//! certificate and broadcasts it. A member settles once every shard it
//! awaits has certified — the core set for a core member, itself for a
//! leg — and the result is a [`Finalization`].
//!
//! # When a counterpart goes silent
//!
//! A leg that issued a crossing is owed an answer. Past the deadline it
//! probes the silent counterpart's cells through a state proof, and what
//! comes back licenses a reclaim, a retirement, or an abandonment
//! record. The ledger of what is still owed is
//! [`UnresolvedTxs`](crate::unresolved::UnresolvedTxs); what counterparts
//! were heard to say is the [`CounterpartMirror`], shared with the vote
//! fence so a record passes exactly where its composer would have
//! offered it.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::Arc;

use hyperscale_core::{
    Action, CrossShardExecutionRequest, FetchIds, FetchRequest, ProtocolEvent, TickBatchOutcome,
};
use hyperscale_engine::legs::{Classified, Licence, Member, Runs, Side};
use hyperscale_engine::{TickEnvironment, build_fee_receipt};
use hyperscale_metrics::{record_reclaim_admitted, record_unresolvable_tx};
use hyperscale_storage::{RecoveredState, TickResolution};
use hyperscale_types::{
    Anchor, Attempt, Block, BlockHash, BlockHeader, BlockHeight, BloomFilter, CertifiedBlock,
    ConsensusPublicKey, CounterpartMirror, Deadline, DeclaredKey, Derivation, ExecutionCertificate,
    ExecutionCertificateVerifyError, ExecutionVote, Finalization, FinalizationHash,
    FinalizationVerifyError, GlobalReceiptRoot, Hash, Inclusion, MerkleInclusionProof, Mode,
    ProvenAnchors, ProvenCells, Provisions, SettledSetVerdict, SettledTxSet, ShardId, ShardTrie,
    StateWrites, StoredReceipt, SubstateKey, TickId, TopologySchedule, TopologySnapshot,
    Transaction, TransactionDecision, TxHash, TxOutcome, TxResolution, UnsettledTx, ValidatorId,
    Verifiable, Verified, WeightedTimestamp, Window, derive_block_transactions,
    settled_set_verdict, tick_leader, tick_leader_at,
};
use tracing::instrument;

use crate::candidates::{Admitted, TickCandidates};
use crate::counterparts::{Counterparts, Offers};
use crate::early_arrivals::{EARLY_VOTE_RETENTION, EarlyArrivalBuffer};
use crate::exec_cert_store::ExecCertStore;
use crate::expected_certs::ExpectedCertTracker;
use crate::finalizations::FinalizationStore;
use crate::gate::{Attested, Gate, gate_certificate};
use crate::lookups::{
    assign_participants, build_provision_requests, ec_has_shard_quorum_power, fetch_keys_covered,
    peers_excluding_self,
};
use crate::outbound_certs::OutboundExecutionCertificateTracker;
use crate::parked::{Parked, ParkedArtifacts, Waiting, Wake};
use crate::provisional::ProvisionalCells;
use crate::provisioning::{ProvisioningTracker, Requirement, requirements_of};
use crate::tick_state::{Admission, Divergence, Membership, TickState};
use crate::ticks::{PendingVoteRetry, RetryEffect, TickRegistry};
use crate::unresolved::{Settleable, Unanswerable, UnresolvedTxs};
use crate::vote_tracker::VoteTracker;

/// One payer-side engagement wait: the transaction, the counterpart
/// shards whose echo its vote waits on, and the signed window end that
/// bounds the wait.
type EngagementWait = (TxHash, BTreeSet<ShardId>, WeightedTimestamp);

/// One transaction a committed block put in flight, as this shard sees
/// it: the body, and the member this shard runs of it.
///
/// The member is built here rather than at each consumer, so what the
/// transaction reaches and what this shard is to it are asked of the one
/// type that answers them — a second `reaches_beyond` over the same set
/// is one more place that answer can drift from the member's.
#[derive(Clone)]
struct CommittedMember {
    tx: Arc<Verifiable<Transaction>>,
    member: Member,
}

/// This shard's members of a committed block's transactions, each under
/// one placement at one anchor: the trie the block committed under, and
/// the answer frozen onto each transaction from here.
fn committed_members(
    classification: &TopologySnapshot,
    local_shard: ShardId,
    transactions: &[Arc<Verifiable<Transaction>>],
) -> Vec<CommittedMember> {
    let trie = classification.shard_trie();
    assign_participants(classification, transactions)
        .into_iter()
        .map(|(tx, participating)| {
            let classified = Classified::freeze(tx.legs(), tx.owners(), trie);
            let side = classified.first_side_at(local_shard);
            CommittedMember {
                member: Member::of(classified, local_shard, side, participating),
                tx,
            }
        })
        .collect()
}

/// The committed block a tick is created against: its identity, and the
/// environment anchors the transactions it commits execute under.
#[derive(Clone, Copy, Debug)]
struct CommittingBlock {
    hash: BlockHash,
    height: BlockHeight,
    /// The block's parent-QC weighted timestamp.
    ts: WeightedTimestamp,
}

/// A tick with entries on the tick chain and no committed fate yet.
struct TickedBatch {
    /// What its abortable members declared they would mutate — the cells
    /// nothing may read until a counterpart's certificate says which
    /// side of each survives.
    ///
    /// Its other members claim nothing: their writes are determined the
    /// moment they execute and readable at once, so a later tick may
    /// fold over them freely. Empty for a tick that ran no member a
    /// counterpart can retract, which is then held only for its own
    /// fate.
    provisional_claims: Vec<(DeclaredKey, Mode)>,
    /// The legs those claims belong to. A tick's fate arrives in halves,
    /// and only the half carrying the legs releases their cells — so the
    /// entry has to know which members that is.
    legs: BTreeSet<TxHash>,
}

/// One composed-but-undispatched tick: the block's identity anchors plus
/// the members that joined at its commit.
struct PendingTick {
    tick: BlockHeight,
    tick_ts: WeightedTimestamp,
    env: TickEnvironment,
    requests: Vec<CrossShardExecutionRequest>,
}

impl PendingTick {
    /// Whether any member runs code drawn from `missing`.
    fn runs_any_of(&self, missing: &BTreeSet<Hash>) -> bool {
        self.requests.iter().any(|request| {
            request
                .transaction
                .as_ref()
                .is_some_and(|body| body.packages().iter().any(|p| missing.contains(p)))
        })
    }
}

/// Data returned when a tick is ready for voting.
///
/// The state machine produces this; the `io_loop` uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this tick belongs to; pairs with `tick_id` to identify the vote target.
    pub block_hash: BlockHash,
    /// Height of the tick-starting block.
    pub block_height: BlockHeight,
    /// BFT-authenticated weighted timestamp at which this tick's outcome is
    /// fixed. Included in the vote payload and the EC canonical hash, so all
    /// validators aggregate under the same identifier.
    pub vote_anchor_ts: WeightedTimestamp,
    /// Tick identifier; unique within `block_hash`.
    pub tick_id: TickId,
    /// Merkle root over per-tx outcome leaves (cross-shard agreement).
    pub global_receipt_root: GlobalReceiptRoot,
    /// Per-tx outcomes in tick order.
    pub tx_outcomes: Vec<TxOutcome>,
}

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    /// Total receipts held across all in-flight ticks, awaiting finalization.
    pub tick_execution_receipts: usize,
    /// Finalizations cached in memory until their proposing block commits.
    pub finalizations: usize,
    /// In-flight tick states (created, not yet finalized or evicted).
    pub ticks: usize,
    /// Committed transactions still owed an outcome.
    pub unresolved_txs: usize,
    /// Per-tick vote trackers awaiting quorum.
    pub vote_trackers: usize,
    /// Buffered execution votes waiting for their tick to begin.
    pub early_votes: usize,
    /// Expected EC arrivals from remote shards we're awaiting.
    pub expected_exec_certs: usize,
    /// Transactions with a provision bundle absorbed.
    pub absorbed_provisions: usize,
    /// Candidates with a requirement set filed.
    pub required_provision_shards: usize,
    /// Ticks whose local EC has been emitted.
    pub ticks_with_ec: usize,
    /// Vote retries scheduled for resend after rotation timeout.
    pub pending_vote_retries: usize,
    /// Active tx → tick assignments in the registry.
    pub tick_assignments: usize,
    /// Early tick attestations buffered before local routing.
    pub early_attestations: usize,
    /// Buffered ECs awaiting tx assignment routing.
    pub pending_routing: usize,
    /// Expected ECs that have already been fulfilled (kept for diagnostics).
    pub fulfilled_exec_certs: usize,
    /// Outbound ECs retained for re-broadcast to remote shards.
    pub outbound_certs: usize,
    /// Commit-proven remote source blocks within retention.
    pub proven_remote_blocks: usize,
    /// Cross-shard ECs deferred on their source block's commit proof. A
    /// sustained rise means a source shard certifies without proving
    /// commits — the fork/withholding signature.
    pub unproven_ecs: usize,
}

/// The name a housekeeping member over inherited records takes on the
/// chain that inherited them.
///
/// Derived from the transaction that issued the crossings and the record
/// cells being settled, so every replica at one frontier reaches the same
/// name and no two members ever share one. It is not the issuing
/// transaction's own hash: that transaction belongs to a chain that has
/// ended, this one never committed it, and a receipt naming it would be a
/// verdict this chain has no standing to reach.
fn inherited_member_name(issued_by: TxHash, records: &[SubstateKey]) -> TxHash {
    let keys: Vec<Vec<u8>> = records.iter().map(|key| key.to_bytes().to_vec()).collect();
    let mut parts: Vec<&[u8]> = vec![b"hyperscale.inherited.records", &issued_by.0.0];
    parts.extend(keys.iter().map(Vec::as_slice));
    TxHash::from(Hash::from_parts(&parts))
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionCoordinator {
    /// Finalizations ready for block inclusion, keyed by
    /// `TickId`. Terminal-state lookup surface for tick-id fetches,
    /// tx-membership queries, and proposal building. Held behind an
    /// `Arc` and shared across same-shard `ExecutionCoordinator`s so
    /// `IoLoop`'s sync-inventory bloom and elided-block rehydration read
    /// from one canonical store per shard rather than vnode-0's
    /// incidentally-convergent copy.
    finalized: Arc<FinalizationStore>,

    /// Current committed height for pruning stale entries.
    committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. "Now" reference for timeouts that must be deterministic across
    /// validators and independent of block production rate.
    committed_ts: WeightedTimestamp,

    /// Anchor selecting the committee that governs the last locally committed
    /// block — the anchor its *parent* carried, since a block's committee
    /// keys on its parent. What tick and provision classification resolves
    /// against, so every replica groups a block's transactions exactly as the
    /// proposer built them and the verifier validated them.
    committed_committee_anchor_wt: WeightedTimestamp,

    // ═══════════════════════════════════════════════════════════════════════
    // Tick dispatch
    // ═══════════════════════════════════════════════════════════════════════
    /// Ticks composed at commit but not yet dispatched, in height order.
    /// Ticks execute serially — each output is the next tick's baseline —
    /// so the head dispatches only when no tick is in flight.
    pending_ticks: VecDeque<PendingTick>,

    /// Whether a dispatched tick's `ExecutionBatchCompleted` is still
    /// outstanding.
    tick_in_flight: bool,

    /// Packages the beacon registers that this node does not hold the
    /// bytes for, replaced wholesale at each beacon commit.
    ///
    /// A queued tick whose members run one of them waits at the dispatch
    /// head until the fetch lands. It cannot be consulted where the tick
    /// is composed: membership is what the committee's votes are cast
    /// over, so it has to be a function of committed chain state alone,
    /// and a node's holdings are not that. Dispatch is where the
    /// difference is local — the tick still answers for exactly the
    /// members it was composed with, whenever it runs.
    missing_packages: BTreeSet<Hash>,

    /// The highest tick whose output is on the tick chain. A resolution
    /// is emitted only once its tick's tick has appended, so a commit
    /// racing ahead of a queued tick cannot resolve a tick the chain has
    /// never seen.
    last_completed_tick: BlockHeight,

    /// Ticks with entries on the tick chain whose fate is still open. A
    /// tick absent from the map — never dispatched, or committed by a
    /// shard past the execution window — resolves nothing.
    ticked: BTreeMap<TickId, TickedBatch>,

    /// The blocks a restart has to replay before this coordinator's
    /// account of what is in flight matches its peers'. Construction has
    /// no schedule to compose against, so they wait for
    /// [`on_committed_state_restored`](Self::on_committed_state_restored)
    /// and are empty from then on.
    replay_blocks: Vec<Verified<CertifiedBlock>>,

    /// The lowest height a tick may be *dispatched* at.
    ///
    /// A tick reads its baseline as of the height below it, and a store
    /// answers a historical read only inside its retention horizon — so a
    /// replay reaching further back than that composes its ticks and runs
    /// none of them. Composition is what fixes which tick holds a member,
    /// and every replica of the shard has to agree on that whatever it
    /// can still execute; the baseline is what the store cannot answer
    /// for. What such a tick left is seated from the receipts that
    /// committed it instead. `GENESIS` on every path but a replay, where
    /// every height qualifies.
    compose_from: BlockHeight,

    /// Tick fates known but not yet emittable, each with the tick that
    /// carries its entries. Drained whenever a tick completes or a block
    /// commits.
    pending_tick_resolutions: Vec<(TickId, BlockHeight, TickResolution)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Provisioning
    // ═══════════════════════════════════════════════════════════════════════
    /// Owns the verified-provision map, required/received remote-shard sets
    /// per tx, and the `ConflictDetector` used for bidirectional node-ID
    /// overlap detection. Wraps the detector as a field so conflict flows
    /// stay co-located with the provision state they reason about.
    provisioning: ProvisioningTracker,

    // ═══════════════════════════════════════════════════════════════════════
    // Per-tick execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Committed transactions no tick has taken yet, each waiting on the
    /// provisions, engagement echoes or cells it needs to reach its
    /// outcome. Nothing here has said anything, so nothing here is owed.
    candidates: TickCandidates,

    /// Owns in-flight `TickState`s, their `VoteTracker`s, the
    /// certificate-dispatched gate, vote-retry bookkeeping, and the
    /// `tx_hash → TickId` reverse index. Every per-tick mutation the
    /// coordinator drives flows through this field.
    ticks: TickRegistry,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (buffered until tracking starts at block commit)
    // ═══════════════════════════════════════════════════════════════════════
    /// Buffers execution votes and cross-shard ECs that arrived before the
    /// local tick was tracked. Drained on block commit (ECs) and on leader
    /// tracker creation (votes).
    early: EarlyArrivalBuffer,

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking (Fallback Detection)
    // ═══════════════════════════════════════════════════════════════════════
    /// Tracks expected ECs from remote block headers and drives timeout-based
    /// fallback fetches when they don't arrive. Owns both the active-expectation
    /// set and the fulfilled-tombstone set used to guard against duplicate
    /// headers re-opening closed expectations.
    expected_certs: ExpectedCertTracker,

    // ═══════════════════════════════════════════════════════════════════════
    // Outbound EC Retention (target → source delivery guarantee)
    // ═══════════════════════════════════════════════════════════════════════
    /// Retains ECs the tick leader broadcast to remote shards and re-emits
    /// them on a deterministic interval until the tick finalizes locally
    /// (positive ACK signal) or the safety horizon elapses. Symmetric to
    /// `OutboundProvisionTracker` on the source side.
    outbound_certs: OutboundExecutionCertificateTracker,

    /// Aggregated local-shard execution certificates awaiting block commit.
    /// Held behind an `Arc` and shared with the `io_loop` so the inbound EC
    /// fetch handler can serve cross-shard fallback requests without taking
    /// a coordinator lock. Populated on local aggregation and on verifying
    /// a local-shard EC received via broadcast; evicted in
    /// `remove_finalization` once the containing block commits.
    exec_certs: Arc<ExecCertStore>,

    /// In-flight verifications, keyed by each artifact's
    /// [`Attested::slot`]. A flooding peer would otherwise re-trigger a
    /// dispatch on every byte-identical retransmit.
    pending_verifications: HashSet<Hash>,

    /// Everything held until evidence lets it through — a beacon epoch,
    /// a source block's commit proof, a departed partner's settled set —
    /// re-driven through the handler it arrived by ([`Self::release`]).
    parked: ParkedArtifacts,

    /// What counterparts have said about the transactions in flight
    /// here, and what this shard still asks them: the ledger of what is
    /// owed an outcome, the mirror the vote fence reads, the questions
    /// out and the proofs fetched back. The tick machine reads the
    /// ledger through it.
    counterparts: Counterparts,

    /// This validator's identity.
    me: ValidatorId,

    /// This validator's home shard.
    local_shard: ShardId,
}

impl ExecutionCoordinator {
    /// Create a new execution state machine with its own fresh stores and a
    /// genesis commit frontier. For hosts running multiple same-shard
    /// validators, prefer [`Self::with_shared_stores`] to share one set of
    /// stores across every coordinator in the shard; for a recovered chain,
    /// it also seeds the frontier from storage.
    #[must_use]
    pub fn new(me: ValidatorId, local_shard: ShardId) -> Self {
        Self::with_shared_stores(
            me,
            local_shard,
            &RecoveredState::default(),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        )
    }

    /// Create a new execution state machine sharing both externally-owned
    /// `ExecCertStore` and `FinalizationStore`. Same-shard vnodes share
    /// one set of stores so the `IoLoop`'s inbound fetch handler and
    /// sync-inventory bloom read from a single canonical view per shard
    /// rather than vnode-0's incidentally-convergent copy.
    ///
    /// The commit-frontier scalars seed from where execution's own
    /// account resumes, which is not where consensus's does: a restart
    /// replays from the block committing the oldest transaction still
    /// owed an outcome, so the frontier seeds at the block below that one
    /// and the replay carries it up to the tip. With nothing owed there
    /// is nothing to replay and the recovered tip is the frontier.
    ///
    /// Either way the seed keeps the next commit on the exact carry path —
    /// height-contiguous, its committee anchor the previous block's — where
    /// a zero frontier would take the gap fallback and classify that
    /// block's ticks under the window it opens: a replica restarted just
    /// below an epoch cut that a reshape moves would group ticks
    /// differently from its peers and split execution votes. A seeded
    /// frontier also gives pre-first-commit bookkeeping (expected-cert
    /// ages, conflict detection) a real clock instead of a zero one.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub fn with_shared_stores(
        me: ValidatorId,
        local_shard: ShardId,
        recovered: &RecoveredState,
        exec_certs: Arc<ExecCertStore>,
        finalized: Arc<FinalizationStore>,
        proven_anchors: Arc<ProvenAnchors>,
        proven_cells: Arc<ProvenCells>,
        evidence: Arc<CounterpartMirror>,
    ) -> Self {
        // Execution resumes below the first block it replays, so the
        // replay carries the frontier up to the tip rather than starting
        // from it. Without the block under the floor there is no clock to
        // carry, and the first block replayed classifies under its own
        // anchor — the same fallback a chain with no history takes, which
        // a genesis frontier is what selects.
        let resume = recovered
            .replay
            .blocks
            .first()
            .map(|certified| (certified.block().height(), recovered.replay.anchor_wt));
        let (committed_height, committed_block_anchor_wt) = match resume {
            Some((first, Some(anchor))) => (first.saturating_sub(1), anchor),
            Some((_, None)) => (BlockHeight::GENESIS, WeightedTimestamp::ZERO),
            None => (recovered.committed_height, recovered.block_anchor_wt()),
        };
        // Whatever seeds the height seeds this too: the block above is
        // contiguous, so it carries `committed_ts` into the slot before
        // anything classifies against it.
        let committed_committee_anchor_wt = match resume {
            Some(_) => committed_block_anchor_wt,
            None => recovered.committee_anchor_wt(),
        };
        Self {
            counterparts: Counterparts::seated(
                local_shard,
                proven_anchors,
                proven_cells,
                evidence,
                &recovered.inherited_records,
            ),
            finalized,
            committed_height,
            committed_ts: committed_block_anchor_wt,
            committed_committee_anchor_wt,
            pending_ticks: VecDeque::new(),
            missing_packages: BTreeSet::new(),
            tick_in_flight: false,
            last_completed_tick: BlockHeight::GENESIS,
            ticked: BTreeMap::new(),
            replay_blocks: recovered.replay.blocks.clone(),
            compose_from: recovered.replay.compose_from,
            pending_tick_resolutions: Vec::new(),
            candidates: TickCandidates::new(local_shard),
            ticks: TickRegistry::new(),
            early: EarlyArrivalBuffer::new(),
            provisioning: ProvisioningTracker::new(),
            expected_certs: ExpectedCertTracker::new(),
            outbound_certs: OutboundExecutionCertificateTracker::new(),
            exec_certs,
            pending_verifications: HashSet::new(),
            parked: ParkedArtifacts::default(),
            me,
            local_shard,
        }
    }

    /// Reference to the shared finalization store. The `io_loop`
    /// clones this `Arc` into its `SharedCaches` so sync-inventory
    /// blooms and elided-block rehydration read from a single canonical
    /// per-shard store rather than vnode-0's incidentally-convergent
    /// copy.
    #[must_use]
    pub const fn finalization_store(&self) -> &Arc<FinalizationStore> {
        &self.finalized
    }

    /// Reference to the shared execution-certificate store. The `io_loop`
    /// clones this `Arc` into its `SharedCaches` so the inbound EC fetch
    /// handler can read aggregated local-shard certificates without
    /// acquiring a coordinator lock.
    #[must_use]
    pub const fn exec_cert_store(&self) -> &Arc<ExecCertStore> {
        &self.exec_certs
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tick Assignment
    // ═══════════════════════════════════════════════════════════════════════════

    /// The committed block's **anchored** committee — `at_for_shard(local_shard,
    /// anchor_wt)`, the same snapshot the proposer classified `ticks` against
    /// and the verifier validated against. Both of those resolve a block's
    /// committee from its parent, so `anchor_wt` is
    /// [`Self::committed_committee_anchor_wt`], not the block's own: the two
    /// straddle an epoch cut once per window, and a reshape cut there changes
    /// the shard set `compute_ticks` routes over.
    ///
    /// Tick and provision classification at commit keys on it, not the
    /// `ArcSwap` head, so every replica groups a block's transactions
    /// identically across a reshape boundary (a head-flipped replica would
    /// otherwise split execution votes). Falls back to the head only if the
    /// window was evicted — unreachable for a just-committed block, whose
    /// committee resolved at verification.
    /// The committee this shard was under at `anchor_wt`, or the head
    /// where the schedule names none.
    ///
    /// The fallback is reached in one shape that matters: a split child
    /// replaying the window it inherited asks about an anchor before its
    /// own cut, where no snapshot names it at all — `Evicted`, not a
    /// transient lag — and there is no committee of its own to find. The
    /// head is then the only one it has, and it classifies the inherited
    /// content the way the child's own keyspace is cut rather than the
    /// way its parent's was.
    ///
    /// That is a reading of the present, which is what the callers here
    /// want: they ask who is party to a transaction *now*, to put a
    /// question to a counterpart that can answer it. A caller wanting
    /// the classification the content was committed under must not use
    /// this — that is the block's own anchor trie, and phase 5 removed
    /// the last consumer that confused the two.
    fn classification_committee<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        anchor_wt: WeightedTimestamp,
    ) -> &'t TopologySnapshot {
        topology_schedule
            .at_for_shard(self.local_shard, anchor_wt)
            .map_or_else(
                || topology_schedule.head().as_ref(),
                |(snapshot, _)| snapshot.as_ref(),
            )
    }

    /// The trie that says who was party to a transaction.
    ///
    /// One accessor rather than an anchor chosen per call site, because
    /// the two sites that ask it have to agree: composition derives an
    /// abandonment's participants from it, and the finalize gate
    /// re-derives the same set to put the fence's question to. A window
    /// later resolves a departed counterpart's *successor*, so a gate
    /// reading a different anchor than composition would ask about a
    /// shard that was never party — and pass, because a live successor is
    /// what [`settled_set_verdict`] steps over.
    ///
    /// The anchor is the block's committee anchor, not its own timestamp:
    /// the two straddle an epoch cut once per window, and it is the
    /// former that classified the block's content.
    fn counterpart_trie<'t>(&self, topology_schedule: &'t TopologySchedule) -> &'t ShardTrie {
        self.classification_committee(topology_schedule, self.committed_committee_anchor_wt)
            .shard_trie()
    }

    /// Set up per-tick execution state for a newly committed block.
    ///
    /// For each distinct tick, creates a [`TickState`], records tx → tick
    /// assignments, and pre-populates provisions that arrived before the
    /// block.
    ///
    /// Emits `ExecuteTransactions` actions
    /// for ticks that are fully provisioned at creation time: single-shard
    /// ticks always qualify; cross-shard ticks do when all required provisions
    /// arrived before block commit.
    ///
    /// Returns the emitted dispatch actions plus any early execution votes
    /// that need to be replayed through `dispatch_execution_vote()`.
    /// Register a new cross-shard tick's transactions: the dependency set
    /// execution waits on and the engagement echoes the payer's vote
    /// waits on.
    fn register_cross_shard_txs(
        &mut self,
        classification: &TopologySnapshot,
        txs: &[CommittedMember],
    ) -> Vec<EngagementWait> {
        let local_shard = self.local_shard;
        let mut engagement_waits: Vec<EngagementWait> = Vec::new();

        for CommittedMember { tx, member } in txs {
            let tx_hash = tx.hash();
            let classified = member.classified();
            let participating = member.reach();
            // A divided member waits on its execution scope minus itself
            // and on the crossings its legs consume, and on nothing else.
            // Its inbound escrow is its engagement — reclaimable if
            // nothing follows — and the crossing bundle it consumes is
            // its counterpart's commitment, so neither half of the
            // engagement exchange is filed, and it runs under its own
            // committing block's clock.
            if classified.decomposed() {
                self.provisioning
                    .record_required(tx_hash, requirements_of(member, tx.legs()));
                continue;
            }
            let remote_participants = || -> BTreeSet<ShardId> {
                participating
                    .iter()
                    .filter(|&&s| s != local_shard)
                    .copied()
                    .collect()
            };

            // The payer shard votes only once every counterpart has echoed
            // its engagement — its own commitment of the transaction — or
            // the window closed without one. Keyed on the same participant
            // set the tick was grouped by, so every replica waits on the
            // same shards.
            if classification
                .shard_trie()
                .shard_for_prefix(tx.body().fee_payer)
                == local_shard
            {
                engagement_waits.push((
                    tx_hash,
                    remote_participants(),
                    tx.validity_range().end_timestamp_exclusive,
                ));
            }

            // The dependency set is what execution waits for: the shards
            // owning the transaction's read set, plus — on a non-payer
            // shard — the payer shard, whose bundle is the engagement
            // evidence and flows even with empty entries. Only the payer's
            // own commutative leg records an empty requirement and
            // dispatches without waiting.
            let trie = classification.shard_trie();
            let mut remote_shards: BTreeSet<ShardId> = tx
                .routing()
                .provision_prefixes
                .iter()
                .map(|prefix| trie.shard_for_prefix(*prefix))
                .filter(|&s| s != local_shard)
                .collect();
            let payer_shard = trie.shard_for_prefix(tx.body().fee_payer);
            if payer_shard != local_shard {
                remote_shards.insert(payer_shard);
                // The payer's bundle carries the transaction clock;
                // remember whose entry to read it from at dispatch.
                self.provisioning.record_payer_shard(tx_hash, payer_shard);
            }
            self.provisioning.record_required(
                tx_hash,
                remote_shards
                    .into_iter()
                    .map(Requirement::CommittedState)
                    .collect(),
            );
        }

        engagement_waits
    }

    /// Record what a committed block puts in flight: the ledger entry it
    /// owes an outcome for, the provisions and engagement echoes its
    /// cross-shard members wait on, and the candidate itself.
    ///
    /// `ts` is the committing block's, which is what a
    /// member executes under however many ticks later it runs — so a
    /// replay of the chain passes the anchors each transaction's own
    /// block carried rather than the tip's.
    ///
    /// Nothing executes here. Whether a transaction can reach its outcome
    /// at this commit is composition's question, asked again at every one.
    fn register_committed_txs(
        &mut self,
        classification: &TopologySnapshot,
        ts: WeightedTimestamp,
        transactions: &[Arc<Verifiable<Transaction>>],
    ) {
        let local_shard = self.local_shard;
        let members = committed_members(classification, local_shard, transactions);
        // The ledger takes the transactions themselves, each with the
        // classification frozen here. What it needs of them — when they
        // expire, what they reserved, what they reach outside this shard,
        // what this shard is to them — is theirs and this shard's, so a
        // rebuild reads the same account off the same blocks however
        // long after.
        self.counterparts.ledger.register_committed(
            members
                .iter()
                .map(|committed| (&committed.tx, committed.member.classified())),
        );
        let reaches_beyond: Vec<CommittedMember> = members
            .iter()
            .filter(|committed| committed.member.reaches_beyond())
            .cloned()
            .collect();
        let engagement_waits = if reaches_beyond.is_empty() {
            Vec::new()
        } else {
            self.register_cross_shard_txs(classification, &reaches_beyond)
        };

        for CommittedMember { tx, member } in members {
            // Block-container entries decoded from the wire land as
            // `Unverified`; lift via `from_persisted` under the same
            // BFT-transitive trust that gates the containing block. Honest
            // live-consensus blocks already carry `Verified` entries (the
            // `.into_verified()` arm short-circuits without re-validating).
            let verified: Arc<Verified<Transaction>> = match (*tx).clone().into_verified() {
                Ok(v) => Arc::new(v),
                Err(raw) => Arc::new(Verified::<Transaction>::from_persisted(raw)),
            };
            self.candidates.register(
                verified,
                member.reach().clone(),
                ts,
                member.classified().clone(),
            );
        }

        for (tx_hash, counterparts, validity_end) in engagement_waits {
            self.candidates.record_engagement_wait(
                tx_hash,
                counterparts,
                Deadline::of(validity_end).at(),
            );
        }
    }

    /// Replay the committed chain from where this coordinator's account
    /// of what is in flight has to resume.
    ///
    /// Tick state does not survive a restart and the chain does. Both
    /// halves of what was lost — which tick holds which transaction, and
    /// what each tick's baseline was — are functions of committed content
    /// alone, so re-driving the ordinary commit path over the stored
    /// blocks reproduces them exactly. A replica that skipped this would
    /// compose those transactions into a tick of its own, and its peers'
    /// certificate for that height would come back under a root it never
    /// computed.
    ///
    /// Two reaches, because a replay has two jobs. Composition runs over
    /// every block the window holds, which runs back as far as an
    /// undischarged record; execution runs only over what the store can
    /// still anchor a baseline at. Below
    /// [`compose_from`](Self::compose_from) the ticks compose and none is
    /// dispatched — nothing is lost there, because such a tick was
    /// settled by a fate the replay reads off the chain, and what it left
    /// is seated from the receipts that committed it.
    ///
    /// The blocks arrive with the provision bundles they carried already
    /// reattached, so a leg composes here on the evidence it composed on
    /// the first time rather than waiting for a fetch nobody will answer.
    ///
    /// Deferred to here rather than done at construction because
    /// composition needs a topology, and there is none until the schedule
    /// is up. Idempotent: the payload is taken, and a live commit that
    /// beat this call has already advanced the frontier past it.
    pub fn on_committed_state_restored(
        &mut self,
        topology_schedule: &TopologySchedule,
        derivation: &dyn Derivation,
    ) -> Vec<Action> {
        let blocks = std::mem::take(&mut self.replay_blocks);
        if blocks.is_empty() {
            return Vec::new();
        }
        // Provision deadlines stamp against this clock, which a commit
        // would have advanced before any of this ran.
        self.provisioning.advance_clock(self.committed_ts);

        tracing::info!(
            shard = %self.local_shard,
            blocks = blocks.len(),
            from = %self.committed_height.next(),
            "Replaying the chain the restart lost execution state for"
        );

        // Every settled tick the replay is below the store's reach to
        // re-run, seated on the chain before the first one it does run
        // reads a baseline that has to carry it.
        let mut actions = self.restored_ticks(&blocks);
        for certified in &blocks {
            // The replay window came off the store, so nothing derived
            // these on the way in.
            derive_block_transactions(certified.block(), derivation);
            // The whole of what a commit does to execution, in the order
            // a commit does it. A finalization the replay recomposes but
            // never releases leaves its members assigned to a tick that
            // has already settled — and a leg's reclaim, which is admitted
            // only where no tick speaks for the transaction, is then held
            // out for as long as the entry lives.
            self.cleanup_committed_finalizations(certified.block().certificates());
            actions.extend(self.on_block_committed(topology_schedule, certified));
        }
        actions
    }

    /// Seat the ticks the replay runs none of on the chain, from what the
    /// receipts that settled them say they left.
    ///
    /// A tick composed below [`compose_from`](Self::compose_from) is one
    /// no replay of this replica's re-runs, and its writes reach the base
    /// only at the block that committed its finalization. Every tick the
    /// replay *does* run below that block reads a baseline the base has
    /// not caught up to and the chain no longer holds — a baseline nobody
    /// else computed. The receipts state exactly what the base gains and
    /// where, which is all such a baseline is missing.
    ///
    /// Ahead of the replay rather than inside it, because the block that
    /// settles a tick can sit above the block the settlement is owed to.
    ///
    /// Only the settlements that committed at or above that height, since
    /// the lowest baseline the replay reads is the one below it and the
    /// base already carries everything settled there.
    fn restored_ticks(&self, blocks: &[Verified<CertifiedBlock>]) -> Vec<Action> {
        let mut resolutions: Vec<(TickId, TickResolution)> = Vec::new();
        for certified in blocks {
            let block = certified.block();
            if block.height() < self.compose_from {
                continue;
            }
            for fw in block.certificates().iter() {
                let fw = fw.as_unverified();
                let tick_id = *fw.tick_id();
                if tick_id.block_height() >= self.compose_from {
                    continue;
                }
                let writes: Vec<(TxHash, StateWrites)> = fw
                    .receipts()
                    .iter()
                    .filter_map(|receipt| {
                        Some((receipt.tx_hash, receipt.consensus.writes()?.clone()))
                    })
                    .collect();
                if writes.is_empty() {
                    continue;
                }
                resolutions.push((
                    tick_id,
                    TickResolution::Restored {
                        height: block.height(),
                        writes,
                    },
                ));
            }
        }
        if resolutions.is_empty() {
            return Vec::new();
        }
        vec![Action::ResolveTicks { resolutions }]
    }

    /// Compose this commit's tick and set it up to be attested.
    ///
    /// The tick takes the candidates that can reach their outcome in it
    /// and the transactions past their deadline that nothing else will,
    /// and nothing else. That is what makes it votable the moment its
    /// batch returns: every member of a tick has an outcome there, so no
    /// member of one waits on another.
    ///
    /// Returns the tick, if the commit composed one, and any early votes
    /// its leader can now replay.
    /// Admit into the tick being composed everything this commit
    /// abandons: past its deadline, with no shard left that could settle
    /// it.
    ///
    /// Read after composition's own assignments, so a member that just
    /// joined this tick is not taken from it — the tick that holds a
    /// transaction is the one that speaks for it.
    ///
    /// Each joins undispatched, reaching the shards its committing block
    /// named. Those are what routes this tick's certificate to the
    /// counterparts still waiting on a verdict for it — the abort is
    /// dominant, so their coverage closes on it — and what the fence
    /// asks its question about. Nothing is awaited: an abort needs no
    /// counterpart's verdict, so the whole shape's one set serves.
    fn admit_abandoned(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick_id: TickId,
        state: &mut TickState,
    ) {
        let local_shard = self.local_shard;
        let trie = self.counterpart_trie(topology_schedule);
        for entry in self.abandonable(tick_id) {
            let UnsettledTx {
                tx_hash,
                declared_work,
                charge,
                ..
            } = entry;
            // A tick that held the member can never speak for it — its
            // coverage will not close — and its other legs would wait on
            // that coverage forever. It goes with the member; the rest of
            // its members reach their own deadlines instead.
            if let Some(held_by) = self.ticks.tick_assignment(tx_hash) {
                self.discard_tick(held_by);
            }
            let mut participating = self.counterparts.ledger.counterparts(tx_hash, trie);
            participating.insert(local_shard);
            state.admit(
                tx_hash,
                Membership::whole(participating).settling(),
                declared_work,
                Admission::Aborted,
            );
            // An abandonment reaches no engine, so the charge its verdict
            // settles is built here rather than read off a result. The
            // floor is owed whether or not the transaction ever ran: the
            // reservation engaged when its block committed it, and an
            // abort that released it without burning would price an
            // attempt nobody could execute below the success it was
            // competing with.
            //
            // Fees never move cross-shard, so only the shard holding the
            // vault settles it — the same question the engine asks of the
            // payers it prices.
            if trie.shard_for_prefix(charge.vault.owner) == local_shard {
                let fee =
                    build_fee_receipt(local_shard, trie, tx_hash, charge.vault, charge.amount);
                state.record_fee_receipt(StoredReceipt::synced(tx_hash, Arc::new(fee)));
            }
            self.candidates.remove(tx_hash);
            self.ticks.assign_tx(tx_hash, tick_id);
            self.counterparts.ledger.certify(tx_hash);
        }
    }

    /// Drop every delivering candidate the delivery window has closed
    /// on, and what no candidate waits for any more.
    ///
    /// Past the close no tick can take the member, and a mixed shard's
    /// delivering candidate is removed by nothing else — its ledger entry
    /// is the leg's, and a leg is never abandoned. What was provisioned
    /// belongs to the candidates waiting on it, and a mixed shard's
    /// delivering member is one until its own tick takes it.
    fn sweep_candidates(&mut self) {
        self.candidates.drop_closed_deliveries(self.committed_ts);
        let candidates = &self.candidates;
        self.provisioning
            .sweep(self.committed_ts, |tx_hash| candidates.contains(tx_hash));
    }

    /// Admit into the tick being composed every reclaim a committed
    /// record has licensed: the leg entries whose core, the record says,
    /// can never claim what they issued.
    ///
    /// Each joins dispatched and awaiting nobody but this shard, since
    /// its own certificate is the whole of its settlement; reserving
    /// nothing, since no block took a reservation for it; and running no
    /// node, since the engine takes the crossings back on the cell's own
    /// evidence. A tick still speaking for the transaction is left to:
    /// the reclaim waits for the leg's own finalization to commit.
    fn admit_reclaims(
        &mut self,
        tick_id: TickId,
        tick_ts: WeightedTimestamp,
        state: &mut TickState,
        requests: &mut Vec<CrossShardExecutionRequest>,
    ) {
        let local_shard = self.local_shard;
        for Settleable {
            tx_hash,
            body: transaction,
            classified,
            charged,
        } in self.counterparts.ledger.reclaimable()
        {
            if self.ticks.tick_assignment(tx_hash).is_some() {
                continue;
            }
            self.counterparts.ledger.admit_reclaim(tx_hash);
            record_reclaim_admitted();
            // A mixed shard's delivering member waits on what the core
            // returns, and the evidence this reclaim is composed from is
            // that the core never claimed. Nothing is coming, so the
            // candidate goes with the leg it was registered beside.
            self.candidates.remove(tx_hash);
            let records = classified.records_issued(local_shard);
            // The plan reads no body — every cell is the record's — but
            // the price still follows the vault, and this is the shard
            // that holds it.
            self.seat_settling(
                tick_id,
                tick_ts,
                state,
                requests,
                tx_hash,
                Some(transaction),
                records,
                Licence::Unclaimed,
                charged,
            );
        }
    }

    /// Admit into the tick being composed the records this shard
    /// inherited with a prefix whose claim it can now read.
    ///
    /// One member per issuing transaction, under a name of this chain's
    /// own ([`inherited_member_name`]) rather than the transaction's.
    /// The transaction was decided on a chain that has ended, and this
    /// one never committed it: naming it here would put a second verdict
    /// on a transaction nothing local can speak for, and would offer the
    /// chain a resolution its own pre-cut rule exists to refuse. What
    /// this shard does decide is the housekeeping itself, which is
    /// nobody else's.
    ///
    /// The member carries the records and no body; whether each is
    /// credited back or deleted is the engine's to decide against the
    /// claim cell, which is the only reader holding a snapshot.
    ///
    /// What bounds the admission is the answer, and every form of it is
    /// committed content, so every replica at one frontier admits the
    /// same set. Where the claim routes here the engine reads the cell
    /// against its own snapshot, inside the window an absent claim means
    /// something in. Where it routes elsewhere the answer is the proof a
    /// block carried, folded before this composes.
    ///
    /// The window is the lapse for every record, not the claim. A leaf
    /// does not name its consumer's role, so a delivery-consumed record
    /// read under the claim window would be judged absent one validity
    /// range before its consumer could honestly have written the cell.
    /// The lapse is the later of the two and is honest for both — and
    /// past it no core shard of any arity can still commit, so the
    /// silence is final however wide the core was.
    fn admit_inherited(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick_id: TickId,
        tick_ts: WeightedTimestamp,
        state: &mut TickState,
        requests: &mut Vec<CrossShardExecutionRequest>,
    ) {
        if self.counterparts.inherited.is_empty() {
            return;
        }
        let Some(committee) = topology_schedule.at(tick_ts) else {
            return;
        };
        let trie = committee.shard_trie();
        let local_shard = self.local_shard;
        // One licence per issuing transaction, so records answered the
        // same way settle together and a record still waiting holds
        // nothing back.
        let mut due: BTreeMap<(TxHash, Licence), Vec<SubstateKey>> = BTreeMap::new();
        for (key, record) in &self.counterparts.inherited {
            let claim = record.cell.consumer_claim;
            let licence = if trie.shard_for_prefix(claim.owner) == local_shard {
                // This shard holds the cell, so the engine reads it
                // against its own snapshot — the same licence, answered
                // without a fetch.
                Window::Lapse
                    .of(record.deadline())
                    .contains(&tick_ts)
                    .then_some(Licence::OwnLeaf)
            } else {
                // The cell is elsewhere, and what decides it is the
                // claim a block carried: present, the consumer holds
                // the crossing and the record is deleted; absent past
                // the lapse, nobody took it and the value goes back.
                match record.answer {
                    Some(Inclusion::Present(_)) => Some(Licence::Accepted),
                    Some(Inclusion::Absent) => Some(Licence::Unclaimed),
                    None => None,
                }
            };
            let Some(licence) = licence else {
                continue;
            };
            due.entry((record.cell.tx, licence)).or_default().push(*key);
        }
        for ((issued_by, licence), records) in due {
            let tx_hash = inherited_member_name(issued_by, &records);
            // Taken once: the credit deletes the cell, so a second
            // member over the same record would read nothing and the
            // records would be stranded behind a refusal.
            for key in &records {
                self.counterparts.inherited.remove(key);
            }
            record_reclaim_admitted();
            // No body reached this shard: the chain that issued the
            // crossing ended at the cut, and the price it owed was
            // settled there.
            self.seat_settling(
                tick_id, tick_ts, state, requests, tx_hash, None, records, licence, true,
            );
        }
    }

    /// Admit into the tick being composed every retirement a committed
    /// record has licensed: a member running no node, awaiting nobody,
    /// reserving nothing, charged nothing, that deletes the records of
    /// crossings every consumer has claimed.
    fn admit_retirements(
        &mut self,
        tick_id: TickId,
        tick_ts: WeightedTimestamp,
        state: &mut TickState,
        requests: &mut Vec<CrossShardExecutionRequest>,
    ) {
        let local_shard = self.local_shard;
        for Settleable {
            tx_hash,
            body: transaction,
            classified,
            charged,
        } in self.counterparts.ledger.retirable()
        {
            // Only once nothing this shard runs of the transaction is
            // left: a mixed shard's delivering member is still a
            // candidate while the core's output is on its way, and the
            // retirement is the last word here, not a word beside it.
            if self.ticks.tick_assignment(tx_hash).is_some() || self.candidates.contains(tx_hash) {
                continue;
            }
            self.counterparts.ledger.admit_retire(tx_hash);
            let records = classified.records_issued(local_shard);
            self.seat_settling(
                tick_id,
                tick_ts,
                state,
                requests,
                tx_hash,
                Some(transaction),
                records,
                Licence::Accepted,
                charged,
            );
        }
    }

    /// Seat a settling member in the tick: dispatched, awaiting nobody
    /// but this shard since its own certificate is the whole of its
    /// settlement, reserving nothing since no block took a reservation
    /// for it, and running no node since the engine settles the records
    /// on the licence alone.
    #[allow(clippy::too_many_arguments)] // one seat, every term of it
    fn seat_settling(
        &mut self,
        tick_id: TickId,
        tick_ts: WeightedTimestamp,
        state: &mut TickState,
        requests: &mut Vec<CrossShardExecutionRequest>,
        tx_hash: TxHash,
        transaction: Option<Arc<Verified<Transaction>>>,
        records: Vec<SubstateKey>,
        on: Licence,
        charged: bool,
    ) {
        let local_shard = self.local_shard;
        // A retirement decides nothing: the verdict was reached where
        // the claims were. Every other settlement is this shard's verdict
        // on the transaction.
        let membership = match on {
            Licence::Accepted => Membership::housekeeping(local_shard),
            Licence::Unclaimed | Licence::OwnLeaf => {
                Membership::whole(BTreeSet::from([local_shard])).settling()
            }
        };
        state.admit(tx_hash, membership, 0, Admission::Executes);
        self.ticks.assign_tx(tx_hash, tick_id);
        requests.push(CrossShardExecutionRequest {
            tx_hash,
            transaction,
            provisions: Vec::new(),
            clock: tick_ts,
            runs: Runs::Settle {
                member: Member::whole(local_shard),
                records,
                on,
                charged,
            },
            arrivals: Vec::new(),
        });
    }

    /// Seat one composed member in the tick: its reservation, its
    /// crossing targets, its tick assignment, and — for a mixed shard's
    /// issuing member — the delivering member it makes composable.
    fn admit_member(
        &mut self,
        tick_id: TickId,
        member: Admitted,
        state: &mut TickState,
        ticked: &mut TickedBatch,
        requests: &mut Vec<CrossShardExecutionRequest>,
    ) {
        let local_shard = self.local_shard;
        // The shape and the body travel together or not at all: a
        // housekeeping member has neither, and is admitted by its own
        // pass rather than through here.
        let shape = member
            .request
            .shape()
            .map(|(shape, body)| (shape.clone(), Arc::clone(body)));
        // A mixed shard's delivering member is the second this shard
        // runs of the transaction: the issuing one returned the
        // reservation its block took and settled the price, so this
        // one reserves nothing and issues nothing.
        let second_member = shape.as_ref().is_some_and(|(shape, _)| shape.is_second());
        let reach = member.membership_reach();
        state.admit(
            member.request.tx_hash,
            member.membership,
            match &shape {
                Some((_, body)) if !second_member => body.work(),
                _ => 0,
            },
            member.admission,
        );
        // Where this member's crossings land, off the frozen
        // classification: the shards its outcome promises a bundle
        // to, if it issues anything. Only an issuing member issues;
        // a delivery and a reclaim promise nobody a bundle.
        let targets: BTreeSet<ShardId> = match &shape {
            Some((shape, _)) if shape.side() == Side::Issuing => shape
                .classified()
                .edges()
                .iter()
                .filter(|edge| edge.from == local_shard)
                .flat_map(|edge| edge.to.iter().copied())
                .collect(),
            _ => BTreeSet::new(),
        };
        state.record_crossing_targets(member.request.tx_hash, targets);
        self.ticks.assign_tx(member.request.tx_hash, tick_id);
        self.counterparts.ledger.certify(member.request.tx_hash);
        // A shard with legs on both sides of the core runs them as two
        // members: the issuing one just admitted, and a delivering one
        // that waits on what the core returns. Registered here, at the
        // issuing admission, so every replica composes it from the
        // same commit; it joins a later tick once its arrival lands.
        if let Some((shape, body)) = &shape
            && shape.side() == Side::Issuing
            && shape.runs_both_sides()
        {
            let delivering = Member::of(
                shape.classified().clone(),
                local_shard,
                Side::Delivering,
                reach,
            );
            self.provisioning.record_required(
                member.request.tx_hash,
                requirements_of(&delivering, body.legs()),
            );
            self.candidates
                .register_member(Arc::clone(body), delivering, member.request.clock);
        }
        if let Some((_, body)) = &shape
            && member.request.runs.abortable()
        {
            ticked.legs.insert(member.request.tx_hash);
            ticked
                .provisional_claims
                .extend(body.routing().declared_modes.clone());
        }
        requests.push(member.request);
    }

    fn compose_tick(
        &mut self,
        topology_schedule: &TopologySchedule,
        block: CommittingBlock,
        held: &mut ProvisionalCells,
    ) -> (
        Option<PendingTick>,
        Vec<Verifiable<ExecutionVote>>,
        Vec<TxHash>,
    ) {
        let local_shard = self.local_shard;
        let tick_id = TickId::new(local_shard, block.height);
        let admitted = self
            .candidates
            .compose(&self.provisioning, held, self.committed_ts);

        let mut state = TickState::new(tick_id, block.hash, block.ts);
        let mut requests: Vec<CrossShardExecutionRequest> = Vec::with_capacity(admitted.len());
        let mut ticked = TickedBatch {
            provisional_claims: Vec::new(),
            legs: BTreeSet::new(),
        };
        for member in admitted {
            self.admit_member(tick_id, member, &mut state, &mut ticked, &mut requests);
        }

        self.admit_abandoned(topology_schedule, tick_id, &mut state);
        self.admit_reclaims(tick_id, block.ts, &mut state, &mut requests);
        self.admit_retirements(tick_id, block.ts, &mut state, &mut requests);
        self.admit_inherited(
            topology_schedule,
            tick_id,
            block.ts,
            &mut state,
            &mut requests,
        );

        if state.is_empty() {
            return (None, Vec::new(), Vec::new());
        }

        // What the tick waits on is what a counterpart owes us, so the
        // wait-set is the expectation set: an entry arms the fallback
        // fetch that recovers a certificate the broadcast lost, and
        // retires when the tick lets the member go.
        for (tx_hash, shard) in state.awaited_counterparts() {
            self.expected_certs
                .register(shard, tx_hash, self.committed_ts);
        }

        let members: Vec<TxHash> = state.tx_hashes().to_vec();

        self.ticks.insert_tick(tick_id, state);
        // Only a tick that runs a batch appends an output, and only an
        // output has a fate to record. A tick that abandons and nothing
        // else claims no cell and settles nothing, so the chain never
        // hears of it.
        if !requests.is_empty() {
            self.ticked.insert(tick_id, ticked);
        }

        // Only the tick leader creates a `VoteTracker` for aggregation.
        // Resolved under the committee seated at the tick's own block,
        // which is the one that will verify the certificate. A window this
        // shard has already left seats nobody, and there is no leader to
        // be: the tick composes, but no vote it could carry would reach a
        // quorum.
        let mut votes_to_replay: Vec<Verifiable<ExecutionVote>> = Vec::new();
        if let Some(committee) = topology_schedule.at(block.ts)
            && let seated = committee.consensus_committee_for_shard(local_shard)
            && !seated.is_empty()
            && self.me == tick_leader(&tick_id, seated)
        {
            let quorum = committee.quorum_threshold_for_shard(local_shard);
            self.ticks
                .insert_tracker(tick_id, VoteTracker::new(tick_id, block.hash, quorum));
            let early_votes = self.early.drain_votes_for_tick(&tick_id);
            if !early_votes.is_empty() {
                tracing::debug!(
                    block_hash = ?block.hash,
                    tick = %tick_id,
                    count = early_votes.len(),
                    "Replaying early execution votes"
                );
                votes_to_replay.extend(early_votes);
            }
        }

        let pending = (!requests.is_empty()).then(|| PendingTick {
            tick: block.height,
            tick_ts: block.ts,
            // Off the block's anchored committee, on the same terms the
            // classification above reads it: what a seal opens onto is
            // execution output, and a window taken from this node's head
            // would make the answer depend on how far this node has
            // folded the beacon rather than on what the block committed.
            env: TickEnvironment::governing(
                self.classification_committee(
                    topology_schedule,
                    self.committed_committee_anchor_wt,
                ),
                topology_schedule.windows(),
            ),
            requests,
        });
        (pending, votes_to_replay, members)
    }

    /// Return completion data for every tick that can emit its vote.
    ///
    /// A tick becomes votable when its batch comes back — composition
    /// admitted only members that could reach their outcome in it, so
    /// there is nothing else to wait for.
    ///
    /// Ticks whose certificate is already dispatched or received are
    /// skipped, as are ticks whose committee the schedule cannot resolve.
    /// That last condition is part of votability rather than a check on
    /// the way out because building the vote consumes it: `build_vote_data`
    /// is one-shot and nothing clears the mark, so a tick scanned here and
    /// dropped afterwards has spent its vote without emitting one. A tick
    /// the schedule cannot route stays votable and is picked up by a later
    /// commit instead.
    ///
    /// # Panics
    ///
    /// Panics if `ticks_iter()` and `get_tick_mut()` disagree about tick
    /// presence — unreachable, no concurrent mutation between them.
    pub fn scan_votable_ticks(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<CompletionData> {
        let local_shard = self.local_shard;
        let routable = |tick: &TickState| {
            topology_schedule
                .at(tick.vote_anchor_ts())
                .is_some_and(|snapshot| {
                    !snapshot
                        .consensus_committee_for_shard(local_shard)
                        .is_empty()
                })
        };

        let votable: Vec<TickId> = self
            .ticks
            .ticks_iter()
            .filter(|(tick_id, tick)| {
                !self.ticks.is_ec_dispatched(tick_id)
                    && !tick.local_ec_emitted()
                    && tick.can_emit_vote()
                    && routable(tick)
            })
            .map(|(tick_id, _)| *tick_id)
            .collect();

        let mut completions = Vec::new();
        for tick_id in votable {
            let tick = self
                .ticks
                .get_tick_mut(&tick_id)
                .expect("tick_id was just produced by ticks_iter() in this method");
            let block_hash = tick.block_hash();
            let block_height = tick.block_height();
            let Some((vote_anchor_ts, global_receipt_root, tx_outcomes)) = tick.build_vote_data()
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash,
                block_height,
                vote_anchor_ts,
                tick_id,
                global_receipt_root,
                tx_outcomes,
            });
        }

        // Building a vote is one of the two places a tick learns its
        // receipts disagree with its committee's.
        self.escalate_divergence();

        completions.sort_by_key(|a| a.tick_id);
        completions
    }

    /// Replace the set of registered packages this node lacks with the
    /// latest beacon reconciliation, releasing the dispatch head if what
    /// held it is no longer missing.
    ///
    /// Replaced wholesale rather than merged, so a package that arrived
    /// by any route — a fetch, this shard's own commit, a boot reseed —
    /// leaves the set at the next commit without anyone reporting it.
    pub fn on_missing_packages_updated(&mut self, packages: Vec<Hash>) -> Vec<Action> {
        let missing: BTreeSet<Hash> = packages.into_iter().collect();
        if missing == self.missing_packages {
            return Vec::new();
        }
        self.missing_packages = missing;
        self.dispatch_next_tick()
    }

    /// Drop installed packages from the missing set and release the
    /// dispatch head if they were what held it.
    ///
    /// Reported once the engine holds the code, not once the bytes
    /// arrive: what the head waits on is the ability to run, and
    /// installation is where that is acquired.
    pub fn on_packages_acquired(&mut self, packages: &[Hash]) -> Vec<Action> {
        let held = self.missing_packages.len();
        for package in packages {
            self.missing_packages.remove(package);
        }
        if self.missing_packages.len() == held {
            return Vec::new();
        }
        self.dispatch_next_tick()
    }

    /// Absorb a completed batch: route receipts and per-member outcomes
    /// onto the tick that ran them, then vote and, where the tick is
    /// already covered, finalize.
    ///
    /// Finalization can fall due here rather than at a commit: a tick
    /// whose local certificate arrived before this validator's engine
    /// finished defers under the `has_local_receipts_for_non_aborted`
    /// gate, and the batch landing is what releases it.
    pub fn on_execution_batch_completed(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick: BlockHeight,
        outcome: TickBatchOutcome,
    ) -> Vec<Action> {
        self.tick_in_flight = false;
        self.last_completed_tick = self.last_completed_tick.max(tick);
        let mut actions = Vec::new();

        let TickBatchOutcome {
            tick_id,
            results,
            tx_outcomes,
            fee_receipts,
            attested_work,
        } = outcome;
        if let Some(state) = self.ticks.get_tick_mut(&tick_id) {
            for result in results {
                state.record_receipt(result);
            }
            for fee in fee_receipts {
                state.record_fee_receipt(fee);
            }
            for (tx_hash, work) in attested_work {
                state.record_attested_work(tx_hash, work);
            }
            for wr in tx_outcomes {
                state.record_escrowed(wr.tx_hash(), wr.escrowed().to_vec());
                let (tx_hash, outcome) = wr.into_parts();
                state.record_execution_result(tx_hash, outcome);
            }
            actions.extend(self.finalize(topology_schedule, &tick_id));
        } else {
            // The coordinator stopped tracking the tick between its
            // dispatch and its batch returning. That says where this
            // coordinator is, not what the tick's fate was, so it
            // resolves nothing: the first resolution recorded for a tick
            // is the one the chain applies, and claiming an abandonment
            // here would consume the entry the tick's real verdict needs.
            //
            // Every fate that reaches the chain reaches it elsewhere. The
            // tick that abandons a transaction discards the one holding
            // it and records that, a committed certificate records its
            // settlement ahead of the block work that untracks it, and a
            // reshape terminal tears the chain down outright.
            tracing::warn!(
                tick = tick.inner(),
                %tick_id,
                "ExecutionBatchCompleted for an untracked tick — dropping"
            );
        }

        // The completed tick's output is on the chain (the handler
        // appends before notifying), so fates waiting on it can resolve
        // and the next queued tick can go.
        actions.extend(self.drain_ready_tick_resolutions());
        actions.extend(self.dispatch_next_tick());
        actions
    }

    /// Scan complete ticks and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after conflicts
    /// have been processed so tick state is deterministic at this height.
    /// Each vote is sent to the tick leader (unicast). The `vote_anchor_ts`
    /// is the tick's own block's shard consensus-authenticated weighted
    /// timestamp, which is what resolves the committee that attests.
    pub fn emit_vote_actions(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let local_vid = self.me;
        let completions = self.scan_votable_ticks(topology_schedule);
        let mut actions = Vec::with_capacity(completions.len());
        for completion in completions {
            // The tick's committee is the one seated at its vote anchor — the
            // same committee that will verify the EC. The scan admits only
            // ticks this resolves for, so a miss here is not reachable; a
            // tick dropped after the scan would have spent its one-shot vote
            // without casting it.
            let Some(committee) = topology_schedule
                .at(completion.vote_anchor_ts)
                .map(|s| s.consensus_committee_for_shard(self.local_shard).to_vec())
                .filter(|committee| !committee.is_empty())
            else {
                debug_assert!(false, "scan_votable_ticks admitted an unroutable tick");
                continue;
            };
            let leader = tick_leader(&completion.tick_id, &committee);
            // Track retry state for non-leaders so we can re-send to a
            // rotated leader if this one doesn't produce an EC.
            let tx_outcomes = Arc::new(completion.tx_outcomes);
            if local_vid != leader {
                self.ticks.record_vote_retry(
                    completion.tick_id,
                    PendingVoteRetry {
                        sent_at: self.committed_ts,
                        attempt: Attempt::INITIAL,
                        block_hash: completion.block_hash,
                        block_height: completion.block_height,
                        vote_anchor_ts: completion.vote_anchor_ts,
                        global_receipt_root: completion.global_receipt_root,
                        tx_outcomes: Arc::clone(&tx_outcomes),
                    },
                );
            }
            actions.push(Action::SignAndSendExecutionVote {
                block_hash: completion.block_hash,
                block_height: completion.block_height,
                vote_anchor_ts: completion.vote_anchor_ts,
                tick_id: completion.tick_id,
                global_receipt_root: completion.global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                leader,
            });
        }
        actions
    }

    /// Clean up execution-local per-tick state for finalizations included in the
    /// committed block.
    ///
    /// Per-tx terminal state for the mempool is driven by
    /// `mempool::on_block_committed` reading `block.certificates` directly.
    /// This function only handles execution's own bookkeeping.
    pub fn cleanup_committed_finalizations(
        &mut self,
        certificates: &[Arc<Verifiable<Finalization>>],
    ) {
        for fw in certificates {
            // No-op for synced ticks we never aggregated locally; for ticks we
            // tracked, releases accumulator/cache state for the tick's txs.
            self.remove_finalization(fw.as_unverified());
        }
    }

    /// Apply provisions committed in a block.
    ///
    /// Absorbs every batch before reading any of it back: interleaving
    /// would let a candidate's readiness turn on provisions iteration
    /// order.
    ///
    /// Each batch is peeked for its [`Verifiable::verified`] marker before
    /// re-wrapping. Same-process upstream paths leave the marker live, so
    /// we borrow the existing [`Verified<Provisions>`] without a body
    /// clone. Wire-decoded blocks land at `Unverified`; the
    /// [`Verified::<Provisions>::from_committed_block`] gate then carries
    /// the BFT-transitive trust source via a re-wrap (one body clone).
    fn apply_committed_provisions(&mut self, batches: &[Arc<Verifiable<Provisions>>]) {
        // Sort for deterministic iteration (logs, action vector order).
        let mut ordered: Vec<&Arc<Verifiable<Provisions>>> = batches.iter().collect();
        ordered.sort_by_key(|b| b.hash());

        for provisions in &ordered {
            if let Some(v) = provisions.verified() {
                self.provisioning.absorb_provisions(v);
            } else {
                let verified = Verified::<Provisions>::from_committed_block(
                    provisions.as_unverified().clone(),
                );
                self.provisioning.absorb_provisions(&verified);
            }
        }

        self.candidates
            .absorb_engagement_evidence(&self.provisioning);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a locally-produced, pre-verified execution vote.
    /// Bypasses the batch-verify path and lands directly in the verified
    /// tally. See [`Self::dispatch_execution_vote`] for the leader,
    /// fallback, and early-buffer routing rules.
    pub fn on_verified_execution_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: Verified<ExecutionVote>,
    ) -> Vec<Action> {
        self.dispatch_execution_vote(topology_schedule, vote.into())
    }

    /// Handle a wire-arrived execution vote. Buffered for batch
    /// verification once combined power could reach quorum. See
    /// [`Self::dispatch_execution_vote`] for the full routing rules.
    pub fn on_unverified_execution_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        self.dispatch_execution_vote(topology_schedule, vote.into())
    }

    /// Routing hub for both ingestion paths.
    ///
    /// Only the tick leader (or a fallback leader via rotation)
    /// aggregates votes. If a vote arrives at a non-leader that has
    /// the accumulator but no tracker, a fallback `VoteTracker` is
    /// created on-demand (the sender determined this validator is the
    /// rotated leader for their retry attempt).
    ///
    /// The `Verifiable<ExecutionVote>` signature lets the
    /// early-arrivals buffer hold either taxonomy under one shape and
    /// replay them through the same path when a fallback tracker
    /// spins up.
    ///
    /// # Panics
    ///
    /// Panics if a vote tracker is created or recovered for a tick but
    /// is missing on the immediate `take_unverified_votes` lookup — the
    /// tracker is locked across `&mut self`, so this is unreachable.
    fn dispatch_execution_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: Verifiable<ExecutionVote>,
    ) -> Vec<Action> {
        let tick_id = *vote.tick_id();
        let validator_id = vote.validator();

        // The committee seated at the vote's anchor — the same one whose
        // positional bitfield the EC will carry. `None` means our beacon
        // hasn't reached that epoch; drop and let the sender's retry re-deliver
        // once we catch up.
        let Some(committee) = topology_schedule.at(vote.vote_anchor_ts()) else {
            return vec![];
        };

        // Only votes from local-committee members count. A globally-known
        // validator outside this shard's committee whose vote pooled into
        // `unverified_power` would puff up the tracker into early
        // aggregation, producing an EC whose signature aggregate carries
        // signatures the verifier's bitfield-derived pubkey pool excludes
        // — guaranteed to fail verification and waste a leader rotation.
        // Mirrors `vote_keeper::record_received_vote`.
        if committee
            .committee_index_for_shard(self.local_shard, validator_id)
            .is_none()
        {
            tracing::warn!(
                validator = validator_id.inner(),
                "Execution vote from validator not in local committee"
            );
            return vec![];
        }

        if !self.ticks.contains_tracker(&tick_id) {
            if !self.ticks.contains_tick(&tick_id) {
                // Block hasn't committed yet — buffer as early vote.
                self.early.buffer_vote(tick_id, vote);
                return vec![];
            }
            if self.ticks.is_ec_dispatched(&tick_id) {
                // Already have EC for this tick — discard late vote.
                return vec![];
            }
            // Tick exists but no VoteTracker and no EC yet. This validator
            // was targeted as a fallback leader (rotated attempt). Create tracker.
            let quorum = committee.quorum_threshold_for_shard(self.local_shard);
            let block_hash = self
                .ticks
                .get_tick(&tick_id)
                .expect("contains_tick returned true two lines above")
                .block_hash();
            tracing::info!(
                tick = %tick_id,
                "Creating fallback VoteTracker — receiving votes as rotated leader"
            );
            let tracker = VoteTracker::new(tick_id, block_hash, quorum);
            self.ticks.insert_tracker(tick_id, tracker);

            // Replay any early votes that were buffered before block commit.
            // These may include retried votes from other validators who
            // committed faster and rotated to us before our block committed.
            let early = self.early.drain_votes_for_tick(&tick_id);
            if !early.is_empty() {
                tracing::debug!(
                    tick = %tick_id,
                    count = early.len(),
                    "Replaying early votes into fallback VoteTracker"
                );
                let mut actions = Vec::new();
                for ev in early {
                    actions.extend(self.dispatch_execution_vote(topology_schedule, ev));
                }
                // Process the current vote that triggered fallback creation.
                actions.extend(self.dispatch_execution_vote(topology_schedule, vote));
                return actions;
            }
        }

        // Already-verified votes (own votes from the sign-and-send gate, or
        // future cached-verified inputs) skip the buffer + batch-verify
        // round trip and land directly in the verified tally.
        let vote = match vote.into_verified() {
            Ok(verified) => return self.handle_verified_vote(topology_schedule, verified),
            Err(raw) => raw,
        };

        // Committee membership was confirmed above; the topology snapshot
        // invariant guarantees the public key resolves.
        let public_key = committee
            .public_key(validator_id)
            .expect("committee member has public key (TopologySnapshot invariant)");

        let tracker = self
            .ticks
            .get_tracker_mut(&tick_id)
            .expect("tracker was inserted above when contains_tracker returned false");

        // buffer_unverified_vote handles dedup per (validator, vote_anchor_ts).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(tick_id)
    }

    /// Check if we should trigger provisions verification for a tick's votes.
    fn maybe_trigger_vote_verification(&mut self, tick_id: TickId) -> Vec<Action> {
        let Some(tracker) = self.ticks.get_tracker_mut(&tick_id) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        let votes = tracker.take_unverified_votes();
        if votes.is_empty() {
            return vec![];
        }

        let block_hash = tracker.block_hash();

        tracing::debug!(
            block_hash = ?block_hash,
            tick = %tick_id,
            vote_count = votes.len(),
            "Dispatching execution vote provisions verification"
        );
        vec![Action::VerifyAndAggregateExecutionVotes {
            tick_id,
            block_hash,
            votes,
        }]
    }

    /// Handle a verified execution vote (own vote or already-verified).
    fn handle_verified_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: Verified<ExecutionVote>,
    ) -> Vec<Action> {
        let tick_id = *vote.tick_id();
        // The vote anchors to a committee the beacon has reached: `at` returning
        // `None` means the beacon hasn't committed that epoch yet (drop and let
        // the sender retry). Membership was confirmed before delegating here.
        if topology_schedule.at(vote.vote_anchor_ts()).is_none() {
            return vec![];
        }

        let Some(tracker) = self.ticks.get_tracker_mut(&tick_id) else {
            return vec![];
        };

        tracker.add_verified_vote(vote);

        let mut actions = self.check_vote_quorum(topology_schedule, tick_id);
        actions.extend(self.maybe_trigger_vote_verification(tick_id));
        actions
    }

    /// Handle provisions execution vote verification completed.
    pub fn on_votes_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick_id: TickId,
        block_hash: BlockHash,
        verified_votes: Vec<Verified<ExecutionVote>>,
    ) -> Vec<Action> {
        // Diagnostic quorum threshold for the split-root warning below, keyed
        // on the votes' anchor before they're consumed into the tracker.
        let warn_quorum = verified_votes
            .first()
            .and_then(|v| topology_schedule.at(v.vote_anchor_ts()))
            .map(|s| s.quorum_threshold_for_shard(self.local_shard));

        let Some(tracker) = self.ticks.get_tracker_mut(&tick_id) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for vote in verified_votes {
            tracker.add_verified_vote(vote);
        }

        // Warn if we have enough total power for quorum but it's split
        // across multiple global receipt roots — this means validators disagree
        // on execution results.
        if let Some(quorum) = warn_quorum
            && tracker.check_quorum().is_none()
            && tracker.total_verified_power() >= quorum
            && tracker.distinct_global_receipt_root_count() > 1
        {
            let summary = tracker.global_receipt_root_power_summary();
            tracing::warn!(
                block_hash = ?block_hash,
                tick = %tick_id,
                global_receipt_root_split = ?summary,
                quorum = quorum.inner(),
                "Execution vote quorum blocked: global receipt roots are split across validators"
            );
        }

        let mut actions = self.check_vote_quorum(topology_schedule, tick_id);
        actions.extend(self.maybe_trigger_vote_verification(tick_id));
        actions
    }

    /// Check if quorum is reached for a tick's votes.
    fn check_vote_quorum(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick_id: TickId,
    ) -> Vec<Action> {
        let local_shard = self.local_shard;
        let Some(tracker) = self.ticks.get_tracker_mut(&tick_id) else {
            return vec![];
        };

        let Some((global_receipt_root, vote_anchor_ts, _total_power)) = tracker.check_quorum()
        else {
            return vec![];
        };

        // The EC's signer bitfield is positional against the committee seated
        // at `vote_anchor_ts` — the committee every verifier resolves from the
        // EC's own anchor. Resolve it before consuming the votes; `None`
        // (beacon behind this epoch) leaves the tracker intact to re-check on a
        // later commit.
        let Some(committee) = topology_schedule
            .at(vote_anchor_ts)
            .map(|s| s.committee_for_shard(local_shard).to_vec())
        else {
            return vec![];
        };

        let block_hash = tracker.block_hash();

        tracing::info!(
            block_hash = ?block_hash,
            tick = %tick_id,
            vote_anchor_ts = vote_anchor_ts.as_millis(),
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(global_receipt_root, vote_anchor_ts);

        // Remove the vote tracker — this EC is the shard's final answer.
        // Mark tick as having an EC to skip it in scan_votable_ticks.
        self.ticks.remove_tracker(&tick_id);
        self.ticks.mark_ec_dispatched(tick_id);

        tracing::debug!(
            block_hash = ?block_hash,
            tick = %tick_id,
            votes = votes.len(),
            "Delegating signature aggregation to crypto pool"
        );

        // Stamp phase times for txs covered by the new local EC. Pure
        // telemetry — IoLoop's slow-tx finalization log reads it.
        let ec_tx_hashes = self
            .ticks
            .get_tick(&tick_id)
            .map(|w| w.tx_hashes().to_vec())
            .unwrap_or_default();

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        let mut actions = vec![Action::AggregateExecutionCertificate {
            tick_id,
            global_receipt_root,
            votes,
            committee,
        }];
        if !ec_tx_hashes.is_empty() {
            actions.push(Action::RecordTxEcCreated {
                tx_hashes: ec_tx_hashes,
            });
        }
        actions
    }

    /// Handle execution certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes signature aggregation for a tick's votes.
    /// Only the tick leader (primary or fallback) reaches this path.
    /// Broadcasts the EC to all local peers and remote participating shards,
    /// then feeds it to the tick-level certificate tracker for finalization.
    pub fn on_certificate_aggregated(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick_id: &TickId,
        certificate: &Arc<Verified<ExecutionCertificate>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        // EC broadcast is routing — who should receive it now — so recipients
        // key on the active head, not the EC's anchor committee.
        let head = topology_schedule.head();

        // Who should receive this certificate is a question about the
        // batch's transactions, not about its identity: the shards they
        // reach, less our own — reach rather than awaited, since a shard
        // this tick waits on nothing from may still claim what a member
        // escrowed. Read off the batch's own record rather than the
        // provision accumulator, which may have been pruned by the time
        // the certificate is aggregated.
        //
        // The same record answers what each of them receives. A shard is
        // party to the transactions naming it and to no others, so that
        // is what its copy carries — the certificate a remote shard gets
        // is sized by its own stake in the batch rather than by the
        // batch.
        let per_target: Vec<(ShardId, HashSet<TxHash>)> = self
            .ticks
            .get_tick(tick_id)
            .map(|tick| {
                tick.counterpart_shards()
                    .into_iter()
                    .map(|shard| (shard, tick.txs_reaching(shard).collect()))
                    .collect()
            })
            .unwrap_or_default();

        // Make the cert available to the io_loop's inbound EC fetch handler
        // for fallback serving until the containing block commits.
        self.exec_certs.insert(Arc::clone(certificate));

        // Broadcast EC to all local peers (they don't aggregate — they need it).
        let local_peers = peers_excluding_self(head, self.me, self.local_shard);
        if !local_peers.is_empty() {
            actions.push(Action::BroadcastExecutionCertificate {
                shard: self.local_shard,
                certificate: Arc::clone(certificate),
                recipients: local_peers,
            });
        }

        // Broadcast each target shard its own projection. Track the
        // per-target send so a dropped notify is re-emitted before the
        // source's 24s fallback timer trips — symmetric to ef4eb45a on
        // provisions; the tracker holds what was sent, so a re-broadcast
        // repeats it byte for byte.
        for (target_shard, txs) in &per_target {
            let recipients: Vec<ValidatorId> = head.committee_for_shard(*target_shard).to_vec();
            let Some(projected) = certificate.project_to(txs) else {
                continue;
            };
            let projected = Arc::new(projected);
            self.outbound_certs.on_broadcast(
                Arc::clone(&projected),
                *target_shard,
                recipients.clone(),
            );
            actions.push(Action::BroadcastExecutionCertificate {
                shard: *target_shard,
                certificate: projected,
                recipients,
            });
        }

        tracing::debug!(
            tick = %tick_id,
            tx_count = certificate.tx_outcomes().len(),
            remote_shards = per_target.len(),
            "Tick leader broadcasting EC to local peers and remote shards"
        );

        // Feed the EC to the tick-level certificate tracker for finalization.
        actions.extend(self.handle_attestation(topology_schedule, certificate));

        actions
    }

    /// Hold a fetched artifact at the one gate every certificate passes
    /// before its signature is verified: once per content, and each
    /// contained certificate to [`gate_certificate`].
    ///
    /// `Ok` carries one key set per certificate, in the artifact's
    /// order, and the in-flight slot stays taken until the verification
    /// result releases it. Anything else has released the slot: a
    /// retransmit while the first dispatch runs, an artifact whose
    /// committee the beacon has not reached (the caller parks it), or a
    /// refusal, logged here with its reason.
    fn gate<T: Attested>(
        &mut self,
        topology_schedule: &TopologySchedule,
        item: &T,
    ) -> Result<Vec<Vec<ConsensusPublicKey>>, Gate> {
        let slot = item.slot();
        if !self.pending_verifications.insert(slot) {
            tracing::debug!(tick = %item.tick_id(), "Duplicate verification dispatch suppressed");
            return Err(Gate::InFlight);
        }
        let mut keys = Vec::new();
        for ec in item.certificates() {
            match gate_certificate(topology_schedule, ec) {
                Ok(public_keys) => keys.push(public_keys),
                Err(refused) => {
                    if let Gate::Refused(why) = refused {
                        tracing::warn!(
                            tick = %item.tick_id(),
                            shard = ec.shard_id().inner(),
                            height = ec.block_height().inner(),
                            "Refusing a fetched certificate: {why}"
                        );
                    }
                    self.pending_verifications.remove(&slot);
                    return Err(refused);
                }
            }
        }
        Ok(keys)
    }

    /// Handle an execution certificate received from another validator.
    ///
    /// Always dispatches signature verification before the cert can
    /// influence any tick state. Routing (and any buffering for txs whose
    /// blocks haven't committed yet) happens in `on_certificate_verified`
    /// once the crypto pool confirms the signature — buffering here without
    /// verifying would let a Byzantine remote inject forged `tx_outcomes`
    /// that the replay path later trusts.
    pub fn on_execution_certificate(
        &mut self,
        topology_schedule: &TopologySchedule,
        cert: Verifiable<ExecutionCertificate>,
    ) -> Vec<Action> {
        let shard = cert.shard_id();

        // Cached-verified short-circuit. `exec_certs` is shared across
        // same-shard vnodes (one `Arc<ExecCertStore>` per shard), so a
        // peer vnode's aggregation makes this EC available to ours
        // before the gossip arrives. A wire-hash match against the
        // cached entry means this is the same aggregation we already
        // verified and routed; a mismatch is a different aggregation
        // of the same logical EC and still needs its own signature check.
        if let Some(cached) = self.exec_certs.get(cert.tick_id())
            && cached.wire_hash() == cert.wire_hash()
        {
            tracing::debug!(
                shard = shard.inner(),
                tick = %cert.tick_id(),
                "Cached verified EC matches incoming wire hash — skipping verify dispatch"
            );
            return vec![];
        }

        // Commit-proof gate: a cross-shard EC is consumable only against a
        // commit-proven source block. Certification alone is not enough —
        // an f+1..2f corrupt committee can certify a sibling block that
        // never commits and export ECs computed from it. Defer until the
        // remote-header coordinator holds the committing structure
        // (`RemoteHeaderCommitted` replays the buffer); the proof trails
        // the source header by one child header at worst. A departed
        // shard's settled set answers instead where it can — see
        // `settled_set_admits` — because a departed chain supplies no
        // further commit proofs.
        if shard != self.local_shard
            && self
                .counterparts
                .proven_anchors
                .at(shard, cert.block_height())
                .is_none()
            && !self.counterparts.settled_set_admits(shard, &cert)
        {
            let height = cert.block_height();
            tracing::debug!(
                shard = shard.inner(),
                tick = %cert.tick_id(),
                height = height.inner(),
                "Deferring EC until its source block is commit-proven"
            );
            self.parked
                .park(Waiting::Proof(shard), Parked::Certificate(Box::new(cert)));
            // At or below the shard's attested boundary the height sits
            // under the remote-header sync anchor — a joiner or a fresh
            // recovery committee anchors there and syncs only forward, so
            // no range fetch ever delivers this block's committing
            // structure. Ask the remote-header coordinator for the commit
            // proof explicitly; above the boundary the forward sync (or
            // gossip) delivers it in the ordinary course.
            if topology_schedule
                .head()
                .boundary(shard)
                .is_some_and(|anchor| height <= anchor.height)
            {
                return vec![Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard: shard,
                    block_height: height,
                })];
            }
            return vec![];
        }

        match self.gate(topology_schedule, &cert) {
            Ok(mut keys) => vec![Action::VerifyExecutionCertificateSignature {
                public_keys: keys.pop().unwrap_or_default(),
                certificate: cert,
            }],
            Err(Gate::InFlight) => vec![],
            Err(Gate::BeaconBehind) => {
                self.parked
                    .park(Waiting::Beacon, Parked::Certificate(Box::new(cert)));
                vec![]
            }
            Err(Gate::Refused(_)) => vec![Action::AbandonFetch(cert.abandon())],
        }
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, hand the cert to `handle_attestation` which routes
    /// per-tx outcomes into any local tick trackers and buffers txs whose
    /// blocks haven't committed yet for replay.
    pub fn on_certificate_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        result: Result<
            Arc<Verified<ExecutionCertificate>>,
            (Arc<ExecutionCertificate>, ExecutionCertificateVerifyError),
        >,
    ) -> Vec<Action> {
        // Release the in-flight slot regardless of outcome — a failed
        // signature still lets the next byte-identical retransmit
        // dispatch again (in case the failure was transient pool error
        // rather than a real signature mismatch). Subsequent arrivals
        // with a different aggregation hash to a different `wire_hash`
        // and aren't gated by this slot.
        let ec_arc = match result {
            Ok(verified) => {
                self.pending_verifications.remove(&verified.wire_hash());
                verified
            }
            Err((raw, err)) => {
                self.pending_verifications.remove(&raw.wire_hash());
                tracing::warn!(
                    shard = raw.shard_id().inner(),
                    tick = %raw.tick_id(),
                    error = ?err,
                    "Invalid execution certificate signature"
                );
                return vec![Action::AbandonFetch(FetchIds::ExecutionCerts(
                    fetch_keys_covered(&raw),
                ))];
            }
        };

        // A single Byzantine signer can produce a cryptographically valid
        // EC; require 2f+1 voting power on the EC's own shard before any
        // state mutation downstream. The committee is the one seated at the
        // EC's anchor. `on_execution_certificate` already resolved it to dispatch
        // this verification, so `None` here means that epoch aged out of the
        // schedule in the interim (the beacon advanced past retention) — the
        // EC is stale, so abandon it.
        let Some(committee) = topology_schedule.at(ec_arc.vote_anchor_ts()) else {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                tick = %ec_arc.tick_id(),
                "Discarding execution certificate — epoch evicted from schedule before verification completed"
            );
            return vec![Action::AbandonFetch(FetchIds::ExecutionCerts(
                fetch_keys_covered(&ec_arc),
            ))];
        };
        if !ec_has_shard_quorum_power(committee, &ec_arc) {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                tick = %ec_arc.tick_id(),
                "Discarding sub-quorum execution certificate"
            );
            return vec![Action::AbandonFetch(FetchIds::ExecutionCerts(
                fetch_keys_covered(&ec_arc),
            ))];
        }
        // The recovery freeze, re-checked here: an EC dispatched before the
        // beacon folded a source-shard halt recovery reaches this point with
        // a valid signature and quorum, but if the freeze has since landed
        // and the EC sits past the attested frontier it is a forged orphan
        // the fence must still drop before it mutates any tick state.
        if topology_schedule.recovery_fences(ec_arc.shard_id(), ec_arc.block_height()) {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                tick = %ec_arc.tick_id(),
                height = ec_arc.block_height().inner(),
                "Discarding verified EC from a recovering shard past the freeze frontier"
            );
            return vec![Action::AbandonFetch(FetchIds::ExecutionCerts(
                fetch_keys_covered(&ec_arc),
            ))];
        }

        let shard = ec_arc.shard_id();

        // Clearing the tombstone before verification would let a Byzantine
        // peer ship an EC with a far-future `vote_anchor_ts`, populating
        // the fulfilled tombstone (deadline = vote_anchor_ts +
        // RETENTION_HORIZON) and suppressing legitimate fallback fetches
        // indefinitely while the verify pool silently rejects the forgery.
        let cleared = self.expected_certs.mark_fulfilled(
            shard,
            ec_arc.tx_outcomes().iter().map(TxOutcome::tx_hash),
            ec_arc.deadline(),
        );
        if cleared {
            tracing::debug!(
                source_shard = shard.inner(),
                block_height = ec_arc.block_height().inner(),
                txs = ec_arc.tx_outcomes().len(),
                at_local_ts_ms = self.committed_ts.as_millis(),
                "Fulfilled expected exec cert"
            );
        }

        let mut actions = vec![Action::Continuation(
            ProtocolEvent::ExecutionCertificateAdmitted {
                certificate: Arc::clone(&ec_arc),
            },
        )];

        // If this is a local shard EC, mark the tick as having an EC to skip
        // it in scan_votable_ticks, and persist it for fallback serving to
        // remote shards.
        if shard == self.local_shard {
            self.ticks.mark_ec_dispatched(*ec_arc.tick_id());
            // EC received from tick leader — cancel any pending vote retry.
            self.ticks.clear_vote_retry(ec_arc.tick_id());
            // Make the verified cert available to the io_loop's inbound EC
            // fetch handler for fallback serving until block commit.
            self.exec_certs.insert(Arc::clone(&ec_arc));
        }

        actions.extend(self.handle_attestation(topology_schedule, &ec_arc));
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking
    // ═══════════════════════════════════════════════════════════════════════════

    /// The shared mirror of commit-proven remote anchors, which the shard
    /// coordinator owns and fills.
    #[must_use]
    pub const fn proven_anchors(&self) -> &Arc<ProvenAnchors> {
        &self.counterparts.proven_anchors
    }

    /// The shared mirror of what this validator has proven of
    /// counterparts' cells, which the shard coordinator owns and this
    /// coordinator's fetches fill.
    #[must_use]
    pub const fn proven_cells(&self) -> &Arc<ProvenCells> {
        &self.counterparts.proven_cells
    }

    /// Ask each silent counterpart what it holds, against the trie that
    /// says who was party to each transaction.
    fn probe_silent_counterparts(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let trie = self.counterpart_trie(topology_schedule);
        self.counterparts.probe(trie, self.committed_ts)
    }

    /// Keep a fetched proof for a block this validator proposes.
    pub fn on_proof_fetched(
        &mut self,
        anchor: Anchor,
        keys: Vec<SubstateKey>,
        proof: MerkleInclusionProof,
    ) {
        self.counterparts.on_proof_fetched(anchor, keys, proof);
    }

    /// What this validator holds to offer in a block it proposes.
    #[must_use]
    pub fn offers(&self) -> Offers {
        self.counterparts.offers()
    }

    /// Handle a commit-proven remote header from the `RemoteHeaderCoordinator`.
    ///
    /// The anchor is already in the shared mirror — the shard coordinator
    /// records it before this runs, which is what opens the commit-proof
    /// gate. What is left here is releasing the shard's certificates held
    /// on the proof, with any whose source block is still unproven
    /// re-parking, and taking the probes the new header now anchors.
    pub fn on_committed_remote_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        source_shard: ShardId,
    ) -> Vec<Action> {
        if source_shard == self.local_shard {
            return vec![];
        }
        let mut actions = self.release(topology_schedule, Wake::Proof(source_shard));
        // A counterpart's header past a leg's deadline is what a probe
        // of its committed set, or of its claim cell, waits on.
        actions.extend(self.probe_silent_counterparts(topology_schedule));
        actions
    }

    /// Re-drive everything `wake` lets through, each by the handler it
    /// arrived by, which parks again whatever still waits.
    fn release(&mut self, topology_schedule: &TopologySchedule, wake: Wake) -> Vec<Action> {
        let mut actions = Vec::new();
        for item in self.parked.release(wake) {
            actions.extend(match item {
                Parked::Certificate(cert) => {
                    self.on_execution_certificate(topology_schedule, *cert)
                }
                Parked::Fetched(tick) => self.admit_finalization(topology_schedule, tick),
                Parked::Built(tick) => self.emit_or_gate_finalized(topology_schedule, tick),
            });
        }
        actions
    }

    /// Eager-fetch every expected execution cert whose fallback hasn't fired,
    /// independent of block commit. The commit-driven [`Self::check_exec_cert_timeouts`]
    /// stops running when the shard stalls on the missing certs, so a
    /// commit-independent driver (the cleanup timer) flushes through here to
    /// break the deadlock.
    pub fn flush_expected_certs(&mut self) -> Vec<Action> {
        let now_ts = self.committed_ts;
        let awaited = self.awaited_txs();
        self.expected_certs
            .flush_all(&awaited, now_ts)
            .into_iter()
            .map(|(source_shard, tx_hash)| {
                Action::Fetch(FetchRequest::ExecutionCerts {
                    source_shard,
                    tx_hash,
                    preferred: None,
                    class: None,
                })
            })
            .collect()
    }

    /// Check for timed-out expected execution certs and emit fallback requests.
    ///
    /// Called during block commit processing. Returns actions for any certs
    /// that have exceeded the timeout.
    fn check_exec_cert_timeouts(&mut self) -> Vec<Action> {
        let now_ts = self.committed_ts;

        let awaited = self.awaited_txs();
        let fetches = self.expected_certs.check_timeouts(&awaited, now_ts);

        let mut actions = Vec::with_capacity(fetches.len());
        for (source_shard, tx_hash, is_retry) in fetches {
            tracing::info!(
                source_shard = source_shard.inner(),
                tx = %tx_hash,
                retry = is_retry,
                "Execution cert timeout — requesting fallback"
            );
            actions.push(Action::Fetch(FetchRequest::ExecutionCerts {
                source_shard,
                tx_hash,
                preferred: None,
                class: None,
            }));
        }

        self.expected_certs.retain_if_tx_needed(&awaited);
        self.expected_certs.prune_fulfilled(now_ts);

        actions
    }

    /// Transactions an outstanding local tick still holds — the authority on
    /// what this shard is waiting for coverage on. Tick entries are removed
    /// by `finalize` once a tick completes, so a transaction leaves this
    /// set exactly when it stops needing any counterpart's outcome.
    fn awaited_txs(&self) -> HashSet<TxHash> {
        self.ticks
            .ticks_iter()
            .flat_map(|(_, state)| state.tx_hashes().iter().copied())
            .collect()
    }

    /// The subset of [`Self::awaited_txs`] whose settlement waits on
    /// `shard` — what this shard owes us specifically.
    fn awaited_txs_from(&self, shard: ShardId) -> HashSet<TxHash> {
        self.ticks
            .ticks_iter()
            .flat_map(|(_, state)| state.txs_awaiting(shard))
            .collect()
    }

    /// Re-send votes to rotated leaders for ticks that haven't produced an EC.
    ///
    /// Called during block commit processing. When a retry's deadline has
    /// elapsed against the committed QC's weighted timestamp, the registry
    /// returns a [`RetryEffect`] for each fired retry with the new attempt
    /// number; the coordinator resolves the rotated leader via topology
    /// and lifts each effect to `Action::SignAndSendExecutionVote`.
    fn check_vote_retry_timeouts(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let effects = self.ticks.check_vote_retry_timeouts(self.committed_ts);
        if effects.is_empty() {
            return Vec::new();
        }

        let mut actions = Vec::with_capacity(effects.len());
        for RetryEffect {
            tick_id,
            attempt,
            block_hash,
            block_height,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
        } in effects
        {
            // The rotated leader is drawn from the committee seated at the
            // tick's anchor — the one that will verify the EC. Two ways
            // there is nobody to rotate to, and both defer the retry to a
            // later commit rather than resolving a leader: the beacon is
            // behind the anchor, or the anchor resolves a window this
            // shard has already left, where its committee is empty and no
            // vote can reach a quorum anyway.
            let Some(committee) = topology_schedule
                .at(vote_anchor_ts)
                .map(|s| s.consensus_committee_for_shard(self.local_shard).to_vec())
                .filter(|committee| !committee.is_empty())
            else {
                continue;
            };
            let new_leader = tick_leader_at(&tick_id, attempt, &committee);
            tracing::info!(
                tick = %tick_id,
                attempt = attempt.inner(),
                new_leader = new_leader.inner(),
                "Vote retry timeout — re-sending to rotated leader"
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash,
                block_height,
                vote_anchor_ts,
                tick_id,
                global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                leader: new_leader,
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle block committed.
    ///
    /// Runs the variant-agnostic bookkeeping (height bump, timeout checks,
    /// pruning), then dispatches to either `on_live_block_committed` —
    /// which drives fresh execution — or `on_sealed_block_committed` —
    /// which only records tx → tick mappings so late-arriving certs can
    /// route back to the mempool.
    ///
    /// Orchestration order matters. The phases below run in sequence and
    /// depend on earlier phases completing first:
    ///
    /// 1. **Anchor time** — bump `committed_height` and `committed_ts`
    ///    from the QC. Every downstream phase reads these.
    /// 2. **First-commit retro-stamp** — entries buffered pre-first-commit
    ///    carry `WeightedTimestamp::ZERO`; stamp them with the new
    ///    `committed_ts` before timeout checks, otherwise
    ///    `elapsed_since(ZERO)` dwarfs every deadline and triggers a
    ///    fallback-fetch storm.
    /// 3. **Timeout checks** — expected-cert fallbacks and vote retries.
    ///    Read the freshly-bumped `committed_ts`.
    /// 4. **Pruning** — resolved ticks, stale buffered ECs, aged
    ///    conflict-detector provisions. Must follow timeouts so a retry
    ///    fires before the tick it references is pruned away.
    /// 5. **Dispatch** — route to the live or sealed path for block-specific
    ///    work (tick setup + dispatch, or late-cert routing).
    #[instrument(skip(self, certified, topology_schedule), fields(
        height = certified.block().height().inner(),
        block_hash = ?certified.block().hash(),
        tx_count = certified.block().transactions().len(),
        is_live = certified.block().is_live(),
    ))]
    pub fn on_block_committed(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let block = certified.block();
        let height = block.height();

        // Update committed height + timestamp before anything else — needed
        // for timeout calculations and pruning even when there are no new
        // transactions.
        //
        // "First commit" means the chain has never committed, not that the
        // clock reads zero: a root chain's first blocks genuinely anchor at
        // zero, and their zero is a carriable parent anchor, not a gap.
        let first_commit = self.committed_height == BlockHeight::GENESIS
            && self.committed_ts == WeightedTimestamp::ZERO;
        if height > self.committed_height {
            let own_anchor = certified.block().header().parent_qc().weighted_timestamp();
            // This block's committee anchors on its parent, whose anchor is
            // the one the previous commit carried — or the recovered frontier
            // seeded at construction, which is the same value across a
            // restart. Contiguity is what makes the carry exact — across a
            // gap (a fresh chain's first commit, or a commit landing above a
            // hole) there is no parent anchor to inherit, so the block's own
            // stands in: the same window except when the gap ends on an
            // epoch's first block, and exact again at the next commit. A
            // fresh chain is exact too: its genesis QC carries the chain
            // origin's anchor, which *is* the parent anchor of block one.
            self.committed_committee_anchor_wt =
                if !first_commit && height == self.committed_height.next() {
                    self.committed_ts
                } else {
                    own_anchor
                };
            self.committed_height = height;
            self.committed_ts = own_anchor;
        }
        self.provisioning.advance_clock(self.committed_ts);
        self.sweep_candidates();
        // What the block says about counterparts, and what it opens to
        // ask them; the strands no counterpart can answer for any more
        // are let go of below.
        let trie = self.counterpart_trie(topology_schedule);
        let committed =
            self.counterparts
                .on_commit(trie, topology_schedule, block, self.committed_ts);
        let mut actions = committed.actions;
        self.release_unanswerable(&committed.unanswerable);

        // Timeout checks + pruning run every block, not just commits that
        // carry txs.
        actions.extend(self.check_exec_cert_timeouts());
        actions.extend(self.check_vote_retry_timeouts(topology_schedule));
        self.prune_execution_state();
        self.early.gc_stale_ecs(self.committed_ts);
        // Re-check gate-held finalizations against the advanced schedule:
        // emit any it now resolves, and drop any whose partner it has
        // evicted from every retained window. Runs every block so a settled
        // set that never reconstructs can't pin the buffer; a rejected
        // straddler's transactions stay owed until their deadline.
        actions.extend(self.release(topology_schedule, Wake::Commit));

        // Re-broadcast outbound ECs that haven't been ACKed via tick
        // finalization. Driven from the commit cadence so the schedule is
        // deterministic across validators.
        for directive in self.outbound_certs.on_block_committed(self.committed_ts) {
            actions.push(Action::BroadcastExecutionCertificate {
                shard: directive.target_shard,
                certificate: directive.certificate,
                recipients: directive.recipients,
            });
        }

        for (_, tick) in self.ticks.ticks_iter_mut() {
            tick.log_if_overdue(self.committed_ts);
        }

        // Tick fates the block's committed certificates decide. Emitted
        // ahead of the block-specific work, so a tick dispatched below
        // reads the resolved chain.
        for fw in block.certificates().iter() {
            let fw = fw.as_unverified();
            let aborted: BTreeSet<TxHash> = fw
                .tx_decisions()
                .into_iter()
                .filter(|(_, decision)| !matches!(decision, TransactionDecision::Accept))
                .map(|(tx_hash, _)| tx_hash)
                .collect();
            // The members this finalization speaks for, which is one
            // half of its tick rather than the whole of it.
            let members: BTreeSet<TxHash> = fw.tx_hashes().collect();
            self.record_tick_resolution(
                fw.tick_id(),
                TickResolution::Settled {
                    height,
                    members,
                    aborted,
                },
            );
        }
        actions.extend(self.drain_ready_tick_resolutions());

        match block {
            Block::Live {
                header,
                transactions,
                certificates,
                provisions,
                ..
            } => actions.extend(self.on_live_block_committed(
                topology_schedule,
                block.hash(),
                header,
                transactions,
                certificates,
                provisions,
            )),
            Block::Sealed {
                header,
                transactions,
                ..
            } => actions.extend(self.on_sealed_block_committed(
                topology_schedule,
                header,
                transactions,
            )),
        }

        actions
    }

    /// Live path: still within the cross-shard execution window. Proposer
    /// broadcasts provisions, setup+dispatch runs for the block's txs, and
    /// inline provisions are applied so newly-created ticks can transition
    /// to `Provisioned` immediately.
    fn on_live_block_committed(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        header: &BlockHeader,
        transactions: &[Arc<Verifiable<Transaction>>],
        certificates: &[Arc<Verifiable<Finalization>>],
        provisions: &[Arc<Verifiable<Provisions>>],
    ) -> Vec<Action> {
        let height = header.height();
        let mut actions = Vec::new();

        // Classification anchors on the block's committee, not the head, so
        // every replica groups its ticks and provisions identically across a
        // reshape boundary.
        let anchored =
            self.classification_committee(topology_schedule, self.committed_committee_anchor_wt);

        // Below where a baseline is readable a tick composes and never
        // runs: which tick holds a member is what every replica has to
        // agree on, and the baseline is the only part of it the store
        // cannot answer for.
        let runnable = height >= self.compose_from;

        // ── Provision broadcasting (proposer only) ─────────────────────
        if runnable && self.me == header.proposer() {
            let local_shard = self.local_shard;
            if let Some((requests, shard_recipients)) =
                build_provision_requests(anchored, transactions, certificates, self.me, local_shard)
            {
                actions.push(Action::FetchAndBroadcastProvisions {
                    block_hash,
                    requests,
                    source_shard: local_shard,
                    block_height: height,
                    source_block_ts: header.parent_qc().weighted_timestamp(),
                    shard_recipients,
                });
            }
        }

        let block = CommittingBlock {
            hash: block_hash,
            height,
            ts: self.committed_ts,
        };

        // Everything this commit puts in flight or unblocks, before
        // anything is composed from it: the block's own transactions, and
        // the provisions and engagement echoes its batches carry.
        if !transactions.is_empty() {
            self.register_committed_txs(anchored, block.ts, transactions);
        }
        if !provisions.is_empty() {
            self.apply_committed_provisions(provisions);
        }
        // Every commit, not only one carrying provisions: a bundle that
        // committed before its transaction did is evidence already in
        // hand, and a payer whose wait only ever cleared on a later
        // bundle would never execute.
        self.candidates
            .absorb_engagement_evidence(&self.provisioning);

        // What earlier ticks hold provisionally, and the set this commit's
        // own composition adds to.
        let mut held = self.provisional_cells();
        let (pending, early_votes, members) =
            self.compose_tick(topology_schedule, block, &mut held);
        for vote in early_votes {
            actions.extend(self.dispatch_execution_vote(topology_schedule, vote));
        }
        // The members that just gained an assignment: a counterpart's
        // certificate that arrived while they waited has a tick to route
        // to now, and nothing else will offer it one.
        if !members.is_empty() {
            actions.extend(self.replay_early_attestations(topology_schedule, &members));
        }
        if let Some(pending) = pending {
            if runnable {
                tracing::debug!(
                    height = height.inner(),
                    members = pending.requests.len(),
                    "Dispatching this commit's tick"
                );
                self.pending_ticks.push_back(pending);
            } else {
                tracing::debug!(
                    height = height.inner(),
                    members = pending.requests.len(),
                    "Composed a tick the store can no longer anchor a baseline for"
                );
            }
        }
        // What composition abandoned, before the tick it composed reads
        // the chain: a discarded tick's legs hold cells this one may
        // need, and nothing else is coming to release them.
        actions.extend(self.drain_ready_tick_resolutions());
        actions.extend(self.dispatch_next_tick());

        actions
    }

    /// Escalate any divergence a tick has just latched.
    ///
    /// A wrong tick output is not one tick's problem to sit out. Under
    /// chaining it is the baseline every later tick reads, so a tick that
    /// declined to finalize would leave the node quietly producing
    /// receipts nobody else agrees with, for as long as its drain lasts.
    ///
    /// There is nothing to repair: re-execution is deterministic and
    /// reproduces the same disagreement. The tick named here is the first
    /// one whose output diverged, which chained baselines make exact — a
    /// later tick reading a wrong baseline would have diverged too, so
    /// the earliest report is the origin.
    fn escalate_divergence(&mut self) {
        let mut earliest: Option<(BlockHeight, TickId, Divergence)> = None;
        for (tick_id, tick) in self.ticks.ticks_iter_mut() {
            let Some(divergence) = tick.take_divergence() else {
                continue;
            };
            let height = tick_id.block_height();
            if earliest.as_ref().is_none_or(|(seen, ..)| height < *seen) {
                earliest = Some((height, *tick_id, divergence));
            }
        }
        let Some((tick, tick_id, divergence)) = earliest else {
            return;
        };
        tracing::error!(
            shard = %self.local_shard,
            tick = tick.inner(),
            tick = %tick_id,
            block_hash = ?divergence.block_hash,
            local_root = ?divergence.local_root,
            ec_root = ?divergence.ec_root,
            "Local execution diverged from the quorum. Every tick from this \
             one on reads a baseline nobody else agrees with. Rebuild \
             required: restore from a state snapshot or resync."
        );
        panic!(
            "BFT CRITICAL: local execution diverged at tick {} (tick {tick_id}): \
             voted receipt root {:?}, committee certified {:?}. Deterministic \
             re-execution reproduces it — operator intervention required.",
            tick.inner(),
            divergence.local_root,
            divergence.ec_root,
        );
    }

    /// The cells unresolved cross-shard legs hold provisionally.
    ///
    /// Rebuilt per commit from `ticked`, which is small: one entry per
    /// tick whose fate has not committed, and the drain budget bounds how
    /// many that can be.
    fn provisional_cells(&self) -> ProvisionalCells {
        let mut cells = ProvisionalCells::default();
        for ticked in self.ticked.values() {
            cells.claim(&ticked.provisional_claims);
        }
        cells
    }

    /// The transactions this commit's tick attests `Aborted`.
    ///
    /// The trigger is the transaction's own deadline: the last block that
    /// could have included it anywhere, plus the longest a cross-shard
    /// transaction can take to finalize. Both figures are its own and the
    /// clock is the committed weighted timestamp, so no replica can reach
    /// the deadline at a frontier where another has not — which is what
    /// lets a committee sign a verdict about it.
    ///
    /// Past it, only the transactions no shard can still settle, which is
    /// what makes abandoning one this shard's decision alone to take.
    ///
    /// Two narrowings that used to sit here are answered elsewhere. An
    /// assembled settlement needs none: its tick is lower, so the store
    /// offers it first and the duplicate-resolution rule refuses the
    /// abort, after which the ledger releases the transaction. And a
    /// transaction a terminating counterpart may have settled is the
    /// fence's question, which [`Finalization::claims`] is what lets the
    /// fence ask about an abandonment at all.
    fn abandonable(&self, composing: TickId) -> Vec<UnsettledTx> {
        self.counterparts
            .ledger
            .past_deadline(self.committed_ts)
            .into_iter()
            .filter(|entry| self.beyond_every_shard(composing, entry.tx_hash))
            .collect()
    }

    /// Drop a tick that can no longer speak for a member being abandoned,
    /// releasing the transactions it holds to their own deadlines and the
    /// cells its legs held against.
    fn discard_tick(&mut self, tick_id: TickId) {
        let counts = self.ticks.discard_tick(&tick_id);
        self.release_chain_holds(tick_id);
        // Its finalization goes with it: a proposer offering one for a
        // member abandoned here would be refused by every voter, and
        // would keep offering it.
        self.finalized.remove_tick(&tick_id);
        // And its certificate, which no finalization of this shard's will
        // ever commit. Left in the cache it is answered to a counterpart
        // asking by transaction, for a verdict this shard has retracted
        // and beside the abort that replaced it.
        self.exec_certs.evict(&tick_id);
        tracing::info!(
            tick = %tick_id,
            released = counts.assignments,
            "Discarded a tick holding an abandoned member"
        );
    }

    /// Tell the chain a tick's legs reach no verdict, so what they hold
    /// against the cells they declared is let go of.
    ///
    /// A leg's reservation stands on the chain until its tick's fate
    /// resolves it, and every later tick's reader takes it as value
    /// already spoken for. A tick that has stopped speaking for its
    /// members reaches no fate, so nothing else would ever release it:
    /// the payer's cells stay locked on every replica that ran the tick,
    /// the entry never evicts, and a replica that rebuilt the chain
    /// without the hold reads a different overlay from the same chain.
    fn release_chain_holds(&mut self, tick_id: TickId) {
        let Some(members) = self
            .ticked
            .get(&tick_id)
            .map(|ticked| ticked.legs.clone())
            .filter(|legs| !legs.is_empty())
        else {
            self.ticked.remove(&tick_id);
            return;
        };
        self.record_tick_resolution(&tick_id, TickResolution::Abandoned { members });
    }

    /// Whether no shard can still settle `tx_hash`.
    ///
    /// A settlement needs a certificate from every shard party to the
    /// transaction, so it takes two things to put one out of reach: no
    /// certificate of ours for a counterpart to combine with its own, or
    /// no counterpart in a position to combine one.
    ///
    /// A tick holding the transaction is speaking for it and is left to.
    /// The one composing now is about to attest it, and its verdict can
    /// carry a charge an abandonment cannot — a payer's leg admitted at
    /// its engagement deadline being exactly that. An earlier one is left
    /// to while it can still close its coverage, which takes a
    /// counterpart it waits on: a record saying that counterpart left the
    /// transaction unsettled ends it, and so does the member awaiting
    /// nobody in the first place, since then no certificate but this
    /// shard's was ever coming. A tick that is itself the abandonment is
    /// left to unconditionally — it is the answer, not a claim on one.
    ///
    /// With no tick speaking for it, what decides is whether a certificate
    /// of ours is out where a counterpart could settle against it. The
    /// account answers that, not the tick registry: the certificate
    /// outlives the tick that produced it — a discard drops the tick, a
    /// restart loses it — and a shard reading the registry would take the
    /// tick's absence for the certificate's and abandon a transaction its
    /// counterpart can still settle.
    ///
    /// That a counterpart has left is not that answer. A shard can settle
    /// its half and then depart, so its departure and its silence are
    /// different facts, and only the second puts a settlement out of
    /// reach. The committed record is what establishes the second, so it
    /// is what licenses spending a tick here — composing on the departure
    /// alone would discard a tick whose settlement had already closed, and
    /// the fence would then refuse the abort that replaced it, tearing the
    /// transaction across the two shards.
    fn beyond_every_shard(&self, composing: TickId, tx_hash: TxHash) -> bool {
        match self.ticks.tick_assignment(tx_hash) {
            Some(tick_id) if tick_id == composing => false,
            Some(tick_id) => {
                let held_by = self.ticks.get_tick(&tick_id);
                // A tick that is itself the member's abandonment is left
                // alone whatever the entry says. It waits on nothing, so
                // it can never fail to close its coverage, and spending
                // another tick on the same member would discard the abort
                // this one carries and compose an identical one — every
                // commit, for as long as the entry stands.
                if held_by.is_some_and(|tick| tick.abandons(tx_hash)) {
                    return false;
                }
                // Two fences refuse the finalization a tick is waiting to
                // commit, and past either the tick has nothing left to
                // say: a delivery's is refused at the lapse, and a
                // success that decides alone at the deadline. Left to,
                // such a tick holds a member nothing can resolve while
                // every proposer offers a finalization every voter
                // refuses. Which clock each runs on is already applied —
                // an entry reaches here only past its own abandon
                // window's opening.
                self.counterparts.ledger.is_unsettled_by_departed(tx_hash)
                    || self.counterparts.ledger.is_delivery(tx_hash)
                    || held_by.is_some_and(|tick| tick.decided_alone(tx_hash))
            }
            None => {
                !self.counterparts.ledger.is_certified(tx_hash)
                    || self.no_counterpart_can_settle(tx_hash)
            }
        }
    }

    /// Whether no counterpart is in a position to settle `tx_hash` against
    /// a certificate of ours: none is party to it, so there is no
    /// certificate but ours to combine with, or a committed record says
    /// the one that was left it unsettled.
    fn no_counterpart_can_settle(&self, tx_hash: TxHash) -> bool {
        !self.counterparts.ledger.reaches_beyond(tx_hash)
            || self.counterparts.ledger.is_unsettled_by_departed(tx_hash)
    }

    /// Let go of what this shard holds against transactions no shard can
    /// settle any more.
    ///
    /// Every counterpart has left and every settled set that could have
    /// spoken for them has stopped reading, so the tick holding one will
    /// never close its coverage — no certificate is coming to close it
    /// with. Its provisional claims are held against writes that will
    /// never apply, and a later transaction reaching those cells is
    /// waiting on nothing.
    ///
    /// Discarding here is not the discard a verdict makes. A verdict is
    /// composed while counterparts are live and spends a tick that might
    /// still have settled; this runs only once none of them can answer,
    /// which is the same condition that makes the transaction's own fate
    /// unreachable. Nothing that could still settle is destroyed, because
    /// by then nothing can.
    ///
    /// Each of these is also a reservation the drain never gets back —
    /// only a committed certificate returns one, and by here none is
    /// coming. Counted by cause, because the drain's baseline rises with
    /// them and a shard that accumulates enough admits nothing at all.
    fn release_unanswerable(&mut self, unanswerable: &[Unanswerable]) {
        for entry in unanswerable {
            record_unresolvable_tx(if entry.covered_by_record {
                "record_covered"
            } else {
                "no_record"
            });
            if let Some(tick_id) = self.ticks.tick_assignment(entry.tx_hash) {
                tracing::info!(
                    tx = %entry.tx_hash,
                    tick = %tick_id,
                    covered_by_record = entry.covered_by_record,
                    "Releasing a strand whose counterparts have all fallen silent"
                );
                self.discard_tick(tick_id);
            }
        }
    }

    /// Record a tick's fate for the tick chain.
    ///
    /// A tick with no tick entry — never dispatched, or committed by a
    /// shard already past its execution window — resolves nothing. The
    /// rest are held until their tick has appended: a block carrying a
    /// certificate can commit while the tick that executed the tick is
    /// still queued, and resolving against a chain that has never seen
    /// the tick would drop the promotion.
    fn record_tick_resolution(&mut self, tick_id: &TickId, resolution: TickResolution) {
        let Some(ticked) = self.ticked.get(tick_id) else {
            return;
        };
        // The claims clear with the fate rather than with the promotion:
        // both the commit path and the tick-completion pump emit pending
        // resolutions before dispatching, so the chain is always at least
        // as resolved as the claim set says by the time a later tick runs.
        //
        // Only the half carrying the legs clears them. A determined
        // member holds no cell — its writes are readable from the append
        // — so its own half settling releases nothing.
        let releases_claims = match &resolution {
            TickResolution::Settled { members, .. } => {
                ticked.legs.iter().all(|leg| members.contains(leg))
            }
            TickResolution::Abandoned { .. } => true,
            // Never reaches here: a restore is emitted for a tick this
            // coordinator holds no claims for, and only the replay emits
            // one at all.
            TickResolution::Restored { .. } => false,
        };
        if releases_claims {
            self.ticked.remove(tick_id);
        }
        self.pending_tick_resolutions
            .push((*tick_id, tick_id.block_height(), resolution));
    }

    /// Emit every buffered resolution whose tick is now on the chain.
    fn drain_ready_tick_resolutions(&mut self) -> Vec<Action> {
        let last = self.last_completed_tick;
        let mut ready: Vec<(TickId, TickResolution)> = Vec::new();
        self.pending_tick_resolutions
            .retain(|(tick_id, tick, resolution)| {
                if *tick <= last {
                    ready.push((*tick_id, resolution.clone()));
                    false
                } else {
                    true
                }
            });
        if ready.is_empty() {
            return Vec::new();
        }
        vec![Action::ResolveTicks { resolutions: ready }]
    }

    /// Dispatch the queued tick at the head, unless one is already in
    /// flight. Ticks execute serially: each output is the next tick's
    /// baseline, so the next dispatch waits for the previous
    /// `ExecutionBatchCompleted` — by which point the handler has
    /// appended the output to the tick chain.
    fn dispatch_next_tick(&mut self) -> Vec<Action> {
        if self.tick_in_flight {
            return Vec::new();
        }
        let Some(head) = self.pending_ticks.front() else {
            return Vec::new();
        };
        // Running a member whose code this node lacks would reach the
        // engine's no-code refusal while every replica holding the bytes
        // settles it — one tick, two receipt roots. Waiting is the whole
        // of the fix: the fetch heals, and the tick that runs then is the
        // tick that was composed now. Ticks are serial, so this shard's
        // execution stops here until the bytes land — the trade a
        // withheld artifact is meant to draw, liveness rather than a
        // fork.
        if head.runs_any_of(&self.missing_packages) {
            tracing::debug!(
                shard = %self.local_shard,
                tick = %head.tick,
                "Holding a tick whose members run code this node has not fetched"
            );
            return Vec::new();
        }
        let Some(tick) = self.pending_ticks.pop_front() else {
            return Vec::new();
        };
        self.tick_in_flight = true;
        vec![Action::ExecuteTransactions {
            tick: tick.tick,
            tick_ts: tick.tick_ts,
            env: tick.env,
            requests: tick.requests,
        }]
    }

    /// Sealed path: past the cross-shard execution window. Ticks will
    /// finalize from the already-aggregated cert + receipts included
    /// downstream, so we skip `TickState` creation, dispatch, and vote
    /// tracking. Only the tx → tick mapping is recorded (plus any early
    /// ECs replayed) so a late-arriving cert still routes back to each
    /// tx for mempool terminal-state bookkeeping.
    fn on_sealed_block_committed(
        &mut self,
        topology_schedule: &TopologySchedule,
        header: &BlockHeader,
        transactions: &[Arc<Verifiable<Transaction>>],
    ) -> Vec<Action> {
        if transactions.is_empty() {
            return Vec::new();
        }
        let anchored =
            self.classification_committee(topology_schedule, self.committed_committee_anchor_wt);
        self.register_sealed_assignments(anchored, header.height(), transactions);
        let tx_hashes: Vec<TxHash> = transactions.iter().map(|tx| tx.hash()).collect();
        self.replay_early_attestations(topology_schedule, &tx_hashes)
    }

    /// Replay buffered certificates for transactions that have just
    /// gained a tick assignment.
    ///
    /// Driven by assignment rather than by commit, because those are no
    /// longer the same moment: a member waits in the candidate pool until
    /// a tick can take it, and a counterpart's certificate arriving in
    /// that window has nowhere to route. Composition is what gives it
    /// one, so composition is what replays.
    fn replay_early_attestations(
        &mut self,
        topology_schedule: &TopologySchedule,
        tx_hashes: &[TxHash],
    ) -> Vec<Action> {
        let ecs_to_replay = self.early.drain_ecs_for_txs(tx_hashes);
        if ecs_to_replay.is_empty() {
            return Vec::new();
        }
        tracing::debug!(
            count = ecs_to_replay.len(),
            "Replaying early tick attestations for newly committed txs"
        );
        let mut actions = Vec::new();
        for ec in &ecs_to_replay {
            actions.extend(self.handle_attestation(topology_schedule, ec));
        }
        actions
    }

    /// What a committed block's finalizations settle about the
    /// transactions they name, for the mempool's status of each: the
    /// ledger's reading, taken before the block releases the entries.
    #[must_use]
    pub fn resolutions_of(
        &self,
        finalizations: &[Arc<Verifiable<Finalization>>],
    ) -> Vec<(TxHash, TxResolution)> {
        self.counterparts.ledger.resolutions_of(finalizations)
    }

    /// Register tx → tick assignments for a `Sealed` block without any of
    /// the execution-side state setup (`TickState`, vote tracker, conflict
    /// detector, required-provision tracking). The block's ticks are
    /// already settled; we only need the mapping so a future cert can
    /// route back to the tx for mempool terminal-state bookkeeping.
    fn register_sealed_assignments(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_height: BlockHeight,
        transactions: &[Arc<Verifiable<Transaction>>],
    ) {
        let _ = topology_snapshot;
        let tick_id = TickId::new(self.local_shard, block_height);
        for tx in transactions {
            self.ticks.assign_tx(tx.hash(), tick_id);
            self.counterparts.ledger.certify(tx.hash());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 5: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a tick-level attestation (execution certificate) from any shard.
    ///
    /// A remote EC's `tick_id` reflects the remote shard's tick composition,
    /// which differs from the local shard's. A single remote EC may contain
    /// outcomes for transactions in MULTIPLE local ticks.
    ///
    /// Routing: iterate `tx_outcomes` → look up local tick via `tick_assignments` →
    /// feed the EC to each affected local tick tracker. `tx_hashes` without a
    /// local assignment are buffered (or kept buffered) via `pending_routing`
    /// until their blocks commit; routed `tx_hashes` are cleared from the
    /// pending set, dropping the EC entirely once fully routed.
    fn handle_attestation(
        &mut self,
        topology_schedule: &TopologySchedule,
        ec: &Arc<Verified<ExecutionCertificate>>,
    ) -> Vec<Action> {
        // What a core says of a transaction a leg here issued for is
        // read before routing: the leg's tick settled long ago, so the
        // certificate routes nowhere, and the refusal is the one thing
        // in it this shard still has a use for.
        let mut actions = self.counterparts.on_certificate(ec);

        let routing = self.ticks.classify_attestation(ec);

        self.early.clear_routed(ec, &routing.routed_tx_hashes);
        self.early.buffer_ec(ec, &routing.unrouted_tx_hashes);

        if routing.affected_ticks.is_empty() {
            return actions;
        }

        // Feed the EC to each affected local tick. Completion requires both
        // the local EC and all remote shards' coverage (aborted txs are
        // terminal-covered). Once `local_ec_emitted` is true, every tx
        // already has an outcome and a matching receipt in the cache.
        for tick_id in &routing.affected_ticks {
            let Some(tick) = self.ticks.get_tick_mut(tick_id) else {
                continue;
            };
            tick.add_execution_certificate(Arc::clone(ec));
            actions.extend(self.finalize(topology_schedule, tick_id));
        }
        // The other: an admitted local EC that contradicts the vote this
        // validator already cast.
        self.escalate_divergence();
        actions
    }

    /// Finalize a tick: build the [`Finalization`], then admit it or hold
    /// it at the split-boundary gate.
    ///
    /// Called when the tick's local EC is present and every non-aborted tx is
    /// covered by all participating shards.
    fn finalize(&mut self, topology_schedule: &TopologySchedule, tick_id: &TickId) -> Vec<Action> {
        let mut halves: Vec<Finalization> = Vec::new();
        let Some(tick) = self.ticks.get_tick_mut(tick_id) else {
            return vec![];
        };
        // Determined first, and the order matters: the two halves of one
        // tick came out of a single batch fold, so a receipt in the second
        // states an absolute computed on top of the first.
        halves.extend(tick.take_determined_finalization());
        halves.extend(tick.take_legs_finalization());
        if halves.is_empty() {
            return vec![];
        }
        let spoken = tick.has_spoken();

        if spoken {
            // Every leg's settlement needed every participating shard's
            // certificate, which means each of them executed this tick —
            // strong evidence they also received our outbound EC (or are
            // about to). Drop the re-broadcast tracker entry to stop
            // wasting bandwidth. The tick itself stays until a committed
            // block resolves its members.
            self.outbound_certs.on_tick_finalized(tick_id);
        }

        // Local-finalization gate produces `Verified<Finalization>`; lift
        // into the `Block::Live.certificates` transport shape once so the
        // store, the admission event, and any downstream `PendingBlock`
        // entry share the same `Arc` without further per-consumer cloning.
        let mut actions = Vec::new();
        for half in halves {
            let finalized_arc = Arc::new(Verified::<Finalization>::seal(half).into());
            actions.extend(self.emit_or_gate_finalized(topology_schedule, finalized_arc));
        }
        actions
    }

    /// Admit a freshly built finalization downstream, or withhold it at
    /// the split-boundary gate so we never produce a tick the vote fence
    /// would reject.
    ///
    /// `Pass` records the tick and emits the admission event (one event
    /// covers both the shard consensus subscriber and the `io_loop`
    /// serving cache). `Defer` parks it until the terminating shard's
    /// settled set resolves it or its scheduled termination clears.
    /// `Reject` drops it — the tick names a past-terminal shard that
    /// didn't settle it, so it must never be produced. Nothing here
    /// resolves its transactions; they stay owed, and the tick at their
    /// deadline abandons them.
    fn emit_or_gate_finalized(
        &mut self,
        topology_schedule: &TopologySchedule,
        finalized_arc: Arc<Verifiable<Finalization>>,
    ) -> Vec<Action> {
        let tick_id = *finalized_arc.tick_id();
        let verdict = {
            // Whether a shard is past-terminal is asked at the committed
            // frontier, which is what a node-local caller reads it at.
            let claims = finalized_arc.claims(self.local_shard, |tx_hash| {
                self.counterparts.mirror.covers(tx_hash)
            });
            self.counterparts.mirror.with_settled(|settled| {
                settled_set_verdict(
                    settled,
                    topology_schedule,
                    self.local_shard,
                    self.committed_ts,
                    claims,
                )
            })
        };
        match verdict {
            SettledSetVerdict::Pass => {
                self.finalized.insert(tick_id, Arc::clone(&finalized_arc));
                vec![Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
                    finalizations: vec![finalized_arc],
                })]
            }
            SettledSetVerdict::Defer => {
                // Hold until evidence resolves the tick: the partner's
                // settled set reconstructs (pass or reject on membership),
                // its scheduled termination clears (pass), or the schedule
                // evicts it from every retained window (reject). Never
                // dropped on a clock — a deadline verdict here can
                // contradict a settlement the partner already committed.
                self.parked
                    .park(Waiting::Settlement, Parked::Built(finalized_arc));
                vec![]
            }
            SettledSetVerdict::Reject => {
                // The partner never settled this half, so it must never be
                // produced. Taking it was one-shot, so the tick will not
                // offer it again — and the members it named are left with
                // a tick that has stopped speaking for them. Releasing
                // their assignments hands them back to the deadline path,
                // which is the only thing that can still resolve them.
                //
                // The chain hears it with them. Only a half naming
                // counterparts reaches this verdict, which is the half
                // carrying the tick's legs, and a leg that will never be
                // produced holds nothing.
                for tx_hash in finalized_arc.tx_hashes() {
                    self.ticks.remove_assignment(tx_hash);
                }
                self.release_chain_holds(tick_id);
                self.drain_ready_tick_resolutions()
            }
        }
    }

    /// Record a past-terminal shard's settled-transaction set for the finalize
    /// gate (mirrors the shard coordinator's fence feed), and release
    /// what waited on it: the finalizations the gate held while the set
    /// was unknown, and the shard's certificates parked on a commit
    /// proof the departed chain can no longer supply — the set stands in
    /// for the proof of everything it names
    /// ([`Counterparts::settled_set_admits`]).
    ///
    /// Also arms the fallback fetch: what the partner says it settled and
    /// we are still waiting on is exactly the certificates it owes us, and
    /// the header that first named them may never have reached us.
    pub fn record_settled_txs(
        &mut self,
        topology_schedule: &TopologySchedule,
        shard: ShardId,
        settled: SettledTxSet,
    ) -> Vec<Action> {
        let now_ts = self.committed_ts;

        let owed: Vec<TxHash> = self
            .awaited_txs_from(shard)
            .into_iter()
            .filter(|tx_hash| settled.txs.contains(tx_hash))
            .filter(|tx_hash| !self.expected_certs.is_fulfilled(shard, *tx_hash))
            .collect();
        for tx_hash in owed {
            self.expected_certs.register(shard, tx_hash, now_ts);
        }

        // What this shard's ledger says the departed shard was party to,
        // taken beside the set: a departure record may name only these,
        // and the fence reads it from the same mirror.
        self.counterparts.on_settled(shard, settled);
        self.release(topology_schedule, Wake::SettledSet(shard))
    }

    /// Admission entry point for fetch-delivered (or otherwise externally
    /// sourced) finalizations.
    ///
    /// Runs [`Self::gate`] over every contained certificate and
    /// dispatches signature verification to the crypto pool via
    /// [`Action::VerifyFinalization`]. The matching
    /// [`ProtocolEvent::FinalizationVerified`] feeds
    /// [`Self::on_finalization_verified`], which emits
    /// `Continuation(FinalizationsAdmitted)` only when every EC's
    /// signature passed.
    ///
    /// Without this gate a peer answering a `finalization.request` could
    /// poison `caches.finalization` with a bogus tick we'd re-serve.
    /// Locally produced finalizations bypass this path: `finalize` emits the
    /// same event from a WC built out of already-verified ECs. Synced
    /// blocks are likewise trusted at admission — the QC chain plus the
    /// synced-block apply path's quorum gate established their integrity
    /// upstream.
    #[must_use]
    pub fn admit_finalization(
        &mut self,
        topology_schedule: &TopologySchedule,
        tick: Arc<Verifiable<Finalization>>,
    ) -> Vec<Action> {
        // Already-finalized short-circuit — a second fetch arrival for a
        // finalization we've already admitted is wasted verification work.
        if self.finalized.get(&tick.receipt_hash()).is_some() {
            tracing::debug!(
                tick = %tick.tick_id(),
                "Finalization already in canonical store — skipping verification"
            );
            return Vec::new();
        }
        match self.gate(topology_schedule, &tick) {
            Ok(ec_public_keys) => vec![Action::VerifyFinalization {
                finalization: tick,
                ec_public_keys,
            }],
            Err(Gate::InFlight) => Vec::new(),
            Err(Gate::BeaconBehind) => {
                self.parked.park(Waiting::Beacon, Parked::Fetched(tick));
                Vec::new()
            }
            Err(Gate::Refused(_)) => vec![Action::AbandonFetch(tick.abandon())],
        }
    }

    /// Re-drive every certificate and finalization held on a committee
    /// epoch the beacon has now reached. Called on `BeaconBlockPersisted`.
    pub fn on_beacon_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self.release(topology_schedule, Wake::Beacon);
        actions.push(Action::Fetch(FetchRequest::SettledTxs {
            wanted: self
                .counterparts
                .wanted_settled_sets(topology_schedule, self.committed_ts),
            preferred: None,
            class: None,
        }));
        actions
    }

    /// Handle the result of [`Action::VerifyFinalization`]. Emits the
    /// admission continuation only when every EC's signature passed.
    #[must_use]
    pub fn on_finalization_verified(
        &mut self,
        result: Result<Arc<Verified<Finalization>>, (Arc<Finalization>, FinalizationVerifyError)>,
    ) -> Vec<Action> {
        // Release the in-flight slot regardless of outcome — future
        // arrivals can dispatch again.
        let tick = match result {
            Ok(verified) => {
                self.pending_verifications
                    .remove(&verified.receipt_hash().into_raw());
                verified
            }
            Err((raw, err)) => {
                self.pending_verifications
                    .remove(&raw.receipt_hash().into_raw());
                tracing::warn!(
                    tick = %raw.tick_id(),
                    error = ?err,
                    "Dropping fetched Finalization: contained EC signature invalid"
                );
                return vec![Action::AbandonFetch(FetchIds::Finalizations(vec![
                    raw.receipt_hash(),
                ]))];
            }
        };
        // Lift the verification result into the `Block::Live.certificates`
        // transport shape exactly once so the admission event and any
        // downstream pending-block storage share the same `Arc`.
        let tick = Arc::new((*tick).clone().into());
        vec![Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
            finalizations: vec![tick],
        })]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Query Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the local tick assignment for a transaction.
    #[must_use]
    pub fn tick_assignment_for(&self, tx_hash: TxHash) -> Option<TickId> {
        self.ticks.tick_assignment(tx_hash)
    }

    /// Every finalization ready for inclusion, in the order a block must
    /// settle them.
    ///
    /// That order is tick order, and it is the store's own: a tick's
    /// certificate settles the writes that tick produced, and a later
    /// tick executed against the earlier one's output. `TickId` sorts by
    /// `(shard, height)`, so iterating the store is already the order
    /// receipts have to be applied in.
    ///
    /// Order is all this offers: which of them a block may carry is
    /// [`Self::owed_determined_ticks`] answered at admission, where a
    /// voter runs the same rule over its own fold.
    #[must_use]
    pub fn get_finalizations(&self) -> Vec<Arc<Verifiable<Finalization>>> {
        self.finalized.all()
    }

    /// Every tick whose determined half the chain still owes, by the
    /// block height its `TickId` names.
    ///
    /// A determined half settles writes a later tick has already read, so
    /// the halves settle in tick order or the chain agrees on a state
    /// nothing can detect afterwards. Admission holds that order by
    /// refusing a half that settles past a tick in this set, which is why
    /// the set is read here rather than filtered here: a proposer's own
    /// ticks are the wrong authority for a rule every voter has to reach
    /// the same answer on, and a validator that never composed the
    /// earlier tick offers the later half in good faith.
    ///
    /// A validator missing the earlier tick holds it in no set and so
    /// enforces nothing, which is the safe direction: the rule can refuse
    /// a block no honest proposer would build, and never accepts one a
    /// composing quorum refuses.
    #[must_use]
    pub fn owed_determined_ticks(&self) -> BTreeSet<BlockHeight> {
        self.ticks
            .ticks_iter()
            .filter(|(_, tick)| tick.determined_unsettled())
            .map(|(tick_id, _)| tick_id.block_height())
            .collect()
    }

    /// Whether provisions from `shard` have been absorbed for `tx_hash` —
    /// committed chain content, since absorption runs at block commit.
    /// The proposal seam's engagement check reads this for the payer
    /// shard of a cross-shard transaction.
    #[must_use]
    pub fn has_provisions_from(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.provisioning.has_received_from(tx_hash, shard)
    }

    /// Get a finalization by its identity (returns `Arc` for sharing).
    #[must_use]
    pub fn get_finalization(
        &self,
        hash: &FinalizationHash,
    ) -> Option<Arc<Verifiable<Finalization>>> {
        self.finalized.get(hash)
    }

    /// Bloom filter over every transaction in a tracked finalization.
    /// Attached to outgoing `GetBlockRequest`s so the responder can elide
    /// finalizations the requester already has. Returns `None` when the
    /// cached set is too large to size a filter within the configured cap.
    #[must_use]
    pub fn cert_bloom_snapshot(&self) -> Option<BloomFilter<TxHash>> {
        self.finalized.cert_bloom_snapshot()
    }

    /// Get the finalization containing a specific transaction.
    ///
    /// Returns the tick if the tx is part of one that finalized. Once
    /// committed, ticks are persisted to storage and should be fetched
    /// from there.
    #[must_use]
    pub fn get_finalization_for_tx(
        &self,
        tx_hash: TxHash,
    ) -> Option<Arc<Verifiable<Finalization>>> {
        self.finalized.get_for_tx(tx_hash)
    }

    /// Remove a finalization (after its finalization has been committed in a block).
    ///
    /// Cleans up all per-tx tracking state for transactions in this tick.
    /// Takes the `Finalization` directly (rather than just a `TickId`) so
    /// cleanup works even when the tick was never aggregated locally — e.g.
    /// for blocks received via sync. The committed `Finalization` is the
    /// authoritative tx-set source.
    pub fn remove_finalization(&mut self, fw: &Finalization) {
        let tick_id = fw.tick_id();
        self.finalized.remove(&fw.receipt_hash());

        let tx_hashes: Vec<TxHash> = fw.tx_hashes().collect();
        // A tick settles in two halves, so the first one committing says
        // nothing about the second. Drop the tick and its certificate
        // only once every member it holds has been resolved — otherwise
        // the legs half loses the state it is still owed from.
        let fully_resolved = self
            .ticks
            .get_tick_mut(tick_id)
            .is_none_or(|tick| tick.record_settled(tx_hashes.iter().copied()));
        if fully_resolved {
            // The local-shard EC is now durable in storage via the
            // committed finalization; drop the in-memory copy so peers
            // fetching after this point fall through to storage.
            self.exec_certs.evict(tick_id);
            // The tick may be absent entirely (sync path: the block was
            // received as committed without local tracking), which is fine.
            self.ticks.remove_tick(tick_id);
        }
        for &tx_hash in &tx_hashes {
            self.ticks.remove_assignment(tx_hash);
        }
        // Drain pending-tx sets on fulfilled-cert tombstones referencing
        // any of these txs. When the EC's last referenced tx terminates,
        // the tombstone evicts — independent of any wall-clock window.
        self.expected_certs
            .on_txs_terminated(tx_hashes.iter().copied());
    }

    /// Drop every pending tick and EC expectation. Called once when the
    /// local chain terminates at a reshape boundary: finalization is a
    /// finalization in a later block, and a terminated chain commits
    /// no later block, so every pending tick here is permanently
    /// undecidable. Serving state (aggregated ECs, finalizations)
    /// stays — peers still fetch what this chain produced.
    pub fn abort_pending_ticks(&mut self) -> Vec<Action> {
        let counts = self.ticks.drain_all();
        let mut expected = self.expected_certs.drain_expected();
        expected.sort();
        tracing::info!(
            ticks = counts.ticks,
            trackers = counts.trackers,
            assignments = counts.assignments,
            expected_certs = expected.len(),
            unresolved = self.counterparts.ledger.len(),
            "Chain terminated — dropped pending execution state"
        );
        // What the chain owes an outcome for goes with the rest. The
        // ledger's entries are abandonable at their deadlines, and a
        // deadline falling after the terminal would have this chain
        // compose a tick to abandon them in — on a coast block, under a
        // committee it no longer has. Nothing here can reach a verdict
        // either way, which is the same reason the ticks above go.
        self.counterparts.ledger = UnresolvedTxs::new(self.local_shard);
        // The terminated chain's tick outputs die with it: successors seed
        // from settled state, and pending resolutions have nothing left to
        // resolve against. A tick still in flight lands on a cleared
        // chain, so its completion must be able to release the queue.
        self.pending_tick_resolutions.clear();
        self.pending_ticks.clear();
        self.ticked.clear();
        self.tick_in_flight = false;
        let mut actions = vec![Action::ClearTickChain];
        if !expected.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::ExecutionCerts(expected)));
        }
        actions
    }

    /// Prune stale tick state (ticks, vote trackers, early votes).
    ///
    /// Ticks stay alive while their `tick_assignment`s list them — an
    /// active assignment means the transaction hasn't reached terminal
    /// state (TC committed or abort completed) so late-arriving votes and
    /// conflicts can still resolve it. Early execution votes follow a
    /// separate policy tied to the registry's state plus a timestamp
    /// retention floor.
    fn prune_execution_state(&mut self) {
        let counts = self.ticks.prune_resolved();

        // Early execution votes:
        // - Tick resolved (EC formed) → votes no longer needed
        // - Leader replayed them (VoteTracker exists) → already consumed
        // - No tick and older than `EARLY_VOTE_RETENTION` → block never
        //   committed, shard consensus broken
        //
        // Non-leaders with a tick but no VoteTracker KEEP early votes. They
        // may become fallback leaders via rotation and need to replay them
        // into the on-demand VoteTracker created in `on_execution_vote`.
        let ev_cutoff = self.committed_ts.minus(EARLY_VOTE_RETENTION);
        let before_ev = self.early.vote_len();
        let registry = &self.ticks;
        self.early.retain_votes(|key, votes| {
            if registry.is_ec_dispatched(key) {
                return false;
            }
            if registry.contains_tracker(key) {
                return false;
            }
            if registry.contains_tick(key) {
                return true;
            }
            votes
                .first()
                .is_some_and(|v| v.vote_anchor_ts() > ev_cutoff)
        });
        let pruned_ev = before_ev - self.early.vote_len();

        if counts.ticks > 0 || counts.trackers > 0 || pruned_ev > 0 || counts.assignments > 0 {
            tracing::debug!(
                pruned_ticks = counts.ticks,
                pruned_vt = counts.trackers,
                pruned_ev,
                pruned_wa = counts.assignments,
                "Pruned resolved tick state"
            );
        }
    }

    /// Check if a transaction is finalized (part of a finalization).
    #[must_use]
    pub fn is_finalized(&self, tx_hash: TxHash) -> bool {
        self.finalized.is_finalized(tx_hash)
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to shard consensus for conflict filtering.
    #[must_use]
    pub fn finalized_tx_hashes(&self) -> HashSet<TxHash> {
        self.finalized.all_tx_hashes()
    }

    /// Get debug info about tick state for a transaction.
    #[must_use]
    pub fn certificate_tracking_debug(&self, tx_hash: TxHash) -> String {
        let tick_info = self.ticks.tick_assignment(tx_hash).map_or_else(
            || "no tick assignment".to_string(),
            |tick_id| {
                self.ticks.get_tick(&tick_id).map_or_else(
                    || {
                        if self.finalized.contains(&tick_id) {
                            format!("tick={tick_id}, finalized")
                        } else {
                            format!("tick={tick_id}, no tracker")
                        }
                    },
                    |tick| {
                        let determined = tick.determined_ready();
                        let legs = tick.legs_ready();
                        format!("tick={tick_id}, determined_ready={determined}, legs_ready={legs}")
                    },
                )
            },
        );

        let early_count = self.early.attestation_count_for_tx(tx_hash);

        format!("{tick_info}, early_attestations={early_count}")
    }

    /// Get execution memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> ExecutionMemoryStats {
        ExecutionMemoryStats {
            tick_execution_receipts: self
                .ticks
                .ticks_iter()
                .map(|(_, w)| w.receipt_count())
                .sum(),
            finalizations: self.finalized.len(),
            ticks: self.ticks.ticks_len(),
            unresolved_txs: self.counterparts.ledger.len(),
            vote_trackers: self.ticks.trackers_len(),
            early_votes: self.early.vote_len(),
            expected_exec_certs: self.expected_certs.expected_len(),
            absorbed_provisions: self.provisioning.absorbed_len(),
            required_provision_shards: self.provisioning.required_len(),
            ticks_with_ec: self.ticks.ec_dispatched_len(),
            pending_vote_retries: self.ticks.retries_len(),
            tick_assignments: self.ticks.assignments_len(),
            early_attestations: self.early.tx_index_len(),
            pending_routing: self.early.pending_routing_len(),
            fulfilled_exec_certs: self.expected_certs.fulfilled_len(),
            outbound_certs: self.outbound_certs.memory_stats().tracked_certificates,
            proven_remote_blocks: self.counterparts.proven_anchors.len(),
            unproven_ecs: self.parked.waiting_on(|w| matches!(w, Waiting::Proof(_))),
        }
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes in cross-shard ticks that haven't yet
    /// finalized. Covers provisioning, voting, and certificate collection
    /// phases uniformly (one `TickState` tracks all of them).
    #[must_use]
    pub fn cross_shard_pending_count(&self) -> usize {
        self.ticks.cross_shard_pending_count()
    }
}

impl std::fmt::Debug for ExecutionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCoordinator")
            .field("finalizations", &self.finalized.len())
            .field("ticks", &self.ticks.ticks_len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::time::Duration;

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_storage::{ReplayWindow, committed_tx_cell_key};
    use hyperscale_types::test_utils::{
        StubVmStatics, certify as test_certify, make_finalization as helpers_make_finalization,
        make_finalization_leaving, make_leg_finalization,
        make_live_block as helpers_make_live_block, state_and_proof, test_prefix, test_transaction,
        test_transaction_running, test_transaction_with_prefixes,
    };
    use hyperscale_types::{
        AbandonmentRecord, AbortCharge, Address, AddressClass, AggregateSignature,
        BeaconWitnessLeafCount, CLAIM_VISIBILITY_LAG, ConsensusPublicKey, ConsensusReceipt,
        ConsensusSignature, CounterpartEvidence, EPOCH_DURATION, Epoch, EpochSeed, EpochWindows,
        ExecutionOutcome, GlobalReceiptHash, Hash, Heard, LocalKey, MAX_FINALIZATION_DELAY,
        MAX_UNSETTLED_PER_BLOCK, MAX_VALIDITY_RANGE, NetworkDefinition, Probed, Question,
        QuorumCertificate, RETENTION_HORIZON, Randomness, RecoveryCause, SeedRing, SeedSource,
        ShardAnchor, ShardRecovery, Signer, SignerBitfield, StateClaim, StateRoot, StoredReceipt,
        SubstateKey, TickHalf, TransactionDecision, TxClaim, TxResolution, UnsettledTx,
        ValidatorInfo, ValidatorSet, Window, Word,
    };
    use hyperscale_vm_effects::{CrossingCell, Hash32, SubintentHash};
    use hyperscale_vm_types::{ResourceAddr, Seeded};

    use super::*;
    use crate::counterparts::Inherited;
    use crate::unresolved::{Kept, Part};

    fn make_test_topology() -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();

        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            validator_set,
        )))
    }

    /// A topology whose `shard` is under a halt recovery frozen at
    /// `frontier`: an old-committee EC from that shard above the frontier is
    /// the orphan the cross-shard freeze must fence.
    fn make_test_topology_recovering(shard: ShardId, frontier: BlockHeight) -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let mut recoveries = BTreeMap::new();
        recoveries.insert(
            shard,
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at: Epoch::GENESIS,
                retained: vec![ValidatorId::new(0)],
                attested_frontier: frontier,
            },
        );
        TopologySchedule::single(Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(validators),
            )
            .with_pending_recoveries(recoveries),
        ))
    }

    /// A tick holding `txs`, each admitted with its participating shards.
    fn tick_holding(
        tick_id: TickId,
        tick_ts: WeightedTimestamp,
        txs: Vec<(Arc<Verified<Transaction>>, BTreeSet<ShardId>)>,
    ) -> TickState {
        let mut state = TickState::new(
            tick_id,
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            tick_ts,
        );
        for (tx, participating) in txs {
            state.admit(
                tx.hash(),
                Membership::whole(participating),
                tx.work(),
                Admission::Executes,
            );
        }
        state
    }

    /// Lift a test transaction into the verified form a tick holds.
    fn verified_arc(tx: &Arc<Transaction>) -> Arc<Verified<Transaction>> {
        Arc::new(Verified::new_unchecked_for_test((**tx).clone()))
    }

    /// Three of four signers: the quorum the admission gate holds a
    /// fetched certificate to before its signature is verified.
    fn quorum_signers() -> SignerBitfield {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        signers
    }

    fn make_test_state() -> ExecutionCoordinator {
        make_test_state_for(ValidatorId::new(0))
    }

    fn make_test_state_for(me: ValidatorId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, ShardId::ROOT)
    }

    fn make_test_state_for_shard(me: ValidatorId, local_shard: ShardId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, local_shard)
    }

    fn make_live_block(
        height: BlockHeight,
        timestamp_ms: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<Transaction>>,
    ) -> Block {
        helpers_make_live_block(
            ShardId::ROOT,
            height,
            timestamp_ms,
            proposer,
            transactions,
            vec![],
        )
    }

    fn make_live_block_on_shard(
        shard: ShardId,
        height: BlockHeight,
        timestamp_ms: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<Transaction>>,
    ) -> Block {
        helpers_make_live_block(shard, height, timestamp_ms, proposer, transactions, vec![])
    }

    fn certify(block: Block) -> CertifiedBlock {
        test_certify(block, 0)
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );

        // Block committed with transaction
        let actions = state.on_block_committed(&topology_schedule, &certify(block));

        // Should request execution (single-shard path) and set up tick tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ExecuteTransactions { .. }))
        );

        // TickState should be set up for this tick.
        let tick_id = state.ticks.tick_assignment(tx_hash);
        assert!(tick_id.is_some());
        assert!(state.ticks.contains_tick(&tick_id.unwrap()));
    }

    /// A tick composes whatever the block committed, and waits at the
    /// dispatch head for code this node has not fetched.
    ///
    /// Membership is what the committee votes over, so it cannot turn on
    /// local holdings; running a member whose code is missing would reach
    /// the engine's no-code refusal while every replica holding the bytes
    /// settled it. So the tick is composed either way and held here, and
    /// what dispatches when the fetch lands is the tick composed now.
    #[test]
    fn a_tick_waits_at_the_dispatch_head_for_code_this_node_lacks() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();

        let package = Hash::from_bytes(b"a package this node has not fetched");
        state.on_missing_packages_updated(vec![package]);

        let tx = test_transaction_running(1, &[package]);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let actions = state.on_block_committed(&topology_schedule, &certify(block));

        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::ExecuteTransactions { .. })),
            "a tick running unfetched code must not dispatch"
        );
        assert!(
            state.ticks.tick_assignment(tx_hash).is_some(),
            "the tick is composed regardless — only its dispatch waits"
        );

        // The fetch lands and the held tick goes, unchanged.
        let released = state.on_packages_acquired(&[package]);
        let dispatched: Vec<&TxHash> = released
            .iter()
            .filter_map(|action| match action {
                Action::ExecuteTransactions { requests, .. } => Some(requests),
                _ => None,
            })
            .flatten()
            .map(|request| &request.tx_hash)
            .collect();
        assert_eq!(
            dispatched,
            vec![&tx_hash],
            "acquiring the package releases exactly the tick that waited on it"
        );
    }

    /// A package nothing in the queued tick runs never holds it.
    #[test]
    fn an_unrelated_missing_package_holds_no_tick() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();

        state.on_missing_packages_updated(vec![Hash::from_bytes(b"someone else's code")]);

        let tx = test_transaction_running(1, &[Hash::from_bytes(b"code this node holds")]);
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let actions = state.on_block_committed(&topology_schedule, &certify(block));

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ExecuteTransactions { .. })),
            "only the code a member runs can hold its tick"
        );
    }

    fn make_topology() -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            validator_set,
        )))
    }

    /// A tick that completes while its committee is unresolvable must keep
    /// its vote.
    ///
    /// The vote is one-shot: `build_vote_data` marks the tick voted during
    /// the scan, and nothing ever clears that mark. The committee lookup
    /// happens afterwards, in `emit_vote_actions`, so a scan that finds no
    /// committee spends the vote and emits nothing — no action, no retry
    /// registration, and `can_emit_vote` false forever after. The tick then
    /// A batch returning for a tick this coordinator has stopped tracking
    /// says where the coordinator is, not what the tick's fate was.
    ///
    /// The first resolution recorded for a tick is the one the chain
    /// applies, so claiming an abandonment here would consume the entry
    /// the tick's real verdict needs — and the verdict that follows a
    /// local finalization is a settlement, which promotes writes an abort
    /// would have dropped.
    #[test]
    fn a_batch_for_an_untracked_tick_resolves_nothing() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            1_000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        state.on_block_committed(&schedule, &test_certify(block, 1_000));

        let tick_id = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the committed tx is assigned to a tick");
        assert!(
            state.ticked.contains_key(&tick_id),
            "the tick joined a tick at commit",
        );

        // The tick finalizes locally, which untracks it, and its batch
        // returns afterwards.
        state.ticks.remove_tick(&tick_id);
        state.on_execution_batch_completed(
            &schedule,
            BlockHeight::new(1),
            TickBatchOutcome {
                tick_id,
                results: vec![],
                tx_outcomes: vec![TxOutcome::new(tx_hash, ExecutionOutcome::Failed)],
                fee_receipts: vec![],
                attested_work: vec![],
            },
        );

        assert!(
            state.ticked.contains_key(&tick_id),
            "the tick's tick entry must survive for its real verdict to claim",
        );
        assert!(
            state.pending_tick_resolutions.is_empty(),
            "no fate was decided, so none may be recorded",
        );
    }

    /// holds its locks and never certifies, which is indistinguishable at
    /// the mempool from a tick that was never ready.
    #[test]
    fn a_tick_keeps_its_vote_when_the_committee_cannot_be_resolved() {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let snapshot = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        ));

        // Second-long windows, with only epoch 0 recorded: a tick anchored
        // at 5000ms falls in epoch 5, which the schedule cannot answer for.
        let unresolvable = TopologySchedule::new(1_000, Epoch::new(0), Arc::clone(&snapshot));
        let mut resolved = unresolvable.clone();
        resolved.insert(Epoch::new(5), Arc::clone(&snapshot));

        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            5_000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        state.on_block_committed(&unresolvable, &test_certify(block, 5_000));

        // Execution lands, so the tick is complete and ready to vote.
        let tick_id = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the committed tx is assigned to a tick");
        state.on_execution_batch_completed(
            &unresolvable,
            BlockHeight::new(1),
            TickBatchOutcome {
                tick_id,
                results: vec![],
                tx_outcomes: vec![TxOutcome::new(tx_hash, ExecutionOutcome::Failed)],
                fee_receipts: vec![],
                attested_work: vec![],
            },
        );

        let blocked = state.emit_vote_actions(&unresolvable);
        assert!(
            blocked.is_empty(),
            "an unresolvable committee routes nowhere, got {blocked:?}",
        );

        // The tick was ready the whole time; only the routing was missing.
        // Once the schedule carries its epoch the vote must still be there.
        let recovered = state.emit_vote_actions(&resolved);
        assert!(
            recovered
                .iter()
                .any(|a| matches!(a, Action::SignAndSendExecutionVote { .. })),
            "the tick must still vote once its committee resolves, got {recovered:?}",
        );
    }

    #[test]
    fn test_only_leader_gets_vote_tracker() {
        let tx = test_transaction(1);

        // Determine who the tick leader will be for this block's tick.
        let topo0 = make_topology();
        let committee = topo0.head().committee_for_shard(ShardId::ROOT).to_vec();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );

        // Commit the block as validator 0 to discover the tick_id.
        let mut state0 = make_test_state();
        state0.on_block_committed(&topo0, &certify(block));
        let tick_id = state0
            .ticks
            .ticks_iter()
            .next()
            .map(|(wid, _)| *wid)
            .unwrap();

        let leader = tick_leader(&tick_id, &committee);

        // Leader should have a VoteTracker.
        let topo_leader = make_topology();
        let block_leader = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_leader = make_test_state_for(leader);
        state_leader.on_block_committed(&topo_leader, &certify(block_leader));
        assert!(
            state_leader.ticks.contains_tracker(&tick_id),
            "Leader should have VoteTracker"
        );

        // A non-leader should NOT have a VoteTracker.
        let non_leader_id = *committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology();
        let block_non = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let mut state_non = make_test_state_for(non_leader_id);
        state_non.on_block_committed(&topo_non, &certify(block_non));
        assert!(
            !state_non.ticks.contains_tracker(&tick_id),
            "Non-leader should NOT have VoteTracker"
        );
    }

    #[test]
    fn test_fallback_tracker_created_on_vote() {
        let tx = test_transaction(1);
        let topo = make_topology();
        let committee = topo.head().committee_for_shard(ShardId::ROOT).to_vec();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );
        let block_hash = block.hash();

        let mut state = make_test_state();
        state.on_block_committed(&topo, &certify(block));

        let tick_id = state
            .ticks
            .ticks_iter()
            .next()
            .map(|(wid, _)| *wid)
            .unwrap();
        let leader = tick_leader(&tick_id, &committee);

        // If we're the leader, this test doesn't apply — find a non-leader topology.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology();
        let block_non = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let mut state_non = make_test_state_for(*non_leader_id);
        state_non.on_block_committed(&topo_non, &certify(block_non));

        assert!(!state_non.ticks.contains_tracker(&tick_id));
        assert!(state_non.ticks.contains_tick(&tick_id));

        // Simulate receiving a vote (as if we're a fallback leader).
        let fake_vote = ExecutionVote::new(
            block_hash,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            tick_id,
            ShardId::ROOT,
            GlobalReceiptRoot::ZERO,
            1,
            vec![],
            leader,
            ConsensusSignature::ZERO,
        );

        state_non.on_unverified_execution_vote(&topo_non, fake_vote);

        // Should have created a fallback VoteTracker.
        assert!(
            state_non.ticks.contains_tracker(&tick_id),
            "Fallback VoteTracker should be created"
        );
    }

    #[test]
    fn on_execution_vote_drops_non_committee_voter() {
        // Vote claiming to be from a validator outside the local shard
        // committee must be rejected at the top of on_execution_vote, with
        // no early-buffer or tracker side effect. Otherwise the vote could
        // pool its cross-shard power into the tracker and trigger premature
        // aggregation that produces an EC the verifier will reject.
        let topo = make_two_shard_topology();
        let local = topo.head().committee_for_shard(ShardId::leaf(1, 0));
        let outsider = (0u64..4)
            .map(ValidatorId::new)
            .find(|v| !local.contains(v))
            .expect("two-shard topology has at least one non-local validator");

        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));
        let tick_id = TickId::new(ShardId::leaf(1, 0), BlockHeight::new(1));
        let vote = ExecutionVote::new(
            BlockHash::ZERO,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            tick_id,
            ShardId::leaf(1, 0),
            GlobalReceiptRoot::ZERO,
            0,
            vec![],
            outsider,
            ConsensusSignature::ZERO,
        );

        let actions = state.on_unverified_execution_vote(&topo, vote);
        assert!(actions.is_empty(), "non-committee vote must be dropped");
        assert!(
            !state.ticks.contains_tracker(&tick_id),
            "rejected vote must not seed a fallback VoteTracker"
        );
        assert_eq!(
            state.memory_stats().pending_routing,
            0,
            "rejected vote must not be early-buffered"
        );
    }

    #[test]
    fn test_vote_retry_timeout_emits_rotated_action() {
        use crate::ticks::VOTE_RETRY_TIMEOUT;
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();
        let committee = topo.head().committee_for_shard(ShardId::ROOT).to_vec();

        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(20);
        // "Now" timestamp exactly VOTE_RETRY_TIMEOUT past the original send.
        state.committed_ts = WeightedTimestamp::from_millis(10_000).plus(VOTE_RETRY_TIMEOUT);

        // Manually insert a pending retry as if we'd sent a vote at t=10_000ms.
        state.ticks.record_vote_retry(
            tick_id,
            PendingVoteRetry {
                sent_at: WeightedTimestamp::from_millis(10_000),
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"block1")),
                block_height: BlockHeight::new(1),
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        let actions = state.check_vote_retry_timeouts(&topo);

        // Elapsed == VOTE_RETRY_TIMEOUT, so should emit retry.
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SignAndSendExecutionVote {
                leader,
                tick_id: wid,
                ..
            } => {
                assert_eq!(wid, &tick_id);
                let expected_leader = tick_leader_at(&tick_id, Attempt::new(1), &committee);
                assert_eq!(*leader, expected_leader, "Should rotate to attempt 1");
            }
            other => panic!(
                "Expected SignAndSendExecutionVote, got {:?}",
                other.type_name()
            ),
        }

        // The retry is still tracked with its cooldown re-anchored at the
        // current committed timestamp — advance exactly one more
        // VOTE_RETRY_TIMEOUT and check that a retry at attempt 2 fires.
        state.committed_ts = state.committed_ts.plus(VOTE_RETRY_TIMEOUT);
        let next = state.check_vote_retry_timeouts(&topo);
        assert_eq!(next.len(), 1);
        if let Action::SignAndSendExecutionVote { leader, .. } = &next[0] {
            let expected = tick_leader_at(&tick_id, Attempt::new(2), &committee);
            assert_eq!(*leader, expected, "second fire rotates to attempt 2");
        } else {
            panic!("expected SignAndSendExecutionVote");
        }
    }

    #[test]
    fn test_vote_retry_cancelled_on_ec_receipt() {
        use crate::ticks::VOTE_RETRY_TIMEOUT;
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();

        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(10);
        state.ticks.record_vote_retry(
            tick_id,
            PendingVoteRetry {
                sent_at: WeightedTimestamp::from_millis(5_000),
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"block1")),
                block_height: BlockHeight::new(1),
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        // Simulate receiving a verified local shard EC with quorum signers.
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        );
        state.on_certificate_verified(&topo, Ok(Arc::new(Verified::new_unchecked_for_test(cert))));

        // Advance time past the retry deadline; if the retry had survived,
        // this would fire a SignAndSendExecutionVote action.
        state.committed_ts = WeightedTimestamp::from_millis(5_000).plus(VOTE_RETRY_TIMEOUT);
        let actions = state.check_vote_retry_timeouts(&topo);
        assert!(
            actions.is_empty(),
            "EC receipt must cancel the retry so no action fires"
        );
    }

    #[test]
    fn on_certificate_verified_rejects_subquorum_ec() {
        // A single Byzantine signer can produce a signature-valid EC. Without a
        // quorum-power gate, that sub-quorum EC would clear the expected-
        // cert record, populate the local-shard fallback-serving cache,
        // and feed tick attestation. The rejection also emits an
        // `AbandonFetch::ExecutionCerts` naming every transaction the cert
        // claimed, so each pinned fetch releases its FSM slot.
        let topo = make_test_topology();
        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(10);

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));

        let mut signers = SignerBitfield::new(4);
        signers.set(0); // single signer — well below 2f+1 = 3
        let covered_tx = TxHash::from(Hash::from_bytes(b"covered by the refused cert"));
        let cert = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                covered_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::ZERO,
            signers,
        ));

        let verified = Arc::new(Verified::new_unchecked_for_test((*cert).clone()));
        let actions = state.on_certificate_verified(&topo, Ok(verified));
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::ExecutionCertificateAdmitted { .. })
            )),
            "sub-quorum EC must produce no admission continuation"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::ExecutionCerts(ids)) if ids == &vec![(tick_id.shard_id(), covered_tx)]
            )),
            "sub-quorum drop must emit AbandonFetch::ExecutionCerts, got: {actions:?}"
        );
        assert!(
            state.exec_certs.get(&tick_id).is_none(),
            "sub-quorum EC must not enter the local-shard serving cache"
        );
    }

    #[test]
    fn on_certificate_verified_invalid_sig_abandons_fetch() {
        // signature verification returns `valid=false`. The cert is
        // dropped without admission, and the FSM is told to release the
        // in-flight slot.
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let covered_tx = TxHash::from(Hash::from_bytes(b"covered by the refused cert"));
        let cert = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                covered_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::ZERO,
            signers,
        ));

        let actions = state.on_certificate_verified(
            &topo,
            Err((
                cert,
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::ExecutionCerts(ids)) if ids == &vec![(tick_id.shard_id(), covered_tx)]
            )),
            "invalid-sig drop must emit AbandonFetch::ExecutionCerts, got: {actions:?}"
        );
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::ExecutionCertificateAdmitted { .. })
            )),
            "invalid-sig must not emit admission continuation"
        );
    }

    // Note: the committee-keys-fail branch of `on_execution_certificate` is
    // structurally covered (emits the abandon when
    // `committee_public_keys_for_shard` returns `None`) but is not
    // exercised by a unit test here — `None` only fires when a known
    // committee member is missing a public key in the topology, a
    // corruption condition the public test fixtures can't easily
    // construct. Realistic failures (unknown shard with empty committee)
    // dispatch with an empty key set and fall through to the invalid-sig
    // branch, which is covered above.

    /// Who a certificate is broadcast to is a question about the batch's
    /// transactions, not its identity: the shards their participants name.
    /// A batch holding a transaction shard 1 is party to owes shard 1 the
    /// certificate — and what shard 1 receives is the outcome for that
    /// transaction, not the batch.
    #[test]
    fn test_leader_broadcasts_ec_locally() {
        use hyperscale_types::compute_global_receipt_root;
        use hyperscale_types::test_utils::test_transaction;

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();

        let mut state = make_test_state();
        let tx = Arc::new(test_transaction(3));
        let participating: BTreeSet<ShardId> =
            [ShardId::ROOT, ShardId::leaf(1, 1)].into_iter().collect();
        state.ticks.insert_tick(
            tick_id,
            tick_holding(
                tick_id,
                WeightedTimestamp::ZERO,
                vec![(verified_arc(&tx), participating)],
            ),
        );

        let outcomes = vec![TxOutcome::new(tx.hash(), ExecutionOutcome::Aborted)];
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            compute_global_receipt_root(&outcomes),
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );

        let actions = state.on_certificate_aggregated(
            &topo,
            &tick_id,
            &Arc::new(Verified::new_unchecked_for_test(cert)),
        );

        // Should have: BroadcastEC(local) + BroadcastEC(remote shard 1)
        let broadcast_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::BroadcastExecutionCertificate { .. }))
            .collect();

        assert!(
            broadcast_actions.len() >= 2,
            "Should broadcast to local peers AND remote shards, got {}",
            broadcast_actions.len()
        );

        // One should be for the local shard (shard 0).
        let has_local = broadcast_actions.iter().any(|a| match a {
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardId::ROOT,
            _ => false,
        });
        assert!(has_local, "Should include local shard broadcast");

        // One should be for the remote shard (shard 1).
        let has_remote = broadcast_actions.iter().any(|a| match a {
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardId::leaf(1, 1),
            _ => false,
        });
        assert!(has_remote, "Should include remote shard broadcast");
    }

    /// A shard receives the outcomes for the transactions it is party to
    /// and nothing else, while this shard's own peers receive the whole
    /// batch — they are building the same finalization we are.
    #[test]
    fn a_remote_shard_receives_only_its_own_transactions() {
        use hyperscale_types::compute_global_receipt_root;
        use hyperscale_types::test_utils::test_transaction;

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();
        let mut state = make_test_state();

        let shared = Arc::new(test_transaction(3));
        let ours = Arc::new(test_transaction(4));
        state.ticks.insert_tick(
            tick_id,
            tick_holding(
                tick_id,
                WeightedTimestamp::ZERO,
                vec![
                    (
                        verified_arc(&shared),
                        [ShardId::ROOT, ShardId::leaf(1, 1)].into_iter().collect(),
                    ),
                    (
                        verified_arc(&ours),
                        std::iter::once(ShardId::ROOT).collect(),
                    ),
                ],
            ),
        );

        let outcomes = vec![
            TxOutcome::new(shared.hash(), ExecutionOutcome::Aborted),
            TxOutcome::new(ours.hash(), ExecutionOutcome::Aborted),
        ];
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            compute_global_receipt_root(&outcomes),
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );

        let actions = state.on_certificate_aggregated(
            &topo,
            &tick_id,
            &Arc::new(Verified::new_unchecked_for_test(cert)),
        );

        let sent = |target: ShardId| -> Arc<Verified<ExecutionCertificate>> {
            actions
                .iter()
                .find_map(|a| match a {
                    Action::BroadcastExecutionCertificate {
                        shard, certificate, ..
                    } if *shard == target => Some(Arc::clone(certificate)),
                    _ => None,
                })
                .expect("a broadcast for the target shard")
        };

        let remote = sent(ShardId::leaf(1, 1));
        assert_eq!(
            remote.tx_outcomes().len(),
            1,
            "the remote shard is party to one of the two"
        );
        assert!(remote.covers(&shared.hash()));
        assert!(!remote.covers(&ours.hash()));
        assert_eq!(
            remote.tx_count(),
            2,
            "the projection still names the whole batch it proves against"
        );
        assert_eq!(
            remote.global_receipt_root(),
            sent(ShardId::ROOT).global_receipt_root()
        );

        let local = sent(ShardId::ROOT);
        assert!(local.is_complete(), "our own peers get the whole batch");
    }

    /// `admit_finalization` must NOT emit `FinalizationsAdmitted`
    /// inline — that would mean signature verification ran on the state-machine
    /// thread, bringing back the pre-async stall on the consensus path.
    /// The expected output is a single `VerifyFinalization` action; the
    /// admission continuation only fires once the verify event lands.
    #[test]
    fn admit_finalization_dispatches_async_verify() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> =
            Arc::new(Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]).into());
        let _fw_hash = tick.receipt_hash();

        let actions = state.admit_finalization(&topo, tick);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::VerifyFinalization { .. }));
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizationsAdmitted { .. })
            )),
            "admission continuation must only fire after async verify"
        );
    }

    /// `on_finalization_verified` with `valid = false` must drop the tick
    /// rather than emit the admission continuation — that's exactly the
    /// poisoning vector this gate exists to close. The dropped tick also
    /// surfaces a `FetchIds::Finalizations` so any pinned fetch
    /// FSM entry releases its slot.
    #[test]
    fn on_finalization_verified_drops_invalid() {
        let mut state = make_test_state();
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        ));
        let tick = Arc::new(Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![ec],
            vec![],
        ));
        let fw_hash = tick.receipt_hash();
        let actions = state.on_finalization_verified(Err((
            tick,
            FinalizationVerifyError::ExecutionCertificate {
                index: 0,
                source: ExecutionCertificateVerifyError::BadAggregatedSignature,
            },
        )));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::Finalizations(ids)) if ids == &vec![fw_hash]
            )),
            "Signature-invalid drop must emit AbandonFetch::Finalizations, got: {actions:?}"
        );
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizationsAdmitted { .. })
            )),
            "must not emit admission continuation on invalid"
        );
    }

    /// `admit_finalization` with an EC lacking quorum power must emit
    /// the abandon (so the FSM doesn't pin) AND must clear the in-flight
    /// dedup set so future arrivals can retry — without that the same
    /// `TickId` would silently fail every subsequent admission.
    #[test]
    fn admit_finalization_quorum_power_fail_abandons_and_clears_dedup() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        // Only one signer in a 4-validator committee — sub-quorum
        // (2f+1=3 needed).
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> =
            Arc::new(Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]).into());
        let fw_hash = tick.receipt_hash();

        let actions = state.admit_finalization(&topo, Arc::clone(&tick));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::Finalizations(ids)) if ids == &vec![fw_hash]
            )),
            "quorum-power drop must emit AbandonFetch::Finalizations, got: {actions:?}"
        );

        // Regression: dedup set must NOT retain this tick so a fresh
        // arrival of the same id (e.g., a peer retransmitting after
        // gossiping a corrected tick) is allowed to dispatch.
        let retry_actions = state.admit_finalization(&topo, tick);
        assert!(
            retry_actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::Finalizations(..)))),
            "retry must still reach the quorum gate, got: {retry_actions:?}"
        );
    }

    /// `admit_finalization` with an unresolvable committee shard must
    /// emit the abandon AND clear the dedup set, same shape as the
    /// quorum-power path.
    #[test]
    fn admit_finalization_unknown_committee_abandons_and_clears_dedup() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        // EC for a shard the test topology doesn't know about — the
        // committee-keys lookup returns `None` and triggers the gate.
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            TickId::new(ShardId::leaf(8, 99), BlockHeight::new(1)),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> =
            Arc::new(Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]).into());
        let fw_hash = tick.receipt_hash();

        let actions = state.admit_finalization(&topo, Arc::clone(&tick));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::Finalizations(ids)) if ids == &vec![fw_hash]
            )),
            "unknown-committee drop must emit AbandonFetch::Finalizations, got: {actions:?}"
        );

        // Regression: dedup set clear lets retries through.
        let retry_actions = state.admit_finalization(&topo, tick);
        assert!(
            retry_actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::Finalizations(..)))),
            "retry must still reach the committee-keys gate, got: {retry_actions:?}"
        );
    }

    /// `on_finalization_verified` with `valid = true` emits exactly the
    /// admission continuation — same shape as the prior synchronous path.
    #[test]
    fn on_finalization_verified_admits_valid() {
        let mut state = make_test_state();
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        ));
        let tick = Arc::new(Verified::new_unchecked_for_test(Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![ec],
            vec![],
        )));
        let actions = state.on_finalization_verified(Ok(tick));
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::Continuation(ProtocolEvent::FinalizationsAdmitted { .. })
        ));
    }

    /// Two byte-identical EC arrivals while the first is still in flight
    /// must produce only one `VerifyExecutionCertificateSignature`
    /// dispatch. This shields the crypto pool from a flooding peer.
    #[test]
    fn on_execution_certificate_dedups_byte_identical_retransmit() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        );

        let first = state.on_execution_certificate(&topo, cert.clone().into());
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));

        // Same bytes mid-flight — must drop without dispatching another
        // verify.
        let second = state.on_execution_certificate(&topo, cert.into());
        assert!(second.is_empty());
    }

    /// The cross-shard freeze: an EC from a recovering shard above its
    /// attested frontier is dropped without dispatching verification — the
    /// forged orphan a beyond-f retained committee would otherwise export.
    /// One at or below the frontier is legitimate pre-halt history and still
    /// dispatches.
    #[test]
    fn on_execution_certificate_fences_ec_past_recovery_frontier() {
        let recovering = ShardId::ROOT;
        let topo = make_test_topology_recovering(recovering, BlockHeight::new(5));

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec_at = |height: u64| {
            ExecutionCertificate::new(
                TickId::new(recovering, BlockHeight::new(height)),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                vec![],
                AggregateSignature::ZERO,
                signers.clone(),
            )
        };

        // Above the frontier — the orphan. Fenced.
        let mut state = make_test_state();
        let orphan = state.on_execution_certificate(&topo, ec_at(6).into());
        assert!(
            matches!(
                orphan.as_slice(),
                [Action::AbandonFetch(FetchIds::ExecutionCerts(..))]
            ),
            "an EC past the freeze frontier is dropped, got {orphan:?}"
        );

        // At the frontier — legitimate suffix, still dispatches to verify.
        let mut state = make_test_state();
        let suffix = state.on_execution_certificate(&topo, ec_at(5).into());
        assert!(
            matches!(
                suffix.as_slice(),
                [Action::VerifyExecutionCertificateSignature { .. }]
            ),
            "an EC within the frontier dispatches, got {suffix:?}"
        );
    }

    /// A cross-shard EC defers on its source block's commit proof: a bare
    /// QC-certified header is not consumability, and the committed event
    /// replays the deferred EC into verify dispatch.
    #[test]
    fn on_execution_certificate_defers_until_source_block_commit_proven() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tick_id = TickId::new(remote_shard, BlockHeight::new(5));
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"deferred_tx")),
                ExecutionOutcome::Aborted,
            )],
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(
            actions.is_empty(),
            "an EC from an unproven source block must defer, got {actions:?}"
        );

        // The commit proof lands: the deferred EC replays into dispatch.
        state.proven_anchors().record(Anchor {
            shard: remote_shard,
            height: BlockHeight::new(5),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        });
        let actions = state.on_committed_remote_header(&topo, remote_shard);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "the committed event must replay the deferred EC, got {actions:?}"
        );
    }

    /// A departed shard's settled set is a commit proof for everything it
    /// names: an EC covered by the set dispatches without waiting on a
    /// remote-header proof no departed chain will supply. An outcome the
    /// set does not name is a verdict that shard never settled, and the
    /// gate still defers it.
    #[test]
    fn settled_set_membership_stands_in_for_the_commit_proof() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let covered = TxHash::from(Hash::from_bytes(b"settled_tx"));
        let make_cert = |tx_hash| {
            ExecutionCertificate::new(
                TickId::new(remote_shard, BlockHeight::new(5)),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)],
                AggregateSignature::ZERO,
                quorum_signers(),
            )
        };

        state.record_settled_txs(
            &topo,
            remote_shard,
            SettledTxSet {
                txs: BTreeSet::from([covered]),
                terminal_wt: WeightedTimestamp::from_millis(1_000),
            },
        );

        let actions = state.on_execution_certificate(&topo, make_cert(covered).into());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "a set-covered EC must dispatch without a commit proof, got {actions:?}"
        );

        let uncovered = TxHash::from(Hash::from_bytes(b"unsettled_tx"));
        let actions = state.on_execution_certificate(&topo, make_cert(uncovered).into());
        assert!(
            actions.is_empty(),
            "an uncovered EC must still defer, got {actions:?}"
        );
    }

    /// The order the recovery actually runs in: the certificate arrives
    /// first and parks on the missing proof, the settled set lands
    /// afterwards and replays it through the gate.
    #[test]
    fn a_settled_set_replays_the_certificates_parked_on_its_proof() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tx_hash = TxHash::from(Hash::from_bytes(b"parked_tx"));
        let cert = ExecutionCertificate::new(
            TickId::new(remote_shard, BlockHeight::new(5)),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)],
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(
            actions.is_empty(),
            "no proof and no set: the EC parks, got {actions:?}"
        );

        let actions = state.record_settled_txs(
            &topo,
            remote_shard,
            SettledTxSet {
                txs: BTreeSet::from([tx_hash]),
                terminal_wt: WeightedTimestamp::from_millis(1_000),
            },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "the set must replay the parked EC into dispatch, got {actions:?}"
        );
    }

    /// An EC parked at or below the source shard's attested boundary sits
    /// under a joiner's remote-header sync anchor, where forward sync
    /// never delivers the committing structure — parking must request the
    /// commit proof explicitly. Above the boundary it stays a silent
    /// defer: gossip or forward sync proves it in the ordinary course.
    #[test]
    fn deferred_ec_below_the_attested_boundary_requests_its_commit_proof() {
        let remote_shard = ShardId::leaf(1, 1);
        let boundary = BlockHeight::new(10);
        let topo = make_two_shard_topology_with_boundary(remote_shard, boundary);
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let cert_at = |height: u64| {
            ExecutionCertificate::new(
                TickId::new(remote_shard, BlockHeight::new(height)),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&height.to_le_bytes())),
                    ExecutionOutcome::Aborted,
                )],
                AggregateSignature::ZERO,
                quorum_signers(),
            )
        };

        // At the boundary: below the sync anchor — the defer asks for the
        // commit proof.
        let actions = state.on_execution_certificate(&topo, cert_at(10).into());
        assert!(
            matches!(
                actions.as_slice(),
                [Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard,
                    block_height,
                })] if *source_shard == remote_shard && *block_height == boundary
            ),
            "a below-anchor defer must request its commit proof, got {actions:?}"
        );

        // Above the boundary: an ordinary silent defer.
        let actions = state.on_execution_certificate(&topo, cert_at(11).into());
        assert!(
            actions.is_empty(),
            "an above-anchor defer needs no explicit request, got {actions:?}"
        );
    }

    /// No pending recovery for the shard: the fence is inert, an EC at any
    /// height dispatches as usual.
    #[test]
    fn on_execution_certificate_fence_inert_without_recovery() {
        let topo = make_test_topology();
        let mut state = make_test_state();
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(99)),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        );
        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(matches!(
            actions.as_slice(),
            [Action::VerifyExecutionCertificateSignature { .. }]
        ));
    }

    /// Once verification completes (success or failure), the in-flight
    /// slot is released and a subsequent retransmit is allowed to
    /// re-dispatch.
    #[test]
    fn on_execution_certificate_releases_slot_after_verification() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        );

        let _ = state.on_execution_certificate(&topo, cert.clone().into());
        // Simulate the crypto pool returning an invalid result. The slot is
        // released so a follow-up arrival can re-dispatch.
        let _ = state.on_certificate_verified(
            &topo,
            Err((
                Arc::new(cert.clone()),
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        let again = state.on_execution_certificate(&topo, cert.into());
        assert_eq!(again.len(), 1);
        assert!(matches!(
            again[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));
    }

    /// An EC already in `exec_certs` (placed there by a co-hosted vnode's
    /// aggregation, or by an earlier verification of the same wire bytes)
    /// short-circuits the verify dispatch on a wire-hash match.
    #[test]
    fn on_execution_certificate_skips_dispatch_on_cached_wire_hash_match() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        );
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(cert.clone())));

        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(
            actions.is_empty(),
            "cached wire-hash match must short-circuit"
        );
    }

    /// A different aggregation of the same logical EC (same `TickId` but
    /// distinct signers / signature, hence distinct wire bytes) is not
    /// short-circuited by an earlier cache entry — it still needs its own
    /// signature check.
    #[test]
    fn on_execution_certificate_falls_through_on_cached_tick_id_with_wire_hash_mismatch() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers_a = SignerBitfield::new(4);
        signers_a.set(0);
        signers_a.set(1);
        signers_a.set(2);
        let mut signers_b = SignerBitfield::new(4);
        signers_b.set(1);
        signers_b.set(2);
        signers_b.set(3);

        let cached = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers_a,
        );
        let incoming = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers_b,
        );
        assert_ne!(cached.wire_hash(), incoming.wire_hash());
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(cached)));

        let actions = state.on_execution_certificate(&topo, incoming.into());
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));
    }

    /// `admit_finalization` dedups a second arrival for the same
    /// `TickId` while verification is still in flight.
    #[test]
    fn admit_finalization_dedups_in_flight_arrival() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> =
            Arc::new(Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]).into());
        let _fw_hash = tick.receipt_hash();

        let first = state.admit_finalization(&topo, Arc::clone(&tick));
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Action::VerifyFinalization { .. }));

        let second = state.admit_finalization(&topo, tick);
        assert!(second.is_empty());
    }

    /// A `Finalization` already in the canonical store short-circuits
    /// before any verify dispatch.
    #[test]
    fn admit_finalization_skips_when_already_finalized() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let raw_finalization = Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]);
        let verifiable_finalization =
            Arc::new(Verified::new_unchecked_for_test(raw_finalization.clone()).into());
        // Seed the canonical store directly (mirrors what `finalize`
        // does on the local-aggregation path).
        state.finalized.insert(tick_id, verifiable_finalization);

        let actions = state.admit_finalization(&topo, Arc::new(Verifiable::from(raw_finalization)));
        assert!(actions.is_empty());
    }

    /// A `Finalization` delivered by `admit_finalization` (the fetch
    /// entry point) must reject any tick whose contained ECs lack quorum
    /// power or signature validity. Otherwise a peer answering
    /// `finalization.request` can poison the `io_loop` serving cache
    /// (via the `Continuation(FinalizationsAdmitted)` interception) and
    /// we re-serve the bogus tick to other peers.
    #[test]
    fn test_admit_finalization_rejects_subquorum_ec() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let tick_id = TickId::new(ShardId::leaf(1, 0), BlockHeight::new(1));
        let bogus_ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000_000),
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            SignerBitfield::empty(), // no signers — far below 2f+1
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(tick_id, TickHalf::Determined, vec![bogus_ec], vec![]).into(),
        );
        let fw_hash = tick.receipt_hash();

        let actions = state.admit_finalization(&topo, tick);
        // No admission continuation — the poisoning vector this gate
        // exists to close. The rejection now emits an `AbandonFetch` so
        // any pinned fetch FSM entry releases its slot.
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizationsAdmitted { .. })
            )),
            "sub-quorum Finalization must produce no admission Continuation"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::Finalizations(ids)) if ids == &vec![fw_hash]
            )),
            "sub-quorum drop must emit AbandonFetch::Finalizations, got: {actions:?}"
        );
    }

    /// Receipt of a cross-shard EC must NOT mark its expectation
    /// fulfilled until the signature has been verified. Otherwise a
    /// Byzantine peer can ship a forged EC, the tombstone is set with
    /// `vote_anchor_ts + RETENTION_HORIZON` (peer-controlled), legitimate
    /// fallback fetches are suppressed, and the verify pool's silent
    /// rejection leaves us stranded.
    #[test]
    fn test_on_execution_certificate_does_not_mark_fulfilled_before_verification() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tick_id = TickId::new(remote_shard, BlockHeight::new(5));
        let cross_shard_tx = TxHash::from(Hash::from_bytes(b"cross-shard tx"));
        state
            .expected_certs
            .register(remote_shard, cross_shard_tx, state.committed_ts);
        assert_eq!(state.expected_certs.expected_len(), 1);
        assert_eq!(state.expected_certs.fulfilled_len(), 0);

        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000_000),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                cross_shard_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::ZERO,
            quorum_signers(),
        );
        let _ = state.on_execution_certificate(&topo, cert.clone().into());
        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation must remain pending until verification completes"
        );
        assert_eq!(
            state.expected_certs.fulfilled_len(),
            0,
            "no tombstone must be created from an unverified EC"
        );

        // Verification fails — the EC was a forgery. State is unchanged;
        // the legitimate cert can still arrive and clear the expectation.
        let _ = state.on_certificate_verified(
            &topo,
            Err((
                Arc::new(cert),
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        assert_eq!(state.expected_certs.expected_len(), 1);
        assert_eq!(state.expected_certs.fulfilled_len(), 0);
    }

    /// A received cross-shard EC must always dispatch signature verification
    /// before any tick state sees it — including when no local tick tracks
    /// any tx in the cert. Without that, a Byzantine remote could buffer
    /// forged `tx_outcomes` that the replay path later trusts at commit
    /// time.
    #[test]
    fn test_on_execution_certificate_always_dispatches_verification_even_without_tracker() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tick_id = TickId::new(remote_shard, BlockHeight::new(5));
        // No local ticks / trackers have been created for this tx.
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"untracked_tx")),
                ExecutionOutcome::Aborted,
            )],
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        // The source block is commit-proven; the gate under test is verify
        // dispatch without a local tracker, not the commit-proof gate.
        state.proven_anchors().record(Anchor {
            shard: remote_shard,
            height: BlockHeight::new(5),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        });
        state.on_committed_remote_header(&topo, remote_shard);
        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "must dispatch signature verification even when no local tracker matches"
        );
        // Nothing lands in the early-arrival buffer until verification passes.
        assert_eq!(state.memory_stats().pending_routing, 0);
        assert_eq!(state.memory_stats().early_attestations, 0);
    }

    // ========================================================================
    // Expected Execution Cert Retention
    // ========================================================================

    /// Multi-shard topology for expected-cert tests: 4 validators, 2 shards.
    /// Local is validator 0 (shard 0); shard 1 = {1, 3}.
    fn make_two_shard_topology() -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        )))
    }

    /// A two-shard schedule whose head attests `shard`'s boundary at
    /// `height` — the anchor a joiner's remote-header sync starts from.
    fn make_two_shard_topology_with_boundary(
        shard: ShardId,
        height: BlockHeight,
    ) -> TopologySchedule {
        use hyperscale_types::{BeaconWitnessLeafCount, BlockHash, ShardAnchor, StateRoot};

        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(
            ShardId::leaf(1, 0),
            vec![ValidatorId::new(0), ValidatorId::new(1)],
        );
        committees.insert(
            ShardId::leaf(1, 1),
            vec![ValidatorId::new(2), ValidatorId::new(3)],
        );
        let mut boundaries = HashMap::new();
        boundaries.insert(
            shard,
            ShardAnchor {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
                height,
                weighted_timestamp: WeightedTimestamp::from_millis(1),
                witness_base: BeaconWitnessLeafCount::ZERO,
                terminal_roots: None,
                handoff_complete: None,
            },
        );
        TopologySchedule::single(Arc::new(TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &validator_set,
            committees.clone(),
            committees,
            boundaries,
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )))
    }

    /// A uniform-power committee over `ids`, one shard, plus its public keys in
    /// committee order (what `committee_public_keys_for_shard` returns).
    fn committee_snapshot(ids: &[u64]) -> (TopologySnapshot, Vec<ConsensusPublicKey>) {
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| {
                let k = BlsSigner::generate();
                ValidatorInfo {
                    validator_id: ValidatorId::new(id),
                    public_key: k.public_key(),
                }
            })
            .collect();
        let pubkeys = validators.iter().map(|v| v.public_key).collect();
        let snapshot = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        );
        (snapshot, pubkeys)
    }

    /// Committee A governs epoch 0 (the routing head); committee B, with
    /// disjoint signing keys, governs epoch 1. A remote EC whose
    /// `vote_anchor_ts` lands in epoch 1 must dispatch signature verification against
    /// B's keys — the committee seated at the EC's anchor — not the head.
    #[test]
    fn remote_ec_verification_resolves_committee_at_its_vote_anchor() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let (snap_a, keys_a) = committee_snapshot(&[0, 1, 2, 3]);
        let (snap_b, keys_b) = committee_snapshot(&[4, 5, 6, 7]);
        assert_ne!(keys_a, keys_b, "committees must have distinct keys");

        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        let mut coord = make_test_state();
        let cert = ExecutionCertificate::new(
            TickId::new(shard, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(ED), // epoch 1
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        let actions = coord.on_execution_certificate(&schedule, Verifiable::from(cert));
        let public_keys = actions
            .iter()
            .find_map(|a| match a {
                Action::VerifyExecutionCertificateSignature { public_keys, .. } => {
                    Some(public_keys)
                }
                _ => None,
            })
            .expect("on_execution_certificate dispatches a signature verification");
        assert_eq!(
            *public_keys, keys_b,
            "remote EC must verify against the committee at its vote_anchor_ts, not the head",
        );
    }

    /// The leader-side counterpart to the test above: when a local vote quorum
    /// forms, `check_vote_quorum` packs the committee at the tick's
    /// `vote_anchor_ts` into the EC. That committee positions the signer
    /// bitfield every verifier later resolves, so it must be the epoch-1
    /// committee (the tick is anchored there), not the head.
    #[test]
    fn local_aggregation_packs_committee_at_vote_anchor() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let (snap_a, _keys_a) = committee_snapshot(&[0, 1, 2, 3]);
        let (snap_b, _keys_b) = committee_snapshot(&[4, 5, 6, 7]);
        let committee_b: Vec<ValidatorId> = snap_b.committee_for_shard(shard).to_vec();
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        // Local node is a committee-B member; commit a local-only tick anchored
        // in epoch 1 (block weighted timestamp = ED, so vote_anchor_ts = ED).
        let mut coord = make_test_state_for(ValidatorId::new(4));
        let block = make_live_block(
            BlockHeight::new(1),
            ED,
            ValidatorId::new(4),
            vec![Arc::new(test_transaction(1))],
        );
        let block_hash = block.hash();
        coord.on_block_committed(&schedule, &test_certify(block, ED));
        let tick_id = coord
            .ticks
            .ticks_iter()
            .next()
            .map(|(w, _)| *w)
            .expect("local-only tick created on commit");

        // Feed a 2f+1 quorum of verified votes from committee B, all sharing the
        // tick's anchor and receipt root so they land in one quorum bucket.
        let mut actions = Vec::new();
        for v in [4u64, 5, 6] {
            let vote = ExecutionVote::new(
                block_hash,
                BlockHeight::new(1),
                WeightedTimestamp::from_millis(ED),
                tick_id,
                shard,
                GlobalReceiptRoot::ZERO,
                1,
                vec![],
                ValidatorId::new(v),
                ConsensusSignature::ZERO,
            );
            actions.extend(
                coord.on_verified_execution_vote(&schedule, Verified::new_unchecked_for_test(vote)),
            );
        }

        let committee = actions
            .iter()
            .find_map(|a| match a {
                Action::AggregateExecutionCertificate { committee, .. } => Some(committee),
                _ => None,
            })
            .expect("vote quorum dispatches certificate aggregation");
        assert_eq!(
            *committee, committee_b,
            "the EC's bitfield committee must be the one at vote_anchor_ts (epoch 1), not the head",
        );
    }

    #[test]
    fn cross_shard_ec_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        // Schedule head is epoch 0; an EC anchored in epoch 5 is ahead of this
        // node's beacon and can't resolve yet.
        let behind = TopologySchedule::new(
            ED,
            Epoch::new(0),
            Arc::new(committee_snapshot(&[0, 1, 2, 3]).0),
        );
        let mut coord = make_test_state();
        let cert = ExecutionCertificate::new(
            TickId::new(shard, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(5 * ED), // epoch 5, past the head
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        let actions = coord.on_execution_certificate(&behind, Verifiable::from(cert));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "an EC whose epoch the beacon hasn't reached must buffer, not dispatch",
        );

        let caught_up = TopologySchedule::single(Arc::new(committee_snapshot(&[0, 1, 2, 3]).0));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            drained
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "draining on catch-up must dispatch the buffered EC's verification",
        );
    }

    #[test]
    fn finalization_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let behind = TopologySchedule::new(
            ED,
            Epoch::new(0),
            Arc::new(committee_snapshot(&[0, 1, 2, 3]).0),
        );
        let mut coord = make_test_state();

        let tick_id = TickId::new(shard, BlockHeight::new(1));
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(5 * ED), // epoch 5, past the head
            GlobalReceiptRoot::ZERO,
            vec![],
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> =
            Arc::new(Finalization::new(tick_id, TickHalf::Determined, vec![ec], vec![]).into());
        let _fw_hash = tick.receipt_hash();

        let actions = coord.admit_finalization(&behind, Arc::clone(&tick));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyFinalization { .. })),
            "a finalization whose EC epoch the beacon hasn't reached must buffer, not dispatch",
        );

        let caught_up = TopologySchedule::single(Arc::new(committee_snapshot(&[0, 1, 2, 3]).0));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            drained
                .iter()
                .any(|a| matches!(a, Action::VerifyFinalization { .. })),
            "draining on catch-up must dispatch the buffered tick's verification",
        );
    }

    /// Expected-cert entries must be retained while a local tick still holds
    /// their transaction — otherwise a cross-shard transaction whose remote
    /// EC missed the broadcast window would be stranded once the expectation
    /// aged out, with no fallback fetch continuing to fire.
    #[test]
    fn test_expected_exec_cert_retained_while_tracker_pending() {
        use std::collections::BTreeSet;

        use hyperscale_types::test_utils::test_transaction;

        let _topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tx = Arc::new(test_transaction(7));
        let tx_hash = tx.hash();
        state
            .expected_certs
            .register(remote_shard, tx_hash, state.committed_ts);
        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation should register for a transaction the source names"
        );

        // Simulate an outstanding local cross-shard tick needing shard 1's EC.
        let local_tick = TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10));
        let mut participating = BTreeSet::new();
        participating.insert(ShardId::leaf(1, 0));
        participating.insert(remote_shard);
        state.ticks.insert_tick(
            local_tick,
            tick_holding(
                local_tick,
                WeightedTimestamp::from_millis(5_000),
                vec![(verified_arc(&tx), participating)],
            ),
        );
        state.ticks.assign_tx(tx_hash, local_tick);

        // Advance committed time past fallback + retry thresholds so the
        // age-based gate would fire. The expectation must survive regardless
        // because a local tick still needs shard 1's EC.
        state.committed_height = BlockHeight::new(500);
        state.committed_ts = WeightedTimestamp::from_millis(60_000);
        let actions = state.check_exec_cert_timeouts();

        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation must survive age pruning while a local tick still needs shard 1"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Fetch(FetchRequest::ExecutionCerts { .. }))),
            "fallback fetch must keep firing while the expectation is retained"
        );

        // Once the local tick resolves (simulating finalize), the
        // expectation is no longer needed and gets pruned.
        state.ticks.remove_tick(&local_tick);
        state.ticks.remove_assignment(tx_hash);
        state.committed_height = BlockHeight::new(600);
        state.committed_ts = WeightedTimestamp::from_millis(120_000);
        let _ = state.check_exec_cert_timeouts();
        assert_eq!(
            state.expected_certs.expected_len(),
            0,
            "expectation must be pruned once no tick needs the source shard"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // finalize — verifies the critical cross-sub-machine fanout that
    // happens when a tick reaches terminal state.
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a local-only tick in the "ready to finalize" state: every tx
    /// has an execution result and a local receipt, and the local EC has
    /// been added. `TickState::is_complete` returns true.
    fn make_ready_local_tick(tx_seeds: &[u8]) -> (TickId, TickState) {
        make_ready_local_tick_at(BlockHeight::new(1), tx_seeds)
    }

    /// [`make_ready_local_tick`] at a chosen tick height.
    fn make_ready_local_tick_at(height: BlockHeight, tx_seeds: &[u8]) -> (TickId, TickState) {
        let tick_id = TickId::new(ShardId::ROOT, height);
        let txs: Vec<(Arc<Verified<Transaction>>, BTreeSet<ShardId>)> = tx_seeds
            .iter()
            .map(|s| {
                let mut participating = BTreeSet::new();
                participating.insert(ShardId::ROOT);
                (
                    Arc::new(Verified::new_unchecked_for_test(test_transaction(*s))),
                    participating,
                )
            })
            .collect();
        let mut tick = tick_holding(tick_id, WeightedTimestamp::from_millis(1_000), txs);

        // Record per-tx execution results + receipts.
        let tx_hashes: Vec<TxHash> = tick.tx_hashes().to_vec();
        let tx_outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| {
                TxOutcome::new(
                    *h,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        for h in &tx_hashes {
            tick.record_execution_result(
                *h,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            );
            tick.record_receipt(StoredReceipt {
                tx_hash: *h,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    #[allow(clippy::default_trait_access)]
                    writes: Default::default(),
                    beacon_witness_events: Vec::new(),
                    events: Vec::new(),
                }),
                metadata: None,
            });
        }

        // Add the local EC; same tick_id flips `local_ec_emitted` to true.
        let local_ec = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"global_receipt_root")),
            tx_outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        tick.add_execution_certificate(local_ec);
        assert!(
            tick.determined_ready(),
            "fixture precondition: a purely local tick settles on its own certificate"
        );

        (tick_id, tick)
    }

    #[test]
    fn finalize_populates_the_finalization_store() {
        let mut state = make_test_state();
        let (tick_id, tick) = make_ready_local_tick(&[1, 2]);
        state.ticks.insert_tick(tick_id, tick);

        let _actions = state.finalize(&make_test_topology(), &tick_id);

        assert!(
            state.finalized.contains(&tick_id),
            "finalized store populated"
        );
        assert_eq!(state.finalized.len(), 1);
        // The tick outlives its handoff: it is what tells a committing
        // block whether the members it resolved were all of them.
        assert!(state.ticks.contains_tick(&tick_id));
        assert!(
            state
                .ticks
                .get_tick(&tick_id)
                .is_some_and(TickState::has_spoken),
            "a purely local tick has nothing left to say",
        );
    }

    /// The fold names the tick whose determined half the chain still
    /// owes, and offers every half it holds beside it. Which of them a
    /// block may carry is admission's to judge against this set, so a
    /// validator whose own ticks are incomplete cannot silently carry
    /// the frontier past one and refuse its half for good.
    #[test]
    fn a_tick_holding_unsettled_determined_members_is_owed() {
        let mut state = make_test_state();
        let topo = make_test_topology();
        let owed_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let owed_tx = Arc::new(Verified::new_unchecked_for_test(test_transaction(7)));
        // Executed, its certificate still owed.
        state.ticks.insert_tick(
            owed_id,
            tick_holding(
                owed_id,
                WeightedTimestamp::from_millis(1_000),
                vec![(owed_tx, BTreeSet::from([ShardId::ROOT]))],
            ),
        );
        let (later_id, later) = make_ready_local_tick_at(BlockHeight::new(2), &[1, 2]);
        state.ticks.insert_tick(later_id, later);
        let _actions = state.finalize(&topo, &later_id);
        assert!(state.finalized.contains(&later_id));

        assert_eq!(
            state.owed_determined_ticks(),
            BTreeSet::from([BlockHeight::new(1), BlockHeight::new(2)]),
            "a half emitted and not yet committed is still one the chain owes",
        );

        let offered: Vec<BlockHeight> = state
            .get_finalizations()
            .iter()
            .map(|fw| fw.as_unverified().tick_id().block_height())
            .collect();
        assert_eq!(offered, vec![BlockHeight::new(2)]);
    }

    #[test]
    fn finalize_emits_the_admission_event() {
        let mut state = make_test_state();
        let (tick_id, tick) = make_ready_local_tick(&[1, 2]);
        state.ticks.insert_tick(tick_id, tick);

        let actions = state.finalize(&make_test_topology(), &tick_id);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::Continuation(ProtocolEvent::FinalizationsAdmitted { .. })
        ));
    }

    #[test]
    fn finalize_is_a_noop_for_an_absent_tick() {
        let mut state = make_test_state();
        let unknown = TickId::new(ShardId::ROOT, BlockHeight::new(99));
        let actions = state.finalize(&make_test_topology(), &unknown);
        assert!(actions.is_empty());
        assert!(state.finalized.is_empty());
    }

    /// A schedule whose final window (epoch 0) is single-shard `ROOT` and
    /// whose next window (epoch 1) splits it into two children — so any
    /// weighted timestamp in epoch 1 is past `ROOT`'s terminal window.
    fn terminating_schedule() -> TopologySchedule {
        terminating_schedule_over(1000)
    }

    /// A schedule in which `ShardId::ROOT` splits at the end of epoch 0, so
    /// it is past-terminal anywhere in epoch 1 and its two children are
    /// live there. `epoch_duration_ms` places the cut on the weighted-time
    /// grid: a caller reaching past a transaction deadline needs windows
    /// wide enough to still resolve there.
    fn terminating_schedule_over(epoch_duration_ms: u64) -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        // The cut rides the final window's own entry — the boundary
        // predicates read the scheduled terminal rather than comparing
        // this window's trie against the next.
        let final_window = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(validators.clone()),
            )
            .with_scheduled_terminals(BTreeMap::from([(ShardId::ROOT, Epoch::new(0))])),
        );
        let post_split = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(validators),
            )
            .with_boundaries(HashMap::from([(
                ShardId::ROOT,
                ShardAnchor {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                    height: BlockHeight::new(9),
                    weighted_timestamp: WeightedTimestamp::from_millis(1_000),
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_roots: None,
                    handoff_complete: None,
                },
            )])),
        );
        let mut sched = TopologySchedule::new(epoch_duration_ms, Epoch::new(0), final_window);
        sched.insert(Epoch::new(1), post_split);
        sched
    }

    /// An empty block at `height` whose parent QC carries `anchor_ms` — the
    /// block's own position on the weighted-time grid.
    /// Commit-time classification resolves against the window the block's
    /// *parent* anchored in, because that is where a block's committee comes
    /// from — so it matches the snapshot the proposer built under and the
    /// verifier validated against. Reading the block's own anchor instead
    /// straddles an epoch cut once per window, and a reshape cut there
    /// changes the shard set `compute_ticks` routes over.
    #[test]
    fn classification_anchors_on_the_parents_window_across_commits() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::ROOT);
        let topo = make_test_topology();

        // `certify` stamps the block's parent-QC weighted timestamp, which is
        // the block's own anchor.
        let commit = |state: &mut ExecutionCoordinator, height: u64, anchor_ms: u64| {
            let block = make_live_block_on_shard(
                ShardId::ROOT,
                BlockHeight::new(height),
                anchor_ms,
                ValidatorId::new(0),
                vec![],
            );
            let _ = state.on_block_committed(&topo, &test_certify(block, anchor_ms));
        };

        commit(&mut state, 1, 500);
        commit(&mut state, 2, 1_500);

        assert_eq!(
            state.committed_committee_anchor_wt,
            WeightedTimestamp::from_millis(500),
            "the second block is classified in the window its parent anchored in",
        );
        assert_eq!(
            state.committed_ts,
            WeightedTimestamp::from_millis(1_500),
            "its own anchor still drives the deterministic clock",
        );
    }

    /// A root chain's first blocks genuinely anchor at zero, and that zero
    /// is a carriable parent anchor, not an uninitialized clock: the second
    /// commit classifies in the window its parent anchored (epoch 0) even
    /// when the chain stalled long enough at genesis for the block to date
    /// itself past a cut.
    #[test]
    fn a_zero_anchor_at_genesis_is_carried_not_treated_as_a_gap() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::ROOT);
        let topo = make_test_topology();

        let commit = |state: &mut ExecutionCoordinator, height: u64, anchor_ms: u64| {
            let block = make_live_block_on_shard(
                ShardId::ROOT,
                BlockHeight::new(height),
                anchor_ms,
                ValidatorId::new(0),
                vec![],
            );
            let _ = state.on_block_committed(&topo, &test_certify(block, anchor_ms));
        };

        // Block 1 anchors at genesis zero; block 2 dates itself far past it.
        commit(&mut state, 1, 0);
        commit(&mut state, 2, 1_500);

        assert_eq!(
            state.committed_committee_anchor_wt,
            WeightedTimestamp::ZERO,
            "block 2's committee anchors on block 1, at genesis zero",
        );
    }

    /// A restarted replica's first commit classifies exactly like a
    /// non-restarted peer's: the frontier seeded from the recovered tip is
    /// the parent anchor the carry needs, so the commit extending the tip
    /// resolves the window the tip anchored — not the one the new block
    /// opens, which a zero frontier's gap fallback would pick and which a
    /// reshape cut between the two turns into a vote-splitting divergence.
    #[test]
    fn a_seeded_frontier_carries_the_recovered_anchor_across_a_restart() {
        let topo = make_test_topology();
        // The recovered tip: height 5, its own anchor at 900 ms.
        let mut state = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &RecoveredState {
                committed_height: BlockHeight::new(5),
                committed_block_anchor_wt: Some(WeightedTimestamp::from_millis(900)),
                committed_committee_anchor_wt: Some(WeightedTimestamp::from_millis(800)),
                ..RecoveredState::default()
            },
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );

        // The first post-restart commit extends the tip and dates itself
        // past it.
        let block = make_live_block_on_shard(
            ShardId::ROOT,
            BlockHeight::new(6),
            1_100,
            ValidatorId::new(0),
            vec![],
        );
        let _ = state.on_block_committed(&topo, &test_certify(block, 1_100));

        assert_eq!(
            state.committed_committee_anchor_wt,
            WeightedTimestamp::from_millis(900),
            "the commit extending the recovered tip is classified in the tip's window",
        );
        assert_eq!(state.committed_ts, WeightedTimestamp::from_millis(1_100));
    }

    /// Commit-time tick/provision classification anchors on the block's
    /// committee — not the `ArcSwap` head, so every replica groups a block's
    /// transactions identically across a reshape boundary (matching the
    /// proposer and the verifier).
    #[test]
    fn classification_committee_anchors_at_the_block_window_not_the_head() {
        let state = make_test_state_for_shard(ValidatorId::new(0), ShardId::ROOT);
        // Epoch 0 carries ROOT (one shard) — the block's anchor; epoch 1
        // splits it (two shards) and is installed as the flipped head.
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let pre_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators.clone()),
        ));
        let post_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), Arc::clone(&pre_split));
        sched.insert(Epoch::new(1), Arc::clone(&post_split));
        sched.set_head(post_split);

        let anchored = state.classification_committee(&sched, WeightedTimestamp::from_millis(500));
        assert_eq!(
            anchored.num_shards(),
            1,
            "classification anchors at the block's window (ROOT, one shard), not the two-shard head",
        );
    }

    /// The seed window a tick executes under is the one its block's
    /// committee carried, not the one this node's head has folded to.
    ///
    /// A head advances as a node folds the beacon and every node folds
    /// at its own pace, so a window read off the head would answer
    /// `Pending` on a laggard where it answers `Ready` on a leader —
    /// one tick, two receipt roots. The block fixes it, on the same
    /// terms as the clock beside it.
    #[test]
    fn a_tick_executes_under_its_blocks_seed_window_not_the_head() {
        const ED: u64 = 1_000;

        let mut state = make_test_state();
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let seeded = |byte: u8| {
            let mut ring = SeedRing::default();
            ring.record(
                Epoch::GENESIS,
                EpochSeed {
                    randomness: Randomness::new([byte; 32]),
                    source: SeedSource::Reveals,
                },
            );
            Arc::new(
                TopologySnapshot::new(
                    NetworkDefinition::simulator(),
                    1,
                    ValidatorSet::new(validators.clone()),
                )
                .with_seeds(ring),
            )
        };
        // One window, two snapshots of it: what the block's committee
        // carried, and what a node further along the fold holds.
        let mut sched = TopologySchedule::new(ED, Epoch::GENESIS, seeded(0xA1));
        sched.set_head(seeded(0xB2));

        let block = make_live_block(
            BlockHeight::new(1),
            500,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        let actions = state.on_block_committed(&sched, &certify(block));
        let env = actions
            .iter()
            .find_map(|action| match action {
                Action::ExecuteTransactions { env, .. } => Some(env),
                _ => None,
            })
            .expect("the commit dispatches its tick");

        assert_eq!(
            env.seeds.at(Epoch::GENESIS.inner()),
            Seeded::Ready([0xA1; 32]),
            "the tick reads the seed its block's committee carried",
        );
        // And the grid is the schedule's own window length, which is
        // what the schedule is indexed by — not a default a snapshot
        // that nobody projected would have answered with.
        assert_eq!(
            env.windows,
            EpochWindows::new(ED),
            "the tick resolves its clock on the chain's epoch grid",
        );
    }

    /// A finalization whose certificate carries `local`'s EC plus a
    /// remote EC on `remote` — the cross-shard shape the gate inspects.
    fn cross_shard_finalization(
        local: ShardId,
        remote: ShardId,
        height: u64,
        tx_hash: TxHash,
    ) -> Arc<Verifiable<Finalization>> {
        let ec = |shard: ShardId| {
            let tick = TickId::new(shard, BlockHeight::new(height));
            ExecutionCertificate::new(
                tick,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(
                    tx_hash,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )
        };
        let local_tick = TickId::new(local, BlockHeight::new(height));
        let tick = Finalization::new(
            local_tick,
            TickHalf::Determined,
            vec![Arc::new(ec(local)), Arc::new(ec(remote))],
            vec![],
        );
        Arc::new(Verified::new_unchecked_for_test(tick).into())
    }

    /// A tick naming a past-terminal shard whose settled set is unknown is
    /// withheld at the finalize gate, then released once the set records
    /// it — the produce-side mirror of the vote fence's defer-and-release.
    #[test]
    fn finalize_gate_defers_then_releases() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));
        // Past ROOT's terminal window — the gate's anchor is the committed ts.
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        let sched = terminating_schedule();
        let tick = cross_shard_finalization(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
            TxHash::from(Hash::from_bytes(b"tx")),
        );
        let tick_id = *tick.tick_id();

        let deferred = state.emit_or_gate_finalized(&sched, tick);
        assert!(
            deferred.is_empty(),
            "the gate withholds the tick while the settled set is unknown",
        );
        assert_eq!(
            state.parked.waiting_on(|w| w == Waiting::Settlement),
            1,
            "held at the gate"
        );
        assert!(!state.finalized.contains(&tick_id));

        let released = state.record_settled_txs(
            &sched,
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        assert!(
            matches!(
                released.as_slice(),
                [Action::Continuation(
                    ProtocolEvent::FinalizationsAdmitted { .. }
                )],
            ),
            "recording the settled set releases the held tick for admission",
        );
        assert_eq!(state.parked.waiting_on(|w| w == Waiting::Settlement), 0);
        assert!(state.finalized.contains(&tick_id));
    }

    /// A tick a past-terminal shard never settled is dropped, not produced
    /// and not buffered for retry. Nothing here resolves its transaction:
    /// it stays owed, and it goes back to the deadline path that can.
    #[test]
    fn finalize_gate_drops_an_unsettled_tick() {
        let local = ShardId::leaf(1, 0);
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        let sched = terminating_schedule();
        state.record_settled_txs(
            &sched,
            ShardId::ROOT,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(test_transaction(9)),
        ));
        let tx_hash = transaction.hash();
        let tick = cross_shard_finalization(local, ShardId::ROOT, 1, tx_hash);
        let tick_id = *tick.tick_id();
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.ticks.assign_tx(tx_hash, tick_id);

        let dropped = state.emit_or_gate_finalized(&sched, tick);
        assert!(
            dropped.is_empty(),
            "the gate drops a tick the terminated shard never settled",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "a rejected tick is not buffered for retry",
        );
        assert!(!state.finalized.contains(&tick_id));
        assert_eq!(
            state.counterparts.ledger.len(),
            1,
            "a gate rejection is not a verdict — the transaction stays owed",
        );
        assert!(
            state.ticks.tick_assignment(tx_hash).is_none(),
            "and its tick has stopped speaking for it, so the deadline path can",
        );
    }

    /// A late execution certificate completes a tick naming a terminated
    /// partner *after* the cut. While the
    /// partner's settled set is unknown the gate **defers** (never emits —
    /// no one-sided application); once the set proves the partner never
    /// settled the tick, the gate **rejects** it. The fence/gate
    /// defer-release that `reshape_sibling`'s natural straddler can't
    /// reach (it finalizes pre-cut) is exercised here against a genuinely
    /// post-cut, unsettled transaction.
    #[test]
    fn late_unsettled_ec_defers_then_rejects_no_one_sided() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));
        // Post-cut: any epoch-1 timestamp is past ROOT's terminal window.
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        let sched = terminating_schedule();
        let tick = cross_shard_finalization(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
            TxHash::from(Hash::from_bytes(b"tx")),
        );
        let tick_id = *tick.tick_id();

        // The late certificate completes the tick before the settled set is
        // reconstructed: the gate defers — held, never emitted.
        let deferred = state.emit_or_gate_finalized(&sched, tick);
        assert!(
            deferred.is_empty(),
            "no one-sided finalize while the partner's settled set is unknown",
        );
        assert_eq!(
            state.parked.waiting_on(|w| w == Waiting::Settlement),
            1,
            "held at the gate"
        );

        // ROOT terminated having settled nothing → the held tick rejects on
        // redrive, is never finalized, and its tx aborts (not wedged).
        state.record_settled_txs(
            &sched,
            ShardId::ROOT,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let released = state.release(&sched, Wake::Commit);
        assert!(
            released.is_empty(),
            "an unsettled transaction is never finalized — no one-sided application",
        );
        assert_eq!(state.parked.waiting_on(|w| w == Waiting::Settlement), 0);
        assert!(!state.finalized.contains(&tick_id));
    }

    /// A gate-held tick is never dropped on a clock: held past its own
    /// execution anchor by `RETENTION_HORIZON` while its partner's
    /// scheduled termination still stands, it stays held — the partner may
    /// yet prove it settled the tick, and a deadline abort would contradict
    /// that settlement. Only the schedule evicting the partner from every
    /// retained window rejects it, so the buffer cannot pin forever.
    #[test]
    fn a_gate_held_tick_survives_the_horizon_until_schedule_eviction() {
        // Windows long enough that the commit clock can pass the tick's
        // anchor plus the horizon while the pre-terminal window still
        // governs — the shape a terminating shard's multi-epoch coast has
        // at production epoch length.
        let epoch_ms = 2 * RETENTION_HORIZON.as_secs() * 1000;
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        // The cut rides the final window's own entry — the boundary
        // predicates read the scheduled terminal rather than comparing
        // this window's trie against the next.
        let final_window = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(validators.clone()),
            )
            .with_scheduled_terminals(BTreeMap::from([(ShardId::ROOT, Epoch::new(0))])),
        );
        let post_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(epoch_ms, Epoch::new(0), final_window);
        sched.insert(Epoch::new(1), Arc::clone(&post_split));

        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        let tick = cross_shard_finalization(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
            TxHash::from(Hash::from_bytes(b"tx")),
        );
        let tick_id = *tick.tick_id();

        // ROOT is live in epoch 0 but leaves the trie at its boundary: the
        // gate defers on the scheduled termination.
        let deferred = state.emit_or_gate_finalized(&sched, tick);
        assert!(
            deferred.is_empty(),
            "held while the partner is scheduled to terminate",
        );
        assert_eq!(
            state.parked.waiting_on(|w| w == Waiting::Settlement),
            1,
            "held at the gate"
        );

        // The settled set doesn't exist yet; the commit clock sails past
        // the tick's anchor (1ms) plus the horizon with epoch 0 still
        // governing. The hold must survive the clock.
        state.committed_ts = WeightedTimestamp::from_millis(2).plus(RETENTION_HORIZON);
        let released = state.release(&sched, Wake::Commit);
        assert!(released.is_empty(), "an unresolved tick is never finalized");
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) > 0,
            "a gate-held tick is never dropped on a clock",
        );

        // ROOT falls out of every retained window: no honest artifact can
        // resolve the tick anymore, so the redrive rejects it.
        let evicted = TopologySchedule::new(epoch_ms, Epoch::new(0), post_split);
        let released = state.release(&evicted, Wake::Commit);
        assert!(released.is_empty(), "an unresolved tick is never finalized");
        assert_eq!(state.parked.waiting_on(|w| w == Waiting::Settlement), 0);
        assert!(!state.finalized.contains(&tick_id));
    }

    /// The transactions the ledger names past their deadline, and what
    /// this shard's next tick attests about them.
    fn abandonment_vote(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        height: u64,
        now_ms: u64,
    ) -> Vec<TxOutcome> {
        let block = make_live_block(
            BlockHeight::new(height),
            now_ms,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(schedule, &test_certify(block, now_ms));
        state
            .scan_votable_ticks(schedule)
            .into_iter()
            .flat_map(|completion| completion.tx_outcomes)
            .collect()
    }

    /// Committed and never resolved, a transaction is abandoned by the
    /// tick composed at the first commit past its deadline — attested
    /// `Aborted`, carrying the reservation its own block took, on a tick
    /// no tick stands behind.
    #[test]
    fn a_transaction_past_its_deadline_is_attested_aborted() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let reserved = tx.work();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        assert_eq!(
            state.counterparts.ledger.len(),
            1,
            "committed and owed an outcome"
        );

        // Its own tick never finalizes; the shard drops it so nothing can
        // attest a second verdict for it.
        state
            .ticks
            .remove_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(1)));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms);
        assert_eq!(
            outcomes.len(),
            1,
            "the tick attests exactly what it abandons"
        );
        assert_eq!(outcomes[0].tx_hash(), tx_hash);
        assert!(outcomes[0].is_aborted(), "abandonment is an abort");
        assert_eq!(
            outcomes[0].declared_work(),
            reserved,
            "releasing exactly what the committing block reserved",
        );
    }

    /// The floor is burned by the abandonment too, which is what stops a
    /// transaction nobody could execute from aborting for free.
    ///
    /// An abandoned member never reaches an engine, so the charge its
    /// verdict settles is composed rather than executed — but the
    /// reservation engaged when its block committed it, and releasing
    /// that without a burn would price an unexecutable attempt below the
    /// success it was competing with.
    #[test]
    fn an_abandoned_transaction_still_settles_its_floor() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let expected = build_fee_receipt(
            ShardId::ROOT,
            state.counterpart_trie(&schedule),
            tx.hash(),
            tx.fee_vault(),
            tx.price(),
        );
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state
            .ticks
            .remove_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(1)));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_aborted());
        assert_eq!(
            outcomes[0].fee_receipt(),
            Some(expected.receipt_hash()),
            "the abandonment settles the same floor an attested abort would",
        );
    }

    /// And it is settled by the payer's own shard alone: fees never move
    /// cross-shard, so a participant abandoning a leg of somebody else's
    /// transaction charges nothing.
    #[test]
    fn an_abandonment_charges_nothing_where_the_vault_is_not() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        // A payer whose prefix the other half of the split owns.
        let tx = test_transaction(0x81);
        assert_eq!(
            state
                .counterpart_trie(&schedule)
                .shard_for_prefix(tx.fee_vault().owner),
            PEER,
            "the fixture is only a test of this if the vault is elsewhere",
        );
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block_on_shard(
                    HOME,
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state
            .ticks
            .remove_tick(&TickId::new(HOME, BlockHeight::new(1)));

        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(2),
            deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(&schedule, &test_certify(block, deadline_ms));
        let outcomes: Vec<TxOutcome> = state
            .scan_votable_ticks(&schedule)
            .into_iter()
            .flat_map(|completion| completion.tx_outcomes)
            .collect();

        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_aborted());
        assert_eq!(
            outcomes[0].fee_receipt(),
            None,
            "the vault is not here, so neither is the burn",
        );
    }

    /// A block a replay feeds back in, as storage hands it over.
    fn replayable(block: Block, now_ms: u64) -> Verified<CertifiedBlock> {
        Verified::<CertifiedBlock>::from_persisted(test_certify(block, now_ms))
    }

    /// The transactions a coordinator's tick at `height` holds.
    fn tick_members(state: &ExecutionCoordinator, height: u64) -> Vec<TxHash> {
        state
            .ticks
            .get_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(height)))
            .map(|tick| tick.tx_hashes().to_vec())
            .unwrap_or_default()
    }

    /// A replay releases the ticks the blocks it re-drives finalized,
    /// exactly as a commit does.
    ///
    /// A replay recomposes the tick that held a transaction *and* commits
    /// the block whose finalization settled it, and the second is what
    /// hands the transaction back. Skipping it leaves the transaction
    /// assigned to a tick that has already settled, which nothing later
    /// clears — and a leg's reclaim, admitted only where no tick speaks
    /// for the transaction, is then held out for as long as its entry
    /// lives.
    #[test]
    fn a_replay_releases_what_the_blocks_it_replays_finalized() {
        let schedule = make_test_topology();
        let held = test_transaction(2);
        let held_hash = held.hash();
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held)],
        );
        let finalization: Arc<Verifiable<Finalization>> = Arc::new(
            helpers_make_finalization(BlockHeight::new(2), held_hash, TransactionDecision::Accept)
                .into(),
        );
        let settling = helpers_make_live_block(
            ShardId::ROOT,
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![],
            vec![finalization],
        );

        let recovered = RecoveredState {
            committed_height: BlockHeight::new(3),
            replay: ReplayWindow {
                blocks: vec![replayable(committing, 2_000), replayable(settling, 3_000)],
                compose_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );

        restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        assert_eq!(
            restarted.ticks.tick_assignment(held_hash),
            None,
            "the replayed finalization hands the transaction back, so nothing \
             speaks for it",
        );
    }

    /// A replay reaching below what the store can anchor composes its
    /// ticks there and dispatches none of them.
    ///
    /// Composition's reach is what the chain is still owed an outcome
    /// for, which runs back as far as an undischarged record; execution's
    /// is a baseline, and a baseline is a historical read the store
    /// retires at `RETENTION_HORIZON`. Dispatching there reads a height
    /// the store answers with a panic — and composing there is what fixes
    /// which tick holds a member, which every replica of the shard reads
    /// the same however far back its own store reaches.
    #[test]
    fn a_replay_below_the_stores_reach_composes_without_dispatching() {
        let schedule = make_test_topology();
        let held = test_transaction(1);
        let held_hash = held.hash();
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held)],
        );
        let above = make_live_block(BlockHeight::new(3), 3_000, ValidatorId::new(0), vec![]);

        let recovered = RecoveredState {
            committed_height: BlockHeight::new(3),
            replay: ReplayWindow {
                blocks: vec![replayable(committing, 2_000), replayable(above, 3_000)],
                // The store has retired everything below height 2, so a
                // tick at 2 would read a baseline at 1 that is gone.
                compose_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );

        let actions = restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "nothing is dispatched at a height whose baseline the store has retired",
        );
        assert_eq!(
            restarted.counterparts.ledger.len(),
            1,
            "the replay still owes the outcome the chain says it owes",
        );
        assert_eq!(
            restarted.ticks.tick_assignment(held_hash),
            Some(TickId::new(ShardId::ROOT, BlockHeight::new(2))),
            "and holds it in the tick a replica that never went down holds it in",
        );
    }

    /// A settled tick the replay folds past is seated on the chain from
    /// the receipts that committed it, ahead of the first tick the replay
    /// composes.
    ///
    /// The writes reach the base at the block that committed the
    /// finalization, which can sit above the block the replay starts
    /// composing at — so a tick composed in between reads a baseline the
    /// base has not caught up to and the chain, having run no tick there,
    /// no longer holds.
    #[test]
    fn a_replay_seats_the_settled_ticks_it_folds_past() {
        let schedule = make_test_topology();
        let settled = test_transaction(1);
        let settled_hash = settled.hash();
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(settled)],
        );
        // The tick at height 2 settles at height 4, one block above where
        // composition resumes.
        let finalization: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization_leaving(BlockHeight::new(2), settled_hash, StateWrites::default())
                .into(),
        );
        let settling = helpers_make_live_block(
            ShardId::ROOT,
            BlockHeight::new(4),
            4_000,
            ValidatorId::new(0),
            vec![],
            vec![finalization],
        );

        let recovered = RecoveredState {
            committed_height: BlockHeight::new(4),
            replay: ReplayWindow {
                blocks: vec![replayable(committing, 2_000), replayable(settling, 4_000)],
                compose_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );

        let actions = restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        let restored = actions.iter().position(|action| {
            matches!(action, Action::ResolveTicks { resolutions }
            if resolutions.iter().any(|(tick_id, resolution)| {
                *tick_id == TickId::new(ShardId::ROOT, BlockHeight::new(2))
                    && matches!(
                        resolution,
                        TickResolution::Restored { height, .. }
                            if *height == BlockHeight::new(4)
                    )
            }))
        });
        assert!(
            restored.is_some(),
            "the tick the replay folded past is seated from what settled it",
        );
        assert!(
            actions[..restored.expect("seated")]
                .iter()
                .all(|action| !matches!(action, Action::ExecuteTransactions { .. })),
            "and seated before anything the replay composes reads a baseline",
        );
    }

    /// And two replicas of one shard at one frontier abandon the same
    /// members, however far back each one's own store reaches.
    ///
    /// The abandonment rides the tick being composed — a member and its
    /// fee receipt — so it reaches a `TxOutcome` and the receipt root. What
    /// decides it is which tick holds the member and whether a
    /// certificate of this shard's covers it, and both are composition's
    /// output: a replay that composed nothing there would have to assert
    /// them, and either answer diverges from the replica that never went
    /// down.
    #[test]
    fn a_replay_abandons_what_a_seated_replica_at_the_same_frontier_does() {
        let schedule = make_test_topology();
        let held = test_transaction(1);
        let held_hash = held.hash();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held)],
        );

        // The replica that was seated when the block committed.
        let mut seated = make_test_state();
        seated.on_block_committed(&schedule, &test_certify(seed, 1_000));
        seated.on_block_committed(&schedule, &test_certify(committing.clone(), 2_000));

        // The replica restarted with the store no longer able to anchor a
        // baseline at the committing height.
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(2),
            replay: ReplayWindow {
                blocks: vec![replayable(committing, 2_000)],
                compose_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );
        restarted.on_committed_state_restored(&schedule, &StubVmStatics);

        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();
        let aborted = |outcomes: Vec<TxOutcome>| {
            outcomes
                .into_iter()
                .map(|outcome| outcome.tx_hash())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            aborted(abandonment_vote(&mut seated, &schedule, 3, deadline_ms)),
            vec![held_hash],
            "fixture precondition: past the deadline the seated replica abandons it",
        );
        assert_eq!(
            aborted(abandonment_vote(&mut restarted, &schedule, 3, deadline_ms)),
            vec![held_hash],
            "and the restarted one abandons it too, or the ticks the two \
             compose carry different receipt roots",
        );
    }

    /// A restart replays the chain it lost execution state for, so it
    /// ends up holding what a replica that never went down holds.
    ///
    /// Which tick holds a transaction is a function of committed content,
    /// but not one anything on the chain records directly — it is
    /// composition's own output. Re-driving composition over the same
    /// blocks is what reproduces it.
    #[test]
    fn a_restart_replays_the_chain_it_lost_execution_state_for() {
        let schedule = make_test_topology();
        let held = test_transaction(1);
        let held_hash = held.hash();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held)],
        );

        // A replica that never went down: its tick at height 2 takes the
        // transaction and holds it until a finalization resolves it.
        let mut live = make_test_state();
        live.on_block_committed(&schedule, &test_certify(seed, 1_000));
        live.on_block_committed(&schedule, &test_certify(committing.clone(), 2_000));
        assert_eq!(
            live.ticks.tick_assignment(held_hash),
            Some(TickId::new(ShardId::ROOT, BlockHeight::new(2))),
            "fixture precondition: the live replica's tick holds it",
        );

        // A restarted one recovers the same chain: the block that
        // committed the transaction, under the clock of the block below
        // it so the replay stays on the carry path.
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(2),
            replay: ReplayWindow {
                blocks: vec![replayable(committing, 2_000)],
                compose_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );
        assert!(
            restarted.candidates.is_empty(),
            "construction has no topology to compose against, so it holds",
        );

        let actions = restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        assert_eq!(
            restarted.ticks.tick_assignment(held_hash),
            live.ticks.tick_assignment(held_hash),
            "the replay puts it back on the tick that already held it",
        );
        assert!(
            actions.iter().any(
                |action| matches!(action, Action::ExecuteTransactions { requests, .. }
                    if requests.iter().any(|r| r.tx_hash == held_hash))
            ),
            "and runs it, because the tick that holds it is the tick that ran it",
        );
        assert_eq!(
            restarted.counterparts.ledger.len(),
            1,
            "still owed, as the chain says"
        );

        // The consequence: the next block composes one tick, not two
        // different ones. A membership disagreement here is a fail-stop —
        // the quorum's certificate comes back under this tick's own id,
        // carrying a root the odd replica never computed.
        let next = make_live_block(
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(2))],
        );
        live.on_block_committed(&schedule, &test_certify(next.clone(), 3_000));
        restarted.on_block_committed(&schedule, &test_certify(next, 3_000));
        assert_eq!(
            tick_members(&restarted, 3),
            tick_members(&live, 3),
            "a tick's membership decides what its certificate says",
        );
    }

    /// A tick whose receipts disagree with the quorum's fail-stops.
    ///
    /// A restarted replica reaches the quorum's receipts because the
    /// replay puts it back on the chain's own fold, upstream of this
    /// check rather than by loosening it — so the check still bites on
    /// the thing it exists for: a replica computing state nobody else
    /// can reproduce.
    #[test]
    #[should_panic(expected = "BFT CRITICAL")]
    fn a_divergent_fold_fail_stops() {
        let schedule = make_test_topology();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let mut state = make_test_state();
        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        state.on_execution_batch_completed(
            &schedule,
            BlockHeight::new(1),
            TickBatchOutcome {
                tick_id,
                results: Vec::new(),
                tx_outcomes: vec![TxOutcome::new(
                    tx_hash,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )],
                fee_receipts: Vec::new(),
                attested_work: Vec::new(),
            },
        );
        state.emit_vote_actions(&schedule);

        // The committee certified a different root for the tick this
        // replica voted on.
        state
            .ticks
            .get_tick_mut(&tick_id)
            .expect("the tick is still tracked")
            .add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
                ExecutionCertificate::new(
                    tick_id,
                    WeightedTimestamp::from_millis(1_000),
                    GlobalReceiptRoot::from_raw(Hash::from_bytes(b"quorum")),
                    vec![TxOutcome::new(
                        tx_hash,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )],
                    AggregateSignature::ZERO,
                    SignerBitfield::new(4),
                ),
            )));
        state.scan_votable_ticks(&schedule);
    }

    /// A member that never ran joins on the shards holding the keyspace
    /// it reaches, not on this one alone.
    ///
    /// That is what routes the tick's certificate to the counterparts
    /// still owed a verdict for it: an abort is dominant, so their
    /// coverage closes on ours and neither side is left waiting on a
    /// transaction the other has already given up on.
    #[test]
    fn an_undispatched_member_joins_on_the_shards_holding_its_keyspace() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);

        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(1),
            deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(&schedule, &test_certify(block, deadline_ms));
        let outcomes: Vec<TxOutcome> = state
            .scan_votable_ticks(&schedule)
            .into_iter()
            .flat_map(|completion| completion.tx_outcomes)
            .collect();
        assert_eq!(outcomes.len(), 1, "the tick speaks for it");
        assert!(outcomes[0].is_aborted());

        let tick = state
            .ticks
            .get_tick(&TickId::new(HOME, BlockHeight::new(1)))
            .expect("the commit past the deadline composed a tick for it");
        assert_eq!(
            tick.counterpart_shards(),
            vec![PEER],
            "so the certificate reaches the shard still waiting on it",
        );
        assert_eq!(
            tick.awaiting_tx_hashes().collect::<Vec<_>>(),
            vec![tx_hash],
            "and it settles as the leg it is, not as a determined member",
        );
    }

    /// A committed record naming a leg entry licenses its reclaim: the
    /// next commit composes the reclaim into its tick as a dispatched
    /// member running no node, awaiting nobody, reserving nothing — and
    /// never as an abandonment, whatever the clock reads.
    #[test]
    fn a_record_naming_a_leg_composes_its_reclaim() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let past_deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                leg_classified(),
                Vec::new(),
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);
        state
            .counterparts
            .ledger
            .release_resolved(&[Arc::new(Verifiable::from(make_leg_finalization(
                BlockHeight::new(1),
                tx_hash,
            )))]);
        state
            .counterparts
            .ledger
            .record_abandonment_records(&[AbandonmentRecord::departed(
                PEER,
                WeightedTimestamp::from_millis(1_000),
                [UnsettledTx::for_transaction(&transaction)],
            )]);

        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(1),
            past_deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        let actions = state.on_block_committed(&schedule, &test_certify(block, past_deadline_ms));

        let tick = state
            .ticks
            .get_tick(&TickId::new(HOME, BlockHeight::new(1)))
            .expect("the commit composed the reclaim into a tick");
        assert_eq!(
            tick.determined_members(),
            vec![tx_hash],
            "it settles on this shard's certificate alone"
        );
        assert_eq!(tick.awaited_counterparts().count(), 0);
        let request = actions
            .iter()
            .find_map(|action| match action {
                Action::ExecuteTransactions { requests, .. } => {
                    requests.iter().find(|request| request.tx_hash == tx_hash)
                }
                _ => None,
            })
            .expect("the reclaim is dispatched to the engine");
        assert!(
            matches!(
                request.runs,
                Runs::Settle {
                    on: Licence::Unclaimed,
                    charged: true,
                    ..
                }
            ),
            "the leg's finalization committed here, so its certificate settled the price"
        );
        assert!(!request.runs.abortable(), "nothing retracts a reclaim");
        assert!(
            state.counterparts.ledger.reclaimable().is_empty(),
            "and the ledger has handed it to the tick"
        );
    }

    /// A verdict the chain committed reaches the refusal mirror on a
    /// replica that never heard the broadcast.
    ///
    /// This is the restart hole closing: the mirror is fed by
    /// certificate broadcast and nothing rebuilds it at startup, so
    /// before the chain carried the commitment a replica that came up
    /// between a core's refusal and the record's proposal could neither
    /// offer the record nor check one. Folding the claim gives it the
    /// same answer its peers hold, from the block alone.
    #[test]
    fn a_committed_verdict_reaches_a_replica_that_heard_no_broadcast() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                leg_classified(),
                Vec::new(),
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);
        assert!(
            state.counterparts.mirror.all().is_empty(),
            "nothing was broadcast to this replica"
        );

        let anchor = WeightedTimestamp::from_millis(7_000);
        let digest = Hash::from_bytes(b"digest");
        let verdict = refused(anchor, digest);
        let before = state.counterparts.mirror.generation();
        state.counterparts.fold_verdict(PEER, tx_hash, verdict);

        assert_eq!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict),
            Some(verdict),
            "the chain's own word reaches the mirror the record fence reads",
        );
        assert!(
            state.counterparts.mirror.generation() > before,
            "and the mirror's generation moves, which is what re-drives the vote fence"
        );

        // The fold is first-write-wins, as the chain's answer is: a
        // second claim restates a decision already committed.
        let again = state.counterparts.fold_verdict(
            PEER,
            tx_hash,
            Heard {
                at: WeightedTimestamp::from_millis(8_000),
                ..verdict
            },
        );
        assert!(again.is_empty(), "{again:?}");
        assert_eq!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict)
                .map(|held| held.at),
            Some(anchor),
        );

        // A claiming success licenses no record, so it never reaches
        // the mirror at all.
        let mut fresh = make_test_state_for_shard(ValidatorId::new(0), HOME);
        fresh
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        assert!(
            fresh
                .counterparts
                .fold_claimed(PEER, tx_hash, WeightedTimestamp::ZERO)
                .is_empty()
        );
        assert!(fresh.counterparts.mirror.all().is_empty());
    }

    /// A core's refusal of a transaction a leg here issued for is
    /// mirrored off its certificate and handed to the vote fence, and a
    /// `Refused` record is offered from it under the certificate's own
    /// anchor, and the mempool hears the verdict. A second copy adds
    /// nothing.
    #[test]
    fn a_cores_refusal_of_a_leg_is_mirrored_and_offered() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                leg_classified(),
                Vec::new(),
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);

        let certificate = |outcome: ExecutionOutcome| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(PEER, BlockHeight::new(3)),
                WeightedTimestamp::from_millis(7_000),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(tx_hash, outcome)],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )))
        };
        let before = state.counterparts.mirror.generation();
        let actions = state.handle_attestation(&schedule, &certificate(ExecutionOutcome::Failed));
        let word = refused(
            WeightedTimestamp::from_millis(7_000),
            certificate(ExecutionOutcome::Failed).attested_digest(),
        );
        assert_eq!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict),
            Some(word),
            "the refusal reaches the mirror the vote fence reads"
        );
        assert!(
            state.counterparts.mirror.generation() > before,
            "and the mirror's generation moves, re-driving the votes that deferred without it"
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                PEER,
                word,
                [UnsettledTx::for_transaction(&transaction)],
            )],
            "and a record is offered under the certificate's anchor"
        );
        assert_eq!(
            resolved(&actions),
            vec![(
                tx_hash,
                TxResolution::CoreDecided(TransactionDecision::Reject)
            )],
            "and the mempool hears the core's verdict"
        );
        let again = state.handle_attestation(&schedule, &certificate(ExecutionOutcome::Failed));
        assert!(
            !again
                .iter()
                .any(|action| matches!(action, Action::Continuation(_))),
            "a second copy adds nothing"
        );
    }

    /// A core's success is the transaction's verdict only once every
    /// core shard has given one, and it is reported to the mempool once:
    /// a second copy of the certificate adds nothing, and no refusal is
    /// mirrored or offered.
    #[test]
    fn a_cores_success_of_a_leg_is_the_verdict_once_the_whole_core_has_spoken() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let certificate = |outcome: ExecutionOutcome| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(PEER, BlockHeight::new(3)),
                WeightedTimestamp::from_millis(7_000),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(tx_hash, outcome)],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )))
        };
        let mut accepting = make_test_state_for_shard(ValidatorId::new(0), HOME);
        accepting
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        accepting.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                leg_classified(),
                Vec::new(),
                Vec::new(),
            ),
        );
        let before = accepting.counterparts.mirror.generation();
        let actions = accepting.handle_attestation(
            &schedule,
            &certificate(ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            }),
        );
        assert_eq!(
            accepting.counterparts.mirror.generation(),
            before,
            "a success is not a refusal"
        );
        assert!(accepting.offers().abandonment_records.is_empty());
        assert_eq!(
            resolved(&actions),
            vec![(
                tx_hash,
                TxResolution::CoreDecided(TransactionDecision::Accept)
            )],
            "the whole core accepted, which is the transaction's verdict"
        );
        let again = accepting.handle_attestation(
            &schedule,
            &certificate(ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            }),
        );
        assert!(
            resolved(&again).is_empty(),
            "the core's verdict is reported once"
        );
    }

    /// The resolutions an attestation handed to the mempool.
    fn resolved(actions: &[Action]) -> Vec<(TxHash, TxResolution)> {
        actions
            .iter()
            .flat_map(|action| match action {
                Action::Continuation(ProtocolEvent::TransactionsResolved { resolutions }) => {
                    resolutions.clone()
                }
                _ => Vec::new(),
            })
            .collect()
    }

    /// A state on [`HOME`] holding `transaction` as a leg, certified and
    /// never resolved, with the shape frozen as `classified` says: what
    /// fixes how many shards the core spans, and so whether its
    /// committed cell is ever asked about.
    fn leg_state(
        transaction: &Arc<Verifiable<Transaction>>,
        classified: Classified,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            transaction.hash(),
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                classified,
                Vec::new(),
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(transaction.hash());
        state
    }

    /// The state-proof fetches among `actions`, by anchor.
    fn state_proof_fetches(actions: &[Action]) -> Vec<(Anchor, Vec<SubstateKey>)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::StateProof { anchor, keys, .. }) => {
                    Some((*anchor, keys.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// A proof over `asked` against a tree holding `present`, and the
    /// commit-proven header at `shard`'s `height` stamped `ts` naming
    /// its root: what a counterpart's chain answers, in the shape a
    /// block carries it.
    fn proven_at(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        shard: ShardId,
        height: u64,
        ts: WeightedTimestamp,
        present: &[SubstateKey],
        asked: &[SubstateKey],
    ) -> (StateClaim, Vec<Action>) {
        let (state_root, proof) = state_and_proof(shard, present, asked);
        let anchor = Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root,
            ts,
        };
        let cells = proof
            .inclusions(state_root, shard, asked)
            .expect("the fixture proof answers for its keys");
        state.proven_anchors().record(anchor);
        // A probe anchors at what stands at the chain's own clock, and
        // both chains run on one wall clock: a node holding a
        // counterpart's header at `ts` has committed to there itself.
        state.committed_ts = state.committed_ts.max(ts);
        let opened = state.on_committed_remote_header(schedule, shard);
        (StateClaim::new(anchor, cells), opened)
    }

    /// Feed `state` the proof its own fetch brings back for `claim`,
    /// against a tree holding `present` — the bytes [`proven_at`] read
    /// the claim off.
    fn fetch_answers(
        state: &mut ExecutionCoordinator,
        claim: &StateClaim,
        present: &[SubstateKey],
    ) {
        let keys = claim.keys();
        let (_, proof) = state_and_proof(claim.anchor.shard, present, &keys);
        state.on_proof_fetched(claim.anchor, keys, proof);
    }

    /// Commit a block on [`HOME`] carrying `bundles` — the seam every
    /// replica folds a proof at — and return what the fold emitted.
    fn commit_carrying(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        height: u64,
        ts_ms: u64,
        bundles: Vec<StateClaim>,
    ) -> Vec<Action> {
        let Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            witness_sources,
            ..
        } = make_live_block_on_shard(
            HOME,
            BlockHeight::new(height),
            ts_ms,
            ValidatorId::new(0),
            vec![],
        )
        else {
            unreachable!("a live block")
        };
        let block = Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims: Arc::new(bundles),
            witness_sources,
        };
        state.on_block_committed(schedule, &test_certify(block, ts_ms))
    }

    /// The part a leg plays, with the cells a fixture names for it.
    fn leg_part(
        body: Arc<Verified<Transaction>>,
        classified: Classified,
        deliveries: Vec<(ShardId, SubstateKey)>,
        claims: Vec<(ShardId, SubstateKey)>,
    ) -> Part {
        let core = classified.core().clone();
        Part::leg(Kept {
            body,
            classified,
            core,
            deliveries,
            claims,
        })
    }

    /// The absences of `tx_hash` at [`PEER`] handed to the fence among
    /// mirror.
    fn absences_observed(state: &ExecutionCoordinator, tx_hash: TxHash) -> Vec<Heard> {
        absences_observed_at(state, PEER, tx_hash)
    }

    /// The absences of `tx_hash` at `at` the mirror holds, whichever
    /// question proved them.
    fn absences_observed_at(
        state: &ExecutionCoordinator,
        at: ShardId,
        tx_hash: TxHash,
    ) -> Vec<Heard> {
        [Probed::Core, Probed::Delivery, Probed::Claim]
            .into_iter()
            .filter_map(|probed| {
                state
                    .counterparts
                    .mirror
                    .heard(tx_hash, at, Question::Cell(probed))
            })
            .collect()
    }

    /// `probed` proved absent at `at`.
    fn absent(probed: Probed, at: WeightedTimestamp) -> Heard {
        Heard {
            question: Question::Cell(probed),
            word: Word::Absent,
            at,
        }
    }

    /// A rejection at `at`, by the certificate `digest` names.
    fn refused(at: WeightedTimestamp, digest: Hash) -> Heard {
        Heard {
            question: Question::Verdict,
            word: Word::Refused {
                decision: TransactionDecision::Reject,
                digest,
            },
            at,
        }
    }

    /// A delivery that never claimed is probed at its lapse, the
    /// deadline plus a validity range, and never at a header short of
    /// it — the deadline itself included, where a core would already be
    /// asked. The proof the chain carries reaches the vote fence with
    /// the lapse as its floor and is offered as a lapse record.
    #[test]
    fn a_silent_delivery_is_probed_past_the_lapse_and_its_lapse_offered() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let lapse = deadline.plus(MAX_VALIDITY_RANGE);
        let claim = SubstateKey {
            owner: test_prefix(0x81),
            local: LocalKey([0xC1; 16]),
        };
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                delivery_classified(),
                vec![(PEER, claim)],
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);

        let held: [(u64, WeightedTimestamp, &[u8]); 2] =
            [(3, deadline, b"deadline"), (4, lapse, b"at")];
        for (height, ts, tag) in held {
            state.proven_anchors().record(Anchor {
                shard: PEER,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::from_bytes(tag)),
                ts,
            });
            state.on_committed_remote_header(&schedule, PEER);
        }
        let later = lapse.plus(Duration::from_secs(1));
        let (bundle, opened) = proven_at(&mut state, &schedule, PEER, 5, later, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
            "the newest header inside the lapse window is the anchor, and the claim cell the key"
        );

        let _ = commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![bundle]);
        assert_eq!(
            absences_observed(&state, tx_hash),
            vec![absent(Probed::Delivery, later)],
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                PEER,
                absent(Probed::Delivery, later),
                [figures]
            )],
            "offered as a lapse, under the anchor it was proved at"
        );
    }

    /// A proof this validator's fetch answered is committed content
    /// waiting for a block: it is offered, dated to the clock the probe
    /// read off the header, until a block carries it, and not after.
    #[test]
    fn a_fetched_proof_is_offered_until_a_block_carries_it() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = UnsettledTx::for_transaction(&transaction).deadline.at();
        let later = deadline
            .plus(MAX_VALIDITY_RANGE)
            .plus(Duration::from_secs(1));
        let claim = SubstateKey {
            owner: test_prefix(0x81),
            local: LocalKey([0xC1; 16]),
        };
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                delivery_classified(),
                vec![(PEER, claim)],
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);
        let (bundle, opened) = proven_at(&mut state, &schedule, PEER, 5, later, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
        );
        fetch_answers(&mut state, &bundle, &[]);
        assert_eq!(
            state.offers().state_claims,
            vec![bundle.clone()],
            "dated to the clock the probe read off the header"
        );

        let deadline_ms = deadline.as_millis();
        commit_carrying(&mut state, &schedule, 1, deadline_ms, Vec::new());
        assert_eq!(
            state.offers().state_claims,
            vec![bundle.clone()],
            "a block carrying no proofs leaves the offer standing"
        );
        commit_carrying(&mut state, &schedule, 2, deadline_ms, vec![bundle]);
        assert!(
            state.offers().state_claims.is_empty(),
            "a proof the chain carries is everybody's"
        );
    }

    /// A question this validator's own proof answered is not put again,
    /// however many newer headers the counterpart commits.
    ///
    /// Every validator probes, not only the proposer, and a counterpart
    /// header lands every block. Read as unanswered until the chain
    /// carries someone's copy, one cell would be fetched from the
    /// counterpart once per block by every member of the committee, for
    /// bytes each of them already holds.
    #[test]
    fn a_proof_this_validator_fetched_stops_it_asking_again() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let claim = SubstateKey {
            owner: test_prefix(0x81),
            local: LocalKey([0xC4; 16]),
        };
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                delivery_classified(),
                vec![(PEER, claim)],
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);

        let lapse = Window::Lapse
            .of(Deadline::of_transaction(&transaction))
            .start;
        let (bundle, opened) = proven_at(&mut state, &schedule, PEER, 5, lapse, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
            "the cell is asked about once",
        );
        fetch_answers(&mut state, &bundle, &[]);

        let (_, opened) = proven_at(&mut state, &schedule, PEER, 6, lapse, &[], &[claim]);
        assert!(
            state_proof_fetches(&opened).is_empty(),
            "and not again at a newer header, the answer being in hand",
        );
        assert_eq!(
            state.offers().state_claims,
            vec![bundle],
            "while the proof is still offered, since only a block makes it everybody's",
        );
    }

    /// A delivering shard that departed at a reshape leaves no header
    /// past the lapse, so its claim cell is asked about on the successor
    /// the trie names for the cell's owner — the child holding the
    /// departed chain's cells — and the absence proved there is offered
    /// as a lapse under the successor's name. A header of the departed
    /// shard past the lapse, should one exist, is asked as well, so
    /// every validator proves whichever shard a record names.
    #[test]
    fn a_delivery_whose_deliverer_departed_is_probed_on_its_successor() {
        let schedule = peer_terminating_schedule(60_000);
        let (successor, _) = PEER.children();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let lapse = deadline.plus(MAX_VALIDITY_RANGE);
        // An owner under the peer's left child, as the trie cuts it.
        let claim = SubstateKey {
            owner: test_prefix(0x81),
            local: LocalKey([0xC1; 16]),
        };
        assert_eq!(
            schedule.head().shard_trie().shard_for_prefix(claim.owner),
            successor,
            "the fixture's claim sits under the departed peer's left child"
        );
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            tx_hash,
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                delivery_classified(),
                vec![(PEER, claim)],
                Vec::new(),
            ),
        );
        state.counterparts.ledger.certify(tx_hash);
        // The local chain has crossed the peer's cut: its committee is
        // anchored in a window whose trie names the children.
        state.committed_committee_anchor_wt = lapse;

        let held: [(u64, WeightedTimestamp, &[u8]); 2] =
            [(3, deadline, b"short"), (4, lapse, b"at")];
        for (height, ts, tag) in held {
            state.proven_anchors().record(Anchor {
                shard: successor,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::from_bytes(tag)),
                ts,
            });
            state.on_committed_remote_header(&schedule, successor);
        }
        let later = lapse.plus(Duration::from_secs(1));
        let (bundle, opened) = proven_at(&mut state, &schedule, successor, 5, later, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
            "the successor's newest header inside the lapse window is the anchor, and the \
             claim cell the key; the departed peer, with no header, is not asked"
        );

        // A header of the departed peer past the lapse is asked as well.
        let (peer_bundle, peer_opened) =
            proven_at(&mut state, &schedule, PEER, 6, lapse, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&peer_opened),
            vec![(peer_bundle.anchor, vec![claim])],
            "the shard that was to deliver is asked wherever it has a header past the lapse"
        );

        let _ = commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![bundle]);
        assert_eq!(
            absences_observed_at(&state, successor, tx_hash),
            vec![absent(Probed::Delivery, later)],
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                successor,
                absent(Probed::Delivery, later),
                [figures]
            )],
            "offered as a lapse under the successor's name"
        );
    }

    /// A leg whose core, spanning two shards, has fallen silent: the
    /// core's three headers held, none asked about while the committed
    /// clock was short of the deadline, and the clock now at it. Only
    /// such a core writes the committed cell a leg asks about.
    struct SilentCore {
        schedule: TopologySchedule,
        state: ExecutionCoordinator,
        tx_hash: TxHash,
        key: SubstateKey,
        figures: UnsettledTx,
        deadline: WeightedTimestamp,
    }

    fn silent_core() -> SilentCore {
        let schedule = two_shard_core_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let key = committed_tx_cell_key(
            CORE,
            tx_hash,
            transaction.validity_range().end_timestamp_exclusive,
        );
        let root = |tag: &[u8]| StateRoot::from_raw(Hash::from_bytes(tag));
        let mut state = leg_state(&transaction, two_shard_core_classified());
        let held: [(u64, WeightedTimestamp, &[u8]); 3] = [
            (3, deadline.minus(Duration::from_millis(1)), b"short"),
            (5, deadline.plus(Duration::from_secs(1)), b"later"),
            (4, deadline, b"at"),
        ];
        for (height, ts, tag) in held {
            state.proven_anchors().record(Anchor {
                shard: CORE,
                height: BlockHeight::new(height),
                state_root: root(tag),
                ts,
            });
            let actions = state.on_committed_remote_header(&schedule, CORE);
            assert!(
                state_proof_fetches(&actions).is_empty(),
                "before the deadline nothing is asked"
            );
        }
        state.committed_ts = deadline;
        SilentCore {
            schedule,
            state,
            tx_hash,
            key,
            figures,
            deadline,
        }
    }

    /// The core's committed cell proved absent past the deadline
    /// reaches the vote fence and is offered as an `Unclaimed` record.
    /// The window is what licenses the answer, not the anchor the
    /// proposer happened to probe at: a proof taken short of the
    /// deadline says nothing, and a second copy adds nothing.
    #[test]
    fn a_silent_core_is_probed_past_the_deadline_and_its_absence_offered() {
        let SilentCore {
            schedule,
            mut state,
            tx_hash,
            key,
            figures,
            deadline,
        } = silent_core();
        let later = deadline.plus(Duration::from_secs(1));
        let (bundle, opened) = proven_at(&mut state, &schedule, CORE, 5, later, &[], &[key]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![key])],
            "the newest header inside the window is the anchor"
        );
        assert!(
            state_proof_fetches(&state.probe_silent_counterparts(&schedule)).is_empty(),
            "a probe in flight is not re-issued while nothing newer is held"
        );

        let (early, _) = proven_at(
            &mut state,
            &schedule,
            CORE,
            2,
            deadline.minus(Duration::from_millis(1)),
            &[],
            &[key],
        );
        let _ = commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![early]);
        assert!(
            absences_observed_at(&state, CORE, tx_hash).is_empty(),
            "a proof taken before the deadline says nothing: the core may still commit"
        );

        let before = state.counterparts.mirror.generation();
        commit_carrying(
            &mut state,
            &schedule,
            2,
            deadline.as_millis(),
            vec![bundle.clone()],
        );
        assert!(
            state.counterparts.mirror.generation() > before,
            "the absence lands in the mirror the fence reads"
        );
        assert_eq!(
            absences_observed_at(&state, CORE, tx_hash),
            vec![absent(Probed::Core, later)],
            "the absence reaches the mirror the vote fence reads"
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                CORE,
                absent(Probed::Core, later),
                [figures]
            )],
            "and a record is offered under the anchor it was proved at"
        );

        let before = state.counterparts.mirror.generation();
        commit_carrying(&mut state, &schedule, 3, deadline.as_millis(), vec![bundle]);
        assert_eq!(
            state.counterparts.mirror.generation(),
            before,
            "a second copy adds nothing"
        );
    }

    /// A core of two shards that turns out to have committed the
    /// transaction is not absent: the presence answers the question,
    /// offers nothing, and the core is not asked again — its own
    /// certificate speaks next.
    #[test]
    fn a_core_that_committed_the_transaction_is_not_probed_again() {
        let schedule = two_shard_core_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = UnsettledTx::for_transaction(&transaction).deadline.at();
        let key = committed_tx_cell_key(
            CORE,
            tx_hash,
            transaction.validity_range().end_timestamp_exclusive,
        );
        let mut state = leg_state(&transaction, two_shard_core_classified());
        state.committed_ts = deadline;
        let (bundle, opened) = proven_at(&mut state, &schedule, CORE, 4, deadline, &[key], &[key]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![key])]
        );

        let folded = commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![bundle]);
        assert!(
            absences_observed_at(&state, CORE, tx_hash).is_empty(),
            "a core that committed it is not absent"
        );
        assert!(
            folded.iter().any(|action| matches!(
                action,
                Action::Fetch(FetchRequest::ExecutionCerts { source_shard, tx_hash: fetched, .. })
                    if *source_shard == CORE && *fetched == tx_hash
            )),
            "and its certificate is fetched, since a refusal there licenses the reclaim"
        );
        assert!(state.offers().abandonment_records.is_empty());
        assert!(
            state_proof_fetches(&state.probe_silent_counterparts(&schedule)).is_empty(),
            "and is not asked again"
        );
    }

    /// A core member asks its siblings, and never itself.
    ///
    /// A core spanning shards settles only when every one of them
    /// certifies, and a sibling that never included the transaction
    /// never will. Without the question the member waits on a
    /// certificate nobody owes it: it is not decided alone, so the
    /// deadline does not reach it, and no counterpart has departed, so
    /// nothing else does either.
    #[test]
    fn a_core_member_asks_the_siblings_it_waits_on() {
        let schedule = two_shard_core_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let cell = |shard| {
            committed_tx_cell_key(
                shard,
                tx_hash,
                transaction.validity_range().end_timestamp_exclusive,
            )
        };
        // A member of the core, on CORE, whose sibling is CORE_SIBLING.
        let mut state = make_test_state_for_shard(ValidatorId::new(0), CORE);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &two_shard_core_classified())]);
        state.counterparts.ledger.certify(tx_hash);
        state.committed_ts = deadline;

        let (never, opened) = proven_at(
            &mut state,
            &schedule,
            CORE_SIBLING,
            4,
            deadline,
            &[],
            &[cell(CORE_SIBLING)],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(never.anchor, vec![cell(CORE_SIBLING)])],
            "the sibling whose certificate the settlement waits on is asked",
        );

        commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![never]);
        assert_eq!(
            absences_observed_at(&state, CORE_SIBLING, tx_hash),
            vec![absent(Probed::Core, deadline)],
            "and its silence is written down",
        );
        let records = state.offers().abandonment_records;
        assert_eq!(
            records,
            vec![AbandonmentRecord::heard(
                CORE_SIBLING,
                absent(Probed::Core, deadline),
                [figures]
            )],
            "so the member can say why its core can never settle",
        );

        // Committed, the record is what releases the member: the entry
        // is covered, and a covered entry is the shard's to abandon.
        state
            .counterparts
            .ledger
            .record_abandonment_records(&records);
        assert!(state.counterparts.ledger.is_unsettled_by_departed(tx_hash));
        assert_eq!(
            state
                .abandonable(TickId::new(CORE, BlockHeight::new(9)))
                .iter()
                .map(|entry| entry.tx_hash)
                .collect::<Vec<_>>(),
            vec![tx_hash],
        );
    }

    /// Every core shard is asked, so the one that never included the
    /// transaction answers even where its sibling did.
    ///
    /// A core settles only if all of its shards do, so one shard absent
    /// past the deadline is the whole answer, while a shard that did
    /// include says only that a sibling is still pending. Asking the
    /// lowest alone strands the crossing exactly when that shard is the
    /// one that included it.
    #[test]
    fn a_core_shard_that_never_included_it_answers_beside_a_sibling_that_did() {
        let schedule = two_shard_core_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let validity_end = transaction.validity_range().end_timestamp_exclusive;
        let cell = |shard| committed_tx_cell_key(shard, tx_hash, validity_end);
        let mut state = leg_state(&transaction, two_shard_core_classified());
        state.committed_ts = deadline;

        // The lowest core shard committed the transaction; its sibling
        // never did.
        let (included, opened) = proven_at(
            &mut state,
            &schedule,
            CORE,
            4,
            deadline,
            &[cell(CORE)],
            &[cell(CORE)],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(included.anchor, vec![cell(CORE)])],
        );
        let (never, opened) = proven_at(
            &mut state,
            &schedule,
            CORE_SIBLING,
            4,
            deadline,
            &[],
            &[cell(CORE_SIBLING)],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(never.anchor, vec![cell(CORE_SIBLING)])],
            "the sibling is asked too, and about its own cell",
        );

        commit_carrying(
            &mut state,
            &schedule,
            1,
            deadline.as_millis(),
            vec![included, never],
        );
        assert!(
            absences_observed_at(&state, CORE, tx_hash).is_empty(),
            "the shard that included it is not absent",
        );
        assert_eq!(
            absences_observed_at(&state, CORE_SIBLING, tx_hash),
            vec![absent(Probed::Core, deadline)],
            "and the sibling that never did answers",
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                CORE_SIBLING,
                absent(Probed::Core, deadline),
                [figures]
            )],
            "which is what licenses taking the crossing back",
        );
    }

    /// A leg entry on `HOME` whose core consumer's claim sits at `claim`
    /// on `PEER`, with the committed clock at the deadline: what a claim
    /// probe is issued for.
    fn claimed_leg_state(
        transaction: &Arc<Verifiable<Transaction>>,
        claim: SubstateKey,
    ) -> ExecutionCoordinator {
        claimed_leg_state_under(transaction, claim, leg_classified())
    }

    /// [`claimed_leg_state`] with the shape frozen as `classified` says:
    /// what fixes how many shards the core spans.
    fn claimed_leg_state_under(
        transaction: &Arc<Verifiable<Transaction>>,
        claim: SubstateKey,
        classified: Classified,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state
            .counterparts
            .ledger
            .register_committed([(transaction, &Classified::whole())]);
        state.counterparts.ledger.seed(
            transaction.hash(),
            leg_part(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                classified,
                Vec::new(),
                vec![(PEER, claim)],
            ),
        );
        state.counterparts.ledger.certify(transaction.hash());
        state.committed_ts = UnsettledTx::for_transaction(transaction).deadline.at();
        state
    }

    /// A core consumer's claim is asked about beside the core's
    /// committed cell. On a core of one shard a claim proved absent
    /// past the deadline is the core never taking the crossing: it
    /// reaches the fence, is offered as an `Untaken` record, and neither
    /// question is asked again.
    #[test]
    fn a_single_shard_cores_claim_proved_absent_is_its_answer() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let figures = UnsettledTx::for_transaction(&transaction);
        let deadline = figures.deadline.at();
        let core_key = committed_tx_cell_key(
            PEER,
            tx_hash,
            transaction.validity_range().end_timestamp_exclusive,
        );
        let claim = SubstateKey {
            owner: core_key.owner,
            local: LocalKey([0x7C; 16]),
        };
        let mut state = claimed_leg_state(&transaction, claim);
        let (bundle, opened) = proven_at(&mut state, &schedule, PEER, 4, deadline, &[], &[claim]);
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
            "a core of one shard writes no committed cell, so only its consumer's claim is asked"
        );

        fetch_answers(&mut state, &bundle, &[]);
        let before = state.counterparts.mirror.generation();
        commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![bundle]);
        assert!(
            state.counterparts.mirror.generation() > before,
            "an absent claim on a core of one shard is evidence"
        );
        assert_eq!(
            state.offers().abandonment_records,
            vec![AbandonmentRecord::heard(
                PEER,
                absent(Probed::Claim, deadline),
                [figures]
            )],
            "offered as untaken, under the anchor it was proved at"
        );

        let (_, opened) = proven_at(
            &mut state,
            &schedule,
            PEER,
            5,
            deadline.plus(Duration::from_secs(2)),
            &[],
            &[claim],
        );
        assert!(
            state_proof_fetches(&opened).is_empty(),
            "and the claim is not asked again: it answered"
        );
    }

    /// On a core of more than one shard the same absence says only that
    /// a sibling is pending: the core settles on its siblings' clock, so
    /// nothing reaches the fence, nothing is offered, and the claim is
    /// asked again at the next header — alone, since the committed cell
    /// answered. That cell is what answers for such a core.
    #[test]
    fn a_multi_shard_cores_claim_proved_absent_is_asked_again() {
        let schedule = two_shard_core_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = UnsettledTx::for_transaction(&transaction).deadline.at();
        let core_key = committed_tx_cell_key(
            CORE,
            tx_hash,
            transaction.validity_range().end_timestamp_exclusive,
        );
        let claim = SubstateKey {
            owner: core_key.owner,
            local: LocalKey([0x7C; 16]),
        };
        let mut state = claimed_leg_state_under(&transaction, claim, two_shard_core_classified());
        let (bundle, opened) = proven_at(
            &mut state,
            &schedule,
            CORE,
            4,
            deadline,
            &[core_key],
            &[core_key, claim],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![core_key, claim])],
            "the committed cell and the claim are asked together"
        );

        fetch_answers(&mut state, &bundle, &[core_key]);
        let before = state.counterparts.mirror.generation();
        commit_carrying(&mut state, &schedule, 1, deadline.as_millis(), vec![bundle]);
        assert_eq!(
            state.counterparts.mirror.generation(),
            before,
            "an absent claim on a core of two shards proves nothing"
        );
        assert!(state.offers().abandonment_records.is_empty());

        let (later, opened) = proven_at(
            &mut state,
            &schedule,
            CORE,
            5,
            deadline.plus(Duration::from_secs(2)),
            &[core_key],
            &[claim],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(later.anchor, vec![claim])],
            "only the claim is asked again: the committed cell answered"
        );
    }

    /// An escrow record a seat inherited: the leaf a predecessor left,
    /// naming a claim cell that sits on `PEER`.
    fn inherited_record(local: u8, expiry_ms: u64) -> (SubstateKey, SubstateKey, CrossingCell) {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let claim = SubstateKey {
            owner: committed_tx_cell_key(
                PEER,
                transaction.hash(),
                transaction.validity_range().end_timestamp_exclusive,
            )
            .owner,
            local: LocalKey([local; 16]),
        };
        let record_key = SubstateKey {
            owner: committed_tx_cell_key(
                HOME,
                transaction.hash(),
                transaction.validity_range().end_timestamp_exclusive,
            )
            .owner,
            local: LocalKey([local ^ 0xFF; 16]),
        };
        let cell = CrossingCell {
            resource: ResourceAddr::new([0xE1; 31]),
            amount: 1_000,
            intent: SubintentHash(Hash32([local; 32])),
            local: 0,
            output: 0,
            expiry_ms,
            tx: transaction.hash(),
            consumer_claim: claim,
            origin: None,
        };
        (record_key, claim, cell)
    }

    /// What a seat holding one inherited record dispatches, once a block
    /// carries a proof of its claim.
    fn inherited_settlement(present: bool) -> Option<Runs> {
        let schedule = two_shard_topology();
        let mut state = make_test_state();
        // Past the lapse, which is where an absence answers.
        let expiry_ms = 400_000;
        let (record_key, claim, cell) = inherited_record(0x6A, expiry_ms);
        let deadline = Deadline::from_expiry(expiry_ms);
        let read_at = Window::Lapse
            .of(deadline)
            .start
            .plus(Duration::from_secs(1));
        state
            .counterparts
            .inherited
            .insert(record_key, Inherited::seated(cell));

        // The claim sits on PEER, so the seat asks rather than reads.
        state.committed_ts = read_at;
        let present_keys: Vec<SubstateKey> = if present { vec![claim] } else { Vec::new() };
        let (bundle, opened) = proven_at(
            &mut state,
            &schedule,
            PEER,
            5,
            read_at,
            &present_keys,
            &[claim],
        );
        assert!(
            state_proof_fetches(&opened)
                .iter()
                .any(|(_, keys)| keys.contains(&claim)),
            "the seat asks whoever holds the claim's prefix"
        );
        let actions = commit_carrying(&mut state, &schedule, 1, read_at.as_millis(), vec![bundle]);
        actions.iter().find_map(|action| match action {
            Action::ExecuteTransactions { requests, .. } => {
                requests.first().map(|request| request.runs.clone())
            }
            _ => None,
        })
    }

    /// A record inherited with a prefix whose claim routes elsewhere is
    /// decided against that claim, proved.
    ///
    /// Present, the consumer holds the crossing and the record is
    /// deleted; absent past the lapse, nobody took it and the value goes
    /// back. Before this a seat skipped such a record on every tick
    /// forever: the value stood on its prefix with nothing naming it.
    #[test]
    fn a_seat_decides_an_inherited_record_against_a_proof_of_its_claim() {
        assert!(
            matches!(
                inherited_settlement(true),
                Some(Runs::Settle {
                    on: Licence::Accepted,
                    ..
                })
            ),
            "a claim proved present retires the record"
        );
        assert!(
            matches!(
                inherited_settlement(false),
                Some(Runs::Settle {
                    on: Licence::Unclaimed,
                    ..
                })
            ),
            "and proved absent past the lapse takes the crossing back"
        );
    }

    /// A leg entry on `HOME` whose core consumer's claim sits on `PEER`
    /// under `local`, with the transaction, its figures and the claim
    /// key beside it.
    fn consumer_claim_fixture(
        local: u8,
    ) -> (
        Arc<Verifiable<Transaction>>,
        UnsettledTx,
        SubstateKey,
        ExecutionCoordinator,
    ) {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let figures = UnsettledTx::for_transaction(&transaction);
        let claim = SubstateKey {
            owner: committed_tx_cell_key(
                PEER,
                transaction.hash(),
                transaction.validity_range().end_timestamp_exclusive,
            )
            .owner,
            local: LocalKey([local; 16]),
        };
        let state = claimed_leg_state(&transaction, claim);
        (transaction, figures, claim, state)
    }

    /// A cued claim is not asked about before the counterpart could
    /// have written it.
    ///
    /// The cue names where the writing execution ran, and the cell
    /// lands a lag past it, so a probe inside the lag is a fetch spent
    /// on an answer that cannot be there — and, since a claim is held
    /// to each voter's own reading, one taken at whichever height each
    /// member's own poll happened to reach.
    #[test]
    fn a_cued_claim_waits_for_the_cell_to_be_readable() {
        let schedule = two_shard_topology();
        let (transaction, figures, claim, mut state) = consumer_claim_fixture(0x7C);
        let claimed_at = figures.deadline.at().minus(Duration::from_secs(5));
        state
            .counterparts
            .fold_claimed(PEER, transaction.hash(), claimed_at);

        let (_, early) = proven_at(
            &mut state,
            &schedule,
            PEER,
            5,
            claimed_at.plus(CLAIM_VISIBILITY_LAG / 2),
            &[],
            &[claim],
        );
        assert!(
            state_proof_fetches(&early).is_empty(),
            "a header inside the lag is not asked of",
        );

        let (bundle, opened) = proven_at(
            &mut state,
            &schedule,
            PEER,
            6,
            claimed_at.plus(CLAIM_VISIBILITY_LAG),
            &[claim],
            &[claim],
        );
        assert_eq!(
            state_proof_fetches(&opened),
            vec![(bundle.anchor, vec![claim])],
            "and the first one past it is",
        );
    }

    /// A consumer's claim proved present is what licenses the
    /// retirement: the cell is written by the consuming execution and by
    /// nothing else, so its presence is the consumer holding the
    /// crossing. The committed claim is the whole of the evidence — it
    /// reaches no mirror and no record — and the certificate is still
    /// fetched, since a core's acceptance decides the transaction.
    #[test]
    fn a_claim_proved_present_licenses_the_retirement_off_the_claim_alone() {
        let schedule = two_shard_topology();
        let (transaction, figures, claim, mut state) = consumer_claim_fixture(0x7C);
        let tx_hash = transaction.hash();
        let probed_wt = figures.deadline.at().plus(Duration::from_secs(2));
        let (bundle, opened) = proven_at(
            &mut state,
            &schedule,
            PEER,
            5,
            probed_wt,
            &[claim],
            &[claim],
        );
        assert!(
            state_proof_fetches(&opened)
                .iter()
                .any(|(at, keys)| *at == bundle.anchor && keys.contains(&claim)),
            "the claim is asked about"
        );

        let folded = commit_carrying(
            &mut state,
            &schedule,
            1,
            probed_wt.as_millis(),
            vec![bundle],
        );
        assert!(
            folded.iter().any(|action| matches!(
                action,
                Action::Fetch(FetchRequest::ExecutionCerts { source_shard, tx_hash: fetched, .. })
                    if *source_shard == PEER && *fetched == tx_hash
            )),
            "a present claim fetches the consumer's certificate"
        );
        assert!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict)
                .is_none(),
            "the verdict is a separate question and nothing answered it"
        );
        assert!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Cell(Probed::Claim))
                .is_none(),
            "a presence is not a word the mirror holds"
        );
        assert!(
            state.offers().abandonment_records.is_empty(),
            "and no record restates it"
        );
        let request = folded
            .iter()
            .find_map(|action| match action {
                Action::ExecuteTransactions { requests, .. } => {
                    requests.iter().find(|request| request.tx_hash == tx_hash)
                }
                _ => None,
            })
            .expect("the same commit composes the retirement into its tick");
        assert!(matches!(
            request.runs,
            Runs::Settle {
                on: Licence::Accepted,
                ..
            }
        ));
        assert!(
            state.counterparts.ledger.retirable().is_empty(),
            "and the ledger has handed it to the tick"
        );
    }

    /// A consumer's acceptance opens the probe and nothing else. It
    /// reaches no mirror and no record: what licenses the retirement is
    /// the presence its probe reads, and once the claim carrying it
    /// commits the next commit composes the retirement into its tick —
    /// a dispatched member running no node, awaiting nobody, charged
    /// nothing.
    #[test]
    fn a_consumers_acceptance_cues_the_probe_and_the_presence_retires() {
        let schedule = two_shard_topology();
        let (transaction, figures, _, mut state) = consumer_claim_fixture(0x7D);
        let tx_hash = transaction.hash();
        let probed_wt = figures.deadline.at().plus(Duration::from_secs(2));
        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            TickId::new(PEER, BlockHeight::new(5)),
            probed_wt,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        let before = state.counterparts.mirror.generation();
        state.handle_attestation(&schedule, &certificate);
        assert_eq!(
            state.counterparts.mirror.generation(),
            before,
            "an acceptance is a cue, so nothing reaches the mirror"
        );
        assert!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict)
                .is_none(),
            "and no record could carry it"
        );
        assert!(
            state.offers().abandonment_records.is_empty(),
            "the retirement waits on the presence its probe reads"
        );

        // The probe answers present, which the committed claim writes
        // to the ledger.
        state.counterparts.ledger.record_claimed(tx_hash, PEER);
        let actions = commit_carrying(&mut state, &schedule, 2, probed_wt.as_millis(), Vec::new());
        let request = actions
            .iter()
            .find_map(|action| match action {
                Action::ExecuteTransactions { requests, .. } => {
                    requests.iter().find(|request| request.tx_hash == tx_hash)
                }
                _ => None,
            })
            .expect("the retirement is dispatched to the engine");
        assert!(matches!(
            request.runs,
            Runs::Settle {
                on: Licence::Accepted,
                ..
            }
        ));
        assert!(!request.runs.abortable(), "nothing retracts a retirement");
        assert!(
            state.counterparts.ledger.retirable().is_empty(),
            "and the ledger has handed it to the tick"
        );
    }

    /// A consumer's acceptance is never offered as a record, whatever
    /// its settled set says.
    ///
    /// A certificate promises a finalization that a cut can land before,
    /// and the terminal sweep then abandons the tick — which is why a
    /// retirement standing on one had to be held to the consumer's
    /// settled set while its termination was scheduled. Nothing here is
    /// held to anything now: the claim cell is written by the consuming
    /// execution or it is not, and a consumer cut before it wrote one
    /// leaves an absence, which is the reclaim's evidence rather than
    /// the retirement's.
    #[test]
    fn a_consumers_acceptance_is_never_a_record_however_its_shard_ends() {
        let schedule = peer_terminating_schedule(60_000);
        let anchor = WeightedTimestamp::from_millis(30_000);
        let cut = WeightedTimestamp::from_millis(60_000);
        let after = WeightedTimestamp::from_millis(61_000);
        let heard_records = |state: &ExecutionCoordinator| {
            state
                .offers()
                .abandonment_records
                .into_iter()
                .filter(|record| matches!(record.evidence(), CounterpartEvidence::Heard(_)))
                .collect::<Vec<_>>()
        };

        let (transaction, _, _, mut state) = consumer_claim_fixture(0x7E);
        let tx_hash = transaction.hash();
        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            TickId::new(PEER, BlockHeight::new(5)),
            anchor,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        state.handle_attestation(&schedule, &certificate);
        assert!(
            state
                .counterparts
                .mirror
                .heard(tx_hash, PEER, Question::Verdict)
                .is_none(),
            "the acceptance is a cue and reaches no mirror"
        );

        for committed_ts in [anchor, after] {
            state.committed_ts = committed_ts;
            assert!(
                heard_records(&state).is_empty(),
                "nothing is offered on the certificate, at {committed_ts:?}"
            );
        }
        // Even the settled set naming it changes nothing: what the
        // record would carry is a reading of the consumer's state, and
        // no probe has answered.
        state.record_settled_txs(
            &schedule,
            PEER,
            SettledTxSet {
                txs: std::iter::once(tx_hash).collect(),
                terminal_wt: cut,
            },
        );
        assert!(
            heard_records(&state).is_empty(),
            "a settled set is not a reading of the claim cell either"
        );
    }

    /// A delivery is abandoned at its window's close out of any tick
    /// still holding it: past the close its issuer may prove the claim
    /// absent and take the crossing back, so the tick that would write
    /// the claim is discarded, its finalization with it.
    #[test]
    fn a_delivery_held_by_a_tick_is_abandoned_at_the_close() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let validity_end = tx.validity_range().end_timestamp_exclusive;
        let close_ms = Window::Delivery
            .of(Deadline::of(validity_end))
            .end
            .as_millis();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state.counterparts.ledger.seed(tx_hash, Part::delivery());
        state.counterparts.ledger.certify(tx_hash);
        let held_by = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        assert_eq!(state.ticks.tick_assignment(tx_hash), Some(held_by));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, close_ms - 1);
        assert!(
            outcomes.is_empty(),
            "inside the window the tick is left to it"
        );
        assert!(state.ticks.contains_tick(&held_by));

        let outcomes = abandonment_vote(&mut state, &schedule, 3, close_ms);
        assert!(
            outcomes
                .iter()
                .any(|outcome| outcome.tx_hash() == tx_hash && outcome.decides()),
            "at the close the delivery is abandoned: {outcomes:?}"
        );
        assert!(
            !state.ticks.contains_tick(&held_by),
            "and the tick that held it is discarded"
        );
    }

    /// Before its deadline a transaction is merely slow, and nothing
    /// abandons it — that is what stops a proposer discarding work.
    #[test]
    fn a_transaction_before_its_deadline_is_not_abandoned() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state
            .ticks
            .remove_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(1)));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms - 1);
        assert!(
            outcomes.is_empty(),
            "a transaction short of its deadline is not abandoned"
        );
        assert_eq!(state.counterparts.ledger.len(), 1, "and stays owed");
    }

    /// A tick that has not yet spoken withholds the abort — it is about
    /// to attest the transaction itself, and that verdict can carry a
    /// charge an abandonment cannot.
    ///
    /// The window is ordinary rather than pathological: a payer's leg
    /// joins a tick at its engagement deadline, which *is* its
    /// abandonment deadline, and the commits between that tick's
    /// composition and its certificate would otherwise abandon the member
    /// it is about to speak for — discarding the tick that carries the
    /// charge. `abort_charges_the_price_on_deadline` is the scenario.
    #[test]
    fn a_tick_that_has_not_attested_withholds_the_abort() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state.committed_ts = WeightedTimestamp::from_millis(deadline_ms);

        assert!(
            state
                .abandonable(TickId::new(ShardId::ROOT, BlockHeight::new(1)))
                .is_empty(),
            "a tick still to vote is an outcome on its way",
        );
        let _ = tx_hash;
    }

    /// A tick holding a member whose success decides alone is not left to
    /// past the transaction's deadline.
    ///
    /// Past it no block carries such a finalization — the deadline fence
    /// refuses it, which is what licenses a leg's reclaim — so a tick
    /// left to would hold a member nothing can resolve while every
    /// proposer offers a finalization every voter refuses.
    #[test]
    fn a_tick_holding_a_success_that_decides_alone_is_abandoned_at_the_deadline() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        let held_by = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        assert_eq!(state.ticks.tick_assignment(tx_hash), Some(held_by));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms - 1);
        assert!(
            outcomes.is_empty(),
            "short of the deadline its own certificate is still on its way"
        );
        assert!(state.ticks.contains_tick(&held_by));

        let outcomes = abandonment_vote(&mut state, &schedule, 3, deadline_ms);
        assert!(
            outcomes
                .iter()
                .any(|outcome| outcome.tx_hash() == tx_hash && outcome.is_aborted()),
            "at the deadline the member is abandoned: {outcomes:?}"
        );
        assert!(
            !state.ticks.contains_tick(&held_by),
            "and the tick that could no longer speak for it is discarded"
        );
    }

    /// A snapshot over an explicit leaf set, with `cut` naming the shards
    /// scheduled to terminate at the epochs given.
    fn leaves_snap(leaves: &[ShardId], cut: &[(ShardId, u64)]) -> Arc<TopologySnapshot> {
        leaves_snap_departed(leaves, cut, &[])
    }

    /// [`leaves_snap`] carrying a terminal boundary record per departed
    /// shard, as every projected snapshot does while the beacon retains
    /// the record — which is exactly as long as the fence may still read
    /// the evidence. `handoff_complete: None` is an open window.
    fn leaves_snap_departed(
        leaves: &[ShardId],
        cut: &[(ShardId, u64)],
        departed: &[(ShardId, Option<Epoch>)],
    ) -> Arc<TopologySnapshot> {
        let boundaries: HashMap<ShardId, ShardAnchor> = departed
            .iter()
            .map(|(shard, handoff_complete)| {
                (
                    *shard,
                    ShardAnchor {
                        state_root: StateRoot::ZERO,
                        block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                        height: BlockHeight::new(9),
                        weighted_timestamp: WeightedTimestamp::from_millis(1_000),
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_roots: None,
                        handoff_complete: *handoff_complete,
                    },
                )
            })
            .collect();
        Arc::new(
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                boundaries,
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            )
            .with_scheduled_terminals(cut.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
    }

    /// This shard, and the peer holding the other half of a straddler.
    const HOME: ShardId = ShardId::leaf(1, 0);
    const PEER: ShardId = ShardId::leaf(1, 1);

    /// Two peers holding a quarter of the keyspace each, neither an
    /// ancestor of the other — the shape in which two departures can
    /// both be party to one transaction.
    const UPPER: ShardId = ShardId::leaf(2, 2);
    const LOWER: ShardId = ShardId::leaf(2, 3);

    /// The two leaves a core of two shards spans, [`PEER`]'s children.
    /// A leg names the lower for the committed cell.
    const CORE: ShardId = ShardId::leaf(2, 2);
    const CORE_SIBLING: ShardId = ShardId::leaf(2, 3);

    /// A shape frozen divided with an inbound leg on `HOME` feeding a
    /// core on `PEER`.
    fn leg_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([PEER]));
        classified
    }

    /// A shape frozen divided under [`two_shard_core_topology`] with an
    /// inbound leg on [`HOME`] feeding a core spanning [`CORE`] and
    /// [`CORE_SIBLING`], so a claim absent on either says only that the
    /// other is pending.
    fn two_shard_core_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[(0, 0)]),
            leg(3, LegRole::Core, &[(1, 0)]),
        ];
        let trie = ShardTrie::from_leaves([HOME, CORE, CORE_SIBLING]);
        let classified = Classified::freeze(&legs, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([CORE, CORE_SIBLING]));
        assert!(classified.decomposed());
        classified
    }

    /// A shape frozen divided with its core on a leaf no held header
    /// names, so only the leg's deliveries are ever probed.
    fn delivery_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(3, LegRole::Core, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, &[], &ShardTrie::uniform(2));
        assert_eq!(classified.core(), &BTreeSet::from([ShardId::leaf(2, 3)]));
        classified
    }

    /// [`HOME`] beside [`CORE`] and [`CORE_SIBLING`], all live: the
    /// topology a leg on `HOME` probes a two-shard core under.
    fn two_shard_core_topology() -> TopologySchedule {
        TopologySchedule::single(leaves_snap(&[HOME, CORE, CORE_SIBLING], &[]))
    }

    /// [`HOME`] and [`PEER`] both live, both crewed — the topology a
    /// straddler between them composes and votes under.
    fn two_shard_topology() -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        )))
    }

    /// A schedule in which [`PEER`] splits at the end of epoch 0 while
    /// [`HOME`] runs on, so the peer is past-terminal anywhere in epoch 1
    /// and its keyspace passes to its two children.
    ///
    /// A counterpart is a peer rather than an ancestor: a shard's own
    /// predecessor never held a transaction the shard committed, so a
    /// fixture that used one would be asking about a settlement that
    /// could not have happened.
    fn peer_terminating_schedule(epoch_duration_ms: u64) -> TopologySchedule {
        peer_terminating_schedule_stamped(epoch_duration_ms, None)
    }

    /// [`peer_terminating_schedule`] with the peer's handoff-complete
    /// stamp under the caller's control: `None` holds the evidence window
    /// open, `Some(epoch)` closes it `TERMINAL_EVIDENCE_EPOCHS` past that
    /// epoch's window.
    fn peer_terminating_schedule_stamped(
        epoch_duration_ms: u64,
        handoff_complete: Option<Epoch>,
    ) -> TopologySchedule {
        let (left, right) = PEER.children();
        let mut sched = TopologySchedule::new(
            epoch_duration_ms,
            Epoch::new(0),
            leaves_snap(&[HOME, PEER], &[(PEER, 0)]),
        );
        let post = leaves_snap_departed(&[HOME, left, right], &[], &[(PEER, handoff_complete)]);
        for epoch in 1..=12u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched.set_head(post);
        sched
    }

    /// The weighted timestamp at which a transaction admitted under
    /// [`state_stranded_on`] can no longer finalize anywhere.
    const STRANDED_DEADLINE_MS: u64 = 60_000 + MAX_FINALIZATION_DELAY.as_secs() * 1000;

    /// A transaction paid for on the `0b0…` side of the keyspace and
    /// writing to the `0b1…` side, so it reaches beyond a shard holding
    /// the first however the trie is cut.
    fn straddling_transaction(seed: u8) -> Transaction {
        test_transaction_with_prefixes(
            &[seed & 0x7F],
            &[test_prefix(seed & 0x7F)],
            &[test_prefix(seed | 0x80)],
        )
    }

    /// A state past `tx`'s deadline whose tick at height 1 holds it with
    /// this shard's own certificate in hand and no counterpart coverage —
    /// the shape a counterpart's silence produces. The transaction
    /// straddles, so `partner` owns the half of it this shard does not.
    /// Commit the record naming `tx_hash` as what the departed peer left
    /// unsettled — the evidence composition requires before it will spend
    /// a tick on an abort.
    fn record_peer_left_unsettled(state: &mut ExecutionCoordinator, tx_hash: TxHash) {
        state
            .counterparts
            .ledger
            .record_abandonment_records(&[AbandonmentRecord::departed(
                PEER,
                WeightedTimestamp::from_millis(60_000),
                vec![UnsettledTx {
                    tx_hash,
                    deadline: Deadline::of(WeightedTimestamp::from_millis(30_000)),
                    declared_work: 1,
                    charge: AbortCharge {
                        vault: SubstateKey {
                            owner: Address::new([9; 31], AddressClass::Component),
                            local: LocalKey([9; 16]),
                        },
                        amount: 5,
                    },
                    reach: Vec::new(),
                }],
            )]);
    }

    fn state_stranded_on(
        topology_schedule: &TopologySchedule,
        seed: u8,
    ) -> (ExecutionCoordinator, TickId, TxHash) {
        let (local, partner) = (HOME, PEER);
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        let tick_id = TickId::new(local, BlockHeight::new(1));
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(seed)),
        ));
        let tx_hash = transaction.hash();
        let mut tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            vec![(
                Arc::new(Verified::new_unchecked_for_test(straddling_transaction(
                    seed,
                ))),
                [local, partner].into_iter().collect(),
            )],
        );
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
                vec![TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(tx_hash, tick_id);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.certify(tx_hash);
        state.committed_ts = WeightedTimestamp::from_millis(STRANDED_DEADLINE_MS);
        state
            .counterparts
            .stamp_departures(topology_schedule, state.committed_ts);
        (state, tick_id, tx_hash)
    }

    /// A schedule in which two sibling peers leave at different cuts
    /// while [`HOME`] runs on: [`UPPER`] at the end of epoch 0 and
    /// [`LOWER`] at the end of epoch 1, each splitting into its own
    /// children.
    ///
    /// Neither is an ancestor of the other, so a transaction reaching a
    /// prefix of each is party to both departures — where a shard and
    /// its descendant would leave only the first party to it.
    fn siblings_terminating_schedule(epoch_duration_ms: u64) -> TopologySchedule {
        let (upper_left, upper_right) = UPPER.children();
        let (lower_left, lower_right) = LOWER.children();
        let mut sched = TopologySchedule::new(
            epoch_duration_ms,
            Epoch::new(0),
            leaves_snap(&[HOME, UPPER, LOWER], &[(UPPER, 0)]),
        );
        sched.insert(
            Epoch::new(1),
            leaves_snap_departed(
                &[HOME, upper_left, upper_right, LOWER],
                &[(LOWER, 1)],
                &[(UPPER, None)],
            ),
        );
        let post = leaves_snap_departed(
            &[HOME, upper_left, upper_right, lower_left, lower_right],
            &[],
            &[(UPPER, None), (LOWER, None)],
        );
        for epoch in 2..=12u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched.set_head(post);
        sched
    }

    /// A transaction paid for on [`HOME`] and writing to a prefix of
    /// [`UPPER`] and one of [`LOWER`].
    fn two_sided_transaction(seed: u8) -> Transaction {
        test_transaction_with_prefixes(
            &[seed & 0x7F],
            &[test_prefix(seed & 0x7F)],
            &[test_prefix((seed & 0x3F) | 0x80), test_prefix(seed | 0xC0)],
        )
    }

    /// [`state_stranded_on`] for a transaction both sibling peers hold a
    /// side of, at a frontier past both their cuts.
    fn state_stranded_between(
        topology_schedule: &TopologySchedule,
        seed: u8,
    ) -> (ExecutionCoordinator, TickId, TxHash) {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(two_sided_transaction(seed)),
        ));
        let tx_hash = transaction.hash();
        let mut tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            vec![(
                Arc::new(Verified::new_unchecked_for_test(two_sided_transaction(
                    seed,
                ))),
                [HOME, UPPER, LOWER].into_iter().collect(),
            )],
        );
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
                vec![TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(tx_hash, tick_id);
        state
            .counterparts
            .ledger
            .register_committed([(&transaction, &Classified::whole())]);
        state.counterparts.ledger.certify(tx_hash);
        state.committed_ts = WeightedTimestamp::from_millis(200_000);
        state
            .counterparts
            .stamp_departures(topology_schedule, state.committed_ts);
        (state, tick_id, tx_hash)
    }

    /// While the counterpart is live the member stays with the tick that
    /// holds it. The counterpart's certificate is still to come, so the
    /// tick can yet speak for the member and a second verdict would
    /// contradict the one it is about to carry.
    #[test]
    fn a_stranded_tick_keeps_its_member_while_its_counterpart_lives() {
        // Windows wide enough that the frontier the fixture sits at is
        // still inside the peer's own epoch.
        let sched = peer_terminating_schedule(600_000);
        let (state, tick_id, _) = state_stranded_on(&sched, 1);

        assert!(
            state
                .abandonable(TickId::new(HOME, BlockHeight::new(9)))
                .is_empty(),
            "a live counterpart can still deliver the verdict this tick waits on",
        );
        assert!(
            state.ticks.contains_tick(&tick_id),
            "so the tick survives its own deadline",
        );
    }

    /// The whole round trip in one place: a counterpart leaves without
    /// settling, its set says so, this shard writes that down, and the
    /// record is what lets the abort be composed afterwards.
    #[test]
    fn silence_from_a_departed_counterpart_is_written_down_and_licenses_the_abort() {
        let sched = peer_terminating_schedule(60_000);
        let (mut state, _, tx_hash) = state_stranded_on(&sched, 1);

        // The peer's settled set arrives, naming nothing: it settled none
        // of what it was party to before it went.
        state.record_settled_txs(
            &sched,
            PEER,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(60_000),
            },
        );

        let records = state.offers().abandonment_records;
        assert_eq!(records.len(), 1, "the peer's departure is answerable");
        assert_eq!(records[0].shard(), PEER);
        assert_eq!(
            records[0].tx_hashes().collect::<Vec<_>>(),
            vec![tx_hash],
            "the straddler is what it left unresolved of our business",
        );

        // Committed, the record is what the account reads afterwards.
        state
            .counterparts
            .ledger
            .record_abandonment_records(&records);
        assert!(state.counterparts.ledger.is_unsettled_by_departed(tx_hash));

        // And what it does not offer twice.
        assert!(
            state.offers().abandonment_records.is_empty(),
            "a departure is answered once",
        );

        assert_eq!(
            state
                .abandonable(TickId::new(HOME, BlockHeight::new(9)))
                .iter()
                .map(|entry| entry.tx_hash)
                .collect::<Vec<_>>(),
            vec![tx_hash],
            "and the record is what makes the abort this shard's to compose",
        );
    }

    /// Once the abort is composed the member is that tick's, and a later
    /// commit leaves it there.
    ///
    /// The record covering the entry never expires, so the entry is owed
    /// at every commit that follows. A shard that read the record as a
    /// licence each time would discard the tick carrying the abort and
    /// compose an identical one, every block, and the abort would never
    /// reach a certificate.
    #[test]
    fn the_tick_that_abandons_a_member_keeps_it() {
        let sched = peer_terminating_schedule(60_000);
        let (mut state, stranded, tx_hash) = state_stranded_on(&sched, 1);
        record_peer_left_unsettled(&mut state, tx_hash);

        let composed = TickId::new(HOME, BlockHeight::new(9));
        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(9),
            STRANDED_DEADLINE_MS,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(&sched, &test_certify(block, STRANDED_DEADLINE_MS));
        assert_eq!(
            state.ticks.tick_assignment(tx_hash),
            Some(composed),
            "the commit past the deadline composes the abort",
        );
        assert!(!state.ticks.contains_tick(&stranded));

        let later = STRANDED_DEADLINE_MS + 1_000;
        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(10),
            later,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(&sched, &test_certify(block, later));
        assert!(
            state.ticks.contains_tick(&composed),
            "the tick carrying the abort survives to be certified",
        );
        assert_eq!(
            state.ticks.tick_assignment(tx_hash),
            Some(composed),
            "and the member stays where it was abandoned",
        );
    }

    /// One transaction can be named by two records, which is why the
    /// budget the composer spends is the block's and not each record's: a
    /// straddler reaching a departed shard reaches its departed successor
    /// too, so the records name more between them than the drain holds,
    /// and a block over that bound is one every voter refuses.
    ///
    /// Also pins the order: ascending by shard is the one form a block may
    /// carry them in, and `settled_sets` is a hash map, so the walk cannot
    /// take its iteration order.
    #[test]
    fn two_departures_over_one_transaction_share_one_block_budget() {
        let sched = siblings_terminating_schedule(60_000);
        let (mut state, _, tx_hash) = state_stranded_between(&sched, 1);

        // Each peer held one of the transaction's two remote prefixes
        // when it committed, so each is the shard a record over that
        // prefix may name.
        let set = |cut_ms: u64| SettledTxSet {
            txs: BTreeSet::new(),
            terminal_wt: WeightedTimestamp::from_millis(cut_ms),
        };
        state.record_settled_txs(&sched, LOWER, set(120_000));
        state.record_settled_txs(&sched, UPPER, set(60_000));

        let records = state.offers().abandonment_records;
        assert_eq!(
            records
                .iter()
                .map(AbandonmentRecord::shard)
                .collect::<Vec<_>>(),
            vec![UPPER, LOWER],
            "ascending by shard, whatever order the sets are held in",
        );
        let named: usize = records.iter().map(|r| r.unsettled().len()).sum();
        assert_eq!(
            named, 2,
            "one outstanding transaction, named twice — the sum is not the drain's count",
        );
        assert!(
            named <= MAX_UNSETTLED_PER_BLOCK,
            "and inside the block's own bound"
        );
        for record in &records {
            assert_eq!(record.tx_hashes().collect::<Vec<_>>(), vec![tx_hash]);
        }
    }

    /// The bit test a shard and its descendant both pass says only that
    /// the keyspace passed on, so a successor that leaves later is not
    /// party to what its predecessor was. A record naming the second cut
    /// would abandon what the first departure had already settled.
    #[test]
    fn a_departed_shards_successor_is_offered_no_record_of_its_business() {
        let sched = peer_terminating_schedule(60_000);
        let (mut state, _, tx_hash) = state_stranded_on(&sched, 1);
        let (peer_left, _) = PEER.children();

        let set = |cut_ms: u64| SettledTxSet {
            txs: BTreeSet::new(),
            terminal_wt: WeightedTimestamp::from_millis(cut_ms),
        };
        state.record_settled_txs(&sched, peer_left, set(120_000));
        state.record_settled_txs(&sched, PEER, set(60_000));

        let records = state.offers().abandonment_records;
        assert_eq!(
            records
                .iter()
                .map(AbandonmentRecord::shard)
                .collect::<Vec<_>>(),
            vec![PEER],
            "only the shard that held the prefix when the transaction committed",
        );
        assert_eq!(records[0].tx_hashes().collect::<Vec<_>>(), vec![tx_hash]);
    }

    /// The certificate outlives the tick that produced it, so losing the
    /// tick does not make the member this shard's to abandon: the
    /// counterpart holds a certificate of ours it can still settle
    /// against, and the account is what remembers that.
    #[test]
    fn a_lost_tick_does_not_release_a_member_a_counterpart_can_settle() {
        let sched = peer_terminating_schedule(600_000);
        let (mut state, tick_id, _) = state_stranded_on(&sched, 1);

        state.ticks.remove_tick(&tick_id);
        state.ticks.discard_tick(&tick_id);

        assert!(
            state
                .abandonable(TickId::new(HOME, BlockHeight::new(9)))
                .is_empty(),
            "the certificate is out there whether or not the tick still is",
        );
    }

    /// A discarded tick's certificate leaves the serving cache with it.
    ///
    /// No finalization of this shard's will ever commit it, so it never
    /// reaches storage and nothing else drops it — and a counterpart
    /// asking by transaction is answered with a verdict this shard has
    /// retracted, beside the abort that replaced it.
    #[test]
    fn a_discarded_ticks_certificate_stops_being_served() {
        let sched = peer_terminating_schedule(600_000);
        let (mut state, tick_id, tx_hash) = state_stranded_on(&sched, 1);
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(
                ExecutionCertificate::new(
                    tick_id,
                    WeightedTimestamp::ZERO,
                    GlobalReceiptRoot::ZERO,
                    vec![TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)],
                    AggregateSignature::ZERO,
                    quorum_signers(),
                ),
            )));

        state.discard_tick(tick_id);

        assert!(
            state.exec_certs.get(&tick_id).is_none(),
            "the tick's own entry goes with it",
        );
        assert!(
            state.exec_certs.certificates_for_tx(tx_hash).is_empty(),
            "and so does the index a counterpart asks by",
        );
    }

    /// A counterpart's departure is not by itself what releases the
    /// member. A shard can settle its half and then leave, so its going
    /// says nothing about whether the transaction is still reachable —
    /// and spending the tick on the departure alone would discard the one
    /// settlement that had already closed. Only a committed record
    /// licenses the abort; until one lands the tick keeps speaking.
    #[test]
    fn a_departure_alone_does_not_release_the_member_its_tick_strands() {
        // Windows placed so the frontier the fixture sits at is past the
        // peer's cut.
        let sched = peer_terminating_schedule(60_000);
        let (state, _, _) = state_stranded_on(&sched, 1);

        assert!(
            state
                .abandonable(TickId::new(HOME, BlockHeight::new(9)))
                .is_empty(),
            "the peer may have settled before it went, and nothing committed says otherwise",
        );
    }

    /// The tick composing now keeps the member it just took, whatever the
    /// counterpart's fate. It is about to attest the transaction itself,
    /// and that verdict can carry a charge an abandonment cannot — a
    /// payer's leg joins a tick at its engagement deadline, which *is* its
    /// abandonment deadline. `abort_charges_the_price_on_deadline` is the
    /// scenario.
    #[test]
    fn the_tick_composing_now_keeps_the_member_it_just_took() {
        let sched = peer_terminating_schedule(60_000);
        let (state, tick_id, _) = state_stranded_on(&sched, 1);

        assert!(
            state.abandonable(tick_id).is_empty(),
            "the tick composing now is the one that speaks for its own member",
        );
    }

    /// A tick that stranded a member is discarded when that member is
    /// abandoned, and the transactions it held alongside are released to
    /// their own deadlines rather than waiting on coverage that will never
    /// close.
    #[test]
    fn the_tick_that_stranded_a_member_is_discarded_with_it() {
        let local = HOME;
        let sched = peer_terminating_schedule(60_000);
        let (mut state, tick_id, tx_hash) = state_stranded_on(&sched, 1);
        record_peer_left_unsettled(&mut state, tx_hash);

        // A second member of the same tick, reaching only into keyspace
        // nobody has left — so its own counterpart is still live.
        let sibling: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(test_transaction(2)),
        ));
        let sibling_hash = sibling.hash();
        state.ticks.assign_tx(sibling_hash, tick_id);
        state
            .counterparts
            .ledger
            .register_committed([(&sibling, &Classified::whole())]);
        state.counterparts.ledger.certify(sibling_hash);

        // The commit that composes the abandonment, on the shard that
        // stranded the member.
        let block = make_live_block_on_shard(
            local,
            BlockHeight::new(9),
            STRANDED_DEADLINE_MS,
            ValidatorId::new(0),
            vec![],
        );
        state.on_block_committed(&sched, &test_certify(block, STRANDED_DEADLINE_MS));

        let composed = TickId::new(local, BlockHeight::new(9));
        assert_eq!(
            state.ticks.tick_assignment(tx_hash),
            Some(composed),
            "the abandonment is composed into this commit's tick",
        );
        assert!(
            !state.ticks.contains_tick(&tick_id),
            "the tick that can never speak for the abandoned member goes with it",
        );
        assert_eq!(
            state.ticks.tick_assignment(sibling_hash),
            None,
            "and its other members are released to their own deadlines",
        );
    }

    /// A discarded tick tells the chain its legs reach no verdict, so
    /// what they hold against the cells they declared is let go of.
    ///
    /// The hold is what every later tick's reader takes as value already
    /// spoken for, and only a fate releases it. A discarded tick reaches
    /// none — so without this the payer's cells stay locked on every
    /// replica that ran the tick, while one that rebuilt the chain
    /// without the hold judges the same reservation feasible.
    #[test]
    fn a_discarded_ticks_legs_release_what_they_held() {
        let local = HOME;
        let sched = peer_terminating_schedule(60_000);
        let (mut state, tick_id, tx_hash) = state_stranded_on(&sched, 1);
        record_peer_left_unsettled(&mut state, tx_hash);
        // The tick ran the member as a leg, so the chain holds its
        // declared reservation until the tick's fate says which side of
        // it survives.
        state.ticked.insert(
            tick_id,
            TickedBatch {
                provisional_claims: Vec::new(),
                legs: BTreeSet::from([tx_hash]),
            },
        );
        state.last_completed_tick = tick_id.block_height();

        let block = make_live_block_on_shard(
            local,
            BlockHeight::new(9),
            STRANDED_DEADLINE_MS,
            ValidatorId::new(0),
            vec![],
        );
        let actions = state.on_block_committed(&sched, &test_certify(block, STRANDED_DEADLINE_MS));

        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::ResolveTicks { resolutions } if resolutions.iter().any(
                    |(id, resolution)| *id == tick_id
                        && matches!(
                            resolution,
                            TickResolution::Abandoned { members } if members.contains(&tx_hash)
                        )
                )
            )),
            "the chain is told the discarded tick's leg never settles",
        );
        assert!(
            !state.ticked.contains_key(&tick_id),
            "and the claim table lets it go with them",
        );
    }

    /// A finalization whose only certificate is this shard's, attesting
    /// `tx_hash` aborted after awaiting `partner` — the shape composition
    /// produces past a deadline.
    fn abandonment_of(local: ShardId, partner: ShardId, tx_hash: TxHash) -> Finalization {
        lone_finalization(
            local,
            TxOutcome::new(tx_hash, ExecutionOutcome::Aborted).awaiting([partner]),
        )
    }

    /// A finalization whose only certificate is this shard's, attesting
    /// `tx_hash` refused by a member that awaited nobody — a leg's own
    /// verdict.
    fn lone_verdict_of(local: ShardId, tx_hash: TxHash) -> Finalization {
        lone_finalization(local, TxOutcome::new(tx_hash, ExecutionOutcome::Failed))
    }

    fn lone_finalization(local: ShardId, outcome: TxOutcome) -> Finalization {
        let tick_id = TickId::new(local, BlockHeight::new(1));
        Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![Arc::new(ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(1),
                GlobalReceiptRoot::ZERO,
                vec![outcome],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ))],
            vec![],
        )
    }

    /// A state whose ledger names `partner` party to `tx_hash`, on the
    /// schedule that has `partner` past-terminal at 1500ms.
    fn state_abandoning(
        topology_schedule: &TopologySchedule,
        local: ShardId,
        transaction: &Arc<Verifiable<Transaction>>,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        state
            .counterparts
            .ledger
            .register_committed([(transaction, &Classified::whole())]);
        state
            .counterparts
            .stamp_departures(topology_schedule, state.committed_ts);
        state
    }

    /// The abort a terminating counterpart might have settled is held at
    /// the fence, not at composition.
    ///
    /// An abandonment carries only this shard's certificate, because an
    /// abort needs no counterpart's verdict — so `settled_set_verdict`,
    /// which skips the local shard, would wave it through. The counterparts
    /// its outcome names as awaited are what let the fence see it, and
    /// while the partner's settled set is unknown it holds: the partner
    /// may already have committed a settlement, and aborting under that is
    /// the one-sided settlement the fence exists to prevent.
    #[test]
    fn the_fence_holds_an_abort_a_terminating_partner_might_have_settled() {
        let (local, partner) = (HOME, PEER);
        let sched = peer_terminating_schedule(1_000);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let abort = abandonment_of(local, partner, tx_hash);
        assert!(
            abort
                .execution_certificates()
                .iter()
                .all(|ec| ec.shard_id() == local),
            "an abandonment carries no counterpart certificate",
        );

        // The abandonment's own outcome is where its counterparts come
        // from: the terminating partner is named, and the gate holds.
        let mut state = state_abandoning(&sched, local, &transaction);
        assert!(
            abort
                .claims(local, |tx_hash| state.counterparts.mirror.covers(tx_hash))
                .iter()
                .any(|(shard, _, claim)| *shard == partner && *claim == TxClaim::Abandoned),
            "an abandonment names the counterparts it awaited",
        );

        let held: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(abort).into());
        assert!(
            state.emit_or_gate_finalized(&sched, held).is_empty(),
            "held while the partner's settled set is unknown",
        );
        assert_eq!(
            state.parked.waiting_on(|w| w == Waiting::Settlement),
            1,
            "held at the gate"
        );
    }

    /// The abort of a transaction the terminated partner never settled is
    /// admitted — the stranded case the deadline path exists for.
    ///
    /// The partner's settled set answers the opposite question from the
    /// one a settlement asks of it: a settlement needs the partner to have
    /// settled its half, an abandonment needs it not to have. Reading the
    /// set the settlement way here would reject the only outcome the
    /// transaction can still reach, and the work it reserved would never
    /// return to the drain.
    #[test]
    fn a_partner_that_never_settled_it_is_what_makes_the_abort_admissible() {
        let (local, partner) = (HOME, PEER);
        let sched = peer_terminating_schedule(1_000);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&sched, local, &transaction);

        state.record_settled_txs(
            &sched,
            partner,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );

        let abort: Arc<Verifiable<Finalization>> = Arc::new(
            Verified::<Finalization>::seal(abandonment_of(local, partner, tx_hash)).into(),
        );
        assert!(
            !state.emit_or_gate_finalized(&sched, abort).is_empty(),
            "the partner terminated without settling it, so the abort is the outcome",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "and nothing is held back"
        );
    }

    /// The abort of a transaction the terminated partner *did* settle is
    /// refused: its half applied, and aborting here would tear the
    /// transaction in two. The settlement path is what resolves it, on the
    /// certificate `record_settled_txs` arms the fetch for.
    #[test]
    fn a_partner_that_settled_it_refuses_the_abort() {
        let (local, partner) = (HOME, PEER);
        let sched = peer_terminating_schedule(1_000);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&sched, local, &transaction);

        state.record_settled_txs(
            &sched,
            partner,
            SettledTxSet {
                txs: BTreeSet::from([tx_hash]),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );

        let abort: Arc<Verifiable<Finalization>> = Arc::new(
            Verified::<Finalization>::seal(abandonment_of(local, partner, tx_hash)).into(),
        );
        assert!(
            state.emit_or_gate_finalized(&sched, abort).is_empty(),
            "the partner settled its half, so this shard may not abort",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "and it is refused rather than held: the set already answered",
        );
    }

    /// A verdict that awaited nobody is not fenced on a counterpart's set.
    ///
    /// A leg's finalization carries only this shard's certificate, as an
    /// abandonment does, but its member awaited nobody: the verdict is
    /// this shard's own, and the core it issued to settles its half on
    /// the record cell rather than on this certificate. Reading it as an
    /// abandonment claim would refuse the leg once the core's settled set
    /// named the transaction — its debit released to the deadline path
    /// after the core had already claimed the crossing.
    #[test]
    fn a_verdict_that_awaited_nobody_is_not_fenced_on_its_counterpart() {
        let (local, partner) = (HOME, PEER);
        let sched = peer_terminating_schedule(1_000);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&sched, local, &transaction);
        state.record_settled_txs(
            &sched,
            partner,
            SettledTxSet {
                txs: BTreeSet::from([tx_hash]),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );

        let verdict = lone_verdict_of(local, tx_hash);
        assert!(
            verdict
                .claims(local, |tx_hash| state.counterparts.mirror.covers(tx_hash))
                .is_empty(),
            "a member that awaited nobody names no counterpart",
        );
        let verdict: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(verdict).into());
        assert!(
            !state.emit_or_gate_finalized(&sched, verdict).is_empty(),
            "the partner settled its half on the record; this shard's verdict is its own",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "and nothing is held back"
        );
    }

    /// An abort naming a partner whose settled set can never be read is
    /// refused. The set is what says whether the partner settled, and
    /// opposite questions of it are still questions of it — so a set
    /// nobody can acquire leaves the abort unproven, exactly as it leaves
    /// a settlement unreachable.
    ///
    /// Refusing costs nothing a readable set would have given: a
    /// transaction's deadline falls well inside its partner's evidence
    /// window, so an abort composed at the deadline reads a set that is
    /// still there. Only a late one arrives here.
    #[test]
    fn a_partner_past_its_evidence_window_refuses_the_abort() {
        let (mut state, sched, tx_hash) = state_past_its_partners_window();
        let abort: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(abandonment_of(HOME, PEER, tx_hash)).into());
        assert!(
            state.emit_or_gate_finalized(&sched, abort).is_empty(),
            "past the window the set cannot establish that the partner did not settle",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "and it is refused rather than held: no later set will answer",
        );
    }

    /// A half the gate refuses releases what its legs held as well as the
    /// assignments it named.
    ///
    /// The half will never be produced, so its legs reach no verdict and
    /// the reservations standing for them on the chain are held against
    /// every later tick for nothing.
    #[test]
    fn a_refused_half_releases_what_its_legs_held() {
        let (mut state, sched, tx_hash) = state_past_its_partners_window();
        let abort: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(abandonment_of(HOME, PEER, tx_hash)).into());
        let tick_id = *abort.tick_id();
        state.ticked.insert(
            tick_id,
            TickedBatch {
                provisional_claims: Vec::new(),
                legs: BTreeSet::from([tx_hash]),
            },
        );
        state.last_completed_tick = tick_id.block_height();

        let actions = state.emit_or_gate_finalized(&sched, abort);
        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::ResolveTicks { resolutions } if resolutions.iter().any(
                    |(id, resolution)| *id == tick_id
                        && matches!(
                            resolution,
                            TickResolution::Abandoned { members } if members.contains(&tx_hash)
                        )
                )
            )),
            "the chain is told the refused half's leg never settles",
        );
        assert!(
            !state.ticked.contains_key(&tick_id),
            "and the claim table lets it go with them",
        );
    }

    /// A shard abandoning a straddler whose partner's settled set has
    /// stopped answering: the handoff completed long enough ago that the
    /// expiry — the stamp's window end plus the evidence window — sits
    /// below the committed frontier.
    fn state_past_its_partners_window() -> (ExecutionCoordinator, TopologySchedule, TxHash) {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&peer_terminating_schedule(1_000), HOME, &transaction);

        let sched = peer_terminating_schedule_stamped(1_000, Some(Epoch::new(0)));
        state.record_settled_txs(
            &sched,
            PEER,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::ZERO,
            },
        );
        state.committed_ts = WeightedTimestamp::from_millis(6_001);
        (state, sched, tx_hash)
    }

    /// A departure the ledger recorded before its window went is
    /// stamped off the head's boundary record when the handoff completes,
    /// though no retained window lists it any more — and the entry a
    /// record covers against it then retires on that clock rather than
    /// holding the departure open for good.
    #[test]
    fn a_departure_no_window_carries_is_stamped_off_the_head() {
        let (left, right) = PEER.children();
        let stamped = TopologySchedule::single(leaves_snap_departed(
            &[HOME, left, right],
            &[],
            &[(PEER, Some(Epoch::new(0)))],
        ));
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&stamped, HOME, &transaction);
        state
            .counterparts
            .ledger
            .record_terminal(PEER, WeightedTimestamp::from_millis(1000), None);
        record_peer_left_unsettled(&mut state, tx_hash);
        assert_eq!(state.counterparts.ledger.unstamped_departures(), vec![PEER]);

        state
            .counterparts
            .stamp_departures(&stamped, state.committed_ts);
        assert!(
            state.counterparts.ledger.unstamped_departures().is_empty(),
            "the head's stamp reaches a departure no window lists"
        );
        let expiry = stamped
            .handoff_evidence_expiry(PEER)
            .expect("the head carries the stamp");
        assert!(
            state
                .counterparts
                .ledger
                .prune(expiry.plus(Duration::from_millis(1)))
                .unanswerable
                .iter()
                .any(|entry| entry.tx_hash == tx_hash && entry.covered_by_record),
            "and the covered entry retires past it"
        );

        // With no stamp and no evidence readable at all, the departure
        // closes at the commit that finds it so, as the settled sets do.
        let gone = TopologySchedule::single(leaves_snap(&[HOME, left, right], &[]));
        let mut state = state_abandoning(&gone, HOME, &transaction);
        state
            .counterparts
            .ledger
            .record_terminal(PEER, WeightedTimestamp::from_millis(1000), None);
        record_peer_left_unsettled(&mut state, tx_hash);
        state
            .counterparts
            .stamp_departures(&gone, state.committed_ts);
        assert!(state.counterparts.ledger.unstamped_departures().is_empty());
        assert!(
            state
                .counterparts
                .ledger
                .prune(state.committed_ts.plus(Duration::from_millis(1)))
                .unanswerable
                .iter()
                .any(|entry| entry.tx_hash == tx_hash && entry.covered_by_record),
            "an unreadable departure closes at once"
        );
    }

    /// An abort naming a partner evicted from every retained window is
    /// refused for the same reason: there is no set to read, and the
    /// certificate this shard already produced is enough for the partner
    /// to have settled against.
    #[test]
    fn a_partner_evicted_from_every_window_refuses_the_abort() {
        // The peer's own window is gone; only the successors of its split
        // are carried. The account outlives the window, so the ledger
        // still names the peer as what held the keyspace then.
        let (left, right) = PEER.children();
        let sched = TopologySchedule::single(leaves_snap(&[HOME, left, right], &[]));
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(7)),
        ));
        let tx_hash = transaction.hash();
        let mut state = state_abandoning(&sched, HOME, &transaction);
        state.counterparts.ledger.record_terminal(
            PEER,
            WeightedTimestamp::from_millis(1000),
            Some(WeightedTimestamp::from_millis(1000).plus(EPOCH_DURATION * 5)),
        );

        let abort: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(abandonment_of(HOME, PEER, tx_hash)).into());
        assert!(
            state.emit_or_gate_finalized(&sched, abort).is_empty(),
            "a shard no retained window carries answers neither question",
        );
        assert!(
            state.parked.waiting_on(|w| w == Waiting::Settlement) == 0,
            "and is refused, not held"
        );
    }

    /// A tick already attesting the abandonment withholds the next one:
    /// the ledger releases when that certificate commits, so re-composing
    /// it every commit in between would discard the tick carrying it.
    #[test]
    fn a_tick_already_abandoning_it_withholds_the_next() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.on_block_committed(
            &schedule,
            &test_certify(
                make_live_block(
                    BlockHeight::new(1),
                    1_000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                ),
                1_000,
            ),
        );
        state
            .ticks
            .remove_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(1)));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms);
        assert_eq!(outcomes.len(), 1, "the tick at the deadline abandons it");
        assert!(
            state
                .abandonable(TickId::new(ShardId::ROOT, BlockHeight::new(3)))
                .is_empty(),
            "and the next commit leaves that tick alone",
        );
        assert!(
            state
                .ticks
                .contains_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(2))),
            "so the tick attesting the abort survives to be certified",
        );
        assert_eq!(
            state.counterparts.ledger.len(),
            1,
            "released only when it commits"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // remove_finalization — cascade correctness across all sub-machines.
    // Refactor plan called this out as a key risk: any new sub-machine added
    // to the coordinator must be updated here or its per-tx state leaks.
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_remove_finalization_cascades_across_every_sub_machine() {
        let mut state = make_test_state();
        let (tick_id, tick) = make_ready_local_tick(&[7]);
        let tx_hash = tick.tx_hashes()[0];

        // Seed every sub-machine with state for this tick's tx.
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(tx_hash, tick_id);
        state.provisioning.record_required(
            tx_hash,
            std::iter::once(Requirement::CommittedState(ShardId::leaf(1, 1))).collect(),
        );
        // Drive finalize to populate the FinalizationStore naturally.
        let _ = state.finalize(&make_test_topology(), &tick_id);
        let finalized = state
            .finalized
            .get_for_tx(tx_hash)
            .expect("tick must be in the finalized store after finalize");

        // Sanity: state is populated across sub-machines.
        let before = state.memory_stats();
        assert_eq!(before.finalizations, 1);
        assert_eq!(before.tick_assignments, 1);
        assert_eq!(before.required_provision_shards, 1);

        state.remove_finalization(&finalized);
        // Provisioning is a candidate's, swept at the next commit.
        state.provisioning.sweep(state.committed_ts, |_| false);

        let after = state.memory_stats();
        assert_eq!(after.finalizations, 0);
        assert_eq!(after.ticks, 0);
        assert_eq!(after.tick_assignments, 0);
        assert_eq!(after.absorbed_provisions, 0);
        assert_eq!(after.required_provision_shards, 0);
    }

    /// An expectation is stamped with the weighted timestamp of the
    /// commit that composed the tick holding it, so the fallback window
    /// is measured from a real clock reading and the first commit after a
    /// restart cannot read as decades overdue.
    #[test]
    fn a_composed_tick_stamps_its_expectations_with_the_commit_clock() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let tx = Arc::new(test_transaction(1));
        let local_tick = TickId::new(ShardId::leaf(1, 0), BlockHeight::new(10));
        let participating = BTreeSet::from([ShardId::leaf(1, 0), remote_shard]);
        state.ticks.insert_tick(
            local_tick,
            tick_holding(
                local_tick,
                WeightedTimestamp::from_millis(0),
                vec![(verified_arc(&tx), participating)],
            ),
        );
        state.expected_certs.register(
            remote_shard,
            tx.hash(),
            WeightedTimestamp::from_millis(30_000),
        );

        let block = make_live_block_on_shard(
            ShardId::leaf(1, 0),
            BlockHeight::new(1),
            30_000,
            ValidatorId::new(0),
            vec![],
        );
        let (block, qc) = certify(block).into_parts();
        let qc = QuorumCertificate::new(
            qc.block_hash(),
            qc.shard_id(),
            qc.height(),
            qc.parent_block_hash(),
            qc.round(),
            qc.signers().clone(),
            qc.aggregated_signature(),
            WeightedTimestamp::from_millis(30_000),
        );
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_block_committed(&topo, &certified);

        let fallback_fired = actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchRequest::ExecutionCerts { .. })));
        assert!(
            !fallback_fired,
            "an expectation stamped at the commit clock is not already overdue at that commit"
        );
    }
}
