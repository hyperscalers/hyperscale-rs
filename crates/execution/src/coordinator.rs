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
//!   verdict; value between them crosses as a record the consumer
//!   claims. An owed crossing's consumer runs no member: its shard's
//!   commit fold credits the record's reading, so a shard that only
//!   takes delivery never includes the transaction.
//! - **Settling.** No member at all: the commit fold takes back a
//!   crossing its consumer refused and retires records whose claims
//!   committed, off readings the block carries.
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
//! A record this shard issued is owed its consumer's answer, and a core
//! member is owed its siblings' certificates. This shard probes a silent
//! counterpart's cells through a state proof. The consumer's `Taken`
//! retires a record in the commit fold, and its `Never` takes the record
//! back there, read at a boundary of the consumer's shard; a sibling's
//! committed cell read absent inside its window licenses the core
//! member's abandonment. The ledger of what is still owed is
//! [`Ledger`](crate::ledger::Ledger); what counterparts
//! were heard to say is the [`CounterpartMirror`], shared with the vote
//! fence so a record passes exactly where its composer would have
//! offered it.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{
    Action, CrossShardExecutionRequest, FetchIds, FetchRequest, ProtocolEvent, TickBatchOutcome,
};
use hyperscale_engine::legs::{Classified, Member, abandoned_never};
use hyperscale_engine::tick_select::{
    ProvisionalCells, Requirement, SeatQuestion, requirements_of,
};
use hyperscale_engine::{
    CodeAvailability, PROTOCOL_RESOURCE, TickEnvironment, build_refusal_receipt,
};
use hyperscale_hbor::Capped;
use hyperscale_metrics::{
    record_batch_unavailable, record_crossing_push_dropped, record_early_vote_refused,
    record_unresolvable_tx,
};
use hyperscale_storage::{FeeTerms, ProvisionalTx, RecoveredState, TickResolution};
use hyperscale_types::network::response::ServedValue;
use hyperscale_types::{
    Anchor, Attempt, Block, BlockHash, BlockHeight, BloomFilter, CarriedClaims, CertifiedBlock,
    CommittedAt, ConsensusPublicKey, CounterpartMirror, DeclaredKey, Derivation, DiscardCause,
    EpochWindows, ExecutionCertificate, ExecutionCertificateVerifyError, ExecutionOutcome,
    ExecutionVote, Finalization, FinalizationHash, FinalizationVerifyError, GlobalReceiptRoot,
    Hash, Joins, MerkleInclusionProof, Mode, Movement, ProvenAnchors, Provisions,
    REATTESTATION_STEP, ScheduleLookup, SettledTxSet, Settlement, ShardId, ShardTrie, StateClaim,
    StateWrites, StoredReceipt, SubstateKey, TickHalf, TickId, TickLine, TopologySchedule,
    TopologySnapshot, Transaction, TransactionDecision, TxHash, TxOutcome, TxResolution,
    UnsettledTx, ValidatorId, VerdictCells, VerdictQuestion, Verifiable, Verified,
    WeightedTimestamp, derive_block_transactions, tick_leader,
};
use tracing::instrument;

use crate::action_handlers::declared_reservations;
use crate::candidates::{Admitted, TickCandidates};
use crate::counterparts::{Counterparts, CrossingIndexSlot, Offers};
use crate::early_arrivals::{EARLY_VOTE_RETENTION, EarlyArrivalBuffer};
use crate::exec_cert_store::ExecCertStore;
use crate::expected_certs::ExpectedCertTracker;
use crate::finalizations::FinalizationStore;
use crate::gate::{Attested, Gate, gate_certificate};
use crate::ledger::{Certified, Ledger, Unanswerable};
use crate::lookups::{
    assign_participants, attesting_committee, build_provision_requests, ec_has_shard_quorum_power,
    fetch_keys_covered, peers_excluding_self, record_pushes,
};
use crate::outbound_certs::OutboundExecutionCertificateTracker;
use crate::parked::{Parked, ParkedArtifacts, Waiting, Wake};
use crate::parked_claims::ParkedClaims;
use crate::provisioning::{ProvisioningTracker, WantedRecord};
use crate::tick_state::{Divergence, Membership, TickState};
use crate::ticks::{PendingVoteRetry, RetryEffect, TickRegistry, VOTE_RETRY_TIMEOUT};
use crate::vote_tracker::VoteTracker;

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
    // A transaction this node could not route takes no part here. Where
    // it runs, what it holds and what this shard owes of it are all read
    // off a derivation only the nodes holding its records reach, and a
    // certified block is committed by every replica alike — including
    // one that has never been where those records are seated. The commit
    // asks for them; nothing is booked on a shape nobody derived.
    let routed: Vec<Arc<Verifiable<Transaction>>> = transactions
        .iter()
        .filter(|tx| tx.as_unverified().is_routed())
        .map(Arc::clone)
        .collect();
    assign_participants(classification, &routed)
        .into_iter()
        .map(|(tx, participating)| {
            let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
            CommittedMember {
                member: Member::of(classified, local_shard, participating),
                tx,
            }
        })
        .collect()
}

/// What each member a finalization's receipts name left, as the receipts
/// state it.
fn receipt_writes(fw: &Finalization) -> Vec<(TxHash, StateWrites)> {
    fw.receipts()
        .iter()
        .filter_map(|receipt| Some((receipt.tx_hash, receipt.consensus.writes()?.clone())))
        .collect()
}

/// What the lines of a held tick's block say of its members: the block's
/// own content, never what this node's ledger let it seat, so every
/// replica holding the tick reads the same set.
struct HeldTick {
    /// The members the lines name `Aborted`: the ones that reach no
    /// engine, whose refusal receipts are built at seating.
    abandoned: BTreeSet<TxHash>,
}

impl HeldTick {
    fn of(lines: &[TickLine]) -> Self {
        let abandoned = lines
            .iter()
            .filter_map(|line| match line {
                TickLine::Member {
                    tx,
                    joins: Joins::Aborted,
                    ..
                } => Some(*tx),
                _ => None,
            })
            .collect();
        Self { abandoned }
    }
}

/// Count a transaction let go of with no outcome, by whether a
/// committed record had covered it.
fn record_unanswerable(covered_by_record: bool) {
    record_unresolvable_tx(if covered_by_record {
        "record_covered"
    } else {
        "no_record"
    });
}

/// The members a commit's tick seats: the manifest's lines, or what
/// this node's own inputs name, with the strands its ledger let go of at
/// this commit.
#[derive(Clone, Copy)]
enum Named<'a> {
    Lines(&'a [TickLine]),
    Composed {
        unanswerable: &'a [Unanswerable],
        recovered: &'a [TickId],
    },
}

/// Where a commit's tick takes its members from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Naming {
    /// The member lines the block's committed manifest names.
    Manifest,
    /// The members this node's own committed inputs name: for a block
    /// whose builder named none, a fixture standing in for a proposer
    /// whose inputs are this node's.
    Composed,
}

/// The committed block a tick is created against: its identity, and the
/// environment anchors the transactions it commits execute under.
#[derive(Clone, Debug)]
struct CommittingBlock {
    hash: BlockHash,
    height: BlockHeight,
    /// The block's parent-QC weighted timestamp.
    ts: WeightedTimestamp,
    /// The fee terms of every transaction it carries: the holds its
    /// commit includes.
    fees: Vec<FeeTerms>,
}

/// A tick with entries on the tick chain and no committed fate yet.
struct TickedBatch {
    /// What each of its abortable members declared it would mutate — the
    /// cells nothing may read until a counterpart's certificate says
    /// which side of each survives.
    ///
    /// Its other members claim nothing: their writes are determined the
    /// moment they execute and readable at once, so a later tick may
    /// fold over them freely. Empty for a tick that ran no member a
    /// counterpart can retract, which is then held only for its own
    /// fate.
    provisional_claims: BTreeMap<TxHash, Vec<(DeclaredKey, Mode)>>,
    /// The legs those claims belong to, each with what it holds by cell
    /// once it completes. A tick's fate arrives by member: its
    /// determined half releases no cell, and each leg's cells go with
    /// the resolution that names it — so the entry has to know which
    /// members those are. Narrows as legs are settled or released, each
    /// letting go of what it held and leaving the rest to their own
    /// resolution.
    legs: BTreeMap<TxHash, BTreeMap<SubstateKey, u128>>,
}

impl TickedBatch {
    /// Whether a leg still unresolved holds cells against the ticks above
    /// it should it complete.
    fn may_reserve(&self) -> bool {
        self.legs.values().any(|reserved| !reserved.is_empty())
    }

    /// Let go of what the legs among `members` hold. Returns whether no
    /// leg is left, which is when the entry has nothing more to release.
    fn resolve(&mut self, members: &BTreeSet<TxHash>) -> bool {
        self.legs.retain(|leg, _| !members.contains(leg));
        self.provisional_claims
            .retain(|leg, _| !members.contains(leg));
        self.legs.is_empty()
    }
}

/// One seated but undispatched tick: the block's identity anchors plus
/// the members that joined at its commit.
#[derive(Clone)]
struct PendingTick {
    tick: BlockHeight,
    tick_ts: WeightedTimestamp,
    env: TickEnvironment,
    requests: Vec<CrossShardExecutionRequest>,
    /// The fee terms of every transaction the tick's block carries. The
    /// block's commit includes a hold for each, and the tick runs over
    /// the base below that block, so they travel with it to the batch
    /// that judges debits under them.
    included: Vec<FeeTerms>,
    /// Whether this node holds everything the tick's lines name: a body
    /// for each member and the bundles each one named to run needs.
    in_hand: bool,
}

/// One seated tick in dispatch order.
enum Queued {
    /// A tick this node runs.
    Run(PendingTick),
    /// A tick this node seated and cannot run: sealed, below the store's
    /// reach, or short a body or a bundle. Every later tick reads a
    /// baseline its readable writes belong in, and is held off what its
    /// completed legs reserve, so none dispatches until its determined
    /// half has settled and every leg that may reserve has resolved, each
    /// seated on the chain in its place from what settled it.
    Held(TickId),
}

impl PendingTick {
    /// The packages this tick's members run that do not resolve on this
    /// node.
    fn missing_code(&self, code: &dyn CodeAvailability) -> Vec<Hash> {
        let missing: BTreeSet<Hash> = self
            .requests
            .iter()
            .map(|request| &request.transaction)
            .flat_map(|body| body.packages().iter().copied())
            .filter(|package| !code.can_run(*package))
            .collect();
        missing.into_iter().collect()
    }
}

/// Data returned when a tick is ready for voting.
///
/// The state machine produces this; the `io_loop` uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this tick belongs to; pairs with `tick_id` to identify the vote target.
    pub(crate) block_hash: BlockHash,
    /// BFT-authenticated weighted timestamp at which this tick's outcome is
    /// fixed. Included in the vote payload and the EC canonical hash, so all
    /// validators aggregate under the same identifier.
    pub(crate) vote_anchor_ts: WeightedTimestamp,
    /// Tick identifier; unique within `block_hash`.
    pub(crate) tick_id: TickId,
    /// Merkle root over per-tx outcome leaves (cross-shard agreement).
    pub(crate) global_receipt_root: GlobalReceiptRoot,
    /// Per-tx outcomes in tick order.
    pub(crate) tx_outcomes: Vec<TxOutcome>,
}

/// What folding committed blocks into execution hands the node: one
/// commit's, or a run's in commit order where a drain or a replay folded
/// several.
#[derive(Debug, Default)]
pub struct CommitEffects {
    /// What each folded block's finalizations settle about the
    /// transactions they name, read off the ledger before the same fold
    /// released the entries.
    pub resolutions: Vec<(TxHash, TxResolution)>,
    /// The folds' actions, in commit order.
    pub actions: Vec<Action>,
    /// Whether a fold here derived the terminal latch: the quiescence
    /// commit, after which no block seats a tick and nothing in flight can
    /// be decided.
    pub terminal: bool,
    /// The member lines each folded block's tick seated, in commit order:
    /// its manifest's, or what this node's own inputs named where the
    /// commit composed.
    pub named: Vec<TickLine>,
}

impl CommitEffects {
    fn absorb(&mut self, later: Self) {
        self.resolutions.extend(later.resolutions);
        self.actions.extend(later.actions);
        self.terminal |= later.terminal;
        self.named.extend(later.named);
    }
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
    /// Votes held for retry until their tick certifies.
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

impl ExecutionMemoryStats {
    /// Every readout as a `(field, value)` pair for the metrics backend.
    ///
    /// The destructure is the drift guard: a field added above does not
    /// compile here until it is given a gauge.
    #[must_use]
    pub fn gauges(&self) -> Vec<(&'static str, usize)> {
        let Self {
            tick_execution_receipts,
            finalizations,
            ticks,
            unresolved_txs,
            vote_trackers,
            early_votes,
            expected_exec_certs,
            absorbed_provisions,
            required_provision_shards,
            ticks_with_ec,
            pending_vote_retries,
            tick_assignments,
            early_attestations,
            pending_routing,
            fulfilled_exec_certs,
            outbound_certs,
            proven_remote_blocks,
            unproven_ecs,
        } = *self;
        vec![
            ("tick_execution_receipts", tick_execution_receipts),
            ("finalizations", finalizations),
            ("ticks", ticks),
            ("unresolved_txs", unresolved_txs),
            ("vote_trackers", vote_trackers),
            ("early_votes", early_votes),
            ("expected_exec_certs", expected_exec_certs),
            ("absorbed_provisions", absorbed_provisions),
            ("required_provision_shards", required_provision_shards),
            ("ticks_with_ec", ticks_with_ec),
            ("pending_vote_retries", pending_vote_retries),
            ("tick_assignments", tick_assignments),
            ("early_attestations", early_attestations),
            ("pending_routing", pending_routing),
            ("fulfilled_exec_certs", fulfilled_exec_certs),
            ("outbound_certs", outbound_certs),
            ("proven_remote_blocks", proven_remote_blocks),
            ("unproven_ecs", unproven_ecs),
        ]
    }
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

    /// The `committed_ts` the cleanup timer last saw, how long it has
    /// stayed there, and how many [`VOTE_RETRY_TIMEOUT`] periods of that
    /// have fired their retries. See [`Self::on_cleanup_tick`].
    stall_seen_ts: WeightedTimestamp,
    stalled_for: Duration,
    stall_retry_periods: u32,

    /// Anchor selecting the committee that governs the last locally committed
    /// block — the anchor its *parent* carried, since a block's committee
    /// keys on its parent. What tick and provision classification resolves
    /// against, so every replica groups a block's transactions exactly as the
    /// proposer built them and the verifier validated them.
    committed_committee_anchor_wt: WeightedTimestamp,

    // ═══════════════════════════════════════════════════════════════════════
    // Tick dispatch
    // ═══════════════════════════════════════════════════════════════════════
    /// Ticks seated at commit but not yet dispatched, in height order.
    /// Ticks execute serially — each output is the next tick's baseline —
    /// so the head dispatches only when no tick is in flight.
    pending_ticks: VecDeque<Queued>,

    /// The seated ticks this node never runs, whose settlements it seats
    /// from their receipts as they commit, each with what its block's
    /// lines say of its members. Kept until the tick leaves the registry,
    /// so both of its halves read the same sets.
    ///
    /// A run appends nothing for a member the lines name `Aborted`, so a
    /// seated settlement leaves it out too: its refusal receipt reaches
    /// every replica's baselines through the base, from the block that
    /// commits it.
    held: BTreeMap<TickId, HeldTick>,

    /// The highest height this replica's settled base is known to carry:
    /// what the loop running this seat found written when it took the
    /// seat, and every `BlockPersisted` it has fed since.
    ///
    /// A tick reads the base as of the height below its own, and a
    /// block's commit writes things into the base that no tick's output
    /// carries, so the head tick dispatches only once that height is at
    /// or below this one. Every replica then reads one baseline for a
    /// tick, however far its own writes trail its commits.
    ///
    /// A mark for when to dispatch, never above what the tick chain
    /// itself records: the chain refuses a baseline past its own.
    persisted: BlockHeight,

    /// Whether a dispatched tick's `ExecutionBatchCompleted` is still
    /// outstanding.
    tick_in_flight: bool,

    /// Whether the committed tip is past this chain's terminal window.
    ///
    /// Derived in every fold from the tip header's parent QC, before
    /// that fold seats, and never cleared. It flips at the quiescence
    /// commit, the first coast block, whose parent QC certifies the
    /// terminal block; the terminal block itself seats as any other.
    /// Seating is the latch's only reader and runs only inside a fold, so
    /// nothing seeds it at construction: a restart, a snap-sync seat and
    /// a reshape adoption each derive it in their first fold. Without it
    /// a tick past the terminal would be seated where nothing can
    /// certify it.
    terminated: bool,

    /// What this node can run, asked where a tick dispatches.
    ///
    /// A queued tick whose members run code this node cannot resolve
    /// waits at the dispatch head. It cannot be consulted where the tick
    /// is seated: membership is what the committee's votes are cast over,
    /// so it is the block's manifest, and a node's holdings are not
    /// committed content. Dispatch is where the difference is local — the
    /// tick still answers for exactly the members it was seated with,
    /// whenever it runs.
    code: Arc<dyn CodeAvailability>,

    /// The group's crossing index slot, held so the host can bind it.
    crossing_index: Arc<CrossingIndexSlot>,

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
    /// no schedule to seat against, so they wait for
    /// [`on_committed_state_restored`](Self::on_committed_state_restored)
    /// and are empty from then on.
    replay_blocks: Vec<Verified<CertifiedBlock>>,
    /// The height of the last block the replay folds; `GENESIS` where
    /// there is none. No tick is dispatched while the committed frontier
    /// sits below it.
    ///
    /// The replay runs ticks whose fates the chain committed long ago,
    /// and a tick's fates travel with its dispatch to be applied as its
    /// output is appended. One dispatched off the commit that seated it
    /// would go out ahead of the later blocks that settle it, and land
    /// an entry the base already carries with nothing to say so.
    replay_through: BlockHeight,
    /// Commits whose anchored committee sits in a window this node's
    /// beacon has not committed yet, each with its committee anchor, in
    /// commit order. Folded as the windows land, and every later commit
    /// queues behind the first, so the fold never runs out of order.
    awaiting_window: VecDeque<(CertifiedBlock, WeightedTimestamp, Naming)>,

    /// The lowest height a tick may be *dispatched* at.
    ///
    /// A tick reads its baseline as of the height below it, and a store
    /// answers a historical read only inside its retention horizon — so a
    /// replay reaching further back than that seats its ticks and runs
    /// none of them. The manifest fixes which tick holds a member, and
    /// every replica of the shard seats it whatever it can still execute;
    /// the baseline is what the store cannot answer for. What such a tick left is seated from the receipts that
    /// committed it instead. `GENESIS` on every path but a replay, where
    /// every height qualifies.
    dispatch_from: BlockHeight,

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
    /// Pushed claims waiting on their anchor's proof.
    parked_claims: ParkedClaims,
    /// The stated members whose rows at the committed tip accept on what
    /// their siblings' state says, as the shard coordinator last handed
    /// them over: the members a legs half may name.
    accepting: BTreeSet<TxHash>,
    /// The records the last live block wrote, by the shard owning each
    /// consumer, kept one commit for the next block's proposer to push
    /// beside the header that proves them.
    pending_push: Option<(BlockHash, Anchor, BTreeMap<ShardId, Vec<SubstateKey>>)>,

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
    pub fn new(me: ValidatorId, local_shard: ShardId, code: Arc<dyn CodeAvailability>) -> Self {
        Self::with_shared_stores(
            me,
            local_shard,
            code,
            Arc::new(CrossingIndexSlot::default()),
            &RecoveredState::default(),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
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
        code: Arc<dyn CodeAvailability>,
        crossing_index: Arc<CrossingIndexSlot>,
        recovered: &RecoveredState,
        exec_certs: Arc<ExecCertStore>,
        finalized: Arc<FinalizationStore>,
        proven_anchors: Arc<ProvenAnchors>,
        mirror: Arc<CounterpartMirror>,
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
            counterparts: Counterparts::new(
                local_shard,
                proven_anchors,
                mirror,
                Arc::clone(&crossing_index) as _,
                recovered.read_frontier.clone(),
            ),
            crossing_index,
            finalized,
            committed_height,
            committed_ts: committed_block_anchor_wt,
            stall_seen_ts: committed_block_anchor_wt,
            stalled_for: Duration::ZERO,
            stall_retry_periods: 0,
            committed_committee_anchor_wt,
            pending_ticks: VecDeque::new(),
            held: BTreeMap::new(),
            code,
            persisted: BlockHeight::GENESIS,
            tick_in_flight: false,
            terminated: false,
            last_completed_tick: BlockHeight::GENESIS,
            ticked: BTreeMap::new(),
            replay_blocks: recovered.replay.blocks.clone(),
            replay_through: recovered
                .replay
                .blocks
                .last()
                .map_or(BlockHeight::GENESIS, |certified| certified.block().height()),
            awaiting_window: VecDeque::new(),
            dispatch_from: recovered.replay.dispatch_from,
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
            parked_claims: ParkedClaims::new(),
            accepting: BTreeSet::new(),
            pending_push: None,
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

    /// The slot this coordinator's crossing questions read from, shared
    /// by the vnode group: the host binds it to the shard's chain once
    /// the chain is open.
    #[must_use]
    pub const fn crossing_index(&self) -> &Arc<CrossingIndexSlot> {
        &self.crossing_index
    }

    /// Reference to the shared execution-certificate store. The `io_loop`
    /// clones this `Arc` into its `SharedCaches` so the inbound EC fetch
    /// handler can read aggregated local-shard certificates without
    /// acquiring a coordinator lock.
    #[must_use]
    pub const fn exec_cert_store(&self) -> &Arc<ExecCertStore> {
        &self.exec_certs
    }

    /// Record that the settled base this seat reads carries `height`,
    /// as the store stood when the seat joined its loop. Nothing is
    /// queued that early, so there is no tick to release.
    pub fn seat_on_persisted_base(&mut self, height: BlockHeight) {
        self.persisted = self.persisted.max(height);
    }

    /// Record that the settled base now carries `height`, and dispatch
    /// the head tick if that is the baseline it was waiting for.
    pub fn on_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
        height: BlockHeight,
    ) -> Vec<Action> {
        self.persisted = self.persisted.max(height);
        self.dispatch_next_tick(topology_schedule)
    }

    /// The lowest height a tick this coordinator has still to run reads
    /// its baseline at — the history this replica's execution needs the
    /// store to keep.
    ///
    /// Ticks run serially in height order, so the next one sits above
    /// the last that completed, and a replay dispatches nothing below
    /// [`dispatch_from`](Self::dispatch_from). A tick reads the height
    /// below its own.
    #[must_use]
    pub fn baseline_floor(&self) -> BlockHeight {
        self.last_completed_tick
            .max(self.dispatch_from.prev().unwrap_or(BlockHeight::GENESIS))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tick Assignment
    // ═══════════════════════════════════════════════════════════════════════════

    /// The committee a committed block's content is classified under: the
    /// one at its `committee_anchor`, its parent's anchor, which is the
    /// snapshot the proposer classified the block against and the verifier
    /// validated it against. The block's own anchor and its committee
    /// anchor straddle an epoch cut once per window, and a reshape cut
    /// there changes the shard set `compute_ticks` routes over.
    ///
    /// `None` while that window is newer than this node's beacon has
    /// committed: the commit waits for it rather than read the head, so
    /// every replica groups a block's transactions identically across a
    /// reshape boundary.
    ///
    /// An evicted committee anchor is reached by the first block of a
    /// chain whose predecessor's anchor lies before its cut, and that
    /// block classifies under its own anchor's window. Where that is
    /// evicted too, no window names this shard at all — a split child
    /// replaying the window it inherited, whose content predates its own
    /// cut — and the head, its only committee, classifies the content the
    /// way the child's own keyspace is cut.
    fn anchored_committee<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        committee_anchor: WeightedTimestamp,
        own_anchor: WeightedTimestamp,
    ) -> Option<&'t TopologySnapshot> {
        let resolve = |wt| match topology_schedule.lookup_for_shard(self.local_shard, wt).0 {
            ScheduleLookup::Committee(snapshot) => Ok(snapshot.as_ref()),
            ScheduleLookup::NotYetCommitted => Err(true),
            ScheduleLookup::Evicted => Err(false),
        };
        match resolve(committee_anchor) {
            Ok(snapshot) => Some(snapshot),
            Err(true) => None,
            Err(false) => match resolve(own_anchor) {
                Ok(snapshot) => Some(snapshot),
                Err(true) => None,
                Err(false) => Some(topology_schedule.head().as_ref()),
            },
        }
    }

    /// The trie that says who was party to a transaction, off the latest
    /// committed block's anchored committee; `None` while that window is
    /// not committed here.
    ///
    /// What a probe of silent counterparts places its questions under. A
    /// window later resolves a departed counterpart's *successor*, a
    /// shard that was never party, so the anchor is the committed
    /// block's and never this node's head.
    fn counterpart_trie<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
    ) -> Option<&'t ShardTrie> {
        self.anchored_committee(
            topology_schedule,
            self.committed_committee_anchor_wt,
            self.committed_ts,
        )
        .map(TopologySnapshot::shard_trie)
    }

    /// Register a new cross-shard tick's transactions: the dependency set
    /// the member runs with once a manifest names it.
    fn register_cross_shard_txs(
        &mut self,
        classification: &TopologySnapshot,
        txs: &[CommittedMember],
    ) {
        let local_shard = self.local_shard;

        for CommittedMember { tx, member } in txs {
            let tx_hash = tx.hash();
            let classified = member.classified();
            // A divided member waits on its execution scope minus itself
            // and on the crossings its legs consume, and on nothing else.
            // Its inbound escrow is its engagement, and the crossing bundle it consumes is
            // its counterpart's commitment, so neither half of the
            // engagement exchange is filed, and it runs under its own
            // committing block's clock.
            if classified.decomposed() {
                self.provisioning
                    .record_required(tx_hash, requirements_of(member, tx.legs()));
                continue;
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
            let payer_shard = trie.shard_for_prefix(tx.fee_payer());
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
    }

    /// Record what a committed block puts in flight: the ledger entry it
    /// owes an outcome for, the provisions and engagement echoes its
    /// cross-shard members wait on, and the candidate itself.
    ///
    /// `block` is the committing block, whose anchor is what a member
    /// executes under however many ticks later it runs — so a replay of
    /// the chain passes the anchors each transaction's own block carried
    /// rather than the tip's.
    ///
    /// Nothing executes here. Whether a transaction can reach its outcome
    /// at this commit is composition's question, asked again at every one.
    fn register_committed_txs(
        &mut self,
        classification: &TopologySnapshot,
        block: &CommittingBlock,
        transactions: &[Arc<Verifiable<Transaction>>],
    ) {
        let local_shard = self.local_shard;
        let members = committed_members(classification, local_shard, transactions);
        // The ledger takes the transactions themselves, each with the
        // classification frozen here and the block that froze it. What
        // it needs of them — when they expire, what they reserved, what
        // they reach outside this shard, what this shard is to them,
        // where this chain committed them — is theirs, this shard's and
        // the block's, so a rebuild reads the same account off the same
        // blocks however long after.
        self.counterparts.ledger.register_committed(
            CommittedAt {
                height: block.height,
                anchor: block.ts,
                committee_anchor: self.committed_committee_anchor_wt,
            },
            &classification.prices(),
            members
                .iter()
                .map(|committed| (&committed.tx, committed.member.classified())),
        );
        let reaches_beyond: Vec<CommittedMember> = members
            .iter()
            .filter(|committed| committed.member.reaches_beyond())
            .cloned()
            .collect();
        if !reaches_beyond.is_empty() {
            self.register_cross_shard_txs(classification, &reaches_beyond);
        }

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
                block.ts,
                classification.prices(),
                member.classified().clone(),
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
    /// blocks, each seated from its manifest, reproduces them exactly.
    ///
    /// Two reaches, because a replay has two jobs. Seating runs over
    /// every block the window holds, which runs back as far as an
    /// undischarged record, and to every tick a finalization the replay
    /// commits from [`dispatch_from`](Self::dispatch_from) on settles;
    /// execution runs only over what the store can still anchor a
    /// baseline at. Below `dispatch_from` the ticks are seated and none
    /// is dispatched — nothing is lost there, because such a tick was
    /// settled by a fate the replay reads off the chain, and what each of
    /// its halves left is seated from the finalization that settled it as
    /// that commit replays.
    ///
    /// The blocks arrive with the provision bundles they carried already
    /// reattached, so a leg runs here on the evidence it ran on the first
    /// time rather than waiting for a fetch nobody will answer.
    ///
    /// Deferred to here rather than done at construction because seating
    /// needs a topology, and there is none until the schedule
    /// is up. Idempotent: the payload is taken, and a live commit that
    /// beat this call has already advanced the frontier past it.
    ///
    /// The effects carry each replayed block's fold in commit order.
    pub fn on_committed_state_restored(
        &mut self,
        topology_schedule: &TopologySchedule,
        derivation: &dyn Derivation,
    ) -> CommitEffects {
        let blocks = std::mem::take(&mut self.replay_blocks);
        if blocks.is_empty() {
            return CommitEffects::default();
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

        let mut effects = CommitEffects::default();
        for certified in &blocks {
            // The replay window came off the store, so nothing derived
            // these on the way in.
            derive_block_transactions(certified.block(), derivation);
            // The fold a live commit runs, releases and terminal latch
            // included: a finalization the replay reseats but never
            // releases leaves its members assigned to a tick that has
            // already settled.
            effects.absorb(self.commit_block_carrying(
                topology_schedule,
                certified,
                Naming::Manifest,
            ));
        }
        effects
    }

    /// The lines this node's own committed inputs name for the tick at
    /// `tick_id`, in a manifest's order: the discard of each recovered
    /// tick; the discard of each member of `unanswerable` a tick holds,
    /// with its fate; its candidates; an abort of each entry past its
    /// deadline no shard is left to settle; then the discard of the tick
    /// that holds each of those, where one does. An abort states what its
    /// entry does: the share, the deadline, and the crossings the ledger
    /// lets an abandonment answer. What a fixture building a block stands
    /// in for.
    fn composed_lines(
        &self,
        anchored: &TopologySnapshot,
        tick_id: TickId,
        unanswerable: &[Unanswerable],
        recovered: &[TickId],
    ) -> Vec<TickLine> {
        let ledger = &self.counterparts.ledger;
        // A tick still owing its determined half is let go of by nothing
        // but a recovery.
        let settled_first = |held_by: &TickId| {
            self.ticks
                .get_tick(held_by)
                .is_none_or(|tick| !tick.determined_unsettled())
        };
        let mut lines: Vec<TickLine> = recovered
            .iter()
            .map(|&tick| TickLine::Discard {
                tick,
                cause: DiscardCause::Recovery,
            })
            .collect();
        for entry in unanswerable {
            let Some(tick) = self
                .ticks
                .tick_assignment(entry.tx_hash)
                .filter(settled_first)
            else {
                continue;
            };
            lines.push(TickLine::Discard {
                tick,
                cause: DiscardCause::Unanswerable(entry.tx_hash),
            });
            lines.push(TickLine::Fate {
                tx: entry.tx_hash,
                charge: entry.charge,
            });
        }
        lines.extend(self.candidates.named(
            anchored.shard_trie(),
            &self.provisioning,
            &mut self.provisional_cells(),
            self.committed_ts,
            &|tx_hash| ledger.abandonment_answers(tx_hash).is_none(),
        ));
        let mut discards = Vec::new();
        for entry in self.abandonable(tick_id) {
            let held_by = match self.ticks.tick_assignment(entry.tx_hash) {
                Some(held_by) if settled_first(&held_by) => Some(held_by),
                Some(_) => continue,
                None => None,
            };
            let reach: Vec<ShardId> = ledger
                .counterparts(entry.tx_hash, anchored.shard_trie())
                .into_iter()
                .collect();
            let crossings =
                ledger
                    .abandonment_answers(entry.tx_hash)
                    .map_or_default(|classified| {
                        classified
                            .refusable_consumed(self.local_shard)
                            .map(|edge| edge.crossing.id)
                            .collect()
                    });
            lines.push(TickLine::Member {
                tx: entry.tx_hash,
                joins: Joins::Aborted,
                settlement: if reach.is_empty() {
                    Settlement::Alone
                } else {
                    Settlement::Awaited
                },
                holds: Capped::empty(),
                reach: Capped::new(reach).expect("no more counterparts than prefixes"),
                awaits: Capped::empty(),
                charge: entry.charge,
                share: entry.charged,
                reserves: Capped::empty(),
                deadline: entry.deadline,
                crossings: Capped::new(crossings).expect("a star's edges are capped"),
            });

            discards.extend(held_by.map(|tick| TickLine::Discard {
                tick,
                cause: DiscardCause::Abandoned(entry.tx_hash),
            }));
        }
        lines.extend(discards);
        lines
    }

    /// Admit into the tick being seated everything its manifest names
    /// `Aborted`.
    ///
    /// Read after the tick's own member assignments, so a member that just
    /// joined this tick is not taken from it — the tick that holds a
    /// transaction is the one that speaks for it.
    ///
    /// Each is seated from its line alone, so a replica holding no
    /// candidate and no ledger entry for the member seats what its peers
    /// do and builds the receipt they build. It joins undispatched,
    /// reaching the shards the line names, which are the ones its
    /// committing block placed. Those are what routes this tick's
    /// certificate to the counterparts still waiting on a verdict for it:
    /// the abort is dominant, so their coverage closes on it. Nothing is
    /// awaited: an abort needs no counterpart's verdict, so the whole
    /// shape's one set serves.
    ///
    /// An abandonment reaches no engine, so what its verdict settles is
    /// built here rather than read off a result: the line's charge, where
    /// the vault is this shard's, and a `Never` at each crossing the line
    /// names whose decline key is this shard's. The receipt rides the
    /// abandonment's finalization under the transaction's own name, so a
    /// later accept of it on this chain is refused as already resolved.
    /// It reads no answer first: a line names crossings only for a member
    /// whose effects never applied, so nothing wrote its claim or decline
    /// key, and a second abandonment of it writes the same bytes. The decline
    /// key names the crossing's edge and no transaction, so it can hold
    /// the `Never` of another transaction carrying the same intent, and
    /// this one is written over it. The record of the transaction whose
    /// `Never` was written over is then bound by no answer at the key,
    /// and is answered again only by a later answer of its own
    /// transaction.
    fn admit_abandoned(
        &mut self,
        trie: &ShardTrie,
        tick_id: TickId,
        state: &mut TickState,
        lines: &[TickLine],
    ) {
        let local_shard = self.local_shard;
        for line in lines {
            let TickLine::Member {
                tx,
                joins: Joins::Aborted,
                reach,
                charge,
                share,
                deadline,
                crossings,
                ..
            } = line
            else {
                continue;
            };
            let tx_hash = *tx;
            // A tick that held the member can never speak for it — its
            // coverage will not close. The member goes, and with it every
            // sibling sharing no verdict with a counterpart, to their own
            // deadlines; a sibling a counterpart can settle stays, since
            // that counterpart settles it against the certificate already
            // out.
            if let Some(held_by) = self.ticks.tick_assignment(tx_hash) {
                self.release_tick(held_by, Some(tx_hash));
            }
            let participating: BTreeSet<ShardId> =
                reach.iter().copied().chain([local_shard]).collect();
            state.admit(
                tx_hash,
                Membership::whole(participating).settling(),
                *share,
                Joins::Aborted,
            );
            // The floor is owed whether or not the transaction ever ran:
            // the reservation engaged when its block committed it, and an
            // abort that released it without burning would price an
            // attempt nobody could execute below the success it was
            // competing with. Fees never move cross-shard, so only the
            // shard holding the vault settles it — the same question the
            // engine asks of the payers it prices.
            let vault = (trie.shard_for_prefix(charge.vault.owner) == local_shard).then(|| {
                (
                    charge.vault,
                    Movement::unjudged(*PROTOCOL_RESOURCE, charge.amount),
                )
            });
            let validity_end_ms = deadline.validity_end().as_millis();
            let nevers: Vec<(SubstateKey, Vec<u8>)> = crossings
                .iter()
                .map(|&id| abandoned_never(tx_hash, validity_end_ms, id))
                .filter(|(key, _)| trie.shard_for_prefix(key.owner) == local_shard)
                .collect();
            if let Some(receipt) = build_refusal_receipt(local_shard, trie, tx_hash, vault, &nevers)
            {
                state.record_refusal_receipt(StoredReceipt::new(tx_hash, Arc::new(receipt)));
            }
            self.candidates.remove(tx_hash);
            self.ticks.assign_tx(tx_hash, tick_id);
            self.counterparts
                .ledger
                .certify(tx_hash, Certified::ByAbandonment);
        }
    }

    /// Drop what no candidate waits for any more: what was provisioned
    /// belongs to the candidates waiting on it.
    fn sweep_candidates(&mut self) {
        let candidates = &self.candidates;
        self.provisioning
            .sweep(self.committed_ts, |tx_hash| candidates.contains(tx_hash));
    }

    /// Seat one composed member in the tick: its reservation, its
    /// crossing targets and its tick assignment.
    fn admit_member(
        &mut self,
        tick_id: TickId,
        member: Admitted,
        state: &mut TickState,
        ticked: &mut TickedBatch,
        requests: &mut Vec<CrossShardExecutionRequest>,
    ) {
        let local_shard = self.local_shard;
        // One table per member: the one the block that committed it
        // named. Both figures a member is priced by are this chain's
        // own — the share its outcome attests, which its abandonment
        // would restate from the record its committing block froze, and
        // the burn, which only the shard holding the payer's vault
        // settles. Reading either at the tick's own head would price one
        // transaction two ways across an epoch fold, and reading the
        // burn at the member's clock would price it at a window its
        // admission never judged the signed ceiling against.
        let prices = member.committed_prices;
        let request = &member.request;
        state.admit(
            request.tx_hash,
            member.membership,
            request
                .member
                .classified()
                .local_price(&request.transaction, local_shard, &prices),
            member.joins,
        );
        self.ticks.assign_tx(member.request.tx_hash, tick_id);
        self.counterparts
            .ledger
            .certify(member.request.tx_hash, Certified::ByExecution);
        if member.request.member.abortable() {
            let declared = &member.request.transaction.routing().declared_modes;
            ticked
                .legs
                .insert(member.request.tx_hash, declared_reservations(declared));
            ticked
                .provisional_claims
                .insert(member.request.tx_hash, declared.clone());
        }
        let mut request = member.request;
        request.prices = prices;
        requests.push(request);
    }

    /// Seat the tick the committing block names: its members, its aborts,
    /// its discards and its fates, as the lines say. Seating reads no
    /// baseline, so it runs whether or not the tick can be dispatched.
    fn seat_tick(
        &mut self,
        topology_schedule: &TopologySchedule,
        anchored: &TopologySnapshot,
        block: &CommittingBlock,
        named: Named<'_>,
        seated: &mut Vec<TickLine>,
    ) -> (
        Option<PendingTick>,
        Vec<Verifiable<ExecutionVote>>,
        Vec<TxHash>,
    ) {
        let local_shard = self.local_shard;
        let tick_id = TickId::new(local_shard, block.height);
        let composed;
        let lines = match named {
            Named::Lines(lines) => lines,
            Named::Composed {
                unanswerable,
                recovered,
            } => {
                composed = self.composed_lines(anchored, tick_id, unanswerable, recovered);
                &composed[..]
            }
        };
        seated.extend(lines.iter().cloned());
        for line in lines {
            match line {
                TickLine::Discard {
                    tick,
                    cause: DiscardCause::Unanswerable(tx_hash),
                } => self.drop_unanswerable(*tick, *tx_hash),
                TickLine::Discard {
                    tick,
                    cause: DiscardCause::Recovery,
                } => self.discard_recovered(*tick),
                TickLine::Fate { tx, .. } => self.let_go(*tx),
                TickLine::Member { .. }
                | TickLine::Discard {
                    cause: DiscardCause::Abandoned(_),
                    ..
                }
                | TickLine::End { .. } => {}
            }
        }
        let (admitted, in_hand) =
            self.candidates
                .take_named(lines, &self.provisioning, anchored.shard_trie(), block.ts);

        let mut state = TickState::new(tick_id, block.hash, block.ts);
        let mut requests: Vec<CrossShardExecutionRequest> = Vec::with_capacity(admitted.len());
        let mut ticked = TickedBatch {
            provisional_claims: BTreeMap::new(),
            legs: BTreeMap::new(),
        };
        for member in admitted {
            self.admit_member(tick_id, member, &mut state, &mut ticked, &mut requests);
        }

        self.admit_abandoned(anchored.shard_trie(), tick_id, &mut state, lines);

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
        // Resolved under the committee that attests the tick, which is
        // the one that will verify the certificate. A window this shard
        // has already left seats nobody, and there is no leader to be:
        // the tick is seated, but no vote it could carry would reach a
        // quorum.
        let mut votes_to_replay: Vec<Verifiable<ExecutionVote>> = Vec::new();
        if let Some(committee) = attesting_committee(topology_schedule, local_shard, block.ts)
            && let seated = committee.consensus_committee_for_shard(local_shard)
            && !seated.is_empty()
            && self.me == tick_leader(&tick_id, seated)
        {
            let mut tracker = VoteTracker::new(tick_id, block.hash);
            tracker.require(block.ts, committee.quorum_threshold_for_shard(local_shard));
            self.ticks.insert_tracker(tick_id, tracker);
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
            env: TickEnvironment::governing(anchored, topology_schedule.windows()),
            requests,
            included: block.fees.clone(),
            in_hand,
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
    /// A tick whose own certificate landed before its batch returned
    /// sends no vote, and its outcomes are fixed here all the same where
    /// this validator seats exactly the members the certificate attests:
    /// the root over them is reconciled with the certificate held, which
    /// is the divergence check a voter gets and what lets the tick hand
    /// off its stating half.
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
            attesting_committee(topology_schedule, local_shard, tick.vote_anchor_ts()).is_some_and(
                |snapshot| {
                    !snapshot
                        .consensus_committee_for_shard(local_shard)
                        .is_empty()
                },
            ) && !topology_schedule.committee_replaced_for_anchored(local_shard, tick.anchor())
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

        let certified: Vec<TickId> = self
            .ticks
            .ticks_iter()
            .filter(|(_, tick)| tick.local_ec_emitted() && tick.can_emit_vote())
            .map(|(tick_id, _)| *tick_id)
            .collect();
        for tick_id in certified {
            if let Some(tick) = self.ticks.get_tick_mut(&tick_id) {
                tick.reconcile_with_certificate();
            }
        }

        let mut completions = Vec::new();
        for tick_id in votable {
            let tick = self
                .ticks
                .get_tick_mut(&tick_id)
                .expect("tick_id was just produced by ticks_iter() in this method");
            let block_hash = tick.block_hash();
            let Some((vote_anchor_ts, global_receipt_root, tx_outcomes)) = tick.build_vote_data()
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash,
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

    /// Take back a tick this node could not run and put it at the
    /// dispatch head.
    ///
    /// The batch attested nothing, so nothing of the tick is spent: it
    /// goes back whole and waits exactly as a tick composed for code
    /// this node has not fetched waits. What releases it is the same
    /// thing — the engine answering for the package — and what retries
    /// it is the next commit, which seats and dispatches as every
    /// commit does. A tick anchored below a halt recovery's bridge goes
    /// back too, and the next dispatch drops it.
    pub fn on_execution_batch_unavailable(
        &mut self,
        tick: BlockHeight,
        tick_ts: WeightedTimestamp,
        env: TickEnvironment,
        requests: Vec<CrossShardExecutionRequest>,
        included: Vec<FeeTerms>,
        package: Hash,
    ) -> Vec<Action> {
        tracing::error!(
            shard = %self.local_shard,
            %tick,
            ?package,
            "Execution stalled: this node cannot run code a committed tick names"
        );
        record_batch_unavailable();
        self.tick_in_flight = false;
        self.pending_ticks.push_front(Queued::Run(PendingTick {
            tick,
            tick_ts,
            env,
            requests,
            included,
            in_hand: true,
        }));
        Vec::new()
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
            refusal_receipts,
        } = outcome;
        if let Some(state) = self.ticks.get_tick_mut(&tick_id) {
            for result in results {
                state.record_receipt(result);
            }
            for fee in refusal_receipts {
                state.record_refusal_receipt(fee);
            }
            for wr in tx_outcomes {
                let (tx_hash, outcome) = wr.into_parts();
                state.record_execution_result(tx_hash, outcome);
            }
            // A certificate that landed ahead of the batch is the
            // committee's answer, and this validator's outcomes are
            // fixed against it before any half is built from them.
            state.reconcile_with_certificate();
            actions.extend(self.finalize(&tick_id));
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
        actions.extend(self.dispatch_next_tick(topology_schedule));
        actions
    }

    /// Scan complete ticks and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after conflicts
    /// have been processed so tick state is deterministic at this height.
    /// Each vote is first sent to the tick leader (unicast). The `vote_anchor_ts`
    /// is the tick's own block's shard consensus-authenticated weighted
    /// timestamp, which is what resolves the committee that attests.
    pub fn emit_vote_actions(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let completions = self.scan_votable_ticks(topology_schedule);
        let mut actions = Vec::with_capacity(completions.len());
        for completion in completions {
            // The tick's committee is the one that attests it — the same
            // committee that will verify the EC. The scan admits only
            // ticks this resolves for, so a miss here is not reachable; a
            // tick dropped after the scan would have spent its one-shot vote
            // without casting it.
            let Some(committee) = attesting_committee(
                topology_schedule,
                self.local_shard,
                completion.vote_anchor_ts,
            )
            .map(|s| s.consensus_committee_for_shard(self.local_shard).to_vec())
            .filter(|committee| !committee.is_empty()) else {
                debug_assert!(false, "scan_votable_ticks admitted an unroutable tick");
                continue;
            };
            let leader = tick_leader(&completion.tick_id, &committee);
            // The first send goes to the tick leader alone. Every voter, the
            // leader included, keeps the vote for retry until a certificate
            // lands; a retry goes to the whole attesting committee and to
            // the voter's own tracker, so the votes meet in every live
            // member's tally.
            let tx_outcomes = Arc::new(completion.tx_outcomes);
            self.ticks.record_vote_retry(
                completion.tick_id,
                PendingVoteRetry {
                    sent_at: self.committed_ts,
                    attempt: Attempt::INITIAL,
                    block_hash: completion.block_hash,
                    vote_anchor_ts: completion.vote_anchor_ts,
                    global_receipt_root: completion.global_receipt_root,
                    tx_outcomes: Arc::clone(&tx_outcomes),
                },
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash: completion.block_hash,
                vote_anchor_ts: completion.vote_anchor_ts,
                tick_id: completion.tick_id,
                global_receipt_root: completion.global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                recipients: vec![leader],
            });
        }
        actions
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
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle an execution vote. A sealed vote lands directly in the
    /// verified tally; an unverified one is buffered for batch
    /// verification once combined power could reach quorum.
    ///
    /// The tick leader tallies the first sends. A vote arriving at a
    /// member that holds the tick but no tracker, and no certificate at
    /// the vote's anchor or later, is a retry or a re-attestation,
    /// addressed to the whole attesting committee, and a fallback
    /// `VoteTracker` is created on demand to tally it.
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
    pub fn on_execution_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: Verifiable<ExecutionVote>,
    ) -> Vec<Action> {
        let tick_id = *vote.tick_id();
        let validator_id = vote.validator();

        // A vote names its claimed voter unauthenticated, and every anchor
        // a tracker sees holds a quorum and a buffer of its own. For a
        // tick this node holds, only an anchor an honest voter signs is
        // taken, which bounds what a tracker keeps by the grid steps the
        // committed clock has reached. A vote for a tick not yet held is
        // held in the early-vote buffer, one slot per voter per tick, and
        // meets this check on replay.
        if let Some(tick) = self.ticks.get_tick(&tick_id)
            && !honest_vote_anchor(tick.anchor(), vote.vote_anchor_ts(), self.committed_ts)
        {
            tracing::debug!(
                tick = %tick_id,
                validator = validator_id.inner(),
                anchor = vote.vote_anchor_ts().as_millis(),
                "Execution vote at an anchor off its tick's grid"
            );
            return vec![];
        }

        // The committee that attests the vote's tick — the same one whose
        // positional bitfield the EC will carry. `None` means our beacon
        // hasn't reached that epoch; drop and let the sender's retry re-deliver
        // once we catch up.
        let Some(committee) =
            attesting_committee(topology_schedule, self.local_shard, vote.vote_anchor_ts())
        else {
            return vec![];
        };

        // Only votes from local-committee members count. A globally-known
        // validator outside this shard's committee whose vote pooled into
        // `unverified_power` would puff up the tracker into early
        // aggregation, producing an EC whose signature aggregate carries
        // signatures the verifier's bitfield-derived pubkey pool excludes
        // — guaranteed to fail verification and waste an aggregation.
        // Mirrors the shard's own membership preflight, which drops a
        // non-committee voter before anything else. Not its equivocation
        // detector: that one runs AFTER signature verification, which is
        // the opposite of what this check is for.
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
                if !self.early.buffer_vote(tick_id, vote) {
                    record_early_vote_refused();
                }
                return vec![];
            }
            if self.ticks.is_ec_dispatched(&tick_id)
                && let Some(answer) = self.answer_spent_vote(&vote)
            {
                return answer;
            }
            // Tick exists but no VoteTracker and no certificate it could
            // still use: a retried or re-attesting vote, which every
            // member tallies. Create the tracker.
            let block_hash = self
                .ticks
                .get_tick(&tick_id)
                .expect("contains_tick returned true two lines above")
                .block_hash();
            tracing::info!(
                tick = %tick_id,
                "Creating fallback VoteTracker — tallying a retried vote"
            );
            self.ticks
                .insert_tracker(tick_id, VoteTracker::new(tick_id, block_hash));

            // Replay any early votes that were buffered before block commit.
            // These may include retried votes from other validators who
            // committed faster and retried before our block committed.
            let early = self.early.drain_votes_for_tick(&tick_id);
            if !early.is_empty() {
                tracing::debug!(
                    tick = %tick_id,
                    count = early.len(),
                    "Replaying early votes into fallback VoteTracker"
                );
                let mut actions = Vec::new();
                for ev in early {
                    actions.extend(self.on_execution_vote(topology_schedule, ev));
                }
                // Process the current vote that triggered fallback creation.
                actions.extend(self.on_execution_vote(topology_schedule, vote));
                return actions;
            }
        }

        // The vote's anchor is held to the quorum of the committee seated
        // there, which is the one its certificate's bitfield would index.
        self.ticks
            .get_tracker_mut(&tick_id)
            .expect("a tracker exists or was inserted above")
            .require(
                vote.vote_anchor_ts(),
                committee.quorum_threshold_for_shard(self.local_shard),
            );

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

    /// The answer to a vote for a tick whose certificate is out, or `None`
    /// if the vote is still to be tallied.
    ///
    /// A vote at the held certificate's anchor or below is spent: a voter
    /// still sending it never received the certificate, and is sent it.
    /// A vote at a later anchor re-attests a tick still owed past the
    /// held certificate's life, and is tallied.
    fn answer_spent_vote(&self, vote: &Verifiable<ExecutionVote>) -> Option<Vec<Action>> {
        let held = self.exec_certs.get(vote.tick_id());
        if held
            .as_ref()
            .is_some_and(|certificate| vote.vote_anchor_ts() > certificate.vote_anchor_ts())
        {
            return None;
        }
        Some(
            held.map(|certificate| Action::BroadcastExecutionCertificate {
                shard: self.local_shard,
                certificate,
                recipients: vec![vote.validator()],
            })
            .into_iter()
            .collect(),
        )
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
        // The vote anchors to a committee the beacon has reached: `None`
        // means the beacon hasn't committed that epoch yet (drop and let
        // the sender retry). Membership was confirmed before delegating here.
        if attesting_committee(topology_schedule, self.local_shard, vote.vote_anchor_ts()).is_none()
        {
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
            .and_then(|v| {
                attesting_committee(topology_schedule, self.local_shard, v.vote_anchor_ts())
            })
            .map(|s| s.quorum_threshold_for_shard(self.local_shard));

        let Some(tracker) = self.ticks.get_tracker_mut(&tick_id) else {
            return vec![];
        };

        tracker.on_verification_complete(verified_votes);

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

        // The EC's signer bitfield is positional against the committee that
        // attests the tick — the Ready-filtered consensus members every
        // verifier resolves from the EC's own anchor and height. A seated
        // member not yet Ready is absent there, so indexing the full
        // committee would shift every later signer. Resolve it before
        // consuming the votes; `None` (beacon behind this epoch) leaves the
        // tracker intact to re-check on a later commit.
        let Some(committee) = attesting_committee(topology_schedule, local_shard, vote_anchor_ts)
            .map(|s| s.consensus_committee_for_shard(local_shard).to_vec())
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
            .map_or_default(|w| w.tx_hashes().to_vec());

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
    /// Reached by whichever member's tally completed: the tick leader, or a
    /// member a retried vote reached.
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
        // batch's transactions, not about its identity: a copy goes where
        // some member owes its outcome, which the frozen membership
        // decides per member. A leg owes nobody, so a tick of legs alone
        // projects nowhere and tracks nothing. Read off the batch's own
        // record rather than the provision accumulator, which may have
        // been pruned by the time the certificate is aggregated.
        //
        // The same record answers what each of them receives: the members
        // that owe that shard their outcome, and no others — the
        // certificate a remote shard gets is sized by its own stake in the
        // batch rather than by the batch.
        let per_target: Vec<(ShardId, HashSet<TxHash>)> =
            self.ticks.get_tick(tick_id).map_or_default(|tick| {
                tick.counterpart_shards()
                    .into_iter()
                    .map(|shard| (shard, tick.txs_reaching(shard).collect()))
                    .collect()
            });

        // Make the cert available to the io_loop's inbound EC fetch handler
        // for fallback serving until the containing block commits.
        self.exec_certs.insert(Arc::clone(certificate));
        self.ticks.clear_vote_retry(tick_id);

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
                self.committed_ts,
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
        actions.extend(self.handle_attestation(certificate));

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
        // state mutation downstream. The committee is the one that attests
        // the EC's tick. `on_execution_certificate` already resolved it to
        // dispatch this verification, so `None` here means that epoch aged
        // out of the schedule in the interim (the beacon advanced past
        // retention) — the EC is stale, so abandon it.
        let Some(committee) = attesting_committee(
            topology_schedule,
            ec_arc.shard_id(),
            ec_arc.vote_anchor_ts(),
        ) else {
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
        // The recovery band, re-checked here: a certificate dispatched
        // before the beacon folded its shard's halt recovery reaches this
        // point with a valid signature and quorum under the replaced
        // committee, and if it now sits in the band it settles nothing the
        // recovered shard keeps.
        if topology_schedule.recovery_orphaned(
            ec_arc.shard_id(),
            ec_arc.vote_anchor_ts(),
            ec_arc.block_height(),
        ) {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                tick = %ec_arc.tick_id(),
                height = ec_arc.block_height().inner(),
                "Discarding verified EC anchored below a recovery's bridge above its frontier"
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
        // remote shards. Only the complete copy stands for the tick: a
        // projection of it — the copy a counterpart shard is sent, which
        // reaches this validator when it also sits in that committee —
        // cannot settle the tick here, so the vote retry that recovers
        // the complete copy keeps running, and the store keeps its slot
        // for the copy that can serve this shard's own peers.
        if shard == self.local_shard && ec_arc.is_complete() {
            self.ticks.mark_ec_dispatched(*ec_arc.tick_id());
            // The certificate ends this voter's retries and its own tally:
            // a later vote for the tick is answered with the certificate.
            self.ticks.clear_vote_retry(ec_arc.tick_id());
            self.ticks.remove_tracker(ec_arc.tick_id());
            // Make the verified cert available to the io_loop's inbound EC
            // fetch handler for fallback serving until block commit.
            self.exec_certs.insert(Arc::clone(&ec_arc));
        }

        actions.extend(self.handle_attestation(&ec_arc));
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

    /// Ask each silent counterpart what it holds, against the trie that
    /// says who was party to each transaction.
    fn probe_silent_counterparts(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let Some(trie) = self.counterpart_trie(topology_schedule) else {
            return Vec::new();
        };
        let wanted = self.wanted_records();
        self.counterparts.probe(
            trie,
            self.committed_ts,
            &wanted,
            topology_schedule.windows(),
        )
    }

    /// The crossing records consumers here wait on with no arrival for:
    /// the candidates' filed requirements.
    fn wanted_records(&self) -> Vec<WantedRecord> {
        self.provisioning.wanted_records()
    }

    /// Keep a fetched proof for a block this validator proposes.
    pub fn on_proof_fetched(
        &mut self,
        anchor: Anchor,
        keys: &[SubstateKey],
        proof: &MerkleInclusionProof,
        values: &[ServedValue],
    ) {
        self.counterparts
            .on_proof_fetched(anchor, keys, proof, values);
    }

    /// Take a proof fetched for verdict questions at `anchor`, each
    /// question as its cells, and hold what a hearing row would take.
    pub fn on_verdict_proof_fetched(
        &mut self,
        anchor: Anchor,
        questions: &[VerdictCells],
        proof: &MerkleInclusionProof,
        windows: EpochWindows,
    ) {
        self.counterparts
            .on_verdict_proof_fetched(anchor, questions, proof, windows);
    }

    /// What this validator holds to offer in a block it proposes,
    /// passing over what `carried`, the chain from this coordinator's
    /// folded tip to the block's parent, carries.
    #[must_use]
    pub fn offers(&self, carried: &CarriedClaims) -> Offers {
        self.counterparts.offers(carried)
    }

    /// Ask the seat questions the committed tip stands, at the committed
    /// clock.
    pub fn ask_seats(&mut self, questions: &[SeatQuestion]) -> Vec<Action> {
        self.counterparts.ask_seats(questions, self.committed_ts)
    }

    /// Stand the verdict questions the committed tip's hearing rows put,
    /// and ask the ones due, at the committed clock.
    ///
    /// A push that landed ahead of a question standing now for the first
    /// time is placed again, so it answers the question before any ask
    /// of it goes out.
    pub fn ask_verdicts(
        &mut self,
        questions: &[VerdictQuestion],
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self.counterparts.ask_verdicts(questions, self.committed_ts);
        let stood: BTreeSet<SubstateKey> =
            self.counterparts.newly_stood().iter().copied().collect();
        if !stood.is_empty() {
            actions.extend(self.release_early_naming(topology_schedule, &stood));
        }
        actions
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
        anchor: Anchor,
    ) -> Vec<Action> {
        let source_shard = anchor.shard;
        if source_shard == self.local_shard {
            return vec![];
        }
        let mut actions = self.release(topology_schedule, Wake::Proof(source_shard));
        // The pushed claims that waited on exactly this anchor re-enter
        // where a fresh push would, against the anchor now proven.
        let now = self.committed_ts;
        for claim in self.parked_claims.release(source_shard, anchor.height) {
            actions.extend(self.place_pushed_claim(topology_schedule, claim, now));
        }
        // A counterpart's header past a leg's deadline is what a probe
        // of its committed set, or of its claim cell, waits on.
        actions.extend(self.probe_silent_counterparts(topology_schedule));
        actions
    }

    /// Re-place the early pushes whose keys `wanted` now names: a push
    /// that ran ahead of its consumer's commit is offered once the
    /// commit files the want.
    fn release_early_pushes(
        &mut self,
        topology_schedule: &TopologySchedule,
        wanted: &[WantedRecord],
    ) -> Vec<Action> {
        let keys: BTreeSet<SubstateKey> = wanted.iter().map(|record| record.key).collect();
        self.release_early_naming(topology_schedule, &keys)
    }

    /// Re-place the early pushes carrying any of `keys`.
    fn release_early_naming(
        &mut self,
        topology_schedule: &TopologySchedule,
        keys: &BTreeSet<SubstateKey>,
    ) -> Vec<Action> {
        let now = self.committed_ts;
        self.parked_claims
            .release_early(keys)
            .into_iter()
            .flat_map(|claim| self.place_pushed_claim(topology_schedule, claim, now))
            .collect()
    }

    /// Place a producer's pushed readings, each past ingress: offered
    /// where its anchor is one this replica commit-proved, dropped where
    /// the proven anchor differs, parked until the proof lands where
    /// there is none yet.
    pub fn on_crossing_readings(
        &mut self,
        topology_schedule: &TopologySchedule,
        claims: Vec<StateClaim>,
    ) -> Vec<Action> {
        let now = self.committed_ts;
        claims
            .into_iter()
            .flat_map(|claim| self.place_pushed_claim(topology_schedule, claim, now))
            .collect()
    }

    fn place_pushed_claim(
        &mut self,
        topology_schedule: &TopologySchedule,
        claim: StateClaim,
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        let anchor = claim.anchor;
        if topology_schedule.recovery_orphaned(anchor.shard, anchor.ts, anchor.height) {
            record_crossing_push_dropped("fenced");
            return vec![];
        }
        // Below the read frontier's floor every voter refuses a fenced
        // reading, and the fallback read covers a push lost or delayed
        // past one producer block.
        let Some(claim) = self
            .counterparts
            .cut_pushed(claim, topology_schedule.windows())
        else {
            record_crossing_push_dropped("below_floor");
            return vec![];
        };
        match self
            .counterparts
            .proven_anchors
            .at(anchor.shard, anchor.height)
        {
            Some(proven) if proven == anchor => {
                if claim.verdicts.is_empty() {
                    let wanted = self.wanted_records();
                    if !self.counterparts.offer_pushed(&claim, &wanted, now)
                        && let Err(reason) = self.parked_claims.hold_early(claim)
                    {
                        record_crossing_push_dropped(reason);
                    }
                } else if let Err(reason) = self
                    .counterparts
                    .offer_pushed_verdicts(&claim, now, topology_schedule.windows())
                    .and_then(|early| {
                        early.map_or(Ok(()), |early| self.parked_claims.hold_unasked(early))
                    })
                {
                    record_crossing_push_dropped(reason);
                }
                vec![]
            }
            Some(_) => {
                record_crossing_push_dropped("anchor_disagrees");
                vec![]
            }
            None => {
                if let Err(reason) = self.parked_claims.park(claim) {
                    record_crossing_push_dropped(reason);
                    return vec![];
                }
                // At or below the shard's attested boundary the header
                // exists and is fetched; above it, it arrives on its own.
                if topology_schedule
                    .head()
                    .boundary(anchor.shard)
                    .is_some_and(|boundary| anchor.height <= boundary.height)
                {
                    return vec![Action::Continuation(ProtocolEvent::CommitProofNeeded {
                        source_shard: anchor.shard,
                        block_height: anchor.height,
                    })];
                }
                vec![]
            }
        }
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
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::ExecutionCerts(vec![(source_shard, tx_hash)]),
                    shard: source_shard,
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
            actions.push(Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::ExecutionCerts(vec![(source_shard, tx_hash)]),
                shard: source_shard,
                preferred: None,
                class: None,
            }));
        }

        // What the expectation tracker lets go of leaves its fallback
        // fetch in flight, answered by nothing: the drop happens exactly
        // where the certificate never came. The ledger asks under the
        // same ids for its own backstop, so only a key neither
        // owner wants is retired.
        let mut dropped: Vec<_> = self
            .expected_certs
            .retain_if_tx_needed(&awaited)
            .into_iter()
            .filter(|&(_, tx_hash)| !self.counterparts.ledger.awaits_certificate(tx_hash))
            .collect();
        dropped.sort();
        if !dropped.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::ExecutionCerts(dropped)));
        }
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

    /// Re-send votes for ticks that haven't produced an EC.
    ///
    /// Called during block commit processing. When a retry's deadline has
    /// elapsed against the committed QC's weighted timestamp, the registry
    /// returns a [`RetryEffect`] for each fired retry, which
    /// [`Self::lift_vote_retries`] addresses to the attesting committee.
    fn check_vote_retry_timeouts(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let effects = self.ticks.check_vote_retry_timeouts(self.committed_ts);
        self.lift_vote_retries(topology_schedule, effects)
    }

    /// Re-sign the vote of every tick still owing its determined half
    /// once the committed clock passes the next step on its anchor grid
    /// ([`reattestation_anchor`]), for the committee seated there.
    ///
    /// A tick its own committee can no longer certify — a holder of a
    /// vote it needed was cut off until its seat was torn down, or is
    /// gone — stalls settlement on this shard for good, since every later
    /// determined half settles behind it. Execution is deterministic, so
    /// a later committee certifies the outcome the tick's own would have,
    /// and every tick that already ran on it stays as it ran. A seat
    /// re-signs only a tick it ran, and only where it sits in that step's
    /// committee. A tick anchored below a halt recovery's bridge is left
    /// to the recovery, whose crossing block discards it: re-signed at a
    /// step past the bridge it would escape the recovery's band, and its
    /// certificate would settle at a counterpart while this shard lets it
    /// go.
    ///
    /// A tick that did certify is re-signed too while its half is owed:
    /// its certificate lapses at the step like any vote, and a tick held
    /// behind a stalled one would otherwise be left with a certificate
    /// no verifier resolves a committee for once the stalled one settles.
    /// [`TickState::revote_at`] keeps a step at or below the held
    /// certificate's anchor from re-signing.
    ///
    /// The re-signed vote replaces the tick's retry entry, so retries
    /// reach the whole committee at the new anchor.
    fn revote_stalled_ticks(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let local_shard = self.local_shard;
        let stalled: Vec<(TickId, WeightedTimestamp)> = self
            .ticks
            .ticks_iter()
            .filter(|(_, tick)| {
                tick.determined_unsettled()
                    && !topology_schedule
                        .committee_replaced_for_anchored(local_shard, tick.anchor())
            })
            .filter_map(|(tick_id, tick)| {
                reattestation_anchor(tick.anchor(), self.committed_ts)
                    .map(|anchor| (*tick_id, anchor))
            })
            .collect();
        let mut actions = Vec::new();
        for (tick_id, anchor) in stalled {
            let Some(committee) = attesting_committee(topology_schedule, local_shard, anchor)
                .map(|snapshot| snapshot.consensus_committee_for_shard(local_shard).to_vec())
                .filter(|committee| committee.contains(&self.me))
            else {
                continue;
            };
            let tick = self
                .ticks
                .get_tick_mut(&tick_id)
                .expect("tick_id was just read off the registry");
            let block_hash = tick.block_hash();
            let Some((vote_anchor_ts, global_receipt_root, tx_outcomes)) = tick.revote_at(anchor)
            else {
                continue;
            };
            tracing::info!(
                tick = %tick_id,
                anchor = anchor.as_millis(),
                "Re-signing a stalled tick's vote for a later committee"
            );
            let tx_outcomes = Arc::new(tx_outcomes);
            self.ticks.record_vote_retry(
                tick_id,
                PendingVoteRetry {
                    sent_at: self.committed_ts,
                    attempt: Attempt::INITIAL,
                    block_hash,
                    vote_anchor_ts,
                    global_receipt_root,
                    tx_outcomes: Arc::clone(&tx_outcomes),
                },
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash,
                vote_anchor_ts,
                tick_id,
                global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                recipients: vec![tick_leader(&tick_id, &committee)],
            });
        }
        actions
    }

    /// Re-send every held vote while execution's committed clock is
    /// frozen, once per [`VOTE_RETRY_TIMEOUT`] of cleanup-timer time.
    ///
    /// Commit-time retries are timed against `committed_ts`, which stops
    /// when no block reaches the fold: a member the crossing left behind
    /// is sent no more proposals, and a fold held behind a window this
    /// node's beacon lacks commits nothing. A vote such a member holds is
    /// still owed to the attesting committee, and the cleanup timer keeps
    /// ticking on every seated vnode, so it is what keeps the vote moving.
    /// A change in `committed_ts` restarts the count, and the commit-time
    /// retries take over again.
    pub fn on_cleanup_tick(
        &mut self,
        topology_schedule: &TopologySchedule,
        interval: Duration,
    ) -> Vec<Action> {
        if self.committed_ts != self.stall_seen_ts {
            self.stall_seen_ts = self.committed_ts;
            self.stalled_for = Duration::ZERO;
            self.stall_retry_periods = 0;
            return Vec::new();
        }
        self.stalled_for = self.stalled_for.saturating_add(interval);
        let periods = u32::try_from(self.stalled_for.as_nanos() / VOTE_RETRY_TIMEOUT.as_nanos())
            .unwrap_or(u32::MAX);
        if periods <= self.stall_retry_periods {
            return Vec::new();
        }
        self.stall_retry_periods = periods;
        let effects = self.ticks.fire_all_vote_retries(self.committed_ts);
        self.lift_vote_retries(topology_schedule, effects)
    }

    /// Hold an empty vote for `tick_id`, anchored at genesis, as if this
    /// seat had sent it at the committed clock.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn hold_vote_retry(&mut self, tick_id: TickId) {
        self.ticks.record_vote_retry(
            tick_id,
            PendingVoteRetry {
                sent_at: self.committed_ts,
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::ZERO,
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(Vec::new()),
            },
        );
    }

    /// Lift fired retries to `Action::SignAndSendExecutionVote`s.
    fn lift_vote_retries(
        &self,
        topology_schedule: &TopologySchedule,
        effects: Vec<RetryEffect>,
    ) -> Vec<Action> {
        let mut actions = Vec::with_capacity(effects.len());
        for RetryEffect {
            tick_id,
            attempt,
            block_hash,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
        } in effects
        {
            // A retry goes to the whole committee that attests the tick —
            // the Ready-filtered set the EC's bitfield indexes — this voter
            // included, so its own vote meets its peers' in every tally,
            // its own among them. Two ways there is nobody to send to, and
            // both defer the retry to a later fire: the beacon is behind
            // the anchor, or the anchor resolves a window this shard has
            // already left, where nobody is seated and no vote can reach a
            // quorum anyway.
            let Some(recipients) =
                attesting_committee(topology_schedule, self.local_shard, vote_anchor_ts)
                    .map(|s| s.consensus_committee_for_shard(self.local_shard).to_vec())
                    .filter(|committee| !committee.is_empty())
            else {
                continue;
            };
            tracing::info!(
                tick = %tick_id,
                attempt = attempt.inner(),
                recipients = recipients.len(),
                "Vote retry — re-sending to the attesting committee"
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash,
                vote_anchor_ts,
                tick_id,
                global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                recipients,
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Fold a committed block into execution: the one entry live commits,
    /// block sync and the restart's replay all take.
    ///
    /// The fold waits behind any commit whose anchored committee sits in
    /// a window this node's beacon has not committed, and folds with it
    /// once it lands, so the effects returned may carry earlier blocks'
    /// ahead of this one's, or nothing. Each block's fold, in order:
    ///
    /// 1. **Resolutions** — what its finalizations settle, read off the
    ///    ledger before anything releases the entries.
    /// 2. **Release** — execution's own bookkeeping for those
    ///    finalizations.
    /// 3. **Anchor time** — bump `committed_height` and `committed_ts`
    ///    from the header's parent QC; everything below reads them.
    /// 4. **Terminal latch** — derived from the new tip before anything
    ///    is seated.
    /// 5. **Timeouts, then pruning**, so a retry fires before the tick it
    ///    references is pruned away.
    /// 6. **Seat, then dispatch** — both forms seat the tick the block
    ///    names; only a live one within the store's reach dispatches it.
    #[instrument(skip(self, certified, topology_schedule), fields(
        height = certified.block().height().inner(),
        block_hash = ?certified.block().hash(),
        tx_count = certified.block().transactions().len(),
        is_live = certified.block().is_live(),
    ))]
    pub fn commit_block(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
        committee_anchor: WeightedTimestamp,
    ) -> CommitEffects {
        self.commit_named(
            topology_schedule,
            certified,
            committee_anchor,
            Naming::Manifest,
        )
    }

    /// [`Self::commit_block`] seating the members this node's own
    /// committed inputs name, in place of the block's manifest: what a
    /// fixture whose blocks name nothing commits through, standing in
    /// for a proposer whose inputs are this node's.
    pub fn commit_block_composing(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
        committee_anchor: WeightedTimestamp,
    ) -> CommitEffects {
        self.commit_named(
            topology_schedule,
            certified,
            committee_anchor,
            Naming::Composed,
        )
    }

    fn commit_named(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
        committee_anchor: WeightedTimestamp,
        naming: Naming,
    ) -> CommitEffects {
        self.awaiting_window
            .push_back((certified.clone(), committee_anchor, naming));
        self.drain_awaiting_window(topology_schedule)
    }

    /// Fold the commits waiting on their windows, oldest first, for as
    /// long as each one's anchored committee resolves. A commit whose
    /// window this node's beacon has not committed stays at the front,
    /// and every later one queues behind it, so the fold still runs in
    /// commit order.
    fn drain_awaiting_window(&mut self, topology_schedule: &TopologySchedule) -> CommitEffects {
        let mut effects = CommitEffects::default();
        while let Some((certified, committee_anchor, _)) = self.awaiting_window.front() {
            let own_anchor = certified.block().header().parent_qc().weighted_timestamp();
            let Some(anchored) =
                self.anchored_committee(topology_schedule, *committee_anchor, own_anchor)
            else {
                break;
            };
            let (certified, committee_anchor, naming) = self
                .awaiting_window
                .pop_front()
                .expect("the front was just read");
            effects.absorb(self.commit_anchored(
                topology_schedule,
                anchored,
                &certified,
                committee_anchor,
                naming,
            ));
        }
        effects
    }

    /// [`Self::commit_block`] with the committee anchor carried from
    /// the commit before: the previous block's own anchor where the chain
    /// is contiguous, the block's own anchor across a gap. The restart's
    /// replay commits this way, since no event carries its anchors.
    ///
    /// "First commit" means the chain has never committed, not that the
    /// clock reads zero: a root chain's first blocks genuinely anchor at
    /// zero, and their zero is a carriable parent anchor, not a gap.
    fn commit_block_carrying(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &CertifiedBlock,
        naming: Naming,
    ) -> CommitEffects {
        let height = certified.block().height();
        let first_commit = self.committed_height == BlockHeight::GENESIS
            && self.committed_ts == WeightedTimestamp::ZERO;
        let committee_anchor = if !first_commit && height == self.committed_height.next() {
            self.committed_ts
        } else {
            certified.block().header().parent_qc().weighted_timestamp()
        };
        self.commit_named(topology_schedule, certified, committee_anchor, naming)
    }

    /// One commit's fold, under the committee its anchor resolved.
    #[allow(clippy::too_many_lines)] // sequential orchestration of one commit's fold
    fn commit_anchored(
        &mut self,
        topology_schedule: &TopologySchedule,
        anchored: &TopologySnapshot,
        certified: &CertifiedBlock,
        committee_anchor: WeightedTimestamp,
        naming: Naming,
    ) -> CommitEffects {
        let block = certified.block();
        let height = block.height();
        let (floor, crossed) = self.cross_a_bridge(topology_schedule, committee_anchor, block);

        // What the block's finalizations settle about the transactions
        // they name, read off their outcomes alone.
        let resolutions: Vec<(TxHash, TxResolution)> = block
            .certificates()
            .iter()
            .flat_map(|finalization| finalization.resolutions())
            .collect();
        for fw in block.certificates().iter() {
            // No-op for synced ticks never aggregated here.
            self.remove_finalization(fw.as_unverified());
        }

        // Update committed height + timestamp before anything else — needed
        // for timeout calculations and pruning even when there are no new
        // transactions.
        if height > self.committed_height {
            self.committed_committee_anchor_wt = committee_anchor;
            self.committed_height = height;
            self.committed_ts = block.header().parent_qc().weighted_timestamp();
        }
        // Read off the tip header's parent QC, which the header's hash
        // pins, and never off the block's own certifying QC, whose
        // timestamp a relay can rewrite. So it flips at the quiescence
        // commit, whose parent QC certifies the terminal block, and
        // before that commit seats.
        let terminal = !self.terminated
            && topology_schedule.past_terminal(self.local_shard, self.committed_ts);
        let mut actions = floor;
        if terminal {
            actions.extend(self.terminate());
        }
        self.provisioning.advance_clock(self.committed_ts);
        self.parked_claims.retire_below(self.committed_ts);
        self.sweep_candidates();
        // What the block says about counterparts, and what it opens to
        // ask them; the strands no counterpart can answer for any more
        // are let go of below.
        let trie = anchored.shard_trie();
        let wanted = self.wanted_records();
        actions.extend(self.release_early_pushes(topology_schedule, &wanted));
        let committed =
            self.counterparts
                .on_commit(trie, topology_schedule, block, self.committed_ts, &wanted);
        actions.extend(committed.actions);
        // The leg entries the fold closed, for the mempool: no
        // finalization names them, so this is where their acceptance is
        // reported.
        if !committed.settled.is_empty() {
            actions.push(Action::Continuation(ProtocolEvent::TransactionsResolved {
                resolutions: committed.settled,
            }));
        }
        let unanswerable = committed.unanswerable;
        // A fixture composing its own lines names the ticks the crossing
        // dropped, as a proposer's manifest names every tick its rows hold.
        let recovered = if naming == Naming::Composed {
            crossed
        } else {
            Vec::new()
        };
        for entry in &unanswerable {
            record_unanswerable(entry.covered_by_record);
        }

        // Timeout checks + pruning run every block, not just commits that
        // carry txs.
        actions.extend(self.check_exec_cert_timeouts());
        actions.extend(self.check_vote_retry_timeouts(topology_schedule));
        actions.extend(self.revote_stalled_ticks(topology_schedule));
        self.prune_execution_state();
        self.early.gc_stale_ecs(self.committed_ts);
        actions.extend(self.offer_legs());

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
        // reads the resolved chain. A held tick never ran here, so what
        // a run of its half would have left is seated from the
        // finalization that settled it, at or above where the store
        // reaches; below it the base carries it.
        let mut restored: Vec<(TickId, TickResolution)> = Vec::new();
        for fw in block.certificates().iter() {
            let fw = fw.as_unverified();
            let aborted: BTreeSet<TxHash> = fw
                .tx_decisions()
                .into_iter()
                .filter(|(_, decision)| !matches!(decision, TransactionDecision::Accept))
                .map(|(tx_hash, _)| tx_hash)
                .collect();
            if let Some(held) = self.held.get(fw.tick_id())
                && height >= self.dispatch_from
            {
                let resolution = if fw.is_determined() {
                    let writes: Vec<(TxHash, StateWrites)> = receipt_writes(fw)
                        .into_iter()
                        .filter(|(tx_hash, _)| !held.abandoned.contains(tx_hash))
                        .collect();
                    (!writes.is_empty()).then_some(TickResolution::Restored { height, writes })
                } else {
                    let legs = self.restored_legs(fw, &aborted, &held.abandoned);
                    (!legs.is_empty()).then(|| TickResolution::RestoredLegs {
                        height,
                        legs,
                        aborted: aborted.clone(),
                    })
                };
                restored.extend(resolution.map(|resolution| (*fw.tick_id(), resolution)));
            }
            // The members this finalization settles, which is one half
            // of its tick rather than the whole of it, and none where a
            // stating half states only yeses.
            let members: BTreeSet<TxHash> = fw.tx_hashes().collect();
            if !members.is_empty() {
                self.record_tick_resolution(
                    fw.tick_id(),
                    TickResolution::Settled {
                        height,
                        members,
                        aborted,
                    },
                );
            }
        }
        if !restored.is_empty() {
            actions.push(Action::ResolveTicks {
                resolutions: restored,
            });
        }
        let ticks = &self.ticks;
        self.held.retain(|tick_id, _| ticks.contains_tick(tick_id));
        actions.extend(self.drain_ready_tick_resolutions());

        let mut named = Vec::new();
        actions.extend(self.on_block_committed(
            &mut named,
            topology_schedule,
            anchored,
            block,
            match naming {
                Naming::Manifest => Named::Lines(block.tick_manifest()),
                Naming::Composed => Named::Composed {
                    unanswerable: &unanswerable,
                    recovered: &recovered,
                },
            },
        ));

        CommitEffects {
            resolutions,
            actions,
            terminal,
            named,
        }
    }

    /// What this commit sends out: the provisions its proposer
    /// broadcasts, the crossing readings the parent's commit made go with
    /// it, and the pushes queued for the next. Nothing on a block this
    /// replica cannot run.
    fn pushes(
        &mut self,
        anchored: &TopologySnapshot,
        committed: &Block,
        runnable: bool,
    ) -> Vec<Action> {
        let block_hash = committed.hash();
        let header = committed.header();
        let transactions = committed.transactions();
        let finalizations = committed.certificates();
        let height = header.height();
        // ── Provision broadcasting (proposer only) ─────────────────────
        // The crossing changes the parent block made go with it: this
        // block's certified header is what proves the parent to a
        // reader, and its proposer sends both. Taken whether or not this
        // replica proposes, so nothing older than one commit is ever
        // pushed.
        let mut actions = Vec::new();
        let pending_push = self.pending_push.take();
        if runnable && self.me == header.proposer() {
            let local_shard = self.local_shard;
            if let Some((requests, shard_recipients)) =
                build_provision_requests(anchored, transactions, self.me, local_shard)
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
            if let Some((parent_hash, anchor, mut targets)) = pending_push {
                // The records still standing whose consumers have not
                // answered them, an owed one uncredited and an escrowed
                // one past its validity end, pushed again at the
                // parent's view, where each record still stands.
                for (target, records) in self.counterparts.record_repushes(
                    anchored.shard_trie(),
                    self.committed_ts,
                    anchor.height,
                ) {
                    let keys = targets.entry(target).or_default();
                    keys.extend(records);
                    keys.sort_unstable();
                    keys.dedup();
                }
                let shard_recipients = targets
                    .keys()
                    .map(|&target| (target, anchored.committee_for_shard(target).to_vec()))
                    .collect();
                actions.push(Action::PushCrossingReadings {
                    block_hash: parent_hash,
                    anchor,
                    targets,
                    shard_recipients,
                });
            }
        }
        // Every live block is pushed for, whether or not it wrote a
        // record: the answers it wrote and the records it removed are
        // the handler's to find, off the block and its parent.
        if runnable {
            let ledger = &self.counterparts.ledger;
            let targets = record_pushes(
                finalizations,
                anchored.shard_trie(),
                self.local_shard,
                |tx_hash, record| ledger.claimants(tx_hash, record),
            );
            let anchor = Anchor {
                shard: self.local_shard,
                height,
                state_root: header.state_root(),
                ts: header.parent_qc().weighted_timestamp(),
            };
            self.pending_push = Some((block_hash, anchor, targets));
        }
        actions
    }

    /// One commit path for both block forms: register what the block
    /// commits, apply the bundles it carries, and seat the tick it names.
    ///
    /// A `Sealed` block is seated exactly as a `Live` one is, since both
    /// keep the transactions, the claims, the records and the manifest
    /// seating reads, but its tick is never dispatched: it carries no
    /// bundles to run a cross-shard member over, and its proposer's pushes
    /// went out when it was live.
    fn on_block_committed(
        &mut self,
        seated: &mut Vec<TickLine>,
        topology_schedule: &TopologySchedule,
        anchored: &TopologySnapshot,
        committed: &Block,
        named: Named<'_>,
    ) -> Vec<Action> {
        let block_hash = committed.hash();
        let header = committed.header();
        let transactions = committed.transactions();
        let provisions = committed.provisions();
        let state_claims = committed.state_claims();
        let height = header.height();
        let mut actions = Vec::new();

        // Below where a baseline is readable, or on a sealed block with
        // no bundles to run over, a tick is seated and never runs: which
        // tick holds a member is what every replica has to agree on, and
        // the baseline and the bundles are what this replica may not
        // hold.
        let runnable = committed.is_live() && height >= self.dispatch_from;

        actions.extend(self.pushes(anchored, committed, runnable));

        let block = CommittingBlock {
            hash: block_hash,
            height,
            ts: header.parent_qc().weighted_timestamp(),
            fees: transactions.iter().map(|tx| FeeTerms::of(tx)).collect(),
        };

        // Everything this commit puts in flight or unblocks, before
        // anything is composed from it: the block's own transactions, and
        // the provisions and engagement echoes its batches carry.
        if !transactions.is_empty() {
            self.register_committed_txs(anchored, &block, transactions);
        }
        // After the block's transactions are registered, so a record
        // read in a transaction's own block is its arrival.
        self.provisioning.fold_record_readings(state_claims);
        if !provisions.is_empty() {
            self.apply_committed_provisions(provisions);
        }
        // Seating appends the lines this block's tick is seated from.
        let lines_from = seated.len();
        // A terminated chain seats nothing: no later block of it can
        // carry a finalization, so a tick it seated could never reach a
        // verdict.
        let (pending, early_votes, members) = if self.terminated {
            (None, Vec::new(), Vec::new())
        } else {
            self.seat_tick(topology_schedule, anchored, &block, named, seated)
        };
        for vote in early_votes {
            actions.extend(self.on_execution_vote(topology_schedule, vote));
        }
        // The members that just gained an assignment: a counterpart's
        // certificate that arrived while they waited has a tick to route
        // to now, and nothing else will offer it one.
        if !members.is_empty() {
            actions.extend(self.replay_early_attestations(&members));
        }
        if let Some(pending) = pending {
            if runnable && pending.in_hand {
                tracing::debug!(
                    height = height.inner(),
                    members = pending.requests.len(),
                    "Dispatching this commit's tick"
                );
                self.pending_ticks.push_back(Queued::Run(pending));
            } else {
                let tick_id = TickId::new(self.local_shard, height);
                tracing::debug!(
                    height = height.inner(),
                    members = pending.requests.len(),
                    in_hand = pending.in_hand,
                    "Seated a tick this node cannot run; holding dispatch behind it"
                );
                self.held
                    .insert(tick_id, HeldTick::of(&seated[lines_from..]));
                self.pending_ticks.push_back(Queued::Held(tick_id));
            }
        }
        // What seating abandoned, before the tick it seated reads the
        // chain: a discarded tick's legs hold cells this one may
        // need, and nothing else is coming to release them.
        actions.extend(self.drain_ready_tick_resolutions());
        actions.extend(self.dispatch_next_tick(topology_schedule));

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
        for claims in self
            .ticked
            .values()
            .flat_map(|ticked| ticked.provisional_claims.values())
        {
            cells.claim(claims);
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
    /// An assembled settlement needs no narrowing here: its tick is
    /// lower, so the store offers it first and the duplicate-resolution
    /// rule refuses the abort, after which the ledger releases the
    /// transaction. Nor does a transaction a counterpart may have settled:
    /// an entry an executing tick took is offered only once a record
    /// covers it or where it reaches no other shard, so no abandonment
    /// names a member whose certificate a counterpart could still settle
    /// against.
    fn abandonable(&self, composing: TickId) -> Vec<UnsettledTx> {
        self.counterparts
            .ledger
            .past_deadline(self.committed_ts)
            .into_iter()
            // A candidate still waiting for a tick is the manifest's to
            // abort.
            .filter(|entry| !self.candidates.contains(entry.tx_hash))
            .filter(|entry| self.beyond_every_shard(composing, entry.tx_hash))
            .collect()
    }

    /// Discard a tick a halt recovery lets go of at its crossing block,
    /// whole: every member goes to the deadline path, a `Shared` one
    /// included, since no committee the shard keeps certifies a tick
    /// anchored below the bridge.
    fn discard_recovered(&mut self, tick_id: TickId) {
        // What the tally saw is the whole diagnosis: split roots are
        // replicas that executed the tick differently, and power under
        // quorum on one root is votes that never arrived.
        let tally = self.ticks.get_tracker(&tick_id);
        tracing::warn!(
            tick = %tick_id,
            tallied_here = tally.is_some(),
            distinct_receipt_roots =
                tally.map_or(0, VoteTracker::distinct_global_receipt_root_count),
            verified_power = tally.map_or(0, |tracker| tracker.total_verified_power().inner()),
            "Discarding a tick a halt recovery left no quorum to certify"
        );
        self.ticks.discard_tick(&tick_id);
        // The floor raise of the crossing it is let go of at drops its
        // chain entry whole, holds and all, so nothing is left to abandon
        // on it.
        self.ticked.remove(&tick_id);
        self.finalized.remove_tick(&tick_id);
        self.exec_certs.evict(&tick_id);
        let height = tick_id.block_height();
        self.pending_ticks
            .retain(|queued| !matches!(queued, Queued::Run(pending) if pending.tick == height));
    }

    /// Release a tick that can no longer speak for `abandoned`, or for
    /// the determined half it owes: every member sharing no verdict with
    /// a counterpart goes to its own deadline, and `abandoned` goes
    /// whatever it shares. A member whose verdict a counterpart shares
    /// stays, with the tick, its certificate and its assignment: the
    /// counterpart settles it against that certificate, which outlives
    /// the tick, and dropped here nothing would settle it and — its
    /// entry certified — nothing could abandon it.
    ///
    /// Nothing kept: the tick, both its finalizations and its
    /// certificate all go. A proposer offering a finalization for a
    /// member abandoned here would be refused by every voter, and would
    /// keep offering it; a certificate left in the cache is answered to
    /// a counterpart asking by transaction, for a verdict this shard has
    /// retracted and beside the abort that replaced it.
    ///
    /// Something kept: the tick stays and so does its certificate, since
    /// a sibling settles against it. Its legs half is composed again on
    /// the kept legs that have their verdict — one taken before may name
    /// a released member, which every voter would refuse, so it is
    /// evicted — and its determined half is untouched, emitted or
    /// pending: it releases no claim, and its writes are readable from
    /// the append. A stating half handed off and not committed states
    /// the member the release took, which the tick no longer holds: the
    /// tick owes it again, every copy held for a block is evicted, and
    /// the next commit builds it over the members kept.
    ///
    /// Which members stay is read off committed membership alone, never
    /// off whether this replica has handed its own certificate off, so
    /// every replica releases the same set on the same commit.
    fn release_tick(&mut self, tick_id: TickId, abandoned: Option<TxHash>) {
        let (released, kept) = self
            .ticks
            .get_tick_mut(&tick_id)
            .map_or_else(|| (Vec::new(), Vec::new()), |tick| tick.release(abandoned));
        let counts = self.ticks.release_tick(&tick_id, &kept);
        self.release_chain_holds(tick_id, &released, kept.is_empty());
        if kept.is_empty() {
            self.finalized.remove_tick(&tick_id);
            self.exec_certs.evict(&tick_id);
            tracing::info!(
                tick = %tick_id,
                released = counts.assignments,
                "Released a tick holding nothing a counterpart can settle"
            );
        } else {
            self.finalized.remove_half(&tick_id, TickHalf::Legs);
            if self
                .ticks
                .get_tick(&tick_id)
                .is_some_and(TickState::stating_owed)
            {
                self.finalized.remove_half(&tick_id, TickHalf::Stated);
            }
            tracing::info!(
                tick = %tick_id,
                released = counts.assignments,
                kept = kept.len(),
                "Released a tick's members, keeping those a counterpart can settle"
            );
        }
    }

    /// Tell the chain a tick's `released` legs reach no verdict, so what
    /// they hold against the cells they declared is let go of; `whole`
    /// releases every leg the tick holds, and drops the entry if it
    /// holds none.
    ///
    /// A leg's reservation stands on the chain until its tick's fate
    /// resolves it, and every later tick's reader takes it as value
    /// already spoken for. A tick that has stopped speaking for a member
    /// reaches no fate for it, so nothing else would ever release it:
    /// the payer's cells stay locked on every replica that ran the tick,
    /// the entry never evicts, and a replica that rebuilt the chain
    /// without the hold reads a different overlay from the same chain.
    /// A kept leg's claims stay for its own settlement to clear.
    fn release_chain_holds(&mut self, tick_id: TickId, released: &[TxHash], whole: bool) {
        let Some(ticked) = self.ticked.get(&tick_id) else {
            return;
        };
        let members: BTreeSet<TxHash> = ticked
            .legs
            .keys()
            .copied()
            .filter(|leg| whole || released.contains(leg))
            .collect();
        if members.is_empty() {
            if whole {
                self.ticked.remove(&tick_id);
            }
            return;
        }
        self.record_tick_resolution(
            &tick_id,
            TickResolution::Abandoned {
                height: self.committed_height,
                members,
            },
        );
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
                // Which clock it runs on is already applied: an entry
                // reaches here only past its own abandon window's
                // opening. A departure is the only covering a held member
                // can have: a leg's readings license nothing, and a
                // core member runs only once every sibling's committed
                // bundle names it, so a sibling's absence reaches only one
                // no tick took.
                self.counterparts.ledger.departed(tx_hash)
            }
            // An entry no execution of ours took is re-offered once its
            // tick is gone: it spends nothing to abort at any age, and
            // its only exit is an abandonment's committed finalization.
            None => {
                !self.counterparts.ledger.executed(tx_hash)
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
            || self.counterparts.ledger.is_covered(tx_hash)
    }

    /// Release the tick holding a transaction no shard can settle any
    /// more, on the committed discard that names it. The fate the same
    /// block names for it is what ends this shard's account of it.
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
    /// which is the same condition that makes a certified outcome for
    /// the transaction unreachable. Nothing that could still settle is
    /// destroyed, because by then nothing can.
    ///
    /// Each of these is a transaction that ends with no certified
    /// outcome, counted by cause where its entry still stands; the
    /// ledger may drop the entry first, and counts it there.
    fn drop_unanswerable(&mut self, tick_id: TickId, tx_hash: TxHash) {
        if self.counterparts.ledger.contains(tx_hash) {
            record_unanswerable(self.counterparts.ledger.departed(tx_hash));
        }
        tracing::info!(
            tx = %tx_hash,
            tick = %tick_id,
            "Releasing a strand whose counterparts have all fallen silent"
        );
        self.release_tick(tick_id, Some(tx_hash));
    }

    /// End this shard's account of a transaction a committed fate
    /// names: no line will name it again, so its candidate goes, and its
    /// row is gone with no certificate, so its ledger entry goes with no
    /// outcome. A tick still holding it is released by the discard the
    /// fate follows, or dropped with every other at the terminal.
    fn let_go(&mut self, tx_hash: TxHash) {
        self.candidates.remove(tx_hash);
        self.counterparts.ledger.forget(tx_hash);
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
        let Some(ticked) = self.ticked.get_mut(tick_id) else {
            return;
        };
        // The claims clear with the fate rather than with the promotion:
        // both the commit path and the tick-completion pump emit pending
        // resolutions before dispatching, so the chain is always at least
        // as resolved as the claim set says by the time a later tick runs.
        //
        // Only a resolution naming legs clears anything, and only theirs.
        // A determined member holds no cell — its writes are readable
        // from the append — so its own half settling releases nothing. A
        // tick's legs settle and are released by member, in as many
        // resolutions as name them, so each lets go of what its legs held
        // and the entry goes with the last of them.
        let released = match &resolution {
            TickResolution::Settled { members, .. } | TickResolution::Abandoned { members, .. } => {
                ticked.resolve(members)
            }
            // Never reaches here: a restore is emitted straight to the
            // chain, for a tick no run of this replica's appended.
            TickResolution::Restored { .. } | TickResolution::RestoredLegs { .. } => false,
        };
        if released {
            self.ticked.remove(tick_id);
        }
        self.pending_tick_resolutions
            .push((*tick_id, tick_id.block_height(), resolution));
    }

    /// At this shard's crossing block past a halt recovery's bridge
    /// ([`TopologySchedule::crossing_block`]), let go of every tick
    /// below it and raise the tick chain floor to the crossing block's
    /// parent height.
    ///
    /// Every tick the registry holds is anchored below the bridge, in a
    /// row or not: the registry drops each whole, with its queue
    /// entries, buffered resolutions, votes, finalizations and
    /// certificates. Every contribution at or below the parent is then
    /// in the base or discarded, so the floor withdraws every chain entry
    /// there and nothing else, and the first tick past the crossing reads
    /// the base alone. A batch in flight now is of a tick the registry no
    /// longer holds: its completion records nothing, and its append lands
    /// at or below the floor, so the chain drops it.
    ///
    /// Asks the shard's own question of the shard's own inputs
    /// ([`TopologySchedule::crossing_block`] at the block's committee
    /// anchor, its parent's), so the commit that drops the ticks is the
    /// one whose lines discard their rows. Answers the floor raise beside
    /// the ticks dropped.
    fn cross_a_bridge(
        &mut self,
        topology_schedule: &TopologySchedule,
        committee_anchor: WeightedTimestamp,
        block: &Block,
    ) -> (Vec<Action>, Vec<TickId>) {
        let Some(floor) = block.height().prev().filter(|_| {
            topology_schedule.crossing_block(
                self.local_shard,
                committee_anchor,
                block.header().parent_qc().weighted_timestamp(),
            )
        }) else {
            return (Vec::new(), Vec::new());
        };
        let below: Vec<TickId> = self
            .ticks
            .ticks_iter()
            .map(|(tick_id, _)| *tick_id)
            .filter(|tick_id| tick_id.block_height() <= floor)
            .collect();
        for tick_id in &below {
            self.discard_recovered(*tick_id);
        }
        self.pending_ticks.retain(|queued| match queued {
            Queued::Run(pending) => pending.tick > floor,
            Queued::Held(tick_id) => tick_id.block_height() > floor,
        });
        self.held
            .retain(|tick_id, _| tick_id.block_height() > floor);
        self.ticked
            .retain(|tick_id, _| tick_id.block_height() > floor);
        self.pending_tick_resolutions
            .retain(|(_, tick, _)| *tick > floor);
        self.last_completed_tick = self.last_completed_tick.max(floor);
        (vec![Action::RaiseTickFloor { floor }], below)
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

    /// A held tick's legs as a run would have left them, read off the
    /// legs finalization `fw`, `aborted` naming those whose effects it
    /// discards.
    ///
    /// Each leg's surviving side is what its receipt states. A leg holds
    /// what it declared only once it completes, which its outcome in this
    /// shard's own certificate says; a leg whose body this node never held
    /// holds nothing here. A member in `abandoned` reached no engine, so
    /// a run left no leg for it and none is seated.
    fn restored_legs(
        &self,
        fw: &Finalization,
        aborted: &BTreeSet<TxHash>,
        abandoned: &BTreeSet<TxHash>,
    ) -> Vec<ProvisionalTx> {
        let declared = self.ticked.get(fw.tick_id()).map(|ticked| &ticked.legs);
        let mut receipts: BTreeMap<TxHash, StateWrites> = receipt_writes(fw).into_iter().collect();
        // Each member the half settles, and whether it completed: every
        // name of a legs half is an accept.
        let settled: Vec<(TxHash, bool)> = if fw.half() == TickHalf::Legs {
            fw.tx_hashes().map(|tx_hash| (tx_hash, true)).collect()
        } else {
            fw.settled_outcomes()
                .map(|outcome| {
                    let completed = matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. });
                    (outcome.tx_hash(), completed)
                })
                .collect()
        };
        settled
            .into_iter()
            .filter(|(tx_hash, _)| !abandoned.contains(tx_hash))
            .map(|(tx_hash, completed)| {
                let receipt = receipts.remove(&tx_hash);
                let (writes, reserve) = if aborted.contains(&tx_hash) {
                    (None, receipt)
                } else {
                    (receipt, None)
                };
                ProvisionalTx {
                    tx_hash,
                    writes,
                    reserve,
                    reserved: declared
                        .and_then(|legs| legs.get(&tx_hash))
                        .filter(|_| completed)
                        .cloned()
                        .unwrap_or_default(),
                }
            })
            .collect()
    }

    /// Dispatch the queued tick at the head, unless one is already in
    /// flight. Ticks execute serially: each output is the next tick's
    /// baseline, so the next dispatch waits for the previous
    /// `ExecutionBatchCompleted` — by which point the handler has
    /// appended the output to the tick chain.
    ///
    /// It waits too for the block below the tick to be written. That
    /// block's commit is in hand by then, and its write never waits on a
    /// tick, so the wait ends at the `BlockPersisted` that names it.
    ///
    /// The tick goes out with every fate recorded for it so far, which
    /// the chain applies under the acquisition that appends its output.
    /// They stay buffered too, and are emitted again once the tick
    /// completes with whatever was recorded while it ran: the chain
    /// resolves a member once however often it is told.
    ///
    /// No tick anchored below a halt recovery's bridge leaves here once
    /// `topology_schedule` holds the recovery: each is dropped from the
    /// queue, since the crossing block discards it. Every dispatch reads
    /// the schedule, so a tick queued before the fold is dropped by the
    /// first dispatch after it, a write's or a commit's alike.
    fn dispatch_next_tick(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let local_shard = self.local_shard;
        let ticks = &self.ticks;
        self.pending_ticks.retain(|queued| match queued {
            Queued::Run(pending) => {
                !topology_schedule.committee_replaced_for_anchored(local_shard, pending.tick_ts)
            }
            Queued::Held(tick_id) => ticks.get_tick(tick_id).is_none_or(|tick| {
                !topology_schedule.committee_replaced_for_anchored(local_shard, tick.anchor())
            }),
        });
        if self.tick_in_flight || self.committed_height < self.replay_through {
            return Vec::new();
        }
        // A held tick blocks until its determined half has settled: its
        // readable writes are in the chain then, seated from the receipts.
        // It blocks too while a leg of it that may reserve is unresolved:
        // whether the leg completed, and so holds what it declared, is
        // committed only by the finalization that settles it, and every
        // later tick below that commit reads the hold.
        while let Some(Queued::Held(tick_id)) = self.pending_ticks.front() {
            if self
                .ticks
                .get_tick(tick_id)
                .is_some_and(TickState::determined_unsettled)
                || self
                    .ticked
                    .get(tick_id)
                    .is_some_and(TickedBatch::may_reserve)
            {
                return Vec::new();
            }
            self.pending_ticks.pop_front();
        }
        let Some(Queued::Run(head)) = self.pending_ticks.front() else {
            return Vec::new();
        };
        if head.tick.prev().is_some_and(|below| below > self.persisted) {
            return Vec::new();
        }
        // Running a member whose code this node lacks would reach the
        // engine's no-code refusal while every replica holding the bytes
        // settles it — one tick, two receipt roots. Waiting is the whole
        // of the fix: the fetch heals, and the tick that runs then is the
        // tick that was seated now. Ticks are serial, so this shard's
        // execution stops here until the bytes land — the trade a
        // withheld artifact is meant to draw, liveness rather than a
        // fork.
        //
        // Asked of the engine rather than read off a set kept in step
        // with it. A set has to be seeded, and a shard seated mid-epoch
        // is handed ticks before anything has seeded it; asking leaves
        // nothing to seed. The held tick names what it waits on, so its
        // code is sought whatever else did or did not ask for it, and the
        // next commit seats and dispatches again, which is what retries
        // a tick held here.
        let missing = head.missing_code(self.code.as_ref());
        if !missing.is_empty() {
            tracing::debug!(
                shard = %self.local_shard,
                tick = %head.tick,
                "Holding a tick whose members run code this node has not fetched"
            );
            return vec![Action::Fetch(FetchRequest::Packages { wanted: missing })];
        }
        let Some(Queued::Run(tick)) = self.pending_ticks.pop_front() else {
            return Vec::new();
        };
        self.tick_in_flight = true;
        let fates: Vec<TickResolution> = self
            .pending_tick_resolutions
            .iter()
            .filter(|(_, height, _)| *height == tick.tick)
            .map(|(_, _, resolution)| resolution.clone())
            .collect();
        vec![Action::ExecuteTransactions {
            tick: tick.tick,
            fates,
            tick_ts: tick.tick_ts,
            env: tick.env,
            requests: tick.requests,
            included: tick.included,
        }]
    }

    /// Replay buffered certificates for transactions that have just
    /// gained a tick assignment.
    ///
    /// Driven by assignment rather than by commit, because those are no
    /// longer the same moment: a member waits in the candidate pool until
    /// a tick can take it, and a counterpart's certificate arriving in
    /// that window has nowhere to route. Seating is what gives it one,
    /// so seating is what replays.
    fn replay_early_attestations(&mut self, tx_hashes: &[TxHash]) -> Vec<Action> {
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
            actions.extend(self.handle_attestation(ec));
        }
        actions
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
    fn handle_attestation(&mut self, ec: &Arc<Verified<ExecutionCertificate>>) -> Vec<Action> {
        let mut actions = Vec::new();
        self.counterparts.on_certificate(ec, self.committed_ts);

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
            if tick.adopt_later_certificate(ec) {
                actions.extend(self.reanchor_finalizations(tick_id, ec));
            } else {
                tick.add_execution_certificate(Arc::clone(ec));
            }
            actions.extend(self.finalize(tick_id));
        }
        // The other: an admitted local EC that contradicts the vote this
        // validator already cast.
        self.escalate_divergence();
        actions
    }

    /// Rebuild every finalization of `tick_id` held for a block on
    /// `local`, the tick's own certificate signed at a later anchor, and
    /// admit the rebuilt copies in their place.
    ///
    /// The held copies carry a certificate whose anchor's window
    /// verifiers evict, after which no block could carry them. Every
    /// copy certifies the same outcomes and receipts, and the chain takes
    /// one half per tick whichever copy it carries: a half's members
    /// settle once, and a determined half settles once above the
    /// frontier.
    fn reanchor_finalizations(
        &self,
        tick_id: &TickId,
        local: &Arc<Verified<ExecutionCertificate>>,
    ) -> Vec<Action> {
        let mut finalizations = Vec::new();
        for held in self.finalized.of_tick(tick_id) {
            let Some(reanchored) = held.reanchored(local) else {
                continue;
            };
            tracing::info!(
                tick = %tick_id,
                anchor = local.vote_anchor_ts().as_millis(),
                "Re-anchoring a held finalization on a later certificate"
            );
            let reanchored: Arc<Verifiable<Finalization>> =
                Arc::new(Verified::<Finalization>::seal(reanchored).into());
            self.finalized.remove(&held.receipt_hash());
            self.finalized.insert(*tick_id, Arc::clone(&reanchored));
            finalizations.push(reanchored);
        }
        if finalizations.is_empty() {
            return Vec::new();
        }
        vec![Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
            finalizations,
        })]
    }

    /// Offer the legs half of every tick whose stated members that can
    /// accept are not the ones its last half names: a block settled one
    /// of them, a release let one go, or the committed tip's rows now
    /// accept another. And the stating half of every tick that owes one
    /// it can build: a release took a member the half it had handed off
    /// stated, so that half was withdrawn, or the vote scan fixed this
    /// validator's own outcomes after the tick's certificate had landed.
    fn offer_legs(&mut self) -> Vec<Action> {
        let due: Vec<TickId> = self
            .ticks
            .ticks_iter()
            .filter(|(_, tick)| tick.legs_ready(&self.accepting) || tick.stating_ready())
            .map(|(tick_id, _)| *tick_id)
            .collect();
        let mut actions = Vec::new();
        for tick_id in due {
            actions.extend(self.finalize(&tick_id));
        }
        actions
    }

    /// Take `accepting` as the stated members whose rows at the committed
    /// tip accept on what their siblings' state says, and offer the legs
    /// half of every tick whose members that can accept changed.
    ///
    /// Execution holds no rows: the shard coordinator reads them and
    /// hands the answer here at each settled tip. A proposer judges each
    /// name again at its own block's anchor and cuts what no longer
    /// stands.
    pub fn offer_accepting(&mut self, accepting: BTreeSet<TxHash>) -> Vec<Action> {
        if accepting == self.accepting {
            return Vec::new();
        }
        self.accepting = accepting;
        self.offer_legs()
    }

    /// Finalize a tick: build the [`Finalization`] of each half that can
    /// settle, and hand it off.
    ///
    /// Called when the tick's local EC is present. The determined half
    /// settles on it alone; the stating half says what it reached for
    /// every member awaiting another shard; the legs half names the
    /// stated members whose rows accept, and is built again, in place of
    /// the one held, each time those members change.
    fn finalize(&mut self, tick_id: &TickId) -> Vec<Action> {
        let Some(tick) = self.ticks.get_tick_mut(tick_id) else {
            return vec![];
        };
        // Determined first, and the order matters: the two halves of one
        // tick came out of a single batch fold, so a receipt in the second
        // states an absolute computed on top of the first.
        let determined = tick.take_determined_finalization();
        let stating = tick.take_stating_finalization();
        let legs = tick
            .legs_ready(&self.accepting)
            .then(|| tick.legs_half(&self.accepting));

        // Local-finalization gate produces `Verified<Finalization>`; lift
        // into the `Block::Live.certificates` transport shape once so the
        // store, the admission event, and any downstream `PendingBlock`
        // entry share the same `Arc` without further per-consumer cloning.
        let mut actions = Vec::new();
        for half in determined.into_iter().chain(stating) {
            let finalized_arc = Arc::new(Verified::<Finalization>::seal(half).into());
            actions.extend(self.emit_finalized(finalized_arc));
        }
        if let Some(half) = legs {
            actions.extend(self.offer_legs_half(tick_id, half));
        }

        if self
            .ticks
            .get_tick(tick_id)
            .is_some_and(TickState::has_spoken)
        {
            // Every leg's settlement needed every participating shard's
            // certificate, which means each of them executed this tick —
            // strong evidence they also received our outbound EC (or are
            // about to). Drop the re-broadcast tracker entry to stop
            // wasting bandwidth. The tick itself stays until a committed
            // block resolves its members.
            self.outbound_certs.on_tick_finalized(tick_id);
        }
        actions
    }

    /// Hand off `half`, the legs half naming every stated member of
    /// `tick_id` that can accept now, or none where it is `None`; it
    /// replaces the legs half the store holds for the tick wherever its
    /// names differ.
    fn offer_legs_half(&mut self, tick_id: &TickId, half: Option<Finalization>) -> Vec<Action> {
        let names: Vec<TxHash> = half
            .as_ref()
            .map_or_else(Vec::new, |half| half.tx_hashes().collect());
        let replaces = self
            .ticks
            .get_tick_mut(tick_id)
            .is_some_and(|tick| tick.offer_legs(names));
        if !replaces {
            return Vec::new();
        }
        // The half held names other members, and a block carrying both
        // would name a member twice.
        self.finalized.remove_half(tick_id, TickHalf::Legs);
        let Some(half) = half else {
            return Vec::new();
        };
        let half: Arc<Verifiable<Finalization>> =
            Arc::new(Verified::<Finalization>::seal(half).into());
        self.finalized.insert(*tick_id, Arc::clone(&half));
        vec![Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
            finalizations: vec![half],
        })]
    }

    /// Record a freshly built finalization and emit its admission event,
    /// which covers both the shard consensus subscriber and the `io_loop`
    /// serving cache.
    fn emit_finalized(&self, finalized_arc: Arc<Verifiable<Finalization>>) -> Vec<Action> {
        self.finalized
            .insert(*finalized_arc.tick_id(), Arc::clone(&finalized_arc));
        vec![Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
            finalizations: vec![finalized_arc],
        })]
    }

    /// Record the transactions a past-terminal shard's terminal block
    /// `terminal` ended, held beside its settled set for whoever reads
    /// the rows the departed shard had accepted. Nothing waits on them
    /// here.
    pub fn record_ended_names(&self, shard: ShardId, terminal: BlockHash, names: BTreeSet<TxHash>) {
        self.counterparts.on_ended(shard, terminal, names);
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

        self.counterparts.on_settled(shard, settled);
        self.parked_claims.drop_shard(shard);
        let mut actions = self.release(topology_schedule, Wake::SettledSet(shard));
        actions.extend(self.offer_legs());
        actions
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
        // A legs half carries no certificate to verify: what holds it is
        // the receipts it names, each recomputing to its named hash, which
        // a copy stored without them does not carry.
        if tick.half() == TickHalf::Legs && tick.validate_against_certificates().is_err() {
            return vec![Action::AbandonFetch(tick.abandon())];
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
    ///
    /// Returns commit effects because a commit parked on a window the
    /// beacon had not committed folds here, and its resolutions and
    /// terminal latch reach the node as any fold's do.
    pub fn on_beacon_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> CommitEffects {
        // The parked commits fold first, so everything below reads the
        // frontier they advance.
        let mut effects = self.drain_awaiting_window(topology_schedule);
        effects
            .actions
            .extend(self.release(topology_schedule, Wake::Beacon));
        effects
            .actions
            .push(Action::Fetch(FetchRequest::SettledTxs {
                wanted: self
                    .counterparts
                    .wanted_settled_sets(topology_schedule, self.committed_ts),
                preferred: None,
                class: None,
            }));
        effects
            .actions
            .push(Action::Fetch(FetchRequest::TerminalLines {
                wanted: self
                    .counterparts
                    .wanted_terminal_lines(topology_schedule, self.committed_ts),
                preferred: None,
                class: None,
            }));
        effects
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

    /// The height of the last block this coordinator folded.
    #[must_use]
    pub const fn committed_height(&self) -> BlockHeight {
        self.committed_height
    }

    /// Get the local tick assignment for a transaction.
    #[must_use]
    pub fn tick_assignment_for(&self, tx_hash: TxHash) -> Option<TickId> {
        self.ticks.tick_assignment(tx_hash)
    }

    /// The receipt root this node voted for `tick_id`, while the tick is
    /// seated and this node has run it: what its execution of the tick
    /// came to, before any certificate reconciles it.
    #[must_use]
    pub fn voted_receipt_root(&self, tick_id: &TickId) -> Option<GlobalReceiptRoot> {
        self.ticks
            .get_tick(tick_id)
            .and_then(TickState::voted_receipt_root)
    }

    /// Every finalization ready for inclusion, in the order a block must
    /// settle them.
    ///
    /// That order is tick order, and it is the store's own: a tick's
    /// certificate settles the writes that tick produced, and a later
    /// tick executed against the earlier one's output. `TickId` sorts by
    /// `(shard, height)`, so iterating the store is already the order
    /// receipts have to be applied in. Within a tick the determined half
    /// comes first: the legs half's members were judged over its output.
    ///
    /// Order is all this offers: which of them a block may carry is
    /// admission's, read off the committed rows.
    #[must_use]
    pub fn get_finalizations(&self) -> Vec<Arc<Verifiable<Finalization>>> {
        self.finalized.all()
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
    pub(crate) fn remove_finalization(&mut self, fw: &Finalization) {
        let tick_id = fw.tick_id();
        self.finalized.remove(&fw.receipt_hash());
        // A tick states once. Every other copy of its stating half, one
        // attested at another anchor or built over other members, states
        // rows the committed one already moved; a half of yeses names no
        // settled member to find them by, so they go by tick and half.
        if fw.half() == TickHalf::Stated {
            self.finalized.remove_half(tick_id, TickHalf::Stated);
            if let Some(tick) = self.ticks.get_tick_mut(tick_id) {
                tick.stating_committed();
            }
        }
        let tx_hashes: Vec<TxHash> = fw.tx_hashes().collect();
        // A held half of the same kind naming a member this one settled
        // settles nothing once this one has: a copy attested at another
        // anchor, or a legs half naming more of the tick's legs or fewer.
        for copy in self.finalized.of_tick(tick_id) {
            if copy.half() == fw.half() && copy.tx_hashes().any(|tx| tx_hashes.contains(&tx)) {
                self.finalized.remove(&copy.receipt_hash());
            }
        }

        // A tick settles its determined half once and its legs by
        // member, so one finalization committing says nothing about the
        // members it does not name. Drop the tick and its certificate
        // only once every member it holds has been resolved — otherwise
        // a leg loses the state it is still owed from.
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

    /// Flush the node-local execution state on the terminal's commit, the
    /// fold that derives the terminal latch. It is a cache of what the
    /// chain committed, and the terminal committed a fate for every
    /// member still in flight, so nothing here is owed an outcome any
    /// more: no later content block exists to finalize a tick in. Serving
    /// state (aggregated ECs, finalizations) stays — peers still fetch
    /// what this chain produced.
    fn terminate(&mut self) -> Vec<Action> {
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
        // The ledger goes with the rest: the terminal's fates are every
        // entry's committed exit, and a deadline falling after the
        // terminal would otherwise have this chain seat a tick to abandon
        // an entry in — on a coast block, under a committee it no longer
        // has.
        self.counterparts.ledger = Ledger::new(self.local_shard);
        // The terminated chain's tick outputs die with it: successors seed
        // from settled state, and pending resolutions have nothing left to
        // resolve against. A tick still in flight lands on a cleared
        // chain, so its completion must be able to release the queue.
        self.pending_tick_resolutions.clear();
        self.pending_ticks.clear();
        self.held.clear();
        self.ticked.clear();
        self.tick_in_flight = false;
        // And the candidates behind them, with the latch that keeps
        // seating from admitting more: a candidate whose cross-shard
        // provisions land past the terminal would otherwise be seated in
        // a tick at a past-terminal anchor, which gets no vote tracker
        // and is never votable — an execution batch dispatched and
        // written into the chain just cleared, for an outcome that can
        // never certify.
        self.candidates.clear();
        self.terminated = true;
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
        // Non-leaders with a tick but no VoteTracker KEEP early votes. A
        // retried vote can seed a tracker there, and they are replayed into
        // the on-demand VoteTracker created in `on_execution_vote`.
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
                        let legs = tick.legs_ready(&self.accepting);
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

/// The latest step on a tick's anchor grid that `committed_ts` has
/// passed, past the tick's own anchor: `tick_ts + k·REATTESTATION_STEP`
/// for the largest `k ≥ 1` at or below `committed_ts`. `None` until the
/// first step.
fn reattestation_anchor(
    tick_ts: WeightedTimestamp,
    committed_ts: WeightedTimestamp,
) -> Option<WeightedTimestamp> {
    let step = u64::try_from(REATTESTATION_STEP.as_millis()).expect("a step fits u64 millis");
    let steps = committed_ts.as_millis().checked_sub(tick_ts.as_millis())? / step;
    (steps >= 1).then(|| WeightedTimestamp::from_millis(tick_ts.as_millis() + steps * step))
}

/// Whether an honest voter signs a tick anchored at `tick_ts` at `anchor`
/// while this node's committed clock reads `committed_ts`: the tick's own
/// anchor, or a step on its grid ([`reattestation_anchor`]) no later than
/// one step past the clock. A voter re-signs at a step once its own
/// committed clock passes it, and a peer's clock can run ahead of this
/// one; a peer more than a step ahead is caught up with by its retries.
fn honest_vote_anchor(
    tick_ts: WeightedTimestamp,
    anchor: WeightedTimestamp,
    committed_ts: WeightedTimestamp,
) -> bool {
    let step = u64::try_from(REATTESTATION_STEP.as_millis()).expect("a step fits u64 millis");
    let on_grid = anchor
        .as_millis()
        .checked_sub(tick_ts.as_millis())
        .is_some_and(|offset| offset % step == 0);
    anchor == tick_ts
        || (on_grid && anchor.as_millis() <= committed_ts.as_millis().saturating_add(step))
}

#[cfg(test)]
mod tests {
    /// Where the fixtures commit a transaction: at the chain's first
    /// block, before any departure a fixture records.
    fn test_committed() -> CommittedAt {
        CommittedAt {
            height: BlockHeight::new(1),
            anchor: WeightedTimestamp::ZERO,
            committee_anchor: WeightedTimestamp::ZERO,
        }
    }

    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;
    use std::time::Duration;

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_storage::{ReplayWindow, committed_tx_cell_key, member_row_leaf};
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::{
        StubVmStatics, certify as test_certify, genesis_charge,
        make_finalization as helpers_make_finalization, make_finalization_leaving,
        make_leg_finalization, make_live_block as helpers_make_live_block, naming, proven_claim,
        state_and_proof, state_and_proof_holding, stating_half_on, stub_abort_charge, test_prefix,
        test_transaction, test_transaction_running, test_transaction_with_prefixes,
    };
    use hyperscale_types::{
        AbandonmentRecord, AbortCharge, Address, AddressClass, AggregateSignature,
        BeaconWitnessLeafCount, ConsensusPublicKey, ConsensusReceipt, ConsensusSignature,
        Crossings, Deadline, Epoch, EpochSeed, EpochWindows, ExecutionCertificateContext,
        ExecutionOutcome, ExecutionVoteMessage, GlobalReceiptHash, Hash, Inclusion, LocalKey,
        MAX_FINALIZATION_DELAY, MAX_UNSETTLED_PER_BLOCK, MAX_VALIDITY_RANGE, NetworkDefinition,
        PriceTable, QuorumCertificate, RETENTION_HORIZON, Randomness, RecoveryBinding,
        RecoveryCause, Role, SeedRing, SeedSource, SettledTxsRoot, Settlement, ShardAnchor,
        ShardRecovery, Signer, SignerBitfield, StateClaim, StateRoot, Stated, StoredReceipt,
        SubstateKey, TerminalEvidence, TickHalf, TransactionDecision, TxResolution, UnsettledTx,
        ValidatorInfo, ValidatorSet, Verify, Window, compute_global_receipt_root, signed_bytes,
    };
    use hyperscale_vm_effects::{
        Answered, CrossingCell, CrossingId, Hash32, IntentHash, Kind, ProtocolHasher, Terms,
    };
    use hyperscale_vm_types::{Drawn, ResourceAddr};

    use super::*;
    use crate::counterparts::TestRows;

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
    fn make_test_topology_recovering(
        shard: ShardId,
        frontier: BlockHeight,
        pending: bool,
    ) -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let mut head = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
        .with_recoveries(BTreeMap::from([(
            shard,
            vec![RecoveryBinding {
                rotated_at: Epoch::GENESIS,
                attested_frontier: frontier,
                completed: !pending,
            }],
        )]));
        if pending {
            head = head.with_pending_recoveries(BTreeMap::from([(
                shard,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::GENESIS,
                    retained: vec![ValidatorId::new(0)],
                    attested_frontier: frontier,
                },
            )]));
        }
        TopologySchedule::single(Arc::new(head))
    }

    /// A schedule whose root shard is under a halt recovery seated at
    /// epoch 20 and frozen at `frontier`, with one-second windows: the
    /// bridge is epoch 21, so an anchor under 21s lies below the bridge,
    /// at or below the frontier and above it alike.
    fn make_test_topology_bridged_at_20(frontier: BlockHeight) -> TopologySchedule {
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
            ShardId::ROOT,
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at: Epoch::new(20),
                retained: vec![ValidatorId::new(0)],
                attested_frontier: frontier,
            },
        );
        TopologySchedule::new(
            1_000,
            Epoch::GENESIS,
            Arc::new(
                TopologySnapshot::new(
                    NetworkDefinition::simulator(),
                    1,
                    ValidatorSet::new(validators),
                )
                .with_pending_recoveries(recoveries),
            ),
        )
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
                tx.price(&PriceTable::GENESIS),
                Joins::Executes,
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

    /// Code this node can run, minus whatever a test withholds.
    #[derive(Default)]
    struct TestCode(Mutex<BTreeSet<Hash>>);

    impl TestCode {
        fn withholding(package: Hash) -> Arc<Self> {
            Arc::new(Self(Mutex::new(BTreeSet::from([package]))))
        }

        /// Let the withheld package resolve, as a landed fetch does.
        fn release(&self, package: Hash) {
            self.0.lock().expect("test code lock").remove(&package);
        }
    }

    impl CodeAvailability for TestCode {
        fn can_run(&self, package: Hash) -> bool {
            !self.0.lock().expect("test code lock").contains(&package)
        }
    }

    fn make_test_state() -> ExecutionCoordinator {
        make_test_state_for(ValidatorId::new(0))
    }

    fn make_test_state_for(me: ValidatorId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, ShardId::ROOT, Arc::new(TestCode::default()))
    }

    fn make_test_state_for_shard(me: ValidatorId, local_shard: ShardId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, local_shard, Arc::new(TestCode::default()))
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
        let actions = state
            .commit_block_carrying(&topology_schedule, &certify(block), Naming::Composed)
            .actions;

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

    /// A tick seats whatever the block named, and waits at the
    /// dispatch head for code this node has not fetched.
    ///
    /// Membership is what the committee votes over, so it cannot turn on
    /// local holdings; running a member whose code is missing would reach
    /// the engine's no-code refusal while every replica holding the bytes
    /// settled it. So the tick is composed either way and held here, and
    /// what dispatches when the fetch lands is the tick composed now.
    ///
    /// Nothing reports the shortfall beforehand: the coordinator is
    /// asked, which is all a shard seated mid-epoch and handed a tick
    /// has to go on. The held tick names the code it waits on, so the
    /// fetch does not hang on whatever else asked for it.
    #[test]
    fn a_tick_waits_at_the_dispatch_head_for_code_this_node_lacks() {
        let package = Hash::from_bytes(b"a package this node has not fetched");
        let code = TestCode::withholding(package);
        let mut state =
            ExecutionCoordinator::new(ValidatorId::new(0), ShardId::ROOT, Arc::clone(&code) as _);
        let topology_schedule = make_test_topology();

        let tx = test_transaction_running(1, &[package]);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let actions = state
            .commit_block_carrying(&topology_schedule, &certify(block), Naming::Composed)
            .actions;

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
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch(FetchRequest::Packages { wanted }) if *wanted == [package]
            )),
            "the held tick asks for the code it waits on"
        );

        // The fetch lands. Nothing reports it: the next commit seats
        // and dispatches as every commit does, and finds the head ready.
        code.release(package);
        let released = state
            .commit_block_carrying(
                &topology_schedule,
                &certify(make_live_block(
                    BlockHeight::new(2),
                    2000,
                    ValidatorId::new(0),
                    vec![],
                )),
                Naming::Composed,
            )
            .actions;
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
            "the commit after the code lands releases exactly the tick that waited on it"
        );
    }

    /// A tick this node could not run comes back whole and runs again.
    ///
    /// The batch attested nothing, so nothing of the tick is spent. What
    /// returns to the dispatch head is the tick its committee composed,
    /// and the commit after it dispatches exactly that.
    #[test]
    fn a_tick_the_engine_could_not_run_is_dispatched_again() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();

        let package = Hash::from_bytes(b"code this node holds");
        let tx = test_transaction_running(1, &[package]);
        let tx_hash = tx.hash();
        let actions = state
            .commit_block_carrying(
                &topology_schedule,
                &certify(make_live_block(
                    BlockHeight::new(1),
                    1000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                )),
                Naming::Composed,
            )
            .actions;
        let Some(Action::ExecuteTransactions {
            tick,
            tick_ts,
            env,
            requests,
            included,
            ..
        }) = actions
            .into_iter()
            .find(|action| matches!(action, Action::ExecuteTransactions { .. }))
        else {
            panic!("a tick running code this node holds must dispatch");
        };

        // The environment refuses it. No receipt exists to attest, so
        // the tick is handed back rather than priced.
        let held =
            state.on_execution_batch_unavailable(tick, tick_ts, env, requests, included, package);
        assert!(
            held.is_empty(),
            "a tick handed back waits; it does not re-run on the spot"
        );

        let again = state
            .commit_block_carrying(
                &topology_schedule,
                &certify(make_live_block(
                    BlockHeight::new(2),
                    2000,
                    ValidatorId::new(0),
                    vec![],
                )),
                Naming::Composed,
            )
            .actions;
        let dispatched: Vec<TxHash> = again
            .iter()
            .filter_map(|action| match action {
                Action::ExecuteTransactions {
                    tick: dispatched_tick,
                    requests,
                    ..
                } if *dispatched_tick == tick => Some(requests),
                _ => None,
            })
            .flatten()
            .map(|request| request.tx_hash)
            .collect();
        assert_eq!(
            dispatched,
            vec![tx_hash],
            "the commit after the refusal dispatches the tick that came back, whole"
        );
    }

    /// A package nothing in the queued tick runs never holds it.
    #[test]
    fn an_unrelated_missing_package_holds_no_tick() {
        let mut state = ExecutionCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            TestCode::withholding(Hash::from_bytes(b"someone else's code")),
        );
        let topology_schedule = make_test_topology();

        let tx = test_transaction_running(1, &[Hash::from_bytes(b"code this node holds")]);
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let actions = state
            .commit_block_carrying(&topology_schedule, &certify(block), Naming::Composed)
            .actions;

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
        state.commit_block_carrying(&schedule, &test_certify(block, 1_000), Naming::Composed);

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
                refusal_receipts: vec![],
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
        // The commit folds under the window it is classified in; only the
        // vote's routing reads the schedule afterwards.
        state.commit_block_carrying(&resolved, &test_certify(block, 5_000), Naming::Composed);

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
                refusal_receipts: vec![],
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
        state0.commit_block_carrying(&topo0, &certify(block), Naming::Composed);
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
        state_leader.commit_block_carrying(&topo_leader, &certify(block_leader), Naming::Composed);
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
        state_non.commit_block_carrying(&topo_non, &certify(block_non), Naming::Composed);
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
        let mut state = make_test_state();
        state.commit_block_carrying(&topo, &certify(block), Naming::Composed);

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
        state_non.commit_block_carrying(&topo_non, &certify(block_non), Naming::Composed);

        assert!(!state_non.ticks.contains_tracker(&tick_id));
        assert!(state_non.ticks.contains_tick(&tick_id));

        // Simulate receiving a vote (as if we're a fallback leader).
        let fake_vote = ExecutionVote::new(
            WeightedTimestamp::ZERO,
            tick_id,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            leader,
            ConsensusSignature::ZERO,
        );

        state_non.on_execution_vote(&topo_non, fake_vote.into());

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
            WeightedTimestamp::ZERO,
            tick_id,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            outsider,
            ConsensusSignature::ZERO,
        );

        let actions = state.on_execution_vote(&topo, vote.into());
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
    fn test_vote_retry_timeout_addresses_the_attesting_committee() {
        use crate::ticks::VOTE_RETRY_TIMEOUT;
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();
        let committee = topo
            .head()
            .consensus_committee_for_shard(ShardId::ROOT)
            .to_vec();

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
                recipients,
                tick_id: wid,
                ..
            } => {
                assert_eq!(wid, &tick_id);
                assert_eq!(
                    recipients, &committee,
                    "a retry addresses the whole committee"
                );
            }
            other => panic!(
                "Expected SignAndSendExecutionVote, got {:?}",
                other.type_name()
            ),
        }

        // The retry is still tracked with its cooldown re-anchored at the
        // current committed timestamp — advance exactly one more
        // VOTE_RETRY_TIMEOUT and check that the second fire addresses the
        // committee too.
        state.committed_ts = state.committed_ts.plus(VOTE_RETRY_TIMEOUT);
        let next = state.check_vote_retry_timeouts(&topo);
        assert_eq!(next.len(), 1);
        if let Action::SignAndSendExecutionVote { recipients, .. } = &next[0] {
            assert_eq!(
                recipients, &committee,
                "the second fire addresses the committee"
            );
        } else {
            panic!("expected SignAndSendExecutionVote");
        }
    }

    /// With execution's committed clock frozen, the cleanup ticks re-send
    /// a held vote once per `VOTE_RETRY_TIMEOUT`: seven one-second ticks
    /// send nothing, the eighth one retry, the sixteenth a second. A change
    /// of the committed clock restarts the count.
    #[test]
    fn a_frozen_commit_clock_retries_once_per_timeout() {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let topo = make_test_topology();
        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(20);
        state.committed_ts = WeightedTimestamp::from_millis(10_000);
        state.ticks.record_vote_retry(
            tick_id,
            PendingVoteRetry {
                sent_at: WeightedTimestamp::from_millis(10_000),
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"block1")),
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );
        let second = Duration::from_secs(1);
        let retries = |actions: &[Action]| {
            actions
                .iter()
                .filter(|a| matches!(a, Action::SignAndSendExecutionVote { tick_id: t, .. } if *t == tick_id))
                .count()
        };

        // The first tick sees a new committed clock and starts counting.
        assert!(state.on_cleanup_tick(&topo, second).is_empty());
        let mut fired = Vec::new();
        for _ in 1..=16 {
            fired.push(retries(&state.on_cleanup_tick(&topo, second)));
        }
        let expected: Vec<usize> = (1..=16).map(|n| usize::from(n % 8 == 0)).collect();
        assert_eq!(fired, expected);

        state.committed_ts = WeightedTimestamp::from_millis(11_000);
        assert!(state.on_cleanup_tick(&topo, second).is_empty());
        for _ in 1..8 {
            assert_eq!(retries(&state.on_cleanup_tick(&topo, second)), 0);
        }
        assert_eq!(retries(&state.on_cleanup_tick(&topo, second)), 1);
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
            Capped::from_array([]),
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

    /// Every voter, the tick leader included, retries to the whole
    /// attesting committee, itself among the recipients: the first send is
    /// a unicast to the leader, and the retry makes each live member's
    /// tally the meeting point. The certificate the leader aggregates
    /// itself ends the retry.
    #[test]
    fn every_voter_retries_to_the_whole_attesting_committee() {
        use crate::ticks::VOTE_RETRY_TIMEOUT;
        let schedule = make_test_topology();
        let committee = schedule
            .head()
            .consensus_committee_for_shard(ShardId::ROOT)
            .to_vec();
        let height = BlockHeight::new(1);
        let leader = tick_leader(&TickId::new(ShardId::ROOT, height), &committee);

        let mut state = make_test_state_for(leader);
        let tick_id = ready_tick_at(&mut state, &schedule, height, 1_000);
        let sent_to = |actions: &[Action]| {
            actions.iter().find_map(|a| match a {
                Action::SignAndSendExecutionVote { recipients, .. } => Some(recipients.clone()),
                _ => None,
            })
        };
        assert_eq!(
            sent_to(&state.emit_vote_actions(&schedule)),
            Some(vec![leader])
        );

        state.committed_ts = state.committed_ts.plus(VOTE_RETRY_TIMEOUT);
        assert_eq!(
            sent_to(&state.check_vote_retry_timeouts(&schedule)),
            Some(committee),
            "the leader re-sends its vote to the whole committee, itself included",
        );

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        );
        state.on_certificate_aggregated(
            &schedule,
            &tick_id,
            &Arc::new(Verified::new_unchecked_for_test(cert)),
        );
        state.committed_ts = state.committed_ts.plus(VOTE_RETRY_TIMEOUT);
        assert_eq!(
            sent_to(&state.check_vote_retry_timeouts(&schedule)),
            None,
            "the certificate it aggregated ends the retry",
        );
    }

    /// An agreeing execution vote on `tick_id` from `voter`, anchored at
    /// `anchor_ms`, marked verified.
    fn verified_vote(
        tick_id: TickId,
        anchor_ms: u64,
        voter: ValidatorId,
    ) -> Verifiable<ExecutionVote> {
        Verified::new_unchecked_for_test(ExecutionVote::new(
            WeightedTimestamp::from_millis(anchor_ms),
            tick_id,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            voter,
            ConsensusSignature::ZERO,
        ))
        .into()
    }

    /// A member that is not the tick leader tallies the retried votes it
    /// is sent: two peers' retries seed its tracker, and its own retry,
    /// which addresses itself too, completes the quorum there.
    #[test]
    fn a_member_holding_every_retried_vote_certifies() {
        let schedule = make_test_topology();
        let committee = schedule
            .head()
            .consensus_committee_for_shard(ShardId::ROOT)
            .to_vec();
        let height = BlockHeight::new(1);
        let leader = tick_leader(&TickId::new(ShardId::ROOT, height), &committee);
        let mut members = committee.iter().copied().filter(|v| *v != leader);
        let me = members.next().expect("a non-leader");
        let peers: Vec<ValidatorId> = members.take(2).collect();

        let mut state = make_test_state_for(me);
        let tick_id = ready_tick_at(&mut state, &schedule, height, 1_000);
        let _ = state.emit_vote_actions(&schedule);
        assert!(
            !state.ticks.contains_tracker(&tick_id),
            "only the leader tallies at seat time"
        );

        let mut actions = Vec::new();
        for peer in &peers {
            actions
                .extend(state.on_execution_vote(&schedule, verified_vote(tick_id, 1_000, *peer)));
        }
        assert!(state.ticks.contains_tracker(&tick_id));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::AggregateExecutionCertificate { .. })),
            "two of four is short of quorum"
        );
        let own = state.on_execution_vote(&schedule, verified_vote(tick_id, 1_000, me));
        assert!(
            own.iter()
                .any(|a| matches!(a, Action::AggregateExecutionCertificate { .. })),
            "{own:?}"
        );
    }

    /// A single-shard topology of four validators, with the keys they
    /// sign under in validator order.
    fn keyed_topology() -> (TopologySchedule, Vec<BlsSigner>) {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .zip(0u64..)
            .map(|(key, seat)| ValidatorInfo {
                validator_id: ValidatorId::new(seat),
                public_key: key.public_key(),
            })
            .collect();
        let schedule = TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )));
        (schedule, keys)
    }

    /// `validator`'s vote for `outcomes` under their own root, as an
    /// honest member signs it.
    fn signed_vote(
        key: &BlsSigner,
        validator: ValidatorId,
        tick_id: TickId,
        anchor: WeightedTimestamp,
        outcomes: &[TxOutcome],
    ) -> Verifiable<ExecutionVote> {
        Verified::<ExecutionVote>::sign_local(
            &NetworkDefinition::simulator(),
            anchor,
            tick_id,
            Capped::new(outcomes.to_vec()).expect("a list written out in a test"),
            validator,
            key,
        )
        .expect("sign")
        .into_inner()
        .into()
    }

    /// `validator`'s vote for `outcomes` under their own root, signed
    /// over `message` in place of the message the vote makes.
    fn missigned_vote(
        key: &BlsSigner,
        validator: ValidatorId,
        tick_id: TickId,
        anchor: WeightedTimestamp,
        outcomes: &[TxOutcome],
        message: &ExecutionVoteMessage,
    ) -> Verifiable<ExecutionVote> {
        ExecutionVote::new(
            anchor,
            tick_id,
            compute_global_receipt_root(outcomes),
            Capped::new(outcomes.to_vec()).expect("a list written out in a test"),
            validator,
            key.sign(&signed_bytes(message, &NetworkDefinition::simulator()))
                .expect("sign"),
        )
        .into()
    }

    /// Run the crypto pool's half of a tally over `actions` and whatever
    /// they lead to: each batch verified and each quorum aggregated
    /// under real signatures, the result handed back as the node hands
    /// it. Returns how many certificates were aggregated.
    fn pool_votes(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        actions: Vec<Action>,
    ) -> usize {
        let net = NetworkDefinition::simulator();
        let mut pending = actions;
        let mut aggregated = 0usize;
        while let Some(action) = pending.pop() {
            match action {
                Action::VerifyAndAggregateExecutionVotes {
                    tick_id,
                    block_hash,
                    votes,
                } => {
                    let verified =
                        Verified::<ExecutionVote>::verify_batch(&BlsVerifier, &net, votes);
                    pending
                        .extend(state.on_votes_verified(schedule, tick_id, block_hash, verified));
                }
                Action::AggregateExecutionCertificate {
                    tick_id,
                    global_receipt_root,
                    votes,
                    committee,
                } => {
                    aggregated += 1;
                    let certificate = Verified::<ExecutionCertificate>::aggregate(
                        &BlsVerifier,
                        &tick_id,
                        global_receipt_root,
                        &votes,
                        &committee,
                    );
                    pending.extend(state.on_certificate_aggregated(
                        schedule,
                        &tick_id,
                        &Arc::new(certificate),
                    ));
                }
                _ => {}
            }
        }
        aggregated
    }

    /// Commit a one-transaction block at height 1 on `state` and land
    /// its execution. Returns the tick, the anchor its vote is cast at
    /// and the outcomes the vote carries.
    fn voted_tick(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
    ) -> (TickId, WeightedTimestamp, Vec<TxOutcome>) {
        let height = BlockHeight::new(1);
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(height, 1_000, ValidatorId::new(0), vec![Arc::new(tx)]);
        state.commit_block_carrying(schedule, &test_certify(block, 1_000), Naming::Composed);
        let tick_id = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the committed tx is assigned to a tick");
        let mut cast = state.on_execution_batch_completed(
            schedule,
            height,
            TickBatchOutcome {
                tick_id,
                results: vec![],
                tx_outcomes: vec![TxOutcome::new(tx_hash, ExecutionOutcome::Failed)],
                refusal_receipts: vec![],
            },
        );
        cast.extend(state.emit_vote_actions(schedule));
        let (anchor, outcomes) = cast
            .iter()
            .find_map(|action| match action {
                Action::SignAndSendExecutionVote {
                    vote_anchor_ts,
                    tx_outcomes,
                    ..
                } => Some((*vote_anchor_ts, tx_outcomes.clone())),
                _ => None,
            })
            .expect("the tick's vote is cast");
        (tick_id, anchor, outcomes)
    }

    /// A replica takes as its tick's certificate only one its committee's
    /// keys verify. The tick leader tallies two honest votes beside a
    /// committee member's vote carrying the honest outcomes and root,
    /// signed over a transaction count one higher. That vote counts
    /// toward nothing: the leader holds
    /// no certificate and goes on tallying, and the certificate a third
    /// honest vote completes is one every peer verifies.
    #[test]
    fn a_leader_takes_no_certificate_its_committee_does_not_verify() {
        let net = NetworkDefinition::simulator();
        let (schedule, keys) = keyed_topology();
        let committee = schedule
            .head()
            .consensus_committee_for_shard(ShardId::ROOT)
            .to_vec();
        let key_of = |validator: ValidatorId| {
            &keys[usize::try_from(validator.inner()).expect("a seat below four")]
        };
        let public_keys: Vec<ConsensusPublicKey> = committee
            .iter()
            .map(|validator| key_of(*validator).public_key())
            .collect();
        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: &public_keys,
        };
        let leader = tick_leader(&TickId::new(ShardId::ROOT, BlockHeight::new(1)), &committee);
        let others: Vec<ValidatorId> = committee
            .iter()
            .copied()
            .filter(|validator| *validator != leader)
            .collect();
        let (honest, late, stray) = (others[0], others[1], others[2]);

        {
            let mut state = make_test_state_for(leader);
            let (tick_id, anchor, outcomes) = voted_tick(&mut state, &schedule);
            let root = compute_global_receipt_root(&outcomes);
            let longer = [outcomes.clone(), outcomes.clone()].concat();
            let message =
                ExecutionVoteMessage::over(anchor, tick_id, root, &longer[..=outcomes.len()]);
            let vote_of =
                |validator| signed_vote(key_of(validator), validator, tick_id, anchor, &outcomes);
            let missigned =
                missigned_vote(key_of(stray), stray, tick_id, anchor, &outcomes, &message);
            let mut aggregated = 0;
            for vote in [vote_of(leader), vote_of(honest), missigned] {
                let actions = state.on_execution_vote(&schedule, vote);
                aggregated += pool_votes(&mut state, &schedule, actions);
            }
            assert_eq!(aggregated, 0, "two honest votes are short of quorum");
            assert!(state.exec_certs.get(&tick_id).is_none());
            assert!(
                state.ticks.contains_tracker(&tick_id),
                "it goes on tallying"
            );

            let actions = state.on_execution_vote(&schedule, vote_of(late));
            assert_eq!(pool_votes(&mut state, &schedule, actions), 1);
            let held = state
                .exec_certs
                .get(&tick_id)
                .expect("three honest votes certify the tick");
            assert_eq!(held.verify(&ctx).map(|_| ()), Ok(()));
        }
    }

    /// A member that admits the tick's complete local certificate stops
    /// tallying: a later vote is answered with the certificate, and nothing
    /// aggregates.
    #[test]
    fn a_complete_local_certificate_drops_the_tracker() {
        let schedule = make_test_topology();
        let committee = schedule
            .head()
            .consensus_committee_for_shard(ShardId::ROOT)
            .to_vec();
        let height = BlockHeight::new(1);
        let leader = tick_leader(&TickId::new(ShardId::ROOT, height), &committee);
        let mut state = make_test_state_for(leader);
        let tick_id = ready_tick_at(&mut state, &schedule, height, 1_000);
        assert!(state.ticks.contains_tracker(&tick_id));

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        );
        let _ = state.on_certificate_verified(
            &schedule,
            Ok(Arc::new(Verified::new_unchecked_for_test(cert))),
        );
        assert!(!state.ticks.contains_tracker(&tick_id));

        let late = *committee.iter().find(|v| **v != leader).expect("a peer");
        let actions = state.on_execution_vote(&schedule, verified_vote(tick_id, 1_000, late));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::BroadcastExecutionCertificate { recipients, .. } if recipients == &vec![late]
            )),
            "{actions:?}"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::AggregateExecutionCertificate { .. })),
            "{actions:?}"
        );
        assert!(!state.ticks.contains_tracker(&tick_id));
    }

    /// A projection of this shard's own certificate — the copy a
    /// counterpart is sent, reaching a validator that also sits in that
    /// counterpart's committee — cannot settle the tick, so it leaves the
    /// vote retry running and the serving slot free for the complete copy.
    #[test]
    fn a_projection_of_the_own_certificate_keeps_the_vote_retry() {
        use hyperscale_types::compute_global_receipt_root;

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
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        let outcomes: Vec<TxOutcome> = [1u8, 2]
            .into_iter()
            .map(|byte| {
                TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&[byte; 32])),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        let kept = outcomes[0].tx_hash();
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let projection = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("two outcomes"),
            AggregateSignature::ZERO,
            signers,
        )
        .project_to(&HashSet::from([kept]))
        .expect("the tick carries it");
        state.on_certificate_verified(
            &topo,
            Ok(Arc::new(Verified::new_unchecked_for_test(projection))),
        );

        assert!(!state.ticks.is_ec_dispatched(&tick_id));
        assert!(state.exec_certs.get(&tick_id).is_none());
        state.committed_ts = WeightedTimestamp::from_millis(5_000).plus(VOTE_RETRY_TIMEOUT);
        let actions = state.check_vote_retry_timeouts(&topo);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndSendExecutionVote { .. })),
            "the retry still fires: {actions:?}"
        );
    }

    /// A tick anchors on its own block's parent QC, never on the clock of
    /// whatever this node committed last: the anchor keys the vote tally,
    /// so two replicas that folded the same block at different points in
    /// their own commit streams must still vote the same anchor.
    #[test]
    fn a_tick_anchors_on_its_own_blocks_parent_qc() {
        let topo = make_topology();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(5);
        state.committed_ts = WeightedTimestamp::from_millis(99_000);
        state.commit_block_carrying(&topo, &test_certify(block, 1_000), Naming::Composed);

        let anchor = state
            .ticks
            .ticks_iter()
            .next()
            .map(|(_, tick)| tick.vote_anchor_ts())
            .expect("the block seats a tick");
        assert_eq!(anchor, WeightedTimestamp::from_millis(1_000));
    }

    /// A vote arriving after the certificate is out comes from a voter
    /// that never received it, and is answered with it.
    #[test]
    fn a_late_vote_is_answered_with_the_certificate() {
        let tx = test_transaction(1);
        let topo = make_topology();
        let committee = topo.head().committee_for_shard(ShardId::ROOT).to_vec();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let mut state = make_test_state();
        state.commit_block_carrying(&topo, &certify(block), Naming::Composed);
        let tick_id = state
            .ticks
            .ticks_iter()
            .next()
            .map(|(id, _)| *id)
            .expect("the block seats a tick");

        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        state.exec_certs.insert(Arc::clone(&certificate));
        state.ticks.mark_ec_dispatched(tick_id);

        let voter = committee[1];
        let late = ExecutionVote::new(
            WeightedTimestamp::ZERO,
            tick_id,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
            voter,
            ConsensusSignature::ZERO,
        );
        let actions = state.on_execution_vote(&topo, late.into());

        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::BroadcastExecutionCertificate { certificate: sent, recipients, .. }
                    if recipients == &vec![voter] && sent.tick_id() == &tick_id
            )),
            "the late voter is sent the certificate: {actions:?}"
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
            Capped::from_array([TxOutcome::new(
                covered_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )]),
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

    /// A certificate dispatched to verify before its shard's recovery
    /// folded here, and verified after, is refused in the recovery's
    /// band, pending or cleared: it settles nothing the recovered shard
    /// keeps. One at the frontier is admitted.
    #[test]
    fn a_certificate_verified_after_its_shards_recovery_folds_is_refused_in_its_band() {
        let at = |height: u64| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(ShardId::ROOT, BlockHeight::new(height)),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&height.to_le_bytes())),
                    ExecutionOutcome::Aborted,
                )]),
                AggregateSignature::ZERO,
                quorum_signers(),
            )))
        };
        let admitted = |actions: &[Action]| {
            actions.iter().any(|action| {
                matches!(
                    action,
                    Action::Continuation(ProtocolEvent::ExecutionCertificateAdmitted { .. })
                )
            })
        };
        for pending in [true, false] {
            let topo = make_test_topology_recovering(ShardId::ROOT, BlockHeight::new(5), pending);
            let mut state = make_test_state();
            let actions = state.on_certificate_verified(&topo, Ok(at(6)));
            assert!(
                !admitted(&actions)
                    && actions
                        .iter()
                        .any(|action| matches!(action, Action::AbandonFetch(..))),
                "pending {pending}: a band certificate is dropped: {actions:?}",
            );
            let mut state = make_test_state();
            let actions = state.on_certificate_verified(&topo, Ok(at(5)));
            assert!(admitted(&actions), "pending {pending}: {actions:?}");
        }
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
            Capped::from_array([TxOutcome::new(
                covered_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )]),
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
            Capped::new(outcomes).expect("a list written out in a test"),
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

    /// A tick of pure legs owes its certificate to nobody: the venue reads
    /// each leg's crossing off the record pushed to it. The certificate
    /// goes to this shard's own peers alone, and nothing is tracked for
    /// re-broadcast.
    #[test]
    fn a_leg_only_tick_projects_nothing_and_tracks_nothing() {
        use hyperscale_types::compute_global_receipt_root;

        use crate::fixtures::{leaf, payer, swap, trie};

        let (local, venue) = (leaf(0), leaf(1));
        let tick_id = TickId::new(local, BlockHeight::new(1));
        let topo = make_test_topology();
        let mut state = make_test_state();
        let leg = TxHash::from(Hash::from_bytes(b"leg"));
        let mut tick = TickState::new(tick_id, BlockHash::ZERO, WeightedTimestamp::ZERO);
        tick.admit(
            leg,
            Membership::of(&Member::of(
                Classified::freeze(&swap(), payer(), &[], &trie()),
                local,
                BTreeSet::from([local, venue]),
            )),
            10,
            Joins::Executes,
        );
        state.ticks.insert_tick(tick_id, tick);

        let outcomes = vec![TxOutcome::new(
            leg,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        let cert = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let actions = state.on_certificate_aggregated(
            &topo,
            &tick_id,
            &Arc::new(Verified::new_unchecked_for_test(cert)),
        );

        let broadcasts: Vec<ShardId> = actions
            .iter()
            .filter_map(|action| match action {
                Action::BroadcastExecutionCertificate { shard, .. } => Some(*shard),
                _ => None,
            })
            .collect();
        assert_eq!(broadcasts, vec![state.local_shard], "local peers only");
        assert_eq!(state.outbound_certs.memory_stats().tracked_certificates, 0);
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
            Capped::new(outcomes).expect("a list written out in a test"),
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([ec]),
                Capped::from_array([]),
            )
            .into(),
        );
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        ));
        let tick = Arc::new(Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([ec]),
            Capped::from_array([]),
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([ec]),
                Capped::from_array([]),
            )
            .into(),
        );
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([ec]),
                Capped::from_array([]),
            )
            .into(),
        );
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        ));
        let tick = Arc::new(Verified::new_unchecked_for_test(Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([ec]),
            Capped::from_array([]),
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
            Capped::from_array([]),
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

    /// The recovery band: an EC anchored below a recovery's bridge above
    /// its attested frontier is dropped without dispatching
    /// verification, while the recovery is pending and once its record
    /// has cleared alike: the replaced committee's certificate for a tick
    /// the recovered chain discards. One at or below the frontier is
    /// pre-halt history and still dispatches.
    #[test]
    fn on_execution_certificate_refuses_an_ec_in_a_recovery_band() {
        let recovering = ShardId::ROOT;
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec_at = |height: u64| {
            ExecutionCertificate::new(
                TickId::new(recovering, BlockHeight::new(height)),
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([]),
                AggregateSignature::ZERO,
                signers.clone(),
            )
        };

        for pending in [true, false] {
            let topo = make_test_topology_recovering(recovering, BlockHeight::new(5), pending);
            let mut state = make_test_state();
            let orphan = state.on_execution_certificate(&topo, ec_at(6).into());
            assert!(
                matches!(
                    orphan.as_slice(),
                    [Action::AbandonFetch(FetchIds::ExecutionCerts(..))]
                ),
                "pending {pending}: an EC in the band is dropped, got {orphan:?}"
            );

            let mut state = make_test_state();
            let suffix = state.on_execution_certificate(&topo, ec_at(5).into());
            assert!(
                matches!(
                    suffix.as_slice(),
                    [Action::VerifyExecutionCertificateSignature { .. }]
                ),
                "pending {pending}: an EC within the frontier dispatches, got {suffix:?}"
            );
        }
    }

    /// Production epoch lengths, for the recovery fixtures below.
    const PRODUCTION_EPOCH_MS: u64 = 300_000;

    /// A two-shard schedule of production-length windows in which the
    /// second shard's halt recovery is pending: its fresh committee
    /// seated at epoch 20, bridge 21, frozen at height 5. Answers the
    /// schedule, the local shard and the recovered one.
    fn pending_recovery_at_production_epochs() -> (TopologySchedule, ShardId, ShardId) {
        let epoch_ms = PRODUCTION_EPOCH_MS;
        let (local, recovered) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let frontier = BlockHeight::new(5);
        let validators: Vec<ValidatorInfo> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let snapshot = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(validators),
            )
            .with_recoveries(BTreeMap::from([(
                recovered,
                vec![RecoveryBinding {
                    rotated_at: Epoch::new(20),
                    attested_frontier: frontier,
                    completed: false,
                }],
            )]))
            .with_pending_recoveries(BTreeMap::from([(
                recovered,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(20),
                    retained: Vec::new(),
                    attested_frontier: frontier,
                },
            )])),
        );
        let mut schedule = TopologySchedule::new(epoch_ms, Epoch::new(19), Arc::clone(&snapshot));
        for epoch in 20..=21 {
            schedule.insert(Epoch::new(epoch), Arc::clone(&snapshot));
        }
        (schedule, local, recovered)
    }

    /// A fresh committee's certificate anchored at its recovery's bridge,
    /// above the frontier, verifies at a counterpart while the recovery
    /// is pending, at production epoch lengths. Its source block's commit
    /// proof survives the proof mirror's retirement while the record
    /// stands, so a copy arriving after the proof dispatches at once, and
    /// a copy arriving first parks on the proof and is replayed when the
    /// proof lands, in the bridge window and not two folds past it. The
    /// replaced committee's certificate at a harvested height, anchored
    /// below the bridge, loses its proof to the same retirement and is
    /// refused.
    #[test]
    fn a_fresh_certificate_at_the_bridge_verifies_while_the_recovery_is_pending() {
        let epoch_ms = PRODUCTION_EPOCH_MS;
        let (schedule, local, recovered) = pending_recovery_at_production_epochs();
        let (fresh_ts, harvested_ts) = (
            WeightedTimestamp::from_millis(21 * epoch_ms + 100),
            WeightedTimestamp::from_millis(20 * epoch_ms + 100),
        );
        let proof = |height: u64, ts| Anchor {
            shard: recovered,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts,
        };
        let certificate = |height: u64, ts| {
            ExecutionCertificate::new(
                TickId::new(recovered, BlockHeight::new(height)),
                ts,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&height.to_le_bytes())),
                    ExecutionOutcome::Aborted,
                )]),
                AggregateSignature::ZERO,
                quorum_signers(),
            )
        };
        let dispatched = |actions: &[Action]| {
            actions
                .iter()
                .any(|action| matches!(action, Action::VerifyExecutionCertificateSignature { .. }))
        };

        // The proof first, retired as every commit retires the mirror.
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        state.proven_anchors().record(proof(10, fresh_ts));
        state.proven_anchors().record(proof(9, harvested_ts));
        state.proven_anchors().forget_orphaned(&schedule);
        assert!(
            state
                .proven_anchors()
                .at(recovered, BlockHeight::new(10))
                .is_some()
        );
        assert!(
            state
                .proven_anchors()
                .at(recovered, BlockHeight::new(9))
                .is_none()
        );
        let actions = state.on_execution_certificate(&schedule, certificate(10, fresh_ts).into());
        assert!(
            dispatched(&actions),
            "the fresh certificate verifies: {actions:?}"
        );

        // The certificate first: it parks on the proof and the proof
        // replays it.
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        assert!(
            state
                .on_execution_certificate(&schedule, certificate(10, fresh_ts).into())
                .is_empty()
        );
        state.proven_anchors().record(proof(10, fresh_ts));
        state.proven_anchors().forget_orphaned(&schedule);
        let actions = state.on_committed_remote_header(&schedule, proof(10, fresh_ts));
        assert!(
            dispatched(&actions),
            "the parked certificate verifies: {actions:?}"
        );

        // The replaced committee's, at a harvested height, is refused.
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        state.proven_anchors().record(proof(9, harvested_ts));
        let actions =
            state.on_execution_certificate(&schedule, certificate(9, harvested_ts).into());
        assert!(
            matches!(
                actions.as_slice(),
                [Action::AbandonFetch(FetchIds::ExecutionCerts(..))]
            ),
            "a band certificate is refused: {actions:?}",
        );
    }

    /// While a recovery is pending, the prober asks a counterpart only at
    /// an anchor a block's admission takes a claim at: the proof mirror
    /// forgets the harvested and coast blocks above the frontier, so
    /// before the fresh chain's first proof lands the newest anchor it
    /// offers is the frontier's, and once that proof lands it is the
    /// fresh block's, kept through every retirement while the record
    /// stands.
    #[test]
    fn a_prober_offers_only_claims_admission_takes_while_a_recovery_is_pending() {
        let epoch_ms = PRODUCTION_EPOCH_MS;
        let (schedule, local, recovered) = pending_recovery_at_production_epochs();
        let state = make_test_state_for_shard(ValidatorId::new(0), local);
        let anchors = state.proven_anchors();
        let proof = |height: u64, ts_ms: u64| Anchor {
            shard: recovered,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(ts_ms),
        };
        let now = WeightedTimestamp::from_millis(22 * epoch_ms);
        let admitted = |anchor: Anchor| {
            !schedule.head().recovery_orphaned(
                schedule.windows(),
                anchor.shard,
                anchor.ts,
                anchor.height,
            )
        };
        for (height, ts_ms) in [
            (5, 19 * epoch_ms),
            (9, 19 * epoch_ms + 1),
            (11, 20 * epoch_ms),
        ] {
            anchors.record(proof(height, ts_ms));
        }
        anchors.forget_orphaned(&schedule);
        let offered = anchors
            .newest_licensed(recovered, now, |_| true)
            .expect("the frontier's proof stands");
        assert_eq!(offered.height, BlockHeight::new(5));
        assert!(admitted(offered));

        anchors.record(proof(12, 21 * epoch_ms + 100));
        anchors.forget_orphaned(&schedule);
        let offered = anchors
            .newest_licensed(recovered, now, |_| true)
            .expect("the fresh block's proof stands");
        assert_eq!(offered.height, BlockHeight::new(12));
        assert!(admitted(offered));
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
            Capped::from_array([TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"deferred_tx")),
                ExecutionOutcome::Aborted,
            )]),
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        let actions = state.on_execution_certificate(&topo, cert.into());
        assert!(
            actions.is_empty(),
            "an EC from an unproven source block must defer, got {actions:?}"
        );

        // The commit proof lands: the deferred EC replays into dispatch.
        let proven = Anchor {
            shard: remote_shard,
            height: BlockHeight::new(5),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        };
        state.proven_anchors().record(proven);
        let actions = state.on_committed_remote_header(&topo, proven);
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
                Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
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
            Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
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
                Capped::from_array([TxOutcome::new(
                    TxHash::from(Hash::from_bytes(&height.to_le_bytes())),
                    ExecutionOutcome::Aborted,
                )]),
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
            Capped::from_array([]),
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
            Capped::from_array([]),
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
            Capped::from_array([]),
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers_a,
        );
        let incoming = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([]),
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([ec]),
                Capped::from_array([]),
            )
            .into(),
        );
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let raw_finalization = Finalization::new(
            tick_id,
            TickHalf::Determined,
            &Capped::from_array([ec]),
            Capped::from_array([]),
        );
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            SignerBitfield::empty(), // no signers — far below 2f+1
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([bogus_ec]),
                Capped::from_array([]),
            )
            .into(),
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
            Capped::from_array([TxOutcome::new(
                cross_shard_tx,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )]),
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
            Capped::from_array([TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"untracked_tx")),
                ExecutionOutcome::Aborted,
            )]),
            AggregateSignature::ZERO,
            quorum_signers(),
        );

        // The source block is commit-proven; the gate under test is verify
        // dispatch without a local tracker, not the commit-proof gate.
        let proven = Anchor {
            shard: remote_shard,
            height: BlockHeight::new(5),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        };
        state.proven_anchors().record(proven);
        state.on_committed_remote_header(&topo, proven);
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
        let mut boundaries = BTreeMap::new();
        boundaries.insert(
            shard,
            ShardAnchor {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
                height,
                weighted_timestamp: WeightedTimestamp::from_millis(1),
                witness_base: BeaconWitnessLeafCount::ZERO,
                terminal_settled_txs: None,
                handoff_complete: None,
                terminal_epoch: None,
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
            Capped::from_array([]),
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
        coord.commit_block_carrying(&schedule, &test_certify(block, ED), Naming::Composed);
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
                WeightedTimestamp::from_millis(ED),
                tick_id,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([]),
                ValidatorId::new(v),
                ConsensusSignature::ZERO,
            );
            actions.extend(
                coord.on_execution_vote(&schedule, Verified::new_unchecked_for_test(vote).into()),
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

    /// A member seated but not yet Ready sits in the committee and outside
    /// its consensus set. Every verifier indexes an EC's signers into the
    /// consensus set, so the aggregator must too: with the not-Ready member
    /// mid-list, indexing the full committee shifts every signer after it
    /// and no peer can verify the certificate.
    #[test]
    fn local_aggregation_indexes_the_consensus_members() {
        let shard = ShardId::ROOT;
        let ids = [4u64, 5, 6, 7];
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| ValidatorInfo {
                validator_id: ValidatorId::new(id),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let members: Vec<ValidatorId> = ids.iter().map(|&id| ValidatorId::new(id)).collect();
        let ready = vec![
            ValidatorId::new(4),
            ValidatorId::new(6),
            ValidatorId::new(7),
        ];
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            HashMap::from([(shard, members)]),
            HashMap::from([(shard, ready.clone())]),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        let schedule = TopologySchedule::single(Arc::new(snapshot));

        let mut coord = make_test_state_for(ValidatorId::new(4));
        let block = make_live_block(
            BlockHeight::new(1),
            1,
            ValidatorId::new(4),
            vec![Arc::new(test_transaction(1))],
        );
        coord.commit_block_carrying(&schedule, &test_certify(block, 1), Naming::Composed);
        let tick_id = coord
            .ticks
            .ticks_iter()
            .next()
            .map(|(w, _)| *w)
            .expect("local-only tick created on commit");

        let mut actions = Vec::new();
        for v in [4u64, 6, 7] {
            let vote = ExecutionVote::new(
                WeightedTimestamp::from_millis(1),
                tick_id,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([]),
                ValidatorId::new(v),
                ConsensusSignature::ZERO,
            );
            actions.extend(
                coord.on_execution_vote(&schedule, Verified::new_unchecked_for_test(vote).into()),
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
            *committee, ready,
            "the EC's bitfield indexes the consensus members, not the full committee",
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
            Capped::from_array([]),
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
        let drained = coord.on_beacon_block_persisted(&caught_up).actions;
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
            Capped::from_array([]),
            AggregateSignature::ZERO,
            signers,
        ));
        let tick: Arc<Verifiable<Finalization>> = Arc::new(
            Finalization::new(
                tick_id,
                TickHalf::Determined,
                &Capped::from_array([ec]),
                Capped::from_array([]),
            )
            .into(),
        );
        let _fw_hash = tick.receipt_hash();

        let actions = coord.admit_finalization(&behind, Arc::clone(&tick));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyFinalization { .. })),
            "a finalization whose EC epoch the beacon hasn't reached must buffer, not dispatch",
        );

        let caught_up = TopologySchedule::single(Arc::new(committee_snapshot(&[0, 1, 2, 3]).0));
        let drained = coord.on_beacon_block_persisted(&caught_up).actions;
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
            actions.iter().any(|a| matches!(
                a,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::ExecutionCerts(..),
                    ..
                })
            )),
            "fallback fetch must keep firing while the expectation is retained"
        );

        // Once the local tick resolves (simulating finalize), the
        // expectation is no longer needed and gets pruned.
        state.ticks.remove_tick(&local_tick);
        state.ticks.remove_assignment(tx_hash);
        state.committed_height = BlockHeight::new(600);
        state.committed_ts = WeightedTimestamp::from_millis(120_000);
        let actions = state.check_exec_cert_timeouts();
        assert_eq!(
            state.expected_certs.expected_len(),
            0,
            "expectation must be pruned once no tick needs the source shard"
        );
        // The fallback fetch fired above and the certificate never came,
        // which is what the prune means. Nothing else answers the id, so
        // the prune has to retire it.
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::ExecutionCerts(ids))
                    if ids == &vec![(remote_shard, tx_hash)]
            )),
            "pruning an expectation must abandon its fetch, got: {actions:?}"
        );
    }

    /// The ledger asks for a counterpart's certificate under the same
    /// fetch ids, one-shot, for transactions no tick speaks for. Retiring
    /// the expectation tracker's copy must not cancel that ask — a fetch
    /// binding with a second producer has no refcount.
    #[test]
    fn pruning_an_expectation_leaves_the_ledgers_own_ask_alone() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();

        state
            .expected_certs
            .register(PEER, tx_hash, state.committed_ts);

        // The ledger holds the transaction and nothing committed has
        // settled what it waits on, so the counterpart's certificate is
        // still worth having here.
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &Classified::whole())],
        );
        assert!(state.counterparts.ledger.awaits_certificate(tx_hash));

        state.committed_height = BlockHeight::new(600);
        state.committed_ts = WeightedTimestamp::from_millis(120_000);
        let actions = state.check_exec_cert_timeouts();

        assert_eq!(state.expected_certs.expected_len(), 0);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchIds::ExecutionCerts(..)))),
            "the ledger still wants the certificate, got: {actions:?}"
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
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            });
        }

        // The tick votes, and the local EC over that vote lands; same
        // tick_id flips `local_ec_emitted` to true.
        let (anchor, root, tx_outcomes) = tick.build_vote_data().expect("every member came back");
        let local_ec = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            anchor,
            root,
            Capped::new(tx_outcomes).expect("a list written out in a test"),
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

        let _actions = state.finalize(&tick_id);

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

    /// A recovery drops every tick below its bridge at the shard's
    /// crossing block and at no other: the first commit anchored at or
    /// past the bridge whose parent is anchored below it. Every tick the
    /// registry holds goes, at or below the frontier and above it alike,
    /// and the tick chain floor rises to the crossing block's parent
    /// height. A commit of the harvested tail, of a coast block, or of a
    /// block past the crossing drops nothing.
    #[test]
    fn the_crossing_commit_drops_every_tick_below_the_bridge() {
        let mut schedule = make_test_topology_bridged_at_20(BlockHeight::new(1));
        let head = Arc::clone(schedule.head());
        for epoch in 1..=30 {
            schedule.insert(Epoch::new(epoch), Arc::clone(&head));
        }
        let hold = |state: &mut ExecutionCoordinator, height: u64, anchor_ms: u64| {
            let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(height));
            let tx = Arc::new(Verified::new_unchecked_for_test(test_transaction(
                u8::try_from(height).unwrap(),
            )));
            state.ticks.insert_tick(
                tick_id,
                tick_holding(
                    tick_id,
                    WeightedTimestamp::from_millis(anchor_ms),
                    vec![(tx, BTreeSet::from([ShardId::ROOT]))],
                ),
            );
            tick_id
        };
        let at = |state: &mut ExecutionCoordinator, height: u64, parent_ms: u64, anchor_ms: u64| {
            state.committed_height = BlockHeight::new(height - 1);
            state.committed_ts = WeightedTimestamp::from_millis(parent_ms);
            let block = test_certify(
                make_live_block(BlockHeight::new(height), 0, ValidatorId::new(0), vec![]),
                anchor_ms,
            );
            state.cross_a_bridge(
                &schedule,
                WeightedTimestamp::from_millis(parent_ms),
                block.block(),
            )
        };

        let mut state = make_test_state();
        let frontier = hold(&mut state, 1, 2_500);
        let tail = hold(&mut state, 2, 2_600);
        for (height, parent_ms, anchor_ms) in [(3, 2_600, 2_900), (4, 2_900, 20_900)] {
            let (raised, dropped) = at(&mut state, height, parent_ms, anchor_ms);
            assert!(
                raised.is_empty() && dropped.is_empty(),
                "a block anchored below the bridge drops nothing",
            );
        }
        let (raised, dropped) = at(&mut state, 5, 20_900, 21_100);
        assert_eq!(dropped, vec![frontier, tail]);
        assert!(matches!(
            raised.as_slice(),
            [Action::RaiseTickFloor { floor }] if *floor == BlockHeight::new(4)
        ));
        assert!(state.ticks.get_tick(&frontier).is_none());
        assert!(state.ticks.get_tick(&tail).is_none());

        let fresh = hold(&mut state, 5, 21_100);
        let (raised, dropped) = at(&mut state, 6, 21_100, 21_200);
        assert!(raised.is_empty() && dropped.is_empty());
        assert!(state.ticks.get_tick(&fresh).is_some());
    }

    /// A two-committee schedule for one shard under a halt recovery: the
    /// replaced committee (validators 0 to 3) seated from epoch 2, the
    /// fresh one (4 to 7) seated at epoch 20 with the bridge at 21 and
    /// one-second windows, frozen at `frontier`. Returns the schedule
    /// with the two committees.
    fn make_test_topology_redrawn(
        frontier: BlockHeight,
    ) -> (TopologySchedule, Vec<ValidatorId>, Vec<ValidatorId>) {
        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let fresh: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let snap = |committee: &[ValidatorId]| {
            Arc::new(TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                1,
                &set,
                std::iter::once((ShardId::ROOT, committee.to_vec())).collect(),
            ))
        };
        let mut recoveries = BTreeMap::new();
        recoveries.insert(
            ShardId::ROOT,
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at: Epoch::new(20),
                retained: old.clone(),
                attested_frontier: frontier,
            },
        );
        let fresh_snap = Arc::new(
            snap(&fresh)
                .as_ref()
                .clone()
                .with_pending_recoveries(recoveries),
        );
        let mut schedule = TopologySchedule::new(1_000, Epoch::new(2), snap(&old));
        schedule.insert(Epoch::new(21), Arc::clone(&fresh_snap));
        schedule.set_head(fresh_snap);
        (schedule, old, fresh)
    }

    /// Commit a one-transaction block at `height` anchored at `anchor_ms`
    /// on `state` and land its execution, so its tick is ready to vote.
    fn ready_tick_at(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        height: BlockHeight,
        anchor_ms: u64,
    ) -> TickId {
        let tx = test_transaction(u8::try_from(height.inner()).unwrap());
        let tx_hash = tx.hash();
        let block = make_live_block(height, anchor_ms, ValidatorId::new(0), vec![Arc::new(tx)]);
        state.commit_block_carrying(schedule, &test_certify(block, anchor_ms), Naming::Composed);
        let tick_id = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the committed tx is assigned to a tick");
        state.on_execution_batch_completed(
            schedule,
            height,
            TickBatchOutcome {
                tick_id,
                results: vec![],
                tx_outcomes: vec![TxOutcome::new(tx_hash, ExecutionOutcome::Failed)],
                refusal_receipts: vec![],
            },
        );
        tick_id
    }

    /// No replica that has folded a halt recovery signs a tick anchored
    /// below its bridge, a fresh member or a replaced one, above the
    /// frontier or at it: the crossing block discards every such tick, and
    /// its certificate would settle at a counterpart what the recovered
    /// shard lets go of.
    #[test]
    fn a_tick_anchored_below_a_bridge_is_signed_by_no_replica_that_folded_it() {
        let frontier = BlockHeight::new(5);
        let (schedule, old, fresh) = make_test_topology_redrawn(frontier);
        for me in [old[1], fresh[1]] {
            for (height, anchor_ms) in [(frontier.next(), 2_500), (frontier, 2_400)] {
                let mut state = make_test_state_for(me);
                ready_tick_at(&mut state, &schedule, height, anchor_ms);
                let actions = state.emit_vote_actions(&schedule);
                assert!(
                    !actions
                        .iter()
                        .any(|action| matches!(action, Action::SignAndSendExecutionVote { .. })),
                    "{me:?} signs the tick at {height:?}: {actions:?}",
                );
            }
        }
    }

    /// A batch the environment hands back for a tick anchored below a
    /// recovery's bridge, folded while the batch was out, runs nowhere
    /// again: neither the next write nor the next commit dispatches it.
    #[test]
    fn a_batch_handed_back_below_a_bridge_runs_nowhere_again() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();
        let package = Hash::from_bytes(b"code this node holds");
        let tx = test_transaction_running(1, &[package]);
        let actions = state
            .commit_block_carrying(
                &topology_schedule,
                &certify(make_live_block(
                    BlockHeight::new(1),
                    1000,
                    ValidatorId::new(0),
                    vec![Arc::new(tx)],
                )),
                Naming::Composed,
            )
            .actions;
        let Some(Action::ExecuteTransactions {
            tick,
            tick_ts,
            env,
            requests,
            included,
            ..
        }) = actions
            .into_iter()
            .find(|action| matches!(action, Action::ExecuteTransactions { .. }))
        else {
            panic!("a tick running code this node holds must dispatch");
        };
        let bridged = make_test_topology_bridged_at_20(BlockHeight::GENESIS);
        let _ =
            state.on_execution_batch_unavailable(tick, tick_ts, env, requests, included, package);
        let written = state.on_block_persisted(&bridged, BlockHeight::new(1));
        assert!(
            !written
                .iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "a write dispatches a tick below the bridge again: {written:?}",
        );
        let again = state
            .commit_block_carrying(
                &bridged,
                &certify(make_live_block(
                    BlockHeight::new(2),
                    2000,
                    ValidatorId::new(0),
                    vec![],
                )),
                Naming::Composed,
            )
            .actions;
        assert!(
            !again.iter().any(|action| matches!(
                action,
                Action::ExecuteTransactions { tick: dispatched, .. } if *dispatched == tick
            )),
            "a tick below the bridge is dispatched again: {again:?}",
        );
    }

    /// A tick queued before this replica folded a recovery, waiting on the
    /// write of the block below it, is not dispatched by that write once
    /// the replica has folded it: the tick is anchored below the bridge,
    /// and no commit comes between to withhold it.
    #[test]
    fn a_tick_queued_before_the_fold_does_not_run_on_the_write_after_it() {
        let mut state = make_test_state();
        let topology_schedule = make_test_topology();
        let package = Hash::from_bytes(b"code this node holds");
        let _ = state.commit_block_carrying(
            &topology_schedule,
            &certify(make_live_block(
                BlockHeight::new(1),
                1000,
                ValidatorId::new(0),
                vec![],
            )),
            Naming::Composed,
        );
        let queued = state
            .commit_block_carrying(
                &topology_schedule,
                &certify(make_live_block(
                    BlockHeight::new(2),
                    2000,
                    ValidatorId::new(0),
                    vec![Arc::new(test_transaction_running(1, &[package]))],
                )),
                Naming::Composed,
            )
            .actions;
        assert!(
            !queued
                .iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "tick 2 waits for height 1 to be written: {queued:?}",
        );
        let ran = state.on_block_persisted(
            &make_test_topology_bridged_at_20(BlockHeight::GENESIS),
            BlockHeight::new(1),
        );
        assert!(
            !ran.iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "a write after the fold dispatches a tick below the bridge: {ran:?}",
        );
    }

    /// The anchors `state` re-signs `tick_id` at once its committed clock
    /// reads `committed_ms`.
    fn revoted_at(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        tick_id: TickId,
        committed_ms: u64,
    ) -> Vec<u64> {
        state.committed_ts = WeightedTimestamp::from_millis(committed_ms);
        state
            .revote_stalled_ticks(schedule)
            .iter()
            .filter_map(|action| match action {
                Action::SignAndSendExecutionVote {
                    tick_id: voted,
                    vote_anchor_ts,
                    ..
                } if *voted == tick_id => Some(vote_anchor_ts.as_millis()),
                _ => None,
            })
            .collect()
    }

    /// A tick still owing its determined half re-signs its vote once the
    /// committed clock passes each step on its anchor grid: never before
    /// the first, once per step, and at the step itself rather than the
    /// clock.
    #[test]
    fn a_stalled_tick_revotes_at_each_grid_point() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tick_id = ready_tick_at(&mut state, &schedule, BlockHeight::new(1), 1_000);
        assert!(
            !state.emit_vote_actions(&schedule).is_empty(),
            "the tick casts its own vote first",
        );
        let step = u64::try_from(REATTESTATION_STEP.as_millis()).unwrap();

        assert!(revoted_at(&mut state, &schedule, tick_id, 1_000 + step - 1).is_empty());
        assert_eq!(
            revoted_at(&mut state, &schedule, tick_id, 1_000 + step),
            vec![1_000 + step]
        );
        assert!(revoted_at(&mut state, &schedule, tick_id, 1_000 + step + 10).is_empty());
        assert_eq!(
            revoted_at(&mut state, &schedule, tick_id, 1_000 + 2 * step + 5),
            vec![1_000 + 2 * step],
        );
    }

    /// A tick anchored below a halt recovery's bridge is never re-signed,
    /// at a step below the bridge or past it, by a replaced member or a
    /// fresh one: re-signed past the bridge, its certificate would escape
    /// the recovery's band and resolve the fresh committee.
    #[test]
    fn a_tick_below_the_bridge_is_never_reattested_past_it() {
        let frontier = BlockHeight::new(5);
        let (mut schedule, old, fresh) = make_test_topology_redrawn(frontier);
        let step = u64::try_from(REATTESTATION_STEP.as_millis()).unwrap();
        let head = Arc::clone(schedule.head());
        let steps: Vec<u64> = (1..=(18_500 / step + 2))
            .map(|at| 2_500 + at * step)
            .collect();
        for &at in &steps {
            let reached = schedule.epoch_for(WeightedTimestamp::from_millis(at));
            if reached > Epoch::new(2) {
                schedule.insert(reached, Arc::clone(&head));
            }
        }
        // The same windows before this replica folded the recovery.
        let mut unfolded = schedule.clone();
        unfolded.set_head(Arc::new(
            (**schedule.head())
                .clone()
                .with_pending_recoveries(BTreeMap::new())
                .with_recoveries(BTreeMap::new()),
        ));
        for me in [old[0], fresh[0]] {
            for (height, anchor_ms) in [(frontier.next(), 2_500), (frontier, 2_400)] {
                let mut seated = make_test_state_for(me);
                let tick = ready_tick_at(&mut seated, &unfolded, height, anchor_ms);
                assert!(
                    !seated.emit_vote_actions(&unfolded).is_empty(),
                    "{me:?} signs the tick before it folds the recovery",
                );
                for &at in &steps {
                    assert!(
                        revoted_at(&mut seated, &schedule, tick, at).is_empty(),
                        "{me:?} re-signs the tick at {height:?} at {at}",
                    );
                }
            }
        }
    }

    /// A vote claiming a real member at an anchor no honest voter signs
    /// for the tick is refused before it takes a quorum or a buffer slot,
    /// so forging one per anchor cannot grow a tracker; a re-signed vote
    /// on the tick's grid is still tallied.
    #[test]
    fn a_vote_off_its_ticks_anchor_grid_is_refused() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tick_id = ready_tick_at(&mut state, &schedule, BlockHeight::new(1), 1_000);
        let step = u64::try_from(REATTESTATION_STEP.as_millis()).unwrap();
        state.committed_ts = WeightedTimestamp::from_millis(1_000 + step);
        let vote_at = |anchor_ms: u64| {
            ExecutionVote::new(
                WeightedTimestamp::from_millis(anchor_ms),
                tick_id,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([]),
                ValidatorId::new(1),
                ConsensusSignature::ZERO,
            )
        };

        // Off the grid, before the tick, and two steps past the clock.
        let forged = (1..=64).map(|i| 1_000 + i).chain([999, 1_000 + 3 * step]);
        for anchor_ms in forged {
            assert!(
                state
                    .on_execution_vote(&schedule, vote_at(anchor_ms).into())
                    .is_empty()
            );
        }
        assert_eq!(
            state
                .ticks
                .get_tracker(&tick_id)
                .map_or(0, VoteTracker::held_anchors),
            0,
            "no forged anchor is held",
        );

        for anchor_ms in [1_000, 1_000 + step, 1_000 + 2 * step] {
            state.on_execution_vote(&schedule, vote_at(anchor_ms).into());
        }
        let tracker = state
            .ticks
            .get_tracker(&tick_id)
            .expect("an on-grid vote is tallied");
        assert_eq!(
            tracker.held_anchors(),
            3,
            "the tick's own anchor, the step the clock passed, and the next",
        );
    }

    /// A tick that certified under its own committee but whose
    /// determined half is still owed a step later is re-signed at that
    /// step; a member holding the earlier certificate tallies the
    /// re-attestation rather than answering it with that certificate, and
    /// once the later certificate lands, the tick and the finalization
    /// held for a block carry it in place of the earlier one.
    #[test]
    fn a_certified_tick_still_owed_a_step_later_is_reattested() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tick_id = ready_tick_at(&mut state, &schedule, BlockHeight::new(1), 1_000);
        let (global_receipt_root, tx_outcomes) = state
            .emit_vote_actions(&schedule)
            .into_iter()
            .find_map(|action| match action {
                Action::SignAndSendExecutionVote {
                    global_receipt_root,
                    tx_outcomes,
                    ..
                } => Some((global_receipt_root, tx_outcomes)),
                _ => None,
            })
            .expect("the tick casts its own vote");
        let tick = state.ticks.get_tick_mut(&tick_id).unwrap();
        for outcome in &tx_outcomes {
            tick.record_receipt(StoredReceipt {
                tx_hash: outcome.tx_hash(),
                consensus: Arc::new(ConsensusReceipt::Failed),
            });
        }
        let certified_at = |anchor_ms: u64| {
            let mut signers = SignerBitfield::new(4);
            for signer in 0..3 {
                signers.set(signer);
            }
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(anchor_ms),
                global_receipt_root,
                Capped::new(tx_outcomes.clone()).expect("one outcome"),
                AggregateSignature::ZERO,
                signers,
            )))
        };
        let local_anchor = |state: &ExecutionCoordinator| {
            let held = state.finalized.of_tick(&tick_id);
            assert_eq!(held.len(), 1, "one determined half is held");
            held[0]
                .local_ec()
                .expect("a determined half")
                .vote_anchor_ts()
                .as_millis()
        };
        state.on_certificate_verified(&schedule, Ok(certified_at(1_000)));
        assert_eq!(local_anchor(&state), 1_000);

        let step = u64::try_from(REATTESTATION_STEP.as_millis()).unwrap();
        assert_eq!(
            revoted_at(&mut state, &schedule, tick_id, 1_000 + step),
            vec![1_000 + step],
            "a certified tick still owed at the step re-signs there",
        );

        let revote = ExecutionVote::new(
            WeightedTimestamp::from_millis(1_000 + step),
            tick_id,
            global_receipt_root,
            Capped::new(tx_outcomes.clone()).expect("one outcome"),
            ValidatorId::new(1),
            ConsensusSignature::ZERO,
        );
        let answered = state.on_execution_vote(&schedule, revote.into());
        assert!(
            !answered
                .iter()
                .any(|a| matches!(a, Action::BroadcastExecutionCertificate { .. })),
            "a re-attestation is not answered with the lapsing certificate: {answered:?}",
        );
        assert_eq!(
            state
                .ticks
                .get_tracker(&tick_id)
                .map(VoteTracker::held_anchors),
            Some(1),
            "the re-attestation is tallied",
        );

        let actions = state.on_certificate_verified(&schedule, Ok(certified_at(1_000 + step)));
        assert_eq!(local_anchor(&state), 1_000 + step);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizationsAdmitted { finalizations })
                    if finalizations.iter().all(|fw| {
                        fw.local_ec()
                            .is_some_and(|ec| ec.vote_anchor_ts().as_millis() == 1_000 + step)
                    })
            )),
            "the re-anchored half is admitted again: {actions:?}",
        );
        assert!(
            revoted_at(&mut state, &schedule, tick_id, 1_000 + step + 10).is_empty(),
            "nothing is re-signed at or below the held certificate's anchor",
        );
    }

    /// The fold offers every half it holds, whatever earlier tick still
    /// owes its own: which of them a block may carry is admission's to
    /// judge against the committed rows, so a validator whose own ticks
    /// are incomplete cannot silently carry the frontier past one.
    #[test]
    fn the_fold_offers_every_half_it_holds() {
        let mut state = make_test_state();
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
        let _actions = state.finalize(&later_id);
        assert!(state.finalized.contains(&later_id));

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

        let actions = state.finalize(&tick_id);

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
        let actions = state.finalize(&unknown);
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
            .with_boundaries(BTreeMap::from([(
                ShardId::ROOT,
                ShardAnchor {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                    height: BlockHeight::new(9),
                    weighted_timestamp: WeightedTimestamp::from_millis(1_000),
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_settled_txs: None,
                    handoff_complete: None,
                    terminal_epoch: None,
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
            let _ = state.commit_block_carrying(
                &topo,
                &test_certify(block, anchor_ms),
                Naming::Composed,
            );
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
            let _ = state.commit_block_carrying(
                &topo,
                &test_certify(block, anchor_ms),
                Naming::Composed,
            );
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
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &RecoveredState {
                committed_height: BlockHeight::new(5),
                committed_block_anchor_wt: Some(WeightedTimestamp::from_millis(900)),
                committed_committee_anchor_wt: Some(WeightedTimestamp::from_millis(800)),
                ..RecoveredState::default()
            },
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
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
        let _ = state.commit_block_carrying(&topo, &test_certify(block, 1_100), Naming::Composed);

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
    /// A commit whose committee anchor lies in a window this node's
    /// beacon has not committed is parked, not classified under the head:
    /// the frontier holds, and a later commit queues behind it. Once the
    /// beacon commits the window, both fold in order under it, as on a
    /// replica that held the window all along.
    #[test]
    fn a_block_whose_window_is_unresolved_is_parked_not_classified_at_the_head() {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::ROOT);
        let validators: Vec<ValidatorInfo> = (0..4u64)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let one_shard = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators.clone()),
        ));
        let two_shards = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), Arc::clone(&one_shard));
        sched.set_head(two_shards);

        let block_at = |height: u64, anchor_ms: u64| {
            test_certify(
                make_live_block_on_shard(
                    ShardId::ROOT,
                    BlockHeight::new(height),
                    anchor_ms,
                    ValidatorId::new(0),
                    vec![],
                ),
                anchor_ms,
            )
        };
        let first = block_at(1, 1_500);
        let second = block_at(2, 1_700);
        let _ = state.commit_block_composing(&sched, &first, WeightedTimestamp::from_millis(1_500));
        let _ =
            state.commit_block_composing(&sched, &second, WeightedTimestamp::from_millis(1_500));
        assert_eq!(state.committed_height, BlockHeight::GENESIS, "both wait");

        sched.insert(Epoch::new(1), one_shard);
        let _ = state.on_beacon_block_persisted(&sched);
        assert_eq!(state.committed_height, BlockHeight::new(2));
        assert_eq!(
            state
                .counterpart_trie(&sched)
                .expect("the window is committed now")
                .leaves()
                .len(),
            1,
            "classified under the window, not the two-shard head",
        );
    }

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

        let at = WeightedTimestamp::from_millis(500);
        let anchored = state
            .anchored_committee(&sched, at, at)
            .expect("the fixture holds the window");
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
        let actions = state
            .commit_block_carrying(&sched, &certify(block), Naming::Composed)
            .actions;
        let env = actions
            .iter()
            .find_map(|action| match action {
                Action::ExecuteTransactions { env, .. } => Some(env),
                _ => None,
            })
            .expect("the commit dispatches its tick");

        assert_eq!(
            env.seeds.at(Epoch::GENESIS.inner()),
            Drawn::Ready([0xA1; 32]),
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
        state.commit_block_carrying(schedule, &test_certify(block, now_ms), Naming::Composed);
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
        let reserved = tx.price(&PriceTable::GENESIS);
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.commit_block_carrying(
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
            Naming::Composed,
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
            outcomes[0].charged(),
            reserved,
            "attesting exactly what the committing block priced",
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
        let expected = build_refusal_receipt(
            ShardId::ROOT,
            state
                .counterpart_trie(&schedule)
                .expect("the fixture holds the window"),
            tx.hash(),
            Some((
                tx.fee_vault(),
                Movement::unjudged(*PROTOCOL_RESOURCE, tx.price(&PriceTable::GENESIS)),
            )),
            &[],
        )
        .expect("a charge names a receipt");
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.commit_block_carrying(
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
            Naming::Composed,
        );
        state
            .ticks
            .remove_tick(&TickId::new(ShardId::ROOT, BlockHeight::new(1)));

        let outcomes = abandonment_vote(&mut state, &schedule, 2, deadline_ms);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_aborted());
        assert_eq!(
            outcomes[0].refusal_receipt(),
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
                .expect("the fixture holds the window")
                .shard_for_prefix(tx.fee_vault().owner),
            PEER,
            "the fixture is only a test of this if the vault is elsewhere",
        );
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.commit_block_carrying(
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
            Naming::Composed,
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
        state.commit_block_carrying(
            &schedule,
            &test_certify(block, deadline_ms),
            Naming::Composed,
        );
        let outcomes: Vec<TxOutcome> = state
            .scan_votable_ticks(&schedule)
            .into_iter()
            .flat_map(|completion| completion.tx_outcomes)
            .collect();

        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_aborted());
        assert_eq!(
            outcomes[0].refusal_receipt(),
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
            .map_or_default(|tick| tick.tx_hashes().to_vec())
    }

    /// A replay releases the ticks the blocks it re-drives finalized,
    /// exactly as a commit does.
    ///
    /// A replay reseats the tick that held a transaction *and* commits
    /// the block whose finalization settled it, and the second is what
    /// hands the transaction back. Skipping it leaves the transaction
    /// assigned to a tick that has already settled, which nothing later
    /// clears.
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
                dispatch_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
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

    /// A sealed block seats exactly what its live form does: the tick its
    /// manifest names, and nothing its manifest does not name. It is
    /// never dispatched, since it carries no bundles to run over.
    #[test]
    fn a_sealed_block_seats_what_its_live_form_does() {
        let schedule = make_test_topology();
        let named_tx = test_transaction(1);
        let unnamed_tx = test_transaction(2);
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(named_tx.clone()), Arc::new(unnamed_tx.clone())],
        );
        let lines = vec![TickLine::Member {
            tx: named_tx.hash(),
            joins: Joins::Executes,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: genesis_charge(&named_tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(&named_tx),
            crossings: Capped::empty(),
        }];
        let live = naming(&test_certify(committing.clone(), 2_000), lines.clone());
        let sealed = naming(&test_certify(committing.into_sealed(), 2_000), lines);
        let seat = |certified: &CertifiedBlock| {
            let mut state = make_test_state();
            state.commit_block_carrying(
                &schedule,
                &test_certify(seed.clone(), 1_000),
                Naming::Manifest,
            );
            state.commit_block_carrying(&schedule, certified, Naming::Manifest);
            state
        };
        let (live, sealed) = (seat(&live), seat(&sealed));
        let tick = Some(TickId::new(ShardId::ROOT, BlockHeight::new(2)));
        for state in [&live, &sealed] {
            assert_eq!(state.ticks.tick_assignment(named_tx.hash()), tick);
            assert_eq!(state.ticks.tick_assignment(unnamed_tx.hash()), None);
        }
        assert!(live.tick_in_flight || !live.pending_ticks.is_empty());
        assert!(
            !sealed.tick_in_flight
                && matches!(
                    sealed.pending_ticks.front(),
                    Some(Queued::Held(held)) if *held == TickId::new(ShardId::ROOT, BlockHeight::new(2))
                ),
            "a sealed tick is seated, never dispatched, and holds dispatch behind it",
        );
    }

    /// A tick anchored below a recovery's bridge that this node cannot
    /// run is seated into `held` as on a replica that has not folded the
    /// recovery, dropped from the queue by the next dispatch, and let go
    /// of from `held` at the crossing block.
    #[test]
    fn a_replaced_tick_not_in_hand_is_held_then_dropped_at_dispatch() {
        let mut schedule = make_test_topology_bridged_at_20(BlockHeight::GENESIS);
        let head = Arc::clone(schedule.head());
        for epoch in 1..=30 {
            schedule.insert(Epoch::new(epoch), Arc::clone(&head));
        }
        let tx = test_transaction(1);
        let mut state = make_test_state();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        state.commit_block_carrying(&schedule, &test_certify(seed, 1_000), Naming::Manifest);
        let sealed = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        )
        .into_sealed();
        let effects = state.commit_block_carrying(
            &schedule,
            &naming(
                &test_certify(sealed, 2_000),
                vec![TickLine::Member {
                    tx: tx.hash(),
                    joins: Joins::Executes,
                    settlement: Settlement::Alone,
                    holds: Capped::empty(),
                    reach: Capped::empty(),
                    awaits: Capped::empty(),
                    charge: genesis_charge(&tx),
                    share: 0,
                    reserves: Capped::empty(),
                    deadline: Deadline::of_transaction(&tx),
                    crossings: Capped::empty(),
                }],
            ),
            Naming::Manifest,
        );
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        assert!(
            state.held.contains_key(&tick_id),
            "the tick is seated into held"
        );
        assert!(
            state.pending_ticks.is_empty()
                && !effects
                    .actions
                    .iter()
                    .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "the dispatch drops the replaced tick from the queue",
        );
        let crossing = test_certify(
            make_live_block(BlockHeight::new(3), 0, ValidatorId::new(0), vec![]),
            21_100,
        );
        let _ = state.cross_a_bridge(
            &schedule,
            WeightedTimestamp::from_millis(2_000),
            crossing.block(),
        );
        assert!(state.held.is_empty(), "the crossing lets go of it");
    }

    /// A tick this node cannot run holds every later tick until its
    /// determined half settles; the settling commit seats what its
    /// receipts say it left on the chain, then the later tick runs.
    #[test]
    fn a_held_tick_holds_dispatch_until_it_settles() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let member = |tx: &Transaction| TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Executes,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: genesis_charge(tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(tx),
            crossings: Capped::empty(),
        };
        let mut state = make_test_state();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        state.commit_block_carrying(&schedule, &test_certify(seed, 1_000), Naming::Manifest);
        let sealed = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held_tx.clone())],
        )
        .into_sealed();
        state.commit_block_carrying(
            &schedule,
            &naming(&test_certify(sealed, 2_000), vec![member(&held_tx)]),
            Naming::Manifest,
        );
        let later = make_live_block(
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![Arc::new(later_tx.clone())],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &naming(&test_certify(later, 3_000), vec![member(&later_tx)]),
            Naming::Manifest,
        );
        let executes = |actions: &[Action]| {
            actions
                .iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. }))
        };
        assert!(
            !executes(&effects.actions),
            "the held tick holds tick 3 back"
        );
        assert!(
            state
                .on_block_persisted(&schedule, BlockHeight::new(3))
                .is_empty(),
            "and still does once the block below it is written",
        );

        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address::new([7; 31], AddressClass::Component),
                local: LocalKey([1; 16]),
            },
            Some(vec![1]),
        );
        let finalization: Arc<Verifiable<Finalization>> =
            Arc::new(make_finalization_leaving(BlockHeight::new(2), held_tx.hash(), writes).into());
        let settling = helpers_make_live_block(
            ShardId::ROOT,
            BlockHeight::new(4),
            4_000,
            ValidatorId::new(0),
            vec![],
            vec![finalization],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(settling, 4_000),
            Naming::Manifest,
        );
        let restored = effects.actions.iter().position(|action| {
            matches!(action, Action::ResolveTicks { resolutions }
            if resolutions.iter().any(|(tick, resolution)| {
                tick.block_height() == BlockHeight::new(2)
                    && matches!(resolution, TickResolution::Restored { .. })
            }))
        });
        let dispatched = effects
            .actions
            .iter()
            .position(|action| matches!(action, Action::ExecuteTransactions { tick, .. } if *tick == BlockHeight::new(3)));
        assert!(restored.is_some(), "the settled half's writes are seated");
        assert!(dispatched.is_some(), "and tick 3 then runs");
        assert!(
            restored < dispatched,
            "seated before the tick that reads them"
        );
    }

    /// A legs finalization of tick 2 at `ROOT`, attesting `leg` as
    /// `outcome` and carrying a receipt that leaves `writes`.
    fn legs_finalization_leaving(
        leg: TxHash,
        outcome: ExecutionOutcome,
        writes: StateWrites,
    ) -> Arc<Verifiable<Finalization>> {
        half_leaving(TickHalf::Legs, vec![(leg, outcome, writes)])
    }

    /// A finalization of `half` of tick 2 at `ROOT`, attesting each of
    /// `members` as its outcome and carrying a receipt that leaves its
    /// writes.
    fn half_leaving(
        half: TickHalf,
        members: Vec<(TxHash, ExecutionOutcome, StateWrites)>,
    ) -> Arc<Verifiable<Finalization>> {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let outcomes = members
            .iter()
            .map(|(tx_hash, outcome, _)| {
                let outcome = TxOutcome::new(*tx_hash, outcome.clone());
                match half {
                    TickHalf::Legs | TickHalf::Stated => outcome.as_role(Role::Leg),
                    TickHalf::Determined => outcome,
                }
            })
            .collect();
        let certificate = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            quorum_signers(),
        );
        let receipts: Vec<StoredReceipt> = members
            .into_iter()
            .map(|(tx_hash, _, writes)| {
                StoredReceipt::new(
                    tx_hash,
                    Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                        writes,
                        beacon_witness_events: Capped::empty(),
                        events: Capped::empty(),
                    }),
                )
            })
            .collect();
        let receipts = Capped::new(receipts).expect("a list written out in a test");
        // A legs half carries no certificate: it accepts what it names.
        let half = if half == TickHalf::Legs {
            Finalization::accepting(tick_id, receipts)
        } else {
            Finalization::new(
                tick_id,
                half,
                &Capped::from_array([Arc::new(certificate)]),
                receipts,
            )
        };
        Arc::new(half.into())
    }

    /// The legs half of tick 2 at `ROOT` over a certificate attesting
    /// every one of `members`, naming `named` of them and carrying their
    /// receipts.
    fn legs_naming(
        members: Vec<(TxHash, ExecutionOutcome, StateWrites)>,
        named: &[TxHash],
    ) -> Arc<Verifiable<Finalization>> {
        let whole = half_leaving(TickHalf::Legs, members);
        let receipts: Vec<StoredReceipt> = whole
            .receipts()
            .iter()
            .filter(|receipt| named.contains(&receipt.tx_hash))
            .cloned()
            .collect();
        Arc::new(
            whole
                .as_unverified()
                .clone()
                .naming(&named.iter().copied().collect())
                .with_receipts(Capped::new(receipts).expect("a list written out in a test"))
                .into(),
        )
    }

    /// The line naming `tx` a member settling on its own tick's
    /// certificate.
    fn alone(tx: &Transaction) -> TickLine {
        TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Executes,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: genesis_charge(tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(tx),
            crossings: Capped::empty(),
        }
    }

    /// The line naming `tx` abandoned, reaching `reach`.
    fn abandoning(tx: &Transaction, reach: &[ShardId]) -> TickLine {
        TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Aborted,
            settlement: if reach.is_empty() {
                Settlement::Alone
            } else {
                Settlement::Awaited
            },
            holds: Capped::empty(),
            reach: Capped::new(reach.to_vec()).expect("a list written out in a test"),
            awaits: Capped::empty(),
            charge: genesis_charge(tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(tx),
            crossings: Capped::empty(),
        }
    }

    /// What an abandonment of `tx` leaves: its charge, unjudged, on the
    /// payer's vault.
    fn abandonment_charge(tx: &Transaction) -> StateWrites {
        let charge = genesis_charge(tx);
        let mut writes = StateWrites::default();
        writes.movements.insert(
            charge.vault,
            Movement::unjudged(*PROTOCOL_RESOURCE, charge.amount),
        );
        writes
    }

    /// A coordinator holding a sealed tick 2 that commits `txs` and names
    /// `lines`.
    fn holding(
        schedule: &TopologySchedule,
        txs: &[&Transaction],
        lines: Vec<TickLine>,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        state.commit_block_carrying(schedule, &test_certify(seed, 1_000), Naming::Manifest);
        let sealed = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            txs.iter().map(|&tx| Arc::new(tx.clone())).collect(),
        )
        .into_sealed();
        state.commit_block_carrying(
            schedule,
            &naming(&test_certify(sealed, 2_000), lines),
            Naming::Manifest,
        );
        state
    }

    /// Seat `leg`, declaring `reserved`, in the held tick 2.
    fn seat_leg(
        state: &mut ExecutionCoordinator,
        leg: TxHash,
        reserved: BTreeMap<SubstateKey, u128>,
    ) {
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        state
            .ticks
            .get_tick_mut(&held)
            .expect("the sealed block's tick is seated")
            .admit(
                leg,
                Membership::whole(BTreeSet::from([ShardId::ROOT, ShardId::leaf(1, 1)])),
                0,
                Joins::Executes,
            );
        state.ticks.assign_tx(leg, held);
        state
            .ticked
            .get_mut(&held)
            .expect("a seated tick with members to run has an entry")
            .legs
            .insert(leg, reserved);
    }

    /// A coordinator holding a sealed tick 2 of one determined member,
    /// `held_tx`, and one leg, `leg`, declaring `reserved`.
    fn holding_a_leg(
        schedule: &TopologySchedule,
        held_tx: &Transaction,
        leg: TxHash,
        reserved: BTreeMap<SubstateKey, u128>,
    ) -> ExecutionCoordinator {
        let mut state = holding(schedule, &[held_tx], vec![alone(held_tx)]);
        seat_leg(&mut state, leg, reserved);
        state
    }

    /// A ticked batch of `legs`, each declaring what
    /// [`leg_reservation`] names.
    fn batch_of_reserving_legs(legs: &[TxHash]) -> TickedBatch {
        let claims: Vec<(DeclaredKey, Mode)> = leg_reservation()
            .into_keys()
            .map(|cell| (DeclaredKey::Cell(cell), Mode::Read))
            .collect();
        TickedBatch {
            provisional_claims: legs.iter().map(|&leg| (leg, claims.clone())).collect(),
            legs: legs.iter().map(|&leg| (leg, leg_reservation())).collect(),
        }
    }

    /// What the fixture's leg declares it reserves: one cell's worth.
    fn leg_reservation() -> BTreeMap<SubstateKey, u128> {
        BTreeMap::from([(
            SubstateKey {
                owner: Address::new([7; 31], AddressClass::Component),
                local: LocalKey([1; 16]),
            },
            50,
        )])
    }

    /// A block at `height` on `ROOT` carrying `finalization`.
    fn settling(height: u64, finalization: Arc<Verifiable<Finalization>>) -> CertifiedBlock {
        let now_ms = height * 1_000;
        test_certify(
            helpers_make_live_block(
                ShardId::ROOT,
                BlockHeight::new(height),
                now_ms,
                ValidatorId::new(0),
                vec![],
                vec![finalization],
            ),
            now_ms,
        )
    }

    /// Every resolution `actions` hand the chain for `tick`, in order.
    fn resolutions_for(actions: &[Action], tick: TickId) -> Vec<TickResolution> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::ResolveTicks { resolutions } => Some(resolutions),
                _ => None,
            })
            .flatten()
            .filter(|(resolved, _)| *resolved == tick)
            .map(|(_, resolution)| resolution.clone())
            .collect()
    }

    /// A held tick whose leg may reserve holds every later tick until
    /// the leg settles, its determined half settled or not. The settling
    /// commit seats the leg, holding what it declared, and settles it at
    /// that commit's height, ahead of the later tick, which then runs.
    #[test]
    fn a_held_ticks_reserving_leg_holds_dispatch_until_it_settles() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let leg = test_transaction(3).hash();
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let reserved = leg_reservation();
        let mut state = holding_a_leg(&schedule, &held_tx, leg, reserved.clone());
        let later = make_live_block(
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![Arc::new(later_tx.clone())],
        );
        state.commit_block_carrying(
            &schedule,
            &naming(&test_certify(later, 3_000), vec![alone(&later_tx)]),
            Naming::Manifest,
        );
        let runs_tick_3 = |actions: &[Action]| {
            actions.iter().position(|action| {
                matches!(action, Action::ExecuteTransactions { tick, .. } if *tick == BlockHeight::new(3))
            })
        };
        assert_eq!(
            runs_tick_3(&state.on_block_persisted(&schedule, BlockHeight::new(3))),
            None,
            "the block below tick 3 being written does not release it",
        );

        let determined: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization_leaving(BlockHeight::new(2), held_tx.hash(), StateWrites::default())
                .into(),
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(4, determined), Naming::Manifest);
        assert_eq!(
            runs_tick_3(&effects.actions),
            None,
            "the determined half settling leaves the leg unresolved, and tick 3 held",
        );

        let completed = legs_finalization_leaving(
            leg,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
            StateWrites::default(),
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(5, completed), Naming::Manifest);
        match resolutions_for(&effects.actions, held).as_slice() {
            [
                TickResolution::RestoredLegs {
                    height,
                    legs,
                    aborted,
                },
            ] => {
                assert_eq!(*height, BlockHeight::new(5), "settled where it committed");
                assert!(aborted.is_empty(), "the leg's effects survive");
                assert_eq!(
                    legs.iter()
                        .map(|seated| (seated.tx_hash, seated.reserved.clone()))
                        .collect::<Vec<_>>(),
                    vec![(leg, reserved)],
                    "the completed leg is seated holding what it declared",
                );
            }
            other => panic!("the leg is seated and settled in one step: {other:?}"),
        }
        let seated = effects.actions.iter().position(|action| {
            matches!(action, Action::ResolveTicks { resolutions }
                if resolutions.iter().any(|(tick, _)| *tick == held))
        });
        assert!(
            runs_tick_3(&effects.actions).is_some() && seated < runs_tick_3(&effects.actions),
            "seated before tick 3, which then runs",
        );
    }

    /// Two legs halves of one held tick, each naming one of its legs,
    /// each seat and settle the leg they name and no other: one in the
    /// block that carries it, and the tick still held for the second.
    /// The tick holds every later tick while a leg of it that may
    /// reserve is unresolved, and lets them run once the last one
    /// settles, its batch gone with it.
    #[test]
    fn two_legs_halves_of_a_held_tick_both_restore() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let (first, second) = (test_transaction(3).hash(), test_transaction(4).hash());
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding_a_leg(&schedule, &held_tx, first, leg_reservation());
        seat_leg(&mut state, second, leg_reservation());
        let later = make_live_block(
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![Arc::new(later_tx.clone())],
        );
        state.commit_block_carrying(
            &schedule,
            &naming(&test_certify(later, 3_000), vec![alone(&later_tx)]),
            Naming::Manifest,
        );
        let _ = state.on_block_persisted(&schedule, BlockHeight::new(3));
        let determined: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization_leaving(BlockHeight::new(2), held_tx.hash(), StateWrites::default())
                .into(),
        );
        state.commit_block_carrying(&schedule, &settling(4, determined), Naming::Manifest);
        let runs_tick_3 = |actions: &[Action]| {
            actions.iter().any(|action| {
                matches!(action, Action::ExecuteTransactions { tick, .. } if *tick == BlockHeight::new(3))
            })
        };
        let members = || {
            [first, second]
                .map(|leg| {
                    (
                        leg,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                        StateWrites::default(),
                    )
                })
                .to_vec()
        };

        for (height, named, last) in [(5, first, false), (6, second, true)] {
            let effects = state.commit_block_carrying(
                &schedule,
                &settling(height, legs_naming(members(), &[named])),
                Naming::Manifest,
            );
            let resolutions = resolutions_for(&effects.actions, held);
            assert_eq!(
                restored_leg_members(&resolutions),
                vec![vec![named]],
                "the half at {height} seats the leg it names: {resolutions:?}",
            );
            assert!(
                resolutions.iter().any(|resolution| matches!(
                    resolution,
                    TickResolution::RestoredLegs { height: at, .. }
                        if *at == BlockHeight::new(height)
                )),
                "settled where it committed: {resolutions:?}",
            );
            assert_eq!(
                (
                    state.ticked.contains_key(&held),
                    runs_tick_3(&effects.actions)
                ),
                (!last, last),
                "the tick holds its batch, and tick 3, exactly while a leg of it stands",
            );
        }
    }

    /// A coordinator holding a sealed tick 2 of one determined member,
    /// `held_tx`, already settled, and two members `first` and `second`
    /// awaiting another shard, each declaring what [`leg_reservation`]
    /// names, with tick 3 running `later_tx` queued behind it.
    fn holding_two_legs_past_the_determined_half(
        schedule: &TopologySchedule,
        held_tx: &Transaction,
        later_tx: &Transaction,
        (first, second): (TxHash, TxHash),
    ) -> ExecutionCoordinator {
        let mut state = holding_a_leg(schedule, held_tx, first, leg_reservation());
        seat_leg(&mut state, second, leg_reservation());
        let later = make_live_block(
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![Arc::new(later_tx.clone())],
        );
        state.commit_block_carrying(
            schedule,
            &naming(&test_certify(later, 3_000), vec![alone(later_tx)]),
            Naming::Manifest,
        );
        let _ = state.on_block_persisted(schedule, BlockHeight::new(3));
        let determined: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization_leaving(BlockHeight::new(2), held_tx.hash(), StateWrites::default())
                .into(),
        );
        state.commit_block_carrying(schedule, &settling(4, determined), Naming::Manifest);
        state
    }

    /// A core member's outcome at `ROOT`, charged 1, awaiting another
    /// shard.
    fn core_outcome(tx_hash: TxHash, outcome: ExecutionOutcome) -> TxOutcome {
        TxOutcome::new(tx_hash, outcome)
            .charging(1)
            .awaiting([ShardId::leaf(1, 1)])
            .as_role(Role::Core)
    }

    /// The stating half of tick 2 at `ROOT` over `outcomes`, carrying
    /// `receipts`, as a block may carry it.
    fn stating_of(
        outcomes: Vec<TxOutcome>,
        receipts: Vec<StoredReceipt>,
    ) -> Arc<Verifiable<Finalization>> {
        let half: Arc<Verifiable<Finalization>> = Arc::new(
            stating_half_on(ShardId::ROOT, BlockHeight::new(2), outcomes, receipts).into(),
        );
        assert_eq!(half.validate_against_certificates(), Ok(()));
        half
    }

    /// Whether `actions` dispatch tick 3.
    fn runs_tick_3(actions: &[Action]) -> bool {
        actions.iter().any(|action| {
            matches!(action, Action::ExecuteTransactions { tick, .. } if *tick == BlockHeight::new(3))
        })
    }

    /// The legs the batch of tick 2 at `ROOT` still holds, where it
    /// stands.
    fn legs_held(state: &ExecutionCoordinator) -> Option<BTreeSet<TxHash>> {
        state
            .ticked
            .get(&TickId::new(ShardId::ROOT, BlockHeight::new(2)))
            .map(|ticked| ticked.legs.keys().copied().collect())
    }

    /// A held tick's stating half seats and settles the member it
    /// refused, in the block that carries it, and leaves the member it
    /// states a yes for held: the tick keeps its batch, and every later
    /// tick, until the legs half that names that member settles it.
    #[test]
    fn a_held_ticks_stating_half_settles_its_refusals_and_holds_its_yeses() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let (refused, accepted) = (test_transaction(3).hash(), test_transaction(4).hash());
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding_two_legs_past_the_determined_half(
            &schedule,
            &held_tx,
            &later_tx,
            (refused, accepted),
        );

        let stating = stating_of(
            vec![
                core_outcome(refused, ExecutionOutcome::Failed),
                core_outcome(accepted, succeeded()),
            ],
            vec![StoredReceipt::new(
                refused,
                Arc::new(ConsensusReceipt::Failed),
            )],
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(5, stating), Naming::Manifest);
        let resolutions = resolutions_for(&effects.actions, held);
        assert_eq!(
            restored_leg_members(&resolutions),
            vec![vec![refused]],
            "the stating half seats the member it settles and no other: {resolutions:?}",
        );
        assert!(
            resolutions.iter().any(|resolution| matches!(
                resolution,
                TickResolution::RestoredLegs { legs, aborted, .. }
                    if legs.iter().all(|seated| seated.reserved.is_empty())
                        && aborted == &BTreeSet::from([refused])
            )),
            "seated holding nothing, its effects discarded: {resolutions:?}",
        );
        assert_eq!(
            (legs_held(&state), runs_tick_3(&effects.actions)),
            (Some(BTreeSet::from([accepted])), false),
            "the batch stands, and tick 3 waits, for the member the half only stated",
        );
        assert!(
            state
                .ticks
                .get_tick(&held)
                .is_some_and(|tick| !tick.stating_owed()),
            "the tick has stated",
        );

        let members = [refused, accepted]
            .map(|leg| (leg, succeeded(), StateWrites::default()))
            .to_vec();
        let effects = state.commit_block_carrying(
            &schedule,
            &settling(6, legs_naming(members, &[accepted])),
            Naming::Manifest,
        );
        assert_eq!(
            restored_leg_members(&resolutions_for(&effects.actions, held)),
            vec![vec![accepted]],
        );
        assert_eq!(
            (legs_held(&state), runs_tick_3(&effects.actions)),
            (None, true),
            "the legs half releases the batch and the ticks held behind it",
        );
        assert!(!state.ticks.contains_tick(&held), "and the tick is done");
    }

    /// A held tick's stating half of nothing but yeses resolves no
    /// member and lets go of nothing: the batch stands whole for the
    /// legs halves that settle its members.
    #[test]
    fn a_held_ticks_stating_half_of_yeses_resolves_nothing() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let (first, second) = (test_transaction(3).hash(), test_transaction(4).hash());
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding_two_legs_past_the_determined_half(
            &schedule,
            &held_tx,
            &later_tx,
            (first, second),
        );

        let stating = stating_of(
            vec![
                core_outcome(first, succeeded()),
                core_outcome(second, succeeded()),
            ],
            Vec::new(),
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(5, stating), Naming::Manifest);
        assert!(
            resolutions_for(&effects.actions, held).is_empty(),
            "a stating half of yeses resolves no member",
        );
        assert_eq!(
            (legs_held(&state), runs_tick_3(&effects.actions)),
            (Some(BTreeSet::from([first, second])), false),
        );
        assert!(
            state
                .ticks
                .get_tick(&held)
                .is_some_and(|tick| !tick.stating_owed()),
        );
    }

    /// A tick's legs settle in as many resolutions as finalizations name
    /// them. Each one lets go of what the legs it names held, and the
    /// batch goes with the last of them, whether that one settles its
    /// leg or abandons it.
    #[test]
    fn a_tick_settling_its_legs_apart_releases_its_batch_with_the_last() {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let (first, second) = (test_transaction(3).hash(), test_transaction(4).hash());
        let settled = |leg: TxHash| TickResolution::Settled {
            height: BlockHeight::new(5),
            members: BTreeSet::from([leg]),
            aborted: BTreeSet::new(),
        };
        let abandoned = |leg: TxHash| TickResolution::Abandoned {
            height: BlockHeight::new(5),
            members: BTreeSet::from([leg]),
        };
        for last in [settled(second), abandoned(second)] {
            let mut state = make_test_state();
            state
                .ticked
                .insert(tick_id, batch_of_reserving_legs(&[first, second]));

            state.record_tick_resolution(&tick_id, settled(first));
            assert_eq!(
                state.ticked[&tick_id]
                    .legs
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![second],
                "the entry stands for the leg no resolution has named",
            );
            assert_eq!(
                state.ticked[&tick_id]
                    .provisional_claims
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                vec![second],
                "holding that leg's cells and no other's",
            );
            assert!(state.ticked[&tick_id].may_reserve());
            assert!(!state.provisional_cells().is_empty());

            state.record_tick_resolution(&tick_id, last.clone());
            assert!(
                !state.ticked.contains_key(&tick_id),
                "the last leg's resolution releases the batch: {last:?}",
            );
            assert!(state.provisional_cells().is_empty());
        }
    }

    /// A tick reads the base as the block below it left it, so it is
    /// dispatched only once that block is written: at the write where
    /// the tick before it had already completed, at that completion
    /// where the write came first, and at its own commit where both had.
    /// Which of a block's writes the tick would have missed is nothing
    /// the wait looks at.
    #[test]
    fn a_tick_is_dispatched_only_once_the_block_below_it_is_written() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let dispatched = |actions: &[Action]| -> Vec<u64> {
            actions
                .iter()
                .filter_map(|action| match action {
                    Action::ExecuteTransactions { tick, .. } => Some(tick.inner()),
                    _ => None,
                })
                .collect()
        };
        let commit = |state: &mut ExecutionCoordinator, height: u64| {
            let tx = test_transaction(u8::try_from(height).expect("a low height"));
            let block = make_live_block(
                BlockHeight::new(height),
                height * 1_000,
                ValidatorId::new(0),
                vec![Arc::new(tx.clone())],
            );
            let block = naming(&test_certify(block, height * 1_000), vec![alone(&tx)]);
            state
                .commit_block_carrying(&schedule, &block, Naming::Manifest)
                .actions
        };
        let complete = |state: &mut ExecutionCoordinator, height: u64| {
            state.on_execution_batch_completed(
                &schedule,
                BlockHeight::new(height),
                TickBatchOutcome {
                    tick_id: TickId::new(ShardId::ROOT, BlockHeight::new(height)),
                    results: vec![],
                    tx_outcomes: vec![],
                    refusal_receipts: vec![],
                },
            )
        };

        assert_eq!(
            dispatched(&commit(&mut state, 1)),
            [1],
            "the first tick reads the base its chain was seated on",
        );
        assert!(dispatched(&commit(&mut state, 2)).is_empty());
        assert!(dispatched(&commit(&mut state, 3)).is_empty());

        assert!(
            dispatched(&complete(&mut state, 1)).is_empty(),
            "tick 1 is done and block 1 is unwritten, so tick 2 waits",
        );
        assert_eq!(
            dispatched(&state.on_block_persisted(&schedule, BlockHeight::new(1))),
            [2],
            "block 1's write releases it",
        );

        assert!(
            dispatched(&state.on_block_persisted(&schedule, BlockHeight::new(2))).is_empty(),
            "block 2 is written and tick 2 is still running, so tick 3 waits",
        );
        assert_eq!(
            dispatched(&complete(&mut state, 2)),
            [3],
            "tick 2's completion releases it",
        );

        assert!(dispatched(&complete(&mut state, 3)).is_empty());
        assert!(dispatched(&state.on_block_persisted(&schedule, BlockHeight::new(3))).is_empty());
        assert_eq!(
            dispatched(&commit(&mut state, 4)),
            [4],
            "block 3 written and tick 3 done, tick 4 runs as it commits",
        );
    }

    /// A held tick's leg that cannot reserve holds no later tick: what it
    /// left is read only from its settlement on, whenever that commits.
    #[test]
    fn a_held_ticks_leg_reserving_nothing_holds_no_dispatch() {
        let schedule = make_test_topology();
        let (held_tx, later_tx) = (test_transaction(1), test_transaction(2));
        let leg = test_transaction(3).hash();
        let mut state = holding_a_leg(&schedule, &held_tx, leg, BTreeMap::new());
        let determined: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization_leaving(BlockHeight::new(2), held_tx.hash(), StateWrites::default())
                .into(),
        );
        state.commit_block_carrying(&schedule, &settling(3, determined), Naming::Manifest);
        state.on_block_persisted(&schedule, BlockHeight::new(3));
        let later = make_live_block(
            BlockHeight::new(4),
            4_000,
            ValidatorId::new(0),
            vec![Arc::new(later_tx.clone())],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &naming(&test_certify(later, 4_000), vec![alone(&later_tx)]),
            Naming::Manifest,
        );
        assert!(
            effects.actions.iter().any(|action| matches!(
                action,
                Action::ExecuteTransactions { tick, .. } if *tick == BlockHeight::new(4)
            )),
            "tick 4 runs with the leg still owed",
        );
    }

    /// The receipt of `tx`'s floor burned on `ROOT`, as an abort
    /// settles it.
    fn floor_receipt(
        state: &ExecutionCoordinator,
        schedule: &TopologySchedule,
        tx: &Transaction,
    ) -> GlobalReceiptHash {
        build_refusal_receipt(
            ShardId::ROOT,
            state
                .counterpart_trie(schedule)
                .expect("the fixture holds the window"),
            tx.hash(),
            Some((
                tx.fee_vault(),
                Movement::unjudged(*PROTOCOL_RESOURCE, tx.price(&PriceTable::GENESIS)),
            )),
            &[],
        )
        .expect("a charge names a receipt")
        .receipt_hash()
    }

    /// Each outcome's transaction and the charge its receipt settles.
    fn charged(outcomes: &[TxOutcome]) -> Vec<(TxHash, Option<GlobalReceiptHash>)> {
        outcomes
            .iter()
            .map(|outcome| (outcome.tx_hash(), outcome.refusal_receipt()))
            .collect()
    }

    /// A discard charges nothing: of two members of one tick, the one an
    /// abort names is charged its floor by that abort, the tick-mate the
    /// discard lets go of is charged by its own abort later, and the
    /// discard itself settles no outcome for either.
    #[test]
    fn a_discard_charges_nothing() {
        let schedule = make_test_topology();
        let mut pair = [test_transaction(1), test_transaction(2)];
        pair.sort_by_key(Transaction::hash);
        let [abandoned, mate] = pair;
        let line = |tx: &Transaction, joins| TickLine::Member {
            tx: tx.hash(),
            joins,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: genesis_charge(tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(tx),
            crossings: Capped::empty(),
        };
        let mut state = make_test_state();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        state.commit_block_carrying(&schedule, &test_certify(seed, 1_000), Naming::Manifest);
        let holding = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(abandoned.clone()), Arc::new(mate.clone())],
        );
        state.commit_block_carrying(
            &schedule,
            &naming(
                &test_certify(holding, 2_000),
                vec![
                    line(&abandoned, Joins::Executes),
                    line(&mate, Joins::Executes),
                ],
            ),
            Naming::Manifest,
        );
        let held_by = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        assert_eq!(state.ticks.tick_assignment(mate.hash()), Some(held_by));

        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();
        let settle = |state: &mut ExecutionCoordinator, height, now_ms, lines| {
            let block = make_live_block(
                BlockHeight::new(height),
                now_ms,
                ValidatorId::new(0),
                vec![],
            );
            state.commit_block_carrying(
                &schedule,
                &naming(&test_certify(block, now_ms), lines),
                Naming::Manifest,
            );
            state
                .scan_votable_ticks(&schedule)
                .into_iter()
                .flat_map(|completion| completion.tx_outcomes)
                .collect::<Vec<TxOutcome>>()
        };
        let expected = floor_receipt(&state, &schedule, &abandoned);
        let outcomes = settle(
            &mut state,
            3,
            deadline_ms,
            vec![
                line(&abandoned, Joins::Aborted),
                TickLine::Discard {
                    tick: held_by,
                    cause: DiscardCause::Abandoned(abandoned.hash()),
                },
            ],
        );
        assert_eq!(
            charged(&outcomes),
            vec![(abandoned.hash(), Some(expected))],
            "the abort charges its member once, and the discard charges nobody",
        );
        assert!(!state.ticks.contains_tick(&held_by));
        assert_eq!(state.ticks.tick_assignment(mate.hash()), None);

        let expected = floor_receipt(&state, &schedule, &mate);
        let outcomes = settle(
            &mut state,
            4,
            deadline_ms + 1_000,
            vec![line(&mate, Joins::Aborted)],
        );
        assert_eq!(
            charged(&outcomes),
            vec![(mate.hash(), Some(expected))],
            "the let-go tick-mate is charged by its own abort alone",
        );
    }

    /// A chain on `ROOT` that commits `tx` at height 2 and next commits
    /// at height 3, on a clock already at the close of `tx`'s abandon
    /// window, in a block naming its abort: the three blocks, and that
    /// clock.
    fn resuming_past_the_abandon_window(tx: &Transaction) -> ([CertifiedBlock; 3], u64) {
        let resumed_ms = 60_000
            + u64::try_from((MAX_FINALIZATION_DELAY + MAX_VALIDITY_RANGE).as_millis()).unwrap();
        let seed = make_live_block(BlockHeight::new(1), 1_000, ValidatorId::new(0), vec![]);
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );
        let resumed = make_live_block(BlockHeight::new(3), resumed_ms, ValidatorId::new(0), vec![]);
        let aborting = TickLine::Member {
            tx: tx.hash(),
            joins: Joins::Aborted,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: genesis_charge(tx),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(tx),
            crossings: Capped::empty(),
        };
        (
            [
                test_certify(seed, 1_000),
                test_certify(committing, 2_000),
                naming(&test_certify(resumed, resumed_ms), vec![aborting]),
            ],
            resumed_ms,
        )
    }

    /// An abort named by the block whose clock closes the member's
    /// abandon window is seated from that block's line, though the same
    /// commit retires the member's ledger entry on its clock, and leaves
    /// nothing behind: the tick and its assignment go when the abort's
    /// finalization commits.
    #[test]
    fn an_abort_seated_as_its_window_closes_leaves_nothing_once_it_settles() {
        let schedule = make_test_topology();
        let tx = test_transaction(1);
        let (blocks, resumed_ms) = resuming_past_the_abandon_window(&tx);
        let mut state = make_test_state();
        for block in &blocks {
            state.commit_block_carrying(&schedule, block, Naming::Manifest);
        }
        let aborting = TickId::new(ShardId::ROOT, BlockHeight::new(3));
        assert!(
            !state.counterparts.ledger.contains(tx.hash()),
            "the commit naming the abort retires the entry on its clock",
        );
        assert_eq!(state.ticks.tick_assignment(tx.hash()), Some(aborting));
        assert_eq!(
            charged(&votable_outcomes(&mut state, &schedule)),
            vec![(tx.hash(), Some(floor_receipt(&state, &schedule, &tx)))],
            "the abort burns the floor its line names",
        );

        let next = make_live_block(
            BlockHeight::new(4),
            resumed_ms + 1_000,
            ValidatorId::new(0),
            vec![],
        );
        state.commit_block_carrying(
            &schedule,
            &test_certify(next, resumed_ms + 1_000),
            Naming::Manifest,
        );
        assert!(
            state.ticks.contains_tick(&aborting),
            "the tick seated from the line carries the abort until it settles",
        );

        let finalization: Arc<Verifiable<Finalization>> = Arc::new(
            helpers_make_finalization(BlockHeight::new(3), tx.hash(), TransactionDecision::Aborted)
                .into(),
        );
        let settling = helpers_make_live_block(
            ShardId::ROOT,
            BlockHeight::new(5),
            resumed_ms + 2_000,
            ValidatorId::new(0),
            vec![],
            vec![finalization],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(settling, resumed_ms + 2_000),
            Naming::Manifest,
        );
        assert_eq!(
            effects.resolutions,
            vec![(
                tx.hash(),
                TxResolution::Decided(TransactionDecision::Aborted)
            )],
        );
        assert!(!state.ticks.contains_tick(&aborting));
        assert_eq!(state.ticks.tick_assignment(tx.hash()), None);
        assert_eq!(state.counterparts.ledger.len(), 0);
    }

    /// A replica that restarts and replays the blocks seats the abort a
    /// replica that lived through them seated, in the same tick and
    /// settling the same receipt.
    #[test]
    fn a_replay_seats_the_abort_named_as_its_window_closes() {
        let schedule = make_test_topology();
        let tx = test_transaction(1);
        let (blocks, _) = resuming_past_the_abandon_window(&tx);
        let mut live = make_test_state();
        for block in &blocks {
            live.commit_block_carrying(&schedule, block, Naming::Manifest);
        }

        let [_, committing, resumed] = blocks;
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(3),
            replay: ReplayWindow {
                blocks: vec![
                    Verified::<CertifiedBlock>::from_persisted(committing),
                    Verified::<CertifiedBlock>::from_persisted(resumed),
                ],
                dispatch_from: BlockHeight::new(2),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
        );
        restarted.on_committed_state_restored(&schedule, &StubVmStatics);

        let aborting = TickId::new(ShardId::ROOT, BlockHeight::new(3));
        assert_eq!(restarted.ticks.tick_assignment(tx.hash()), Some(aborting));
        let replayed = charged(&votable_outcomes(&mut restarted, &schedule));
        assert_eq!(
            replayed,
            vec![(tx.hash(), Some(floor_receipt(&live, &schedule, &tx)))],
        );
        assert_eq!(replayed, charged(&votable_outcomes(&mut live, &schedule)));
    }

    /// A replay reaching below what the store can anchor seats its
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
    fn a_replay_below_the_stores_reach_seats_without_dispatching() {
        let schedule = make_test_topology();
        let held = test_transaction(1);
        let held_hash = held.hash();
        let held_deadline = Deadline::of_transaction(&held);
        let committing = make_live_block(
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![Arc::new(held)],
        );
        let above = make_live_block(BlockHeight::new(3), 3_000, ValidatorId::new(0), vec![]);
        // The committing block names its own transaction, ready at once.
        let committing = Verified::<CertifiedBlock>::from_persisted(naming(
            &test_certify(committing, 2_000),
            vec![TickLine::Member {
                tx: held_hash,
                joins: Joins::Executes,
                settlement: Settlement::Alone,
                holds: Capped::empty(),
                reach: Capped::empty(),
                awaits: Capped::empty(),
                charge: stub_abort_charge(1),
                share: 0,
                reserves: Capped::empty(),
                deadline: held_deadline,
                crossings: Capped::empty(),
            }],
        ));

        let recovered = RecoveredState {
            committed_height: BlockHeight::new(3),
            replay: ReplayWindow {
                blocks: vec![committing, replayable(above, 3_000)],
                // The store has retired everything below height 2, so a
                // tick at 2 would read a baseline at 1 that is gone.
                dispatch_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
        );
        assert_eq!(
            restarted.baseline_floor(),
            BlockHeight::new(2),
            "the replay's first dispatchable tick reads the height below it",
        );

        let actions = restarted
            .on_committed_state_restored(&schedule, &StubVmStatics)
            .actions;
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

    /// A settled tick the replay seats below where it dispatches is
    /// seated on the chain from the receipts that settled it, as their
    /// commit replays and ahead of the first tick the replay dispatches.
    ///
    /// The writes reach the base at the block that committed the
    /// finalization, which can sit above the block the replay starts
    /// dispatching at — so a tick dispatched in between reads a baseline
    /// the base has not caught up to and the chain, having run no tick
    /// there, no longer holds.
    #[test]
    fn a_replay_seats_the_settled_ticks_it_folds_past() {
        let schedule = make_test_topology();
        let settled = test_transaction(1);
        let settled_hash = settled.hash();
        let committing = Verified::<CertifiedBlock>::from_persisted(naming(
            &test_certify(
                make_live_block(
                    BlockHeight::new(2),
                    2_000,
                    ValidatorId::new(0),
                    vec![Arc::new(settled.clone())],
                ),
                2_000,
            ),
            vec![alone(&settled)],
        ));
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
                blocks: vec![committing, replayable(settling, 4_000)],
                dispatch_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
        );

        let actions = restarted
            .on_committed_state_restored(&schedule, &StubVmStatics)
            .actions;
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
    /// refusal receipt — so it reaches a `TxOutcome` and the receipt root. What
    /// decides it is which tick holds the member and whether a
    /// certificate of this shard's covers it, and both are composition's
    /// output: a replay that composed nothing there would have to assert
    /// them, and either answer diverges from the replica that never went
    /// down. The fixture's member is held and decides alone, so both keep
    /// it past the deadline; a replay that lost its tick would abandon it.
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
        seated.commit_block_carrying(&schedule, &test_certify(seed, 1_000), Naming::Composed);
        let committing = test_certify(committing, 2_000);
        let named = seated
            .commit_block_carrying(&schedule, &committing, Naming::Composed)
            .named;

        // The replica restarted with the store no longer able to anchor a
        // baseline at the committing height.
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(2),
            replay: ReplayWindow {
                blocks: vec![Verified::<CertifiedBlock>::from_persisted(naming(
                    &committing,
                    named,
                ))],
                dispatch_from: BlockHeight::new(3),
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
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
        let holder = Some(TickId::new(ShardId::ROOT, BlockHeight::new(2)));
        assert_eq!(
            aborted(abandonment_vote(&mut seated, &schedule, 3, deadline_ms)),
            Vec::<TxHash>::new(),
            "fixture precondition: past the deadline the seated replica keeps it",
        );
        assert_eq!(seated.ticks.tick_assignment(held_hash), holder);
        assert_eq!(
            aborted(abandonment_vote(&mut restarted, &schedule, 3, deadline_ms)),
            Vec::<TxHash>::new(),
            "and the restarted one keeps it too, or the ticks the two \
             compose carry different receipt roots",
        );
        assert_eq!(restarted.ticks.tick_assignment(held_hash), holder);
    }

    /// The members `resolutions` seat readable from a determined half's
    /// receipts.
    fn restored_members(resolutions: &[TickResolution]) -> Vec<Vec<TxHash>> {
        resolutions
            .iter()
            .filter_map(|resolution| match resolution {
                TickResolution::Restored { writes, .. } => {
                    Some(writes.iter().map(|(tx_hash, _)| *tx_hash).collect())
                }
                _ => None,
            })
            .collect()
    }

    /// The members `resolutions` seat as legs from a legs half's receipts.
    fn restored_leg_members(resolutions: &[TickResolution]) -> Vec<Vec<TxHash>> {
        resolutions
            .iter()
            .filter_map(|resolution| match resolution {
                TickResolution::RestoredLegs { legs, .. } => {
                    Some(legs.iter().map(|leg| leg.tx_hash).collect())
                }
                _ => None,
            })
            .collect()
    }

    /// What the fixture's run member leaves: one cell.
    fn one_cell() -> StateWrites {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address::new([7; 31], AddressClass::Component),
                local: LocalKey([1; 16]),
            },
            Some(vec![1]),
        );
        writes
    }

    /// A held tick's determined half is seated from its receipts less
    /// the member its block's lines name `Aborted`.
    ///
    /// An abandoned member reaches no engine, so a replica that ran the
    /// tick appended nothing for it: its charge reaches that replica's
    /// baselines through the base alone, from the finalization's height.
    /// A restored entry carrying the refusal receipt would put the charge
    /// under every tick this replica runs below that height.
    #[test]
    fn a_restored_tick_leaves_an_abandonments_charge_to_the_base() {
        let schedule = make_test_topology();
        let (ran, abandoned) = (test_transaction(1), test_transaction(2));
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding(
            &schedule,
            &[&ran, &abandoned],
            vec![alone(&ran), abandoning(&abandoned, &[])],
        );

        let determined = half_leaving(
            TickHalf::Determined,
            vec![
                (
                    ran.hash(),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                    one_cell(),
                ),
                (
                    abandoned.hash(),
                    ExecutionOutcome::Aborted,
                    abandonment_charge(&abandoned),
                ),
            ],
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(3, determined), Naming::Manifest);
        assert_eq!(
            restored_members(&resolutions_for(&effects.actions, held)),
            vec![vec![ran.hash()]],
            "the run member alone is seated; the abandonment's charge is the base's",
        );
    }

    /// A held tick's legs half is seated less the member its block's
    /// lines name `Aborted`: a run holds no leg for a member that reached
    /// no engine, so a verdict on it promotes nothing.
    #[test]
    fn restored_legs_leave_out_an_abandoned_member() {
        let schedule = make_test_topology();
        let (ran, abandoned) = (test_transaction(1), test_transaction(2));
        let leg = test_transaction(3).hash();
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding(
            &schedule,
            &[&ran, &abandoned],
            vec![alone(&ran), abandoning(&abandoned, &[ShardId::leaf(1, 1)])],
        );
        seat_leg(&mut state, leg, BTreeMap::new());

        let legs = half_leaving(
            TickHalf::Legs,
            vec![
                (
                    leg,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                    one_cell(),
                ),
                (
                    abandoned.hash(),
                    ExecutionOutcome::Aborted,
                    abandonment_charge(&abandoned),
                ),
            ],
        );
        let effects = state.commit_block_carrying(&schedule, &settling(3, legs), Naming::Manifest);
        assert_eq!(
            restored_leg_members(&resolutions_for(&effects.actions, held)),
            vec![vec![leg]],
            "the leg a run would hold is seated, and the abandoned member is not",
        );
    }

    /// The members a held tick's lines name `Aborted` are kept for as
    /// long as the tick is: its legs half committing first leaves the
    /// determined half's restore still without them.
    #[test]
    fn a_held_ticks_aborted_lines_outlive_its_legs_half() {
        let schedule = make_test_topology();
        let (ran, abandoned) = (test_transaction(1), test_transaction(2));
        let leg = test_transaction(3).hash();
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let mut state = holding(
            &schedule,
            &[&ran, &abandoned],
            vec![alone(&ran), abandoning(&abandoned, &[])],
        );
        seat_leg(&mut state, leg, BTreeMap::new());

        let legs = legs_finalization_leaving(
            leg,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
            StateWrites::default(),
        );
        let effects = state.commit_block_carrying(&schedule, &settling(3, legs), Naming::Manifest);
        assert_eq!(
            restored_leg_members(&resolutions_for(&effects.actions, held)),
            vec![vec![leg]],
            "fixture precondition: the legs half settles first",
        );

        let determined = half_leaving(
            TickHalf::Determined,
            vec![
                (
                    ran.hash(),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                    one_cell(),
                ),
                (
                    abandoned.hash(),
                    ExecutionOutcome::Aborted,
                    abandonment_charge(&abandoned),
                ),
            ],
        );
        let effects =
            state.commit_block_carrying(&schedule, &settling(4, determined), Naming::Manifest);
        assert_eq!(
            restored_members(&resolutions_for(&effects.actions, held)),
            vec![vec![ran.hash()]],
            "the determined half is still seated without the abandoned member",
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
        live.commit_block_carrying(&schedule, &test_certify(seed, 1_000), Naming::Composed);
        let committing = test_certify(committing, 2_000);
        let named = live
            .commit_block_carrying(&schedule, &committing, Naming::Composed)
            .named;
        assert_eq!(
            live.ticks.tick_assignment(held_hash),
            Some(TickId::new(ShardId::ROOT, BlockHeight::new(2))),
            "fixture precondition: the live replica's tick holds it",
        );

        // A restarted one recovers the same chain: the block that
        // committed the transaction, naming what the live commit seated,
        // under the clock of the block below it so the replay stays on
        // the carry path.
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(2),
            replay: ReplayWindow {
                blocks: vec![Verified::<CertifiedBlock>::from_persisted(naming(
                    &committing,
                    named,
                ))],
                dispatch_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::from_millis(1_000)),
            },
            ..RecoveredState::default()
        };
        let mut restarted = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
        );
        assert!(
            restarted.candidates.is_empty(),
            "construction has no topology to compose against, so it holds",
        );
        // The store it restarted over holds every block it replays.
        restarted.seat_on_persisted_base(recovered.committed_height);

        let actions = restarted
            .on_committed_state_restored(&schedule, &StubVmStatics)
            .actions;
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
        live.commit_block_carrying(
            &schedule,
            &test_certify(next.clone(), 3_000),
            Naming::Composed,
        );
        restarted.commit_block_carrying(&schedule, &test_certify(next, 3_000), Naming::Composed);
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
        state.commit_block_carrying(
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
            Naming::Composed,
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
                refusal_receipts: Vec::new(),
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
                    Capped::from_array([TxOutcome::new(
                        tx_hash,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )]),
                    AggregateSignature::ZERO,
                    SignerBitfield::new(4),
                ),
            )));
        state.scan_votable_ticks(&schedule);
    }

    /// `block` certified with its header's parent QC at `parent_ms` and
    /// its own certifying QC at `qc_ms`: the certifying stamp rides
    /// outside the signed header, so the two can disagree.
    fn certify_split(block: Block, parent_ms: u64, qc_ms: u64) -> CertifiedBlock {
        let stamped = test_certify(block, parent_ms);
        let qc = stamped.qc();
        let rewritten = QuorumCertificate::new(
            qc.block_hash(),
            qc.shard_id(),
            qc.height(),
            qc.parent_block_hash(),
            qc.round(),
            qc.signers().clone(),
            qc.aggregated_signature(),
            WeightedTimestamp::from_millis(qc_ms),
        );
        CertifiedBlock::new_unchecked(
            stamped.block().clone(),
            Verified::new_unchecked_for_test(rewritten),
        )
    }

    fn clears_the_tick_chain(actions: &[Action]) -> bool {
        actions
            .iter()
            .any(|action| matches!(action, Action::ClearTickChain))
    }

    /// The latch reads the committed tip header's parent QC, never the
    /// block's own certifying QC: the terminal block composes as any
    /// other, however its certifying stamp reads, and the quiescence
    /// commit after it derives the latch before it composes.
    #[test]
    fn the_latch_reads_the_quiescence_commits_parent_qc() {
        let schedule = terminating_schedule();
        let mut state = make_test_state();

        let terminal = make_live_block(
            BlockHeight::new(1),
            500,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &certify_split(terminal, 500, 1_500),
            Naming::Composed,
        );
        assert!(
            !effects.terminal,
            "the terminal block's own fold is not the quiescence commit"
        );
        assert!(!state.terminated);
        assert_eq!(
            tick_members(&state, 1).len(),
            1,
            "the terminal block composes"
        );

        let quiescence = make_live_block(
            BlockHeight::new(2),
            1_500,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(2))],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(quiescence, 1_500),
            Naming::Composed,
        );
        assert!(
            effects.terminal,
            "a parent QC past the cut is the quiescence commit"
        );
        assert!(clears_the_tick_chain(&effects.actions));
        assert!(
            tick_members(&state, 2).is_empty(),
            "the latch is derived before the quiescence commit composes",
        );
        assert!(
            tick_members(&state, 1).is_empty(),
            "and the terminal block's tick, which nothing can certify, is drained",
        );
    }

    /// A schedule in which [`HOME`] splits at the end of epoch 0 while
    /// [`PEER`] runs on, with windows retained well past a straddler's
    /// deadline.
    fn home_terminating_schedule(epoch_duration_ms: u64) -> TopologySchedule {
        let (left, right) = HOME.children();
        let mut sched = TopologySchedule::new(
            epoch_duration_ms,
            Epoch::new(0),
            leaves_snap(&[HOME, PEER], &[(HOME, 0)]),
        );
        let post = leaves_snap_departed(&[left, right, PEER], &[], &[(HOME, None)]);
        for epoch in 1..=12u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched.set_head(post);
        sched
    }

    /// A terminated chain composes nothing, however its candidates
    /// unblock afterwards.
    ///
    /// The drain at the quiescence commit clears what is held, and the
    /// latch refuses what arrives after. The registration below is the
    /// second case — the shape a cross-shard provision landing past the
    /// terminal leaves — and it is what the drain alone does not cover.
    #[test]
    fn a_terminated_chain_composes_no_further_tick() {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        // BASELINE: the same commit on a live chain composes a tick.
        {
            let mut live = make_test_state_for_shard(ValidatorId::new(0), HOME);
            live.counterparts.ledger.register_committed(
                test_committed(),
                &PriceTable::GENESIS,
                [(&transaction, &Classified::whole())],
            );
            let block = make_live_block_on_shard(
                HOME,
                BlockHeight::new(1),
                deadline_ms,
                ValidatorId::new(0),
                vec![],
            );
            live.commit_block_carrying(
                &two_shard_topology(),
                &test_certify(block, deadline_ms),
                Naming::Composed,
            );
            assert!(
                live.ticks
                    .get_tick(&TickId::new(HOME, BlockHeight::new(1)))
                    .is_some(),
                "the fixture must reach composition, or the assertion below is vacuous",
            );
        }

        let schedule = home_terminating_schedule(10_000);
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let quiescence = make_live_block_on_shard(
            HOME,
            BlockHeight::new(1),
            20_000,
            ValidatorId::new(0),
            vec![],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(quiescence, 20_000),
            Naming::Composed,
        );
        assert!(effects.terminal);

        // A candidate that lands after the quiescence commit:
        // composition admitted exactly this one on the live chain above,
        // so nothing but the latch stands between it and a tick.
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &Classified::whole())],
        );
        let coast = make_live_block_on_shard(
            HOME,
            BlockHeight::new(2),
            deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(coast, deadline_ms),
            Naming::Composed,
        );

        assert!(!effects.terminal, "the drain runs once");
        assert!(
            state
                .ticks
                .get_tick(&TickId::new(HOME, BlockHeight::new(2)))
                .is_none(),
            "a terminated chain composes no tick, not even for a candidate \
             registered after the quiescence commit",
        );
    }

    /// Nothing clears the latch: a later tip whose anchor resolves no
    /// window reads not-past, and the chain stays terminated without
    /// draining again.
    #[test]
    fn the_latch_never_clears() {
        let schedule = terminating_schedule();
        let mut state = make_test_state();
        let quiescence = make_live_block(BlockHeight::new(1), 1_500, ValidatorId::new(0), vec![]);
        assert!(
            state
                .commit_block_carrying(
                    &schedule,
                    &test_certify(quiescence, 1_500),
                    Naming::Composed
                )
                .terminal
        );

        // Epoch 50 is a window this schedule never committed.
        let unresolved = make_live_block(
            BlockHeight::new(2),
            50_500,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        assert!(!schedule.past_terminal(ShardId::ROOT, WeightedTimestamp::from_millis(50_500)));
        let effects = state.commit_block_carrying(
            &schedule,
            &test_certify(unresolved, 50_500),
            Naming::Composed,
        );
        assert!(!effects.terminal);
        assert!(
            !clears_the_tick_chain(&effects.actions),
            "the drain does not run again"
        );
        assert!(state.terminated);
        assert!(tick_members(&state, 2).is_empty());
    }

    /// A coordinator restarted over `blocks`, anchored where the first of
    /// them begins.
    fn restarted_over(
        blocks: Vec<Verified<CertifiedBlock>>,
        committed_height: u64,
        anchor_ms: u64,
    ) -> ExecutionCoordinator {
        let recovered = RecoveredState {
            committed_height: BlockHeight::new(committed_height),
            replay: ReplayWindow {
                blocks,
                dispatch_from: BlockHeight::GENESIS,
                anchor_wt: Some(WeightedTimestamp::from_millis(anchor_ms)),
            },
            ..RecoveredState::default()
        };
        ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            ShardId::ROOT,
            Arc::new(TestCode::default()),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
        )
    }

    /// A replay that crosses the quiescence commit derives the latch in
    /// that block's fold, as the live chain did, and composes nothing
    /// past it.
    #[test]
    fn a_replay_across_the_quiescence_commit_composes_nothing_past_it() {
        let schedule = terminating_schedule();
        let block = |height: u64, ms: u64, seed: u8| {
            replayable(
                make_live_block(
                    BlockHeight::new(height),
                    ms,
                    ValidatorId::new(0),
                    vec![Arc::new(test_transaction(seed))],
                ),
                ms,
            )
        };
        let mut restarted = restarted_over(
            vec![block(1, 500, 1), block(2, 1_500, 2), block(3, 1_800, 3)],
            3,
            0,
        );

        let effects = restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        assert!(effects.terminal);
        assert!(clears_the_tick_chain(&effects.actions));
        assert!(restarted.terminated);
        for height in 1..=3 {
            assert!(
                tick_members(&restarted, height).is_empty(),
                "no tick stands at height {height}",
            );
        }
    }

    /// A replay whose window starts past the quiescence commit derives
    /// the latch in its first block's fold, before that block composes.
    #[test]
    fn a_replay_starting_past_the_quiescence_commit_terminates_at_its_first_block() {
        let schedule = terminating_schedule();
        let past = make_live_block(
            BlockHeight::new(4),
            1_800,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        let mut restarted = restarted_over(vec![replayable(past, 1_800)], 4, 1_500);

        let effects = restarted.on_committed_state_restored(&schedule, &StubVmStatics);
        assert!(effects.terminal);
        assert!(tick_members(&restarted, 4).is_empty());
    }

    /// A seat with no replay past the cut derives the latch in its first
    /// fold and composes nothing there.
    #[test]
    fn a_seat_past_the_cut_terminates_before_its_first_composition() {
        let schedule = terminating_schedule();
        let mut seated = restarted_over(Vec::new(), 4, 1_500);
        assert!(
            !seated.terminated,
            "nothing seeds the latch at construction"
        );
        assert!(
            !seated
                .on_committed_state_restored(&schedule, &StubVmStatics)
                .terminal
        );

        let first = make_live_block(
            BlockHeight::new(5),
            1_800,
            ValidatorId::new(0),
            vec![Arc::new(test_transaction(1))],
        );
        let effects =
            seated.commit_block_carrying(&schedule, &test_certify(first, 1_800), Naming::Composed);
        assert!(effects.terminal);
        assert!(tick_members(&seated, 5).is_empty());
    }

    /// A leg entry whose record a block takes back is reported as the
    /// abort it is, and the same commit releases the entry: the block's
    /// claims are the whole of it, the record read at the parent beside
    /// its consumer's `Never` read at a boundary, and no member is seated
    /// for the return.
    #[test]
    fn commit_block_reports_a_reclaim_as_the_abort_and_releases_it() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &leg_classified())],
        );
        let (record_key, _, cell) = owned_record();
        let actions = commit_carrying(
            &mut state,
            &schedule,
            2,
            past_the_horizon(),
            taking_back(record_key, &cell, 2),
        );
        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::Continuation(ProtocolEvent::TransactionsResolved { resolutions })
                    if resolutions
                        == &vec![(tx_hash, TxResolution::Decided(TransactionDecision::Aborted))]
            )),
            "the return is the transaction aborted: {actions:?}",
        );
        assert!(!dispatched(&actions), "and no member is seated for it");
        assert_eq!(
            state.counterparts.ledger.len(),
            0,
            "and the same fold released the entry"
        );
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

        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &Classified::whole())],
        );

        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(1),
            deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        state.commit_block_carrying(
            &schedule,
            &test_certify(block, deadline_ms),
            Naming::Composed,
        );
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

    /// A committed record naming a leg entry covers it and seats
    /// nothing, whatever the clock reads: no reclaim and no abandonment.
    /// The leg's record goes back only in the fold, on its consumer's
    /// `Never` read at a boundary.
    #[test]
    fn a_record_covering_a_leg_seats_nothing() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let past_deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &leg_classified())],
        );
        state
            .counterparts
            .ledger
            .certify(tx_hash, Certified::ByExecution);
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
            .record_abandonment_records(&[AbandonmentRecord::new(
                PEER,
                WeightedTimestamp::from_millis(1_000),
                [UnsettledTx::for_transaction(
                    &transaction,
                    test_committed(),
                    transaction.price(&PriceTable::GENESIS),
                    &PriceTable::GENESIS,
                )],
            )]);
        assert!(covered(&state, tx_hash));

        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(1),
            past_deadline_ms,
            ValidatorId::new(0),
            vec![],
        );
        let actions = state
            .commit_block_carrying(
                &schedule,
                &test_certify(block, past_deadline_ms),
                Naming::Composed,
            )
            .actions;
        assert!(
            state
                .ticks
                .get_tick(&TickId::new(HOME, BlockHeight::new(1)))
                .is_none(),
            "the commit seats no tick for it",
        );
        assert!(!dispatched(&actions));
        assert!(
            state.counterparts.ledger.contains(tx_hash),
            "and the entry stands for its record"
        );
    }

    /// A core's certificate tells the mempool nothing, whatever it says
    /// of a transaction a leg here issued for, and offers no record:
    /// the leg's terminal is what this shard's chain closes it on, which
    /// a replica that missed the certificate reads the same. A refusal's
    /// kind is the core's alone — what reaches this chain is the `Never`
    /// it writes, which licenses the reclaim and says nothing of why —
    /// and a success is not the transaction accepted, since a core whose
    /// certificates never combined is abandoned all the same.
    #[test]
    fn a_cores_certificate_is_no_verdict_of_a_leg() {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        for outcome in [
            ExecutionOutcome::Failed,
            ExecutionOutcome::Aborted,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        ] {
            let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
            state.counterparts.ledger.register_committed(
                test_committed(),
                &PriceTable::GENESIS,
                [(&transaction, &leg_classified())],
            );
            state
                .counterparts
                .ledger
                .certify(tx_hash, Certified::ByExecution);
            let actions = state.handle_attestation(&Arc::new(Verified::new_unchecked_for_test(
                ExecutionCertificate::new(
                    TickId::new(PEER, BlockHeight::new(3)),
                    WeightedTimestamp::from_millis(7_000),
                    GlobalReceiptRoot::ZERO,
                    Capped::from_array([
                        TxOutcome::new(tx_hash, outcome.clone()).as_role(Role::Core)
                    ]),
                    AggregateSignature::ZERO,
                    SignerBitfield::new(4),
                ),
            )));
            assert!(
                !actions.iter().any(|action| matches!(
                    action,
                    Action::Continuation(ProtocolEvent::TransactionsResolved { .. })
                )),
                "{outcome:?}: the mempool hears nothing off the core's certificate"
            );
            assert!(
                state
                    .offers(&CarriedClaims::default())
                    .abandonment_records
                    .is_empty(),
                "{outcome:?}: and no record restates it"
            );
        }
    }

    /// A state on [`HOME`] holding `transaction` as a leg, certified and
    /// never resolved, with the shape frozen as `classified` says: what
    /// fixes how many shards the core spans, and so whether its
    /// committed cell is ever asked about.
    fn leg_state(
        transaction: &Arc<Verifiable<Transaction>>,
        classified: &Classified,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(transaction, classified)],
        );
        state
            .counterparts
            .ledger
            .certify(transaction.hash(), Certified::ByExecution);
        state
    }

    /// The state-proof fetches among `actions`, by anchor.
    fn state_proof_fetches(actions: &[Action]) -> Vec<(Anchor, Vec<SubstateKey>)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(keys),
                    ..
                }) => keys.first().map(|(anchor, _)| {
                    (
                        *anchor,
                        keys.iter().map(|(_, key)| *key).collect::<Vec<_>>(),
                    )
                }),
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
        let (state_root, proof) = state_and_proof_holding(shard, &fixture_leaves(present), asked);
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
        let opened = state.on_committed_remote_header(schedule, anchor);
        (StateClaim::new(anchor, cells, proof), opened)
    }

    /// The answer the consumer of the fixtures' transaction, the first
    /// [`straddling_transaction`], writes for `id` in `answered`'s role:
    /// what a fixture tree holds at that answer cell, and what a reading
    /// of it states.
    fn fixture_answer(id: &CrossingId, answered: Answered) -> Vec<u8> {
        let transaction = straddling_transaction(1);
        id.answer(
            transaction.hash(),
            answered,
            transaction
                .validity_range()
                .end_timestamp_exclusive
                .as_millis(),
        )
        .to_bytes()
    }

    /// What a fixture tree holds at each of `present`. At an answer cell
    /// of a crossing a fixture shape issues, [`fixture_answer`], so a
    /// presence read off the tree is the answer to the record the
    /// fixtures' transaction issued; at any other key, the key's own
    /// bytes.
    fn fixture_leaves(present: &[SubstateKey]) -> Vec<(SubstateKey, Vec<u8>)> {
        let answers: Vec<(SubstateKey, Vec<u8>)> = [
            leg_classified(),
            two_shard_core_classified(),
            delivery_classified(),
            peer_fed_core_classified(),
        ]
        .iter()
        .flat_map(|classified| {
            classified
                .crossings()
                .map(|(edge, _)| edge.crossing.id)
                .collect::<Vec<_>>()
        })
        .flat_map(|id| {
            [Answered::Taken, Answered::Never].map(|answered| {
                (
                    id.answer_key(&ProtocolHasher, answered),
                    fixture_answer(&id, answered),
                )
            })
        })
        .collect();
        present
            .iter()
            .map(|key| {
                let value = answers
                    .iter()
                    .find(|(answer, _)| answer == key)
                    .map_or_else(|| key.to_bytes().to_vec(), |(_, value)| value.clone());
                (*key, value)
            })
            .collect()
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
            state_claims: Arc::new(Capped::new(bundles).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources,
        };
        state
            .commit_block_carrying(schedule, &test_certify(block, ts_ms), Naming::Composed)
            .actions
    }

    /// Whether the chain read `key` on `shard` absent for `tx_hash`, as
    /// the ledger holds it.
    fn read_absent(
        state: &ExecutionCoordinator,
        shard: ShardId,
        tx_hash: TxHash,
        key: SubstateKey,
    ) -> bool {
        state.counterparts.ledger.read_absent(tx_hash, shard, key)
    }

    /// Whether the commit that read the evidence covered the entry of
    /// `tx_hash`: no counterpart can settle it, and it asks nothing more.
    /// It licenses a core member's abandonment and nothing of a record:
    /// a record goes back only in the fold, on its consumer's `Never`
    /// read at a boundary.
    fn covered(state: &ExecutionCoordinator, tx_hash: TxHash) -> bool {
        state.counterparts.ledger.is_covered(tx_hash)
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
        let figures = UnsettledTx::for_transaction(
            &transaction,
            test_committed(),
            transaction.price(&PriceTable::GENESIS),
            &PriceTable::GENESIS,
        );
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
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &two_shard_core_classified())],
        );
        state
            .counterparts
            .ledger
            .certify(tx_hash, Certified::ByExecution);
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
        assert!(
            read_absent(&state, CORE_SIBLING, tx_hash, cell(CORE_SIBLING)),
            "and its silence is written down",
        );
        assert!(
            state
                .offers(&CarriedClaims::default())
                .abandonment_records
                .is_empty(),
            "with no record to restate it"
        );

        // The committed claim is what releases the member: the entry is
        // covered, and a covered entry is the shard's to abandon.
        assert!(state.counterparts.ledger.is_covered(tx_hash));
        let held_by = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the same commit composes the abort");
        assert!(
            state
                .ticks
                .get_tick(&held_by)
                .is_some_and(|tick| tick.abandons(tx_hash)),
            "into a tick that abandons it"
        );
    }

    /// A leg entry on `HOME` whose core consumer's claim sits on `PEER`,
    /// with the committed clock at the deadline.
    fn claimed_leg_state(transaction: &Arc<Verifiable<Transaction>>) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(transaction, &leg_classified())],
        );
        state
            .counterparts
            .ledger
            .certify(transaction.hash(), Certified::ByExecution);
        state.committed_ts = UnsettledTx::for_transaction(
            transaction,
            test_committed(),
            transaction.price(&PriceTable::GENESIS),
            &PriceTable::GENESIS,
        )
        .deadline
        .at();
        state
    }

    /// An escrow record this shard holds: a leaf naming a claim cell
    /// that sits on `PEER`, and a cell of its own to credit where
    /// nobody claims it.
    fn held_record(local: u8, validity_end_ms: u64) -> (SubstateKey, SubstateKey, CrossingCell) {
        crossing_fixture(local, validity_end_ms, HOME, PEER)
    }

    /// The record the entry [`leg_classified`] registers issues here, as
    /// its leaf holds it: a record an entry of this shard's owns, and one
    /// its consumer on `PEER` is asked about. It states its issuing
    /// transaction's own validity end, as a leg's record does.
    fn owned_record() -> (SubstateKey, SubstateKey, CrossingCell) {
        let id = leg_classified().edges()[0].crossing.id;
        let record_key = id.record_key(&ProtocolHasher);
        let transaction = straddling_transaction(1);
        let cell = id.cell(
            transaction.hash(),
            ResourceAddr::new([0xE1; 31]),
            1_000,
            transaction
                .validity_range()
                .end_timestamp_exclusive
                .as_millis(),
            Terms::Escrowed {
                credit: SubstateKey {
                    owner: record_key.owner,
                    local: LocalKey([0x0F; 16]),
                },
            },
        );
        (
            record_key,
            id.answer_key(&ProtocolHasher, Answered::Taken),
            cell,
        )
    }

    /// A crossing handed *to* this shard: the record sits on `PEER`
    /// where its producer committed it, and the claim under a target of
    /// `HOME`'s, which is what makes the answer this shard's to give.
    ///
    /// [`held_record`] read from the other end, and the ends are what
    /// the two fixtures differ in: a producer holds the record and asks
    /// about the answer, a consumer holds the answer and is asked for
    /// it.
    fn arrived_record(local: u8, validity_end_ms: u64) -> (SubstateKey, SubstateKey, CrossingCell) {
        crossing_fixture(local, validity_end_ms, PEER, HOME)
    }

    /// A record and its claim for one crossing, produced under a target
    /// of `producer`'s and consumed under one of `consumer`'s, with the
    /// keys the system derives.
    fn crossing_fixture(
        local: u8,
        validity_end_ms: u64,
        producer: ShardId,
        consumer: ShardId,
    ) -> (SubstateKey, SubstateKey, CrossingCell) {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let validity_end = transaction.validity_range().end_timestamp_exclusive;
        let id = CrossingId {
            producer: committed_tx_cell_key(producer, transaction.hash(), validity_end).owner,
            consumer: committed_tx_cell_key(consumer, transaction.hash(), validity_end).owner,
            intent: IntentHash(Hash32([local; 32])),
            local: 0,
            output: 0,
        };
        let record_key = id.record_key(&ProtocolHasher);
        let claim = id.answer_key(&ProtocolHasher, Answered::Taken);
        let cell = id.cell(
            transaction.hash(),
            ResourceAddr::new([0xE1; 31]),
            1_000,
            validity_end_ms,
            Terms::Escrowed {
                credit: SubstateKey {
                    owner: record_key.owner,
                    local: LocalKey([local ^ 0x0F; 16]),
                },
            },
        );
        (record_key, claim, cell)
    }

    /// Hold `cells` in this shard's committed state, as its crossing
    /// index answers, and derive the questions they put under
    /// `schedule`'s head.
    fn hold(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        cells: impl IntoIterator<Item = (SubstateKey, Vec<u8>)>,
    ) -> Arc<TestRows> {
        let rows = Arc::new(TestRows::default());
        for (key, value) in cells {
            rows.put(key, value);
        }
        state.crossing_index().bind(Arc::clone(&rows) as _);
        state.counterparts.derive_asks(schedule.head().shard_trie());
        rows
    }

    /// Whether a commit dispatched any member.
    fn dispatched(actions: &[Action]) -> bool {
        actions.iter().any(|action| {
            matches!(action, Action::ExecuteTransactions { requests, .. } if !requests.is_empty())
        })
    }

    /// Which of the two answer cells a proof carries, of the pair one
    /// probe asks for.
    #[derive(Clone, Copy)]
    enum Proved {
        /// The consumer holds the crossing.
        Claim,
        /// The consumer will never take it.
        Decline,
        /// Neither cell is there, which answers nothing.
        Neither,
    }

    /// What a shard holding one record dispatches, once a block carries
    /// a proof of its consumer's two answer cells. `owed_here` registers
    /// the issuing transaction in the ledger, which is the shard's other
    /// way of reaching the same leaves.
    fn held_settlement(proved: Proved, owed_here: bool) -> Option<Member> {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        // Past the deadline, where a question is first asked.
        let validity_end_ms = 400_000;
        let (record_key, claim, cell) = owned_record();
        if owed_here {
            let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
                Verified::new_unchecked_for_test(straddling_transaction(1)),
            ));
            state.counterparts.ledger.register_committed(
                test_committed(),
                &PriceTable::GENESIS,
                [(&transaction, &leg_classified())],
            );
        }
        let deadline = Deadline::of(WeightedTimestamp::from_millis(validity_end_ms));
        let read_at = deadline.at().plus(Duration::from_secs(1));
        let decline = CrossingId::of_record(record_key.owner, &cell)
            .answer_key(&ProtocolHasher, Answered::Never);
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);

        // The claim sits on PEER, so the seat asks rather than reads.
        state.committed_ts = read_at;
        let present_keys: Vec<SubstateKey> = match proved {
            Proved::Claim => vec![claim],
            Proved::Decline => vec![decline],
            Proved::Neither => Vec::new(),
        };
        let (bundle, opened) = proven_at(
            &mut state,
            &schedule,
            PEER,
            5,
            read_at,
            &present_keys,
            &[claim, decline],
        );
        assert_eq!(
            state_proof_fetches(&opened)
                .iter()
                .filter(|(_, keys)| keys.contains(&claim))
                .count(),
            1,
            "the shard asks whoever holds the claim's prefix, once: the leaf asks \
             only where no entry of its own is already asking",
        );
        let id = CrossingId::of_record(record_key.owner, &cell);
        let actions = commit_carrying(
            &mut state,
            &schedule,
            1,
            read_at.as_millis(),
            vec![bundle.naming([(claim, id), (decline, id)])],
        );
        actions.iter().find_map(|action| match action {
            Action::ExecuteTransactions { requests, .. } => {
                requests.first().map(|request| request.member.clone())
            }
            _ => None,
        })
    }

    /// A held record whose consumer routes elsewhere is decided by the
    /// commit fold alone, on its consumer's answer, and never by a
    /// member: whatever a fresh proof of the consumer's two cells says,
    /// the commit carrying it composes nothing.
    ///
    /// The claim present is the consumer holding the crossing, which the
    /// fold retires the record on. The decline present at a fresh anchor
    /// is one a recovery of the consumer's shard may discard, so nothing
    /// takes the value back on it: the fold returns the record on its
    /// `Never` read at a boundary of that shard. Neither cell there says
    /// only that the consumer has not spoken, at any clock.
    #[test]
    fn a_held_record_is_decided_against_a_proof_of_its_consumers_answer() {
        for proved in [Proved::Claim, Proved::Decline, Proved::Neither] {
            for owed_here in [false, true] {
                assert!(
                    held_settlement(proved, owed_here).is_none(),
                    "a proof of the consumer's answer composes no member",
                );
            }
        }
    }

    /// A record no entry names, standing past its deadline with its
    /// consumer's shard departed, is named by no departure: nothing
    /// offers it in an abandonment record, though the departed shard's
    /// settled set is held and names no transaction of it. The departed
    /// shard may have taken the record before the window its settled set
    /// covers, and what says so is its answer, which a departure does
    /// not read.
    #[test]
    fn a_crossing_a_departure_names_off_a_leaf_is_not_offered() {
        let schedule = two_shard_topology();
        let mut state = make_test_state();
        let validity_end_ms = 400_000;
        let (record_key, _, cell) = held_record(0x6A, validity_end_ms);
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);
        let past = Window::LegEntry
            .of(Deadline::of(WeightedTimestamp::from_millis(
                validity_end_ms,
            )))
            .end
            .plus(Duration::from_secs(1));
        state.committed_ts = past;

        state.counterparts.on_settled(
            PEER,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: past,
            },
        );
        assert!(
            state
                .offers(&CarriedClaims::default())
                .abandonment_records
                .is_empty(),
            "the departure names nothing off the record's leaf",
        );
    }

    /// A record key names its producer's intent, so the entry of a
    /// second transaction carrying the same intent names the key of the
    /// record the first one issued. That entry asks only for its own
    /// transaction's answers and settles nothing of the first's record,
    /// so with the first's entry gone the leaf still asks the record's
    /// consumer whether it took the record.
    #[test]
    fn a_record_beside_another_transactions_entry_is_still_asked_about() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let second: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let (record_key, claim, issued) = owned_record();
        let first = CrossingCell {
            tx: TxHash::from(Hash::from_bytes(b"the first transaction")),
            validity_end_ms: 1_000,
            ..issued
        };
        let id = CrossingId::of_record(record_key.owner, &first);
        let decline = id.answer_key(&ProtocolHasher, Answered::Never);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&second, &leg_classified())],
        );
        assert!(
            state
                .counterparts
                .ledger
                .issued_by(record_key, second.hash())
                && !state.counterparts.ledger.issued_by(record_key, first.tx),
            "the second transaction's entry names the key, and is not the record's",
        );
        hold(&mut state, &schedule, [(record_key, first.to_bytes())]);

        // Past the record's own deadline and short of the second
        // transaction's, so no question of the entry's is due and what
        // is asked is the leaf's.
        let read_at = Deadline::of(WeightedTimestamp::from_millis(first.validity_end_ms))
            .at()
            .plus(Duration::from_secs(1));
        assert!(read_at < Deadline::of_transaction(&second).at());
        state.committed_ts = read_at;
        let never = id
            .answer(first.tx, Answered::Never, first.validity_end_ms)
            .to_bytes();
        let (state_root, proof) =
            state_and_proof_holding(PEER, &[(decline, never)], &[claim, decline]);
        let anchor = Anchor {
            shard: PEER,
            height: BlockHeight::new(5),
            state_root,
            ts: read_at,
        };
        state.proven_anchors().record(anchor);
        let opened = state.on_committed_remote_header(&schedule, anchor);
        assert_eq!(
            state_proof_fetches(&opened)
                .iter()
                .filter(|(_, keys)| keys.contains(&claim) && !keys.contains(&decline))
                .count(),
            1,
            "the leaf asks the record's consumer whether it took the record, and asks its \
             decline of no fresh header: {opened:?}",
        );

        state.on_proof_fetched(anchor, &[claim, decline], &proof, &[]);
        assert!(
            state
                .offers(&CarriedClaims::default())
                .state_claims
                .iter()
                .all(|reading| reading.crossing_of(decline).is_none()),
            "a fresh decline is held to offer by nothing",
        );
    }

    /// A block clock more than a retention horizon past the anchors
    /// [`never_read`] reads at, so each is at a boundary of the block.
    fn past_the_horizon() -> u64 {
        u64::try_from(RETENTION_HORIZON.as_millis()).unwrap() + 100_000
    }

    /// The claims a block of [`HOME`] at `height` carries to take the
    /// record `cell` at `record_key` back: the record read at the block's
    /// parent, and its consumer's `Never` of its transaction read at an
    /// anchor of [`PEER`] the block is at a boundary of.
    fn taking_back(record_key: SubstateKey, cell: &CrossingCell, height: u64) -> Vec<StateClaim> {
        let id = CrossingId::of_record(record_key.owner, cell);
        let parent = StateClaim::new(
            proven_anchor_of(HOME, height - 1, WeightedTimestamp::ZERO),
            [(
                record_key,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record_key, id)]);
        vec![parent, never_read(record_key, cell, 2)]
    }

    /// A block carrying the consumer's `Never` for a record here, named
    /// for the crossing, read at `PEER`.
    fn never_read(record_key: SubstateKey, cell: &CrossingCell, height: u64) -> StateClaim {
        let id = CrossingId::of_record(record_key.owner, cell);
        let decline = id.answer_key(&ProtocolHasher, Answered::Never);
        let declined = id
            .answer(cell.tx, Answered::Never, cell.validity_end_ms)
            .to_bytes();
        StateClaim::new(
            proven_anchor_of(PEER, height, WeightedTimestamp::from_millis(height * 1_000)),
            [(decline, Inclusion::Present(jmt_value_hash(&declined)))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(decline, id)])
    }

    /// A certified live block on `shard` at `height` anchored at `ts_ms`,
    /// carrying `transactions` and `claims`.
    fn block_reading(
        shard: ShardId,
        height: u64,
        ts_ms: u64,
        transactions: Vec<Arc<Transaction>>,
        claims: Vec<StateClaim>,
    ) -> CertifiedBlock {
        let Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            witness_sources,
            ..
        } = make_live_block_on_shard(
            shard,
            BlockHeight::new(height),
            ts_ms,
            ValidatorId::new(0),
            transactions,
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
            state_claims: Arc::new(Capped::new(claims).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources,
        };
        test_certify(block, ts_ms)
    }

    /// Whether `actions` resolve `tx_hash` as an abort.
    fn resolved_aborted(actions: &[Action], tx_hash: TxHash) -> bool {
        actions.iter().any(|action| {
            matches!(
                action,
                Action::Continuation(ProtocolEvent::TransactionsResolved { resolutions })
                    if resolutions.contains(&(
                        tx_hash,
                        TxResolution::Decided(TransactionDecision::Aborted),
                    ))
            )
        })
    }

    /// A consumer's `Never` read at an anchor of its shard fresh to the
    /// block takes nothing back: the consumer's chain above its last
    /// recorded boundary is one a recovery of that shard can discard, and
    /// the `Never` with it. A block carrying the record at its parent
    /// beside it seats no member, closes no entry and covers none; the
    /// same `Never` read at an anchor the block is at a boundary of
    /// returns the record and closes the entry as its abort.
    #[test]
    fn a_never_in_a_discarded_suffix_takes_nothing_back() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let mut state = leg_state(&transaction, &leg_classified());
        let (record_key, _, cell) = owned_record();
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);

        // The `Never` at PEER's height 2, a block anchored a moment later.
        let fresh = commit_carrying(
            &mut state,
            &schedule,
            1,
            3_000,
            taking_back(record_key, &cell, 1),
        );
        assert!(
            !dispatched(&fresh),
            "a fresh Never dispatches nothing: {fresh:?}"
        );
        assert!(!resolved_aborted(&fresh, tx_hash));
        assert!(
            state.counterparts.ledger.contains(tx_hash) && !covered(&state, tx_hash),
            "and the entry stands, uncovered",
        );

        let boundary = commit_carrying(
            &mut state,
            &schedule,
            2,
            past_the_horizon(),
            taking_back(record_key, &cell, 2),
        );
        assert!(resolved_aborted(&boundary, tx_hash));
        assert!(!state.counterparts.ledger.contains(tx_hash));
    }

    /// A record taken back in a block is returned by that block whatever
    /// becomes of the tick at its height: the return is no member of it,
    /// the entry closes at the block's own commit, and a later discard of
    /// the tick re-seats, re-licenses and resolves nothing.
    #[test]
    fn a_reclaim_is_untouched_by_a_discard_of_the_tick_at_its_height() {
        let schedule = two_shard_topology();
        let leg: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let mut state = leg_state(&leg, &leg_classified());
        let (record_key, _, cell) = owned_record();
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);

        let beside = Arc::new(straddling_transaction(2));
        let returning = block_reading(
            HOME,
            2,
            past_the_horizon(),
            vec![Arc::clone(&beside)],
            taking_back(record_key, &cell, 2),
        );
        let actions = state
            .commit_block_carrying(&schedule, &returning, Naming::Composed)
            .actions;
        assert!(
            resolved_aborted(&actions, leg.hash()),
            "the block returns the record and closes the entry: {actions:?}",
        );
        let tick = TickId::new(HOME, BlockHeight::new(2));
        assert!(
            state
                .ticks
                .get_tick(&tick)
                .is_none_or(|seated| !seated.tx_hashes().contains(&leg.hash())),
            "the tick at its height holds no return",
        );

        let anchored = Arc::clone(schedule.head());
        let discarding = CommittingBlock {
            hash: BlockHash::from_raw(Hash::from_bytes(b"discarding")),
            height: BlockHeight::new(3),
            ts: WeightedTimestamp::from_millis(past_the_horizon() + 1_000),
            fees: Vec::new(),
        };
        let _ = state.seat_tick(
            &schedule,
            &anchored,
            &discarding,
            Named::Lines(&[TickLine::Discard {
                tick,
                cause: DiscardCause::Recovery,
            }]),
            &mut Vec::new(),
        );
        let after = commit_carrying(&mut state, &schedule, 4, past_the_horizon() + 2_000, vec![]);
        assert!(!resolved_aborted(&after, leg.hash()), "resolved once");
        assert!(!dispatched(&after));
        assert_eq!(state.ticks.tick_assignment(leg.hash()), None);
        assert!(!state.counterparts.ledger.contains(leg.hash()));
    }

    /// The root chain's claim, at its parent at `height - 1`, reading a
    /// record and its consumer's `Never` of the record's transaction,
    /// both ends of which the chain holds: what returns the record.
    fn returned_at_the_root(height: u64) -> StateClaim {
        let id = CrossingId {
            producer: Address::new([0x61; 31], AddressClass::Component),
            consumer: Address::new([0x62; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x63; 32])),
            local: 0,
            output: 0,
        };
        let tx = TxHash::from(Hash::from_bytes(b"refused at the root"));
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let cell = id.cell(
            tx,
            ResourceAddr::new([0xE1; 31]),
            5,
            1_000,
            Terms::Escrowed {
                credit: SubstateKey {
                    owner: id.producer,
                    local: LocalKey([0x64; 16]),
                },
            },
        );
        let answer = id.answer(tx, Answered::Never, 1_000).to_bytes();
        StateClaim::new(
            proven_anchor_of(ShardId::ROOT, height - 1, WeightedTimestamp::ZERO),
            [
                (
                    record,
                    Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
                ),
                (never, Inclusion::Present(jmt_value_hash(&answer)).into()),
            ],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, id), (never, id)])
    }

    /// A block licensing only a reclaim seats no tick, so it holds no
    /// dispatch behind it: the next block's tick runs the members its
    /// lines name, on a replica that ran every tick, on one restored
    /// over the reclaiming block, and on one that restored it unrun.
    #[test]
    fn a_block_licensing_only_a_reclaim_dispatches_the_members_its_lines_name() {
        let schedule = make_test_topology();
        let reclaiming = block_reading(
            ShardId::ROOT,
            1,
            1_000,
            vec![],
            vec![returned_at_the_root(1)],
        );
        let tx = test_transaction(1);
        let next = block_reading(ShardId::ROOT, 2, 2_000, vec![Arc::new(tx.clone())], vec![]);
        let restored = |dispatch_from: u64| {
            let recovered = RecoveredState {
                committed_height: BlockHeight::new(1),
                replay: ReplayWindow {
                    blocks: vec![Verified::<CertifiedBlock>::from_persisted(
                        reclaiming.clone(),
                    )],
                    dispatch_from: BlockHeight::new(dispatch_from),
                    anchor_wt: Some(WeightedTimestamp::ZERO),
                },
                ..RecoveredState::default()
            };
            let mut state = ExecutionCoordinator::with_shared_stores(
                ValidatorId::new(0),
                ShardId::ROOT,
                Arc::new(TestCode::default()),
                Arc::new(CrossingIndexSlot::default()),
                &recovered,
                Arc::new(ExecCertStore::new()),
                Arc::new(FinalizationStore::new()),
                Arc::new(ProvenAnchors::new()),
                Arc::new(CounterpartMirror::new()),
            );
            state.seat_on_persisted_base(BlockHeight::new(1));
            let actions = state
                .on_committed_state_restored(&schedule, &StubVmStatics)
                .actions;
            (state, actions)
        };
        let live = {
            let mut state = make_test_state();
            let actions = state
                .commit_block_carrying(&schedule, &reclaiming, Naming::Composed)
                .actions;
            let mut actions = [
                actions,
                state.on_block_persisted(&schedule, BlockHeight::new(1)),
            ]
            .concat();
            actions.retain(|action| matches!(action, Action::ExecuteTransactions { .. }));
            (state, actions)
        };
        for (replica, (mut state, before)) in [
            ("ran every tick", live),
            ("restored", restored(1)),
            ("restored the reclaiming block unrun", restored(2)),
        ] {
            assert!(
                !before
                    .iter()
                    .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
                "{replica}: the reclaiming block dispatches nothing: {before:?}",
            );
            assert!(
                tick_members(&state, 1).is_empty() && state.held.is_empty(),
                "{replica}: and seats no tick",
            );
            let mut actions = state
                .commit_block_carrying(&schedule, &next, Naming::Composed)
                .actions;
            actions.extend(state.on_block_persisted(&schedule, BlockHeight::new(2)));
            let dispatched = actions.iter().find_map(|action| match action {
                Action::ExecuteTransactions { tick, requests, .. }
                    if *tick == BlockHeight::new(2) =>
                {
                    Some(
                        requests
                            .iter()
                            .map(|request| request.tx_hash)
                            .collect::<Vec<_>>(),
                    )
                }
                _ => None,
            });
            assert_eq!(
                dispatched,
                Some(vec![tx.hash()]),
                "{replica}: the next tick runs what its lines name",
            );
        }
    }

    /// A leg waiting to run past the evidence that its core never will
    /// is left to run: nothing takes it out of the candidates, and the
    /// next block naming it dispatches it. Its record goes back later, in
    /// the fold of a block reading its consumer's `Never`, which closes
    /// the entry as the transaction's abort.
    #[test]
    fn a_pending_leg_past_its_dead_core_runs_and_is_taken_back() {
        let schedule = two_shard_topology();
        let leg: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = leg.hash();
        let mut state = leg_state(&leg, &leg_classified());
        state.candidates.register(
            Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
            BTreeSet::from([HOME, PEER]),
            WeightedTimestamp::ZERO,
            PriceTable::GENESIS,
            leg_classified(),
        );
        record_peer_left_unsettled(&mut state, tx_hash);
        assert!(covered(&state, tx_hash), "the core is dead");

        let unnamed = block_reading(HOME, 1, 2_000, vec![], vec![]);
        let actions = state
            .commit_block_carrying(&schedule, &unnamed, Naming::Manifest)
            .actions;
        assert!(!dispatched(&actions));
        assert!(
            state.candidates.contains(tx_hash),
            "the leg still waits to run"
        );

        let naming = block_reading(HOME, 2, 3_000, vec![], vec![]);
        let mut actions = state
            .commit_block_carrying(&schedule, &naming, Naming::Composed)
            .actions;
        actions.extend(state.on_block_persisted(&schedule, BlockHeight::new(2)));
        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::ExecuteTransactions { requests, .. }
                    if requests.iter().any(|request| request.tx_hash == tx_hash)
            )),
            "the next block naming it runs it: {actions:?}",
        );

        let (record_key, _, cell) = owned_record();
        let returning = commit_carrying(
            &mut state,
            &schedule,
            3,
            past_the_horizon(),
            taking_back(record_key, &cell, 3),
        );
        assert!(resolved_aborted(&returning, tx_hash));
    }

    /// A validity end well clear of zero, so the deadline it derives is
    /// an instant the tests can sit either side of.
    const REFUSED_VALIDITY_END_MS: u64 = 4_000_000;

    /// A shard seated at [`HOME`] with a delivery waiting on a crossing
    /// [`PEER`] writes, and no reading of it. Returns the record, its
    /// cell and the clock the requirement was filed at, which is what the
    /// read's arming is measured from.
    fn a_delivery_waiting_on_a_crossing() -> (
        ExecutionCoordinator,
        ShardTrie,
        SubstateKey,
        CrossingCell,
        WeightedTimestamp,
    ) {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let (record_key, _, cell) = arrived_record(0x71, REFUSED_VALIDITY_END_MS);
        let filed_at = Deadline::of(WeightedTimestamp::from_millis(REFUSED_VALIDITY_END_MS)).at();
        state.provisioning.advance_clock(filed_at);
        state.provisioning.record_required(
            cell.tx,
            BTreeSet::from([Requirement::Crossing { key: record_key }]),
        );
        let trie = schedule
            .at(filed_at)
            .expect("the window is seated")
            .shard_trie()
            .clone();
        (state, trie, record_key, cell, filed_at)
    }

    /// The anchors a probe's asks of [`PEER`] name `record` at.
    fn record_asks(actions: &[Action], record: SubstateKey) -> Vec<Anchor> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(ids),
                    shard,
                    ..
                }) if *shard == PEER => Some(
                    ids.iter()
                        .filter(|(_, key)| *key == record)
                        .map(|(anchor, _)| *anchor)
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// A record a delivery here waits on is read from the record's
    /// holder one finalization delay past the commit that filed the
    /// want, at the holder's newest proven anchor, and not again until
    /// the holder has moved on; a committed arrival ends the read.
    #[test]
    fn a_record_read_arms_a_finalization_delay_past_the_commit_and_ends_with_the_arrival() {
        let (mut state, trie, record_key, cell, filed_at) = a_delivery_waiting_on_a_crossing();
        let armed = filed_at.plus(MAX_FINALIZATION_DELAY);
        let before = armed.minus(Duration::from_millis(1));
        state
            .counterparts
            .proven_anchors
            .record(proven_anchor_of(PEER, 9, before));
        let wanted = state.wanted_records();
        assert_eq!(wanted.len(), 1);
        assert!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, before, &wanted, EpochWindows::new(0)),
                record_key
            )
            .is_empty(),
            "nothing is asked inside one finalization delay of the commit that filed the want",
        );

        let first = proven_anchor_of(PEER, 10, armed);
        state.counterparts.proven_anchors.record(first);
        assert_eq!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, armed, &wanted, EpochWindows::new(0)),
                record_key
            ),
            vec![first],
            "one ask at the holder's newest proven anchor",
        );
        assert!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, armed, &wanted, EpochWindows::new(0)),
                record_key
            )
            .is_empty(),
            "and not again at the same anchor",
        );
        state
            .counterparts
            .proven_anchors
            .record(proven_anchor_of(PEER, 11, armed));
        assert!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, armed, &wanted, EpochWindows::new(0)),
                record_key
            )
            .is_empty(),
            "the second ask waits two heights",
        );
        let third = proven_anchor_of(PEER, 12, armed);
        state.counterparts.proven_anchors.record(third);
        assert_eq!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, armed, &wanted, EpochWindows::new(0)),
                record_key
            ),
            vec![third],
        );

        state.provisioning.handed(record_key, cell);
        let wanted = state.wanted_records();
        assert!(wanted.is_empty(), "a committed arrival ends the want");
        state
            .counterparts
            .proven_anchors
            .record(proven_anchor_of(PEER, 20, armed));
        assert!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, armed, &wanted, EpochWindows::new(0)),
                record_key
            )
            .is_empty(),
        );
    }

    /// Whether `state` holds, to offer, a live reading of the record at
    /// `key` naming `tx` as its issuer.
    fn holds_record(state: &ExecutionCoordinator, key: SubstateKey, tx: TxHash) -> bool {
        use hyperscale_vm_effects::CrossingLeaf;

        state
            .offers(&CarriedClaims::default())
            .state_claims
            .iter()
            .any(|claim| {
                claim.held(key).is_some_and(|bytes| {
                    matches!(
                        CrossingLeaf::read(&ProtocolHasher, key, bytes),
                        Some(CrossingLeaf::Record { cell, .. }) if cell.tx == tx
                    )
                })
            })
    }

    /// A consumer waiting on one record, its want filed one finalization
    /// delay back so the read is armed, and a pushed claim of the record
    /// at the holder's height 9: the state the push tests start from.
    fn a_body_awaiting_a_push() -> (
        ExecutionCoordinator,
        TopologySchedule,
        ShardTrie,
        SubstateKey,
        CrossingCell,
        Anchor,
        StateClaim,
    ) {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let (record_key, _, cell) = arrived_record(0x75, REFUSED_VALIDITY_END_MS);
        let now = Deadline::of(WeightedTimestamp::from_millis(REFUSED_VALIDITY_END_MS)).at();
        state
            .provisioning
            .advance_clock(now.minus(MAX_FINALIZATION_DELAY));
        state.provisioning.record_required(
            cell.tx,
            BTreeSet::from([Requirement::Crossing { key: record_key }]),
        );
        // The candidate the want is filed for, which is what keeps the
        // want standing across the commits the tests make.
        state.candidates.register_member(
            Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
            Member::whole(HOME),
            now,
            PriceTable::GENESIS,
        );
        state.provisioning.advance_clock(now);
        state.committed_ts = now;
        let trie = schedule
            .at(now)
            .expect("the window is seated")
            .shard_trie()
            .clone();
        let (state_root, proof) = state_and_proof(PEER, &[record_key], &[record_key]);
        let anchor = Anchor {
            shard: PEER,
            height: BlockHeight::new(9),
            state_root,
            ts: now,
        };
        let claim = StateClaim::new(
            anchor,
            [(
                record_key,
                Stated::Held(Bytes::new(cell.to_bytes()).unwrap()),
            )],
            proof,
        );
        (state, schedule, trie, record_key, cell, anchor, claim)
    }

    #[test]
    fn a_push_at_a_proven_anchor_is_held_and_stands_in_for_an_ask() {
        let (mut state, schedule, trie, record_key, cell, anchor, claim) = a_body_awaiting_a_push();
        state.counterparts.proven_anchors.record(anchor);
        let now = anchor.ts;
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert!(
            holds_record(&state, record_key, cell.tx),
            "the pushed reading is held",
        );
        assert!(state.parked_claims.is_empty());

        // While the pushed reading is held to offer nothing is asked,
        // and the want stands until a block carries it.
        let wanted = state.wanted_records();
        assert_eq!(wanted.len(), 1);
        for height in [9, 10, 11] {
            state
                .counterparts
                .proven_anchors
                .record(proven_anchor_of(PEER, height, now));
            assert!(
                record_asks(
                    &state
                        .counterparts
                        .probe(&trie, now, &wanted, EpochWindows::new(0)),
                    record_key
                )
                .is_empty(),
                "no ask at height {height} while the pushed reading is held",
            );
        }

        assert_eq!(
            state.offers(&CarriedClaims::default()).state_claims.len(),
            1,
            "the pushed reading is what the next block carries",
        );
    }

    /// A pushed reading at an anchor in its shard's recovery band, a
    /// harvested or coast block above the frontier, is dropped whether
    /// or not its proof is held: no block admits it. The same reading
    /// with the frontier at its height is held.
    #[test]
    fn a_push_at_an_anchor_in_a_recovery_band_is_dropped() {
        for (frontier, held) in [(8, false), (9, true)] {
            let (mut state, schedule, _, record_key, cell, anchor, claim) =
                a_body_awaiting_a_push();
            let recovered =
                TopologySchedule::single(Arc::new((**schedule.head()).clone().with_recoveries(
                    BTreeMap::from([(
                        PEER,
                        vec![RecoveryBinding {
                            rotated_at: Epoch::GENESIS,
                            attested_frontier: BlockHeight::new(frontier),
                            completed: true,
                        }],
                    )]),
                )));
            state.counterparts.proven_anchors.record(anchor);
            assert!(
                state
                    .on_crossing_readings(&recovered, vec![claim])
                    .is_empty()
            );
            assert_eq!(
                holds_record(&state, record_key, cell.tx),
                held,
                "frontier {frontier}",
            );
            assert!(state.parked_claims.is_empty());
        }
    }

    #[test]
    fn a_push_before_its_proof_is_parked_and_carried_by_the_header() {
        let (mut state, schedule, _, record_key, cell, anchor, claim) = a_body_awaiting_a_push();
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert_eq!(
            state.parked_claims.len(),
            1,
            "held until the anchor is proven"
        );
        assert!(!holds_record(&state, record_key, cell.tx));

        state.counterparts.proven_anchors.record(anchor);
        state.on_committed_remote_header(&schedule, anchor);
        assert!(state.parked_claims.is_empty());
        assert!(holds_record(&state, record_key, cell.tx));
    }

    #[test]
    fn a_push_whose_anchor_disagrees_with_the_proven_one_is_dropped() {
        let (mut state, schedule, _, _, _, anchor, claim) = a_body_awaiting_a_push();
        state.counterparts.proven_anchors.record(Anchor {
            state_root: StateRoot::ZERO,
            ..anchor
        });
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert!(
            state.parked_claims.is_empty(),
            "not parked: the anchor is proven, differently"
        );
        assert!(
            state
                .offers(&CarriedClaims::default())
                .state_claims
                .is_empty()
        );
    }

    #[test]
    fn a_push_ahead_of_its_want_is_held_until_the_want_is_filed() {
        let (mut state, schedule, _, record_key, cell, anchor, claim) = a_body_awaiting_a_push();
        state.provisioning.record_required(cell.tx, BTreeSet::new());
        state.counterparts.proven_anchors.record(anchor);
        // Short of the record's validity end, where a block here may
        // still commit its transaction and file the want: past the end
        // a record nothing waits on is held for no want.
        state.committed_ts = WeightedTimestamp::from_millis(REFUSED_VALIDITY_END_MS - 1);
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert!(
            state
                .offers(&CarriedClaims::default())
                .state_claims
                .is_empty(),
            "nothing wants the reading yet, so nothing is offered",
        );
        assert_eq!(state.parked_claims.len(), 1, "and it is held for the want");

        state.provisioning.record_required(
            cell.tx,
            BTreeSet::from([Requirement::Crossing { key: record_key }]),
        );
        let wanted = state.wanted_records();
        assert!(state.release_early_pushes(&schedule, &wanted).is_empty());
        assert!(state.parked_claims.is_empty());
        assert!(holds_record(&state, record_key, cell.tx));
    }

    /// A record whose member here already holds its arrival is one that
    /// member may yet take. Past the record's validity end every push of
    /// it finds the member's row standing: none is kept to offer, and
    /// none is parked for a want, since no want can be filed for it.
    /// With the member gone, its row with it, the next push is kept.
    #[test]
    fn a_push_of_a_record_a_member_holds_the_arrival_of_is_neither_kept_nor_parked() {
        let (mut state, schedule, _, record_key, cell, anchor, claim) = a_body_awaiting_a_push();
        state.provisioning.handed(record_key, cell);
        assert!(
            state.wanted_records().is_empty(),
            "the member wants nothing more"
        );
        let row = member_row_leaf(HOME, cell.tx);
        let rows = hold(&mut state, &schedule, [(row, vec![1])]);
        let pushed_at = |height: u64| {
            let mut claim = claim.clone();
            claim.anchor.height = BlockHeight::new(height);
            claim
        };
        for height in 9..73 {
            let claim = pushed_at(height);
            state.counterparts.proven_anchors.record(claim.anchor);
            assert!(
                state
                    .on_crossing_readings(&schedule, vec![claim])
                    .is_empty()
            );
            assert!(
                state
                    .offers(&CarriedClaims::default())
                    .state_claims
                    .is_empty(),
                "kept at {height}"
            );
            assert!(state.parked_claims.is_empty(), "parked at {height}");
        }

        rows.remove(row);
        state.provisioning.sweep(state.committed_ts, |_| false);
        let claim = pushed_at(73);
        state.counterparts.proven_anchors.record(claim.anchor);
        assert_eq!(anchor.shard, claim.anchor.shard);
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert!(holds_record(&state, record_key, cell.tx));
    }

    /// A pushed presence held when another proposer's block raises its
    /// producer's entry above it, by an absence naming the record's
    /// crossing, is dropped at that commit, its read
    /// starts over, the next proven anchor at or above the floor is
    /// asked at once, and a push at the old anchor arriving afterwards
    /// is dropped where it lands.
    #[test]
    fn a_held_presence_below_a_raised_floor_is_dropped_and_read_again() {
        let (mut state, schedule, trie, record_key, cell, anchor, claim) = a_body_awaiting_a_push();
        state.counterparts.proven_anchors.record(anchor);
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim.clone()])
                .is_empty()
        );
        assert!(holds_record(&state, record_key, cell.tx));

        let now = anchor.ts;
        let id = CrossingId::of_record(record_key.owner, &cell);
        let mut above = proven_claim(PEER, 10, &[], &[record_key]).naming([(record_key, id)]);
        above.anchor.ts = now.plus(Duration::from_secs(1));
        commit_carrying(&mut state, &schedule, 1, now.as_millis(), vec![above]);
        assert!(
            !holds_record(&state, record_key, cell.tx),
            "the held presence sits below the raised floor and is dropped",
        );

        let next = proven_anchor_of(PEER, 11, now.plus(Duration::from_secs(2)));
        state.counterparts.proven_anchors.record(next);
        let wanted = state.wanted_records();
        assert_eq!(
            record_asks(
                &state
                    .counterparts
                    .probe(&trie, next.ts, &wanted, schedule.windows()),
                record_key
            ),
            vec![next],
            "the read starts over and asks at the next anchor above the floor",
        );
        assert!(
            state
                .on_crossing_readings(&schedule, vec![claim])
                .is_empty()
        );
        assert!(
            !holds_record(&state, record_key, cell.tx),
            "a push at the old anchor is dropped below the floor",
        );
    }

    /// A push below the floor carrying a record beside a cell the
    /// frontier does not fence loses the record and keeps the cell: the
    /// record is not offered, and the cell is held, under the proof cut
    /// to it, for the want that will name it.
    #[test]
    fn a_mixed_push_below_the_floor_keeps_what_the_frontier_does_not_fence() {
        let (mut state, schedule, _, record_key, cell, anchor, _) = a_body_awaiting_a_push();
        let now = anchor.ts;
        let id = CrossingId::of_record(record_key.owner, &cell);
        let mut above = proven_claim(PEER, 10, &[], &[record_key]).naming([(record_key, id)]);
        above.anchor.ts = now.plus(Duration::from_secs(1));
        commit_carrying(&mut state, &schedule, 1, now.as_millis(), vec![above]);

        let beside = SubstateKey {
            owner: record_key.owner,
            local: LocalKey([0x77; 16]),
        };
        let mut bare = proven_claim(PEER, 8, &[beside], &[beside]);
        bare.anchor.ts = now.minus(Duration::from_secs(1));
        let below = bare.anchor;
        state.counterparts.proven_anchors.record(below);
        assert!(
            state
                .on_crossing_readings(&schedule, vec![bare.clone()])
                .is_empty()
        );
        assert_eq!(
            state.parked_claims.release_early(&BTreeSet::from([beside])),
            vec![bare],
            "a push the frontier fences nothing of is held whole below the floor",
        );

        let (state_root, proof) = state_and_proof_holding(
            PEER,
            &[(record_key, cell.to_bytes()), (beside, vec![1])],
            &[record_key, beside],
        );
        let below = Anchor {
            height: BlockHeight::new(7),
            state_root,
            ..below
        };
        state.counterparts.proven_anchors.record(below);
        let cells: Vec<(SubstateKey, Stated)> = proof
            .inclusions(state_root, PEER, &[record_key, beside])
            .expect("the fixture proof answers for its keys")
            .into_iter()
            .map(|(key, inclusion)| {
                if key == record_key {
                    (key, Stated::Held(Bytes::new(cell.to_bytes()).unwrap()))
                } else {
                    (key, Stated::Inclusion(inclusion))
                }
            })
            .collect();
        let mixed = StateClaim::new(below, cells, proof);
        assert_eq!(mixed.verify(), Ok(()));
        assert!(
            state
                .on_crossing_readings(&schedule, vec![mixed])
                .is_empty()
        );
        assert!(
            !holds_record(&state, record_key, cell.tx),
            "the record below the floor is not held to offer",
        );
        let kept = state.parked_claims.release_early(&BTreeSet::from([beside]));
        assert_eq!(kept.len(), 1, "the cell beside it is held");
        assert_eq!(kept[0].keys(), vec![beside]);
        assert_eq!(kept[0].anchor, below);
        assert_eq!(kept[0].verify(), Ok(()));
    }

    #[test]
    fn held_claims_are_offered_oldest_anchor_first() {
        let (mut state, schedule, _, record_key, cell, anchor, later) = a_body_awaiting_a_push();
        let earlier_ts = anchor.ts.minus(Duration::from_secs(1));
        let (state_root, proof) = state_and_proof(PEER, &[record_key], &[record_key]);
        let earlier_anchor = Anchor {
            shard: PEER,
            height: BlockHeight::new(8),
            state_root,
            ts: earlier_ts,
        };
        let earlier = StateClaim::new(
            earlier_anchor,
            [(
                record_key,
                Stated::Held(Bytes::new(cell.to_bytes()).unwrap()),
            )],
            proof,
        );
        state.counterparts.proven_anchors.record(anchor);
        state.counterparts.proven_anchors.record(earlier_anchor);
        state.on_crossing_readings(&schedule, vec![later, earlier]);
        let offered: Vec<Anchor> = state
            .offers(&CarriedClaims::default())
            .state_claims
            .iter()
            .map(|claim| claim.anchor)
            .collect();
        assert_eq!(offered, vec![earlier_anchor, anchor]);
    }

    /// An anchor of `shard` at `height`, as a validator that has proven
    /// it holds one.
    fn proven_anchor_of(shard: ShardId, height: u64, ts: WeightedTimestamp) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts,
        }
    }

    /// Seat an answered crossing, returning the record key, the answer
    /// cell's key and the crossing.
    fn answered_crossing(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        seed: u8,
    ) -> (SubstateKey, SubstateKey, CrossingId) {
        let (record_key, _, cell) = arrived_record(seed, REFUSED_VALIDITY_END_MS);
        let id = CrossingId::of_record(record_key.owner, &cell);
        let answer_key = id.answer_key(&ProtocolHasher, Answered::Taken);
        hold(
            state,
            schedule,
            [(
                answer_key,
                id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                    .to_bytes(),
            )],
        );
        (record_key, answer_key, id)
    }

    /// An answer's deletion is the commit fold's alone: a block carrying
    /// its record read absent, named for the crossing, composes no
    /// member for it, whatever the fold makes of the reading.
    #[test]
    fn a_record_read_absent_composes_no_member() {
        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let (record_key, _, id) = answered_crossing(&mut state, &schedule, 0x7A);
        let at = WeightedTimestamp::from_millis(10_000);
        state.committed_ts = at;
        let (claim, _) = proven_at(&mut state, &schedule, PEER, 9, at, &[], &[record_key]);
        let actions = commit_carrying(
            &mut state,
            &schedule,
            1,
            at.as_millis(),
            vec![claim.clone().naming([(record_key, id)])],
        );
        assert!(
            claim
                .naming([(record_key, id)])
                .deleting()
                .any(|deleting| deleting == record_key),
            "the reading is the one the fold judges the answer's deletion on",
        );
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::ExecuteTransactions { .. })),
            "and no member is composed for it",
        );
    }

    /// A leg entry on `HOME` whose core consumer's claim sits on `PEER`,
    /// with the transaction, its figures and the claim key beside it.
    fn consumer_claim_fixture() -> (
        Arc<Verifiable<Transaction>>,
        UnsettledTx,
        SubstateKey,
        ExecutionCoordinator,
    ) {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let figures = UnsettledTx::for_transaction(
            &transaction,
            test_committed(),
            transaction.price(&PriceTable::GENESIS),
            &PriceTable::GENESIS,
        );
        let claim = core_claim(&leg_classified());
        let state = claimed_leg_state(&transaction);
        (transaction, figures, claim, state)
    }

    /// A consumer's claim proved present, named for its crossing, is
    /// what settles the record: the commit fold removes it, the entry
    /// that issued it closes as the transaction accepted, and no member
    /// is composed. The committed claim is the whole of the evidence: no
    /// certificate is fetched after it.
    #[test]
    fn a_claim_proved_present_settles_the_record_in_the_fold() {
        let schedule = two_shard_topology();
        let (transaction, figures, claim, mut state) = consumer_claim_fixture();
        let tx_hash = transaction.hash();
        let crossing = leg_classified()
            .crossings()
            .find(|(edge, _)| edge.from == HOME)
            .map(|(edge, _)| edge.crossing.id)
            .expect("the leg issues one crossing");
        let record_key = crossing.record_key(&ProtocolHasher);
        let cell = crossing.cell(
            tx_hash,
            *PROTOCOL_RESOURCE,
            10,
            transaction
                .validity_range()
                .end_timestamp_exclusive
                .as_millis(),
            Terms::Escrowed {
                credit: SubstateKey {
                    owner: crossing.producer,
                    local: LocalKey([0x33; 16]),
                },
            },
        );
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);
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
            vec![bundle.naming([(claim, crossing)])],
        );
        assert!(
            !folded.iter().any(|action| matches!(
                action,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::ExecutionCerts(_),
                    ..
                })
            )),
            "a present claim fetches no certificate"
        );
        assert!(
            !folded.iter().any(|action| matches!(
                action,
                Action::ExecuteTransactions { requests, .. }
                    if requests.iter().any(|request| request.tx_hash == tx_hash)
            )),
            "no member is composed for it",
        );
        assert!(
            folded.iter().any(|action| matches!(
                action,
                Action::Continuation(ProtocolEvent::TransactionsResolved { resolutions })
                    if resolutions.contains(&(tx_hash, TxResolution::Decided(TransactionDecision::Accept)))
            )),
            "and the entry closes as the transaction accepted: {folded:?}",
        );
        assert!(
            !state.counterparts.ledger.contains(tx_hash),
            "the ledger has let the entry go"
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

        state.commit_block_carrying(
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
            Naming::Composed,
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
    /// charge.
    #[test]
    fn a_tick_that_has_not_attested_withholds_the_abort() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.commit_block_carrying(
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
            Naming::Composed,
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

    /// A tick holding a member whose success decides alone keeps it past
    /// the transaction's deadline.
    ///
    /// The member was named to run while the deadline had not passed, so
    /// its success is admissible whenever its finalization commits: a
    /// producer reclaims only on the consumer's own `Never`, which no
    /// block carries beside the success.
    #[test]
    fn a_tick_holding_a_success_that_decides_alone_keeps_it_past_the_deadline() {
        let schedule = make_test_topology();
        let mut state = make_test_state();
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let deadline_ms = 60_000 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();

        state.commit_block_carrying(
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
            Naming::Composed,
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
            outcomes.iter().all(|outcome| outcome.tx_hash() != tx_hash),
            "at the deadline nothing abandons the member: {outcomes:?}"
        );
        assert_eq!(
            state.ticks.tick_assignment(tx_hash),
            Some(held_by),
            "and the tick that holds it still speaks for it"
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
        leaves_snap_attesting(leaves, cut, departed, None)
    }

    /// [`leaves_snap_departed`] whose boundary records attest `attested`
    /// as each departed shard's settled root: with one, the departure's
    /// evidence is something a survivor fetches.
    fn leaves_snap_attesting(
        leaves: &[ShardId],
        cut: &[(ShardId, u64)],
        departed: &[(ShardId, Option<Epoch>)],
        attested: Option<SettledTxsRoot>,
    ) -> Arc<TopologySnapshot> {
        let boundaries: BTreeMap<ShardId, ShardAnchor> = departed
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
                        terminal_settled_txs: attested,
                        handoff_complete: *handoff_complete,
                        terminal_epoch: None,
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

    /// The two leaves a delivery fixture places off [`HOME`], [`PEER`]'s
    /// children again: the core of one shard bearing the verdict, and
    /// the shard the leg's crossing is delivered on.
    const BEARER: ShardId = ShardId::leaf(2, 2);
    const DELIVERER: ShardId = ShardId::leaf(2, 3);

    /// A shape frozen divided with an inbound leg on `HOME` feeding a
    /// core on `PEER`.
    fn leg_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &ShardTrie::uniform(1));
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
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([CORE, CORE_SIBLING]));
        assert!(classified.decomposed());
        classified
    }

    /// A shape frozen divided under [`delivery_topology`] with an
    /// inbound leg on [`HOME`] delivered on [`DELIVERER`], the core of
    /// one shard on [`BEARER`].
    fn delivery_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[]),
            leg(3, LegRole::Outbound, &[(0, 0)]),
        ];
        let trie = ShardTrie::from_leaves([HOME, BEARER, DELIVERER]);
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([BEARER]));
        assert!(classified.decomposed());
        classified
    }

    /// The claim cell the core writes for what `classified` says
    /// [`HOME`] issued, under the shard holding the consumer's target.
    fn core_claim(classified: &Classified) -> SubstateKey {
        one_answer(classified, Kind::Escrowed, Answered::Taken, "to the core")
    }

    /// The one answer cell in `answered`'s role that the consumer of
    /// the `kind` crossing [`HOME`] issued writes.
    fn one_answer(
        classified: &Classified,
        kind: Kind,
        answered: Answered,
        to: &str,
    ) -> SubstateKey {
        let answers: Vec<SubstateKey> = classified
            .crossings()
            .filter(|(edge, _)| edge.from == HOME && edge.crossing.kind == kind)
            .map(|(edge, _)| edge.crossing.id.answer_key(&ProtocolHasher, answered))
            .collect();
        assert_eq!(answers.len(), 1, "the fixture issues one crossing {to}");
        answers[0]
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

    /// [`peer_terminating_schedule_stamped`] at one-second epochs whose
    /// boundary record attests a settled root, so the peer's terminal is
    /// one a survivor fetches from; and a state on the surviving shard
    /// holding nothing of the departure, one epoch past the cut.
    fn state_beside_an_attested_departure(
        handoff_complete: Option<Epoch>,
    ) -> (ExecutionCoordinator, TopologySchedule) {
        let (left, right) = PEER.children();
        let mut sched = TopologySchedule::new(
            1_000,
            Epoch::new(0),
            leaves_snap(&[HOME, PEER], &[(PEER, 0)]),
        );
        let post = leaves_snap_attesting(
            &[HOME, left, right],
            &[],
            &[(PEER, handoff_complete)],
            Some(SettledTxsRoot::ZERO),
        );
        for epoch in 1..=12u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&post));
        }
        sched.set_head(post);
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        state.committed_ts = WeightedTimestamp::from_millis(1_500);
        (state, sched)
    }

    /// The terminal block the boundary record of
    /// [`state_beside_an_attested_departure`] names for the peer.
    fn peer_terminal() -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(b"terminal"))
    }

    /// The departed shards `wanted` asks about.
    fn shards_of(wanted: &[TerminalEvidence]) -> Vec<ShardId> {
        wanted.iter().map(|evidence| evidence.shard).collect()
    }

    /// The terminals whose lines `state` asks for under `sched`.
    fn lines_wanted(state: &ExecutionCoordinator, sched: &TopologySchedule) -> Vec<ShardId> {
        shards_of(
            &state
                .counterparts
                .wanted_terminal_lines(sched, state.committed_ts),
        )
    }

    /// The terminals whose settled sets `state` asks for under `sched`.
    fn sets_wanted(state: &ExecutionCoordinator, sched: &TopologySchedule) -> Vec<ShardId> {
        shards_of(
            &state
                .counterparts
                .wanted_settled_sets(sched, state.committed_ts),
        )
    }

    fn empty_settled_set() -> SettledTxSet {
        SettledTxSet {
            txs: BTreeSet::new(),
            terminal_wt: WeightedTimestamp::from_millis(1_000),
        }
    }

    /// A departed shard's lines are wanted, under the terminal its
    /// boundary record names, while the names its terminal ended are not
    /// held; recording them, an empty list included, ends the want. The
    /// settled set is wanted and acquired on its own: neither answer
    /// stands in for the other.
    #[test]
    fn terminal_lines_are_wanted_until_the_names_are_held() {
        let (mut state, sched) = state_beside_an_attested_departure(None);
        let wanted = state
            .counterparts
            .wanted_terminal_lines(&sched, state.committed_ts);
        let [evidence] = wanted.as_slice() else {
            panic!("one departure, one terminal: {wanted:?}");
        };
        assert_eq!(evidence.shard, PEER);
        assert_eq!(evidence.height, BlockHeight::new(9));
        assert_eq!(evidence.block_hash, peer_terminal());
        assert_eq!(sets_wanted(&state, &sched), vec![PEER]);

        // The set arriving leaves the lines wanted.
        let _ = state.record_settled_txs(&sched, PEER, empty_settled_set());
        assert!(sets_wanted(&state, &sched).is_empty());
        assert_eq!(lines_wanted(&state, &sched), vec![PEER]);

        let accepted = TxHash::from(Hash::from_bytes(b"accepted"));
        state.record_ended_names(PEER, peer_terminal(), BTreeSet::from([accepted]));
        assert!(lines_wanted(&state, &sched).is_empty());
        let mirror = &state.counterparts.mirror;
        assert_eq!(mirror.ended(PEER, peer_terminal(), accepted), Some(true));
        assert_eq!(
            mirror.ended(
                PEER,
                peer_terminal(),
                TxHash::from(Hash::from_bytes(b"left"))
            ),
            Some(false),
        );
    }

    /// The names arriving first leave the settled set wanted, and a
    /// terminal that ended nothing is still an answer.
    #[test]
    fn the_names_arriving_leave_the_settled_set_wanted() {
        let (state, sched) = state_beside_an_attested_departure(None);

        state.record_ended_names(PEER, peer_terminal(), BTreeSet::new());

        assert!(lines_wanted(&state, &sched).is_empty());
        assert_eq!(sets_wanted(&state, &sched), vec![PEER]);
        assert!(
            state
                .counterparts
                .mirror
                .with_settled(|sets| !sets.contains_key(&PEER)),
        );
    }

    /// The lines stop being wanted where the settled set does: once the
    /// handoff-anchored evidence window has closed.
    #[test]
    fn terminal_lines_are_not_wanted_past_the_evidence_window() {
        let (mut state, sched) = state_beside_an_attested_departure(Some(Epoch::new(0)));
        let expiry = sched
            .handoff_evidence_expiry(PEER)
            .expect("the head carries the stamp");

        state.committed_ts = expiry;
        assert_eq!(lines_wanted(&state, &sched), vec![PEER]);
        assert_eq!(sets_wanted(&state, &sched), vec![PEER]);

        state.committed_ts = expiry.plus(Duration::from_millis(1));
        assert!(lines_wanted(&state, &sched).is_empty());
        assert!(sets_wanted(&state, &sched).is_empty());
    }

    /// Names verified against a terminal the boundary record does not
    /// name are not the current terminal's: the want stands until the
    /// names of the terminal the evidence names arrive.
    #[test]
    fn names_of_another_terminal_leave_the_lines_wanted() {
        let (state, sched) = state_beside_an_attested_departure(None);
        let accepted = TxHash::from(Hash::from_bytes(b"accepted"));
        let superseded = BlockHash::from_raw(Hash::from_bytes(b"superseded"));

        state.record_ended_names(PEER, superseded, BTreeSet::from([accepted]));
        assert_eq!(lines_wanted(&state, &sched), vec![PEER]);
        let mirror = &state.counterparts.mirror;
        assert_eq!(mirror.ended(PEER, peer_terminal(), accepted), None);

        state.record_ended_names(PEER, peer_terminal(), BTreeSet::new());
        assert!(lines_wanted(&state, &sched).is_empty());
        let mirror = &state.counterparts.mirror;
        assert_eq!(mirror.ended(PEER, peer_terminal(), accepted), Some(false));
    }

    /// Every beacon fold names the terminals whose lines are wanted on
    /// their own fetch, beside the settled sets', and names none once
    /// the names are held, which is what the node's diff releases on.
    #[test]
    fn a_beacon_fold_asks_for_the_lines_on_their_own_fetch() {
        let (mut state, sched) = state_beside_an_attested_departure(None);
        let asked = |state: &mut ExecutionCoordinator| {
            let actions = state.on_beacon_block_persisted(&sched).actions;
            let lines = actions.iter().find_map(|action| match action {
                Action::Fetch(FetchRequest::TerminalLines { wanted, .. }) => {
                    Some(shards_of(wanted))
                }
                _ => None,
            });
            let sets = actions.iter().find_map(|action| match action {
                Action::Fetch(FetchRequest::SettledTxs { wanted, .. }) => Some(shards_of(wanted)),
                _ => None,
            });
            (lines, sets)
        };

        assert_eq!(asked(&mut state), (Some(vec![PEER]), Some(vec![PEER])));

        state.record_ended_names(PEER, peer_terminal(), BTreeSet::new());
        assert_eq!(asked(&mut state), (Some(vec![]), Some(vec![PEER])));
    }

    /// The names leave the mirror with the set, at the commit that finds
    /// the schedule no longer reading the departure's evidence.
    #[test]
    fn the_ended_names_retire_with_the_settled_set() {
        let (mut state, open) = state_beside_an_attested_departure(None);
        let accepted = TxHash::from(Hash::from_bytes(b"accepted"));
        let _ = state.record_settled_txs(&open, PEER, empty_settled_set());
        state.record_ended_names(PEER, peer_terminal(), BTreeSet::from([accepted]));

        let block = make_live_block(BlockHeight::new(1), 6_001, ValidatorId::new(0), vec![]);
        let now = WeightedTimestamp::from_millis(6_001);
        let _ = state
            .counterparts
            .on_commit(open.head().shard_trie(), &open, &block, now, &[]);
        let mirror = &state.counterparts.mirror;
        assert_eq!(
            mirror.ended(PEER, peer_terminal(), accepted),
            Some(true),
            "an unstamped window holds the names"
        );
        assert!(mirror.with_settled(|sets| sets.contains_key(&PEER)));

        let (_, closed) = state_beside_an_attested_departure(Some(Epoch::new(0)));
        let _ = state
            .counterparts
            .on_commit(closed.head().shard_trie(), &closed, &block, now, &[]);
        let mirror = &state.counterparts.mirror;
        assert_eq!(mirror.ended(PEER, peer_terminal(), accepted), None);
        assert!(mirror.with_settled(|sets| !sets.contains_key(&PEER)));
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
            .record_abandonment_records(&[AbandonmentRecord::new(
                PEER,
                WeightedTimestamp::from_millis(60_000),
                vec![UnsettledTx {
                    tx_hash,
                    deadline: Deadline::of(WeightedTimestamp::from_millis(30_000)),
                    charged: 1,
                    charge: AbortCharge {
                        vault: SubstateKey {
                            owner: Address::new([9; 31], AddressClass::Component),
                            local: LocalKey([9; 16]),
                        },
                        amount: 5,
                    },
                    committed: test_committed(),
                    reach: Capped::empty(),
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
                Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(tx_hash, tick_id);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &Classified::whole())],
        );
        state
            .counterparts
            .ledger
            .certify(tx_hash, Certified::ByExecution);
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
                Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(tx_hash, tick_id);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &Classified::whole())],
        );
        state
            .counterparts
            .ledger
            .certify(tx_hash, Certified::ByExecution);
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

        let records = state.offers(&CarriedClaims::default()).abandonment_records;
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
        assert!(state.counterparts.ledger.is_covered(tx_hash));

        // And what it does not offer twice.
        assert!(
            state
                .offers(&CarriedClaims::default())
                .abandonment_records
                .is_empty(),
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
        state.commit_block_carrying(
            &sched,
            &test_certify(block, STRANDED_DEADLINE_MS),
            Naming::Composed,
        );
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
        state.commit_block_carrying(&sched, &test_certify(block, later), Naming::Composed);
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

        let records = state.offers(&CarriedClaims::default()).abandonment_records;
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

        let records = state.offers(&CarriedClaims::default()).abandonment_records;
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

    /// A tick released with nothing kept takes its certificate out of
    /// the serving cache with it.
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
                    Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
                    AggregateSignature::ZERO,
                    quorum_signers(),
                ),
            )));

        state.release_tick(tick_id, Some(tx_hash));

        assert!(
            state.exec_certs.get(&tick_id).is_none(),
            "the tick's own entry goes with it",
        );
        assert!(
            state.exec_certs.certificates_for_tx(tx_hash).is_empty(),
            "and so does the index a counterpart asks by",
        );
    }

    /// A success with a receipt in hand, as the engine reports one.
    fn succeeded() -> ExecutionOutcome {
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        }
    }

    /// The receipt a succeeded member's finalization drains.
    fn succeeded_receipt(tx_hash: TxHash) -> StoredReceipt {
        StoredReceipt {
            tx_hash,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        }
    }

    /// [`PEER`]'s certificate settling `tx_hash` against this shard's:
    /// a success that awaited [`HOME`] for it.
    fn peer_settles(tx_hash: TxHash) -> Arc<Verified<ExecutionCertificate>> {
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            TickId::new(PEER, BlockHeight::new(1)),
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"peer")),
            Capped::from_array([TxOutcome::new(tx_hash, succeeded()).awaiting([HOME])]),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )))
    }

    /// A state whose tick at height 1 holds `T`, a transaction whose
    /// verdict [`PEER`] shares, beside `X`, a member of this shard alone,
    /// with this shard's own certificate out attesting both succeeded and
    /// both receipts in hand. Past `X`'s deadline, at a frontier where
    /// [`PEER`] can still settle `T` against the certificate.
    fn state_holding_a_shared_verdict(seed: u8) -> (ExecutionCoordinator, TickId, TxHash, TxHash) {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        let shared: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(seed)),
        ));
        let alone: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(test_transaction(seed + 1)),
        ));
        let (t, x) = (shared.hash(), alone.hash());
        let mut tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            vec![
                (
                    Arc::new(Verified::new_unchecked_for_test(straddling_transaction(
                        seed,
                    ))),
                    BTreeSet::from([HOME, PEER]),
                ),
                (
                    Arc::new(Verified::new_unchecked_for_test(test_transaction(seed + 1))),
                    BTreeSet::from([HOME]),
                ),
            ],
        );
        for tx_hash in [t, x] {
            tick.record_execution_result(tx_hash, succeeded());
            tick.record_receipt(succeeded_receipt(tx_hash));
        }
        certify_own(&mut tick);
        state.ticks.insert_tick(tick_id, tick);
        state.ticks.assign_tx(t, tick_id);
        state.ticks.assign_tx(x, tick_id);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [
                (&shared, &Classified::whole()),
                (&alone, &Classified::whole()),
            ],
        );
        state.counterparts.ledger.certify(t, Certified::ByExecution);
        state.counterparts.ledger.certify(x, Certified::ByExecution);
        state.committed_ts = WeightedTimestamp::from_millis(STRANDED_DEADLINE_MS);
        (state, tick_id, t, x)
    }

    /// A state at [`HOME`] whose tick at height 1 holds two transactions
    /// whose verdict [`PEER`] shares, this shard's own certificate out
    /// attesting both succeeded and both receipts in hand.
    fn state_holding_two_legs() -> (ExecutionCoordinator, TickId, TxHash, TxHash) {
        let (mut state, tick_id, near, far) = state_running_two_legs();
        state
            .ticks
            .get_tick_mut(&tick_id)
            .expect("seated above")
            .add_execution_certificate(own_certificate(tick_id, 1_000, near, far));
        (state, tick_id, near, far)
    }

    /// [`HOME`]'s complete certificate of `tick_id`, anchored at
    /// `anchor_ms`, attesting `near` and `far` succeeded awaiting
    /// [`PEER`] as the vote of a replica that ran them attests it.
    fn own_certificate(
        tick_id: TickId,
        anchor_ms: u64,
        near: TxHash,
        far: TxHash,
    ) -> Arc<Verified<ExecutionCertificate>> {
        use hyperscale_types::compute_global_receipt_root;
        let outcomes = [(near, 1), (far, 2)].map(|(tx_hash, seed)| {
            TxOutcome::new(tx_hash, succeeded())
                .charging(straddling_transaction(seed).price(&PriceTable::GENESIS))
                .awaiting([PEER])
                .as_role(Role::Whole)
        });
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(anchor_ms),
            compute_global_receipt_root(&outcomes),
            Capped::from_array(outcomes),
            AggregateSignature::ZERO,
            quorum_signers(),
        )))
    }

    /// Cast `tick`'s own vote and feed it the certificate of that vote,
    /// anchored at the tick: what a replica that ran the tick holds once
    /// its committee certified it.
    fn certify_own(tick: &mut TickState) {
        let (anchor, root, outcomes) = tick
            .build_vote_data()
            .expect("every member of the fixture's tick came back");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                anchor,
                root,
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
    }

    /// [`state_holding_two_legs`] before this shard's own certificate
    /// lands: both members run, both receipts in hand, the vote cast.
    fn state_running_two_legs() -> (ExecutionCoordinator, TickId, TxHash, TxHash) {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        let shared = |seed: u8| {
            Arc::new(Verified::new_unchecked_for_test(straddling_transaction(
                seed,
            )))
        };
        let (near, far) = (shared(1).hash(), shared(2).hash());
        let mut tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            vec![
                (shared(1), BTreeSet::from([HOME, PEER])),
                (shared(2), BTreeSet::from([HOME, PEER])),
            ],
        );
        for tx_hash in [near, far] {
            tick.record_execution_result(tx_hash, succeeded());
            tick.record_receipt(succeeded_receipt(tx_hash));
            state.ticks.assign_tx(tx_hash, tick_id);
        }
        tick.build_vote_data().expect("both members came back");
        state.ticks.insert_tick(tick_id, tick);
        (state, tick_id, near, far)
    }

    /// Hand off whatever `tick_id` can, and commit the stating half
    /// among it as the block that carries it does. Returns that half.
    fn commit_stating(
        state: &mut ExecutionCoordinator,
        tick_id: TickId,
    ) -> Arc<Verifiable<Finalization>> {
        let stating = announced(&state.finalize(&tick_id))
            .into_iter()
            .find(|fw| fw.half() == TickHalf::Stated)
            .expect("a tick holding its own certificate hands off its stating half");
        state.remove_finalization(stating.as_unverified());
        stating
    }

    /// The transactions each finalization states a yes for.
    fn stated_by(finalizations: &[Arc<Verifiable<Finalization>>]) -> Vec<Vec<TxHash>> {
        finalizations
            .iter()
            .map(|fw| fw.stated_outcomes().map(TxOutcome::tx_hash).collect())
            .collect()
    }

    /// The stating halves the store holds for a proposer.
    fn held_stating(state: &ExecutionCoordinator) -> Vec<Arc<Verifiable<Finalization>>> {
        state
            .get_finalizations()
            .into_iter()
            .filter(|fw| fw.half() == TickHalf::Stated)
            .collect()
    }

    /// A committed discard that takes a member out of a tick whose
    /// stating half is handed off and not committed withdraws that
    /// half: no block admits one stating a member its tick no longer
    /// holds. The tick owes it again, the copy held for a proposer goes,
    /// and the next commit builds it over the members the discard kept.
    /// No legs half is offered meanwhile, whatever is covered.
    #[test]
    fn a_stating_half_is_built_again_over_the_members_a_discard_kept() {
        let (mut state, tick_id, near, far) = state_holding_two_legs();

        let first = announced(&state.finalize(&tick_id));
        assert_eq!(stated_by(&first), vec![vec![near, far]]);
        assert_eq!(first[0].half(), TickHalf::Stated);
        assert_eq!(held_stating(&state).len(), 1);
        assert!(
            announced(&state.offer_legs()).is_empty(),
            "a half handed off is not built again while the tick stands as it stated",
        );

        row_accepts(&mut state, near);
        assert!(
            announced(&state.finalize(&tick_id)).is_empty(),
            "a covered member's legs half waits for the stating half to commit",
        );

        state.release_tick(tick_id, Some(far));
        assert!(
            held_stating(&state).is_empty(),
            "the half stating the released member is held for no block",
        );
        assert!(
            state
                .ticks
                .get_tick(&tick_id)
                .is_some_and(|tick| tick.stating_owed() && !tick.has_spoken()),
        );

        let again = announced(&state.offer_legs());
        assert_eq!(
            stated_by(&again),
            vec![vec![near]],
            "over what the discard kept"
        );
        assert_ne!(again[0].receipt_hash(), first[0].receipt_hash());
        assert_eq!(
            held_stating(&state)
                .iter()
                .map(|fw| fw.receipt_hash())
                .collect::<Vec<_>>(),
            vec![again[0].receipt_hash()],
        );
        assert!(announced(&state.offer_legs()).is_empty());

        state.remove_finalization(again[0].as_unverified());
        assert!(held_stating(&state).is_empty());
        assert_eq!(
            names_of(&announced(&state.offer_legs())),
            vec![vec![near]],
            "the commit of the stating half is what lets the covered leg settle",
        );
    }

    /// A discard after a tick's stating half committed builds no second
    /// one: the tick states once, the members the discard kept stand
    /// stated, and their legs half follows as their coverage lands.
    #[test]
    fn a_discard_after_the_stating_half_committed_builds_no_second_one() {
        let (mut state, tick_id, near, far) = state_holding_two_legs();
        let stating = commit_stating(&mut state, tick_id);
        assert_eq!(stated_by(&[stating]), vec![vec![near, far]]);

        state.release_tick(tick_id, Some(far));
        assert!(
            state
                .ticks
                .get_tick(&tick_id)
                .is_some_and(|tick| !tick.stating_owed() && !tick.stating_ready()),
            "a committed stating half is not owed again",
        );
        assert!(announced(&state.offer_legs()).is_empty());
        assert!(announced(&state.finalize(&tick_id)).is_empty());
        assert!(state.get_finalizations().is_empty());

        row_accepts(&mut state, near);
        let legs = announced(&state.offer_legs());
        assert_eq!(names_of(&legs), vec![vec![near]]);
        assert_eq!(legs[0].half(), TickHalf::Legs);
        state.remove_finalization(legs[0].as_unverified());
        assert!(
            state.ticks.get_tick(&tick_id).is_none(),
            "the last stated member settled, and the tick is done",
        );
    }

    /// A replica that ran a tick and receives its own shard's
    /// certificate only after a block committed the tick's stating half
    /// hands off no stating half of its own: the chain has stated the
    /// tick. Its legs half follows once the certificate and the
    /// counterpart's coverage are in hand.
    #[test]
    fn a_replica_whose_certificate_lands_after_the_stating_commit_offers_legs_and_no_stating_half()
    {
        let (mut ahead, tick_id, near, far) = state_holding_two_legs();
        let stating = commit_stating(&mut ahead, tick_id);

        let (mut late, _, _, _) = state_running_two_legs();
        assert!(announced(&late.finalize(&tick_id)).is_empty());
        late.remove_finalization(stating.as_unverified());
        row_accepts(&mut late, near);
        assert!(
            announced(&late.offer_legs()).is_empty(),
            "nothing is built without the tick's own certificate",
        );

        late.ticks
            .get_tick_mut(&tick_id)
            .expect("the tick stands for its stated members")
            .add_execution_certificate(own_certificate(tick_id, 1_000, near, far));
        let built = announced(&late.finalize(&tick_id));
        assert!(
            built.iter().all(|fw| fw.half() == TickHalf::Legs),
            "no second stating half: {:?}",
            built.iter().map(|fw| fw.half()).collect::<Vec<_>>(),
        );
        assert_eq!(names_of(&built), vec![vec![near]]);
        assert!(held_stating(&late).is_empty());
    }

    /// A state at [`HOME`] whose tick at height 1 seats the straddling
    /// transactions of `seeds`, each dispatched and none returned. The
    /// tick's block ran those of seeds 1 and 2, `near` and `far`.
    fn seated_awaiting_its_batch(seeds: &[u8]) -> (ExecutionCoordinator, TickId, TxHash, TxHash) {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        let shared = |seed: u8| {
            Arc::new(Verified::new_unchecked_for_test(straddling_transaction(
                seed,
            )))
        };
        let tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            seeds
                .iter()
                .map(|&seed| (shared(seed), BTreeSet::from([HOME, PEER])))
                .collect(),
        );
        state.ticks.insert_tick(tick_id, tick);
        for &seed in seeds {
            state.ticks.assign_tx(shared(seed).hash(), tick_id);
        }
        (state, tick_id, shared(1).hash(), shared(2).hash())
    }

    /// Admit [`HOME`]'s complete certificate of the tick, attesting
    /// `near` and `far`, as a broadcast admits it.
    fn certified_by_its_shard(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        tick_id: TickId,
        (near, far): (TxHash, TxHash),
    ) {
        let _ =
            state.on_certificate_verified(schedule, Ok(own_certificate(tick_id, 1_000, near, far)));
        assert!(
            state.ticks.is_ec_dispatched(&tick_id),
            "the certificate is admitted",
        );
    }

    /// Land the tick's batch, each of `ran` with its outcome, and run
    /// the vote scan that follows a batch. Returns what the scan emitted.
    fn batch_returned(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        tick_id: TickId,
        ran: &[(TxHash, ExecutionOutcome)],
    ) -> Vec<Action> {
        let _ = state.on_execution_batch_completed(
            schedule,
            BlockHeight::new(1),
            TickBatchOutcome {
                tick_id,
                results: ran
                    .iter()
                    .map(|(tx_hash, _)| succeeded_receipt(*tx_hash))
                    .collect(),
                tx_outcomes: ran
                    .iter()
                    .map(|(tx_hash, outcome)| TxOutcome::new(*tx_hash, outcome.clone()))
                    .collect(),
                refusal_receipts: vec![],
            },
        );
        state.emit_vote_actions(schedule)
    }

    /// The stating halves a commit of an empty block at height 2
    /// announces.
    fn stating_announced_at_the_next_commit(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
    ) -> Vec<Arc<Verifiable<Finalization>>> {
        let block = make_live_block_on_shard(
            HOME,
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![],
        );
        let effects =
            state.commit_block_carrying(schedule, &test_certify(block, 2_000), Naming::Manifest);
        announced(&effects.actions)
            .into_iter()
            .filter(|fw| fw.half() == TickHalf::Stated)
            .collect()
    }

    /// A replica that ran every seat of a tick after its shard had
    /// already certified it sends no vote, and still states the tick:
    /// its own outcomes are fixed as the batch returns, their root is
    /// reconciled with the certificate held, and the stating half is
    /// handed off there, with no commit to wait for.
    #[test]
    fn a_replica_certified_before_its_batch_returns_still_states_the_tick() {
        let schedule = two_shard_topology();
        let (mut state, tick_id, near, far) = seated_awaiting_its_batch(&[1, 2]);
        certified_by_its_shard(&mut state, &schedule, tick_id, (near, far));
        let scanned = batch_returned(
            &mut state,
            &schedule,
            tick_id,
            &[(near, succeeded()), (far, succeeded())],
        );
        assert!(
            !scanned
                .iter()
                .any(|action| matches!(action, Action::SignAndSendExecutionVote { .. })),
            "a certified tick is sent no vote: {scanned:?}",
        );
        assert_eq!(
            state.voted_receipt_root(&tick_id),
            Some(own_certificate(tick_id, 1_000, near, far).global_receipt_root()),
            "its own root is reconciled with the certificate's",
        );

        assert_eq!(stated_by(&held_stating(&state)), vec![vec![near, far]]);
        assert!(
            stating_announced_at_the_next_commit(&mut state, &schedule).is_empty(),
            "the half is handed off once",
        );
        assert_eq!(held_stating(&state).len(), 1);
    }

    /// A replica that ran every seat of a tick after its shard had
    /// already certified it settles the tick's determined half as its
    /// batch returns: its outcomes are fixed against the certificate
    /// held, their root agrees, and the whole half is handed off with
    /// no commit to wait for.
    #[test]
    fn a_replica_certified_before_its_batch_returns_still_settles_its_determined_half() {
        use hyperscale_types::compute_global_receipt_root;

        let schedule = two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), HOME);
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        let local = |seed: u8| {
            Arc::new(Verified::new_unchecked_for_test(straddling_transaction(
                seed,
            )))
        };
        let tick = tick_holding(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            [1, 2]
                .map(|seed| (local(seed), BTreeSet::from([HOME])))
                .to_vec(),
        );
        state.ticks.insert_tick(tick_id, tick);
        let (near, far) = (local(1).hash(), local(2).hash());
        for tx_hash in [near, far] {
            state.ticks.assign_tx(tx_hash, tick_id);
        }
        let outcomes = [(near, 1), (far, 2)].map(|(tx_hash, seed)| {
            TxOutcome::new(tx_hash, succeeded())
                .charging(straddling_transaction(seed).price(&PriceTable::GENESIS))
                .as_role(Role::Whole)
        });
        let root = compute_global_receipt_root(&outcomes);
        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(1_000),
            root,
            Capped::from_array(outcomes),
            AggregateSignature::ZERO,
            quorum_signers(),
        )));
        let _ = state.on_certificate_verified(&schedule, Ok(certificate));

        assert!(state.finalized.is_empty(), "no receipt is held yet");

        let actions = state.on_execution_batch_completed(
            &schedule,
            BlockHeight::new(1),
            TickBatchOutcome {
                tick_id,
                results: vec![succeeded_receipt(near), succeeded_receipt(far)],
                tx_outcomes: vec![
                    TxOutcome::new(near, succeeded()),
                    TxOutcome::new(far, succeeded()),
                ],
                refusal_receipts: vec![],
            },
        );
        assert_eq!(state.voted_receipt_root(&tick_id), Some(root));
        let determined: Vec<Arc<Verifiable<Finalization>>> = announced(&actions)
            .into_iter()
            .filter(|fw| fw.is_determined())
            .collect();
        assert_eq!(names_of(&determined), vec![vec![near, far]]);
    }

    /// A replica whose own run of every seat disagrees with a
    /// certificate that landed first is caught as one that voted before
    /// it is: the scan reconciles its root and the divergence escalates,
    /// where it would otherwise go on executing over a baseline nobody
    /// else holds.
    #[test]
    #[should_panic(expected = "BFT CRITICAL: local execution diverged")]
    fn a_replica_certified_before_a_divergent_batch_is_caught() {
        let schedule = two_shard_topology();
        let (mut state, tick_id, near, far) = seated_awaiting_its_batch(&[1, 2]);
        certified_by_its_shard(&mut state, &schedule, tick_id, (near, far));
        let _ = batch_returned(
            &mut state,
            &schedule,
            tick_id,
            &[(near, ExecutionOutcome::Failed), (far, succeeded())],
        );
    }

    /// A replica that seated a strict subset of a tick, one member of
    /// it being a transaction it could not route, did not run the tick
    /// whole. Certified before its scan, it fixes no outcomes against a
    /// certificate over members it does not seat: a root over its subset
    /// is no divergence, and it states nothing.
    #[test]
    fn a_replica_seating_part_of_a_certified_tick_reconciles_nothing() {
        let schedule = two_shard_topology();
        let (mut state, tick_id, near, far) = seated_awaiting_its_batch(&[1]);
        certified_by_its_shard(&mut state, &schedule, tick_id, (near, far));
        let scanned = batch_returned(&mut state, &schedule, tick_id, &[(near, succeeded())]);
        assert!(
            !scanned
                .iter()
                .any(|action| matches!(action, Action::SignAndSendExecutionVote { .. })),
        );
        assert_eq!(
            state.voted_receipt_root(&tick_id),
            None,
            "its subset's root is not put against the tick's certificate",
        );
        assert!(
            stating_announced_at_the_next_commit(&mut state, &schedule).is_empty(),
            "and it states no part of the tick",
        );
        assert!(held_stating(&state).is_empty());
    }

    /// A stating half re-anchored on a later certificate is a second
    /// copy of the tick's one stating half, under another hash and, where
    /// it states only yeses, naming no settled member a commit could find
    /// it by. The commit of either copy evicts every stating copy of the
    /// tick, so none is offered to a block that would refuse it.
    #[test]
    fn a_reanchored_stating_copy_is_evicted_at_the_commit() {
        let (mut state, tick_id, near, far) = state_holding_two_legs();
        let original = announced(&state.finalize(&tick_id));
        assert_eq!(stated_by(&original), vec![vec![near, far]]);

        let later = own_certificate(tick_id, 2_000, near, far);
        assert!(
            state
                .ticks
                .get_tick_mut(&tick_id)
                .expect("seated")
                .adopt_later_certificate(&later),
        );
        let copies = announced(&state.reanchor_finalizations(&tick_id, &later));
        assert_eq!(stated_by(&copies), vec![vec![near, far]]);
        assert_ne!(copies[0].receipt_hash(), original[0].receipt_hash());
        assert_eq!(copies[0].tx_count(), 0, "it names no settled member");
        assert_eq!(
            held_stating(&state).len(),
            1,
            "the copy is held in its place"
        );

        // A block carried the original, which a voter resolved by hash.
        state.remove_finalization(original[0].as_unverified());
        assert!(
            state.get_finalizations().is_empty(),
            "the re-anchored copy goes with the commit of the half it copies",
        );
        assert!(
            state
                .ticks
                .get_tick(&tick_id)
                .is_some_and(|tick| !tick.stating_owed() && !tick.stating_ready()),
        );
        assert!(announced(&state.offer_legs()).is_empty());
    }

    /// The committed tip's rows accept `member`, as the shard
    /// coordinator hands them over.
    fn row_accepts(state: &mut ExecutionCoordinator, member: TxHash) {
        state.accepting.insert(member);
    }

    /// The members each finalization `actions` announce names, in order.
    fn announced(actions: &[Action]) -> Vec<Arc<Verifiable<Finalization>>> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Continuation(ProtocolEvent::FinalizationsAdmitted { finalizations }) => {
                    Some(finalizations.clone())
                }
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn names_of(finalizations: &[Arc<Verifiable<Finalization>>]) -> Vec<Vec<TxHash>> {
        finalizations
            .iter()
            .map(|fw| fw.tx_hashes().collect())
            .collect()
    }

    /// A tick's legs entry is replaced as its coverage grows, and the
    /// one it replaces has already been announced: the announcement is
    /// what fills the cache a fetch by hash is served from, so the store
    /// a proposer builds from lets it go.
    #[test]
    fn a_replaced_legs_entry_is_announced_before_the_store_lets_it_go() {
        let (mut state, tick_id, near, far) = state_holding_two_legs();

        commit_stating(&mut state, tick_id);
        let mut built = Vec::new();
        for member in [near, far] {
            row_accepts(&mut state, member);
            built.extend(announced(&state.finalize(&tick_id)));
        }

        assert_eq!(
            names_of(&built),
            vec![vec![near], vec![near, far]],
            "each entry is announced as it is built",
        );
        assert_eq!(
            state
                .get_finalizations()
                .iter()
                .map(|fw| fw.receipt_hash())
                .collect::<Vec<_>>(),
            vec![built[1].receipt_hash()],
            "the store offers a proposer the entry naming every covered leg, and no other",
        );
        assert!(
            state.finalized.get(&built[0].receipt_hash()).is_none(),
            "the replaced entry is the announcement's to answer for",
        );
    }

    /// A stated member accepts on its row however long after its tick
    /// the row says so: no certificate of its counterpart is ever asked
    /// for, so none lapses. The clock runs a retention horizon past the
    /// tick's anchor, with [`PEER`]'s certificate never delivered, and
    /// the legs half is built as the row accepts, carrying no certificate.
    #[test]
    fn a_stated_row_accepts_after_its_certificate_would_have_lapsed() {
        let (mut state, tick_id, near, _) = state_holding_two_legs();
        commit_stating(&mut state, tick_id);
        state.committed_ts = WeightedTimestamp::from_millis(past_the_horizon() + 1_000);
        assert!(announced(&state.offer_legs()).is_empty());

        let built = announced(&state.offer_accepting(BTreeSet::from([near])));
        assert_eq!(names_of(&built), vec![vec![near]]);
        assert!(
            built
                .iter()
                .all(|fw| fw.half() == TickHalf::Legs && fw.local_ec().is_none()),
            "a legs half carries no certificate",
        );
    }

    /// After a release, `T` is still this shard's to settle on [`PEER`]'s
    /// certificate — the kept tick's legs half names `T` and no released
    /// member — and never this shard's to abandon.
    fn assert_the_shared_verdict_still_settles(
        state: &mut ExecutionCoordinator,
        tick_id: TickId,
        t: TxHash,
    ) {
        let tick = state
            .ticks
            .get_tick_mut(&tick_id)
            .expect("the tick keeps the member whose verdict a counterpart shares");
        tick.add_execution_certificate(peer_settles(t));
        let stating = tick
            .take_stating_finalization()
            .expect("the kept tick states the member it still holds");
        assert_eq!(
            stating
                .stated_outcomes()
                .map(TxOutcome::tx_hash)
                .collect::<Vec<_>>(),
            vec![t],
            "the stating half states T and nothing released",
        );
        tick.stating_committed();
        let legs = tick
            .legs_half(&BTreeSet::from([t]))
            .expect("T's row accepts");
        assert_eq!(
            legs.tx_hashes().collect::<Vec<_>>(),
            vec![t],
            "the legs half names T and nothing released",
        );
        assert!(
            state
                .abandonable(TickId::new(HOME, BlockHeight::new(10)))
                .iter()
                .all(|entry| entry.tx_hash != t),
            "T is a counterpart's to settle, never this shard's to abandon",
        );
    }

    /// A tick released because a sibling member was abandoned keeps the
    /// member whose verdict a counterpart shares.
    ///
    /// `X` is past its deadline and a departure covers it, so the block
    /// names its abort beside the discard of the tick that held it, and
    /// the composing tick seats the abort. `T` sat in the
    /// same tick awaiting [`PEER`], whose certificate settles it against
    /// this shard's — out already, and outliving the tick. Dropped with
    /// the tick, `T` is settled by nobody: its entry is certified, so the
    /// deadline path never abandons it either.
    #[test]
    fn a_release_through_an_abandoned_sibling_keeps_the_member_a_counterpart_can_settle() {
        let (mut state, tick_id, t, x) = state_holding_a_shared_verdict(1);
        let alone: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(test_transaction(2)),
        ));
        assert_eq!(alone.hash(), x);
        state
            .counterparts
            .ledger
            .record_abandonment_records(&[AbandonmentRecord::new(
                PEER,
                WeightedTimestamp::from_millis(1_000),
                [UnsettledTx::for_transaction(
                    &alone,
                    test_committed(),
                    alone.price(&PriceTable::GENESIS),
                    &PriceTable::GENESIS,
                )],
            )]);
        assert!(state.counterparts.ledger.is_covered(x));
        let sched = two_shard_topology();
        let composing = TickId::new(HOME, BlockHeight::new(9));
        let mut composing_tick = TickState::new(
            composing,
            BlockHash::from_raw(Hash::from_bytes(b"composing")),
            WeightedTimestamp::from_millis(STRANDED_DEADLINE_MS),
        );

        let trie = state
            .counterpart_trie(&sched)
            .expect("the fixture holds the window")
            .clone();
        let named = [
            TickLine::Member {
                tx: x,
                joins: Joins::Aborted,
                settlement: Settlement::Alone,
                holds: Capped::empty(),
                reach: Capped::empty(),
                awaits: Capped::empty(),
                charge: stub_abort_charge(2),
                share: 0,
                reserves: Capped::empty(),
                deadline: Deadline::of_transaction(&alone),
                crossings: Capped::empty(),
            },
            TickLine::Discard {
                tick: tick_id,
                cause: DiscardCause::Abandoned(x),
            },
        ];
        state.admit_abandoned(&trie, composing, &mut composing_tick, &[]);
        assert!(
            composing_tick.tx_hashes().is_empty(),
            "a held member is the manifest's to abort",
        );
        state.admit_abandoned(&trie, composing, &mut composing_tick, &named);
        assert_eq!(
            composing_tick.tx_hashes(),
            &[x],
            "X is abandoned, T is not: a counterpart can still settle it",
        );

        assert_the_shared_verdict_still_settles(&mut state, tick_id, t);
    }

    /// The line aborting `transaction` under `classified` on [`HOME`], as
    /// the block that commits it at [`test_committed`] states it:
    /// reaching `reach`, at the genesis prices, answering `crossings`.
    fn aborting(
        transaction: &Arc<Verifiable<Transaction>>,
        classified: &Classified,
        reach: &[ShardId],
        crossings: Crossings,
    ) -> TickLine {
        TickLine::Member {
            tx: transaction.hash(),
            joins: Joins::Aborted,
            settlement: if reach.is_empty() {
                Settlement::Alone
            } else {
                Settlement::Awaited
            },
            holds: Capped::empty(),
            reach: Capped::new(reach.to_vec()).expect("a short reach"),
            awaits: Capped::empty(),
            charge: genesis_charge(transaction),
            share: classified.local_price(transaction, HOME, &PriceTable::GENESIS),
            reserves: Capped::empty(),
            deadline: Deadline::of_transaction(transaction),
            crossings,
        }
    }

    /// Seat `line` in a tick of `state`'s at height 9 under `trie`, and
    /// return what the tick then attests with the refusal receipts it
    /// holds.
    fn seat_abort(
        state: &mut ExecutionCoordinator,
        trie: &ShardTrie,
        line: &TickLine,
    ) -> (Vec<TxOutcome>, Vec<GlobalReceiptHash>) {
        let composing = TickId::new(HOME, BlockHeight::new(9));
        let mut tick = TickState::new(
            composing,
            BlockHash::from_raw(Hash::from_bytes(b"composing")),
            state.committed_ts,
        );
        state.admit_abandoned(trie, composing, &mut tick, std::slice::from_ref(line));
        assert_eq!(
            state.ticks.tick_assignment(line_tx(line)),
            Some(composing),
            "the tick the line names the abort in is the one that speaks for it",
        );
        let outcomes = tick
            .build_vote_data()
            .expect("an abandonment waits on no engine")
            .2;
        let receipts = outcomes
            .iter()
            .filter_map(TxOutcome::refusal_receipt)
            .collect();
        (outcomes, receipts)
    }

    /// The transaction a member line names.
    fn line_tx(line: &TickLine) -> TxHash {
        match line {
            TickLine::Member { tx, .. } => *tx,
            other => panic!("not a member line: {other:?}"),
        }
    }

    /// An abort a committed manifest names is seated from its line at
    /// whatever age the chain reaches it, on a replica holding the
    /// member's ledger entry, on one whose entry its clocks retired, and
    /// on one that never held it: each attests the same outcome over the
    /// same refusal receipt, which is the one the entry's own figures
    /// build.
    #[test]
    fn an_abort_named_past_the_abandon_window_is_seated() {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let x = transaction.hash();
        let sched = two_shard_topology();
        let trie = sched.head().shard_trie().clone();
        assert_eq!(
            trie.shard_for_prefix(transaction.fee_vault().owner),
            HOME,
            "the fixture's vault is this shard's",
        );
        let resumed = Deadline::of_transaction(&transaction)
            .at()
            .plus(MAX_VALIDITY_RANGE);
        let holding = || {
            let mut state = core_state(HOME, &transaction, &Classified::whole());
            state.committed_ts = resumed;
            state
        };

        let mut entry_holding = holding();
        let figures = entry_holding
            .counterparts
            .ledger
            .past_deadline(Deadline::of_transaction(&transaction).at())
            .into_iter()
            .find(|entry| entry.tx_hash == x)
            .expect("inside its window the entry restates what the abort settles");
        let line = aborting(&transaction, &Classified::whole(), &[PEER], Capped::empty());
        let TickLine::Member {
            charge,
            share,
            deadline,
            reach,
            ..
        } = &line
        else {
            unreachable!("the fixture builds a member line");
        };
        assert_eq!(
            (*charge, *share, *deadline),
            (figures.charge, figures.charged, figures.deadline),
            "the line states the figures the entry holds",
        );
        assert_eq!(
            reach.iter().copied().collect::<BTreeSet<_>>(),
            entry_holding.counterparts.ledger.counterparts(x, &trie),
            "and the parties it names",
        );
        let from_figures = build_refusal_receipt(
            HOME,
            &trie,
            x,
            Some((
                figures.charge.vault,
                Movement::unjudged(*PROTOCOL_RESOURCE, figures.charge.amount),
            )),
            &[],
        )
        .expect("a charge names a receipt")
        .receipt_hash();

        let mut pruned = holding();
        pruned.counterparts.ledger.prune(resumed);
        assert!(
            !pruned.counterparts.ledger.contains(x),
            "past its window the entry goes, whatever the block names",
        );
        let mut entrant = make_test_state_for_shard(ValidatorId::new(0), HOME);
        entrant.committed_ts = resumed;

        let seated = seat_abort(&mut entry_holding, &trie, &line);
        assert_eq!(seated.0.len(), 1);
        assert!(seated.0[0].is_aborted());
        assert_eq!(seated.0[0].role(), Role::Settling);
        assert_eq!(seated.0[0].charged(), figures.charged);
        assert_eq!(seated.0[0].counterparts(), &[PEER]);
        assert_eq!(
            seated.1,
            vec![from_figures],
            "the receipt the entry's own figures build",
        );
        assert_eq!(
            seat_abort(&mut pruned, &trie, &line),
            seated,
            "a replica whose entry its clocks retired seats the same abandonment",
        );
        assert_eq!(
            seat_abort(&mut entrant, &trie, &line),
            seated,
            "and so does one that never held the transaction",
        );
    }

    /// An abandonment's parties are the ones its committing block
    /// placed, which the line names: seated under a trie in which the
    /// counterpart has since split, it attests the shard the transaction
    /// was committed with, where the ledger names that shard's
    /// successors.
    #[test]
    fn an_abort_after_its_reach_reshaped_names_the_committing_placement() {
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let x = transaction.hash();
        let (left, right) = PEER.children();
        let reshaped = ShardTrie::from_leaves([HOME, left, right]);
        let mut state = core_state(HOME, &transaction, &Classified::whole());
        let now = state.counterparts.ledger.counterparts(x, &reshaped);
        assert!(
            !now.contains(&PEER) && !now.is_empty(),
            "the ledger places the routes under the trie it is asked at: {now:?}",
        );

        let line = aborting(&transaction, &Classified::whole(), &[PEER], Capped::empty());
        let (outcomes, _) = seat_abort(&mut state, &reshaped, &line);
        assert_eq!(
            outcomes[0].counterparts(),
            &[PEER],
            "the abandonment attests the committing block's placement",
        );
    }

    /// A record naming a transaction before this shard commits it
    /// rebuilds a ledger entry that answers no crossing, while the row
    /// the commit writes stands uncovered and its abort line names every
    /// crossing the member consumes. The line is what every replica
    /// seats: the rebuilt replica writes the `Never`s a replica holding
    /// the committing block does.
    #[test]
    fn a_record_before_the_commit_leaves_the_abort_its_nevers() {
        let schedule = two_shard_topology();
        let trie = schedule.head().shard_trie().clone();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction_paying_away(1)),
        ));
        let x = transaction.hash();
        let classified = peer_fed_core_classified();
        let never = never_of(&transaction);
        let crossings: Crossings = Capped::new(
            classified
                .refusable_consumed(HOME)
                .map(|edge| edge.crossing.id)
                .collect(),
        )
        .expect("a star's edges are capped");
        let line = aborting(&transaction, &classified, &[PEER], crossings);

        let mut rebuilt = make_test_state_for_shard(ValidatorId::new(0), HOME);
        record_peer_left_unsettled(&mut rebuilt, x);
        rebuilt.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&transaction, &classified)],
        );
        assert!(
            rebuilt.counterparts.ledger.abandonment_answers(x).is_none(),
            "the entry the record rebuilt answers nothing",
        );
        let mut seated = core_state(HOME, &transaction, &classified);

        let expected = build_refusal_receipt(HOME, &trie, x, None, std::slice::from_ref(&never))
            .expect("a Never names a receipt")
            .receipt_hash();
        let from_block = seat_abort(&mut seated, &trie, &line);
        assert_eq!(
            from_block.1,
            vec![expected],
            "the line's Never, and no charge"
        );
        assert_eq!(
            seat_abort(&mut rebuilt, &trie, &line),
            from_block,
            "the replica the record reached first seats what the line names",
        );
    }

    /// Commit an empty block on `shard` at `ts`, as the chain hands it
    /// over, and return what the fold emitted.
    fn commit_empty_on(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
        shard: ShardId,
        height: u64,
        ts: WeightedTimestamp,
    ) -> Vec<Action> {
        let block = make_live_block_on_shard(
            shard,
            BlockHeight::new(height),
            ts.as_millis(),
            ValidatorId::new(0),
            vec![],
        );
        state
            .commit_block_carrying(
                schedule,
                &test_certify(block, ts.as_millis()),
                Naming::Composed,
            )
            .actions
    }

    /// The outcomes every tick that can vote now attests.
    fn votable_outcomes(
        state: &mut ExecutionCoordinator,
        schedule: &TopologySchedule,
    ) -> Vec<TxOutcome> {
        state
            .scan_votable_ticks(schedule)
            .into_iter()
            .flat_map(|completion| completion.tx_outcomes)
            .collect()
    }

    /// A shape frozen divided under [`two_shard_topology`] with an
    /// inbound leg on [`PEER`] feeding a core of [`HOME`] alone, so
    /// `HOME` holds the crossing's claim and decline keys.
    fn peer_fed_core_classified() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(2, LegRole::Inbound, &[]),
            leg(0, LegRole::Core, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([HOME]));
        assert!(classified.decomposed());
        classified
    }

    /// [`straddling_transaction`] the other way round: paying from the
    /// `0b1…` side and writing to the `0b0…` side, so its vault sits on
    /// [`PEER`] and what it feeds on [`HOME`].
    fn straddling_transaction_paying_away(seed: u8) -> Transaction {
        test_transaction_with_prefixes(
            &[seed | 0x80],
            &[test_prefix(seed | 0x80)],
            &[test_prefix(seed & 0x7F)],
        )
    }

    /// A state on `shard` holding `transaction` as a core entry no tick
    /// has taken, frozen as `classified`.
    fn core_state(
        shard: ShardId,
        transaction: &Arc<Verifiable<Transaction>>,
        classified: &Classified,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), shard);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(transaction, classified)],
        );
        state
    }

    /// The one `Never` [`HOME`] writes for `transaction` under
    /// [`peer_fed_core_classified`]: the crossing the leg on [`PEER`]
    /// hands the core.
    fn never_of(transaction: &Arc<Verifiable<Transaction>>) -> (SubstateKey, Vec<u8>) {
        let classified = peer_fed_core_classified();
        let edges: Vec<_> = classified.refusable_consumed(HOME).collect();
        assert_eq!(edges.len(), 1, "the fixture hands the core one crossing");
        abandoned_never(
            transaction.hash(),
            transaction
                .validity_range()
                .end_timestamp_exclusive
                .as_millis(),
            edges[0].crossing.id,
        )
    }

    /// The deadline of `transaction` as committed at [`test_committed`].
    fn deadline_of(transaction: &Arc<Verifiable<Transaction>>) -> WeightedTimestamp {
        UnsettledTx::for_transaction(
            transaction,
            test_committed(),
            transaction.price(&PriceTable::GENESIS),
            &PriceTable::GENESIS,
        )
        .deadline
        .at()
    }

    /// A committed core member no tick of this shard's ever took is
    /// abandoned with a receipt carrying `Never` at each refusable
    /// crossing it consumed, on the shard holding the decline key, which
    /// is not the vault's. The receipt rides the abandonment under the
    /// transaction's own name, and its keys held nothing before it: the
    /// entry never reached an executing tick, so no member of it ran.
    #[test]
    fn an_uncertified_abandonment_answers_on_the_shard_holding_the_decline() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction_paying_away(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = deadline_of(&transaction);
        let never = never_of(&transaction);
        let mut state = core_state(HOME, &transaction, &peer_fed_core_classified());
        let trie = state
            .counterpart_trie(&schedule)
            .expect("the fixture holds the window");
        assert_eq!(
            trie.shard_for_prefix(never.0.owner),
            HOME,
            "the fixture's decline key is this shard's",
        );
        assert_eq!(
            trie.shard_for_prefix(transaction.fee_vault().owner),
            PEER,
            "and the vault is not",
        );
        let expected =
            build_refusal_receipt(HOME, trie, tx_hash, None, std::slice::from_ref(&never))
                .expect("a Never names a receipt");

        commit_empty_on(&mut state, &schedule, HOME, 1, deadline);
        let outcomes = votable_outcomes(&mut state, &schedule);
        assert_eq!(
            outcomes.len(),
            1,
            "the abandonment is composed at the deadline"
        );
        assert_eq!(outcomes[0].tx_hash(), tx_hash);
        assert!(outcomes[0].is_aborted());
        assert_eq!(
            outcomes[0].refusal_receipt(),
            Some(expected.receipt_hash()),
            "the receipt carries the Never and no charge",
        );
    }

    /// An abandonment composed and then lost is composed again, byte for
    /// byte, and never twice at once: while the tick holding it stands
    /// nothing is composed for the member, and once the tick is
    /// released — as a recovery discard and the settled-set gate's
    /// `Reject` release it — the next commit composes the same
    /// abandonment with the same receipt.
    #[test]
    fn a_discarded_abandonment_is_composed_again() {
        let schedule = two_shard_topology();
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction_paying_away(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = deadline_of(&transaction);
        let mut state = core_state(HOME, &transaction, &peer_fed_core_classified());

        commit_empty_on(&mut state, &schedule, HOME, 1, deadline);
        let first = votable_outcomes(&mut state, &schedule);
        assert_eq!(first.len(), 1);
        assert!(
            first[0].refusal_receipt().is_some(),
            "the receipt carries the Never"
        );
        let tick_id = state
            .ticks
            .tick_assignment(tx_hash)
            .expect("the abandonment holds the member");

        commit_empty_on(
            &mut state,
            &schedule,
            HOME,
            2,
            deadline.plus(Duration::from_secs(1)),
        );
        assert_eq!(
            state.ticks.tick_assignment(tx_hash),
            Some(tick_id),
            "while the abandonment stands, no second is composed",
        );

        state.release_tick(tick_id, Some(tx_hash));
        assert!(state.ticks.tick_assignment(tx_hash).is_none());
        commit_empty_on(
            &mut state,
            &schedule,
            HOME,
            3,
            deadline.plus(Duration::from_secs(2)),
        );
        let again = votable_outcomes(&mut state, &schedule);
        assert_eq!(
            again.len(),
            1,
            "the entry is re-offered once its tick is gone"
        );
        assert_eq!(again[0].tx_hash(), tx_hash);
        assert_eq!(
            again[0].refusal_receipt(),
            first[0].refusal_receipt(),
            "and composes the same answer to a key that still holds nothing",
        );
        assert_ne!(state.ticks.tick_assignment(tx_hash), Some(tick_id));
    }

    /// An entry an executing tick took, then released, writes no
    /// `Never` on any exit: its certificate may be out and a sibling may
    /// have combined an accept with it. Released uncovered it is neither
    /// abandoned nor answered, and a release for unanswerability leaves
    /// the producer's record held — value locked, listed and counted.
    /// Covered by a record, it is abandoned with the charge alone.
    #[test]
    fn a_certified_exit_writes_no_never() {
        let schedule = two_shard_topology();
        // Paying from this shard, so the charge is settled here and a
        // receipt carrying the charge alone is told from one carrying a
        // `Never` beside it.
        let transaction: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from(
            Verified::new_unchecked_for_test(straddling_transaction(1)),
        ));
        let tx_hash = transaction.hash();
        let deadline = deadline_of(&transaction);
        let mut state = core_state(HOME, &transaction, &peer_fed_core_classified());
        let trie = schedule.head().shard_trie().clone();
        assert_eq!(
            trie.shard_for_prefix(transaction.fee_vault().owner),
            HOME,
            "the fixture's vault is this shard's",
        );
        let tick_id = TickId::new(HOME, BlockHeight::new(1));
        state.ticks.insert_tick(
            tick_id,
            tick_holding(
                tick_id,
                WeightedTimestamp::from_millis(1_000),
                vec![(
                    Arc::new(Verified::new_unchecked_for_test(straddling_transaction(1))),
                    BTreeSet::from([HOME, PEER]),
                )],
            ),
        );
        state.ticks.assign_tx(tx_hash, tick_id);
        state
            .counterparts
            .ledger
            .certify(tx_hash, Certified::ByExecution);
        let (record_key, _, cell) = held_record(0x6A, 400_000);
        hold(&mut state, &schedule, [(record_key, cell.to_bytes())]);

        state.release_tick(tick_id, Some(tx_hash));
        assert!(state.ticks.tick_assignment(tx_hash).is_none());
        commit_empty_on(
            &mut state,
            &schedule,
            HOME,
            2,
            deadline.plus(Duration::from_secs(1)),
        );
        assert!(
            state.ticks.tick_assignment(tx_hash).is_none(),
            "an executed member released uncovered is not abandoned",
        );
        assert!(votable_outcomes(&mut state, &schedule).is_empty());
        assert!(
            state
                .counterparts
                .ledger
                .abandonment_answers(tx_hash)
                .is_none(),
            "and nothing answers for it",
        );

        // Covered by the departed sibling's record, the entry is
        // abandoned inside its window and settles the charge alone.
        state.counterparts.ledger.record_terminal(
            PEER,
            deadline.plus(Duration::from_secs(2)),
            None,
        );
        record_peer_left_unsettled(&mut state, tx_hash);
        commit_empty_on(
            &mut state,
            &schedule,
            HOME,
            3,
            deadline.plus(Duration::from_secs(3)),
        );
        let outcomes = votable_outcomes(&mut state, &schedule);
        assert_eq!(outcomes.len(), 1, "covered, the entry is abandoned");
        assert!(outcomes[0].is_aborted());
        let charge = build_refusal_receipt(
            HOME,
            &trie,
            tx_hash,
            Some((
                transaction.fee_vault(),
                Movement::unjudged(*PROTOCOL_RESOURCE, transaction.price(&PriceTable::GENESIS)),
            )),
            &[],
        )
        .expect("a charge names a receipt");
        assert_eq!(
            outcomes[0].refusal_receipt(),
            Some(charge.receipt_hash()),
            "the charge alone: an executed entry answers nothing",
        );
    }

    /// A committed `Unanswerable` discard releases that member from its
    /// tick and keeps its siblings a counterpart can settle. Its entry
    /// stands until the fate the same block names for it.
    #[test]
    fn a_release_through_an_unanswerable_member_keeps_its_siblings() {
        let (mut state, tick_id, t, x) = state_holding_a_shared_verdict(5);

        state.drop_unanswerable(tick_id, x);

        assert!(
            state.ticks.tick_assignment(x).is_none(),
            "the unanswerable member is let go of",
        );
        assert!(
            state.counterparts.ledger.contains(x),
            "the discard releases the tick and ends nothing",
        );
        state.let_go(x);
        assert!(
            !state.counterparts.ledger.contains(x),
            "its fate ends the entry with no outcome",
        );
        assert_the_shared_verdict_still_settles(&mut state, tick_id, t);
    }

    /// Seat the tick of a block at height 9 on [`HOME`] whose committed
    /// manifest names `lines`.
    fn seat_lines(state: &mut ExecutionCoordinator, lines: &[TickLine]) {
        let sched = two_shard_topology();
        let anchored = Arc::clone(sched.head());
        let block = CommittingBlock {
            hash: BlockHash::from_raw(Hash::from_bytes(b"fating")),
            height: BlockHeight::new(9),
            ts: state.committed_ts,
            fees: Vec::new(),
        };
        let _ = state.seat_tick(
            &sched,
            &anchored,
            &block,
            Named::Lines(lines),
            &mut Vec::new(),
        );
    }

    /// Nothing of `tx_hash` is left on `state`, and the block that let
    /// it go seated no tick.
    fn assert_let_go(state: &ExecutionCoordinator, tx_hash: TxHash, replica: &str) {
        assert!(
            !state.candidates.contains(tx_hash),
            "{replica}: no candidate",
        );
        assert!(
            state.ticks.tick_assignment(tx_hash).is_none(),
            "{replica}: no tick speaks for it",
        );
        assert!(
            !state.counterparts.ledger.contains(tx_hash),
            "{replica}: no ledger entry",
        );
        assert!(
            !state
                .ticks
                .contains_tick(&TickId::new(HOME, BlockHeight::new(9))),
            "{replica}: a discard and a fate seat nothing",
        );
    }

    /// An end line seats nothing and lets nothing go: the member it
    /// names keeps its tick, its ledger entry and what its tick-mate is
    /// owed, and the block seats no tick for it.
    #[test]
    fn an_end_line_seats_nothing_and_lets_nothing_go() {
        let (mut state, tick_id, t, x) = state_holding_a_shared_verdict(5);
        assert_eq!(state.ticks.tick_assignment(t), Some(tick_id));
        assert!(state.counterparts.ledger.contains(t));
        assert!(state.counterparts.ledger.contains(x));
        let resolutions = state.pending_tick_resolutions.len();

        let mut seated = Vec::new();
        let lines = [TickLine::End { tx: t }, TickLine::End { tx: x }];
        let sched = two_shard_topology();
        let anchored = Arc::clone(sched.head());
        let block = CommittingBlock {
            hash: BlockHash::from_raw(Hash::from_bytes(b"ending")),
            height: BlockHeight::new(9),
            ts: state.committed_ts,
            fees: Vec::new(),
        };
        let (pending, votes, _) =
            state.seat_tick(&sched, &anchored, &block, Named::Lines(&lines), &mut seated);
        assert!(pending.is_none());
        assert!(votes.is_empty());
        assert_eq!(seated, lines, "the lines seated are the block's");
        assert_eq!(state.ticks.tick_assignment(t), Some(tick_id));
        assert!(state.counterparts.ledger.contains(t));
        assert!(state.counterparts.ledger.contains(x));
        assert_eq!(state.pending_tick_resolutions.len(), resolutions);
        assert!(
            !state
                .ticks
                .contains_tick(&TickId::new(HOME, BlockHeight::new(9))),
            "an end seats no tick",
        );
    }

    /// An `Unanswerable` discard and the fate after it end this shard's
    /// account of the member alike on a replica that ran its tick, on
    /// one that seated the tick and never ran it, and on one holding
    /// nothing of it: no candidate, no tick assignment, no hold on the
    /// chain and no ledger entry, and no tick seated for the block. A
    /// fate alone ends the entry of a member a discard already released.
    #[test]
    fn a_fate_seats_nothing_and_forgets_its_entry() {
        let pair = |tick_id: TickId, tx: TxHash| {
            [
                TickLine::Discard {
                    tick: tick_id,
                    cause: DiscardCause::Unanswerable(tx),
                },
                TickLine::Fate {
                    tx,
                    charge: stub_abort_charge(1),
                },
            ]
        };

        let (mut ran, tick_id, t, x) = state_holding_a_shared_verdict(5);
        ran.ticked.insert(
            tick_id,
            TickedBatch {
                provisional_claims: BTreeMap::new(),
                legs: BTreeMap::from([(t, BTreeMap::new())]),
            },
        );
        seat_lines(&mut ran, &pair(tick_id, t));
        assert_let_go(&ran, t, "ran the tick");
        assert!(
            ran.pending_tick_resolutions
                .iter()
                .any(|(tick, _, resolution)| {
                    *tick == tick_id
                        && matches!(
                            resolution,
                            TickResolution::Abandoned { members, .. }
                                if *members == BTreeSet::from([t])
                        )
                }),
            "what its leg held on the chain is let go of",
        );
        assert!(
            ran.counterparts.ledger.contains(x),
            "a sibling the discard released is still owed its own outcome",
        );

        let (mut held, tick_id, t, _) = state_holding_a_shared_verdict(5);
        held.held.insert(tick_id, HeldTick::of(&[]));
        held.pending_ticks.push_back(Queued::Held(tick_id));
        seat_lines(&mut held, &pair(tick_id, t));
        assert_let_go(&held, t, "held the tick");
        assert!(!held.ticks.contains_tick(&tick_id));
        let _ = held.dispatch_next_tick(&make_test_topology());
        assert!(
            held.pending_ticks.is_empty(),
            "the released tick holds no later one back",
        );

        let mut bare = make_test_state_for_shard(ValidatorId::new(0), HOME);
        seat_lines(&mut bare, &pair(tick_id, t));
        assert_let_go(&bare, t, "held nothing");

        let (mut released, tick_id, t, _) = state_holding_a_shared_verdict(5);
        released.ticks.discard_tick(&tick_id);
        assert!(released.counterparts.ledger.contains(t));
        let [_, fate] = pair(tick_id, t);
        seat_lines(&mut released, &[fate]);
        assert_let_go(&released, t, "released before its fate");
    }

    /// A release of a tick in which no member shares a verdict leaves
    /// nothing behind: the tick, both its finalizations and its
    /// certificate all go, and its members fall to their own deadlines.
    #[test]
    fn a_release_keeping_nothing_leaves_nothing_behind() {
        let sched = peer_terminating_schedule(600_000);
        let (mut state, tick_id, tx_hash) = state_stranded_on(&sched, 1);
        let certificate = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)]),
            AggregateSignature::ZERO,
            quorum_signers(),
        );
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(
                certificate.clone(),
            )));
        for half in [TickHalf::Determined, TickHalf::Legs] {
            state.finalized.insert(
                tick_id,
                Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
                    Finalization::new(
                        tick_id,
                        half,
                        &Capped::from_array([Arc::new(certificate.clone())]),
                        Capped::from_array([]),
                    ),
                ))),
            );
        }

        state.release_tick(tick_id, Some(tx_hash));

        assert!(state.ticks.get_tick(&tick_id).is_none(), "the tick goes");
        assert!(
            state.ticks.tick_assignment(tx_hash).is_none(),
            "and its member falls to its own deadline",
        );
        assert!(
            !state.finalized.contains(&tick_id),
            "both its finalizations go",
        );
        assert!(
            state.exec_certs.get(&tick_id).is_none(),
            "and its certificate",
        );
    }

    /// After a kept release the `ticked` entry names the kept legs only,
    /// a legs finalization taken before the release is gone, the next
    /// take names the kept legs, and the kept legs' later settlement
    /// clears the entry.
    #[test]
    fn a_kept_release_narrows_the_ticked_entry_and_recomposes_the_legs_half() {
        let (mut state, tick_id, t, x) = state_holding_a_shared_verdict(7);
        state.ticked.insert(
            tick_id,
            TickedBatch {
                provisional_claims: BTreeMap::new(),
                legs: BTreeMap::from([(t, BTreeMap::new()), (x, BTreeMap::new())]),
            },
        );
        let taken_before = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            Capped::from_array([
                TxOutcome::new(t, ExecutionOutcome::Aborted),
                TxOutcome::new(x, ExecutionOutcome::Aborted),
            ]),
            AggregateSignature::ZERO,
            quorum_signers(),
        );
        state.finalized.insert(
            tick_id,
            Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
                Finalization::new(
                    tick_id,
                    TickHalf::Legs,
                    &Capped::from_array([Arc::new(taken_before)]),
                    Capped::from_array([]),
                ),
            ))),
        );

        state.release_tick(tick_id, Some(x));

        assert_eq!(
            state.ticked[&tick_id]
                .legs
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([t]),
            "the entry names the kept legs only",
        );
        assert!(
            state
                .pending_tick_resolutions
                .iter()
                .any(|(tick, _, resolution)| {
                    *tick == tick_id
                        && matches!(
                            resolution,
                            TickResolution::Abandoned { members, .. } if *members == BTreeSet::from([x])
                        )
                }),
            "the released leg's holds are let go of",
        );
        assert!(
            !state.finalized.contains(&tick_id),
            "the legs finalization taken before the release is gone",
        );
        assert_the_shared_verdict_still_settles(&mut state, tick_id, t);

        state.record_tick_resolution(
            &tick_id,
            TickResolution::Settled {
                height: BlockHeight::new(2),
                members: BTreeSet::from([t]),
                aborted: BTreeSet::new(),
            },
        );
        assert!(
            !state.ticked.contains_key(&tick_id),
            "the kept legs' settlement clears the entry",
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
    /// abandonment deadline.
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
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(&sibling, &Classified::whole())],
        );
        state
            .counterparts
            .ledger
            .certify(sibling_hash, Certified::ByExecution);

        // The commit that composes the abandonment, on the shard that
        // stranded the member.
        let block = make_live_block_on_shard(
            local,
            BlockHeight::new(9),
            STRANDED_DEADLINE_MS,
            ValidatorId::new(0),
            vec![],
        );
        state.commit_block_carrying(
            &sched,
            &test_certify(block, STRANDED_DEADLINE_MS),
            Naming::Composed,
        );

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
                provisional_claims: BTreeMap::new(),
                legs: BTreeMap::from([(tx_hash, BTreeMap::new())]),
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
        let actions = state
            .commit_block_carrying(
                &sched,
                &test_certify(block, STRANDED_DEADLINE_MS),
                Naming::Composed,
            )
            .actions;

        assert!(
            actions.iter().any(|action| matches!(
                action,
                Action::ResolveTicks { resolutions } if resolutions.iter().any(
                    |(id, resolution)| *id == tick_id
                        && matches!(
                            resolution,
                            TickResolution::Abandoned { members, .. } if members.contains(&tx_hash)
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

    /// A state whose ledger names `partner` party to `tx_hash`, on the
    /// schedule that has `partner` past-terminal at 1500ms.
    fn state_abandoning(
        topology_schedule: &TopologySchedule,
        local: ShardId,
        transaction: &Arc<Verifiable<Transaction>>,
    ) -> ExecutionCoordinator {
        let mut state = make_test_state_for_shard(ValidatorId::new(0), local);
        state.committed_ts = WeightedTimestamp::from_millis(1500);
        state.counterparts.ledger.register_committed(
            test_committed(),
            &PriceTable::GENESIS,
            [(transaction, &Classified::whole())],
        );
        state
            .counterparts
            .stamp_departures(topology_schedule, state.committed_ts);
        state
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
                .iter()
                .any(|entry| entry.tx_hash == tx_hash && entry.covered_by_record),
            "an unreadable departure closes at once"
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

        state.commit_block_carrying(
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
            Naming::Composed,
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
        let _ = state.finalize(&tick_id);
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

        let actions = state
            .commit_block_carrying(&topo, &certified, Naming::Composed)
            .actions;

        let fallback_fired = actions.iter().any(|a| {
            matches!(
                a,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::ExecutionCerts(..),
                    ..
                })
            )
        });
        assert!(
            !fallback_fired,
            "an expectation stamped at the commit clock is not already overdue at that commit"
        );
    }
}
