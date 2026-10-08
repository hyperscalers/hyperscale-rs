//! The sans-io reshape orchestrator.
//!
//! One per host. It owns the per-duty sequencing decisions of a split or merge —
//! when to sync, re-assert ready, follow, adopt, and seat — and drives them by
//! reading the committed-state projection ([`ReshapeView`]) and reacting to io
//! results. It holds the sans-io sequencers ([`ObserverBootstrap`],
//! [`ObserverTail`]) so both harnesses run the *same* sequencing; the adapter
//! owns all io (`RocksDB` opens, network fetch/notify, store writes, timers) and
//! the wall-clock pacing of [`ReshapeOrchestrator::step`].
//!
//! Each `step` reads the view, applies the io results the adapter feeds back,
//! advances every duty, and returns the io the adapter should perform. It is
//! idempotent: one-shot requests are guarded by duty flags, the sequencers gate
//! their own in-flight fetches, and the ready re-assert is deliberately repeated
//! each step (the adapter's step cadence paces it — production's 1s sleep,
//! simulation's per-slice pump).
//!
//! It covers all three reshape duties — the **split observer**, the **split
//! parent half**, and the **merge keeper** — each discovered from its own cohort
//! projection and sequenced to the shared adopt and seat tail.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_shard::committed_cells_for;
use hyperscale_storage::ImportProgress;
use hyperscale_types::network::request::{
    BlockIntent, GetBlockRequest, GetRemoteHeadersRequest, GetStateRangeRequest,
};
use hyperscale_types::network::response::{
    GetBlockResponse, GetRemoteHeadersResponse, GetStateRangeResponse,
};
use hyperscale_types::{
    Anchor, Block, BlockHash, BlockHeader, BlockHeight, ChainOrigin, Derivation, FrontierInputs,
    LocalTimestamp, QuorumCertificate, ShardAnchor, ShardId, StateRoot, SubstateKey, SubstateLeaf,
    ValidatorId, Verifier, WeightedTimestamp, derive_block_transactions,
};

use crate::bootstrap::{BootstrapRequest, ShardBootstrap, StateRangeOutcome};
use crate::reshape::merge_flip::merge_genesis_from_terminals;
use crate::reshape::observer::{
    ObserverBootstrap, ObserverTail, ProveOutcome, TailOutcome, TerminalSighting, TwoChainCheck,
};
use crate::reshape::split_flip::split_genesis_from_terminal;
use crate::reshape::view::ReshapeView;

/// What a [`ReshapeRequest::Fetch`] asks the adapter to retrieve, forwarded from
/// a held sequencer.
#[derive(Debug, Clone)]
pub enum FetchKind {
    /// A snap-sync state sub-range, from [`ObserverBootstrap`].
    StateRange {
        /// The sub-range id the response must be paired back to.
        sub_range: usize,
        /// The range request itself.
        request: GetStateRangeRequest,
    },
    /// A single block by height, from [`ObserverTail`] or a terminal fetch.
    Block {
        /// The block request itself.
        request: GetBlockRequest,
    },
    /// A batch of consecutive certified headers, from a recognizing
    /// [`ObserverTail`]. A recognition walk discards bodies, so it reads
    /// headers — which a host co-hosting the source serves from its own
    /// store, and which batch far better over the wire when it does not.
    Headers {
        /// The header request itself.
        request: GetRemoteHeadersRequest,
    },
}

/// Which genesis derivation a [`ReshapeRequest::Adopt`] performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptKind {
    /// A split observer adopts the store it followed to the parent's terminal.
    Split,
    /// A split parent half re-roots its cloned parent store onto the child
    /// subtree.
    ParentHalf,
    /// A merge parent adopts from both children's terminal contributions.
    Merge,
}

/// A unit of io the orchestrator needs the adapter to perform. The adapter owns
/// the store handles, network, and timers; it answers with a [`ReshapeEvent`].
#[derive(Debug, Clone)]
pub enum ReshapeRequest {
    /// Open (wiping any stale directory) `shard`'s store and replicate the
    /// engine bootstrap into it. Answered by [`ReshapeEvent::Opened`].
    OpenStore {
        /// The duty's store shard.
        shard: ShardId,
    },
    /// Seed `child`'s store by cloning the host's local `parent` store onto the
    /// child subtree, once the local parent has committed through the terminal
    /// crossing. Answered by [`ReshapeEvent::Opened`] when the clone lands,
    /// [`ReshapeEvent::SeedDeferred`] while the local parent is still behind,
    /// or [`ReshapeEvent::SeedUnavailable`] when the host holds no parent
    /// store to clone.
    SeedFromParent {
        /// The splitting parent whose store is cloned.
        parent: ShardId,
        /// The split child the clone seeds.
        child: ShardId,
        /// Height the local parent must have committed through before the
        /// clone is taken — the child's genesis height, one past the
        /// parent's terminal. Passed rather than read from the child's
        /// beacon anchor, which does not exist until an epoch after the
        /// cut and is precisely what the early flip does without.
        through: BlockHeight,
    },
    /// Fetch from `from`'s committee, on behalf of `duty`. Answered by
    /// [`ReshapeEvent::Fetched`] (or [`ReshapeEvent::FetchFailed`]). The
    /// adapter resolves `from` to its serving peers itself.
    Fetch {
        /// The duty this fetch belongs to (an observer's child).
        duty: ShardId,
        /// The shard whose committee serves the request.
        from: ShardId,
        /// What to fetch.
        kind: FetchKind,
    },
    /// Durably stage one verified snap-sync chunk into `shard`'s store.
    /// Answered by [`ReshapeEvent::Staged`], or by
    /// [`ReshapeEvent::StageFailed`] handing the chunk back.
    StageChunk {
        /// The duty's store shard.
        shard: ShardId,
        /// The assembly's progress after this chunk.
        progress: ImportProgress,
        /// The chunk's verified leaves.
        leaves: Vec<SubstateLeaf>,
    },
    /// Build `shard`'s boundary state at `height` from its staged
    /// chunks. Answered by [`ReshapeEvent::Imported`]. Emitted only
    /// after every [`Self::StageChunk`] has been acknowledged.
    FinalizeImport {
        /// The duty's store shard.
        shard: ShardId,
        /// The boundary height the staged leaves seed.
        height: BlockHeight,
    },
    /// Apply a followed parent block's child-prefix writes into `shard`'s store.
    /// Answered by [`ReshapeEvent::Applied`].
    ApplyFollow {
        /// The duty's store shard.
        shard: ShardId,
        /// The followed block, whole: its settled receipts, the
        /// transactions it committed, and the sweep its header names.
        block: Arc<Block>,
        /// The committed cells the block wrote, classified under its own
        /// window.
        creations: Vec<(SubstateKey, Vec<u8>)>,
        /// What the block's claims did to the read frontier.
        frontier: FrontierInputs,
    },
    /// Sign a ready signal for `validator` attesting the sync of `child`,
    /// anchored at `anchor`, and notify `recipients` — the target committee
    /// minus the signer. No response.
    BroadcastReady {
        /// The seat holder signing the signal.
        validator: ValidatorId,
        /// The successor shard the signer attests it synced — the split
        /// child an observer bootstrapped, or the child a merge keeper runs.
        /// Bound into the signed signal so the fold credits it only to a
        /// matching seat.
        child: ShardId,
        /// The attested anchor the signal windows from.
        anchor: ShardAnchor,
        /// The committee the signal is broadcast to.
        recipients: Vec<ValidatorId>,
    },
    /// Adopt `shard`'s derived genesis, verifying the adopted root against the
    /// beacon anchor. Answered by [`ReshapeEvent::Adopted`].
    Adopt {
        /// The duty's store shard.
        shard: ShardId,
        /// Split vs merge derivation.
        kind: AdoptKind,
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds, read off the same headers
        /// the genesis derives from — one for a split child, two for a
        /// merged parent.
        predecessors: Vec<Anchor>,
    },
    /// Seat the prepared `shard` — install its genesis and run consensus. No
    /// response (terminal).
    Seat {
        /// The duty's store shard.
        shard: ShardId,
    },
}

/// What a [`ReshapeEvent::Fetched`] carried back.
#[derive(Debug, Clone)]
pub enum FetchedKind {
    /// A state sub-range response, paired by `sub_range`.
    StateRange {
        /// The sub-range id this answers.
        sub_range: usize,
        /// The response.
        response: Box<GetStateRangeResponse>,
    },
    /// A block response.
    Block {
        /// The response.
        response: Box<GetBlockResponse>,
    },
    /// A certified-header batch response.
    Headers {
        /// The response.
        response: Box<GetRemoteHeadersResponse>,
    },
}

/// An io result the adapter feeds back into [`ReshapeOrchestrator::step`].
#[derive(Debug, Clone)]
pub enum ReshapeEvent {
    /// A store open completed.
    Opened {
        /// The opened store shard.
        shard: ShardId,
    },
    /// A fetch returned a response.
    Fetched {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed (which keeper half it answers).
        from: ShardId,
        /// The response.
        kind: FetchedKind,
    },
    /// A fetch failed at the transport level and should be re-armed.
    FetchFailed {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed.
        from: ShardId,
        /// What failed.
        kind: FetchKind,
    },
    /// A staged chunk was durably written.
    Staged {
        /// The store shard.
        shard: ShardId,
    },
    /// A staged chunk's durable write failed; the chunk comes back for
    /// re-staging on the next advance.
    StageFailed {
        /// The store shard.
        shard: ShardId,
        /// The assembly's progress after the chunk.
        progress: ImportProgress,
        /// The chunk's verified leaves.
        leaves: Vec<SubstateLeaf>,
    },
    /// A boundary import completed with the resulting store root.
    Imported {
        /// The store shard.
        shard: ShardId,
        /// The imported root.
        root: StateRoot,
    },
    /// A followed-block application completed with the resulting store root.
    Applied {
        /// The store shard.
        shard: ShardId,
        /// The applied root.
        root: StateRoot,
    },
    /// A genesis adoption completed (root already verified against the anchor).
    Adopted {
        /// The store shard.
        shard: ShardId,
    },
    /// A [`ReshapeRequest::SeedFromParent`] could not run yet — the host's local
    /// parent has not committed through the terminal crossing — so the seed
    /// should be re-armed and retried.
    SeedDeferred {
        /// The split child whose seed is deferred.
        child: ShardId,
    },
    /// A [`ReshapeRequest::SeedFromParent`] found no parent store on this
    /// host to clone — it restarted without one — so the parent half can
    /// never seed. The duty relinquishes the child's seat to the adapter's
    /// ordinary join, which seats the child against its attested anchor.
    SeedUnavailable {
        /// The split child whose seat is relinquished.
        child: ShardId,
    },
}

/// One observer's progress through its split duty.
enum ObserverPhase {
    /// Awaiting the child store open.
    Opening,
    /// Syncing the child span from the parent's attested anchor.
    Syncing(Box<ObserverBootstrap>),
    /// Synced; re-asserting ready and following the parent toward its terminal
    /// crossing, until the children seed.
    Following(Box<ObserverTail>),
    /// The child anchored before the follow applied the parent's terminal.
    /// The parent's blocks above the terminal that would prove it are no
    /// longer served under the child's id, so the follow cannot finish. A
    /// parent-half seat this host holds on the child takes the seat over and
    /// seeds it from the local parent; with none, the seat is the ordinary
    /// join's, which snap-syncs against the child's anchor. Inert, and kept
    /// so the observer is not rediscovered, until the committed projection
    /// releases it.
    Relinquished,
    /// The children seeded; fetching the certified terminal to derive genesis.
    FetchingTerminal {
        /// The beacon-seeded child anchor the derivation verifies against.
        anchor: ShardAnchor,
        ask: TerminalAsk,
    },
    /// Terminal fetched and genesis derived; awaiting the next `advance` to emit
    /// the adopt.
    Adopting {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds.
        predecessors: Vec<Anchor>,
    },
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted into the store; awaiting the placement that seats it.
    Prepared,
    /// Seat emitted; inert until the committed projection releases the duty.
    /// The duty stays in the map so `discover_parent_half_duties` keeps deferring
    /// a co-hosted parent half of this child to the observer's seat — which
    /// installs every homed committee member, parent halves included — rather
    /// than opening a second duty that would re-seat the child from genesis.
    Seated,
}

/// Wait between a seat's first two ready assertions.
const READY_REASSERT_MIN: Duration = Duration::from_secs(1);

/// Wait before asking again after a fetch that failed or answered with
/// something the duty could not use: a terminal fetch that did not deliver
/// the terminal, a walk whose answer or unproven run was refused, or a walk
/// at the chain's tip that found nothing above it yet.
const REFETCH_WAIT: Duration = Duration::from_secs(1);

/// Pace a walk after the answer that produced `outcome`. One that could
/// not advance it — nothing held at the height yet, or a refusal — holds
/// the next fetch back by [`REFETCH_WAIT`]; every answer pumps the
/// orchestrator at once, so a walk at the tip would otherwise ask again as
/// fast as the peer replies. An accepted answer asks again at once, so a
/// walk behind the tip is not slowed.
fn paced(tail: &mut ObserverTail, outcome: TailOutcome, now: LocalTimestamp, duty: ShardId) {
    match outcome {
        TailOutcome::Accepted => {}
        TailOutcome::NotYetAvailable => tail.defer(now.plus(REFETCH_WAIT)),
        TailOutcome::Rejected(reason) => {
            tracing::warn!(?duty, reason, "refused an answer to a reshape walk");
            tail.defer(now.plus(REFETCH_WAIT));
        }
    }
}

/// When a terminal fetch may go out: one at a time, and after an answer
/// that did not deliver the terminal, not again until
/// [`REFETCH_WAIT`] has passed. Every answer pumps the orchestrator
/// at once, so without the wait a peer answering wrongly would be asked
/// again as fast as it replies.
#[derive(Debug, Clone, Copy)]
enum TerminalAsk {
    /// No fetch in flight; the next may go out from this instant.
    Due(LocalTimestamp),
    InFlight,
}

impl TerminalAsk {
    const NOW: Self = Self::Due(LocalTimestamp::ZERO);

    /// Whether a fetch goes out at `now`, marking it in flight if so.
    fn begin(&mut self, now: LocalTimestamp) -> bool {
        match *self {
            Self::Due(at) if now >= at => {
                *self = Self::InFlight;
                true
            }
            _ => false,
        }
    }

    /// The fetch in flight did not deliver the terminal.
    fn missed(&mut self, now: LocalTimestamp) {
        *self = Self::Due(now.plus(REFETCH_WAIT));
    }
}

/// Ceiling the re-assert wait doubles up to, so a seat the beacon never
/// credits keeps asserting rather than falling silent.
///
/// The anchor window turns over about once an epoch and restarts the
/// backoff, so this governs how many assertions a seat makes inside one
/// epoch rather than how long it can go quiet. Held well under the epoch
/// because the readiness gate needs a quorum of seats pooled at one
/// committee at one time, and an emitter cannot see how close that is:
/// raising the ceiling to 16s drops a 30s-epoch cohort to about five
/// assertions per epoch, which is under what a halt recovery's committee
/// churn needs to reach its gate.
const READY_REASSERT_MAX: Duration = Duration::from_secs(4);

/// One seat's ready assertion schedule.
///
/// A ready signal only says something new when the anchor window it is cut
/// from turns over, which happens once per epoch — the boundary record the
/// emitter windows from refreshes at the epoch fold, and the gate that
/// consumes the signal re-evaluates at the same fold. Everything between is
/// retransmission against loss, so it backs off rather than repeating at
/// the pump's rate.
///
/// Real time, not steps: the production supervisor pumps the orchestrator on
/// a timer while the simulation drives it to a fixpoint, so a step means
/// different things on either side and only a clock reads the same on both.
struct ReadyAssert {
    /// Anchor window start the last assertion was cut from. A different
    /// value is a genuinely new signal and restarts the backoff.
    window: WeightedTimestamp,
    /// Committee the last assertion went to. A pool is per member and
    /// local, so a member seated since then holds nothing this seat sent —
    /// a committee redraw or shuffle silently undoes every assertion so
    /// far, and only re-sending repairs it.
    recipients: Vec<ValidatorId>,
    /// When the next assertion comes due.
    due: LocalTimestamp,
    /// Wait applied after the next assertion, doubling to
    /// [`READY_REASSERT_MAX`].
    backoff: Duration,
}

impl ReadyAssert {
    /// Whether to assert at `now` for an anchor windowed at `window`,
    /// addressed to `recipients`, advancing the schedule when it answers
    /// `true`.
    ///
    /// Asserts immediately for anything it has not asserted for — a fresh
    /// window, or a committee it has not sent this window to — then backs
    /// off geometrically.
    fn should_assert(
        slot: &mut Option<Self>,
        window: WeightedTimestamp,
        recipients: &[ValidatorId],
        now: LocalTimestamp,
    ) -> bool {
        match slot {
            Some(state) if state.window == window && state.recipients == recipients => {
                if now < state.due {
                    return false;
                }
                state.backoff = (state.backoff * 2).min(READY_REASSERT_MAX);
                state.due = now.plus(state.backoff);
            }
            _ => {
                *slot = Some(Self {
                    window,
                    recipients: recipients.to_vec(),
                    due: now.plus(READY_REASSERT_MIN),
                    backoff: READY_REASSERT_MIN,
                });
            }
        }
        true
    }
}

/// One split observer duty, keyed by the child it syncs. A host may hold more
/// than one cohort seat for the same child (multiple co-hosted validators drawn
/// into it); they share the one child-span sync and store, each re-asserting its
/// own ready signal and seating under the one placement.
struct ObserverDuty {
    parent: ShardId,
    child: ShardId,
    validators: Vec<ValidatorId>,
    phase: ObserverPhase,
    open_requested: bool,
    store_opened: bool,
    /// Verified chunks awaiting a [`ReshapeRequest::StageChunk`] emit on
    /// the next advance.
    pending_stage: Vec<(ImportProgress, Vec<SubstateLeaf>)>,
    /// Stage writes emitted but not yet acknowledged; the finalize waits
    /// for zero so every staged chunk is durable first.
    stages_unacked: usize,
    /// Hash of the genesis this duty adopted from its own follow, before
    /// the beacon's anchor existed. Checked against that anchor when it
    /// lands; a mismatch means the parent chain this host followed is not
    /// the one the network committed.
    adopted_genesis: Option<BlockHash>,
    /// Per-seat ready re-assertion schedules. A seat the beacon has already
    /// credited is absent — it stops asserting for good.
    ready_asserts: BTreeMap<ValidatorId, Option<ReadyAssert>>,
}

/// One keeper seat this host runs in a pending merge.
struct KeeperMember {
    validator: ValidatorId,
    own_child: ShardId,
    /// Ready re-assertion schedule for this seat.
    ready_assert: Option<ReadyAssert>,
}

/// One child half's progress in a keeper's merged-store build: its
/// span assembly (staged into the parent store as chunks arrive) and
/// its certified terminal.
struct KeeperHalf {
    child: ShardId,
    bootstrap: Box<ShardBootstrap>,
    terminal: Option<(BlockHeader, QuorumCertificate)>,
    /// The anchored terminal the fetch in flight names.
    terminal_requested: Option<BlockHash>,
    terminal_ask: TerminalAsk,
}

impl KeeperHalf {
    fn new(child: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            child,
            bootstrap: Box::new(ShardBootstrap::state_only(child, anchor)),
            terminal: None,
            terminal_requested: None,
            terminal_ask: TerminalAsk::NOW,
        }
    }

    /// A half whose terminal the keeper already recognised on the child's
    /// own chain, so its span assembles against that terminal rather than
    /// against whichever crossing the beacon last anchored.
    fn recognized(child: ShardId, sighting: &TerminalSighting) -> Self {
        let header = &sighting.header;
        Self {
            child,
            bootstrap: Box::new(ShardBootstrap::state_only(child, terminal_anchor(header))),
            terminal: Some((header.clone(), sighting.terminal_qc.clone())),
            terminal_requested: None,
            terminal_ask: TerminalAsk::NOW,
        }
    }
}

/// One child's terminal walk in a keeper's merge duty: the follow that
/// finds which of the child's blocks ends its chain, applying nothing.
struct KeeperRecognition {
    child: ShardId,
    tail: Box<ObserverTail>,
    /// The terminal once found and commit-proven. Retained so the proof
    /// is verified once rather than on every advance the sibling half
    /// still has to catch up over.
    proven: Option<TerminalSighting>,
}

/// The anchor a recognised terminal stands in for — the record the beacon
/// writes for that same block when its contribution folds an epoch later.
/// Mirrors `record_boundaries`' field-for-field construction, so a half
/// assembled against it verifies exactly as one assembled against the
/// beacon's.
fn terminal_anchor(header: &BlockHeader) -> ShardAnchor {
    ShardAnchor {
        state_root: header.state_root(),
        block_hash: header.hash(),
        height: header.height(),
        weighted_timestamp: header.parent_qc().weighted_timestamp(),
        witness_base: header.beacon_witness_base(),
        terminal_settled_txs: header.settled_txs_root(),
        handoff_complete: None,
        terminal_epoch: None,
    }
}

/// One keeper's progress through its merge duty, keyed by the parent it reforms.
enum KeeperPhase {
    /// Re-asserting ready until the cut is in reach.
    ReassertingReady,
    /// Walking both children's chains to find the terminals that end them,
    /// so the parent reforms at the cut rather than an epoch later when the
    /// beacon composes its anchor. Applies nothing — the merged store is
    /// built from the halves' spans in `Building`.
    Recognizing {
        left: Box<KeeperRecognition>,
        right: Box<KeeperRecognition>,
    },
    /// Both terminals in hand; collecting both halves' spans, deriving the
    /// merged genesis, and finalizing the staged union.
    Building {
        /// The instant the children terminate at, and the merged chain's
        /// clock anchor.
        cut_wt: WeightedTimestamp,
        /// The beacon's composed parent anchor, when this duty reached
        /// `Building` by the fallback rather than the cut-over. Present
        /// means the derivation is checked against it. Boxed: the anchor
        /// dwarfs every other variant of the phase.
        anchor: Option<Box<ShardAnchor>>,
        left: Box<KeeperHalf>,
        right: Box<KeeperHalf>,
        derived: Option<(ChainOrigin, Box<Block>, Vec<Anchor>)>,
        finalize_requested: bool,
    },
    /// Union imported; awaiting the next advance to emit the adopt.
    Adopting {
        origin: ChainOrigin,
        genesis: Box<Block>,
        predecessors: Vec<Anchor>,
    },
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted; awaiting the placement that seats the keepers.
    Prepared,
}

/// One merge keeper duty, keyed by the parent it reforms.
struct KeeperDuty {
    members: Vec<KeeperMember>,
    phase: KeeperPhase,
    open_requested: bool,
    store_opened: bool,
    /// Verified chunks (from either half — their spans are disjoint)
    /// awaiting a [`ReshapeRequest::StageChunk`] emit on the next
    /// advance.
    pending_stage: Vec<(ImportProgress, Vec<SubstateLeaf>)>,
    /// Stage writes emitted but not yet acknowledged; the union
    /// finalize waits for zero so every staged chunk is durable first.
    stages_unacked: usize,
}

/// One parent half's progress through its split duty, keyed by the child it
/// seats.
enum ParentHalfPhase {
    /// Awaiting the child anchor, then seeding the child store by cloning the
    /// host's local parent once it has committed through the terminal crossing.
    /// The fallback entry, for a duty with no scheduled cut to recognise.
    Seeding {
        /// Whether the seed request is already in flight.
        requested: bool,
    },
    /// Walking the parent's own committed chain to find its terminal
    /// crossing, so the child can be seeded and adopted at the cut rather
    /// than an epoch later when the beacon publishes the child's anchor.
    /// Applies nothing — the store comes from cloning the local parent.
    Recognizing(Box<ObserverTail>),
    /// Terminal recognised and genesis derived; cloning the local parent
    /// through the child's genesis height.
    SeedingAt {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds.
        predecessors: Vec<Anchor>,
        /// Whether the seed request is already in flight.
        requested: bool,
    },
    /// Store seeded; fetching the parent's certified terminal to derive the
    /// child genesis.
    FetchingTerminal {
        /// The beacon-seeded child anchor the derivation verifies against.
        anchor: ShardAnchor,
        ask: TerminalAsk,
    },
    /// Terminal fetched and genesis derived; awaiting the next `advance` to emit
    /// the adopt.
    Adopting {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds.
        predecessors: Vec<Anchor>,
    },
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted; awaiting the placement that seats it.
    Prepared,
    /// Seated; inert until the committed projection releases the duty.
    Seated,
    /// The host holds no parent store to seed the child from, so the child's
    /// seat is the adapter's ordinary join's. Inert, and kept only so the
    /// duty is not rediscovered, until the committed projection releases it.
    Relinquished,
}

/// One split parent-half duty, keyed by the child it seats. As with an observer
/// duty, a host may hold more than one parent-half seat for the same child; they
/// share the one cloned store and seat under the one placement.
struct ParentHalfDuty {
    parent: ShardId,
    validators: Vec<ValidatorId>,
    phase: ParentHalfPhase,
    store_seeded: bool,
}

/// The keeper half `from` addresses, when it is one of the duty's children.
/// The recognition walk covering `from`, when a keeper is still finding
/// its children's terminals.
fn recognition_for<'a>(
    left: &'a mut KeeperRecognition,
    right: &'a mut KeeperRecognition,
    from: ShardId,
) -> Option<&'a mut KeeperRecognition> {
    if left.child == from {
        Some(left)
    } else if right.child == from {
        Some(right)
    } else {
        None
    }
}

fn half_for<'a>(
    left: &'a mut KeeperHalf,
    right: &'a mut KeeperHalf,
    from: ShardId,
) -> Option<&'a mut KeeperHalf> {
    if from == left.child {
        Some(left)
    } else if from == right.child {
        Some(right)
    } else {
        None
    }
}

/// The per-host reshape orchestrator. See the module docs.
#[derive(Default)]
pub struct ReshapeOrchestrator {
    /// This host's validator ids — the seats it may hold.
    me: Vec<ValidatorId>,
    /// In-flight observer duties, keyed by child.
    observers: BTreeMap<ShardId, ObserverDuty>,
    /// In-flight keeper duties, keyed by the parent each reforms.
    keepers: BTreeMap<ShardId, KeeperDuty>,
    /// In-flight parent-half duties, keyed by the child each seats.
    parent_halves: BTreeMap<ShardId, ParentHalfDuty>,
}

impl ReshapeOrchestrator {
    /// A fresh orchestrator for a host running `me`.
    #[must_use]
    pub const fn new(me: Vec<ValidatorId>) -> Self {
        Self {
            me,
            observers: BTreeMap::new(),
            keepers: BTreeMap::new(),
            parent_halves: BTreeMap::new(),
        }
    }

    /// Whether an in-flight duty owns seating `shard` — a merging parent a
    /// keeper reforms, or a splitting child an observer syncs or a parent
    /// half seeds. The adapter suppresses the placement-delta join for such
    /// a shard so the orchestrator seats it from the duty's prepared store,
    /// rather than the join racing a redundant fresh snap-sync against it.
    #[must_use]
    pub fn is_seating(&self, shard: ShardId) -> bool {
        self.keepers.contains_key(&shard)
            || ((self.observers.contains_key(&shard) || self.parent_halves.contains_key(&shard))
                && !self.relinquished(shard))
    }

    /// Whether this host's split duty for `shard` relinquished the child's
    /// seat to the adapter's ordinary join — a parent half with no parent
    /// store to seed from (see [`ReshapeEvent::SeedUnavailable`]) or whose
    /// child anchored past its genesis, or an observer whose follow the
    /// child's anchor overtook and that no parent half took over from. The
    /// adapter reads the committed cohort as reshape ownership; a
    /// relinquished seat is not, and a store the duty prepared for it is the
    /// adapter's to discard.
    ///
    /// A parent half exists beside an observer only once the observer has
    /// relinquished, so when present it is the duty that owns the seat.
    #[must_use]
    pub fn relinquished(&self, shard: ShardId) -> bool {
        self.parent_halves.get(&shard).map_or_else(
            || {
                self.observers
                    .get(&shard)
                    .is_some_and(|duty| matches!(duty.phase, ObserverPhase::Relinquished))
            },
            |half| matches!(half.phase, ParentHalfPhase::Relinquished),
        )
    }

    /// Advance every duty one step: apply the io results in `events`, discover
    /// new duties from `view`, and return the io the adapter should perform.
    ///
    /// `derivation` is this node's: a followed block arrives off the wire
    /// or out of a peer's store with none of its transactions derived, and
    /// the committed cells a follow writes are read off what deriving them
    /// seats.
    pub fn step(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        events: Vec<ReshapeEvent>,
        now: LocalTimestamp,
    ) -> Vec<ReshapeRequest> {
        for event in events {
            self.apply_event(event, now);
        }
        self.discover_observer_duties(view);
        self.discover_keeper_duties(view);

        let mut requests = Vec::new();
        let children: Vec<ShardId> = self.observers.keys().copied().collect();
        for child in children {
            self.advance_observer(child, view, verifier, derivation, now, &mut requests);
        }
        // After the observers advance, so a parent half takes over an
        // observer that relinquished in this very step: between steps the
        // adapter would otherwise read the seat as the join's, drop the
        // observer's store and start a join nothing may be able to serve.
        self.discover_parent_half_duties(view);
        let parents: Vec<ShardId> = self.keepers.keys().copied().collect();
        for parent in parents {
            self.advance_keeper(parent, view, verifier, now, &mut requests);
        }
        let halves: Vec<ShardId> = self.parent_halves.keys().copied().collect();
        for child in halves {
            self.advance_parent_half(child, view, verifier, now, &mut requests);
        }
        // A seated or relinquished parent half lingers only to keep its child
        // from being re-discovered; once the projection releases it (the child
        // committed past genesis) the duty is done.
        self.parent_halves.retain(|child, duty| {
            !matches!(
                duty.phase,
                ParentHalfPhase::Seated | ParentHalfPhase::Relinquished
            ) || view.parent_half_cohorts().contains_key(child)
        });
        // A seated or relinquished observer lingers through the parent-half
        // phase so its child stays in `observers` rather than being
        // rediscovered; a seated one also defers any co-hosted parent half
        // to the seat already issued. Once the projection releases the
        // child the duty ends.
        self.observers.retain(|child, duty| {
            !matches!(
                duty.phase,
                ObserverPhase::Seated | ObserverPhase::Relinquished
            ) || view.parent_half_cohorts().contains_key(child)
        });
        requests
    }

    /// The observer duty for `shard` that still owns it. A relinquished
    /// observer is inert: io for the child belongs to the parent half that
    /// took the seat over.
    fn live_observer(&mut self, shard: ShardId) -> Option<&mut ObserverDuty> {
        self.observers
            .get_mut(&shard)
            .filter(|duty| !matches!(duty.phase, ObserverPhase::Relinquished))
    }

    /// Route one io result to the duty and sequencer awaiting it.
    fn apply_event(&mut self, event: ReshapeEvent, now: LocalTimestamp) {
        match event {
            ReshapeEvent::Opened { shard } => {
                if let Some(duty) = self.live_observer(shard) {
                    duty.store_opened = true;
                } else if let Some(duty) = self.keepers.get_mut(&shard) {
                    duty.store_opened = true;
                } else if let Some(duty) = self.parent_halves.get_mut(&shard) {
                    duty.store_seeded = true;
                }
            }
            ReshapeEvent::Fetched { duty, from, kind } => {
                if self.live_observer(duty).is_some() {
                    self.apply_observer_fetched(duty, kind, now);
                } else if self.keepers.contains_key(&duty) {
                    self.apply_keeper_fetched(duty, from, kind, now);
                } else if self.parent_halves.contains_key(&duty) {
                    self.apply_parent_half_fetched(duty, kind, now);
                }
            }
            ReshapeEvent::FetchFailed { duty, from, kind } => {
                self.apply_fetch_failed(duty, from, kind, now);
            }
            ReshapeEvent::Staged { shard } => {
                if let Some(duty) = self.live_observer(shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                } else if let Some(duty) = self.keepers.get_mut(&shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                }
            }
            ReshapeEvent::StageFailed {
                shard,
                progress,
                leaves,
            } => {
                // Hand the chunk back to the front of the queue: the next
                // advance re-emits it, so a transient write failure retries
                // instead of pinning `stages_unacked` above zero forever.
                // With no live duty for the shard the chunk is dropped.
                if let Some(duty) = self.live_observer(shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                    duty.pending_stage.insert(0, (progress, leaves));
                } else if let Some(duty) = self.keepers.get_mut(&shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                    duty.pending_stage.insert(0, (progress, leaves));
                }
            }
            ReshapeEvent::Imported { shard, root } => self.apply_imported(shard, root),
            ReshapeEvent::Applied { shard, root } => {
                if let Some(duty) = self.live_observer(shard)
                    && let ObserverPhase::Following(tail) = &mut duty.phase
                    && tail.on_applied(root).is_err()
                {
                    // A diverged follow fails closed: drop the duty so the
                    // adapter falls back to a fresh snap-sync join.
                    self.observers.remove(&shard);
                }
            }
            ReshapeEvent::Adopted { shard } => {
                if let Some(duty) = self.live_observer(shard)
                    && matches!(duty.phase, ObserverPhase::AwaitingAdopt)
                {
                    duty.phase = ObserverPhase::Prepared;
                } else if let Some(duty) = self.keepers.get_mut(&shard)
                    && matches!(duty.phase, KeeperPhase::AwaitingAdopt)
                {
                    duty.phase = KeeperPhase::Prepared;
                } else if let Some(duty) = self.parent_halves.get_mut(&shard)
                    && matches!(duty.phase, ParentHalfPhase::AwaitingAdopt)
                {
                    duty.phase = ParentHalfPhase::Prepared;
                }
            }
            ReshapeEvent::SeedDeferred { child } => {
                if let Some(duty) = self.parent_halves.get_mut(&child) {
                    match &mut duty.phase {
                        ParentHalfPhase::Seeding { requested }
                        | ParentHalfPhase::SeedingAt { requested, .. } => *requested = false,
                        _ => {}
                    }
                }
            }
            ReshapeEvent::SeedUnavailable { child } => {
                if let Some(duty) = self.parent_halves.get_mut(&child)
                    && matches!(
                        duty.phase,
                        ParentHalfPhase::Seeding { .. } | ParentHalfPhase::SeedingAt { .. }
                    )
                {
                    duty.phase = ParentHalfPhase::Relinquished;
                }
            }
        }
    }

    /// Re-arm a failed fetch on the duty awaiting it.
    fn apply_fetch_failed(
        &mut self,
        duty: ShardId,
        from: ShardId,
        kind: FetchKind,
        now: LocalTimestamp,
    ) {
        if let Some(observer) = self.live_observer(duty) {
            match (&mut observer.phase, kind) {
                (ObserverPhase::Syncing(bootstrap), FetchKind::StateRange { sub_range, .. }) => {
                    bootstrap.on_state_range_failure(sub_range);
                }
                (ObserverPhase::Following(tail), FetchKind::Block { .. }) => {
                    tail.on_failure();
                }
                (ObserverPhase::FetchingTerminal { ask, .. }, _) => ask.missed(now),
                _ => {}
            }
        } else if let Some(keeper) = self.keepers.get_mut(&duty) {
            match &mut keeper.phase {
                KeeperPhase::Recognizing { left, right } => {
                    if let Some(half) = recognition_for(left, right, from) {
                        half.tail.on_failure();
                    }
                }
                KeeperPhase::Building { left, right, .. } => {
                    if let Some(half) = half_for(left, right, from) {
                        match kind {
                            FetchKind::StateRange { sub_range, .. } => {
                                half.bootstrap.on_state_range_failure(sub_range);
                            }
                            FetchKind::Block { .. } => {
                                half.terminal_requested = None;
                                half.terminal_ask.missed(now);
                            }
                            // A building half walks no headers.
                            FetchKind::Headers { .. } => {}
                        }
                    }
                }
                _ => {}
            }
        } else if let Some(half) = self.parent_halves.get_mut(&duty) {
            match &mut half.phase {
                ParentHalfPhase::Recognizing(tail) => tail.on_failure(),
                ParentHalfPhase::FetchingTerminal { ask, .. } => ask.missed(now),
                _ => {}
            }
        }
    }

    /// Route an import root to the observer or keeper awaiting it.
    fn apply_imported(&mut self, shard: ShardId, root: StateRoot) {
        if let Some(observer) = self.live_observer(shard) {
            if let ObserverPhase::Syncing(bootstrap) = &mut observer.phase {
                bootstrap.on_imported(root);
            }
        } else if let Some(keeper) = self.keepers.get_mut(&shard) {
            // The merged union imported; emit the adopt next.
            let derived = match &mut keeper.phase {
                KeeperPhase::Building { derived, .. } => derived.take(),
                _ => None,
            };
            if let Some((origin, genesis, predecessors)) = derived {
                keeper.phase = KeeperPhase::Adopting {
                    origin,
                    genesis,
                    predecessors,
                };
            }
        }
    }

    /// Route a keeper half's fetch response, recording its terminal once served.
    fn apply_keeper_fetched(
        &mut self,
        parent: ShardId,
        from: ShardId,
        kind: FetchedKind,
        now: LocalTimestamp,
    ) {
        let Some(keeper) = self.keepers.get_mut(&parent) else {
            return;
        };
        if let KeeperPhase::Recognizing { left, right } = &mut keeper.phase {
            if let FetchedKind::Headers { response } = &kind
                && let Some(half) = recognition_for(left, right, from)
            {
                let outcome = half.tail.on_certified_headers(&response.headers);
                paced(&mut half.tail, outcome, now, parent);
            }
            return;
        }
        let KeeperPhase::Building { left, right, .. } = &mut keeper.phase else {
            return;
        };
        let Some(half) = half_for(left, right, from) else {
            return;
        };
        match kind {
            FetchedKind::StateRange {
                sub_range,
                response,
            } => {
                if let StateRangeOutcome::Staged { leaves, progress } =
                    half.bootstrap.on_state_range(sub_range, &response)
                {
                    keeper.pending_stage.push((progress, leaves));
                }
            }
            // A building half walks no headers.
            FetchedKind::Headers { .. } => {}
            // Only the anchored terminal is recorded; anything else leaves
            // the half without one, and the next advance asks again.
            FetchedKind::Block { response } => {
                let expected = half.terminal_requested.take();
                half.terminal_ask.missed(now);
                if let Some(elided) = response.block() {
                    let served = elided.header().hash();
                    if expected == Some(served) {
                        half.terminal = Some((elided.header().clone(), elided.qc().clone()));
                    } else {
                        tracing::warn!(
                            child = ?half.child,
                            ?served,
                            ?expected,
                            "a keeper's terminal fetch returned a block other than the anchored terminal"
                        );
                    }
                }
            }
        }
    }

    /// Route a fetch response to its sequencer, deriving genesis once the
    /// terminal arrives.
    fn apply_observer_fetched(&mut self, duty: ShardId, kind: FetchedKind, now: LocalTimestamp) {
        let Some(duty) = self.observers.get_mut(&duty) else {
            return;
        };
        let child = duty.child;
        let mut next: Option<ObserverPhase> = None;
        match (&mut duty.phase, kind) {
            (
                ObserverPhase::Syncing(bootstrap),
                FetchedKind::StateRange {
                    sub_range,
                    response,
                },
            ) => {
                if let StateRangeOutcome::Staged { leaves, progress } =
                    bootstrap.on_state_range(sub_range, &response)
                {
                    duty.pending_stage.push((progress, leaves));
                }
            }
            (ObserverPhase::Following(tail), FetchedKind::Block { response }) => {
                let outcome = tail.on_response(&response);
                paced(tail, outcome, now, child);
            }
            (ObserverPhase::FetchingTerminal { anchor, ask }, FetchedKind::Block { response }) => {
                ask.missed(now);
                let anchor = *anchor;
                if let Some(elided) = response.block()
                    && let Some((genesis, origin, predecessor)) =
                        anchored_split_genesis(child, elided.header(), elided.qc(), &anchor)
                {
                    next = Some(ObserverPhase::Adopting {
                        origin,
                        genesis: Box::new(genesis),
                        predecessors: predecessor.into_iter().collect(),
                    });
                }
            }
            _ => {}
        }
        if let Some(phase) = next {
            duty.phase = phase;
        }
    }

    /// Derive a parent half's child genesis once its terminal fetch returns.
    fn apply_parent_half_fetched(
        &mut self,
        child: ShardId,
        kind: FetchedKind,
        now: LocalTimestamp,
    ) {
        let Some(duty) = self.parent_halves.get_mut(&child) else {
            return;
        };
        let mut next: Option<ParentHalfPhase> = None;
        if let ParentHalfPhase::Recognizing(tail) = &mut duty.phase
            && let FetchedKind::Headers { response } = &kind
        {
            let outcome = tail.on_certified_headers(&response.headers);
            paced(tail, outcome, now, child);
            return;
        }
        if let ParentHalfPhase::FetchingTerminal { anchor, ask } = &mut duty.phase
            && let FetchedKind::Block { response } = kind
        {
            ask.missed(now);
            let anchor = *anchor;
            if let Some(elided) = response.block()
                && let Some((genesis, origin, predecessor)) =
                    anchored_split_genesis(child, elided.header(), elided.qc(), &anchor)
            {
                next = Some(ParentHalfPhase::Adopting {
                    origin,
                    genesis: Box::new(genesis),
                    predecessors: predecessor.into_iter().collect(),
                });
            }
        }
        if let Some(phase) = next {
            duty.phase = phase;
        }
    }

    /// Open an observer duty for every cohort seat this host holds that it
    /// isn't already running.
    fn discover_observer_duties(&mut self, view: &ReshapeView) {
        for (&parent, cohort) in view.observer_cohorts() {
            for (&validator, seat) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let child = seat.shard;
                let duty = self.observers.entry(child).or_insert_with(|| ObserverDuty {
                    parent,
                    child,
                    validators: Vec::new(),
                    phase: ObserverPhase::Opening,
                    open_requested: false,
                    store_opened: false,
                    pending_stage: Vec::new(),
                    stages_unacked: 0,
                    adopted_genesis: None,
                    ready_asserts: BTreeMap::new(),
                });
                if !duty.validators.contains(&validator) {
                    duty.validators.push(validator);
                }
            }
        }
    }

    /// Advance one observer duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over ObserverPhase
    fn advance_observer(
        &mut self,
        child: ShardId,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let Some(duty) = self.observers.get_mut(&child) else {
            return;
        };
        // A duty that flipped from its own follow adopted a genesis before
        // the beacon published one. The seeded anchor is the same block
        // derived twice — once by this host from the chain it tailed, once
        // by the fold from the terminal contribution it committed — so the
        // two must agree.
        //
        // Only against the *seeded* anchor. `seed_split_children` fills a
        // child's record only while it is still the zero placeholder, so a
        // child whose own first crossing folds first keeps that crossing as
        // its anchor and is never seeded. Comparing a genesis hash against
        // a crossing hash can only mismatch, and the child is correct.
        // `advanced_past_genesis` is exactly that distinction: the fold
        // sets it on a real crossing and never on a seed.
        if duty.adopted_genesis.is_some() {
            if view.advanced_past_genesis(child) {
                // The comparison window closed with no disagreement to see.
                duty.adopted_genesis = None;
            } else if let Some(anchor) = view.boundary(child) {
                let adopted = duty.adopted_genesis.take();
                if anchor.block_hash != adopted.expect("checked above") {
                    // The local parent chain and the network disagree about a
                    // committed block. Nothing here can repair that: the store
                    // may already be seated under a running vnode, so wiping it
                    // would take the shard down to fix a fault it cannot fix.
                    // Surface it and stop — the duty is done either way, and
                    // the split's cohort projection has already released, so no
                    // rediscovery re-opens it.
                    tracing::error!(
                        ?child,
                        adopted = ?adopted,
                        anchored = ?anchor.block_hash,
                        "adopted split-child genesis disagrees with the beacon anchor; \
                         the followed parent chain is not the one the network committed"
                    );
                    self.observers.remove(&child);
                    return;
                }
            }
        }
        let Some(duty) = self.observers.get_mut(&child) else {
            return;
        };
        match &mut duty.phase {
            ObserverPhase::Opening => {
                if !duty.open_requested {
                    out.push(ReshapeRequest::OpenStore { shard: child });
                    duty.open_requested = true;
                }
                if duty.store_opened
                    && let Some(anchor) = view.boundary(duty.parent)
                {
                    duty.phase = ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(
                        duty.parent,
                        anchor,
                        child,
                    )));
                }
            }
            ObserverPhase::Syncing(bootstrap) => {
                for (progress, leaves) in duty.pending_stage.drain(..) {
                    duty.stages_unacked += 1;
                    out.push(ReshapeRequest::StageChunk {
                        shard: child,
                        progress,
                        leaves,
                    });
                }
                for request in bootstrap.next_requests() {
                    // The pending child's witness accumulator starts empty, so
                    // an observer bootstrap only ever emits state ranges.
                    let BootstrapRequest::StateRange(sub_range, request) = request else {
                        continue;
                    };
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: duty.parent,
                        kind: FetchKind::StateRange { sub_range, request },
                    });
                }
                if duty.stages_unacked == 0
                    && let Some(height) = bootstrap.take_finalize()
                {
                    out.push(ReshapeRequest::FinalizeImport {
                        shard: child,
                        height,
                    });
                }
                if bootstrap.imported_root().is_some() {
                    let anchor = bootstrap.anchor();
                    duty.phase =
                        ObserverPhase::Following(Box::new(ObserverTail::new(anchor, child)));
                }
            }
            ObserverPhase::Following(tail) => {
                // Publish the parent's cut as soon as the beacon schedules
                // one, so the follow recognises the terminal crossing as it
                // walks past it rather than being told which crossing was
                // terminal an epoch later.
                tail.set_terminal_cut(view.terminal_cut(duty.parent));
                // Release whatever the fetched run now proves committed,
                // each QC verified against the parent committee of its own
                // window.
                let parent = duty.parent;
                let proved = tail.prove(verifier, view.network(), |anchor_wt, qc_wt| {
                    view.certifying_committee(parent, anchor_wt, qc_wt)
                });
                if let ProveOutcome::Refuted(reason) = proved {
                    tracing::warn!(?child, reason, "dropped an unproven run of parent blocks");
                    tail.defer(now.plus(REFETCH_WAIT));
                }
                // Flip at the cut, from the chain this host followed,
                // rather than an epoch later when the beacon publishes the
                // anchor. The store must have applied through the terminal
                // — the genesis adopts the child subtree as of *its* root.
                // A settled sighting is of a terminal proven committed, since
                // the follow applies nothing else.
                if let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                {
                    tracing::info!(
                        ?child,
                        terminal_height = sighting.header.height().inner(),
                        "flipping the split child from its own follow of the parent"
                    );
                    duty.adopted_genesis = Some(derived.block.hash());
                    duty.phase = ObserverPhase::Adopting {
                        origin: derived.origin,
                        genesis: Box::new(derived.block.clone()),
                        predecessors: derived.predecessor.into_iter().collect(),
                    };
                    return;
                }
                // Once this child's boundary seeds, the parent terminated. A
                // tail that already applied the terminal derives genesis from
                // it. One that did not cannot: proving the terminal takes the
                // parent's blocks above it, and the child's committee serves
                // its own chain at those heights — the follow would refuse
                // every answer. A parent-half seat this host holds on the
                // child takes the seat over, cloning the local parent; with
                // none, the seat goes to the join.
                if let Some(anchor) = view.boundary(child) {
                    if tail.next_height() >= anchor.height {
                        duty.phase = ObserverPhase::FetchingTerminal {
                            anchor,
                            ask: TerminalAsk::NOW,
                        };
                    } else {
                        tracing::info!(
                            ?child,
                            followed_to = tail.next_height().inner(),
                            anchor_height = anchor.height.inner(),
                            "split child anchored before the follow reached the parent's \
                             terminal; relinquishing the observer's seat"
                        );
                        duty.phase = ObserverPhase::Relinquished;
                    }
                    return;
                }
                // Assert ready to the splitting parent's committee until the
                // beacon credits the seat. Every co-hosted seat for this child
                // asserts its own signal, on its own schedule.
                if let Some(anchor) = view.boundary(duty.parent) {
                    for &validator in &duty.validators {
                        if view.observer_ready(duty.parent, validator) {
                            // The gate has banked this seat's readiness; a
                            // further signal cannot change the count.
                            duty.ready_asserts.remove(&validator);
                            continue;
                        }
                        let recipients = recipients_for(view, duty.parent, validator);
                        let slot = duty.ready_asserts.entry(validator).or_default();
                        if !ReadyAssert::should_assert(
                            slot,
                            anchor.weighted_timestamp,
                            &recipients,
                            now,
                        ) {
                            continue;
                        }
                        out.push(ReshapeRequest::BroadcastReady {
                            validator,
                            child: duty.child,
                            anchor,
                            recipients,
                        });
                    }
                }
                if let Some(request) = tail.next_request(now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: duty.parent,
                        kind: FetchKind::Block { request },
                    });
                }
                if let Some(block) = tail.take_apply() {
                    derive_block_transactions(&block, derivation);
                    let creations = committed_cells_for(&block);
                    let frontier = FrontierInputs::of_block(&block, view.schedule().windows());
                    out.push(ReshapeRequest::ApplyFollow {
                        shard: child,
                        block,
                        creations,
                        frontier,
                    });
                }
            }
            ObserverPhase::FetchingTerminal { anchor, ask } => {
                // The terminal is the parent's tip, which its members serve
                // until the children go live and they leave it; from then a
                // child member that flipped holds it, as the block its
                // genesis follows. Neither alone holds it throughout, so each
                // round asks both and the first answer that derives the
                // genesis takes it.
                if ask.begin(now) {
                    let request = split_terminal_request(view, duty.parent, anchor);
                    for from in [duty.parent, child] {
                        out.push(ReshapeRequest::Fetch {
                            duty: child,
                            from,
                            kind: FetchKind::Block {
                                request: request.clone(),
                            },
                        });
                    }
                }
            }
            ObserverPhase::Adopting { .. } => {
                if let ObserverPhase::Adopting {
                    origin,
                    genesis,
                    predecessors,
                } = std::mem::replace(&mut duty.phase, ObserverPhase::AwaitingAdopt)
                {
                    out.push(ReshapeRequest::Adopt {
                        shard: child,
                        kind: AdoptKind::Split,
                        origin,
                        genesis,
                        predecessors,
                    });
                }
            }
            ObserverPhase::AwaitingAdopt | ObserverPhase::Seated | ObserverPhase::Relinquished => {}
            ObserverPhase::Prepared => {
                if duty
                    .validators
                    .iter()
                    .any(|validator| view.committee(child).contains(validator))
                {
                    out.push(ReshapeRequest::Seat { shard: child });
                    duty.phase = ObserverPhase::Seated;
                }
            }
        }
    }

    /// Open a keeper duty for every cohort seat this host holds, accumulating
    /// the members it runs for each merging parent.
    fn discover_keeper_duties(&mut self, view: &ReshapeView) {
        for (&child, cohort) in view.keeper_cohorts() {
            for (&validator, seat) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let parent = seat.shard;
                let duty = self.keepers.entry(parent).or_insert_with(|| KeeperDuty {
                    members: Vec::new(),
                    phase: KeeperPhase::ReassertingReady,
                    open_requested: false,
                    store_opened: false,
                    pending_stage: Vec::new(),
                    stages_unacked: 0,
                });
                if !duty
                    .members
                    .iter()
                    .any(|m| m.validator == validator && m.own_child == child)
                {
                    duty.members.push(KeeperMember {
                        validator,
                        own_child: child,
                        ready_assert: None,
                    });
                }
            }
        }
    }

    /// Advance one keeper duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over KeeperPhase
    fn advance_keeper(
        &mut self,
        parent: ShardId,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let Some(duty) = self.keepers.get_mut(&parent) else {
            return;
        };
        match &mut duty.phase {
            KeeperPhase::ReassertingReady => {
                let (left, right) = parent.children();
                // With both cuts scheduled a window ahead, the children's own
                // chains say which of their blocks end them — no need to wait
                // for the beacon to compose the parent's anchor. Only when
                // genuinely early: once that anchor projects the children have
                // terminated and may already have dissolved, so a walk of
                // their chains would never resolve.
                if !view.merge_composed(parent)
                    && view.terminal_cut(left).is_some()
                    && view.terminal_cut(right).is_some()
                    && let Some(left_anchor) = view.boundary(left)
                    && let Some(right_anchor) = view.boundary(right)
                {
                    duty.phase = KeeperPhase::Recognizing {
                        left: Box::new(KeeperRecognition {
                            child: left,
                            tail: Box::new(ObserverTail::recognizing(left_anchor, left)),
                            proven: None,
                        }),
                        right: Box::new(KeeperRecognition {
                            child: right,
                            tail: Box::new(ObserverTail::recognizing(right_anchor, right)),
                            proven: None,
                        }),
                    };
                    return;
                }
                // Fallback: build once the merge has executed — the beacon
                // seated a live committee on the reformed parent and composed
                // its anchor. A bare `boundary(parent)` would also match the
                // parent's own pre-merge terminal record (a grow-then-merge
                // reforms a shard that split earlier), firing the build against
                // the wrong anchor and quitting the ready re-assert before the
                // gate fires.
                if view.merge_composed(parent)
                    && let Some(parent_anchor) = view.boundary(parent)
                    && let Some(left_anchor) = view.boundary(left)
                    && let Some(right_anchor) = view.boundary(right)
                {
                    duty.phase = KeeperPhase::Building {
                        cut_wt: parent_anchor.weighted_timestamp,
                        // The fallback holds the composed anchor, so the
                        // derivation is checked against it. The cut-over path
                        // below has none yet — its guard is the pair of
                        // commitment proofs it built the terminals from.
                        anchor: Some(Box::new(parent_anchor)),
                        left: Box::new(KeeperHalf::new(left, left_anchor)),
                        right: Box::new(KeeperHalf::new(right, right_anchor)),
                        derived: None,
                        finalize_requested: false,
                    };
                    return;
                }
                for member in &mut duty.members {
                    let Some(anchor) = view.boundary(member.own_child) else {
                        continue;
                    };
                    if view.keeper_ready(member.own_child, member.validator) {
                        // Credited: the merge gate has this seat's readiness.
                        member.ready_assert = None;
                        continue;
                    }
                    let recipients = recipients_for(view, member.own_child, member.validator);
                    if !ReadyAssert::should_assert(
                        &mut member.ready_assert,
                        anchor.weighted_timestamp,
                        &recipients,
                        now,
                    ) {
                        continue;
                    }
                    out.push(ReshapeRequest::BroadcastReady {
                        validator: member.validator,
                        child: member.own_child,
                        anchor,
                        recipients,
                    });
                }
            }
            KeeperPhase::Recognizing { left, right } => {
                for half in [&mut *left, &mut *right] {
                    if half.proven.is_some() {
                        continue;
                    }
                    half.tail.set_terminal_cut(view.terminal_cut(half.child));
                    let check = half
                        .tail
                        .settled_terminal()
                        .map(|sighting| terminal_commit(half.child, sighting, verifier, view));
                    if matches!(check, Some(TwoChainCheck::Refuted(_))) {
                        half.tail.restart();
                        half.tail.defer(now.plus(REFETCH_WAIT));
                    }
                    if check == Some(TwoChainCheck::Verified) {
                        half.proven = half.tail.settled_terminal().cloned();
                    } else if let Some(request) = half.tail.next_header_request(half.child, now) {
                        out.push(ReshapeRequest::Fetch {
                            duty: parent,
                            from: half.child,
                            kind: FetchKind::Headers { request },
                        });
                    }
                }
                // Both children's terminals are commit-proven, so the merged
                // root composes from a pair neither chain can have forged.
                // Both terminate on one cut — a merge stamps its two children
                // in a single step — so either child's resolves it. Read from
                // the tail's latch, not the projection: the applying fold has
                // consumed the record by the time both walks finish, so the
                // view no longer names the cut this parent's clock anchors at.
                if let (Some(left_sighting), Some(right_sighting)) = (&left.proven, &right.proven)
                    && let Some(cut_wt) = left.tail.terminal_cut()
                {
                    tracing::info!(
                        ?parent,
                        left_terminal = left_sighting.header.height().inner(),
                        right_terminal = right_sighting.header.height().inner(),
                        "reforming the merged parent from both children's own chains"
                    );
                    duty.phase = KeeperPhase::Building {
                        cut_wt,
                        anchor: None,
                        left: Box::new(KeeperHalf::recognized(left.child, left_sighting)),
                        right: Box::new(KeeperHalf::recognized(right.child, right_sighting)),
                        derived: None,
                        finalize_requested: false,
                    };
                } else if view.merge_composed(parent) {
                    // The walk ran out of time: the beacon has composed the
                    // parent's anchor, so the children have terminated and may
                    // already have dissolved — nothing further will arrive to
                    // prove. Hand back to the re-assert, whose compose branch
                    // builds against that anchor.
                    tracing::debug!(
                        ?parent,
                        "merge terminal walk did not resolve before the parent composed; \
                         falling back to the attested anchor"
                    );
                    duty.phase = KeeperPhase::ReassertingReady;
                }
            }
            KeeperPhase::Building {
                cut_wt,
                anchor,
                left,
                right,
                derived,
                finalize_requested,
            } => {
                if !duty.open_requested {
                    out.push(ReshapeRequest::OpenStore { shard: parent });
                    duty.open_requested = true;
                }
                for (progress, leaves) in duty.pending_stage.drain(..) {
                    duty.stages_unacked += 1;
                    out.push(ReshapeRequest::StageChunk {
                        shard: parent,
                        progress,
                        leaves,
                    });
                }
                // The halves stage straight into the parent store, so their
                // fetches wait for it to open.
                if duty.store_opened {
                    advance_keeper_half(left, parent, view, now, out);
                    advance_keeper_half(right, parent, view, now, out);
                }
                if derived.is_none()
                    && let (Some((left_h, left_qc)), Some((right_h, right_qc))) =
                        (&left.terminal, &right.terminal)
                    && let Ok((genesis, origin, predecessors)) = merge_genesis_from_terminals(
                        parent,
                        (left_h, left_qc),
                        (right_h, right_qc),
                        *cut_wt,
                    )
                    // On the fallback the beacon has already composed this
                    // parent, so the derivation is checked against it —
                    // agreement is free, and disagreement means the local
                    // child chains and the network disagree about a committed
                    // block.
                    && anchor.as_deref().is_none_or(|a| {
                        let matches = genesis.hash() == a.block_hash;
                        if !matches {
                            tracing::error!(
                                ?parent,
                                derived = ?genesis.hash(),
                                anchored = ?a.block_hash,
                                "derived merged-parent genesis does not reconstruct \
                                 the beacon anchor"
                            );
                        }
                        matches
                    })
                {
                    *derived = Some((origin, Box::new(genesis), predecessors));
                }
                if !*finalize_requested
                    && duty.stages_unacked == 0
                    && left.bootstrap.is_staged()
                    && right.bootstrap.is_staged()
                    && let Some((origin, _, _)) = derived.as_ref()
                {
                    out.push(ReshapeRequest::FinalizeImport {
                        shard: parent,
                        height: origin.genesis_height,
                    });
                    *finalize_requested = true;
                }
            }
            KeeperPhase::Adopting { .. } => {
                if let KeeperPhase::Adopting {
                    origin,
                    genesis,
                    predecessors,
                } = std::mem::replace(&mut duty.phase, KeeperPhase::AwaitingAdopt)
                {
                    out.push(ReshapeRequest::Adopt {
                        shard: parent,
                        kind: AdoptKind::Merge,
                        origin,
                        genesis,
                        predecessors,
                    });
                }
            }
            KeeperPhase::AwaitingAdopt => {}
            KeeperPhase::Prepared => {
                if duty
                    .members
                    .iter()
                    .any(|m| view.committee(parent).contains(&m.validator))
                {
                    out.push(ReshapeRequest::Seat { shard: parent });
                    self.keepers.remove(&parent);
                }
            }
        }
    }

    /// Open a parent-half duty for every cohort seat this host holds that it
    /// isn't already running. A child already covered by an observer duty is
    /// left to it — the observer's seat installs every homed committee member,
    /// the parent halves among them — until the observer relinquishes. Then
    /// the parent half seeds the child from the host's own parent chain: the
    /// join that takes a relinquished seat snap-syncs from the child's
    /// committee, and when every host on that committee relinquished, none
    /// of them serves it.
    fn discover_parent_half_duties(&mut self, view: &ReshapeView) {
        for (&child, cohort) in view.parent_half_cohorts() {
            if self
                .observers
                .get(&child)
                .is_some_and(|duty| !matches!(duty.phase, ObserverPhase::Relinquished))
            {
                continue;
            }
            for (&validator, &parent) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let duty = self
                    .parent_halves
                    .entry(child)
                    .or_insert_with(|| ParentHalfDuty {
                        parent,
                        validators: Vec::new(),
                        phase: ParentHalfPhase::Seeding { requested: false },
                        store_seeded: false,
                    });
                if !duty.validators.contains(&validator) {
                    duty.validators.push(validator);
                }
            }
        }
    }

    /// Advance one parent-half duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over ParentHalfPhase
    fn advance_parent_half(
        &mut self,
        child: ShardId,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let Some(duty) = self.parent_halves.get_mut(&child) else {
            return;
        };
        let parent = duty.parent;
        let store_seeded = duty.store_seeded;
        let mut next: Option<ParentHalfPhase> = None;
        match &mut duty.phase {
            ParentHalfPhase::Seeding { requested } => {
                // With the cut scheduled a window ahead, the parent's own
                // chain says which of its blocks is the terminal — no need
                // to wait for the beacon to publish the child's anchor.
                // Only when genuinely early: once the child's anchor
                // projects, the parent has terminated and may already have
                // dissolved, so a walk of its chain would never resolve.
                // Late-discovered duties take the anchor path below.
                if !*requested
                    && view.boundary(child).is_none()
                    && view.terminal_cut(parent).is_some()
                    && let Some(parent_anchor) = view.boundary(parent)
                {
                    next = Some(ParentHalfPhase::Recognizing(Box::new(
                        ObserverTail::recognizing(parent_anchor, child),
                    )));
                }
                // Fallback: the child anchor seeds once the parent's terminal
                // folds; it is the version the clone must reach and the
                // derivation verifies against.
                else if let Some(anchor) = view.boundary(child) {
                    if anchor_past_genesis(view, parent, &anchor) {
                        // The child crossed since its genesis, so its anchor
                        // names a block of the child's own chain: no clone of
                        // the parent reaches it, and no genesis derived from the
                        // parent's terminal reconstructs it. The seat is the
                        // join's, which snap-syncs against that anchor.
                        tracing::info!(
                            ?child,
                            anchor_height = anchor.height.inner(),
                            "split child anchored past its genesis; relinquishing the parent half's seat"
                        );
                        next = Some(ParentHalfPhase::Relinquished);
                    } else if store_seeded {
                        next = Some(ParentHalfPhase::FetchingTerminal {
                            anchor,
                            ask: TerminalAsk::NOW,
                        });
                    } else if !*requested {
                        out.push(ReshapeRequest::SeedFromParent {
                            parent,
                            child,
                            through: anchor.height,
                        });
                        *requested = true;
                    }
                }
            }
            ParentHalfPhase::Recognizing(tail) => {
                tail.set_terminal_cut(view.terminal_cut(parent));
                let check = tail
                    .settled_terminal()
                    .map(|sighting| terminal_commit(parent, sighting, verifier, view));
                if matches!(check, Some(TwoChainCheck::Refuted(_))) {
                    tail.restart();
                    tail.defer(now.plus(REFETCH_WAIT));
                }
                if check == Some(TwoChainCheck::Verified)
                    && let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                {
                    tracing::info!(
                        ?child,
                        terminal_height = sighting.header.height().inner(),
                        "seating the split child's parent half from the local parent chain"
                    );
                    next = Some(ParentHalfPhase::SeedingAt {
                        origin: derived.origin,
                        genesis: Box::new(derived.block.clone()),
                        predecessors: derived.predecessor.into_iter().collect(),
                        requested: false,
                    });
                } else if view.boundary(child).is_some() {
                    // The walk ran out of time: the beacon published the
                    // child's anchor, so the parent has terminated and may
                    // already have dissolved — nothing further will arrive to
                    // prove. Hand back to the seed, whose anchor branch clones
                    // the local parent against that height.
                    tracing::debug!(
                        ?child,
                        "parent terminal walk did not resolve before the child anchored; \
                         falling back to the attested anchor"
                    );
                    next = Some(ParentHalfPhase::Seeding { requested: false });
                } else if let Some(request) = tail.next_header_request(parent, now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Headers { request },
                    });
                }
            }
            ParentHalfPhase::SeedingAt {
                origin,
                genesis,
                predecessors,
                requested,
            } => {
                if store_seeded {
                    next = Some(ParentHalfPhase::Adopting {
                        origin: *origin,
                        genesis: genesis.clone(),
                        predecessors: predecessors.clone(),
                    });
                } else if !*requested {
                    out.push(ReshapeRequest::SeedFromParent {
                        parent,
                        child,
                        through: origin.genesis_height,
                    });
                    *requested = true;
                }
            }
            ParentHalfPhase::FetchingTerminal { anchor, ask } => {
                // The seed gates on the local parent reaching the terminal, so
                // the host's own retained chain serves the certified terminal.
                if ask.begin(now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Block {
                            request: split_terminal_request(view, parent, anchor),
                        },
                    });
                }
            }
            ParentHalfPhase::Adopting { .. } => {
                if let ParentHalfPhase::Adopting {
                    origin,
                    genesis,
                    predecessors,
                } = std::mem::replace(&mut duty.phase, ParentHalfPhase::AwaitingAdopt)
                {
                    out.push(ReshapeRequest::Adopt {
                        shard: child,
                        kind: AdoptKind::ParentHalf,
                        origin,
                        genesis,
                        predecessors,
                    });
                }
            }
            ParentHalfPhase::AwaitingAdopt
            | ParentHalfPhase::Seated
            | ParentHalfPhase::Relinquished => {}
            ParentHalfPhase::Prepared => {
                if duty
                    .validators
                    .iter()
                    .any(|validator| view.committee(child).contains(validator))
                {
                    out.push(ReshapeRequest::Seat { shard: child });
                    duty.phase = ParentHalfPhase::Seated;
                }
            }
        }
        if let Some(phase) = next {
            duty.phase = phase;
        }
    }
}

/// Whether a split child's attested `anchor` sits past its genesis: the
/// parent's terminal record names the terminal, and the child's genesis is
/// the block above it. Without that record nothing places the genesis,
/// and the anchor is taken to be it.
fn anchor_past_genesis(view: &ReshapeView, parent: ShardId, anchor: &ShardAnchor) -> bool {
    view.boundary(parent).is_some_and(|record| {
        record.terminal_epoch.is_some() && anchor.height > record.height.next()
    })
}

/// The fetch for a split parent's certified terminal, the block just
/// below the child's seeded genesis.
///
/// The fold that seeds the child's anchor from the terminal contribution
/// records that same crossing as the parent's boundary, so while the
/// parent's record stands at the terminal's height it names the block: a
/// certified sibling at the height does not answer. A record at any other
/// height is not this crossing, and the request asks by height alone.
fn split_terminal_request(
    view: &ReshapeView,
    parent: ShardId,
    child_anchor: &ShardAnchor,
) -> GetBlockRequest {
    let terminal = child_anchor.height.prev().unwrap_or(child_anchor.height);
    let request = GetBlockRequest::new(terminal, BlockIntent::Execute);
    match view.boundary(parent) {
        Some(record) if record.height == terminal && record.terminal_epoch.is_some() => {
            request.naming(record.block_hash)
        }
        _ => request,
    }
}

/// Derive a successor's genesis on the anchor fallback path, checking it
/// against the anchor the beacon attested.
///
/// The derivation is shared with the cut-over flip and the beacon fold, so
/// it takes no anchor. This path holds one, so it compares: agreement is
/// free, and disagreement means the local parent chain and the network
/// disagree about a committed block. The cut-over flip has no anchor to
/// compare against yet — its guard is the commitment proof at the front.
fn anchored_split_genesis(
    child: ShardId,
    terminal: &BlockHeader,
    qc: &QuorumCertificate,
    anchor: &ShardAnchor,
) -> Option<(Block, ChainOrigin, Option<Anchor>)> {
    let (genesis, origin) = split_genesis_from_terminal(child, terminal, qc)
        .inspect_err(|error| {
            tracing::warn!(?child, %error, "split child genesis derivation failed");
        })
        .ok()?;
    if genesis.hash() != anchor.block_hash {
        tracing::error!(
            ?child,
            derived = ?genesis.hash(),
            anchored = ?anchor.block_hash,
            "derived split-child genesis does not reconstruct the beacon anchor"
        );
        return None;
    }
    Some((genesis, origin, terminal.as_terminal_anchor()))
}

/// Whether a recognizing walk's terminal of `shard` is commit-proven — the
/// gate its flip keys on.
///
/// Two QCs can exist at one height; two commits cannot. Certification
/// alone would let a superseded block seed the successor. Each QC of the
/// proof verifies against `shard`'s committee for its own window, as the
/// schedule resolves it, so the serving peer is trusted for availability
/// alone: the walk's headers below the terminal are pinned by hash to it,
/// and nothing the flip derives reads the block the walk passed it by.
///
/// `Pending` while no round-contiguous pair has formed yet, or its window
/// is above what this host's beacon has folded.
fn terminal_commit(
    shard: ShardId,
    sighting: &TerminalSighting,
    verifier: &dyn Verifier,
    view: &ReshapeView,
) -> TwoChainCheck {
    let height = sighting.header.height().inner();
    let Some(terminal_proof) = &sighting.commit_proof else {
        return TwoChainCheck::Pending;
    };
    // What the proof commits must be the block the genesis derives from.
    // A prefix proof's two-chain sits above the terminal, so the link's
    // foot is the only thing tying it back down; checked before the
    // signature work, which is the expensive half.
    let check = if terminal_proof.proof.proven_block_hash() == sighting.header.hash() {
        terminal_proof.check(verifier, view.network(), |anchor_wt, qc_wt| {
            view.certifying_committee(shard, anchor_wt, qc_wt)
        })
    } else {
        TwoChainCheck::Refuted("the commit proof commits a block other than the terminal")
    };
    if let TwoChainCheck::Refuted(reason) = check {
        tracing::warn!(
            ?shard,
            height,
            reason,
            "refused the terminal's commit proof; walking again from the anchor"
        );
    }
    check
}

/// A ready signal's recipients — `shard`'s committee minus the signer.
fn recipients_for(view: &ReshapeView, shard: ShardId, validator: ValidatorId) -> Vec<ValidatorId> {
    view.committee(shard)
        .iter()
        .copied()
        .filter(|&v| v != validator)
        .collect()
}

/// Advance one keeper half: forward its snap-sync state ranges (each
/// verified chunk stages into the parent store through the duty's
/// queue), and fetch its certified terminal until it arrives.
fn advance_keeper_half(
    half: &mut KeeperHalf,
    duty: ShardId,
    view: &ReshapeView,
    now: LocalTimestamp,
    out: &mut Vec<ReshapeRequest>,
) {
    for request in half.bootstrap.next_requests() {
        // The half collect only assembles state, so only state ranges appear.
        let BootstrapRequest::StateRange(sub_range, request) = request else {
            continue;
        };
        out.push(ReshapeRequest::Fetch {
            duty,
            from: half.child,
            kind: FetchKind::StateRange { sub_range, request },
        });
    }
    if half.terminal.is_none()
        && let Some(anchor) = view.boundary(half.child)
        && half.terminal_ask.begin(now)
    {
        // A merging child's boundary anchors its terminal crossing directly —
        // the block whose hash and height the beacon composed the parent from —
        // so the certified terminal sits at the anchor height itself, and is
        // the anchored block: a certified sibling at that height does not
        // answer.
        let terminal = anchor.height;
        out.push(ReshapeRequest::Fetch {
            duty,
            from: half.child,
            kind: FetchKind::Block {
                request: GetBlockRequest::new(terminal, BlockIntent::Execute)
                    .naming(anchor.block_hash),
            },
        });
        half.terminal_requested = Some(anchor.block_hash);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_storage::test_helpers::{
        make_test_block, make_test_block_with_anchor_wt, make_test_certified,
    };
    use hyperscale_types::network::request::GetBlockRequest;
    use hyperscale_types::network::response::{GetBlockResponse, GetRemoteHeadersResponse};
    use hyperscale_types::test_utils::{
        StubVmStatics, TestCommittee, install_stub_protocol_statics, signed_child_block,
        signed_split_terminal, stub_transaction, test_key,
    };
    use hyperscale_types::{
        BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, CertifiedBlockHeader,
        ElidedCertifiedBlock, Epoch, Hash, Inventory, LocalTimestamp, NetworkDefinition,
        PrincipalAddr, ReshapeSeat, Round, ShardAnchor, ShardId, Signer, SplitChildRoots,
        StateRoot, TimestampRange, TopologySchedule, TopologySnapshot, Transaction, ValidatorId,
        ValidatorInfo, ValidatorSet, Verifiable, WeightedTimestamp,
    };

    use super::{
        FetchKind, FetchedKind, KeeperDuty, KeeperMember, KeeperPhase, KeeperRecognition,
        ObserverDuty, ObserverPhase, ParentHalfDuty, ParentHalfPhase, REFETCH_WAIT, ReshapeEvent,
        ReshapeOrchestrator, ReshapeRequest, TerminalAsk, split_terminal_request,
    };
    use crate::reshape::observer::{ObserverBootstrap, ObserverTail};
    use crate::reshape::view::ReshapeView;

    fn vid(id: u64) -> ValidatorId {
        ValidatorId::new(id)
    }

    /// The orchestrator's local clock at `ms`. Only the ready-assertion
    /// schedule reads it; every other step is clock independent, so tests
    /// that aren't about pacing pump at a fixed instant.
    fn at(ms: u64) -> LocalTimestamp {
        LocalTimestamp::from_millis(ms)
    }

    /// A non-zero anchor whose `prev` height is a valid terminal.
    fn anchor() -> ShardAnchor {
        anchor_at(WeightedTimestamp::ZERO)
    }

    /// [`anchor`] windowed at `wt` — the value a ready signal cuts its
    /// validity window from, and so what distinguishes one assertion from
    /// a re-assertion of the same thing.
    fn anchor_at(wt: WeightedTimestamp) -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
            height: BlockHeight::new(8),
            weighted_timestamp: wt,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        }
    }

    /// A schedule headed by `snapshot`, cut into one-second windows.
    fn windowed(snapshot: &TopologySnapshot) -> TopologySchedule {
        TopologySchedule::new(1_000, Epoch::GENESIS, Arc::new(snapshot.clone()))
    }

    /// Project a snapshot with the given committees, observer cohort seats
    /// `(parent, validator, child)` none of which the beacon has credited,
    /// and seeded boundaries.
    fn snapshot(
        committees: &[(ShardId, &[u64])],
        cohort: &[(ShardId, u64, ShardId)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        snapshot_with_ready(committees, &uncredited(cohort), seeded)
    }

    /// [`snapshot`] with each observer seat's credited readiness spelled
    /// out: `(parent, validator, child, ready)`.
    fn snapshot_with_ready(
        committees: &[(ShardId, &[u64])],
        cohort: &[(ShardId, u64, ShardId, bool)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        build(committees, cohort, &[], &[], seeded, anchor())
    }

    /// Project a snapshot with keeper cohort seats `(child, validator, parent)`.
    fn snapshot_keepers(
        committees: &[(ShardId, &[u64])],
        keepers: &[(ShardId, u64, ShardId)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        snapshot_keepers_with_ready(committees, &uncredited(keepers), seeded)
    }

    /// [`snapshot_keepers`] with each keeper seat's credited readiness
    /// spelled out: `(child, validator, parent, ready)`.
    fn snapshot_keepers_with_ready(
        committees: &[(ShardId, &[u64])],
        keepers: &[(ShardId, u64, ShardId, bool)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        build(committees, &[], keepers, &[], seeded, anchor())
    }

    /// Seat triples as the beacon projects them before any `ReshapeReady`
    /// has folded.
    fn uncredited(seats: &[(ShardId, u64, ShardId)]) -> Vec<(ShardId, u64, ShardId, bool)> {
        seats.iter().map(|&(a, v, b)| (a, v, b, false)).collect()
    }

    /// Project a snapshot with parent-half cohort seats `(child, validator,
    /// parent)`.
    fn snapshot_parent_halves(
        committees: &[(ShardId, &[u64])],
        parent_halves: &[(ShardId, u64, ShardId)],
        seeded: &[ShardId],
    ) -> TopologySnapshot {
        build(committees, &[], &[], parent_halves, seeded, anchor())
    }

    fn build(
        committees: &[(ShardId, &[u64])],
        observers: &[(ShardId, u64, ShardId, bool)],
        keepers: &[(ShardId, u64, ShardId, bool)],
        parent_halves: &[(ShardId, u64, ShardId)],
        seeded: &[ShardId],
        boundary: ShardAnchor,
    ) -> TopologySnapshot {
        let mut ids: BTreeSet<u64> = BTreeSet::new();
        for (_, members) in committees {
            ids.extend(members.iter().copied());
        }
        for (_, v, _, _) in observers.iter().chain(keepers) {
            ids.insert(*v);
        }
        for (_, v, _) in parent_halves {
            ids.insert(*v);
        }
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| ValidatorInfo {
                validator_id: vid(id),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let committee_map: HashMap<ShardId, Vec<ValidatorId>> = committees
            .iter()
            .map(|(s, members)| (*s, members.iter().map(|&m| vid(m)).collect()))
            .collect();
        let mut observer_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> =
            BTreeMap::new();
        for (parent, v, child, ready) in observers {
            observer_cohorts.entry(*parent).or_default().insert(
                vid(*v),
                ReshapeSeat {
                    shard: *child,
                    ready: *ready,
                },
            );
        }
        let mut keeper_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> =
            BTreeMap::new();
        for (child, v, parent, ready) in keepers {
            keeper_cohorts.entry(*child).or_default().insert(
                vid(*v),
                ReshapeSeat {
                    shard: *parent,
                    ready: *ready,
                },
            );
        }
        let mut parent_half_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> =
            BTreeMap::new();
        for (child, v, parent) in parent_halves {
            parent_half_cohorts
                .entry(*child)
                .or_default()
                .insert(vid(*v), *parent);
        }
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committee_map.clone(),
            committee_map,
            seeded.iter().map(|&s| (s, boundary)).collect(),
            HashMap::new(),
            observer_cohorts,
            keeper_cohorts,
            parent_half_cohorts,
            BTreeSet::new(),
        )
    }

    fn observer_duty(
        parent: ShardId,
        child: ShardId,
        validator: u64,
        phase: ObserverPhase,
    ) -> ObserverDuty {
        ObserverDuty {
            parent,
            child,
            validators: vec![vid(validator)],
            phase,
            open_requested: true,
            store_opened: true,
            pending_stage: Vec::new(),
            stages_unacked: 0,
            adopted_genesis: None,
            ready_asserts: BTreeMap::new(),
        }
    }

    fn following(tail: ObserverTail) -> ObserverPhase {
        ObserverPhase::Following(Box::new(tail))
    }

    /// The block fetch in `requests`, if any.
    fn follow_fetch(requests: &[ReshapeRequest]) -> Option<BlockHeight> {
        requests.iter().find_map(|r| match r {
            ReshapeRequest::Fetch {
                kind: FetchKind::Block { request },
                ..
            } => Some(request.height),
            _ => None,
        })
    }

    /// The blocks `requests` asks the store to apply.
    fn follow_applies(requests: &[ReshapeRequest]) -> Vec<BlockHash> {
        requests
            .iter()
            .filter_map(|r| match r {
                ReshapeRequest::ApplyFollow { block, .. } => Some(block.hash()),
                _ => None,
            })
            .collect()
    }

    /// A one-window schedule seating `committee` on `shard`. Every stamp a
    /// test signs below one second sits inside that window.
    fn committee_schedule(shard: ShardId, committee: &TestCommittee) -> TopologySchedule {
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        let members: Vec<ValidatorId> = committee.validator_ids().to_vec();
        let snap = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            HashMap::from([(shard, members.clone())]),
            HashMap::from([(shard, members)]),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        windowed(&snap)
    }

    /// An unsigned block at height 1 and the attested anchor naming it.
    fn anchored_block() -> (Block, ShardAnchor) {
        let block = make_test_block(BlockHeight::new(1));
        let anchor = ShardAnchor {
            block_hash: block.hash(),
            height: BlockHeight::new(1),
            ..anchor()
        };
        (block, anchor)
    }

    fn refetch_ms() -> u64 {
        u64::try_from(REFETCH_WAIT.as_millis()).expect("fits")
    }

    /// An observer following a parent whose committee is `committee`,
    /// driven end to end through the orchestrator: a losing sibling a peer
    /// serves is held unproven and never applied, the answer that
    /// contradicts it holds the next fetch back by the refetch wait, and
    /// the committed chain is applied once each block's two-chain verifies
    /// against the committee the schedule resolves.
    #[test]
    fn a_follower_applies_only_what_the_parent_committee_proves() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee);
        let view = ReshapeView::new(&schedule);

        let wt = WeightedTimestamp::from_millis;
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(&committee, &anchor_block, Round::new(2), wt(100));
        let sibling = signed_child_block(&committee, &anchor_block, Round::new(3), wt(150));
        let b3 = signed_child_block(&committee, &b2, Round::new(3), wt(200));
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    committee.sign_qc(block.header(), &committee.quorum_indices(), wt(900)),
                    &Inventory::empty(),
                ))),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );

        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&sibling)],
            at(0),
        );
        assert_eq!(
            follow_fetch(&requests),
            Some(BlockHeight::new(3)),
            "the follow fetches ahead of what it can prove",
        );
        assert!(follow_applies(&requests).is_empty());

        // The committed chain's next block contradicts the sibling.
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(0),
        );
        assert!(follow_applies(&requests).is_empty());
        assert_eq!(
            follow_fetch(&requests),
            None,
            "a refused answer holds the next fetch back"
        );
        let refetch = refetch_ms();
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b2)],
            at(refetch),
        );
        assert!(follow_applies(&requests).is_empty());
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(refetch),
        );
        assert_eq!(
            follow_applies(&requests),
            vec![b2.hash()],
            "the committed block is applied once its two-chain verifies",
        );
    }

    /// A transaction a block carries as decoded, with nothing derived.
    fn carrying_an_underived_transaction(block: Block) -> Block {
        install_stub_protocol_statics();
        let payer = PrincipalAddr::new([0x11; 31]);
        let routed = stub_transaction(
            payer,
            &[payer.address()],
            1_000,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        );
        let decoded = Transaction::new(routed.body().clone());
        assert!(!decoded.is_routed());
        let Block::Live {
            header,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            witness_sources,
            ..
        } = block
        else {
            unreachable!("the fixture builds a live block")
        };
        Block::Live {
            header,
            transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(decoded))])),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            tick_manifest,
            witness_sources,
        }
    }

    /// A follower applies a block whose transactions it fetched with
    /// nothing derived.
    ///
    /// A block a peer serves out of its store, or one decoded off the
    /// wire, carries no derivations: deriving is the receiving node's own
    /// answer. The committed cells the follow writes are each
    /// transaction's validity window, which only a derivation seats, so a
    /// follow that read them as the block came would panic.
    #[test]
    fn a_follower_derives_the_transactions_it_fetched() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee);
        let view = ReshapeView::new(&schedule);

        let wt = WeightedTimestamp::from_millis;
        let (anchor_block, anchor) = anchored_block();
        let b2 = carrying_an_underived_transaction(signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            wt(100),
        ));
        let b3 = signed_child_block(&committee, &b2, Round::new(3), wt(200));
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    committee.sign_qc(block.header(), &committee.quorum_indices(), wt(900)),
                    &Inventory::empty(),
                ))),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );

        orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b2)],
            at(0),
        );
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(0),
        );
        assert_eq!(
            follow_applies(&requests),
            vec![b2.hash()],
            "the fetched block is applied with its committed cells",
        );
    }

    /// A follow at the parent's tip asks for a height nothing holds yet.
    /// That answer holds the next ask back by the refetch wait rather than
    /// re-asking as fast as the peer replies, while an answer that delivers
    /// a block asks on at once.
    #[test]
    fn an_empty_answer_at_the_tip_defers_the_next_follow_fetch() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );
        let answer = |response: GetBlockResponse| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(response),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![answer(GetBlockResponse::not_found())],
            at(0),
        );
        assert_eq!(
            follow_fetch(&requests),
            None,
            "nothing at the tip holds the next ask back",
        );
        let refetch = refetch_ms();
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(refetch - 1),
        );
        assert_eq!(follow_fetch(&requests), None);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let found = GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &b2,
            committee.sign_qc(
                b2.header(),
                &committee.quorum_indices(),
                WeightedTimestamp::from_millis(900),
            ),
            &Inventory::empty(),
        ));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![answer(found)],
            at(refetch),
        );
        assert_eq!(
            follow_fetch(&requests),
            Some(BlockHeight::new(3)),
            "a delivered block asks on at once",
        );
    }

    /// A parent half recognizing `parent`'s terminal above `anchor`,
    /// the parent's cut published at 150ms.
    fn recognizing_parent_half(
        parent: ShardId,
        child: ShardId,
        anchor: ShardAnchor,
    ) -> ReshapeOrchestrator {
        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(150)));
        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        orch.parent_halves.insert(
            child,
            ParentHalfDuty {
                parent,
                validators: vec![vid(50)],
                phase: ParentHalfPhase::Recognizing(Box::new(tail)),
                store_seeded: false,
            },
        );
        orch
    }

    /// The headers answer a recognizing walk of `parent` takes, each
    /// header served with a quorum of `committee`'s QC over it.
    fn walked(
        child: ShardId,
        parent: ShardId,
        committee: &TestCommittee,
        blocks: &[&Block],
    ) -> ReshapeEvent {
        let headers = blocks
            .iter()
            .map(|block| {
                CertifiedBlockHeader::new(
                    block.header().clone(),
                    committee.sign_qc(
                        block.header(),
                        &committee.quorum_indices(),
                        WeightedTimestamp::from_millis(900),
                    ),
                )
            })
            .collect();
        ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Headers {
                response: Box::new(GetRemoteHeadersResponse::of(
                    Capped::new(headers).expect("within one request"),
                )),
            },
        }
    }

    /// The first height of each header fetch in `requests`.
    fn header_fetches_from(requests: &[ReshapeRequest]) -> Vec<BlockHeight> {
        requests
            .iter()
            .filter_map(|r| match r {
                ReshapeRequest::Fetch {
                    kind: FetchKind::Headers { request },
                    ..
                } => Some(request.from_height),
                _ => None,
            })
            .collect()
    }

    fn seeds_through(requests: &[ReshapeRequest]) -> Option<BlockHeight> {
        requests.iter().find_map(|r| match r {
            ReshapeRequest::SeedFromParent { through, .. } => Some(*through),
            _ => None,
        })
    }

    /// A parent half walks its parent's committed headers as a server
    /// hands them over, and seeds the child only from a terminal whose
    /// commit the parent committee's own QCs prove, each against the
    /// committee its window resolves. A successor the committee never
    /// certified leaves the walk unresolved, so the anchor path still
    /// covers it; the genuine successor seeds the child at the genesis
    /// height above the terminal.
    #[test]
    fn a_parent_half_seeds_only_from_a_terminal_its_committee_proves() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let impostors = TestCommittee::new(4, 99);
        let schedule = committee_schedule(parent, &committee);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let terminal = signed_split_terminal(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(200),
            pair,
        );
        let successor = signed_child_block(
            &committee,
            &terminal,
            Round::new(3),
            WeightedTimestamp::from_millis(300),
        );

        let mut orch = recognizing_parent_half(parent, child, anchor);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&terminal])],
            at(0),
        );
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(3)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &impostors, &[&successor])],
            at(0),
        );
        assert_eq!(seeds_through(&requests), None);
        assert!(
            header_fetches_from(&requests).is_empty(),
            "a refuted proof holds the walk back",
        );
        assert!(
            matches!(
                orch.parent_halves[&child].phase,
                ParentHalfPhase::Recognizing(_)
            ),
            "a successor the committee never certified proves nothing",
        );

        // The walk starts over above the anchor, where the committee's own
        // certificates prove the terminal.
        let refetch = refetch_ms();
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let _ = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&terminal, &successor])],
            at(refetch),
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(
            seeds_through(&requests),
            Some(terminal.height().next()),
            "a proven terminal seeds the child through its genesis height",
        );
    }

    /// A recognizing walk at its chain's tip gets an empty batch; the next
    /// ask waits out the refetch wait, and a batch that delivers headers
    /// asks on at once.
    #[test]
    fn an_empty_answer_at_the_tip_defers_the_next_walk_fetch() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );

        let mut orch = recognizing_parent_half(parent, child, anchor);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[])],
            at(0),
        );
        assert_eq!(
            header_fetches_from(&requests),
            Vec::new(),
            "an empty batch holds the next ask back",
        );
        let refetch = refetch_ms();
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(refetch - 1),
        );
        assert!(header_fetches_from(&requests).is_empty());
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&b2])],
            at(refetch),
        );
        assert_eq!(
            header_fetches_from(&requests),
            vec![BlockHeight::new(3)],
            "a delivered batch asks on at once"
        );
    }

    #[test]
    fn detects_a_cohort_seat_and_opens_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 5, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::OpenStore { shard }] if *shard == child),
            "a held cohort seat must open the child store; got {requests:?}",
        );
    }

    #[test]
    fn ignores_a_cohort_seat_this_host_does_not_hold() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 9, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        assert!(
            orch.step(
                &ReshapeView::new(&windowed(&snap)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0)
            )
            .is_empty()
        );
    }

    #[test]
    fn syncing_forwards_the_bootstrap_state_ranges() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 4])], &[], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(parent, anchor(), child))),
            ),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::Fetch { from, kind: FetchKind::StateRange { .. }, .. } if *from == parent
            )),
            "a syncing duty must forward the bootstrap's state ranges; got {requests:?}",
        );
    }

    #[test]
    fn a_failed_stage_re_queues_and_re_emits_the_chunk() {
        use hyperscale_storage::test_helpers::completed_import_progress;
        use hyperscale_types::SubstateLeaf;

        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 4])], &[], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let mut duty = observer_duty(
            parent,
            child,
            5,
            ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(parent, anchor(), child))),
        );
        let progress = completed_import_progress(BlockHeight::new(1), 0);
        let leaves = vec![SubstateLeaf {
            key: test_key(7u8),
            value: Bytes::from_array([7]),
        }];
        duty.pending_stage.push((progress.clone(), leaves.clone()));
        orch.observers.insert(child, duty);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::StageChunk { shard, .. } if *shard == child)),
            "a pending chunk must emit; got {requests:?}",
        );
        assert_eq!(orch.observers[&child].stages_unacked, 1);

        // The durable write failed: the chunk comes back and the same
        // step's advance re-emits it, leaving it unacked again — the
        // finalize gate stays closed until a Staged ack lands.
        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::StageFailed {
                shard: child,
                progress,
                leaves,
            }],
            at(0),
        );
        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::StageChunk { shard, .. } if *shard == child)),
            "a failed stage must re-emit its chunk; got {requests:?}",
        );
        let duty = &orch.observers[&child];
        assert_eq!(duty.stages_unacked, 1);
        assert!(duty.pending_stage.is_empty());
    }

    #[test]
    fn following_reasserts_ready_to_the_parent_committee() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::BroadcastReady { validator, recipients, .. }
                    if *validator == vid(5) && !recipients.contains(&vid(5)) && recipients.len() == 3
            )),
            "a following duty must re-assert ready to the parent committee minus self; got {requests:?}",
        );
    }

    /// An observer duty in `Following`, ready to assert against `parent`.
    fn following_observer(parent: ShardId, child: ShardId) -> ReshapeOrchestrator {
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );
        orch
    }

    /// Ready assertions carry a window cut from the parent's boundary anchor,
    /// so nothing new can be said until that anchor turns over. Pumping
    /// against one anchor must back off in real time rather than assert once
    /// per pump.
    #[test]
    fn ready_assertions_back_off_within_one_anchor_window() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[], &[parent]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = following_observer(parent, child);

        // A minute of pumping at the production tick's cadence.
        let asserts = (0..60_000)
            .step_by(1_000)
            .filter(|&ms| {
                orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(ms))
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. }))
            })
            .count();

        // Geometric backoff to the ceiling: assertions at 0, 1, 3 and 7
        // seconds, then every four — seventeen inside the minute, against the
        // sixty a per-pump assertion would cost.
        assert_eq!(
            asserts, 17,
            "one anchor window must cost a bounded number of assertions",
        );
    }

    /// The pump rate must not change the assertion rate: the simulation drives
    /// the orchestrator to a fixpoint, so a schedule counting steps rather
    /// than time would burn a whole window's backoff inside one slice and go
    /// quiet — a divergence between the harnesses that only shows up as a
    /// stalled reshape.
    #[test]
    fn pumping_without_the_clock_advancing_asserts_once() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[], &[parent]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = following_observer(parent, child);

        let asserts = (0..64)
            .filter(|_| {
                orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(5_000))
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. }))
            })
            .count();

        assert_eq!(
            asserts, 1,
            "a fixpoint that passes no time must cost exactly one assertion",
        );
    }

    /// A fresh anchor window is a genuinely new signal — the previous one is
    /// on its way to expiring — so the backoff restarts and the duty asserts
    /// immediately rather than waiting out the old schedule.
    #[test]
    fn a_new_anchor_window_re_arms_the_assertion() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[], &[parent]);
        let mut orch = following_observer(parent, child);

        // Run the first window out to where it has backed off well past the
        // tick.
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        for ms in (0..60_000).step_by(1_000) {
            let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(ms));
        }
        assert!(
            !orch
                .step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(60_000))
                .iter()
                .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
            "the window must be deep into its backoff",
        );

        let rolled = build(
            &[(parent, &[1, 2, 3, 5])],
            &[],
            &[],
            &[],
            &[parent],
            anchor_at(WeightedTimestamp::from_millis(30_000)),
        );
        let requests = orch.step(
            &ReshapeView::new(&windowed(&rolled)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(60_000),
        );

        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
            "a rolled anchor window must assert at once; got {requests:?}",
        );
    }

    /// Once the beacon has folded the seat's `ReshapeReady`, the gate has
    /// banked it and a further signal cannot change the count. The duty must
    /// fall silent for good rather than assert until the split executes.
    #[test]
    fn a_credited_observer_seat_stops_asserting() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_with_ready(
            &[(parent, &[1, 2, 3, 5])],
            &[(parent, 5, child, true)],
            &[parent],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        for step in 0..8 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                !requests
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
                "step {step}: a credited seat must not assert; got {requests:?}",
            );
        }
    }

    /// The keeper half of the same rule: a keeper the merge gate has already
    /// counted stops re-asserting.
    #[test]
    fn a_credited_keeper_seat_stops_asserting() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        let snap = snapshot_keepers_with_ready(
            &[(own_child, &[1, 2, 3, 5])],
            &[(own_child, 5, parent, true)],
            &[own_child],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        for step in 0..8 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                !requests
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
                "step {step}: a credited keeper must not assert; got {requests:?}",
            );
        }
    }

    #[test]
    fn the_gate_advances_a_follower_to_the_terminal_fetch() {
        let parent = ShardId::ROOT;
        let (child, sibling) = parent.children();
        // Both children seeded → the gate fires; the terminal fetch addresses
        // the parent, whose tip it is, and the child, whose flipped members
        // hold it once the parent's have left.
        let snap = snapshot(&[(child, &[1, 2])], &[], &[parent, child, sibling]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        // First step fires the gate (Following → FetchingTerminal); the second
        // emits the terminal fetch.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));

        for source in [parent, child] {
            assert!(
                requests.iter().any(|r| matches!(
                    r,
                    ReshapeRequest::Fetch { duty, from, kind: FetchKind::Block { .. }, .. }
                        if *duty == child && *from == source
                )),
                "the gate must drive a terminal fetch from {source:?}; got {requests:?}",
            );
        }
    }

    /// The observed child of [`overtaken_follower`]: anchored at a height
    /// the follow, still at the parent's anchor, has not reached.
    fn overtaking_view(parent_halves: &[(ShardId, u64, ShardId)]) -> TopologySchedule {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let child_anchor = ShardAnchor {
            height: BlockHeight::new(20),
            ..anchor()
        };
        let snap = build(
            &[(child, &[1, 5, 6])],
            &[],
            &[],
            parent_halves,
            &[],
            anchor(),
        )
        .with_boundaries(BTreeMap::from([(parent, anchor()), (child, child_anchor)]));
        windowed(&snap)
    }

    /// A host running `me` whose observer seat 5 follows ROOT's split into
    /// its left child.
    fn overtaken_follower(me: &[u64]) -> ReshapeOrchestrator {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let mut orch = ReshapeOrchestrator::new(me.iter().map(|&id| vid(id)).collect());
        orch.observers.insert(
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );
        orch
    }

    /// A follower the child's anchor overtook before it applied the parent's
    /// terminal cannot prove that terminal from anything the child serves.
    /// With no parent-half seat on the host it relinquishes the seat to the
    /// join and fetches nothing more.
    #[test]
    fn a_follower_the_child_anchor_overtakes_relinquishes_the_seat() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // Validator 6 seats the child from the parent, on another host.
        let schedule = overtaking_view(&[(child, 6, parent)]);
        let view = ReshapeView::new(&schedule);
        let mut orch = overtaken_follower(&[5]);
        assert!(orch.is_seating(child));

        for _ in 0..2 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                requests.is_empty(),
                "a relinquished follower asks for nothing; got {requests:?}"
            );
        }
        assert!(matches!(
            orch.observers[&child].phase,
            ObserverPhase::Relinquished
        ));
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "the relinquished seat is the join's to take"
        );

        let released = snapshot(&[(child, &[1, 5, 6])], &[], &[]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            orch.observers.is_empty() && orch.parent_halves.is_empty(),
            "the released cohort ends the relinquished duty"
        );
    }

    /// An overtaken follower on a host that also holds a parent-half seat
    /// on the child hands the seat to that parent half in the same step,
    /// so the child is seeded from the host's own parent chain rather than
    /// joined from a committee that may hold no copy of it. The io the
    /// parent half asks for reaches it, not the inert observer.
    #[test]
    fn an_overtaken_follower_hands_the_seat_to_its_co_hosted_parent_half() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let schedule = overtaking_view(&[(child, 6, parent)]);
        let view = ReshapeView::new(&schedule);
        let mut orch = overtaken_follower(&[5, 6]);

        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(matches!(
            orch.observers[&child].phase,
            ObserverPhase::Relinquished
        ));
        assert_eq!(
            seeds_through(&requests),
            Some(BlockHeight::new(20)),
            "the parent half seeds the child at its anchor; got {requests:?}"
        );
        assert!(!orch.relinquished(child));
        assert!(
            orch.is_seating(child),
            "the parent half owns the seat, so placement leaves it alone"
        );

        let _ = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: child }],
            at(0),
        );
        assert!(
            orch.parent_halves[&child].store_seeded,
            "the seeded store is the parent half's"
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            !block_fetches(&requests, parent).is_empty(),
            "the seeded parent half fetches the parent's terminal; got {requests:?}"
        );
    }

    #[test]
    fn a_prepared_duty_seats_once_the_placement_lands() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The observer is now seated on the child committee.
        let snap = snapshot(&[(child, &[1, 5])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(parent, child, 5, ObserverPhase::Prepared),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == child),
            "a prepared duty must seat once placed on the child; got {requests:?}",
        );
    }

    #[test]
    fn a_prepared_duty_waits_until_placed() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // Child committee does not yet include the observer.
        let snap = snapshot(&[(child, &[1, 2])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers.insert(
            child,
            observer_duty(parent, child, 5, ObserverPhase::Prepared),
        );

        assert!(
            orch.step(
                &ReshapeView::new(&windowed(&snap)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0)
            )
            .is_empty()
        );
    }

    #[test]
    fn detects_a_keeper_seat_and_reasserts_ready() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        // The keeper runs `own_child` and reforms `parent`; the parent has not
        // composed yet, so it re-asserts ready to the own-child committee.
        let snap = snapshot_keepers(
            &[(own_child, &[1, 2, 3, 5])],
            &[(own_child, 5, parent)],
            &[own_child],
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::BroadcastReady { validator, recipients, .. }
                    if *validator == vid(5) && !recipients.contains(&vid(5)) && recipients.len() == 3
            )),
            "a keeper must re-assert ready to its own-child committee minus self; got {requests:?}",
        );
    }

    #[test]
    fn the_keeper_gate_opens_the_parent_store_and_collects_both_halves() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        // The merge reformed the parent — a live parent committee plus both
        // children's terminal anchors → the gate fires.
        let snap = snapshot_keepers(
            &[(parent, &[5, 6]), (left, &[1, 2]), (right, &[3, 4])],
            &[(left, 5, parent)],
            &[parent, left, right],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        // First step fires the gate (ReassertingReady → Building); the second
        // opens the parent store. The halves stage straight into that store,
        // so their fetches wait for the open to land.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));

        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { shard } if *shard == parent)),
            "the keeper gate must open the parent store; got {requests:?}",
        );
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::Fetch { .. })),
            "no half may fetch before the parent store opens; got {requests:?}",
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: parent }],
            at(0),
        );
        for half in [left, right] {
            assert!(
                requests.iter().any(|r| matches!(
                    r,
                    ReshapeRequest::Fetch { from, kind: FetchKind::StateRange { .. }, .. } if *from == half
                )),
                "the keeper must snap-sync the {half:?} half; got {requests:?}",
            );
        }
    }

    #[test]
    fn a_prepared_keeper_seats_when_placed_on_the_parent() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        // The keeper is now seated on the reformed parent committee.
        let snap = snapshot_keepers(&[(parent, &[1, 5])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.keepers.insert(
            parent,
            KeeperDuty {
                members: vec![KeeperMember {
                    validator: vid(5),
                    own_child,
                    ready_assert: None,
                }],
                phase: KeeperPhase::Prepared,
                open_requested: true,
                store_opened: true,
                pending_stage: Vec::new(),
                stages_unacked: 0,
            },
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == parent),
            "a prepared keeper must seat once placed on the parent; got {requests:?}",
        );
    }

    #[test]
    fn detects_a_parent_half_seat_and_seeds_from_the_parent() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The child anchor has seeded, so the duty seeds the child store from
        // the host's local parent.
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(
                requests.as_slice(),
                [ReshapeRequest::SeedFromParent { parent: p, child: c, .. }]
                    if *p == parent && *c == child
            ),
            "a held parent-half seat must seed from the parent; got {requests:?}",
        );
    }

    #[test]
    fn a_deferred_seed_re_arms_and_retries() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        // The first step seeds; the seed is one-shot, so the next is quiet.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0))
                .is_empty()
        );

        // A deferral (the local parent is still behind) re-arms the seed.
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::SeedDeferred { child }],
            at(0),
        );
        assert!(
            requests.iter().any(
                |r| matches!(r, ReshapeRequest::SeedFromParent { child: c, .. } if *c == child)
            ),
            "a deferred seed must re-arm and retry; got {requests:?}",
        );
    }

    /// A seed with no parent store to clone relinquishes the seat: the duty
    /// stops seeding and no longer claims the child, but stays until the
    /// projection releases the cohort, so it is not rediscovered into the
    /// same missing store.
    #[test]
    fn an_unavailable_seed_relinquishes_the_seat_until_the_projection_releases_it() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            orch.is_seating(child),
            "the discovered duty claims the child"
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::SeedUnavailable { child }],
            at(0),
        );
        assert!(
            requests.is_empty(),
            "a relinquished duty emits nothing; got {requests:?}"
        );
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "a relinquished seat is the join's to take"
        );
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0))
                .is_empty(),
            "the duty is not rediscovered while the cohort stands"
        );

        let released = snapshot_parent_halves(&[(child, &[1, 5])], &[], &[child]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            !orch.relinquished(child) && !orch.parent_halves.contains_key(&child),
            "the released cohort ends the relinquished duty"
        );
    }

    /// A parent half seeds against its child's genesis anchor, one above the
    /// parent's terminal record; once the child has crossed past its genesis,
    /// no clone of the parent reaches the anchor and the seat is the join's.
    #[test]
    fn a_parent_half_relinquishes_a_child_anchored_past_its_genesis() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let terminal = ShardAnchor {
            height: BlockHeight::new(7),
            terminal_epoch: Some(Epoch::new(3)),
            ..anchor()
        };
        let seeding = |child_anchor: ShardAnchor| {
            let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[])
                .with_boundaries(BTreeMap::from([(parent, terminal), (child, child_anchor)]));
            let schedule = windowed(&snap);
            let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
            let requests = orch.step(
                &ReshapeView::new(&schedule),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0),
            );
            (orch, requests)
        };

        let (orch, requests) = seeding(anchor());
        assert!(
            matches!(
                requests.as_slice(),
                [ReshapeRequest::SeedFromParent { through, .. }] if *through == BlockHeight::new(8)
            ),
            "a genesis anchor seeds from the parent; got {requests:?}"
        );
        assert!(orch.is_seating(child));

        let crossed = ShardAnchor {
            height: BlockHeight::new(12),
            ..anchor()
        };
        let (orch, requests) = seeding(crossed);
        assert!(
            requests.is_empty(),
            "an anchor past the genesis seeds nothing; got {requests:?}"
        );
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "the relinquished seat is the join's to take"
        );
    }

    #[test]
    fn a_parent_half_is_left_to_an_active_observer_duty() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The host holds an observer seat (validator 5, syncing the child) and a
        // parent-half seat (validator 6) for the same child.
        let snap = build(
            &[(parent, &[1, 2])],
            &[(parent, 5, child, false)],
            &[],
            &[(child, 6, parent)],
            &[],
            anchor(),
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5), vid(6)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { shard } if *shard == child)),
            "the observer duty opens the child store; got {requests:?}",
        );
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::SeedFromParent { .. })),
            "no parent-half seed is emitted while an observer covers the child; got {requests:?}",
        );
    }

    #[test]
    fn a_prepared_parent_half_seats_then_releases_with_the_projection() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.parent_halves.insert(
            child,
            ParentHalfDuty {
                parent,
                validators: vec![vid(5)],
                phase: ParentHalfPhase::Prepared,
                store_seeded: true,
            },
        );

        // Placed on the child committee → seat, then persist while the
        // projection still lists the cohort.
        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == child),
            "a prepared parent half seats once placed; got {requests:?}",
        );
        assert!(
            orch.parent_halves.contains_key(&child),
            "a seated parent half persists while the projection lists it",
        );

        // Once the child commits past genesis the projection releases the
        // cohort, and the seated duty is dropped.
        let released = snapshot_parent_halves(&[(child, &[1, 5])], &[], &[child]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            !orch.parent_halves.contains_key(&child),
            "a released seated parent half is dropped",
        );
    }

    // ─── the derived-versus-attested cross-check ────────────────────────

    /// A seated observer duty holding `adopted` as the genesis it flipped on.
    fn adopted_duty(parent: ShardId, child: ShardId, adopted: BlockHash) -> ObserverDuty {
        ObserverDuty {
            adopted_genesis: Some(adopted),
            ..observer_duty(parent, child, 5, ObserverPhase::Seated)
        }
    }

    /// The seeded anchor agrees with what the host derived: the check
    /// clears and the duty carries on untouched.
    #[test]
    fn a_matching_seeded_anchor_clears_the_cross_check() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The parent-half projection still lists the child, so a seated
        // duty is not yet released — the state the seed lands in.
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.observers
            .insert(child, adopted_duty(parent, child, anchor().block_hash));

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.is_empty(),
            "a matching anchor emits nothing; got {requests:?}"
        );
        assert!(
            orch.observers.contains_key(&child),
            "a matching anchor leaves the duty in place",
        );
        assert!(
            orch.observers[&child].adopted_genesis.is_none(),
            "the check is consumed once it has agreed",
        );
    }

    /// The child folded a crossing of its own before its parent's terminal
    /// folded, so the beacon never wrote the seed and the anchor is that
    /// crossing. A genesis hash cannot match a crossing hash, and the child
    /// is correct — the comparison window has closed, not been failed.
    #[test]
    fn a_crossing_anchor_closes_the_cross_check_without_wiping() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child])
            .with_advanced(BTreeSet::from([child]));
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let derived = BlockHash::from_raw(Hash::from_bytes(b"locally-derived-genesis"));
        orch.observers
            .insert(child, adopted_duty(parent, child, derived));

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { .. })),
            "a producing child must never have its store re-opened; got {requests:?}",
        );
        assert!(
            orch.observers.contains_key(&child),
            "a producing child's duty survives the closed window",
        );
    }

    /// A genuine disagreement against the seeded anchor: the followed parent
    /// chain is not the one the network committed. The duty stops without
    /// touching the store, which a seated vnode is running on.
    #[test]
    fn a_disagreeing_seeded_anchor_stops_without_re_opening_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let forged = BlockHash::from_raw(Hash::from_bytes(b"forged"));
        orch.observers
            .insert(child, adopted_duty(parent, child, forged));

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { .. })),
            "a disagreement must not wipe the store; got {requests:?}",
        );
        assert!(
            !orch.observers.contains_key(&child),
            "a disagreeing duty stops rather than re-seeding",
        );
    }

    // ─── recognition walks fall back ────────────────────────────────────

    /// A parent half whose walk never resolves a commit-provable terminal
    /// hands back to the anchor path once the child's anchor lands, rather
    /// than fetching heights past a tip that will never advance.
    #[test]
    fn a_parent_half_walk_falls_back_once_the_child_anchors() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The child's anchor projects, so the parent has terminated: the
        // walk cannot resolve and the seed is the way through.
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.parent_halves.insert(
            child,
            ParentHalfDuty {
                parent,
                validators: vec![vid(5)],
                phase: ParentHalfPhase::Recognizing(Box::new(ObserverTail::recognizing(
                    anchor(),
                    child,
                ))),
                store_seeded: false,
            },
        );

        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        // The first step leaves `Recognizing`; the second emits the seed the
        // anchor path opens with.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            matches!(
                orch.parent_halves[&child].phase,
                ParentHalfPhase::Seeding { .. }
            ),
            "the walk must hand back to the seed",
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            requests.iter().any(
                |r| matches!(r, ReshapeRequest::SeedFromParent { child: c, .. } if *c == child)
            ),
            "the fallback must emit the anchor path's seed; got {requests:?}",
        );
    }

    /// A keeper whose walks never resolve hands back to the re-assert once
    /// the beacon composes the parent, so the compose branch can build
    /// against the attested anchor.
    #[test]
    fn a_keeper_walk_falls_back_once_the_parent_composes() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        // A live committee on a seeded parent is a composed merge.
        let snap = snapshot_keepers(
            &[(parent, &[1, 5]), (left, &[1]), (right, &[1])],
            &[(left, 5, parent)],
            &[parent, left, right],
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        orch.keepers.insert(
            parent,
            KeeperDuty {
                members: vec![KeeperMember {
                    validator: vid(5),
                    own_child: left,
                    ready_assert: None,
                }],
                phase: KeeperPhase::Recognizing {
                    left: Box::new(KeeperRecognition {
                        child: left,
                        tail: Box::new(ObserverTail::recognizing(anchor(), left)),
                        proven: None,
                    }),
                    right: Box::new(KeeperRecognition {
                        child: right,
                        tail: Box::new(ObserverTail::recognizing(anchor(), right)),
                        proven: None,
                    }),
                },
                open_requested: false,
                store_opened: false,
                pending_stage: Vec::new(),
                stages_unacked: 0,
            },
        );

        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            matches!(
                orch.keepers[&parent].phase,
                KeeperPhase::ReassertingReady | KeeperPhase::Building { .. }
            ),
            "the walk must hand back to the re-assert, which builds on the anchor",
        );
    }

    /// The block fetches a duty emitted from `from`, as their requests.
    fn block_fetches(requests: &[ReshapeRequest], from_shard: ShardId) -> Vec<GetBlockRequest> {
        requests
            .iter()
            .filter_map(|r| match r {
                ReshapeRequest::Fetch {
                    from,
                    kind: FetchKind::Block { request },
                    ..
                } if *from == from_shard => Some(request.clone()),
                _ => None,
            })
            .collect()
    }

    /// A split's terminal fetch names the parent's terminal crossing, the
    /// block the parent's own boundary records one below the child's
    /// seeded genesis; a record at another height is not that crossing,
    /// and the fetch asks by height alone.
    #[test]
    fn a_split_terminal_fetch_names_the_parents_terminal_crossing() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let terminal_hash = BlockHash::from_raw(Hash::from_bytes(b"terminal"));
        let parent_record = |height| ShardAnchor {
            block_hash: terminal_hash,
            height: BlockHeight::new(height),
            terminal_epoch: Some(Epoch::new(3)),
            ..anchor()
        };
        let observing = |record: ShardAnchor| {
            let snap = snapshot(&[(child, &[1, 2])], &[], &[])
                .with_boundaries(BTreeMap::from([(parent, record), (child, anchor())]));
            let schedule = windowed(&snap);
            let view = ReshapeView::new(&schedule);
            assert_eq!(
                split_terminal_request(&view, parent, &anchor()).hash,
                (record.height == BlockHeight::new(7)).then_some(terminal_hash),
                "the parent half's fetch names the same block",
            );
            let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
            orch.observers.insert(
                child,
                observer_duty(
                    parent,
                    child,
                    5,
                    ObserverPhase::FetchingTerminal {
                        anchor: anchor(),
                        ask: TerminalAsk::NOW,
                    },
                ),
            );
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            let fetches = block_fetches(&requests, child);
            assert_eq!(fetches.len(), 1, "got {requests:?}");
            assert_eq!(fetches[0].height, BlockHeight::new(7));
            fetches[0].hash
        };
        assert_eq!(observing(parent_record(7)), Some(terminal_hash));
        assert_eq!(observing(parent_record(5)), None);
    }

    /// A keeper records only the anchored terminal: a fetch answered with
    /// another block at the height leaves the half without a terminal and
    /// asks again once the refetch wait has passed, and the anchored block
    /// ends the fetching.
    #[test]
    fn a_keeper_records_only_the_anchored_terminal() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        let terminal = make_test_block(BlockHeight::new(8));
        let sibling = make_test_block_with_anchor_wt(BlockHeight::new(8), 5);
        assert_ne!(terminal.hash(), sibling.hash());
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: parent,
            from: left,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    make_test_certified(block.clone()).qc().clone(),
                    &Inventory::empty(),
                ))),
            },
        };
        let snap = build(
            &[(parent, &[5, 6]), (left, &[1, 2]), (right, &[3, 4])],
            &[],
            &uncredited(&[(left, 5, parent)]),
            &[],
            &[parent, left, right],
            ShardAnchor {
                block_hash: terminal.hash(),
                ..anchor()
            },
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: parent }],
            at(0),
        );
        let fetches = block_fetches(&requests, left);
        assert_eq!(fetches.len(), 1, "got {requests:?}");
        assert_eq!(fetches[0].hash, Some(terminal.hash()));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&sibling)],
            at(0),
        );
        assert!(
            block_fetches(&requests, left).is_empty(),
            "a sibling answer is dropped and not asked again at once; got {requests:?}",
        );
        let refetch = u64::try_from(REFETCH_WAIT.as_millis()).expect("fits");
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(
            block_fetches(&requests, left).len(),
            1,
            "the terminal is asked for again after the wait; got {requests:?}",
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&terminal)],
            at(refetch),
        );
        assert!(
            block_fetches(&requests, left).is_empty(),
            "the anchored terminal is recorded; got {requests:?}",
        );
        let KeeperPhase::Building { left: half, .. } = &orch.keepers[&parent].phase else {
            panic!("the keeper builds the parent");
        };
        assert_eq!(
            half.terminal.as_ref().map(|(header, _)| header.hash()),
            Some(terminal.hash())
        );
    }
}
