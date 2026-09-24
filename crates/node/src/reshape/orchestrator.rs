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
    Block, BlockHash, BlockHeader, BlockHeight, ChainOrigin, FrontierInputs, LocalTimestamp,
    NetworkDefinition, PredecessorTerminal, QuorumCertificate, ShardAnchor, ShardId, StateRoot,
    SubstateKey, SubstateLeaf, ValidatorId, Verifier, WeightedTimestamp,
};

use crate::bootstrap::{BootstrapRequest, ShardBootstrap, StateRangeOutcome};
use crate::reshape::merge_flip::merge_genesis_from_terminals;
use crate::reshape::observer::{ObserverBootstrap, ObserverTail, TerminalSighting};
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
    /// A single committed block by height, from [`ObserverTail`] or a terminal
    /// fetch.
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
    /// crossing. Answered by [`ReshapeEvent::Opened`] when the clone lands, or
    /// [`ReshapeEvent::SeedDeferred`] while the local parent is still behind.
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
        predecessors: Vec<PredecessorTerminal>,
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
    /// The children seeded; fetching the certified terminal to derive genesis.
    FetchingTerminal {
        /// The beacon-seeded child anchor the derivation verifies against.
        anchor: ShardAnchor,
        /// Whether the terminal fetch is already in flight.
        requested: bool,
    },
    /// Terminal fetched and genesis derived; awaiting the next `advance` to emit
    /// the adopt.
    Adopting {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds.
        predecessors: Vec<PredecessorTerminal>,
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
    terminal_requested: bool,
}

impl KeeperHalf {
    fn new(child: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            child,
            bootstrap: Box::new(ShardBootstrap::state_only(child, anchor)),
            terminal: None,
            terminal_requested: false,
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
            terminal: Some((header.clone(), sighting.canonical_qc.clone())),
            terminal_requested: true,
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
        terminal_roots: header.terminal_roots(),
        handoff_complete: None,
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
        derived: Option<(ChainOrigin, Box<Block>, Vec<PredecessorTerminal>)>,
        finalize_requested: bool,
    },
    /// Union imported; awaiting the next advance to emit the adopt.
    Adopting {
        origin: ChainOrigin,
        genesis: Box<Block>,
        predecessors: Vec<PredecessorTerminal>,
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
        predecessors: Vec<PredecessorTerminal>,
        /// Whether the seed request is already in flight.
        requested: bool,
    },
    /// Store seeded; fetching the parent's certified terminal to derive the
    /// child genesis.
    FetchingTerminal {
        /// The beacon-seeded child anchor the derivation verifies against.
        anchor: ShardAnchor,
        /// Whether the terminal fetch is already in flight.
        requested: bool,
    },
    /// Terminal fetched and genesis derived; awaiting the next `advance` to emit
    /// the adopt.
    Adopting {
        /// The derived chain origin.
        origin: ChainOrigin,
        /// The derived genesis block.
        genesis: Box<Block>,
        /// The terminals this duty succeeds.
        predecessors: Vec<PredecessorTerminal>,
    },
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted; awaiting the placement that seats it.
    Prepared,
    /// Seated; inert until the committed projection releases the duty.
    Seated,
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
    /// keeper reforms, or a splitting child an observer syncs. The adapter
    /// suppresses the placement-delta join for such a shard so the
    /// orchestrator seats it from the duty's prepared store, rather than the
    /// join racing a redundant fresh snap-sync against it.
    #[must_use]
    pub fn is_seating(&self, shard: ShardId) -> bool {
        self.keepers.contains_key(&shard)
            || self.observers.contains_key(&shard)
            || self.parent_halves.contains_key(&shard)
    }

    /// Advance every duty one step: apply the io results in `events`, discover
    /// new duties from `view`, and return the io the adapter should perform.
    pub fn step(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        events: Vec<ReshapeEvent>,
        now: LocalTimestamp,
    ) -> Vec<ReshapeRequest> {
        for event in events {
            self.apply_event(event);
        }
        self.discover_observer_duties(view);
        self.discover_keeper_duties(view);
        self.discover_parent_half_duties(view);

        let mut requests = Vec::new();
        let children: Vec<ShardId> = self.observers.keys().copied().collect();
        for child in children {
            self.advance_observer(child, view, verifier, now, &mut requests);
        }
        let parents: Vec<ShardId> = self.keepers.keys().copied().collect();
        for parent in parents {
            self.advance_keeper(parent, view, verifier, now, &mut requests);
        }
        let halves: Vec<ShardId> = self.parent_halves.keys().copied().collect();
        for child in halves {
            self.advance_parent_half(child, view, verifier, &mut requests);
        }
        // A seated parent half lingers only to keep its child from being
        // re-discovered; once the projection releases it (the child committed
        // past genesis) the duty is done.
        self.parent_halves.retain(|child, duty| {
            !matches!(duty.phase, ParentHalfPhase::Seated)
                || view.parent_half_cohorts().contains_key(child)
        });
        // A seated observer lingers through the parent-half phase so its child
        // stays in `observers`, deferring any co-hosted parent half to the seat
        // already issued; once the projection releases the child the duty ends.
        self.observers.retain(|child, duty| {
            !matches!(duty.phase, ObserverPhase::Seated)
                || view.parent_half_cohorts().contains_key(child)
        });
        requests
    }

    /// Route one io result to the duty and sequencer awaiting it.
    fn apply_event(&mut self, event: ReshapeEvent) {
        match event {
            ReshapeEvent::Opened { shard } => {
                if let Some(duty) = self.observers.get_mut(&shard) {
                    duty.store_opened = true;
                } else if let Some(duty) = self.keepers.get_mut(&shard) {
                    duty.store_opened = true;
                } else if let Some(duty) = self.parent_halves.get_mut(&shard) {
                    duty.store_seeded = true;
                }
            }
            ReshapeEvent::Fetched { duty, from, kind } => {
                if self.observers.contains_key(&duty) {
                    self.apply_observer_fetched(duty, kind);
                } else if self.keepers.contains_key(&duty) {
                    self.apply_keeper_fetched(duty, from, kind);
                } else if self.parent_halves.contains_key(&duty) {
                    self.apply_parent_half_fetched(duty, kind);
                }
            }
            ReshapeEvent::FetchFailed { duty, from, kind } => {
                self.apply_fetch_failed(duty, from, kind);
            }
            ReshapeEvent::Staged { shard } => {
                if let Some(duty) = self.observers.get_mut(&shard) {
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
                if let Some(duty) = self.observers.get_mut(&shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                    duty.pending_stage.insert(0, (progress, leaves));
                } else if let Some(duty) = self.keepers.get_mut(&shard) {
                    duty.stages_unacked = duty.stages_unacked.saturating_sub(1);
                    duty.pending_stage.insert(0, (progress, leaves));
                }
            }
            ReshapeEvent::Imported { shard, root } => self.apply_imported(shard, root),
            ReshapeEvent::Applied { shard, root } => {
                if let Some(duty) = self.observers.get_mut(&shard)
                    && let ObserverPhase::Following(tail) = &mut duty.phase
                    && tail.on_applied(root).is_err()
                {
                    // A diverged follow fails closed: drop the duty so the
                    // adapter falls back to a fresh snap-sync join.
                    self.observers.remove(&shard);
                }
            }
            ReshapeEvent::Adopted { shard } => {
                if let Some(duty) = self.observers.get_mut(&shard)
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
        }
    }

    /// Re-arm a failed fetch on the duty awaiting it.
    fn apply_fetch_failed(&mut self, duty: ShardId, from: ShardId, kind: FetchKind) {
        if let Some(observer) = self.observers.get_mut(&duty) {
            match (&mut observer.phase, kind) {
                (ObserverPhase::Syncing(bootstrap), FetchKind::StateRange { sub_range, .. }) => {
                    bootstrap.on_state_range_failure(sub_range);
                }
                (ObserverPhase::Following(tail), FetchKind::Block { .. }) => tail.on_failure(),
                (ObserverPhase::FetchingTerminal { requested, .. }, _) => *requested = false,
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
                            FetchKind::Block { .. } => half.terminal_requested = false,
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
                ParentHalfPhase::FetchingTerminal { requested, .. } => *requested = false,
                _ => {}
            }
        }
    }

    /// Route an import root to the observer or keeper awaiting it.
    fn apply_imported(&mut self, shard: ShardId, root: StateRoot) {
        if let Some(observer) = self.observers.get_mut(&shard) {
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
    fn apply_keeper_fetched(&mut self, parent: ShardId, from: ShardId, kind: FetchedKind) {
        let Some(keeper) = self.keepers.get_mut(&parent) else {
            return;
        };
        if let KeeperPhase::Recognizing { left, right } = &mut keeper.phase {
            if let FetchedKind::Headers { response } = &kind
                && let Some(half) = recognition_for(left, right, from)
            {
                half.tail.on_certified_headers(&response.headers);
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
            FetchedKind::Block { response } => {
                if let Some(elided) = &response.certified {
                    half.terminal = Some((elided.header().clone(), elided.qc().clone()));
                }
                half.terminal_requested = false;
            }
        }
    }

    /// Route a fetch response to its sequencer, deriving genesis once the
    /// terminal arrives.
    fn apply_observer_fetched(&mut self, duty: ShardId, kind: FetchedKind) {
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
                let _ = tail.on_response(&response);
            }
            (
                ObserverPhase::FetchingTerminal { anchor, requested },
                FetchedKind::Block { response },
            ) => {
                *requested = false;
                let anchor = *anchor;
                if let Some(elided) = &response.certified
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
    fn apply_parent_half_fetched(&mut self, child: ShardId, kind: FetchedKind) {
        let Some(duty) = self.parent_halves.get_mut(&child) else {
            return;
        };
        let mut next: Option<ParentHalfPhase> = None;
        if let ParentHalfPhase::Recognizing(tail) = &mut duty.phase
            && let FetchedKind::Headers { response } = &kind
        {
            tail.on_certified_headers(&response.headers);
            return;
        }
        if let ParentHalfPhase::FetchingTerminal { anchor, requested } = &mut duty.phase
            && let FetchedKind::Block { response } = kind
        {
            *requested = false;
            let anchor = *anchor;
            if let Some(elided) = &response.certified
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
                // Capture the parent's committee while it is still live —
                // its applying fold drops it from the head, and that lands
                // around when the follow reaches the terminal whose QCs it
                // verifies.
                tail.capture_committee(view.resolved_committee(duty.parent));
                // Flip at the cut, from the chain this host followed,
                // rather than an epoch later when the beacon publishes the
                // anchor. The store must have applied through the terminal
                // — the genesis adopts the child subtree as of *its* root —
                // and the terminal must be commit-proven, since a bare
                // certificate can be superseded.
                if let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                    && commit_proven(child, sighting, verifier, view.network())
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
                // Once this child's boundary seeds, the parent terminated.
                // Keep following its committed blocks until the tail catches
                // up through the terminal crossing, then derive genesis from
                // it — adopting before the followed store reaches the terminal
                // would reproduce the wrong child-subtree root.
                let child_anchor = view.boundary(child);
                if let Some(anchor) = child_anchor
                    && tail.next_height() >= anchor.height
                {
                    duty.phase = ObserverPhase::FetchingTerminal {
                        anchor,
                        requested: false,
                    };
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
                // The parent committee serves its blocks while it lives; once
                // this child's anchor projects the parent has dissolved, so the
                // child committee's parent halves serve the parent's crossing
                // blocks from their retained chain.
                let from = if child_anchor.is_some() {
                    child
                } else {
                    duty.parent
                };
                if let Some(request) = tail.next_request() {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from,
                        kind: FetchKind::Block { request },
                    });
                }
                if let Some(block) = tail.take_apply() {
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
            ObserverPhase::FetchingTerminal { anchor, requested } => {
                if !*requested {
                    let terminal = anchor.height.prev().unwrap_or(anchor.height);
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: child,
                        kind: FetchKind::Block {
                            request: GetBlockRequest::new(terminal, BlockIntent::Execute),
                        },
                    });
                    *requested = true;
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
            ObserverPhase::AwaitingAdopt | ObserverPhase::Seated => {}
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
                    half.tail
                        .capture_committee(view.resolved_committee(half.child));
                    if let Some(sighting) = half.tail.settled_terminal()
                        && commit_proven(half.child, sighting, verifier, view.network())
                    {
                        half.proven = Some(sighting.clone());
                    } else if let Some(request) = half.tail.next_header_request(half.child) {
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
                    advance_keeper_half(left, parent, view, out);
                    advance_keeper_half(right, parent, view, out);
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
    /// the parent halves among them.
    fn discover_parent_half_duties(&mut self, view: &ReshapeView) {
        for (&child, cohort) in view.parent_half_cohorts() {
            if self.observers.contains_key(&child) {
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
                    if store_seeded {
                        next = Some(ParentHalfPhase::FetchingTerminal {
                            anchor,
                            requested: false,
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
                tail.capture_committee(view.resolved_committee(parent));
                if let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                    && commit_proven(child, sighting, verifier, view.network())
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
                } else if let Some(request) = tail.next_header_request(parent) {
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
            ParentHalfPhase::FetchingTerminal { anchor, requested } => {
                // The seed gates on the local parent reaching the terminal, so
                // the host's own retained chain serves the certified terminal.
                if !*requested {
                    let terminal = anchor.height.prev().unwrap_or(anchor.height);
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Block {
                            request: GetBlockRequest::new(terminal, BlockIntent::Execute),
                        },
                    });
                    *requested = true;
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
            ParentHalfPhase::AwaitingAdopt | ParentHalfPhase::Seated => {}
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
) -> Option<(Block, ChainOrigin, Option<PredecessorTerminal>)> {
    let (genesis, origin) =
        split_genesis_from_terminal(child, terminal, qc, anchor.weighted_timestamp)
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
    Some((genesis, origin, terminal.as_predecessor_terminal()))
}

/// Whether the parent's terminal is commit-proven — the gate the flip
/// keys on.
///
/// Two QCs can exist at one height; two commits cannot. Certification
/// alone would let a superseded block seed the children.
fn commit_proven(
    child: ShardId,
    sighting: &TerminalSighting,
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
) -> bool {
    let height = sighting.header.height().inner();
    let Some((proof, committee)) = &sighting.commit_proof else {
        tracing::debug!(
            ?child,
            height,
            "no commit proof for the parent's terminal yet: no captured committee, \
             or the coast has not yet produced a round-contiguous pair — the \
             anchor path still covers it"
        );
        return false;
    };
    // What the proof commits must be the block the genesis derives from.
    // A prefix proof's two-chain sits above the terminal, so the link's
    // foot is the only thing tying it back down; checked before the
    // signature work, which is the expensive half.
    if proof.proven_block_hash() != sighting.header.hash() {
        tracing::error!(
            ?child,
            height,
            proven = ?proof.proven_block_hash(),
            "the commit proof commits a block other than the parent's terminal"
        );
        return false;
    }
    // Both QCs are the parent's, in the same window, so the two-chain
    // verifies against one committee twice.
    let committees = [committee.clone(), committee.clone()];
    if let Err(error) = proof.verify_resolved(verifier, network, &committees) {
        tracing::error!(
            ?child,
            height,
            %error,
            "the parent's terminal failed commit-proof verification"
        );
        return false;
    }
    true
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
/// queue), and fetch its certified terminal once.
fn advance_keeper_half(
    half: &mut KeeperHalf,
    duty: ShardId,
    view: &ReshapeView,
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
        && !half.terminal_requested
        && let Some(anchor) = view.boundary(half.child)
    {
        // A merging child's boundary anchors its terminal crossing directly —
        // the block whose hash and height the beacon composed the parent from —
        // so the certified terminal sits at the anchor height itself.
        let terminal = anchor.height;
        out.push(ReshapeRequest::Fetch {
            duty,
            from: half.child,
            kind: FetchKind::Block {
                request: GetBlockRequest::new(terminal, BlockIntent::Execute),
            },
        });
        half.terminal_requested = true;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch, Hash, LocalTimestamp,
        NetworkDefinition, ReshapeSeat, ShardAnchor, ShardId, Signer, StateRoot, TopologySchedule,
        TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, WeightedTimestamp,
    };

    use super::{
        FetchKind, KeeperDuty, KeeperMember, KeeperPhase, KeeperRecognition, ObserverDuty,
        ObserverPhase, ParentHalfDuty, ParentHalfPhase, ReshapeEvent, ReshapeOrchestrator,
        ReshapeRequest,
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
            terminal_roots: None,
            handoff_complete: None,
        }
    }

    /// A schedule headed by `snapshot`, cut into one-second windows.
    fn windowed(snapshot: &TopologySnapshot) -> TopologySchedule {
        TopologySchedule::new(1_000, Epoch::GENESIS, std::sync::Arc::new(snapshot.clone()))
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

    #[test]
    fn detects_a_cohort_seat_and_opens_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 5, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
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
                ObserverPhase::Following(Box::new(ObserverTail::new(anchor(), child))),
            ),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
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
                ObserverPhase::Following(Box::new(ObserverTail::new(anchor(), child))),
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
                orch.step(&view, &BlsVerifier, Vec::new(), at(ms))
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
                orch.step(&view, &BlsVerifier, Vec::new(), at(5_000))
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
            let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(ms));
        }
        assert!(
            !orch
                .step(&view, &BlsVerifier, Vec::new(), at(60_000))
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
                ObserverPhase::Following(Box::new(ObserverTail::new(anchor(), child))),
            ),
        );

        for step in 0..8 {
            let requests = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
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
            let requests = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
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
        // the child committee.
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
                ObserverPhase::Following(Box::new(ObserverTail::new(anchor(), child))),
            ),
        );

        // First step fires the gate (Following → FetchingTerminal); the second
        // emits the terminal fetch.
        let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, Vec::new(), at(0));

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::Fetch { duty, from, kind: FetchKind::Block { .. }, .. }
                    if *duty == child && *from == child
            )),
            "the gate must drive a terminal fetch from the child committee; got {requests:?}",
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
        let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, Vec::new(), at(0));

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
        let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
        assert!(orch.step(&view, &BlsVerifier, Vec::new(), at(0)).is_empty());

        // A deferral (the local parent is still behind) re-arms the seed.
        let requests = orch.step(
            &view,
            &BlsVerifier,
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
        let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
        assert!(
            matches!(
                orch.parent_halves[&child].phase,
                ParentHalfPhase::Seeding { .. }
            ),
            "the walk must hand back to the seed",
        );
        let requests = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
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
        let _ = orch.step(&view, &BlsVerifier, Vec::new(), at(0));
        assert!(
            matches!(
                orch.keepers[&parent].phase,
                KeeperPhase::ReassertingReady | KeeperPhase::Building { .. }
            ),
            "the walk must hand back to the re-assert, which builds on the anchor",
        );
    }
}
