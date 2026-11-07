//! The io vocabulary between the orchestrator and its adapters: the
//! requests a step returns and the events the adapter feeds back.

use std::sync::Arc;

use hyperscale_storage::ImportProgress;
use hyperscale_types::network::request::{
    GetBlockRequest, GetRemoteHeadersRequest, GetStateRangeRequest,
};
use hyperscale_types::network::response::{
    GetBlockResponse, GetRemoteHeadersResponse, GetStateRangeResponse,
};
use hyperscale_types::{
    Block, BlockHeight, FrontierInputs, ShardAnchor, ShardId, StateRoot, SubstateKey, SubstateLeaf,
    ValidatorId,
};

use crate::reshape::genesis::DerivedGenesis;

/// What a [`ReshapeRequest::Fetch`] asks the adapter to retrieve, forwarded from
/// a held sequencer.
#[derive(Debug, Clone)]
pub enum FetchKind {
    /// A snap-sync state sub-range, from [`ObserverBootstrap`](crate::reshape::observer::ObserverBootstrap).
    StateRange {
        /// The sub-range id the response must be paired back to.
        sub_range: usize,
        /// The range request itself.
        request: GetStateRangeRequest,
    },
    /// A single block by height, from [`ObserverTail`](crate::reshape::observer::ObserverTail) or a terminal fetch.
    Block {
        /// The block request itself.
        request: GetBlockRequest,
    },
    /// A batch of consecutive certified headers, from a recognizing
    /// [`ObserverTail`](crate::reshape::observer::ObserverTail). A recognition walk discards bodies, so it reads
    /// headers — which a host co-hosting the source serves from its own
    /// store, and which batch far better over the wire when it does not.
    Headers {
        /// The header request itself.
        request: GetRemoteHeadersRequest,
    },
}

/// Names one request that expects a completion.
///
/// The orchestrator hands each such request a fresh ticket and the adapter
/// echoes it in the event that answers it; a duty takes a completion only
/// for a ticket it still awaits,
/// so one answering an earlier request for the same store, or a request of
/// a duty since dropped and rediscovered, changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ticket(u64);

impl Ticket {
    /// The ticket numbered `raw`.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The ticket issued after this one.
    pub(super) const fn successor(self) -> Self {
        Self(self.0 + 1)
    }
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
        /// Echoed by the answering event.
        ticket: Ticket,
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
        /// Echoed by the answering event.
        ticket: Ticket,
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
        /// Echoed by the answering event.
        ticket: Ticket,
    },
    /// Build `shard`'s boundary state at `height` from its staged
    /// chunks. Answered by [`ReshapeEvent::Imported`]. Emitted only
    /// after every [`Self::StageChunk`] has been acknowledged.
    FinalizeImport {
        /// The duty's store shard.
        shard: ShardId,
        /// The boundary height the staged leaves seed.
        height: BlockHeight,
        /// Echoed by the answering event.
        ticket: Ticket,
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
        /// Echoed by the answering event.
        ticket: Ticket,
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
    /// state root the genesis names. Answered by [`ReshapeEvent::Adopted`].
    Adopt {
        /// The duty's store shard.
        shard: ShardId,
        /// Split vs merge derivation.
        kind: AdoptKind,
        /// The derived genesis.
        genesis: Box<DerivedGenesis>,
        /// Echoed by the answering event.
        ticket: Ticket,
    },
    /// Seat the prepared `shard` — install its genesis and run consensus. No
    /// response (terminal).
    Seat {
        /// The duty's store shard.
        shard: ShardId,
    },
}

impl ReshapeRequest {
    /// The store a store-prep request prepares: [`Self::OpenStore`]'s shard,
    /// [`Self::SeedFromParent`]'s child. `None` for every other request.
    #[must_use]
    pub const fn prepared_shard(&self) -> Option<ShardId> {
        match self {
            Self::OpenStore { shard, .. } => Some(*shard),
            Self::SeedFromParent { child, .. } => Some(*child),
            _ => None,
        }
    }

    /// What a store-prep for a shard this host already runs answers; `None`
    /// for every other request.
    ///
    /// A duty only ever prepares a store for a shard this host does not run
    /// yet, so a running target is a duty rediscovered on a host that kept
    /// the shard's loop: its store is that loop's live store and stays. An
    /// open answers nothing and the duty stays unopened; a seed answers
    /// [`ReshapeEvent::SeedUnavailable`], so the parent half relinquishes its
    /// seat to the join, which seats its members on the running loop.
    #[must_use]
    pub const fn over_running(&self) -> Option<OverRunning> {
        match self {
            Self::OpenStore { .. } => Some(OverRunning::Nothing),
            Self::SeedFromParent { child, ticket, .. } => {
                Some(OverRunning::Answer(ReshapeEvent::SeedUnavailable {
                    child: *child,
                    ticket: *ticket,
                }))
            }
            _ => None,
        }
    }
}

/// What a store-prep for a shard this host already runs answers (see
/// [`ReshapeRequest::over_running`]).
#[derive(Debug, Clone)]
pub enum OverRunning {
    /// Nothing: the duty is left unopened.
    Nothing,
    /// This event, fed back to the orchestrator.
    Answer(ReshapeEvent),
}

/// The seed gate a [`ReshapeRequest::SeedFromParent`] passes before its
/// clone; `None` when the clone may run. `ticket` is the seed's.
///
/// [`ReshapeEvent::SeedUnavailable`] when this host holds no parent store
/// (`parent_height` is `None`), [`ReshapeEvent::SeedDeferred`] while the
/// parent's committed height is below `through`.
///
/// `through` is the child's genesis height; the parent commits one block
/// past its terminal (the coast certifying it), so the local chain is ready
/// for the clone once its tip reaches it.
#[must_use]
pub fn seed_gate(
    parent_height: Option<BlockHeight>,
    child: ShardId,
    through: BlockHeight,
    ticket: Ticket,
) -> Option<ReshapeEvent> {
    match parent_height {
        None => Some(ReshapeEvent::SeedUnavailable { child, ticket }),
        Some(height) if height < through => Some(ReshapeEvent::SeedDeferred { child, ticket }),
        Some(_) => None,
    }
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

/// An io result the adapter feeds back into [`ReshapeOrchestrator::step`](super::ReshapeOrchestrator::step).
#[derive(Debug, Clone)]
pub enum ReshapeEvent {
    /// A store open completed.
    Opened {
        /// The opened store shard.
        shard: ShardId,
        /// The open's or seed's ticket.
        ticket: Ticket,
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
        /// The stage write's ticket.
        ticket: Ticket,
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
        /// The stage write's ticket.
        ticket: Ticket,
    },
    /// A boundary import completed with the resulting store root.
    Imported {
        /// The store shard.
        shard: ShardId,
        /// The imported root.
        root: StateRoot,
        /// The finalize's ticket.
        ticket: Ticket,
    },
    /// A followed-block application completed with the resulting store root.
    Applied {
        /// The store shard.
        shard: ShardId,
        /// The applied root.
        root: StateRoot,
        /// The application's ticket.
        ticket: Ticket,
    },
    /// A genesis adoption completed, its root already verified against the
    /// genesis's.
    Adopted {
        /// The store shard.
        shard: ShardId,
        /// The adopt's ticket.
        ticket: Ticket,
    },
    /// A [`ReshapeRequest::SeedFromParent`] could not run yet — the host's local
    /// parent has not committed through the terminal crossing. The duty
    /// re-requests the seed once `SEED_RETRY` has passed, so the adapter
    /// feeds this back like any other event.
    SeedDeferred {
        /// The split child whose seed is deferred.
        child: ShardId,
        /// The seed's ticket.
        ticket: Ticket,
    },
    /// A [`ReshapeRequest::SeedFromParent`] found no parent store on this
    /// host to clone — it restarted without one — so the parent half can
    /// never seed. The duty relinquishes the child's seat to the adapter's
    /// ordinary join, which seats the child against its attested anchor.
    SeedUnavailable {
        /// The split child whose seat is relinquished.
        child: ShardId,
        /// The seed's ticket.
        ticket: Ticket,
    },
}
