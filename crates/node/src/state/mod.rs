//! Node state machine.

mod bft;
mod execution;
mod proposal;
mod provisions;
mod sync;
mod timers;
mod transactions;

use hyperscale_bft::{BftConfig, BftCoordinator, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_execution::ExecutionCoordinator;
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator};
use hyperscale_provisions::{OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_topology::TopologyCoordinator;
use hyperscale_types::{Block, LocalTimestamp, ShardGroupId, StateRoot, TopologySnapshot};
use std::sync::Arc;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, and provisions into a single state machine.
/// View changes are handled implicitly via local round advancement in `BftCoordinator` (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: `SyncManager`, simulation: runner logic).
/// The runner sends `SyncBlockReadyToApply` events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology — passed by reference to subsystem methods.
    topology: TopologyCoordinator,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftCoordinator,

    /// Execution state.
    execution: ExecutionCoordinator,

    /// Mempool state.
    mempool: MempoolCoordinator,

    /// Provision coordination for cross-shard transactions.
    provisions: ProvisionCoordinator,

    /// Retains outbound provisions until the target shard's
    /// execution certificates ACK every transaction they contain.
    outbound_provisions: OutboundProvisionTracker,

    /// Remote block header coordination (single source of truth).
    remote_headers: RemoteHeaderCoordinator,

    /// Current time.
    now: LocalTimestamp,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.snapshot().local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `topology` - Network topology
    /// * `signing_key` - Key for signing votes and proposals
    /// * `bft_config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    /// * `mempool_config` - Mempool configuration
    /// * `provision_config` - Provision coordinator configuration
    #[must_use]
    pub fn new(
        node_index: NodeIndex,
        topology: TopologyCoordinator,
        bft_config: &BftConfig,
        recovered: RecoveredState,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<hyperscale_provisions::ProvisionStore>,
    ) -> Self {
        Self {
            node_index,
            bft: BftCoordinator::new(node_index, bft_config.clone(), recovered),
            execution: ExecutionCoordinator::new(),
            mempool: MempoolCoordinator::with_config(mempool_config),
            provisions: ProvisionCoordinator::with_config_and_store(
                provision_config,
                Arc::clone(&provision_store),
            ),
            outbound_provisions: OutboundProvisionTracker::new(provision_store),
            remote_headers: RemoteHeaderCoordinator::new(),
            topology,
            now: LocalTimestamp::ZERO,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's index.
    #[must_use]
    pub const fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    #[must_use]
    pub fn shard(&self) -> ShardGroupId {
        self.topology.snapshot().local_shard()
    }

    /// Get the current topology snapshot.
    #[must_use]
    pub fn topology(&self) -> &TopologySnapshot {
        self.topology.snapshot()
    }

    /// Get a reference to the mempool state.
    #[must_use]
    pub const fn mempool(&self) -> &MempoolCoordinator {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    #[must_use]
    pub const fn bft(&self) -> &BftCoordinator {
        &self.bft
    }

    /// Get a reference to the execution state.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionCoordinator {
        &self.execution
    }

    /// Get a reference to the provision coordinator.
    #[must_use]
    pub const fn provisions(&self) -> &ProvisionCoordinator {
        &self.provisions
    }

    /// Get a reference to the remote header coordinator.
    #[must_use]
    pub const fn remote_headers(&self) -> &RemoteHeaderCoordinator {
        &self.remote_headers
    }

    /// Get the last committed JMT root hash (delegated to BFT's verification pipeline).
    #[must_use]
    pub const fn last_committed_jmt_root(&self) -> StateRoot {
        self.bft.jmt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: &Block) -> Vec<Action> {
        self.bft
            .initialize_genesis(self.topology.snapshot(), genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        node = self.node_index,
        shard = self.topology.snapshot().local_shard().0,
        event = %event.type_name(),
        height = self.bft.committed_height().0,
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch over the ProtocolEvent enum; one arm per variant
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ViewChangeTimer => self.on_view_change_timer(),
            ProtocolEvent::ContentAvailable => self.try_event_driven_proposal(),

            // ── BFT Consensus ────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockHeaderReceived { .. }
            | ProtocolEvent::QuorumCertificateFormed { .. }
            | ProtocolEvent::RemoteBlockCommitted { .. }
            | ProtocolEvent::BlockVoteReceived { .. }
            | ProtocolEvent::BlockReadyToCommit { .. }
            | ProtocolEvent::QuorumCertificateResult { .. }
            | ProtocolEvent::QcSignatureVerified { .. }
            | ProtocolEvent::RemoteHeaderQcVerified { .. }
            | ProtocolEvent::RemoteHeaderAdmitted { .. }
            | ProtocolEvent::BlockRootVerified { .. }
            | ProtocolEvent::ProposalBuilt { .. }
            | ProtocolEvent::BlockCommitted { .. }
            | ProtocolEvent::BlockPersisted { .. }
            | ProtocolEvent::FinalizedWavesAdmitted { .. }) => self.handle_bft(evt),

            // ── Provisions ───────────────────────────────────────────────
            evt @ (ProtocolEvent::ProvisionsReceived { .. }
            | ProtocolEvent::StateProvisionsVerified { .. }
            | ProtocolEvent::ProvisionsAdmitted { .. }
            | ProtocolEvent::OutboundProvisionBroadcast { .. }
            | ProtocolEvent::OutboundEcObserved { .. }) => self.handle_provisions(evt),

            // ── Execution ────────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionBatchCompleted { .. }
            | ProtocolEvent::ExecutionVoteReceived { .. }
            | ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. }
            | ProtocolEvent::ExecutionCertificateAggregated { .. }
            | ProtocolEvent::ExecutionCertificateSignatureVerified { .. }
            | ProtocolEvent::WaveCompleted { .. }
            | ProtocolEvent::ExecutionCertificateAdmitted { .. }) => self.handle_execution(evt),

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionCertificateCreated { .. }
            | ProtocolEvent::TransactionGossipReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }) => self.handle_transaction(evt),

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::SyncBlockReadyToApply { .. }
            | ProtocolEvent::SyncEcVerificationComplete { .. }
            | ProtocolEvent::SyncProtocolComplete { .. }
            | ProtocolEvent::SyncResumed
            | ProtocolEvent::ChainMetadataFetched { .. }) => self.handle_sync(evt),

            // ── Global Consensus / Epoch (not yet implemented) ───────────
            // When implemented, route to GlobalConsensusState.
            // The #[instrument] span already logs the specific event name.
            //
            // TODO(epoch): After transition_to_next_epoch() / mark_shard_splitting() /
            // clear_shard_splitting() mutates self.topology, emit
            // Action::TopologyChanged { topology: Arc::clone(self.topology.snapshot()) }
            // so the io_loop updates its shared topology snapshot.
            ProtocolEvent::GlobalConsensusTimer
            | ProtocolEvent::GlobalBlockReceived { .. }
            | ProtocolEvent::GlobalBlockVoteReceived { .. }
            | ProtocolEvent::GlobalQcFormed { .. }
            | ProtocolEvent::EpochEndApproaching { .. }
            | ProtocolEvent::EpochTransitionReady { .. }
            | ProtocolEvent::EpochTransitionComplete { .. }
            | ProtocolEvent::ValidatorSyncComplete { .. }
            | ProtocolEvent::ShardSplitInitiated { .. }
            | ProtocolEvent::ShardSplitComplete { .. }
            | ProtocolEvent::ShardMergeInitiated { .. }
            | ProtocolEvent::ShardMergeComplete { .. } => vec![],
        };

        // Drain any state root verifications that became ready during this event.
        for ready in self.bft.drain_ready_state_root_verifications() {
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_block_hash: ready.parent_block_hash,
                parent_state_root: ready.parent_state_root,
                parent_block_height: ready.parent_block_height,
                expected_root: ready.expected_root,
                finalized_waves: ready.finalized_waves,
                block_height: ready.block_height,
            });
        }

        // Re-enter try_propose if a deferred proposal was unblocked.
        // ContentAvailable triggers fresh tx selection against current state,
        // avoiding stale transactions from the original deferral.
        if self.bft.take_ready_proposal() {
            actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
        }

        actions
    }

    fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        self.bft.set_time(now);
    }

    fn now(&self) -> LocalTimestamp {
        self.now
    }
}
