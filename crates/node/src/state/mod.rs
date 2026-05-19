//! Composite node state machine.
//!
//! [`NodeStateMachine`] composes the per-domain coordinators —
//! [`BftCoordinator`], [`ExecutionCoordinator`], [`MempoolCoordinator`],
//! [`ProvisionCoordinator`], [`RemoteHeaderCoordinator`], and
//! [`TopologyCoordinator`] — into a single deterministic
//! [`StateMachine`] over [`ProtocolEvent`] inputs and [`Action`] outputs.
//!
//! All consensus-critical mutation flows through this state machine.
//! Asynchronous concerns (network I/O, thread-pool dispatch, timer
//! scheduling) live on [`IoLoop`](crate::io_loop), which feeds events
//! in and dispatches emitted [`Action`]s.
//!
//! Submodules route inputs to the appropriate coordinator: [`bft`] for
//! BFT events, [`execution`] for wave/EC events, [`mempool`] /
//! [`transactions`] for tx ingress, [`provisions`] for cross-shard state,
//! [`proposal`] for proposer-side construction, [`sync`] for catch-up,
//! and [`timers`] for timeout dispatch.

mod bft;
mod execution;
mod proposal;
mod provisions;
mod sync;
mod timers;
mod transactions;

#[cfg(test)]
mod test_support;

use std::sync::Arc;

use hyperscale_bft::{BftConfig, BftCoordinator};
use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_execution::{ExecCertStore, ExecutionCoordinator, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, TxStore};
use hyperscale_provisions::{
    OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator, ProvisionStore,
};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_storage::RecoveredState;
use hyperscale_topology::TopologyCoordinator;
use hyperscale_types::{Block, LocalTimestamp, ShardGroupId, StateRoot, TopologySnapshot};
use tracing::instrument;

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, and provisions into a single state
/// machine. View changes are handled implicitly via local round advancement
/// in `BftCoordinator` (HotStuff-2 style).
///
/// The block-sync state machine itself lives on `IoLoop` (in
/// `shard_io::sync::block`); when a synced block is ready to apply,
/// `IoLoop` fires a `BlockSyncReadyToApply` event into this state machine,
/// which routes it to BFT.
pub struct NodeStateMachine {
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
            .field("validator", &self.topology.snapshot().local_validator_id())
            .field("shard", &self.topology.snapshot().local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine.
    ///
    /// `provision_store`, `tx_store`, `exec_cert_store`, and
    /// `finalized_wave_store` are scoped per shard so same-shard vnodes
    /// converge on one canonical store. Use `RecoveredState::default()`
    /// for a fresh start.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // per-shard-shared stores threaded explicitly
    pub fn new(
        topology: TopologyCoordinator,
        bft_config: &BftConfig,
        recovered: RecoveredState,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<ProvisionStore>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalized_wave_store: Arc<FinalizedWaveStore>,
    ) -> Self {
        Self {
            bft: BftCoordinator::new(bft_config.clone(), recovered),
            execution: ExecutionCoordinator::with_shared_stores(
                exec_cert_store,
                finalized_wave_store,
            ),
            mempool: MempoolCoordinator::with_tx_store(mempool_config, tx_store),
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

    /// Get the current topology snapshot as an `Arc`, for sites that
    /// need to clone it into off-thread closures (delegated action
    /// dispatch). Carries this vnode's `local_validator_id`, so per-
    /// vnode signing context stays consistent with the snapshot the
    /// handler reads.
    #[must_use]
    pub const fn topology_arc(&self) -> &Arc<TopologySnapshot> {
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

    /// Get a reference to the outbound provision tracker.
    #[must_use]
    pub const fn outbound_provisions(&self) -> &OutboundProvisionTracker {
        &self.outbound_provisions
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
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        validator = self.topology.snapshot().local_validator_id().inner(),
        shard = self.topology.snapshot().local_shard().inner(),
        event = %event.type_name(),
        height = self.bft.committed_height().inner(),
    ))]
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.now = now;
        self.bft.set_time(now);
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ViewChangeTimer => self.on_view_change_timer(),

            // ── BFT Consensus ────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockHeaderReceived { .. }
            | ProtocolEvent::QuorumCertificateFormed { .. }
            | ProtocolEvent::RemoteHeaderReceived { .. }
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
            | ProtocolEvent::ExecutionCertificatesReceived { .. }
            | ProtocolEvent::ExecutionCertificateSignatureVerified { .. }
            | ProtocolEvent::ExecutionCertificateAdmitted { .. }
            | ProtocolEvent::FinalizedWavesReceived { .. }
            | ProtocolEvent::FinalizedWaveVerified { .. }) => self.handle_execution(evt),

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::TransactionValidated { .. }
            | ProtocolEvent::TransactionsReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }) => self.handle_transaction(evt),

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::BlockSyncReadyToApply { .. }
            | ProtocolEvent::BlockSyncComplete { .. }
            | ProtocolEvent::RemoteHeaderSyncComplete { .. }
            | ProtocolEvent::CommittedStateRestored { .. }) => self.handle_sync(evt),
        };

        // Drain any state root verifications that became ready during this event.
        let local_shard = self.topology.snapshot().local_shard();
        for ready in self.bft.drain_ready_state_root_verifications(local_shard) {
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_block_hash: ready.parent_block_hash,
                parent_state_root: ready.parent_state_root,
                parent_block_height: ready.parent_block_height,
                expected_root: ready.expected_root,
                expected_local_receipt_root: ready.expected_local_receipt_root,
                finalized_waves: ready.finalized_waves,
                block_height: ready.block_height,
            });
        }

        // If any emitter latched a proposal-retry during this dispatch (or
        // BFT's verification path unblocked a deferred proposal), re-enter
        // `try_propose` once with fresh transaction selection — avoids
        // stale txs from the original deferral.
        if self.bft.take_ready_proposal() {
            actions.extend(self.try_event_driven_proposal());
        }

        actions
    }
}
