//! Host bring-up: genesis bootstrap and inbound handler registration.
//!
//! These methods run at well-defined points in the host's life, not
//! on every event. The run-loop methods live in [`super`].
//!
//! - [`NodeHost::initialize_shard_genesis`] feeds the supplied genesis
//!   block into every vnode of its shard and drains the resulting
//!   actions via the common [`NodeHost::drain_actions`] path.
//! - [`NodeHost::install_engine_genesis`] commits the genesis substates +
//!   computes the genesis state root. Only runs on a fresh node.
//! - [`NodeHost::register_inbound_handlers`] wires the request / gossip /
//!   notification handler closures into the network adapter. Required
//!   before the host starts processing events; reached by both genesis
//!   and resume paths.

use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::sharding::{
    filter_genesis_updates_for_shard, resolve_owned_nodes_from_updates,
};
use hyperscale_engine::{GenesisConfig, prepared_genesis};
use hyperscale_network::Network;
use hyperscale_storage::{GenesisCommit, RecoveredState, ShardStorage};
use hyperscale_types::{
    Block, CertifiedBlock, ChainOrigin, NodeId, ShardId, StateRoot, ValidatorId, Verified,
};

use crate::host::{NodeHost, ShardGenesis};
use crate::shard::{HostEvent, StepOutput, committed_state_restored};

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Initialize every vnode in `genesis_block`'s shard with the
    /// supplied genesis block, dispatching the resulting actions
    /// per-vnode. Vnodes in other hosted shards are untouched —
    /// cross-shard hosts call this once per shard with that shard's
    /// genesis block.
    pub fn initialize_shard_genesis(&mut self, genesis_block: &Block) {
        let shard = genesis_block.header().shard_id();
        let count = self.vnodes_len(shard);
        let now = self.shard_loop_mut(shard).now;
        for vnode_idx in 0..count {
            let actions = self
                .vnode_state_mut(shard, vnode_idx)
                .initialize_genesis(now, genesis_block);
            self.shard_loop_mut(shard).drain_actions(vnode_idx, actions);
        }
        self.shard_loop_mut(shard)
            .seed_genesis_substate_frontier(genesis_block);
    }

    /// Resume a runtime-seated shard's consensus from its recovered
    /// committed state — [`ShardLoop::resume_committed`]'s counterpart for
    /// the simulation runner, which routes the restore through the host
    /// step so the resulting sends and timer arms flow through its
    /// scheduler (production seats the pinned loop pre-spawn and captures
    /// the timer ops directly). A committee seated onto a quiet chain — a
    /// halt recovery's fresh committee — hears nothing from gossip, so
    /// without the restore its vnodes never propose or time out.
    ///
    /// [`ShardLoop::resume_committed`]: crate::shard::ShardLoop::resume_committed
    pub fn resume_shard_committed(
        &mut self,
        shard: ShardId,
        recovered: &RecoveredState,
    ) -> StepOutput {
        self.step(HostEvent::protocol(
            shard,
            committed_state_restored(recovered),
        ))
    }

    /// Run the deterministic part of one shard's genesis ceremony: install
    /// engine genesis, build the genesis block under `proposer`, persist it
    /// into the shard's vnodes, and drain the resulting setup output.
    ///
    /// Returns the block, its certified form, and the drained
    /// [`StepOutput`](crate::shard::StepOutput). The caller commits the
    /// certified block — production steps `BlockCommitted` inline, simulation
    /// schedules it after the network is wired — so this stops short of the
    /// commit, the one step the two runners can't share.
    pub fn build_shard_genesis(
        &mut self,
        shard: ShardId,
        proposer: ValidatorId,
        config: &GenesisConfig,
    ) -> ShardGenesis
    where
        S: GenesisCommit,
    {
        let genesis_jmt_root = self.install_engine_genesis(shard, config);
        let block = Block::genesis(shard, proposer, genesis_jmt_root, ChainOrigin::ROOT);
        self.initialize_shard_genesis(&block);
        self.flush_all_batches();
        let setup_output = self.drain_pending_output();
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis(
            shard,
            proposer,
            genesis_jmt_root,
            ChainOrigin::ROOT,
        ));
        ShardGenesis {
            block,
            certified,
            setup_output,
        }
    }

    /// Install engine genesis on `shard`'s storage.
    ///
    /// Builds (or reuses) the cached merged [`hyperscale_storage::DatabaseUpdates`]
    /// for `(network, config)`, commits substates, and computes the JMT root
    /// at version 0. Returns the genesis state root.
    ///
    /// Independent of network-handler registration — runners call
    /// [`Self::register_inbound_handlers`] once their genesis-or-resume
    /// decision is settled.
    ///
    /// # Panics
    ///
    /// Panics if the JMT is already initialized (genesis must run on a fresh
    /// store).
    pub fn install_engine_genesis(&mut self, shard: ShardId, config: &GenesisConfig) -> StateRoot
    where
        S: GenesisCommit,
    {
        // A per-shard store holds only its own shard's accounts: prefix-rooting
        // (each store roots its JMT at the shard's prefix) requires it, since a
        // foreign-prefix key would be mis-bucketed beneath this shard's root.
        // Drop xrd balances whose address routes to another shard.
        let topology_snapshot = self.process.topology_snapshot.load();
        let mut config = config.clone();
        config.xrd_balances.retain(|(address, _)| {
            let det_node_id = NodeId::from_radix(address.into_node_id());
            topology_snapshot.shard_for_node_id(&det_node_id) == shard
        });
        let merged = prepared_genesis(self.process.dispatch_handles.executor.network(), &config);
        // Genesis writes the full initial state in one batch, so every owned
        // node's `Own(_)` ref is present in `merged` — resolve ownership from
        // it directly to owner-prefix vaults under their accounts.
        let owner_map = resolve_owned_nodes_from_updates(&merged);
        // The full bootstrap is replicated to every shard's substate store for
        // read availability, but the prefix-rooted JMT must hold only this
        // shard's subtree, so the committed state root is the global tree's
        // node at the shard prefix.
        let jmt_updates = filter_genesis_updates_for_shard(
            &merged,
            &owner_map,
            shard,
            topology_snapshot.shard_trie(),
        );
        self.shard_io(shard)
            .storage
            .install_genesis(&merged, &jmt_updates, &owner_map)
    }

    /// Register inbound network handlers (requests, gossip, notifications).
    ///
    /// Must be called once per node before the `NodeHost` starts processing
    /// events. Both genesis and resume paths reach this — registration is
    /// not coupled to whether genesis ran.
    pub fn register_inbound_handlers(&mut self) {
        self.register_request_handler();
        self.register_gossip_handlers();
        self.register_notification_handlers();
    }
}
