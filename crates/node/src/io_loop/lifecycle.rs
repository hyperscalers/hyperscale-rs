//! Lifecycle helpers for the I/O loop — bring-up and (eventually)
//! tear-down.
//!
//! These methods run at well-defined points in the host's life, not
//! on every event. The run-loop methods live in [`super`].
//!
//! - [`IoLoop::handle_actions`] drains the action vec returned by
//!   `NodeStateMachine::initialize_genesis` (initial timer sets, etc.).
//! - [`IoLoop::install_engine_genesis`] commits the genesis substates +
//!   computes the genesis state root. Only runs on a fresh node.
//! - [`IoLoop::register_inbound_handlers`] wires the request / gossip /
//!   notification handler closures into the network adapter. Required
//!   before the I/O loop starts processing events; reached by both
//!   genesis and resume paths.

use hyperscale_core::Action;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, GenesisConfig, prepared_genesis};
use hyperscale_network::Network;
use hyperscale_storage::{GenesisCommit, Storage};
use hyperscale_types::{Block, ShardGroupId, StateRoot};

use crate::io_loop::IoLoop;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Process actions emitted by a single vnode's genesis init.
    ///
    /// Called by runners that drive `NodeStateMachine::initialize_genesis`
    /// directly on `vnodes[vnode_idx].state`. Most callers prefer
    /// [`Self::initialize_all_vnodes_genesis`] which does both steps
    /// for every hosted vnode.
    pub fn handle_actions(&mut self, vnode_idx: usize, actions: Vec<Action>) {
        let shard = self.vnodes[vnode_idx].shard;
        for action in actions {
            self.process_action(vnode_idx, action);
        }
        self.flush_block_commits(shard);
    }

    /// Initialize every hosted vnode's state machine with `genesis_block`
    /// and dispatch the resulting actions per-vnode.
    ///
    /// Callers hosting vnodes across multiple shards drive this once per
    /// shard with the shard-appropriate genesis block; this method
    /// initializes the vnodes whose `local_shard()` matches
    /// `genesis_block`'s shard, leaving the others untouched.
    pub fn initialize_all_vnodes_genesis(&mut self, genesis_block: &Block) {
        let target_shard = genesis_block.header().shard_group_id();
        for vnode_idx in 0..self.vnodes_len() {
            if self.vnodes[vnode_idx].shard != target_shard {
                continue;
            }
            let actions = self
                .vnode_state_mut(vnode_idx)
                .initialize_genesis(genesis_block);
            self.handle_actions(vnode_idx, actions);
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
    pub fn install_engine_genesis(
        &mut self,
        shard: ShardGroupId,
        config: &GenesisConfig,
    ) -> StateRoot
    where
        S: GenesisCommit,
    {
        let merged = prepared_genesis(self.executor.network(), config);
        self.shard_storage(shard).install_genesis(&merged)
    }

    /// Register inbound network handlers (requests, gossip, notifications).
    ///
    /// Must be called once per node before the `IoLoop` starts processing
    /// events. Both genesis and resume paths reach this — registration is
    /// not coupled to whether genesis ran.
    pub fn register_inbound_handlers(&mut self) {
        self.register_request_handler();
        self.register_gossip_handlers();
        self.register_notification_handlers();
    }
}
