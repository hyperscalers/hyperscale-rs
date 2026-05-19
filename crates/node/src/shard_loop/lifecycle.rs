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

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, GenesisConfig, prepared_genesis};
use hyperscale_network::Network;
use hyperscale_storage::{GenesisCommit, Storage};
use hyperscale_types::{Block, ShardGroupId, StateRoot};

use crate::host::NodeHost;

impl<S, N, D, E> NodeHost<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Initialize every vnode in `genesis_block`'s shard with the
    /// supplied genesis block, dispatching the resulting actions
    /// per-vnode. Vnodes in other hosted shards are untouched —
    /// cross-shard hosts call this once per shard with that shard's
    /// genesis block.
    pub fn initialize_shard_genesis(&mut self, genesis_block: &Block) {
        let shard = genesis_block.header().shard_group_id();
        let count = self.vnodes_len(shard);
        for vnode_idx in 0..count {
            let actions = self
                .vnode_state_mut(shard, vnode_idx)
                .initialize_genesis(genesis_block);
            self.shard_loop_mut(shard).drain_actions(vnode_idx, actions);
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
        self.shard_io(shard).storage.install_genesis(&merged)
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
