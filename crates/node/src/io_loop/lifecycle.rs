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
use hyperscale_types::StateRoot;

use crate::io_loop::IoLoop;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Process actions from genesis initialization.
    ///
    /// `NodeStateMachine::initialize_genesis()` returns actions (timer sets)
    /// that must be processed through the `IoLoop`'s action handler.
    pub fn handle_actions(&mut self, actions: Vec<Action>) {
        for action in actions {
            self.process_action(0, action);
        }
        self.flush_block_commits();
    }

    /// Install engine genesis on this node's storage.
    ///
    /// Builds (or reuses) the cached merged [`hyperscale_storage::DatabaseUpdates`]
    /// for `(network, config)`, commits substates, and computes the JMT root
    /// at version 0. Returns the genesis state root.
    ///
    /// Independent of network-handler registration — runners call
    /// [`Self::register_inbound_handlers`] once their genesis-or-resume
    /// decision is settled.
    pub fn install_engine_genesis(&mut self, config: &GenesisConfig) -> StateRoot
    where
        S: GenesisCommit,
    {
        let merged = prepared_genesis(self.executor.network(), config);
        self.storage().install_genesis(&merged)
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
