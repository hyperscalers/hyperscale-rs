//! A running host's internals, for this crate's own tests.
//!
//! A probe reads its transport, its derivation, its topology and the shard
//! stores it holds through the same gate as every [`NodeHandle`] call, and
//! commands go straight to its runner. Built only under the `test-utils`
//! feature, which no embedder enables.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use hyperscale_network_iroh::IrohAdapter;
use hyperscale_node::SharedTopologySnapshot;
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{Derivation, ShardId, TopologySnapshot, TransactionStatus, TxHash};
use tokio::sync::mpsc::error::TrySendError;

use crate::handle::{HostCalls, NodeHandle};
use crate::node::NodeError;
use crate::rpc::NodeStatusState;
pub use crate::runner::RunnerCommand;
pub use crate::supervisor::ShardCommand;
use crate::supervisor::shard_data_dir;

/// The shard stores a host opened at their own directories, by shard. Weak:
/// a store closes when the host lets it go, whatever is recorded here.
pub(crate) type ShardStores = Arc<Mutex<HashMap<ShardId, Weak<RocksDbShardStorage>>>>;

/// Records `store`, opened at `dir` for `shard`, when `dir` is the shard's
/// own directory under `root`; a staging store beside it is not recorded.
pub(crate) fn record_shard_store(
    stores: &ShardStores,
    root: &Path,
    dir: &Path,
    shard: ShardId,
    store: &Arc<RocksDbShardStorage>,
) {
    if dir == shard_data_dir(root, shard) {
        stores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(shard, Arc::downgrade(store));
    }
}

/// What a probe reaches beyond the handle's own calls. It lives in the
/// host's `HostCalls`, so it drops with them, before the host's stop
/// returns.
pub(crate) struct ProbeState {
    pub(crate) network: Arc<IrohAdapter>,
    pub(crate) derivation: Arc<dyn Derivation>,
    pub(crate) topology: SharedTopologySnapshot,
    /// The topology the host started on, read before its runner ran.
    pub(crate) startup_topology: Arc<TopologySnapshot>,
    pub(crate) shard_stores: ShardStores,
}

/// A look inside a running host, lent for the length of one
/// [`NodeHandle::probe`] closure. Nothing it hands out outlives that closure
/// except what the caller copies out of it.
#[derive(Clone, Copy)]
pub struct Probe<'a> {
    calls: &'a HostCalls,
    state: &'a ProbeState,
}

impl<'a> Probe<'a> {
    /// The host's transport, with its fault gate.
    #[must_use]
    pub fn network(&self) -> &'a IrohAdapter {
        &self.state.network
    }

    /// The derivation the host's replicas resolve envelopes through.
    #[must_use]
    pub fn derivation(&self) -> &'a dyn Derivation {
        self.state.derivation.as_ref()
    }

    /// Runs `read` on the host's store for `shard`; `None` when the host
    /// holds none there.
    pub fn shard_store<T>(
        &self,
        shard: ShardId,
        read: impl FnOnce(&RocksDbShardStorage) -> T,
    ) -> Option<T> {
        let store = self
            .state
            .shard_stores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&shard)
            .and_then(Weak::upgrade)?;
        Some(read(&store))
    }

    /// The live topology slot the host's shards and supervisor read; a
    /// test may store a snapshot of its own into it.
    #[must_use]
    pub fn topology(&self) -> SharedTopologySnapshot {
        Arc::clone(&self.state.topology)
    }

    /// The topology the host started on, before its runner folded anything.
    #[must_use]
    pub fn startup_topology(&self) -> Arc<TopologySnapshot> {
        Arc::clone(&self.state.startup_topology)
    }

    /// The `/status` readouts: connected peers and, per hosted validator,
    /// its shard, height and view.
    #[must_use]
    pub fn node_status(&self) -> Arc<NodeStatusState> {
        self.calls.publishers.node_status.load_full()
    }

    /// What became of a transaction the host has seen, with the hosted
    /// shard that reported it.
    #[must_use]
    pub fn tx_status(&self, hash: &TxHash) -> Option<(TransactionStatus, ShardId)> {
        self.calls.tx_status.get(hash)
    }
}

impl NodeHandle {
    /// Runs `look` inside the running host. `None` once the host has
    /// stopped, or for a host built without a probe.
    pub fn probe<T>(&self, look: impl FnOnce(Probe<'_>) -> T) -> Option<T> {
        self.with(|calls| {
            calls
                .probe
                .as_ref()
                .map(|state| look(Probe { calls, state }))
        })
        .flatten()
    }

    /// Sends `command` to the host's runner.
    ///
    /// # Errors
    ///
    /// [`NodeError::Stopped`] if the host is no longer running.
    pub async fn command(&self, command: RunnerCommand) -> Result<(), NodeError> {
        let commands = self
            .with(|calls| calls.commands.clone())
            .ok_or(NodeError::Stopped)?;
        commands.send(command).await.map_err(|_| NodeError::Stopped)
    }

    /// Sends `command` to the host's runner without waiting for room.
    ///
    /// # Errors
    ///
    /// [`TrySendError::Full`] if the runner's queue is full, and
    /// [`TrySendError::Closed`] once the host has stopped.
    pub fn try_command(&self, command: RunnerCommand) -> Result<(), TrySendError<RunnerCommand>> {
        match self.with(|calls| calls.commands.clone()) {
            Some(commands) => commands.try_send(command),
            None => Err(TrySendError::Closed(command)),
        }
    }
}
