//! What an embedder calls on a running host.
//!
//! A [`NodeHandle`] reaches the host through a gate and a weak reference:
//! every call enters the gate, upgrades, runs and leaves, so a handle kept
//! past the host's stop holds nothing open, and the host's teardown waits
//! out the calls already in before it drops what they reach. Once the host
//! has stopped, each call gives its empty answer without reaching it.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use hyperscale_core::Gate;
use hyperscale_engine::PreviewReport;
use hyperscale_node::TxStatusCache;
use hyperscale_storage::BeaconChainReader;
use hyperscale_types::{
    BeaconBlockHash, BeaconState, BlockHeight, CertifiedBeaconBlock, Epoch, ShardId, Transaction,
    TransactionStatus, TxHash, Verified,
};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{mpsc, oneshot, watch};

use crate::node::NodeError;
use crate::observe::{HeaderSummary, Observation};
use crate::rpc::NodeStatusState;
use crate::rpc::state::{MempoolSnapshot, PreviewSender, RpcPublishers, TxSubmissionSender};
use crate::status::SyncStatus;
use crate::{LocalValidator, RunnerCommand};

/// Everything a handle's calls reach. The host's `Node` holds the one
/// strong reference and drops it only once the gate has closed and every
/// call has left it.
pub struct HostCalls {
    pub submit: TxSubmissionSender,
    pub preview: PreviewSender,
    pub history: Arc<dyn BeaconChainReader>,
    pub publishers: RpcPublishers,
    pub tx_status: Arc<TxStatusCache>,
    /// The transport's count of connected peer hosts.
    pub peers: Box<dyn Fn() -> usize + Send + Sync>,
    pub commands: mpsc::Sender<RunnerCommand>,
    /// The host's own runtime, which runs a preview's blocking work.
    pub runtime: RuntimeHandle,
}

/// A running host, as its embedder calls it. Cloning is cheap, and a clone
/// kept past the host's stop holds none of its state: its calls answer
/// empty, `false` or [`NodeError::Stopped`].
#[derive(Clone)]
pub struct NodeHandle {
    calls: Weak<HostCalls>,
    gate: Arc<Gate>,
}

impl NodeHandle {
    pub(crate) fn new(calls: &Arc<HostCalls>, gate: Arc<Gate>) -> Self {
        Self {
            calls: Arc::downgrade(calls),
            gate,
        }
    }

    /// Runs `call` on the host while the gate admits it. The strong
    /// reference taken here drops before the entry does, so the host's
    /// last one is never a caller's.
    fn with<T>(&self, call: impl FnOnce(&HostCalls) -> T) -> Option<T> {
        let _entry = self.gate.enter()?;
        let calls = self.calls.upgrade()?;
        Some(call(&calls))
    }

    /// Sends a transaction into the network; `false` if the host did not
    /// take it.
    #[must_use]
    pub fn submit(&self, transaction: Arc<Transaction>) -> bool {
        self.with(|calls| (calls.submit)(transaction))
            .unwrap_or(false)
    }

    /// Runs a transaction against committed state without sending it, on
    /// the host's own blocking workers. `None` when no hosted shard could
    /// answer, or the host has stopped.
    pub async fn preview(&self, transaction: &Transaction) -> Option<PreviewReport> {
        let runtime = self.with(|calls| calls.runtime.clone())?;
        let handle = self.clone();
        let transaction = transaction.clone();
        runtime
            .spawn_blocking(move || handle.with(|calls| (calls.preview)(&transaction)))
            .await
            .ok()
            .flatten()
            .flatten()
            .map(|report| *report)
    }

    /// Take on `validator` while the host runs, without a restart and
    /// without interrupting the validators it already runs. The host attests
    /// it to every peer it is linked to and starts its beacon participation;
    /// it is seated wherever its placement puts it, as at start. Peers route
    /// to it once their topology holds its registration. The host does not
    /// remember it: the caller passes it again at the next start.
    ///
    /// # Errors
    ///
    /// [`NodeError::AddValidator`] if the host would not take it, and
    /// [`NodeError::Stopped`] if the host is no longer running.
    pub async fn add_validator(&self, validator: LocalValidator) -> Result<(), NodeError> {
        let commands = self
            .with(|calls| calls.commands.clone())
            .ok_or(NodeError::Stopped)?;
        let (reply, answer) = oneshot::channel();
        commands
            .send(RunnerCommand::AddValidator { validator, reply })
            .await
            .map_err(|_| NodeError::Stopped)?;
        answer
            .await
            .map_err(|_| NodeError::Stopped)?
            .map_err(NodeError::AddValidator)
    }

    /// What the host's beacon thread has seen, republished after each step
    /// that changed it: the latest committed beacon state, each shard's
    /// newest certified header, and the last day of adopted epochs with
    /// what each settled. `None` until the thread's first step. The
    /// receiver's `changed` fails once the host has stopped.
    #[must_use]
    pub fn observe(&self) -> watch::Receiver<Option<Arc<Observation>>> {
        self.with(|calls| calls.publishers.observations.subscribe())
            .unwrap_or_else(|| watch::channel(None).1)
    }

    /// The certified headers the host has seen for `shard` from `since` on,
    /// oldest first: the last hour of them, each with its signers and the
    /// proposers whose rounds failed before it.
    #[must_use]
    pub fn headers(&self, shard: ShardId, since: BlockHeight) -> Vec<HeaderSummary> {
        self.with(|calls| calls.publishers.headers.since(shard, since))
            .unwrap_or_default()
    }

    /// The bytes each shard's snap-sync import has staged, for every import
    /// in progress: a shard the host is copying before it can sign.
    #[must_use]
    pub fn importing(&self) -> BTreeMap<ShardId, u64> {
        self.with(|calls| calls.publishers.importing.snapshot())
            .unwrap_or_default()
    }

    /// Peer hosts the host's transport holds a connection to.
    #[must_use]
    pub fn peers(&self) -> usize {
        self.with(|calls| (calls.peers)()).unwrap_or(0)
    }

    /// What became of a transaction the host has seen, as far as its own
    /// shards' legs of it go.
    #[must_use]
    pub fn tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.with(|calls| calls.tx_status.get(hash).map(|(status, _)| status))
            .flatten()
    }

    /// The committed beacon chain, for history the observation does not
    /// carry: any epoch's block and state.
    #[must_use]
    pub fn history(&self) -> HandleHistory {
        HandleHistory(self.clone())
    }

    /// The `/status` readouts: connected peers and, per hosted validator,
    /// its shard, height and view.
    pub(crate) fn node_status(&self) -> Arc<NodeStatusState> {
        self.with(|calls| calls.publishers.node_status.load_full())
            .unwrap_or_default()
    }

    /// Block sync progress per hosted shard.
    pub(crate) fn sync_status(&self) -> Arc<SyncStatus> {
        self.with(|calls| calls.publishers.sync_status.load_full())
            .unwrap_or_default()
    }

    /// The mempool's counts per hosted validator.
    pub(crate) fn mempool(&self) -> Arc<MempoolSnapshot> {
        self.with(|calls| calls.publishers.mempool.load_full())
            .unwrap_or_default()
    }
}

/// The host's committed beacon chain, read through its handle: every read
/// answers `None` or empty once the host has stopped.
#[derive(Clone)]
pub struct HandleHistory(NodeHandle);

impl BeaconChainReader for HandleHistory {
    fn get_beacon_block_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
        self.0
            .with(|calls| calls.history.get_beacon_block_by_epoch(epoch))
            .flatten()
    }

    fn get_beacon_block_by_hash(
        &self,
        hash: BeaconBlockHash,
    ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
        self.0
            .with(|calls| calls.history.get_beacon_block_by_hash(hash))
            .flatten()
    }

    fn get_state_by_epoch(&self, epoch: Epoch) -> Option<Arc<BeaconState>> {
        self.0
            .with(|calls| calls.history.get_state_by_epoch(epoch))
            .flatten()
    }

    fn latest_committed_epoch(&self) -> Option<Epoch> {
        self.0
            .with(|calls| calls.history.latest_committed_epoch())
            .flatten()
    }

    fn latest_committed(&self) -> Option<(Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>)> {
        self.0
            .with(|calls| calls.history.latest_committed())
            .flatten()
    }

    /// One pass through the gate for the whole walk, so a stop part way
    /// through never leaves it with a gap.
    fn states_since(&self, floor: Epoch) -> Vec<Arc<BeaconState>> {
        self.0
            .with(|calls| calls.history.states_since(floor))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// A beacon chain with nothing committed.
    struct NoHistory;

    impl BeaconChainReader for NoHistory {
        fn get_beacon_block_by_epoch(
            &self,
            _: Epoch,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }
        fn get_beacon_block_by_hash(
            &self,
            _: BeaconBlockHash,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }
        fn get_state_by_epoch(&self, _: Epoch) -> Option<Arc<BeaconState>> {
            None
        }
        fn latest_committed_epoch(&self) -> Option<Epoch> {
            None
        }
        fn latest_committed(
            &self,
        ) -> Option<(Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>)> {
            None
        }
    }

    /// A host that answers submissions with `submit` and previews with
    /// `preview`, its published state at defaults and no chain committed,
    /// behind an open gate. The calls stay reachable while the returned
    /// `Arc` lives.
    pub fn host(
        submit: TxSubmissionSender,
        preview: PreviewSender,
    ) -> (Arc<HostCalls>, NodeHandle) {
        let calls = Arc::new(HostCalls {
            submit,
            preview,
            history: Arc::new(NoHistory),
            publishers: RpcPublishers::default(),
            tx_status: Arc::new(TxStatusCache::new()),
            peers: Box::new(|| 0),
            commands: mpsc::channel(1).0,
            runtime: RuntimeHandle::current(),
        });
        let handle = NodeHandle::new(&calls, Arc::new(Gate::new()));
        (calls, handle)
    }
}
