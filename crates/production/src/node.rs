//! A validator host started from a library.
//!
//! [`Node::start`] opens the storage, the beacon store and the runner a host
//! needs at the data directory's one layout, and hands back the publishers and
//! senders an embedder reads. The host runs on a tokio runtime and thread pools
//! of its own, so stopping it ends everything it started. It installs nothing
//! process-global beyond the first-wins statics the runner already sets;
//! tracing, signals and the allocator stay with the embedder.

use std::collections::BTreeMap;
use std::io::Error as IoError;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use arc_swap::ArcSwap;
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig, ThreadPoolError};
use hyperscale_engine::GenesisConfig as EngineGenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_node::TxStatusCache;
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbConfig, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, BlockHeight, ConsensusPublicKey, GenesisValidators, ShardId, ValidatorId,
    shard_prefix_path,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinError, JoinHandle};

use crate::network_file::{NetworkFile, NetworkFileError};
use crate::observe::{HeaderRing, HeaderSummary, Importing, Observation};
use crate::rpc::{MempoolSnapshot, NodeStatusState, PreviewSender, TxSubmissionSender};
use crate::transport::TransportConfig;
use crate::{
    LocalValidator, ProductionRunner, RunnerError, ShutdownHandle, StorageDirResolver,
    StorageFactory, SyncStatus, shard_data_dir,
};

/// Everything a host needs to start, as plain values.
pub struct NodeSetup {
    /// Where every shard's store and the beacon store live; a restart with
    /// the same directory reopens what an earlier run created.
    pub data_dir: PathBuf,
    /// The validators this host runs. Which shard each sits on comes from the
    /// committed beacon state, not from here.
    pub validators: Vec<LocalValidator>,
    /// The network's genesis validators: every host of one network starts
    /// from the same set.
    pub genesis: GenesisValidators,
    /// Genesis accounts, staking pools and packages.
    pub engine_genesis: EngineGenesisConfig,
    /// Epoch length and the rules derived from it; one per network.
    pub beacon_chain: BeaconChainConfig,
    /// Per-shard BFT timing and limits, the same on every hosted shard.
    pub shard_consensus: ShardConsensusConfig,
    /// Mempool admission limits for every hosted shard.
    pub mempool: MempoolConfig,
    /// Limits on the provisions cross-shard execution waits for.
    pub provisions: ProvisionConfig,
    /// The network backend's configuration; its type follows the `libp2p` or
    /// `iroh` feature.
    pub transport: TransportConfig,
    /// Consensus and throughput pool sizes.
    pub threads: ThreadPoolConfig,
    /// Worker threads of the host's own tokio runtime, which carries its
    /// networking and storage I/O; 0 is one per core.
    pub io_threads: usize,
    /// `RocksDB` tuning for every store the host opens.
    pub storage: RocksDbConfig,
}

/// The host runtime's workers unless told otherwise: its compute runs on the
/// thread pools, so its async side is networking and channel forwarding.
pub const DEFAULT_IO_THREADS: usize = 2;

/// Megabytes of block cache each `RocksDB` store keeps unless told otherwise.
pub const DEFAULT_BLOCK_CACHE_MB: usize = 512;

/// The (consensus, throughput) pool threads for a host with `total_cores`.
///
/// Two go to the consensus pool, whose work is liveness-critical, and every
/// other core to throughput, at least one. State-machine threads are not
/// reserved against: unpinned, the scheduler interleaves them with pool
/// workers.
#[must_use]
pub const fn for_core_count(total_cores: usize) -> (usize, usize) {
    let consensus = 2;
    let throughput = total_cores.saturating_sub(consensus);
    (consensus, if throughput == 0 { 1 } else { throughput })
}

impl NodeSetup {
    /// A host of `validators` joining the network `network` defines, over
    /// `transport`, every other setting at the validator binary's default.
    ///
    /// # Errors
    ///
    /// When the file's genesis is malformed, or a validator here signs with
    /// a key other than the one the file lists for it.
    pub fn from_network(
        data_dir: PathBuf,
        validators: Vec<LocalValidator>,
        network: &NetworkFile,
        transport: TransportConfig,
    ) -> Result<Self, NetworkFileError> {
        let local: Vec<(ValidatorId, ConsensusPublicKey)> = validators
            .iter()
            .map(|v| (v.validator_id, v.signer.public_key()))
            .collect();
        network.check_hosted(&local)?;
        let available = thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        let (consensus, throughput) = for_core_count(available);
        Ok(Self {
            data_dir,
            genesis: network
                .genesis
                .validators(network.network.clone(), &local)?,
            engine_genesis: network.genesis.engine()?,
            beacon_chain: network.beacon_chain(),
            validators,
            shard_consensus: ShardConsensusConfig::default(),
            mempool: MempoolConfig::default(),
            provisions: ProvisionConfig::default(),
            transport,
            threads: ThreadPoolConfig::builder()
                .consensus_threads(consensus)
                .throughput_threads(throughput)
                .build_unchecked(),
            io_threads: DEFAULT_IO_THREADS,
            storage: RocksDbConfig {
                block_cache_size: Some(DEFAULT_BLOCK_CACHE_MB * 1024 * 1024),
                ..RocksDbConfig::default()
            },
        })
    }
}

/// Why a host did not start or stopped with an error.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The host's tokio runtime could not be built.
    #[error("the host's runtime: {0}")]
    Runtime(IoError),
    /// The consensus or throughput thread pool could not be built.
    #[error("thread pools: {0}")]
    Threads(#[from] ThreadPoolError),
    /// The beacon store under the data directory could not be opened.
    #[error("beacon store at {path}: {reason}")]
    BeaconStore {
        /// The store's directory.
        path: PathBuf,
        /// What `RocksDB` reported.
        reason: String,
    },
    /// The runner could not be built, or stopped with an error.
    #[error("the host stopped: {0}")]
    Runner(#[from] RunnerError),
    /// The runner's task panicked or was cancelled.
    #[error("the host's task ended abnormally: {0}")]
    Task(#[from] JoinError),
    /// The thread tearing the host down panicked.
    #[error("the host's teardown panicked")]
    Teardown,
}

/// A running host. Dropping it stops the host, as [`Node::stop`] does, and
/// finishes tearing it down on a thread of its own without waiting.
pub struct Node {
    status: Arc<ArcSwap<NodeStatusState>>,
    sync_status: Arc<ArcSwap<SyncStatus>>,
    mempool: Arc<ArcSwap<MempoolSnapshot>>,
    tx_status: Arc<TxStatusCache>,
    headers: Arc<HeaderRing>,
    observe: watch::Receiver<Option<Arc<Observation>>>,
    importing: Arc<Importing>,
    shutdown: Option<ShutdownHandle>,
    /// Everything that reaches the host's stores; `None` only once a
    /// teardown has taken it.
    host: Option<Host>,
}

/// What a teardown ends, in the order it ends it.
struct Host {
    running: JoinHandle<Result<(), RunnerError>>,
    runtime: Runtime,
    submit: TxSubmissionSender,
    preview: PreviewSender,
    history: Arc<dyn BeaconChainReader>,
    dispatch: Arc<PooledDispatch>,
}

impl Host {
    /// Waits for the runner, then ends everything it left: the runtime's
    /// tasks and blocking jobs, the handles into the stores, and the pools'
    /// jobs. Runs on a thread with no runtime of its own, so a socket whose
    /// drop hands its close to the current runtime closes here.
    fn tear_down(self) -> Result<(), NodeError> {
        let Self {
            running,
            runtime,
            submit,
            preview,
            history,
            dispatch,
        } = self;
        let outcome = runtime.block_on(running);
        drop(runtime);
        drop((submit, preview, history));
        dispatch.wait_idle();
        outcome??;
        Ok(())
    }

    /// Tears the host down on a fresh thread and waits for it there. A
    /// caller that stops waiting leaves the thread to finish.
    async fn tear_down_apart(self) -> Result<(), NodeError> {
        let (done_tx, done) = oneshot::channel();
        thread::Builder::new()
            .name("host-teardown".into())
            .spawn(move || {
                let _ = done_tx.send(self.tear_down());
            })
            .map_err(NodeError::Runtime)?;
        done.await.unwrap_or(Err(NodeError::Teardown))
    }
}

impl Node {
    /// Opens the host's stores, builds its runner and starts it on a tokio
    /// runtime of the host's own. Callable from anywhere, inside another
    /// runtime or not; it blocks while the stores open and the network binds.
    ///
    /// # Errors
    ///
    /// If the host's runtime, its thread pools or its beacon store cannot be
    /// made, or the runner cannot be built.
    pub fn start(setup: NodeSetup) -> Result<Self, NodeError> {
        let mut runtime = RuntimeBuilder::new_multi_thread();
        runtime.enable_all().thread_name("host-io");
        if setup.io_threads > 0 {
            runtime.worker_threads(setup.io_threads);
        }
        let runtime = runtime.build().map_err(NodeError::Runtime)?;
        // Built on a thread of its own inside the host's runtime: the build
        // takes the current runtime's handle, and a runtime that fails to
        // build a host must drop where blocking is allowed.
        thread::Builder::new()
            .name("host-start".into())
            .spawn(move || Self::build(setup, runtime))
            .map_err(NodeError::Runtime)?
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    /// Builds the host inside `runtime` and starts its runner there.
    fn build(setup: NodeSetup, runtime: Runtime) -> Result<Self, NodeError> {
        let entered = runtime.enter();
        let dispatch = Arc::new(PooledDispatch::new(
            setup.threads,
            runtime.handle().clone(),
        )?);

        let shard_dirs = setup.data_dir.clone();
        let storage_dir: StorageDirResolver =
            Arc::new(move |shard: ShardId| shard_data_dir(&shard_dirs, shard));
        // Opens a shard's store when the runner seats this host on it, at the
        // one directory convention, so a restart reopens what a seat created.
        let shard_storage = setup.storage.clone();
        let storage_factory: StorageFactory = Arc::new(move |dir, shard| {
            RocksDbShardStorage::open_with_config(dir, &shard_storage, shard_prefix_path(shard))
                .map(Arc::new)
                .map_err(|e| format!("failed to open database at {}: {e:?}", dir.display()))
        });

        let beacon_path = setup.data_dir.join("beacon").join("db");
        let beacon_db = Arc::new(
            RocksDbBeaconStorage::open_with_config(&beacon_path, &setup.storage).map_err(|e| {
                NodeError::BeaconStore {
                    path: beacon_path.clone(),
                    reason: format!("{e:?}"),
                }
            })?,
        );
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::clone(&beacon_db) as _;
        let history: Arc<dyn BeaconChainReader> = beacon_db;

        let status = Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default())));
        let sync_status = Arc::new(ArcSwap::new(Arc::new(SyncStatus::default())));
        let mempool = Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default())));

        let mut runner = ProductionRunner::builder(
            setup.validators,
            setup.genesis,
            setup.shard_consensus,
            beacon_storage,
            setup.transport,
            storage_factory,
            storage_dir,
        )
        .dispatch(Arc::clone(&dispatch))
        .rpc_status(Arc::clone(&status))
        .mempool_snapshot(Arc::clone(&mempool))
        .sync_status(Arc::clone(&sync_status))
        .mempool_config(setup.mempool)
        .provision_config(setup.provisions)
        .beacon_chain_config(setup.beacon_chain)
        .genesis_config(setup.engine_genesis)
        .build()?;

        // These panic once `run` has taken the runner, so they are taken now.
        let submit = runner.tx_submission_sender();
        let preview = runner.preview_sender();
        let tx_status = runner.tx_status_cache();
        let headers = runner.header_ring();
        let observe = runner.observe();
        let importing = runner.importing();
        let shutdown = runner.shutdown_handle();
        let running = runtime.spawn(runner.run());
        drop(entered);

        Ok(Self {
            status,
            sync_status,
            mempool,
            tx_status,
            headers,
            observe,
            importing,
            shutdown,
            host: Some(Host {
                running,
                runtime,
                submit,
                preview,
                history,
                dispatch,
            }),
        })
    }

    /// The host's handles; present until a teardown takes them.
    const fn host(&self) -> &Host {
        self.host
            .as_ref()
            .expect("only a teardown, which consumes the node, takes the host")
    }

    /// The host's status: connected peers and, per hosted validator, its
    /// shard, height and view. Refreshed by the runner's status tick.
    #[must_use]
    pub fn status(&self) -> Arc<ArcSwap<NodeStatusState>> {
        Arc::clone(&self.status)
    }

    /// Block sync progress per hosted shard.
    #[must_use]
    pub fn sync_status(&self) -> Arc<ArcSwap<SyncStatus>> {
        Arc::clone(&self.sync_status)
    }

    /// The mempool's counts per hosted validator.
    #[must_use]
    pub fn mempool(&self) -> Arc<ArcSwap<MempoolSnapshot>> {
        Arc::clone(&self.mempool)
    }

    /// Sends a transaction into the network; `false` if the host did not take
    /// it.
    #[must_use]
    pub fn submit(&self) -> TxSubmissionSender {
        Arc::clone(&self.host().submit)
    }

    /// Runs a transaction against committed state without sending it. Blocks,
    /// so call it off the async runtime.
    #[must_use]
    pub fn preview(&self) -> PreviewSender {
        Arc::clone(&self.host().preview)
    }

    /// What became of each transaction this host has seen.
    #[must_use]
    pub fn tx_status(&self) -> Arc<TxStatusCache> {
        Arc::clone(&self.tx_status)
    }

    /// The certified headers this host has seen for `shard` from `since` on,
    /// oldest first: the last hour of them, each with its signers and the
    /// proposers whose rounds failed before it.
    #[must_use]
    pub fn headers(&self, shard: ShardId, since: BlockHeight) -> Vec<HeaderSummary> {
        self.headers.since(shard, since)
    }

    /// What the host's beacon thread has seen, republished after each step
    /// that changed it: the latest committed beacon state, each shard's
    /// newest certified header, and the last day of adopted epochs with
    /// what each settled. `None` until the thread's first step.
    #[must_use]
    pub fn observe(&self) -> watch::Receiver<Option<Arc<Observation>>> {
        self.observe.clone()
    }

    /// The bytes each shard's snap-sync import has staged, for every import
    /// in progress: a shard this host is copying before it can sign.
    #[must_use]
    pub fn importing(&self) -> BTreeMap<ShardId, u64> {
        self.importing.snapshot()
    }

    /// The committed beacon chain, for history the observation does not
    /// carry: any epoch's block and state.
    #[must_use]
    pub fn history(&self) -> Arc<dyn BeaconChainReader> {
        Arc::clone(&self.host().history)
    }

    /// The handle that stops the host, for a caller that stops it from
    /// elsewhere (a signal) while awaiting [`Node::finished`]. `None` once
    /// taken.
    pub const fn take_shutdown(&mut self) -> Option<ShutdownHandle> {
        self.shutdown.take()
    }

    /// Waits for the host to stop on its own or through a taken shutdown
    /// handle, then for everything it started to end: once this returns,
    /// its stores are closed and its sockets released.
    ///
    /// # Errors
    ///
    /// If the host stopped with an error or its task or teardown panicked.
    pub async fn finished(mut self) -> Result<(), NodeError> {
        let Some(host) = self.host.take() else {
            return Ok(());
        };
        // The shutdown handle stays alive until the runner has returned:
        // dropping it would stop the host.
        let outcome = host.tear_down_apart().await;
        drop(self.shutdown.take());
        outcome
    }

    /// Stops the host and waits until it has, and everything it started
    /// has ended: once this returns, its stores are closed and its sockets
    /// released. Dropping the future part way leaves the host to finish
    /// stopping on its own.
    ///
    /// # Errors
    ///
    /// If the host stopped with an error or its task or teardown panicked.
    pub async fn stop(mut self) -> Result<(), NodeError> {
        if let Some(shutdown) = self.shutdown.take() {
            shutdown.shutdown();
        }
        self.finished().await
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let Some(host) = self.host.take() else {
            return;
        };
        if let Some(shutdown) = self.shutdown.take() {
            shutdown.shutdown();
        }
        // Never blocks the dropping context: the teardown runs detached.
        let spawned = thread::Builder::new()
            .name("host-teardown".into())
            .spawn(move || {
                if let Err(e) = host.tear_down() {
                    tracing::warn!(error = %e, "The host stopped with an error");
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "The host's teardown thread did not start");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::for_core_count;

    #[test]
    fn two_cores_go_to_consensus_and_the_rest_to_throughput() {
        assert_eq!(for_core_count(16), (2, 14));
        assert_eq!(for_core_count(32), (2, 30));
        assert_eq!(for_core_count(4), (2, 2));
    }

    #[test]
    fn throughput_keeps_a_thread_when_consensus_takes_every_core() {
        assert_eq!(for_core_count(2), (2, 1));
    }
}
