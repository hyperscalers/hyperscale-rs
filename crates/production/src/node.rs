//! A validator host started from a library.
//!
//! [`Node::start`] opens the storage, the beacon store and the runner a host
//! needs at the data directory's one layout, and hands back the owner that
//! stops it; every call an embedder makes goes through its [`NodeHandle`]. The host runs on a tokio runtime and thread pools
//! of its own, so stopping it ends everything it started. It installs nothing
//! process-global beyond the first-wins statics the runner already sets;
//! tracing, signals and the allocator stay with the embedder.

use std::fs::{File, OpenOptions, TryLockError, create_dir_all};
use std::io::Error as IoError;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use hyperscale_core::Gate;
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig, ThreadPoolError};
use hyperscale_engine::GenesisConfig as EngineGenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_iroh::IrohConfig;
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::BeaconStorage;
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbConfig, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, ConsensusPublicKey, GenesisValidators, ShardId, ValidatorId,
    shard_prefix_path,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle};

use crate::handle::{HostCalls, NodeHandle};
use crate::network_file::{NetworkFile, NetworkFileError};
use crate::{
    AddValidatorError, LocalValidator, ProductionRunner, RunnerError, ShutdownHandle,
    StorageDirResolver, StorageFactory, shard_data_dir,
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
    /// The iroh transport's configuration.
    pub transport: IrohConfig,
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
        transport: IrohConfig,
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
    /// Another host holds the data directory.
    #[error("another host holds the data at {path}")]
    InUse {
        /// The data directory.
        path: PathBuf,
    },
    /// The data directory could not be made or locked.
    #[error("data directory {path}: {reason}")]
    DataDir {
        /// The data directory.
        path: PathBuf,
        /// What the file system reported.
        reason: String,
    },
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
    /// The running host would not take on a validator.
    #[error("adding a validator: {0}")]
    AddValidator(#[from] AddValidatorError),
    /// The host is no longer running.
    #[error("the host has stopped")]
    Stopped,
}

/// A running host's owner, which stops it and waits for it.
///
/// Dropping it stops the host, as [`Node::stop`] does, and finishes tearing
/// it down on a thread of its own without waiting. Every other call goes
/// through its [`NodeHandle`].
pub struct Node {
    handle: NodeHandle,
    shutdown: Option<ShutdownHandle>,
    /// Everything that reaches the host's stores; `None` only once a
    /// teardown has taken it.
    teardown: Option<Teardown>,
}

/// What a teardown ends, in the order it ends it.
struct Teardown {
    running: JoinHandle<Result<(), RunnerError>>,
    runtime: Runtime,
    /// Every handle call passes it.
    gate: Arc<Gate>,
    /// The one strong reference to what handle calls reach.
    calls: Arc<HostCalls>,
    dispatch: Arc<PooledDispatch>,
    /// The data directory's lock, released once every store has closed.
    lock: File,
}

impl Teardown {
    /// Waits for the runner, then refuses further handle calls and ends
    /// everything the runner left: the runtime's tasks and blocking jobs,
    /// the calls already in, the handles into the stores, and the pools'
    /// jobs. Runs on a thread with no runtime of its own, so a socket whose
    /// drop hands its close to the current runtime closes here.
    fn tear_down(self) -> Result<(), NodeError> {
        let Self {
            running,
            runtime,
            gate,
            calls,
            dispatch,
            lock,
        } = self;
        let outcome = runtime.block_on(running);
        gate.close();
        // A call still in that waits on the host's runtime, a preview's
        // blocking job, ends with it.
        drop(runtime);
        gate.close_and_wait();
        drop(calls);
        dispatch.wait_idle();
        drop(lock);
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

        let lock = lock_data_dir(&setup.data_dir)?;
        let beacon_path = beacon_data_dir(&setup.data_dir).join("db");
        let beacon_db = Arc::new(
            RocksDbBeaconStorage::open_with_config(&beacon_path, &setup.storage).map_err(|e| {
                NodeError::BeaconStore {
                    path: beacon_path.clone(),
                    reason: format!("{e:?}"),
                }
            })?,
        );
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::clone(&beacon_db) as _;

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
        .mempool_config(setup.mempool)
        .provision_config(setup.provisions)
        .beacon_chain_config(setup.beacon_chain)
        .genesis_config(setup.engine_genesis)
        .build()?;

        // The senders panic once `run` has taken the runner, so they are
        // taken now.
        let network = Arc::clone(runner.network());
        let calls = Arc::new(HostCalls {
            submit: runner.tx_submission_sender(),
            preview: runner.preview_sender(),
            history: beacon_db,
            publishers: runner.publishers(),
            tx_status: runner.tx_status_cache(),
            peers: Box::new(move || network.cached_peer_count()),
            commands: runner.reconfigure_handle(),
            runtime: runtime.handle().clone(),
        });
        let gate = Arc::new(Gate::new());
        let shutdown = runner.shutdown_handle();
        let running = runtime.spawn(runner.run());
        drop(entered);

        Ok(Self {
            handle: NodeHandle::new(&calls, Arc::clone(&gate)),
            shutdown,
            teardown: Some(Teardown {
                running,
                runtime,
                gate,
                calls,
                dispatch,
                lock,
            }),
        })
    }

    /// The handle every call on the running host goes through. Clones are
    /// cheap; one kept past the host's stop answers empty.
    #[must_use]
    pub fn handle(&self) -> NodeHandle {
        self.handle.clone()
    }

    /// The handle that stops the host, for a caller that stops it from
    /// elsewhere (a signal) while awaiting [`Node::finished`]. `None` once
    /// taken.
    pub const fn take_shutdown(&mut self) -> Option<ShutdownHandle> {
        self.shutdown.take()
    }

    /// Waits for the host to stop on its own or through a taken shutdown
    /// handle, then for everything it started to end: once this returns,
    /// its stores are closed and its sockets released. Handle calls run
    /// until the host has stopped, and are refused from then on.
    ///
    /// # Errors
    ///
    /// If the host stopped with an error or its task or teardown panicked.
    pub async fn finished(mut self) -> Result<(), NodeError> {
        let Some(teardown) = self.teardown.take() else {
            return Ok(());
        };
        // The shutdown handle stays alive until the runner has returned:
        // dropping it would stop the host.
        let outcome = teardown.tear_down_apart().await;
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

/// Where the host keeps its beacon store under the data directory `root`.
#[must_use]
pub fn beacon_data_dir(root: &Path) -> PathBuf {
    root.join("beacon")
}

/// Makes the data directory and takes its lock, held for the host's life.
/// The lock is advisory, between hosts: a second host on the same data is
/// refused before it opens a store.
fn lock_data_dir(root: &Path) -> Result<File, NodeError> {
    let failed = |e: IoError| NodeError::DataDir {
        path: root.to_path_buf(),
        reason: e.to_string(),
    };
    create_dir_all(root).map_err(failed)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("host.lock"))
        .map_err(failed)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(NodeError::InUse {
            path: root.to_path_buf(),
        }),
        Err(TryLockError::Error(e)) => Err(failed(e)),
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let Some(teardown) = self.teardown.take() else {
            return;
        };
        if let Some(shutdown) = self.shutdown.take() {
            shutdown.shutdown();
        }
        // Never blocks the dropping context: the teardown runs detached.
        let spawned = thread::Builder::new()
            .name("host-teardown".into())
            .spawn(move || {
                if let Err(e) = teardown.tear_down() {
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
