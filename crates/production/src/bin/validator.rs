//! Hyperscale Validator Node
//!
//! Production binary for running a validator node.
//!
//! # Usage
//!
//! ```bash
//! # Start with configuration file
//! hyperscale-validator --config validator.toml
//!
//! # Override data directory
//! hyperscale-validator --config validator.toml --data-dir /var/lib/hyperscale
//! ```
//!
//! # Configuration
//!
//! See `ValidatorConfig` for all configuration options. Example TOML:
//!
//! ```toml
//! [node]
//! data_dir = "./data"
//!
//! [[vnode]]
//! validator_id = 0
//! key_path = "./keys/v0.key"
//!
//! [network]
//! listen_addr = "/ip4/0.0.0.0/udp/9000/quic-v1"
//! bootstrap_peers = []
//!
//! [threads]
//! consensus_threads = 2
//! throughput_threads = 12
//! io_threads = 2
//!
//! [metrics]
//! enabled = true
//! listen_addr = "0.0.0.0:9090"
//! ```
//!
//! A host can run multiple validators in one process by listing additional
//! `[[vnode]]` blocks. Validators on one shard attach as signers to that
//! shard's one replica, which verifies, executes and commits the chain
//! once for the host; validators on different shards share only the
//! libp2p peer, the beacon loop and the dispatch pools.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use clap::Parser;
use hex::{decode as hex_decode, encode as hex_encode};
use hyperscale_crypto_bls::BlsSigner;
use hyperscale_dispatch_pooled::ThreadPoolConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_production::network_file::{Genesis, network_name};
use hyperscale_production::rpc::{RpcServer, RpcServerConfig};
use hyperscale_production::transport::VersionInteroperabilityMode;
use hyperscale_production::{
    DEFAULT_BLOCK_CACHE_MB, LocalValidator, Node, NodeSetup, TelemetryConfig, TelemetryGuard,
    for_core_count, init_telemetry,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage_rocksdb::{CompressionType as RocksCompressionType, RocksDbConfig};
use hyperscale_types::{
    BeaconChainConfig, ConsensusPublicKey, NetworkDefinition, Signer, ValidatorId,
};
use serde::Deserialize;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::signal;
use tokio::task::spawn;
use toml::from_str as toml_from_str;
use tracing::{info, warn};
use tracing_appender::non_blocking as wrap_non_blocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::never;
use tracing_subscriber::{EnvFilter, fmt};

#[cfg_attr(feature = "iroh", path = "validator/network_iroh.rs")]
#[cfg_attr(not(feature = "iroh"), path = "validator/network_libp2p.rs")]
mod network;

use network::{NetworkConfig, build_network_config};

/// Hyperscale Validator Node
///
/// Runs a production validator participating in shard consensus.
#[derive(Parser, Debug)]
#[command(name = "hyperscale-validator")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to configuration file (TOML)
    #[arg(short, long)]
    config: PathBuf,

    /// Data directory for `RocksDB` (overrides config). Per-shard
    /// `RocksDB` instances are opened at `data_dir/shard-{N}/db`.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Metrics listen address (overrides config)
    #[arg(long)]
    metrics_addr: Option<String>,

    /// Bootstrap peer multiaddresses (can be specified multiple times)
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Log level filter (overrides `RUST_LOG`)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Disable `UPnP` port forwarding (overrides config)
    #[arg(long)]
    no_upnp: bool,

    /// Version interoperability mode (strict, relaxed, off)
    #[arg(long)]
    version_interop_mode: Option<VersionInteroperabilityMode>,

    /// Clean the data directory on startup
    #[arg(long)]
    clean: bool,

    /// Path to log file (redirects all logs to this file)
    #[arg(long)]
    logfile: Option<PathBuf>,
}

/// Top-level validator configuration.
///
/// `deny_unknown_fields` rejects stray top-level keys so a stale config —
/// e.g. an obsolete `shard`/`num_shards` line, now derived from beacon
/// state — fails loudly at load rather than being silently dropped.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidatorConfig {
    /// Host-level identity configuration
    pub(crate) node: NodeConfig,

    /// Hosted validators. One entry per validator this process runs. A
    /// single-validator deployment has exactly one block; multi-validator
    /// hosts list one block per identity. Entries on one shard attach as
    /// signers to that shard's one replica and its storage; each shard
    /// the host carries gets its own `ShardIo`.
    #[serde(rename = "vnode", default)]
    pub(crate) vnodes: Vec<VnodeEntry>,

    /// Network configuration
    #[serde(default)]
    pub(crate) network: NetworkConfig,

    /// Thread pool configuration
    #[serde(default)]
    pub(crate) threads: ThreadsConfig,

    /// Storage configuration
    #[serde(default)]
    pub(crate) storage: StorageConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfigToml,

    /// Genesis configuration (validators in the network)
    #[serde(default)]
    pub genesis: Genesis,

    /// Mempool configuration
    #[serde(default)]
    pub(crate) mempool: MempoolConfig,

    /// Provision coordinator configuration
    #[serde(default)]
    pub(crate) provisions: ProvisionConfig,
}

/// Host-level identity configuration. Per-validator identity lives in
/// [`VnodeEntry`].
///
/// `deny_unknown_fields` rejects obsolete keys — notably the dropped
/// `shard`/`num_shards`, now projected from beacon state.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeConfig {
    /// Network this node is configured for. Bound into every
    /// signed consensus message to prevent cross-network replay.
    /// Parsed from a network name (`"mainnet"`, `"testnet"`,
    /// `"simulator"`, etc.) via [`NetworkDefinition::from_str`](std::str::FromStr::from_str).
    #[serde(default = "default_network", with = "network_name")]
    pub(crate) network: NetworkDefinition,

    /// Data directory for storage. Per-shard `RocksDB` instances are
    /// opened at `data_dir/shard-{N}/db`.
    #[serde(default = "default_data_dir")]
    pub(crate) data_dir: PathBuf,
}

fn default_network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// One hosted validator's identity inputs.
///
/// No shard is named here — shard participation is a projection of beacon
/// state, derived by the runner at startup (an obsolete `shard = N` line in
/// an existing config is ignored).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VnodeEntry {
    /// Validator ID (index in the committee)
    pub(crate) validator_id: u64,

    /// Path to this validator's signing key file
    pub(crate) key_path: PathBuf,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

/// Thread pool configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct ThreadsConfig {
    /// Threads in the consensus pool (0 = auto). Liveness-critical work
    /// — block votes, QC verification, state root, proposal building.
    #[serde(default)]
    pub(crate) consensus_threads: usize,

    /// Threads in the throughput pool (0 = auto). General crypto
    /// verification, transaction signature validation, and engine
    /// execution share this pool; in-handler `par_iter` fans batches
    /// across the same workers.
    #[serde(default)]
    pub(crate) throughput_threads: usize,

    /// Number of tokio runtime worker threads (0 = auto).
    /// Controls the async I/O runtime used for networking, timers, and RPC.
    #[serde(default)]
    pub(crate) io_threads: usize,

    /// Enable CPU core pinning (Linux only)
    #[serde(default)]
    pub(crate) pin_cores: bool,
}

/// Compression type for storage (maps to `RocksDB` compression).
#[allow(missing_docs)] // codec names are self-explanatory
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CompressionType {
    None,
    Snappy,
    Zlib,
    #[default]
    Lz4,
    Lz4hc,
    Zstd,
}

impl From<CompressionType> for RocksCompressionType {
    fn from(ct: CompressionType) -> Self {
        match ct {
            CompressionType::None => Self::None,
            CompressionType::Snappy => Self::Snappy,
            CompressionType::Zlib => Self::Zlib,
            CompressionType::Lz4 => Self::Lz4,
            CompressionType::Lz4hc => Self::Lz4hc,
            CompressionType::Zstd => Self::Zstd,
        }
    }
}

/// Storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StorageConfig {
    /// Maximum background jobs for `RocksDB`
    #[serde(default = "default_max_background_jobs")]
    pub(crate) max_background_jobs: i32,

    /// Write buffer size in MB
    #[serde(default = "default_write_buffer_mb")]
    pub(crate) write_buffer_mb: usize,

    /// Maximum number of write buffers
    #[serde(default = "default_max_write_buffer_number")]
    pub(crate) max_write_buffer_number: i32,

    /// Block cache size in MB (0 to disable)
    #[serde(default = "default_block_cache_mb")]
    pub(crate) block_cache_mb: usize,

    /// Compression type (none, snappy, zlib, lz4, lz4hc, zstd)
    #[serde(default)]
    pub(crate) compression: CompressionType,

    /// Bloom filter bits per key (0 to disable)
    #[serde(default = "default_bloom_filter_bits")]
    pub(crate) bloom_filter_bits: f64,

    /// Bytes per sync in MB (0 to disable)
    #[serde(default = "default_bytes_per_sync_mb")]
    pub(crate) bytes_per_sync_mb: usize,

    /// Number of log files to keep
    #[serde(default = "default_keep_log_file_num")]
    pub(crate) keep_log_file_num: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_background_jobs: default_max_background_jobs(),
            write_buffer_mb: default_write_buffer_mb(),
            max_write_buffer_number: default_max_write_buffer_number(),
            block_cache_mb: default_block_cache_mb(),
            compression: CompressionType::default(),
            bloom_filter_bits: default_bloom_filter_bits(),
            bytes_per_sync_mb: default_bytes_per_sync_mb(),
            keep_log_file_num: default_keep_log_file_num(),
        }
    }
}

const fn default_max_background_jobs() -> i32 {
    4
}

const fn default_write_buffer_mb() -> usize {
    128
}

const fn default_max_write_buffer_number() -> i32 {
    3
}

const fn default_block_cache_mb() -> usize {
    DEFAULT_BLOCK_CACHE_MB
}

const fn default_bloom_filter_bits() -> f64 {
    10.0
}

const fn default_bytes_per_sync_mb() -> usize {
    1
}

const fn default_keep_log_file_num() -> usize {
    10
}

/// Metrics configuration.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetricsConfig {
    /// Enable metrics endpoint
    #[serde(default = "default_metrics_enabled")]
    pub(crate) enabled: bool,

    /// Metrics HTTP listen address
    #[serde(default = "default_metrics_addr")]
    pub(crate) listen_addr: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            listen_addr: default_metrics_addr(),
        }
    }
}

const fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_addr() -> String {
    "0.0.0.0:9090".to_string()
}

/// Telemetry configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct TelemetryConfigToml {
    /// Enable OpenTelemetry tracing
    #[serde(default)]
    pub(crate) enabled: bool,

    /// OTLP endpoint for traces
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub(crate) service_name: String,

    /// Optional log file path. If provided, logs are written to this file.
    #[serde(default)]
    pub(crate) log_file: Option<PathBuf>,
}

fn default_service_name() -> String {
    "hyperscale-validator".to_string()
}

impl ValidatorConfig {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if its contents fail to
    /// parse as TOML in the [`ValidatorConfig`] schema.
    pub(crate) fn load(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml_from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Apply CLI overrides to the configuration.
    fn apply_overrides(&mut self, cli: &Cli) {
        if let Some(ref data_dir) = cli.data_dir {
            self.node.data_dir.clone_from(data_dir);
        }

        if let Some(ref metrics_addr) = cli.metrics_addr {
            self.metrics.listen_addr.clone_from(metrics_addr);
        }

        if !cli.bootstrap.is_empty() {
            self.network.bootstrap_peers.extend(cli.bootstrap.clone());
        }

        if cli.no_upnp {
            self.network.upnp_enabled = false;
        }

        if let Some(mode) = cli.version_interop_mode {
            self.network.version_interop_mode = Some(mode);
        }

        if let Some(ref logfile) = cli.logfile {
            self.telemetry.log_file = Some(logfile.clone());
        }
    }
}

/// Format a public key as a hex string.
fn format_public_key(pk: &ConsensusPublicKey) -> String {
    hex_encode(pk.as_bytes())
}

/// Load or generate a signing keypair.
///
/// The key file stores a 32-byte seed that deterministically generates the keypair.
/// This seed can be stored as raw bytes or hex-encoded.
fn load_or_generate_signer(key_path: Option<&PathBuf>) -> Result<BlsSigner> {
    use rand::{Rng, rng};

    let Some(path) = key_path else {
        warn!("No key path specified, generating ephemeral keypair");
        let mut seed = [0u8; 32];
        rng().fill_bytes(&mut seed);
        return Ok(BlsSigner::from_seed(&seed));
    };

    if path.exists() {
        let key_bytes = fs::read(path)
            .with_context(|| format!("Failed to read key file: {}", path.display()))?;

        let decoded = if key_bytes.len() == 64 {
            hex_decode(&key_bytes).with_context(|| "Failed to decode hex key")?
        } else if key_bytes.len() == 32 {
            key_bytes
        } else {
            bail!(
                "Invalid key file size: expected 32 bytes (raw) or 64 hex chars, got {} bytes",
                key_bytes.len()
            );
        };

        let seed: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("Key must be exactly 32 bytes"))?;

        Ok(BlsSigner::from_seed(&seed))
    } else {
        info!("Key file not found, generating new keypair");

        let mut seed = [0u8; 32];
        rng().fill_bytes(&mut seed);

        let keypair = BlsSigner::from_seed(&seed);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private_seed(path, &seed)
            .with_context(|| format!("Failed to write key file: {}", path.display()))?;
        info!("Saved new keypair seed to {}", path.display());

        Ok(keypair)
    }
}

/// Write a freshly generated signing seed to `path`.
///
/// The file is created owner-only on unix: `fs::write` would take the
/// process umask, which typically leaves private key material
/// world-readable. Creation is exclusive, so a key that appeared since
/// the existence check is an error rather than something to overwrite.
fn write_private_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?.write_all(seed)?;
    Ok(())
}

/// Build thread pool configuration from TOML config.
///
/// When TOML values are 0 (auto), computes thread counts based on
/// available cores. The I/O (tokio) thread count is returned separately
/// since it is not part of the rayon pool configuration.
fn build_thread_pool_config(config: &ThreadsConfig) -> ThreadPoolConfig {
    let all_auto = config.consensus_threads == 0 && config.throughput_threads == 0;

    let mut builder = if all_auto {
        let available = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
        let (consensus, throughput) = for_core_count(available);
        ThreadPoolConfig::builder()
            .consensus_threads(consensus)
            .throughput_threads(throughput)
    } else {
        let mut b = ThreadPoolConfig::builder();
        if config.consensus_threads > 0 {
            b = b.consensus_threads(config.consensus_threads);
        }
        if config.throughput_threads > 0 {
            b = b.throughput_threads(config.throughput_threads);
        }
        b
    };

    if config.pin_cores {
        builder = builder.pin_cores(true);
    }

    builder.build_unchecked()
}

/// Build `RocksDB` configuration from TOML config.
fn build_rocksdb_config(config: &StorageConfig) -> RocksDbConfig {
    RocksDbConfig {
        max_background_jobs: config.max_background_jobs,
        write_buffer_size: config.write_buffer_mb * 1024 * 1024,
        max_write_buffer_number: config.max_write_buffer_number,
        block_cache_size: if config.block_cache_mb > 0 {
            Some(config.block_cache_mb * 1024 * 1024)
        } else {
            None
        },
        compression: config.compression.into(),
        bloom_filter_bits: config.bloom_filter_bits,
        bytes_per_sync: config.bytes_per_sync_mb * 1024 * 1024,
        keep_log_file_num: config.keep_log_file_num,
    }
}

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration first (before runtime construction) to read io_threads
    let mut config = ValidatorConfig::load(&cli.config)?;
    config.apply_overrides(&cli);

    // Build tokio runtime with configurable worker threads.
    // io_threads = 0 means auto (tokio default: one thread per CPU core).
    let mut rt_builder = RuntimeBuilder::new_multi_thread();
    rt_builder.enable_all();
    if config.threads.io_threads > 0 {
        rt_builder.worker_threads(config.threads.io_threads);
    }
    let rt = rt_builder
        .build()
        .context("Failed to build tokio runtime")?;

    rt.block_on(async_main(cli, config))
}

#[allow(clippy::too_many_lines)] // straight-line startup wiring; helpers would just shuffle locals
async fn async_main(cli: Cli, config: ValidatorConfig) -> Result<()> {
    // If telemetry is enabled, init_telemetry sets up the global subscriber with OTLP export;
    // otherwise the basic fmt subscriber is used.
    #[allow(dead_code)]
    enum UnifiedGuard {
        Telemetry(TelemetryGuard),
        Basic(Option<WorkerGuard>),
    }

    // Telemetry's `validator` resource attribute reports the primary
    // (first-listed) vnode's id. Shard participation is beacon-derived and
    // can change over the node's life, so it isn't a stable startup label.
    let primary_validator_label = config.vnodes.first().map_or(0, |v| v.validator_id);

    let _log_guard = if config.telemetry.enabled {
        let telemetry_config = TelemetryConfig {
            service_name: config.telemetry.service_name.clone(),
            otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
            sampling_ratio: 1.0,
            prometheus_enabled: false, // We handle metrics separately
            prometheus_port: 9090,
            resource_attributes: vec![(
                "validator".to_string(),
                primary_validator_label.to_string(),
            )],
            log_file: config.telemetry.log_file.clone(),
        };
        UnifiedGuard::Telemetry(init_telemetry(&telemetry_config)?)
    } else {
        // Basic logging without OTLP export
        let builder = fmt();

        let inner_guard = if let Some(log_file) = &config.telemetry.log_file {
            if let Some(parent) = log_file.parent() {
                fs::create_dir_all(parent)?;
            }
            let file_name = log_file
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid log file name"))?
                .to_string_lossy()
                .to_string();
            let directory = log_file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();

            let file_appender = never(directory, file_name);
            let (non_blocking_writer, guard) = wrap_non_blocking(file_appender);

            builder
                .with_writer(non_blocking_writer)
                .with_ansi(false) // Disable ANSI colors in file logs
                .with_target(true)
                .with_thread_ids(true)
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
                )
                .init();
            Some(guard)
        } else {
            builder
                .with_env_filter(
                    EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
                )
                .init();
            None
        };
        UnifiedGuard::Basic(inner_guard)
    };

    info!("Hyperscale Validator starting...");

    info!(
        hosted_vnodes = config.vnodes.len(),
        "Host configuration loaded"
    );
    for v in &config.vnodes {
        info!(validator_id = v.validator_id, "Hosting vnode");
    }

    // Clean data directory if requested via cli parameter
    if cli.clean {
        if config.node.data_dir.exists() {
            info!(
                "Cleaning data directory: {}",
                config.node.data_dir.display()
            );
            fs::remove_dir_all(&config.node.data_dir).with_context(|| {
                format!(
                    "Failed to clean data directory: {}",
                    config.node.data_dir.display()
                )
            })?;
        } else {
            info!(
                "Skipping clean: Data directory does not exist: {}",
                config.node.data_dir.display()
            );
        }
    }

    fs::create_dir_all(&config.node.data_dir)?;

    #[cfg(not(feature = "iroh"))]
    network::setup_upnp(&config.network).await;

    if config.vnodes.is_empty() {
        bail!(
            "No [[vnode]] entries in configuration; at least one is required. \
             Add a [[vnode]] block with validator_id, shard, and key_path."
        );
    }

    let thread_config = build_thread_pool_config(&config.threads);
    let shard_config = ShardConsensusConfig::default();
    let network_config = build_network_config(&config)?;
    let beacon_chain_config = BeaconChainConfig::production();
    let rocksdb_config = build_rocksdb_config(&config.storage);

    // Pass 1: load every hosted vnode's signing keypair so the topology builder
    // can substitute trusted local public keys for genesis-hex pubkeys.
    // Ordered Vec — single-validator mode picks the first entry, so source
    // order must be the same as config.vnodes.
    let mut hosted_signers: Vec<(ValidatorId, Arc<BlsSigner>)> =
        Vec::with_capacity(config.vnodes.len());
    for entry in &config.vnodes {
        let keypair = load_or_generate_signer(Some(&entry.key_path))?;
        info!(
            validator_id = entry.validator_id,
            public_key = %format_public_key(&keypair.public_key()),
            "Loaded vnode signing keypair"
        );
        hosted_signers.push((ValidatorId::new(entry.validator_id), Arc::new(keypair)));
    }

    // Build the host's genesis validators. Genesis is always a single ROOT
    // shard; the network grows to its target topology by splitting under load.
    // The runner projects the host's topology snapshot from this.
    let local_keys: Vec<(ValidatorId, ConsensusPublicKey)> = hosted_signers
        .iter()
        .map(|(validator_id, signer)| (*validator_id, signer.public_key()))
        .collect();
    let genesis_validators = config
        .genesis
        .validators(config.node.network.clone(), &local_keys)?;

    // The validators this host runs. Shard participation is not named here —
    // the runner derives each validator's seat (or pool membership) from the
    // committed beacon state and opens any seated shard's storage itself.
    let validators: Vec<LocalValidator> = hosted_signers
        .iter()
        .map(|(validator_id, signer)| LocalValidator {
            validator_id: *validator_id,
            signer: Arc::clone(signer) as Arc<dyn Signer>,
        })
        .collect();

    let mut node = Node::start(NodeSetup {
        data_dir: config.node.data_dir.clone(),
        validators,
        genesis: genesis_validators,
        engine_genesis: config
            .genesis
            .engine()
            .context("Failed to parse genesis configuration")?,
        beacon_chain: beacon_chain_config,
        shard_consensus: shard_config,
        mempool: config.mempool.clone(),
        provisions: config.provisions,
        transport: network_config,
        threads: thread_config,
        storage: rocksdb_config,
    })
    .context("Failed to start the node")?;

    let rpc_ready = Arc::new(AtomicBool::new(false));
    let rpc_handle = if config.metrics.enabled {
        let rpc_config = RpcServerConfig {
            listen_addr: config.metrics.listen_addr.parse().with_context(|| {
                format!(
                    "Invalid metrics listen address: {}",
                    config.metrics.listen_addr
                )
            })?,
            metrics_enabled: true,
            sync_backpressure_threshold: Some(10),
        };

        let rpc_server = RpcServer::with_state(
            rpc_config,
            rpc_ready.clone(),
            node.sync_status(),
            node.status(),
            node.submit(),
            node.preview(),
            node.tx_status(),
            node.mempool(),
        );
        let handle = rpc_server
            .start()
            .await
            .context("Failed to start RPC server")?;

        Some(handle)
    } else {
        None
    };

    let shutdown_handle = node.take_shutdown();

    spawn(async move {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            () = ctrl_c => info!("Received Ctrl+C"),
            () = terminate => info!("Received SIGTERM"),
        }

        if let Some(handle) = shutdown_handle {
            info!("Initiating graceful shutdown...");
            handle.shutdown();
        }
    });

    if let Some(ref handle) = rpc_handle {
        handle.set_ready(true);
    }

    info!("Validator node started, press Ctrl+C to stop");

    if let Err(e) = node.finished().await {
        bail!("Runner error: {e}");
    }

    if let Some(handle) = rpc_handle {
        handle.abort();
    }

    info!("Validator shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("validator.key");
        let seed = [7u8; 32];

        write_private_seed(&path, &seed).expect("write seed");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "key file must carry no group or other permissions, got {mode:o}"
        );
        assert_eq!(fs::read(&path).expect("read back").as_slice(), &seed);
        assert!(
            write_private_seed(&path, &[9u8; 32]).is_err(),
            "an existing key must not be overwritten"
        );
    }

    #[test]
    fn test_build_thread_pool_config_auto() {
        let config = ThreadsConfig::default();
        let pool_config = build_thread_pool_config(&config);
        assert!(pool_config.consensus_threads >= 2);
        assert!(pool_config.throughput_threads >= 1);
    }

    #[test]
    fn test_build_thread_pool_config_explicit() {
        let config = ThreadsConfig {
            consensus_threads: 3,
            throughput_threads: 14,
            io_threads: 0,
            pin_cores: false,
        };
        let pool_config = build_thread_pool_config(&config);
        assert_eq!(pool_config.consensus_threads, 3);
        assert_eq!(pool_config.throughput_threads, 14);
    }

    /// The shipped example config must satisfy the `deny_unknown_fields`
    /// guard: renaming or dropping a field must update the example in
    /// lockstep, or an operator's copy of it fails to load.
    #[test]
    fn example_config_parses() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/validator.example.toml");
        ValidatorConfig::load(&path).expect("shipped example config parses");
    }
}
