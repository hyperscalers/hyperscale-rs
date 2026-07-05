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
//! `[[vnode]]` blocks. Same-shard vnodes share storage, fetch state, and
//! gossipsub subscriptions; different-shard vnodes share only the libp2p
//! peer and dispatch pools.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use clap::Parser;
use hex::{decode as hex_decode, encode as hex_encode};
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
use hyperscale_engine::GenesisConfig as EngineGenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_libp2p::{Libp2pConfig, VersionInteroperabilityMode};
use hyperscale_production::rpc::{MempoolSnapshot, NodeStatusState, RpcServer, RpcServerConfig};
use hyperscale_production::{
    LocalValidator, ProductionRunner, StorageDirResolver, StorageFactory, SyncStatus,
    TelemetryConfig, TelemetryGuard, init_telemetry, shard_data_dir,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::BeaconStorage;
use hyperscale_storage_rocksdb::{
    CompressionType as RocksCompressionType, RocksDbBeaconStorage, RocksDbConfig,
    RocksDbShardStorage,
};
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, GenesisValidators, ShardId, ValidatorId,
    ValidatorInfo, ValidatorSet, bls_keypair_from_seed, generate_bls_keypair, shard_prefix_path,
};
use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use radix_common::network::NetworkDefinition;
use radix_common::prelude::AddressBech32Decoder;
use serde::Deserialize;
use tokio::runtime::{Builder as RuntimeBuilder, Handle as TokioHandle};
use tokio::signal;
use tokio::task::spawn;
use toml::from_str as toml_from_str;
use tracing::{info, warn};
use tracing_appender::non_blocking as wrap_non_blocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::never;
use tracing_subscriber::{EnvFilter, fmt};

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
pub struct ValidatorConfig {
    /// Host-level identity configuration
    pub node: NodeConfig,

    /// Hosted validators. One entry per validator this process runs. A
    /// single-validator deployment has exactly one block; multi-validator
    /// hosts list one block per identity. Same-shard entries share
    /// storage and gossipsub subscriptions; different-shard entries
    /// additionally provision a per-shard `ShardIo`.
    #[serde(rename = "vnode", default)]
    pub vnodes: Vec<VnodeEntry>,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Thread pool configuration
    #[serde(default)]
    pub threads: ThreadsConfig,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfigToml,

    /// Genesis configuration (validators in the network)
    #[serde(default)]
    pub genesis: GenesisConfig,

    /// Mempool configuration
    #[serde(default)]
    pub mempool: MempoolConfig,

    /// Provision coordinator configuration
    #[serde(default)]
    pub provisions: ProvisionConfig,
}

/// Host-level identity configuration. Per-validator identity lives in
/// [`VnodeEntry`].
///
/// `deny_unknown_fields` rejects obsolete keys — notably the dropped
/// `shard`/`num_shards`, now projected from beacon state.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Radix network this node is configured for. Bound into every
    /// BLS-signed consensus message to prevent cross-network replay.
    /// Parsed from a network name (`"mainnet"`, `"stokenet"`,
    /// `"simulator"`, etc.) via [`NetworkDefinition::from_str`].
    #[serde(default = "default_network", with = "network_serde")]
    pub network: NetworkDefinition,

    /// Data directory for storage. Per-shard `RocksDB` instances are
    /// opened at `data_dir/shard-{N}/db`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

const fn default_network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// `serde` adapter that parses `NetworkDefinition` from its logical name.
///
/// `NetworkDefinition` doesn't impl `Deserialize` directly because its
/// `logical_name` / `hrp_suffix` fields are derived from `id` — the
/// canonical wire representation is the name string.
mod network_serde {
    use std::str::FromStr;

    use radix_common::network::NetworkDefinition;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NetworkDefinition, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        NetworkDefinition::from_str(&name).map_err(|_| {
            D::Error::custom(format!(
                "unknown network `{name}` (expected one of: mainnet, stokenet, simulator, ...)"
            ))
        })
    }
}

/// One hosted validator's identity inputs.
///
/// No shard is named here — shard participation is a projection of beacon
/// state, derived by the runner at startup (an obsolete `shard = N` line in
/// an existing config is ignored).
#[derive(Debug, Clone, Deserialize)]
pub struct VnodeEntry {
    /// Validator ID (index in the committee)
    pub validator_id: u64,

    /// Path to this validator's signing key file
    pub key_path: PathBuf,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

/// Network configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// QUIC listen address (multiaddr format, e.g., "/ip4/0.0.0.0/udp/9000/quic-v1")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Bootstrap peer addresses
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval in milliseconds
    #[serde(default = "default_gossipsub_heartbeat_ms")]
    pub gossipsub_heartbeat_ms: u64,

    /// Enable `UPnP` port forwarding
    #[serde(default = "default_upnp_enabled")]
    pub upnp_enabled: bool,

    /// Version interoperability mode
    pub version_interop_mode: Option<VersionInteroperabilityMode>,

    /// Idle connection timeout in milliseconds
    #[serde(default = "default_idle_connection_timeout_ms")]
    pub idle_connection_timeout_ms: u64,

    /// QUIC keep-alive interval in milliseconds
    #[serde(default = "default_keep_alive_interval_ms")]
    pub keep_alive_interval_ms: u64,
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/udp/9000/quic-v1".to_string()
}

const fn default_max_message_size() -> usize {
    65536
}

const fn default_gossipsub_heartbeat_ms() -> u64 {
    300
}

const fn default_upnp_enabled() -> bool {
    true
}

const fn default_idle_connection_timeout_ms() -> u64 {
    60_000
}

const fn default_keep_alive_interval_ms() -> u64 {
    15_000
}

/// Thread pool configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThreadsConfig {
    /// Threads in the consensus pool (0 = auto). Liveness-critical work
    /// — block votes, QC verification, state root, proposal building.
    #[serde(default)]
    pub consensus_threads: usize,

    /// Threads in the throughput pool (0 = auto). General crypto
    /// verification, transaction signature validation, and Radix Engine
    /// execution share this pool; in-handler `par_iter` fans batches
    /// across the same workers.
    #[serde(default)]
    pub throughput_threads: usize,

    /// Number of tokio runtime worker threads (0 = auto).
    /// Controls the async I/O runtime used for networking, timers, and RPC.
    #[serde(default)]
    pub io_threads: usize,

    /// Enable CPU core pinning (Linux only)
    #[serde(default)]
    pub pin_cores: bool,
}

/// Compression type for storage (maps to `RocksDB` compression).
#[allow(missing_docs)] // codec names are self-explanatory
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionType {
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
pub struct StorageConfig {
    /// Maximum background jobs for `RocksDB`
    #[serde(default = "default_max_background_jobs")]
    pub max_background_jobs: i32,

    /// Write buffer size in MB
    #[serde(default = "default_write_buffer_mb")]
    pub write_buffer_mb: usize,

    /// Maximum number of write buffers
    #[serde(default = "default_max_write_buffer_number")]
    pub max_write_buffer_number: i32,

    /// Block cache size in MB (0 to disable)
    #[serde(default = "default_block_cache_mb")]
    pub block_cache_mb: usize,

    /// Compression type (none, snappy, zlib, lz4, lz4hc, zstd)
    #[serde(default)]
    pub compression: CompressionType,

    /// Bloom filter bits per key (0 to disable)
    #[serde(default = "default_bloom_filter_bits")]
    pub bloom_filter_bits: f64,

    /// Bytes per sync in MB (0 to disable)
    #[serde(default = "default_bytes_per_sync_mb")]
    pub bytes_per_sync_mb: usize,

    /// Number of log files to keep
    #[serde(default = "default_keep_log_file_num")]
    pub keep_log_file_num: usize,

    /// Number of block heights of JMT history to retain before garbage collection.
    ///
    /// Stale JMT nodes and their associations are kept for this many heights
    /// before being eligible for deletion. This enables historical queries within
    /// this window.
    ///
    /// Set to 0 for immediate deletion (no history retention).
    /// Defaults to 256.
    #[serde(default = "default_jmt_history_length", alias = "jmt_history_length")]
    pub jmt_history_length: u64,
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
            jmt_history_length: default_jmt_history_length(),
        }
    }
}

const fn default_jmt_history_length() -> u64 {
    256
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
    512
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
pub struct MetricsConfig {
    /// Enable metrics endpoint
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,

    /// Metrics HTTP listen address
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: String,
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
pub struct TelemetryConfigToml {
    /// Enable OpenTelemetry tracing
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint for traces
    #[serde(default)]
    pub otlp_endpoint: Option<String>,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Optional log file path. If provided, logs are written to this file.
    #[serde(default)]
    pub log_file: Option<PathBuf>,
}

fn default_service_name() -> String {
    "hyperscale-validator".to_string()
}

/// Genesis configuration defining the validator set and initial balances.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GenesisConfig {
    /// Validators in the network
    #[serde(default)]
    pub validators: Vec<ValidatorEntry>,

    /// Initial XRD balances for accounts
    #[serde(default)]
    pub xrd_balances: Vec<XrdBalanceEntry>,
}

/// An XRD balance entry for genesis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct XrdBalanceEntry {
    /// `Bech32`-encoded account address (e.g., `"account_sim1..."`).
    pub address: String,

    /// Balance as a string (parsed as `Decimal`)
    pub balance: String,
}

/// A validator entry in genesis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorEntry {
    /// Validator ID
    pub id: u64,

    /// Hex-encoded public key
    pub public_key: String,
}

impl ValidatorConfig {
    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if its contents fail to
    /// parse as TOML in the [`ValidatorConfig`] schema.
    pub fn load(path: &PathBuf) -> Result<Self> {
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
fn format_public_key(pk: &Bls12381G1PublicKey) -> String {
    hex_encode(pk.to_vec())
}

/// Load or generate a signing keypair.
///
/// The key file stores a 32-byte seed that deterministically generates the keypair.
/// This seed can be stored as raw bytes or hex-encoded.
fn load_or_generate_keypair(key_path: Option<&PathBuf>) -> Result<Bls12381G1PrivateKey> {
    use rand::{Rng, rng};

    let Some(path) = key_path else {
        warn!("No key path specified, generating ephemeral keypair");
        return Ok(generate_bls_keypair());
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

        Ok(bls_keypair_from_seed(&seed))
    } else {
        info!("Key file not found, generating new keypair");

        let mut seed = [0u8; 32];
        rng().fill_bytes(&mut seed);

        let keypair = bls_keypair_from_seed(&seed);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, seed)?;
        info!("Saved new keypair seed to {}", path.display());

        Ok(keypair)
    }
}

/// Build the genesis validators the runner projects the host's topology
/// snapshot from.
///
/// `local_keypairs` carries every hosted vnode's (`validator_id`, private key)
/// in `config.vnodes` order. For each genesis validator whose id matches a
/// hosted vnode, the public key is taken from the local keypair rather than
/// parsed from the genesis hex — keeping the set consistent with what this
/// process actually signs with.
///
/// Genesis is always a single ROOT shard: the network launches at one shard
/// and grows by splitting, so there is no operator-facing genesis-distribution
/// knob. The network reaches its target topology by driving the real split
/// lifecycle.
fn build_genesis_validators(
    network: NetworkDefinition,
    genesis: &GenesisConfig,
    local_keypairs: &[(ValidatorId, Arc<Bls12381G1PrivateKey>)],
) -> Result<GenesisValidators> {
    let lookup_local = |id: ValidatorId| -> Option<&Arc<Bls12381G1PrivateKey>> {
        local_keypairs
            .iter()
            .find_map(|(vid, k)| (*vid == id).then_some(k))
    };

    let validators: Vec<ValidatorInfo> = if genesis.validators.is_empty() {
        warn!("No validators in genesis config, running in single-validator mode");
        let (validator_id, keypair) = local_keypairs.first().expect("at least one hosted vnode");
        vec![ValidatorInfo {
            validator_id: *validator_id,
            public_key: keypair.public_key(),
        }]
    } else {
        genesis
            .validators
            .iter()
            .map(|v| {
                let validator_id = ValidatorId::new(v.id);
                let public_key = if let Some(keypair) = lookup_local(validator_id) {
                    keypair.public_key()
                } else {
                    let key_bytes = hex_decode(&v.public_key).with_context(|| {
                        format!("Invalid hex public key for validator {}", v.id)
                    })?;
                    if key_bytes.len() != 48 {
                        bail!(
                            "Invalid public key length for validator {}: expected 48 (BLS), got {}",
                            v.id,
                            key_bytes.len()
                        );
                    }
                    Bls12381G1PublicKey::try_from(key_bytes.as_slice()).map_err(|_| {
                        anyhow::anyhow!("Invalid BLS public key for validator {}", v.id)
                    })?
                };
                Ok(ValidatorInfo {
                    validator_id,
                    public_key,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };

    let validator_set = ValidatorSet::new(validators);

    // Genesis seats every configured validator in the single ROOT committee.
    let committee: Vec<ValidatorId> = validator_set
        .validators
        .iter()
        .map(|v| v.validator_id)
        .collect();

    Ok(GenesisValidators::new(network, validator_set, committee))
}

/// Build engine genesis configuration from TOML config.
///
/// Converts the TOML-friendly genesis config (with string addresses and balances)
/// to the engine's `GenesisConfig` type.
fn build_engine_genesis_config(config: &GenesisConfig) -> Result<EngineGenesisConfig> {
    use std::str::FromStr;

    use radix_common::math::Decimal;
    use radix_common::types::ComponentAddress;

    let network = NetworkDefinition::simulator();
    let decoder = AddressBech32Decoder::new(&network);

    let mut engine_config = EngineGenesisConfig::test_default();

    for entry in &config.xrd_balances {
        let (_, address_bytes) = decoder
            .validate_and_decode(&entry.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {:?}", entry.address, e))?;

        let address = ComponentAddress::try_from(address_bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!("Invalid component address '{}': {:?}", entry.address, e)
        })?;

        let balance = Decimal::from_str(&entry.balance)
            .map_err(|e| anyhow::anyhow!("Invalid balance '{}': {:?}", entry.balance, e))?;

        engine_config.xrd_balances.push((address, balance));
    }

    info!(
        xrd_balances = engine_config.xrd_balances.len(),
        "Parsed genesis XRD balances"
    );

    Ok(engine_config)
}

/// Compute (consensus, throughput) pool thread counts for the given host
/// core count.
///
/// 2 cores go to the dedicated consensus pool (liveness-critical work);
/// every remaining core goes to the throughput pool. State-machine
/// threads are not reserved against because pinning is off by default —
/// the OS scheduler interleaves them with pool workers. Floors at
/// (2, 1) so small machines still come up; oversubscription is tolerable
/// there.
fn for_core_count(total_cores: usize) -> (usize, usize) {
    let consensus = 2;
    let throughput = total_cores.saturating_sub(consensus).max(1);
    (consensus, throughput)
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

/// Build network configuration from TOML config.
fn build_network_config(config: &NetworkConfig) -> Result<Libp2pConfig> {
    let listen_addr: Multiaddr = config
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid listen address: {}", config.listen_addr))?;

    let listen_addresses = vec![listen_addr];

    // Filter out our own listen addresses from bootstrap peers.
    let bootstrap_peers: Vec<_> = config
        .bootstrap_peers
        .iter()
        .filter_map(|addr| {
            let parsed = addr.parse::<Multiaddr>().ok().or_else(|| {
                warn!("Invalid bootstrap peer address: {}", addr);
                None
            })?;

            // Check if this bootstrap peer matches any of our listen addresses
            // We compare string representations to handle minor formatting differences
            let is_self = listen_addresses.iter().any(|listen| {
                // Check if port and protocol match
                // We're aggressive here: if it looks like us, don't dial it
                listen.to_string() == parsed.to_string()
            });

            if is_self {
                info!("Removing self from bootstrap peers: {}", addr);
                None
            } else {
                Some(parsed)
            }
        })
        .collect();

    Ok(Libp2pConfig::default()
        .with_listen_addresses(listen_addresses)
        .with_bootstrap_peers(bootstrap_peers)
        .with_max_message_size(config.max_message_size)
        .with_gossipsub_heartbeat(Duration::from_millis(config.gossipsub_heartbeat_ms))
        .with_idle_connection_timeout(Duration::from_millis(config.idle_connection_timeout_ms))
        .with_keep_alive_interval(Duration::from_millis(config.keep_alive_interval_ms))
        .with_version_interop_mode(
            config
                .version_interop_mode
                .unwrap_or(VersionInteroperabilityMode::Strict),
        ))
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
        jmt_history_length: config.jmt_history_length,
    }
}

/// Setup `UPnP` port forwarding.
#[allow(clippy::too_many_lines)] // mostly nested error logging branches; helpers obscure the flow
async fn setup_upnp(config: &NetworkConfig) {
    if !config.upnp_enabled {
        info!("UPnP disabled in configuration");
        return;
    }

    info!("Attempting to setup UPnP port forwarding...");

    // Determine local IP address by connecting to a public DNS (no data is sent)
    // We try multiple reliable DNS servers to ensure robustness
    let dns_servers = ["8.8.8.8:80", "1.1.1.1:80", "9.9.9.9:80"];
    let mut local_ip = None;

    for server in &dns_servers {
        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if socket.connect(server).is_ok()
                    && let Ok(addr) = socket.local_addr()
                {
                    local_ip = Some(addr.ip());
                    break;
                }
            }
            Err(e) => {
                warn!(
                    "Could not bind socket to determine local IP for UPnP: {}",
                    e
                );
            }
        }
    }

    let Some(local_ip) = local_ip else {
        warn!(
            "Could not determine local IP for UPnP: failed to connect to any external DNS server"
        );
        return;
    };

    // Parse listen address to get the port
    let listen_addr_parsed: Multiaddr = match config.listen_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to parse listen address for UPnP: {}", e);
            return;
        }
    };

    let mut quic_port = None;
    for protocol in &listen_addr_parsed {
        if let Protocol::Udp(port) = protocol {
            quic_port = Some(port);
            break;
        }
    }

    // Use igd-next for UPnP
    match search_gateway(SearchOptions::default()).await {
        Ok(gateway) => {
            let external_ip = match gateway.get_external_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    warn!("Failed to get external IP from UPnP gateway: {}", e);
                    return;
                }
            };
            info!("UPnP Gateway found. External IP: {}", external_ip);

            // Map QUIC port (UDP)
            if let Some(port) = quic_port {
                let local_addr = SocketAddr::new(local_ip, port);
                match gateway
                    .add_port(
                        PortMappingProtocol::UDP,
                        port,
                        local_addr,
                        60 * 60, // 1 hour lease
                        "Hyperscale Validator QUIC",
                    )
                    .await
                {
                    Ok(()) => info!("Successfully mapped QUIC port {} (UDP) via UPnP", port),
                    Err(e) => warn!("Failed to map QUIC port {} (UDP) via UPnP: {}", port, e),
                }
            } else {
                warn!("Could not determine QUIC port from listen address for UPnP");
            }
        }
        Err(e) => {
            warn!(
                "UPnP gateway not found or accessible: {}. Port forwarding may be required manually.",
                e
            );
        }
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
                .unwrap_or_else(|| std::path::Path::new("."))
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

    setup_upnp(&config.network).await;

    if config.vnodes.is_empty() {
        bail!(
            "No [[vnode]] entries in configuration; at least one is required. \
             Add a [[vnode]] block with validator_id, shard, and key_path."
        );
    }

    let thread_config = build_thread_pool_config(&config.threads);
    let shard_config = ShardConsensusConfig::default();
    let network_config = build_network_config(&config.network)?;
    let rocksdb_config = build_rocksdb_config(&config.storage);

    let dispatch = Arc::new(
        PooledDispatch::new(thread_config, TokioHandle::current())
            .context("Failed to initialize thread pools")?,
    );

    let dir_data_dir = config.node.data_dir.clone();
    let storage_dir: StorageDirResolver =
        Arc::new(move |shard: ShardId| shard_data_dir(&dir_data_dir, shard));

    // Opens a shard's storage when the runner seats this host on it — a
    // beacon-derived startup seat or a runtime placement change — at one
    // directory convention so a restart reopens what an earlier seat created.
    // The runner derives which shards to open from the committed beacon
    // state, so the host opens none up front.
    let factory_rocksdb_config = rocksdb_config.clone();
    let factory_storage_dir = Arc::clone(&storage_dir);
    let storage_factory: StorageFactory = Arc::new(move |shard: ShardId| {
        let shard_dir = factory_storage_dir(shard);
        RocksDbShardStorage::open_with_config(
            &shard_dir,
            &factory_rocksdb_config,
            shard_prefix_path(shard),
        )
        .map(Arc::new)
        .map_err(|e| format!("failed to open database at {}: {e:?}", shard_dir.display()))
    });

    // Process-level beacon storage, shared across every hosted vnode's
    // `BeaconCoordinator`. One DB under `{data_dir}/beacon/db`.
    let beacon_db_path = config.node.data_dir.join("beacon").join("db");
    let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(
        RocksDbBeaconStorage::open_with_config(&beacon_db_path, &rocksdb_config)
            .with_context(|| format!("Failed to open beacon DB at {}", beacon_db_path.display()))?,
    );
    info!(path = %beacon_db_path.display(), "Beacon storage opened");

    // Pass 1: load every hosted vnode's signing keypair so the topology builder
    // can substitute trusted local public keys for genesis-hex pubkeys.
    // Ordered Vec — single-validator mode picks the first entry, so source
    // order must be the same as config.vnodes.
    let mut hosted_keypairs: Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)> =
        Vec::with_capacity(config.vnodes.len());
    for entry in &config.vnodes {
        let keypair = load_or_generate_keypair(Some(&entry.key_path))?;
        info!(
            validator_id = entry.validator_id,
            public_key = %format_public_key(&keypair.public_key()),
            "Loaded vnode signing keypair"
        );
        hosted_keypairs.push((ValidatorId::new(entry.validator_id), Arc::new(keypair)));
    }

    // Build the host's genesis validators. Genesis is always a single ROOT
    // shard; the network grows to its target topology by splitting under load.
    // The runner projects the host's topology snapshot from this.
    let genesis_validators = build_genesis_validators(
        config.node.network.clone(),
        &config.genesis,
        &hosted_keypairs,
    )?;

    // The validators this host runs. Shard participation is not named here —
    // the runner derives each validator's seat (or pool membership) from the
    // committed beacon state and opens any seated shard's storage itself.
    let validators: Vec<LocalValidator> = hosted_keypairs
        .iter()
        .map(|(validator_id, signing_key)| LocalValidator {
            validator_id: *validator_id,
            signing_key: Arc::clone(signing_key),
        })
        .collect();

    // Shared RPC state objects used by both runner and RPC server. ArcSwap gives
    // HTTP handlers lock-free reads. Per-vnode entries are filled in by the
    // runner's first status tick; until then `vnodes` is empty.
    let rpc_ready = Arc::new(AtomicBool::new(false));
    let rpc_sync_status = Arc::new(ArcSwap::new(Arc::new(SyncStatus::default())));
    // `num_shards` is published by the runner from the live topology on each
    // status tick; it starts at the default until the first tick.
    let rpc_node_status = Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default())));
    let rpc_mempool_snapshot = Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default())));

    // The runner is built before the RPC server because it owns the crossbeam
    // event channel the RPC server submits transactions through.
    let mut runner_builder = ProductionRunner::builder(
        validators,
        genesis_validators,
        shard_config,
        beacon_storage,
        network_config,
        storage_factory,
        storage_dir,
    )
    .dispatch(dispatch)
    .rpc_status(rpc_node_status.clone())
    .mempool_snapshot(rpc_mempool_snapshot.clone())
    .sync_status(rpc_sync_status.clone())
    .mempool_config(config.mempool.clone())
    .provision_config(config.provisions);

    if !config.genesis.xrd_balances.is_empty() {
        let engine_genesis = build_engine_genesis_config(&config.genesis)
            .context("Failed to parse genesis configuration")?;
        runner_builder = runner_builder.genesis_config(engine_genesis);
    }

    let mut runner = runner_builder
        .build()
        .context("Failed to create production runner")?;

    // RPC-submitted transactions flow through this channel: gossip to all
    // relevant shards, validate via the shared batcher, dispatch to mempool.
    let tx_submission_sender = runner.tx_submission_sender();
    let rpc_tx_status = runner.tx_status_cache();

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
            rpc_sync_status,
            rpc_node_status.clone(),
            tx_submission_sender,
            rpc_tx_status,
            rpc_mempool_snapshot,
        );
        let handle = rpc_server
            .start()
            .await
            .context("Failed to start RPC server")?;

        Some(handle)
    } else {
        None
    };

    let shutdown_handle = runner.shutdown_handle();

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

    if let Err(e) = runner.run().await {
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

    #[test]
    fn test_for_core_count() {
        // 16 cores: 2 consensus + 14 throughput
        let (consensus, throughput) = for_core_count(16);
        assert_eq!(consensus, 2);
        assert_eq!(throughput, 14);

        // 32 cores: 2 consensus + 30 throughput
        let (consensus, throughput) = for_core_count(32);
        assert_eq!(consensus, 2);
        assert_eq!(throughput, 30);

        // 4 cores: 2 consensus + 2 throughput
        let (consensus, throughput) = for_core_count(4);
        assert_eq!(consensus, 2);
        assert_eq!(throughput, 2);
    }

    #[test]
    fn test_for_core_count_floor() {
        // 2 cores: floored at 1 throughput (consensus would otherwise eat both).
        let (consensus, throughput) = for_core_count(2);
        assert_eq!(consensus, 2);
        assert_eq!(throughput, 1);
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
