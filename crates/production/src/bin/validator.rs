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
//!
//! # Specify signing key path
//! hyperscale-validator --config validator.toml --key /etc/hyperscale/validator.key
//! ```
//!
//! # Configuration
//!
//! See `ValidatorConfig` for all configuration options. Example TOML:
//!
//! ```toml
//! [node]
//! validator_id = 0
//! shard = 0
//! data_dir = "./data"
//!
//! [network]
//! listen_addr = "/ip4/0.0.0.0/udp/9000/quic-v1"
//! tcp_fallback_port = 30500
//! bootstrap_peers = []
//!
//! [consensus]
//! proposal_interval_ms = 300
//! view_change_timeout_ms = 3000
//!
//! [threads]
//! crypto_threads = 4
//! execution_threads = 8
//! io_threads = 2
//!
//! [metrics]
//! enabled = true
//! listen_addr = "0.0.0.0:9090"
//! ```

use anyhow::{bail, Context, Result};
use clap::Parser;
use hyperscale_bft::BftConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_libp2p::{derive_libp2p_keypair, VersionInteroperabilityMode};
use hyperscale_production::rpc::{RpcServer, RpcServerConfig};
use hyperscale_production::Libp2pConfig;
use hyperscale_production::{
    init_telemetry, PooledDispatch, ProductionRunner, RocksDbConfig, RocksDbStorage,
    TelemetryConfig, ThreadPoolConfig,
};
use hyperscale_types::{
    bls_keypair_from_seed, generate_bls_keypair, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    ShardGroupId, StaticTopology, ValidatorId, ValidatorInfo, ValidatorSet,
};
use radix_common::network::NetworkDefinition;
use radix_common::prelude::AddressBech32Decoder;
use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

/// Hyperscale Validator Node
///
/// Runs a production validator participating in BFT consensus.
#[derive(Parser, Debug)]
#[command(name = "hyperscale-validator")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to configuration file (TOML)
    #[arg(short, long)]
    config: PathBuf,

    /// Path to validator signing key (overrides config)
    #[arg(long)]
    key: Option<PathBuf>,

    /// Data directory for RocksDB (overrides config)
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Metrics listen address (overrides config)
    #[arg(long)]
    metrics_addr: Option<String>,

    /// Bootstrap peer multiaddresses (can be specified multiple times)
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Log level filter (overrides RUST_LOG)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Disable UPnP port forwarding (overrides config)
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
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorConfig {
    /// Node identity configuration
    pub node: NodeConfig,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Consensus configuration
    #[serde(default)]
    pub consensus: ConsensusConfig,

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
}

/// Node identity configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Validator ID (index in the committee)
    pub validator_id: u64,

    /// Shard group this validator belongs to
    #[serde(default)]
    pub shard: u64,

    /// Number of shards in the network
    #[serde(default = "default_num_shards")]
    pub num_shards: u64,

    /// Path to the signing key file
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    /// Data directory for storage
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_num_shards() -> u64 {
    1
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

    /// TCP fallback port (optional, enables TCP transport alongside QUIC)
    pub tcp_fallback_port: Option<u16>,

    /// Whether TCP fallback is enabled (default: true)
    #[serde(default = "default_tcp_fallback_enabled")]
    pub tcp_fallback_enabled: bool,

    /// Bootstrap peer addresses
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval in milliseconds
    #[serde(default = "default_gossipsub_heartbeat_ms")]
    pub gossipsub_heartbeat_ms: u64,

    /// Enable UPnP port forwarding
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

fn default_tcp_fallback_enabled() -> bool {
    true
}

fn default_max_message_size() -> usize {
    65536
}

fn default_gossipsub_heartbeat_ms() -> u64 {
    100
}

fn default_upnp_enabled() -> bool {
    true
}

fn default_idle_connection_timeout_ms() -> u64 {
    60_000
}

fn default_keep_alive_interval_ms() -> u64 {
    15_000
}

/// Consensus configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ConsensusConfig {
    /// Interval between proposal attempts (milliseconds)
    #[serde(default = "default_proposal_interval_ms")]
    pub proposal_interval_ms: u64,

    /// Timeout for view change (milliseconds)
    #[serde(default = "default_view_change_timeout_ms")]
    pub view_change_timeout_ms: u64,

    /// Maximum transactions per block
    #[serde(default = "default_max_transactions_per_block")]
    pub max_transactions_per_block: usize,

    /// Maximum certificates per block
    #[serde(default = "default_max_certificates_per_block")]
    pub max_certificates_per_block: usize,

    /// Maximum transactions for speculative execution (in-flight + cached).
    /// Higher values allow more aggressive speculation but use more memory.
    #[serde(default = "default_speculative_max_txs")]
    pub speculative_max_txs: usize,

    /// Rounds to pause speculation after a view change.
    /// Higher values reduce wasted work during instability but may reduce hit rate.
    #[serde(default = "default_view_change_cooldown_rounds")]
    pub view_change_cooldown_rounds: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            proposal_interval_ms: default_proposal_interval_ms(),
            view_change_timeout_ms: default_view_change_timeout_ms(),
            max_transactions_per_block: default_max_transactions_per_block(),
            max_certificates_per_block: default_max_certificates_per_block(),
            speculative_max_txs: default_speculative_max_txs(),
            view_change_cooldown_rounds: default_view_change_cooldown_rounds(),
        }
    }
}

fn default_proposal_interval_ms() -> u64 {
    300
}

fn default_view_change_timeout_ms() -> u64 {
    3000
}

fn default_max_transactions_per_block() -> usize {
    4096
}

fn default_max_certificates_per_block() -> usize {
    4096
}

fn default_speculative_max_txs() -> usize {
    500 // Matches hyperscale_execution::DEFAULT_SPECULATIVE_MAX_TXS
}

fn default_view_change_cooldown_rounds() -> u64 {
    3 // Matches hyperscale_execution::DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS
}

/// Thread pool configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThreadsConfig {
    /// Number of crypto verification threads (0 = auto)
    #[serde(default)]
    pub crypto_threads: usize,

    /// Number of execution threads (0 = auto)
    #[serde(default)]
    pub execution_threads: usize,

    /// Number of I/O threads (0 = auto)
    #[serde(default)]
    pub io_threads: usize,

    /// Enable CPU core pinning (Linux only)
    #[serde(default)]
    pub pin_cores: bool,
}

/// Compression type for storage (maps to RocksDB compression).
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

impl From<CompressionType> for hyperscale_production::CompressionType {
    fn from(ct: CompressionType) -> Self {
        match ct {
            CompressionType::None => hyperscale_production::CompressionType::None,
            CompressionType::Snappy => hyperscale_production::CompressionType::Snappy,
            CompressionType::Zlib => hyperscale_production::CompressionType::Zlib,
            CompressionType::Lz4 => hyperscale_production::CompressionType::Lz4,
            CompressionType::Lz4hc => hyperscale_production::CompressionType::Lz4hc,
            CompressionType::Zstd => hyperscale_production::CompressionType::Zstd,
        }
    }
}

/// Storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Maximum background jobs for RocksDB
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

    /// Enable historical substate values storage.
    ///
    /// When enabled, the storage persists associations between JMT leaf nodes
    /// and their substate values. This enables historical state queries - looking
    /// up substate values at any past state version (within the retention window).
    ///
    /// This adds storage overhead proportional to the number of substates modified.
    /// Defaults to `false` for minimal overhead; enable for Mesh API compatibility
    /// or when historical state queries are needed.
    #[serde(default)]
    pub enable_historical_substate_values: bool,

    /// Number of state versions to retain before garbage collection.
    ///
    /// Stale JMT nodes and their associations are kept for this many versions
    /// before being eligible for deletion. This enables historical queries within
    /// this window.
    ///
    /// Set to 0 for immediate deletion (no history retention).
    /// Defaults to 60,000 versions (matching Babylon's default).
    #[serde(default = "default_state_version_history_length")]
    pub state_version_history_length: u64,
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
            enable_historical_substate_values: false,
            state_version_history_length: default_state_version_history_length(),
        }
    }
}

fn default_state_version_history_length() -> u64 {
    60_000 // Match Babylon's default
}

fn default_max_background_jobs() -> i32 {
    4
}

fn default_write_buffer_mb() -> usize {
    128
}

fn default_max_write_buffer_number() -> i32 {
    3
}

fn default_block_cache_mb() -> usize {
    512
}

fn default_bloom_filter_bits() -> f64 {
    10.0
}

fn default_bytes_per_sync_mb() -> usize {
    1
}

fn default_keep_log_file_num() -> usize {
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

fn default_metrics_enabled() -> bool {
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
    /// Bech32-encoded account address (e.g., "account_sim1...")
    pub address: String,

    /// Balance as a string (parsed as Decimal)
    pub balance: String,
}

/// A validator entry in genesis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorEntry {
    /// Validator ID
    pub id: u64,

    /// Shard this validator belongs to
    #[serde(default)]
    pub shard: Option<u64>,

    /// Hex-encoded public key
    pub public_key: String,

    /// Voting power (default: 1)
    #[serde(default = "default_voting_power")]
    pub voting_power: u64,
}

fn default_voting_power() -> u64 {
    1
}

impl ValidatorConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Apply CLI overrides to the configuration.
    fn apply_overrides(&mut self, cli: &Cli) {
        if let Some(ref key_path) = cli.key {
            self.node.key_path = Some(key_path.clone());
        }

        if let Some(ref data_dir) = cli.data_dir {
            self.node.data_dir = data_dir.clone();
        }

        if let Some(ref metrics_addr) = cli.metrics_addr {
            self.metrics.listen_addr = metrics_addr.clone();
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
    hex::encode(pk.to_vec())
}

/// Load or generate a signing keypair.
///
/// The key file stores a 32-byte seed that deterministically generates the keypair.
/// This seed can be stored as raw bytes or hex-encoded.
fn load_or_generate_keypair(key_path: Option<&PathBuf>) -> Result<Bls12381G1PrivateKey> {
    match key_path {
        Some(path) => {
            if path.exists() {
                let key_bytes = fs::read(path)
                    .with_context(|| format!("Failed to read key file: {}", path.display()))?;

                // Try to decode as hex first, then as raw bytes
                let decoded = if key_bytes.len() == 64 {
                    // Likely hex-encoded (64 hex chars = 32 bytes)
                    hex::decode(&key_bytes).with_context(|| "Failed to decode hex key")?
                } else if key_bytes.len() == 32 {
                    // Raw bytes
                    key_bytes
                } else {
                    bail!(
                        "Invalid key file size: expected 32 bytes (raw) or 64 hex chars, got {} bytes",
                        key_bytes.len()
                    );
                };

                // Convert to fixed array
                let seed: [u8; 32] = decoded
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Key must be exactly 32 bytes"))?;

                // Use BLS12-381 for consensus (supports signature aggregation)
                Ok(bls_keypair_from_seed(&seed))
            } else {
                info!("Key file not found, generating new keypair");

                // Generate random seed
                let mut seed = [0u8; 32];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut seed);

                let keypair = bls_keypair_from_seed(&seed);

                // Save the seed
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, seed)?;
                info!("Saved new keypair seed to {}", path.display());

                Ok(keypair)
            }
        }
        None => {
            warn!("No key path specified, generating ephemeral keypair");
            Ok(generate_bls_keypair())
        }
    }
}

/// Build the topology from genesis configuration.
fn build_topology(
    config: &ValidatorConfig,
    local_keypair: &Bls12381G1PrivateKey,
) -> Result<Arc<dyn hyperscale_types::Topology>> {
    use std::collections::HashMap;

    let local_validator_id = ValidatorId(config.node.validator_id);
    let local_shard = ShardGroupId(config.node.shard);
    let num_shards = config.node.num_shards;

    // Build validator set from genesis config
    let validators: Vec<ValidatorInfo> = if config.genesis.validators.is_empty() {
        // Single validator mode (development/testing)
        warn!("No validators in genesis config, running in single-validator mode");
        vec![ValidatorInfo {
            validator_id: local_validator_id,
            public_key: local_keypair.public_key(),
            voting_power: 1,
        }]
    } else {
        config
            .genesis
            .validators
            .iter()
            .map(|v| {
                let public_key = if v.id == config.node.validator_id {
                    // Use our own key for our validator ID
                    local_keypair.public_key()
                } else {
                    // Parse hex-encoded public key (BLS12-381 only)
                    let key_bytes = hex::decode(&v.public_key).with_context(|| {
                        format!("Invalid hex public key for validator {}", v.id)
                    })?;

                    // BLS12-381 public key (compressed, 48 bytes)
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
                    validator_id: ValidatorId(v.id),
                    public_key,
                    voting_power: v.voting_power,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };

    let validator_set = ValidatorSet::new(validators);

    // Check if validators have explicit shard assignments
    let has_shard_assignments = config.genesis.validators.iter().any(|v| v.shard.is_some());

    if has_shard_assignments {
        // Build shard committees from explicit shard assignments in config
        // This is required for multi-shard setups where each validator needs to know
        // about ALL validators across ALL shards for cross-shard message verification
        let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();

        for v in &config.genesis.validators {
            // Use explicit shard if provided, otherwise fall back to validator_id % num_shards
            let shard = ShardGroupId(v.shard.unwrap_or(v.id % num_shards));
            shard_committees
                .entry(shard)
                .or_default()
                .push(ValidatorId(v.id));
        }

        info!(
            num_shards = num_shards,
            total_validators = config.genesis.validators.len(),
            "Building topology with explicit shard assignments"
        );

        Ok(StaticTopology::with_shard_committees(
            local_validator_id,
            local_shard,
            num_shards,
            &validator_set,
            shard_committees,
        )
        .into_arc())
    } else {
        // Legacy mode: all validators in genesis belong to local shard only
        // This only works for single-shard deployments
        if num_shards > 1 {
            warn!(
                "Multi-shard deployment without explicit shard assignments in genesis config. \
                 Cross-shard messages may fail. Add 'shard = N' to each [[genesis.validators]] entry."
            );
        }

        Ok(StaticTopology::with_local_shard(
            local_validator_id,
            local_shard,
            num_shards,
            validator_set,
        )
        .into_arc())
    }
}

/// Build engine genesis configuration from TOML config.
///
/// Converts the TOML-friendly genesis config (with string addresses and balances)
/// to the engine's GenesisConfig type.
fn build_engine_genesis_config(config: &GenesisConfig) -> Result<hyperscale_engine::GenesisConfig> {
    use radix_common::math::Decimal;
    use radix_common::types::ComponentAddress;
    use std::str::FromStr;

    let network = NetworkDefinition::simulator();
    let decoder = AddressBech32Decoder::new(&network);

    let mut engine_config = hyperscale_engine::GenesisConfig::test_default();

    // Convert XRD balances
    for entry in &config.xrd_balances {
        // Decode bech32 address
        let (_, address_bytes) = decoder
            .validate_and_decode(&entry.address)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {:?}", entry.address, e))?;

        let address = ComponentAddress::try_from(address_bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!("Invalid component address '{}': {:?}", entry.address, e)
        })?;

        // Parse balance
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

/// Build thread pool configuration from TOML config.
fn build_thread_pool_config(config: &ThreadsConfig) -> ThreadPoolConfig {
    let mut builder = ThreadPoolConfig::builder();

    if config.crypto_threads > 0 {
        builder = builder.crypto_threads(config.crypto_threads);
    }
    if config.execution_threads > 0 {
        builder = builder.execution_threads(config.execution_threads);
    }
    if config.io_threads > 0 {
        builder = builder.io_threads(config.io_threads);
    }
    if config.pin_cores {
        builder = builder.pin_cores(true);
    }

    builder.build_unchecked()
}

/// Build BFT configuration from TOML config.
fn build_bft_config(config: &ConsensusConfig) -> BftConfig {
    BftConfig::new()
        .with_proposal_interval(Duration::from_millis(config.proposal_interval_ms))
        .with_view_change_timeout(Duration::from_millis(config.view_change_timeout_ms))
        .with_max_transactions(config.max_transactions_per_block)
}

/// Build network configuration from TOML config.
fn build_network_config(config: &NetworkConfig) -> Result<Libp2pConfig> {
    let listen_addr: libp2p::Multiaddr = config
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid listen address: {}", config.listen_addr))?;

    let listen_addresses = vec![listen_addr.clone()];

    // Calculate default TCP fallback port if enabled but not specified (UDP port + 21500)
    let tcp_fallback_port = if config.tcp_fallback_enabled && config.tcp_fallback_port.is_none() {
        listen_addr.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::Udp(port) => Some(port + 21500),
            _ => None,
        })
    } else {
        config.tcp_fallback_port
    };

    // Filter out our own listen addresses from bootstrap peers
    // Also filter TCP addresses if TCP fallback is disabled
    let bootstrap_peers: Vec<_> = config
        .bootstrap_peers
        .iter()
        .filter_map(|addr| {
            // Skip TCP addresses if TCP transport is disabled
            if !config.tcp_fallback_enabled && addr.contains("/tcp/") {
                trace!("Skipping TCP bootstrap peer (TCP disabled): {}", addr);
                return None;
            }

            let parsed = addr.parse::<libp2p::Multiaddr>().ok().or_else(|| {
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
        .with_tcp_fallback(config.tcp_fallback_enabled, tcp_fallback_port)
        .with_version_interop_mode(
            config
                .version_interop_mode
                .unwrap_or(VersionInteroperabilityMode::Strict),
        ))
}

/// Build RocksDB configuration from TOML config.
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
        enable_historical_substate_values: config.enable_historical_substate_values,
        state_version_history_length: config.state_version_history_length,
        ..RocksDbConfig::default()
    }
}

/// Setup UPnP port forwarding.
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

    for server in dns_servers.iter() {
        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if socket.connect(server).is_ok() {
                    if let Ok(addr) = socket.local_addr() {
                        local_ip = Some(addr.ip());
                        break;
                    }
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

    let local_ip = match local_ip {
        Some(ip) => ip,
        None => {
            warn!("Could not determine local IP for UPnP: failed to connect to any external DNS server");
            return;
        }
    };

    // Parse listen address to get the port
    let listen_addr_parsed: libp2p::Multiaddr = match config.listen_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to parse listen address for UPnP: {}", e);
            return;
        }
    };

    let mut quic_port = None;
    for protocol in listen_addr_parsed.iter() {
        if let libp2p::multiaddr::Protocol::Udp(port) = protocol {
            quic_port = Some(port);
            break;
        }
    }

    // Use igd-next for UPnP
    match igd_next::aio::tokio::search_gateway(Default::default()).await {
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
                        igd_next::PortMappingProtocol::UDP,
                        port,
                        local_addr,
                        60 * 60, // 1 hour lease
                        "Hyperscale Validator QUIC",
                    )
                    .await
                {
                    Ok(_) => info!("Successfully mapped QUIC port {} (UDP) via UPnP", port),
                    Err(e) => warn!("Failed to map QUIC port {} (UDP) via UPnP: {}", port, e),
                }
            } else {
                warn!("Could not determine QUIC port from listen address for UPnP");
            }

            // Map TCP fallback port
            if config.tcp_fallback_enabled {
                if let Some(port) = config.tcp_fallback_port {
                    let local_addr = SocketAddr::new(local_ip, port);
                    match gateway
                        .add_port(
                            igd_next::PortMappingProtocol::TCP,
                            port,
                            local_addr,
                            60 * 60, // 1 hour lease
                            "Hyperscale Validator TCP",
                        )
                        .await
                    {
                        Ok(_) => info!("Successfully mapped TCP fallback port {} via UPnP", port),
                        Err(e) => warn!("Failed to map TCP fallback port {} via UPnP: {}", port, e),
                    }
                }
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration first (before logging init) to check if telemetry is enabled
    let mut config = ValidatorConfig::load(&cli.config)?;
    config.apply_overrides(&cli);

    // Initialize telemetry/logging
    // If telemetry is enabled, init_telemetry sets up the global subscriber with OTLP export.
    // Otherwise, use basic fmt subscriber.
    #[allow(dead_code)]
    enum UnifiedGuard {
        Telemetry(hyperscale_production::TelemetryGuard),
        Basic(Option<tracing_appender::non_blocking::WorkerGuard>),
    }

    let _log_guard = if config.telemetry.enabled {
        let telemetry_config = TelemetryConfig {
            service_name: config.telemetry.service_name.clone(),
            otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
            sampling_ratio: 1.0,
            prometheus_enabled: false, // We handle metrics separately
            prometheus_port: 9090,
            resource_attributes: vec![("shard".to_string(), config.node.shard.to_string())],
            log_file: config.telemetry.log_file.clone(),
        };
        UnifiedGuard::Telemetry(init_telemetry(&telemetry_config)?)
    } else {
        // Basic logging without OTLP export
        let builder = tracing_subscriber::fmt();

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
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();

            let file_appender = tracing_appender::rolling::never(directory, file_name);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            builder
                .with_writer(non_blocking)
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
        validator_id = config.node.validator_id,
        shard = config.node.shard,
        num_shards = config.node.num_shards,
        "Node configuration loaded"
    );

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

    // Ensure data directory exists
    fs::create_dir_all(&config.node.data_dir)?;

    // Setup UPnP
    setup_upnp(&config.network).await;

    // Load or generate keys
    let signing_keypair = load_or_generate_keypair(config.node.key_path.as_ref())?;
    info!(
        public_key = %format_public_key(&signing_keypair.public_key()),
        "Loaded signing keypair"
    );

    // Derive libp2p identity deterministically from signing key
    // This ensures PeerIds are predictable and can be computed from public keys
    let p2p_identity = derive_libp2p_keypair(&signing_keypair.public_key());
    info!(
        peer_id = %p2p_identity.public().to_peer_id(),
        "Derived p2p identity from signing key"
    );

    // Build topology
    let topology = build_topology(&config, &signing_keypair)?;
    info!(
        committee_size = topology.local_committee_size(),
        quorum_threshold = topology.local_quorum_threshold(),
        "Topology initialized"
    );

    // Build configurations
    let thread_config = build_thread_pool_config(&config.threads);
    let bft_config = build_bft_config(&config.consensus);
    let network_config = build_network_config(&config.network)?;
    let rocksdb_config = build_rocksdb_config(&config.storage);

    // Initialize dispatch pools
    let dispatch =
        Arc::new(PooledDispatch::new(thread_config).context("Failed to initialize thread pools")?);

    // Open storage
    let db_path = config.node.data_dir.join("db");
    let storage = RocksDbStorage::open_with_config(&db_path, rocksdb_config)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    let storage = Arc::new(storage);
    info!("Storage opened at {}", db_path.display());

    // Create shared RPC state objects that will be used by both runner and RPC server.
    // These are created first so they can be wired into both components.
    use arc_swap::ArcSwap;
    use hyperscale_production::rpc::{MempoolSnapshot, NodeStatusState};
    use std::sync::atomic::AtomicBool;
    use tokio::sync::RwLock;

    let rpc_ready = Arc::new(AtomicBool::new(false));
    // Use ArcSwap for lock-free reads of sync status from HTTP handlers
    let rpc_sync_status = Arc::new(ArcSwap::new(Arc::new(
        hyperscale_production::SyncStatus::default(),
    )));
    let rpc_node_status = Arc::new(RwLock::new(NodeStatusState {
        validator_id: config.node.validator_id,
        shard: config.node.shard,
        num_shards: config.node.num_shards,
        ..Default::default()
    }));
    let rpc_mempool_snapshot = Arc::new(RwLock::new(MempoolSnapshot::default()));

    // Create production runner first (before RPC server)
    // The runner creates the crossbeam event channel that the RPC server needs
    // for submitting transactions directly to NodeLoop.
    let mut runner_builder = ProductionRunner::builder()
        .topology(topology)
        .signing_key(signing_keypair)
        .bft_config(bft_config)
        .dispatch(dispatch)
        .storage(storage)
        .network(network_config, p2p_identity)
        .rpc_status(rpc_node_status.clone())
        .mempool_snapshot(rpc_mempool_snapshot.clone())
        .sync_status(rpc_sync_status.clone())
        .speculative_max_txs(config.consensus.speculative_max_txs)
        .view_change_cooldown_rounds(config.consensus.view_change_cooldown_rounds)
        .mempool_config(config.mempool.clone());

    // Wire up genesis configuration if XRD balances are specified
    if !config.genesis.xrd_balances.is_empty() {
        let engine_genesis = build_engine_genesis_config(&config.genesis)
            .context("Failed to parse genesis configuration")?;
        runner_builder = runner_builder.genesis_config(engine_genesis);
    }

    let mut runner = runner_builder
        .build()
        .await
        .context("Failed to create production runner")?;

    // Get the transaction submission sender from the runner
    // RPC-submitted transactions go through this channel to:
    // 1. Gossip to all relevant shards (RPC submissions need gossip)
    // 2. Validate via the shared batcher
    // 3. Dispatch to mempool
    let tx_submission_sender = runner.tx_submission_sender();
    let rpc_tx_status_cache = runner.tx_status_cache();

    // Start RPC server with the transaction submission channel and state
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

        // Use with_state to pass all shared state objects
        let rpc_server = RpcServer::with_state(
            rpc_config,
            rpc_ready.clone(),
            rpc_sync_status,
            rpc_node_status.clone(),
            tx_submission_sender,
            rpc_tx_status_cache,
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

    // Get shutdown handle
    let shutdown_handle = runner.shutdown_handle();

    // Spawn shutdown signal handler
    tokio::spawn(async move {
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
            _ = ctrl_c => info!("Received Ctrl+C"),
            _ = terminate => info!("Received SIGTERM"),
        }

        if let Some(handle) = shutdown_handle {
            info!("Initiating graceful shutdown...");
            handle.shutdown();
        }
    });

    // Mark node as ready
    if let Some(ref handle) = rpc_handle {
        handle.set_ready(true);
    }

    info!("Validator node started, press Ctrl+C to stop");

    // Run the main event loop
    if let Err(e) = runner.run().await {
        bail!("Runner error: {}", e);
    }

    // Cleanup RPC server
    if let Some(handle) = rpc_handle {
        handle.abort();
    }

    info!("Validator shutdown complete");
    Ok(())
}
