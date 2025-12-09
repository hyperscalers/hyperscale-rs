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
use hyperscale_core::Event;
use hyperscale_production::network::Libp2pConfig;
use hyperscale_production::rpc::{RpcServer, RpcServerConfig};
use hyperscale_production::{
    init_telemetry, ProductionRunner, RocksDbConfig, RocksDbStorage, TelemetryConfig,
    ThreadPoolConfig, ThreadPoolManager,
};
use hyperscale_types::{
    KeyPair, KeyType, PublicKey, ShardGroupId, StaticTopology, ValidatorId, ValidatorInfo,
    ValidatorSet,
};
use libp2p::identity;
use parking_lot::RwLock;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{info, warn};
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
    /// Listen address (multiaddr format)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Bootstrap peer addresses
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Request timeout in milliseconds
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,

    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval in milliseconds
    #[serde(default = "default_gossipsub_heartbeat_ms")]
    pub gossipsub_heartbeat_ms: u64,
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/udp/9000/quic-v1".to_string()
}

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_max_message_size() -> usize {
    65536
}

fn default_gossipsub_heartbeat_ms() -> u64 {
    1000
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
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            proposal_interval_ms: default_proposal_interval_ms(),
            view_change_timeout_ms: default_view_change_timeout_ms(),
            max_transactions_per_block: default_max_transactions_per_block(),
            max_certificates_per_block: default_max_certificates_per_block(),
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

/// Storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Maximum background jobs for RocksDB
    #[serde(default = "default_max_background_jobs")]
    pub max_background_jobs: i32,

    /// Write buffer size in MB
    #[serde(default = "default_write_buffer_mb")]
    pub write_buffer_mb: usize,

    /// Block cache size in MB (0 to disable)
    #[serde(default = "default_block_cache_mb")]
    pub block_cache_mb: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_background_jobs: default_max_background_jobs(),
            write_buffer_mb: default_write_buffer_mb(),
            block_cache_mb: default_block_cache_mb(),
        }
    }
}

fn default_max_background_jobs() -> i32 {
    4
}

fn default_write_buffer_mb() -> usize {
    128
}

fn default_block_cache_mb() -> usize {
    512
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
}

fn default_service_name() -> String {
    "hyperscale-validator".to_string()
}

/// Genesis configuration defining the validator set.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct GenesisConfig {
    /// Validators in the network
    #[serde(default)]
    pub validators: Vec<ValidatorEntry>,
}

/// A validator entry in genesis configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorEntry {
    /// Validator ID
    pub id: u64,

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
    }
}

/// Format a public key as a hex string.
fn format_public_key(pk: &PublicKey) -> String {
    match pk {
        PublicKey::Ed25519(bytes) => hex::encode(bytes),
        PublicKey::Bls12381(bytes) => hex::encode(bytes),
    }
}

/// Load or generate a signing keypair.
///
/// The key file stores a 32-byte seed that deterministically generates the keypair.
/// This seed can be stored as raw bytes or hex-encoded.
fn load_or_generate_keypair(key_path: Option<&PathBuf>) -> Result<KeyPair> {
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
                Ok(KeyPair::from_seed(KeyType::Bls12381, &seed))
            } else {
                info!("Key file not found, generating new keypair");

                // Generate random seed
                let mut seed = [0u8; 32];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut seed);

                let keypair = KeyPair::from_seed(KeyType::Bls12381, &seed);

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
            Ok(KeyPair::generate_bls())
        }
    }
}

/// Load or generate a libp2p identity keypair.
fn load_or_generate_libp2p_identity(data_dir: &PathBuf) -> Result<identity::Keypair> {
    let identity_path = data_dir.join("p2p_identity.key");

    if identity_path.exists() {
        let key_bytes = fs::read(&identity_path)?;

        // libp2p ed25519 keys are 64 bytes (secret + public)
        let mut key_array = [0u8; 64];
        if key_bytes.len() == 64 {
            key_array.copy_from_slice(&key_bytes);
        } else {
            bail!(
                "Invalid p2p identity key size: expected 64 bytes, got {}",
                key_bytes.len()
            );
        }

        identity::Keypair::ed25519_from_bytes(key_array)
            .map_err(|e| anyhow::anyhow!("Failed to parse p2p identity: {}", e))
    } else {
        info!("Generating new p2p identity");
        let keypair = identity::Keypair::generate_ed25519();

        // Save the identity (64 bytes: secret key + public key)
        fs::create_dir_all(data_dir)?;
        let key_bytes = keypair
            .clone()
            .try_into_ed25519()
            .map_err(|_| anyhow::anyhow!("Failed to get ed25519 keypair"))?
            .to_bytes();
        fs::write(&identity_path, key_bytes)?;
        info!("Saved p2p identity to {}", identity_path.display());

        Ok(keypair)
    }
}

/// Build the topology from genesis configuration.
fn build_topology(
    config: &ValidatorConfig,
    local_keypair: &KeyPair,
) -> Result<Arc<dyn hyperscale_types::Topology>> {
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
                    // Parse hex-encoded public key
                    let key_bytes = hex::decode(&v.public_key)
                        .with_context(|| format!("Invalid hex public key for validator {}", v.id))?;

                    // Ed25519 public keys are 32 bytes
                    if key_bytes.len() == 32 {
                        let bytes: [u8; 32] = key_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
                        PublicKey::Ed25519(bytes)
                    } else if key_bytes.len() == 48 {
                        // BLS12-381 public key (compressed)
                        PublicKey::Bls12381(key_bytes)
                    } else {
                        bail!(
                            "Invalid public key length for validator {}: expected 32 (Ed25519) or 48 (BLS), got {}",
                            v.id,
                            key_bytes.len()
                        );
                    }
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

    Ok(
        StaticTopology::with_local_shard(
            local_validator_id,
            local_shard,
            num_shards,
            validator_set,
        )
        .into_arc(),
    )
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
    let listen_addr = config
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid listen address: {}", config.listen_addr))?;

    let bootstrap_peers: Vec<_> = config
        .bootstrap_peers
        .iter()
        .filter_map(|addr| {
            addr.parse().ok().or_else(|| {
                warn!("Invalid bootstrap peer address: {}", addr);
                None
            })
        })
        .collect();

    Ok(Libp2pConfig::default()
        .with_listen_addresses(vec![listen_addr])
        .with_bootstrap_peers(bootstrap_peers)
        .with_request_timeout(Duration::from_millis(config.request_timeout_ms))
        .with_max_message_size(config.max_message_size)
        .with_gossipsub_heartbeat(Duration::from_millis(config.gossipsub_heartbeat_ms)))
}

/// Build RocksDB configuration from TOML config.
fn build_rocksdb_config(config: &StorageConfig) -> RocksDbConfig {
    RocksDbConfig {
        max_background_jobs: config.max_background_jobs,
        write_buffer_size: config.write_buffer_mb * 1024 * 1024,
        max_write_buffer_number: 3,
        block_cache_size: if config.block_cache_mb > 0 {
            Some(config.block_cache_mb * 1024 * 1024)
        } else {
            None
        },
        ..RocksDbConfig::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    info!("Hyperscale Validator starting...");

    // Load configuration
    let mut config = ValidatorConfig::load(&cli.config)?;
    config.apply_overrides(&cli);

    info!(
        validator_id = config.node.validator_id,
        shard = config.node.shard,
        num_shards = config.node.num_shards,
        "Node configuration loaded"
    );

    // Initialize telemetry if enabled
    let _telemetry_guard = if config.telemetry.enabled {
        let telemetry_config = TelemetryConfig {
            service_name: config.telemetry.service_name.clone(),
            otlp_endpoint: config.telemetry.otlp_endpoint.clone(),
            sampling_ratio: 1.0,
            prometheus_enabled: false, // We handle metrics separately
            prometheus_port: 9090,
            resource_attributes: vec![
                (
                    "validator_id".to_string(),
                    config.node.validator_id.to_string(),
                ),
                ("shard".to_string(), config.node.shard.to_string()),
            ],
        };
        Some(init_telemetry(&telemetry_config)?)
    } else {
        None
    };

    // Ensure data directory exists
    fs::create_dir_all(&config.node.data_dir)?;

    // Load or generate keys
    let signing_keypair = load_or_generate_keypair(config.node.key_path.as_ref())?;
    info!(
        public_key = %format_public_key(&signing_keypair.public_key()),
        "Loaded signing keypair"
    );

    let p2p_identity = load_or_generate_libp2p_identity(&config.node.data_dir)?;
    info!(
        peer_id = %p2p_identity.public().to_peer_id(),
        "Loaded p2p identity"
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

    // Initialize thread pools
    let thread_pools = Arc::new(
        ThreadPoolManager::new(thread_config).context("Failed to initialize thread pools")?,
    );

    // Open storage
    let db_path = config.node.data_dir.join("db");
    let storage = RocksDbStorage::open_with_config(&db_path, rocksdb_config)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    let storage = Arc::new(RwLock::new(storage));
    info!("Storage opened at {}", db_path.display());

    // Create transaction submission channel for RPC server
    let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel(1000);

    // Start RPC server
    let rpc_handle = if config.metrics.enabled {
        let rpc_config = RpcServerConfig {
            listen_addr: config.metrics.listen_addr.parse().with_context(|| {
                format!(
                    "Invalid metrics listen address: {}",
                    config.metrics.listen_addr
                )
            })?,
            metrics_enabled: true,
        };

        let rpc_server = RpcServer::new(rpc_config, tx_sender);
        let handle = rpc_server
            .start()
            .await
            .context("Failed to start RPC server")?;

        // Update node status with initial values
        {
            let mut status = handle.node_status().write().await;
            status.validator_id = config.node.validator_id;
            status.shard = config.node.shard;
            status.num_shards = config.node.num_shards;
        }

        Some(handle)
    } else {
        None
    };

    // Create production runner
    let mut runner_builder = ProductionRunner::builder()
        .topology(topology)
        .signing_key(signing_keypair)
        .bft_config(bft_config)
        .thread_pools(thread_pools)
        .storage(storage)
        .network(network_config, p2p_identity);

    // Wire up RPC status updates if RPC server is enabled
    if let Some(ref handle) = rpc_handle {
        runner_builder = runner_builder.rpc_status(handle.node_status().clone());
    }

    let mut runner = runner_builder
        .build()
        .await
        .context("Failed to create production runner")?;

    // Get event sender for transaction injection
    let event_sender = runner.event_sender();

    // Get shutdown handle
    let shutdown_handle = runner.shutdown_handle();

    // Spawn transaction forwarder (RPC -> event loop)
    tokio::spawn(async move {
        while let Some(tx) = tx_receiver.recv().await {
            // Inject transaction as if received via gossip
            if let Err(e) = event_sender
                .send(Event::TransactionGossipReceived { tx })
                .await
            {
                warn!("Failed to forward RPC transaction: {}", e);
            }
        }
    });

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
