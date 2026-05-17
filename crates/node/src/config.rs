//! Consolidated configuration for `IoLoop`.

use std::time::Duration;

use crate::io_loop::sync::block::BlockSyncConfig;
use crate::shard::fetch::FetchConfig;

/// Configuration for [`IoLoop`](crate::io_loop::IoLoop).
///
/// Bundles all sub-component configs so runners can pass a single value.
#[derive(Debug, Default, Clone)]
pub struct NodeConfig {
    /// Block-sync (catch-up + rehydration) configuration.
    pub block_sync: BlockSyncConfig,
    /// Inbound transaction fetch configuration.
    pub transaction_fetch: FetchConfig,
    /// Cross-shard provision fetch configuration.
    pub provision_fetch: FetchConfig,
    /// Execution-certificate fetch configuration.
    pub exec_cert_fetch: FetchConfig,
    /// Batch-window configuration.
    pub batch: BatchConfig,
}

/// Batching thresholds for the I/O loop.
///
/// Each batch has a maximum item count and a time window. The batch flushes
/// when either limit is reached. Defaults match the previous hard-coded
/// constants.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Max items in the execution-vote verification batch.
    pub execution_vote_max: usize,
    /// Flush window for the execution-vote verification batch.
    pub execution_vote_window: Duration,

    /// Max items in the outbound execution-vote broadcast batch.
    pub broadcast_vote_max: usize,
    /// Flush window for the outbound execution-vote broadcast batch.
    pub broadcast_vote_window: Duration,

    /// Max items in the outbound execution-certificate broadcast batch.
    pub broadcast_cert_max: usize,
    /// Flush window for the outbound execution-certificate broadcast batch.
    pub broadcast_cert_window: Duration,

    /// Max items in the transaction-validation batch.
    pub tx_validation_max: usize,
    /// Flush window for the transaction-validation batch.
    pub tx_validation_window: Duration,

    /// Max items in the committed-block-header sender-signature batch.
    pub committed_header_max: usize,
    /// Flush window for the committed-block-header sender-signature batch.
    pub committed_header_window: Duration,

    /// Max transactions in a per-shard outbound `TransactionGossip` batch.
    /// Bounded so the encoded batch stays well under the gossipsub
    /// max-message size (default 1 MiB) at typical tx sizes.
    pub tx_gossip_max: usize,
    /// Flush window for the per-shard outbound `TransactionGossip` batch.
    /// Trades a small tail-latency cost for substantially fewer wire
    /// messages and larger per-message payloads (which activates
    /// gossipsub v1.2 IDONTWANT dedup).
    pub tx_gossip_window: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            execution_vote_max: 64,
            execution_vote_window: Duration::from_millis(20),

            broadcast_vote_max: 64,
            broadcast_vote_window: Duration::from_millis(15),

            broadcast_cert_max: 64,
            broadcast_cert_window: Duration::from_millis(15),

            tx_validation_max: 512,
            tx_validation_window: Duration::from_millis(50),

            committed_header_max: 32,
            committed_header_window: Duration::from_millis(15),

            tx_gossip_max: 200,
            tx_gossip_window: Duration::from_millis(50),
        }
    }
}
