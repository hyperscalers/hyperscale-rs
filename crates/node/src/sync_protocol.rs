//! Sync protocol state machine.
//!
//! Pure synchronous state machine for block sync. Tracks height queues
//! and validates responses. Does NOT handle peer selection, async dispatch,
//! or banning — those stay in the runner-specific wrapper.
//!
//! # Usage
//!
//! ```text
//! Runner ──► SyncProtocol::handle(SyncInput) ──► Vec<SyncOutput>
//! ```
//!
//! Production: `SyncManager` wraps this, maps outputs to tokio tasks.
//! Simulation: feeds inputs/outputs synchronously via event queue.

use hyperscale_metrics as metrics;
use hyperscale_types::{Block, Hash, QuorumCertificate};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use tracing::{debug, info, trace, warn};

/// Configuration for the sync protocol.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum number of concurrent fetch requests.
    pub max_concurrent_fetches: usize,

    /// Maximum number of heights to queue ahead of committed height.
    /// Creates a sliding window that limits memory usage.
    pub sync_window_size: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_fetches: 32,
            sync_window_size: 64,
        }
    }
}

/// Current sync state for external APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStateKind {
    /// Not syncing, node is up to date.
    Idle,
    /// Actively fetching and applying blocks.
    Syncing,
}

impl SyncStateKind {
    /// Returns a string representation for metrics/logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStateKind::Idle => "idle",
            SyncStateKind::Syncing => "syncing",
        }
    }
}

/// Sync status snapshot for external APIs.
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    /// Current sync state.
    pub state: SyncStateKind,
    /// Current committed height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind target.
    pub blocks_behind: u64,
    /// Number of pending fetch requests.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: SyncStateKind::Idle,
            current_height: 0,
            target_height: None,
            blocks_behind: 0,
            pending_fetches: 0,
            queued_heights: 0,
        }
    }
}

/// Inputs to the sync protocol state machine.
#[derive(Debug)]
pub enum SyncInput {
    /// Start or update sync target.
    StartSync {
        target_height: u64,
        target_hash: Hash,
    },
    /// A block response was received.
    /// `None` means the peer did not have the block.
    BlockResponseReceived {
        height: u64,
        block: Box<Option<(Block, QuorumCertificate)>>,
    },
    /// A block fetch failed after all retries.
    BlockFetchFailed { height: u64 },
    /// A block was committed by the state machine.
    BlockCommitted { height: u64 },
}

/// Outputs from the sync protocol state machine.
#[derive(Debug)]
pub enum SyncOutput {
    /// Request the runner to fetch a block at this height.
    FetchBlock { height: u64 },
    /// A validated block is ready to deliver to BFT.
    DeliverBlock {
        block: Box<Block>,
        qc: Box<QuorumCertificate>,
    },
    /// Sync is complete (reached target).
    SyncComplete { height: u64 },
}

/// Sync protocol state machine.
///
/// Tracks which heights need fetching and validates responses.
/// The runner drives this by calling `handle()` with inputs and
/// executing the returned outputs.
pub struct SyncProtocol {
    config: SyncConfig,
    sync_target: Option<(u64, Hash)>,
    committed_height: u64,
    heights_to_fetch: BinaryHeap<Reverse<u64>>,
    heights_queued: HashSet<u64>,
    heights_in_flight: HashSet<u64>,
}

impl SyncProtocol {
    /// Create a new sync protocol state machine.
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            sync_target: None,
            committed_height: 0,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            heights_in_flight: HashSet::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: SyncInput) -> Vec<SyncOutput> {
        match input {
            SyncInput::StartSync {
                target_height,
                target_hash,
            } => self.handle_start_sync(target_height, target_hash),
            SyncInput::BlockResponseReceived { height, block } => {
                self.handle_block_response(height, *block)
            }
            SyncInput::BlockFetchFailed { height } => self.handle_block_fetch_failed(height),
            SyncInput::BlockCommitted { height } => self.handle_block_committed(height),
        }
    }

    /// Check if currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_target.is_some()
    }

    /// Get the sync target height (for metrics).
    pub fn sync_target_height(&self) -> Option<u64> {
        self.sync_target.map(|(h, _)| h)
    }

    /// Number of blocks behind target (for metrics).
    pub fn blocks_behind(&self) -> u64 {
        self.sync_target
            .map(|(t, _)| t.saturating_sub(self.committed_height))
            .unwrap_or(0)
    }

    /// Get current sync status.
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            state: if self.sync_target.is_some() {
                SyncStateKind::Syncing
            } else {
                SyncStateKind::Idle
            },
            current_height: self.committed_height,
            target_height: self.sync_target.map(|(h, _)| h),
            blocks_behind: self
                .sync_target
                .map(|(t, _)| t.saturating_sub(self.committed_height))
                .unwrap_or(0),
            pending_fetches: self.heights_in_flight.len(),
            queued_heights: self.heights_queued.len(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(&mut self, target_height: u64, target_hash: Hash) -> Vec<SyncOutput> {
        if self.sync_target.is_some_and(|(t, _)| t >= target_height) {
            return vec![];
        }

        info!(
            target_height,
            ?target_hash,
            committed = self.committed_height,
            "Starting sync"
        );

        self.sync_target = Some((target_height, target_hash));
        self.queue_heights_in_window();
        self.emit_fetch_outputs()
    }

    fn handle_block_response(
        &mut self,
        height: u64,
        block: Option<(Block, QuorumCertificate)>,
    ) -> Vec<SyncOutput> {
        self.heights_in_flight.remove(&height);

        match block {
            Some((block, qc)) => {
                // Validate
                if block.header.height.0 != height {
                    warn!(
                        expected = height,
                        got = block.header.height.0,
                        "Height mismatch in sync response"
                    );
                    metrics::record_sync_block_filtered("height_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                let block_hash = block.hash();
                if qc.block_hash != block_hash {
                    warn!(height, "QC block hash mismatch in sync response");
                    metrics::record_sync_block_filtered("qc_hash_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                if qc.height.0 != height {
                    warn!(height, "QC height mismatch in sync response");
                    metrics::record_sync_block_filtered("qc_height_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                trace!(height, "Valid sync block received");
                metrics::record_sync_block_downloaded();
                metrics::record_sync_block_verified();
                let mut outputs = vec![SyncOutput::DeliverBlock {
                    block: Box::new(block),
                    qc: Box::new(qc),
                }];
                outputs.extend(self.emit_fetch_outputs());
                outputs
            }
            None => {
                debug!(height, "Empty sync response, re-queuing");
                metrics::record_sync_response_error("empty_response");
                self.queue_height(height);
                self.emit_fetch_outputs()
            }
        }
    }

    fn handle_block_fetch_failed(&mut self, height: u64) -> Vec<SyncOutput> {
        self.heights_in_flight.remove(&height);
        warn!(height, "Sync fetch failed, re-queuing");
        metrics::record_sync_response_error("fetch_failed");
        self.queue_height(height);
        self.emit_fetch_outputs()
    }

    fn handle_block_committed(&mut self, height: u64) -> Vec<SyncOutput> {
        self.committed_height = height;
        self.remove_heights_at_or_below(height);

        if let Some((target, _)) = self.sync_target {
            metrics::record_sync_block_applied();
            if height >= target {
                info!(height, target, "Sync complete");
                self.sync_target = None;
                self.clear_height_queue();
                return vec![SyncOutput::SyncComplete { height: target }];
            }

            // Extend sliding window
            self.queue_heights_in_window();
        }

        self.emit_fetch_outputs()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Height Queue Helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn queue_height(&mut self, height: u64) {
        if !self.heights_in_flight.contains(&height) && self.heights_queued.insert(height) {
            self.heights_to_fetch.push(Reverse(height));
        }
    }

    fn pop_next_height(&mut self) -> Option<u64> {
        while let Some(Reverse(height)) = self.heights_to_fetch.pop() {
            if self.heights_queued.remove(&height) && !self.heights_in_flight.contains(&height) {
                return Some(height);
            }
        }
        None
    }

    fn clear_height_queue(&mut self) {
        self.heights_to_fetch.clear();
        self.heights_queued.clear();
    }

    fn remove_heights_at_or_below(&mut self, threshold: u64) {
        self.heights_queued.retain(|&h| h > threshold);
        self.heights_in_flight.retain(|&h| h > threshold);
    }

    fn queue_heights_in_window(&mut self) {
        let Some((target_height, _)) = self.sync_target else {
            return;
        };

        let first_height = self.committed_height + 1;
        let window_end = if self.config.sync_window_size == 0 {
            target_height
        } else {
            (self.committed_height + self.config.sync_window_size).min(target_height)
        };

        for height in first_height..=window_end {
            if !self.heights_in_flight.contains(&height) {
                self.queue_height(height);
            }
        }
    }

    /// Emit FetchBlock outputs for pending heights up to concurrent limit.
    fn emit_fetch_outputs(&mut self) -> Vec<SyncOutput> {
        let mut outputs = Vec::new();
        while self.heights_in_flight.len() < self.config.max_concurrent_fetches {
            if let Some(height) = self.pop_next_height() {
                self.heights_in_flight.insert(height);
                outputs.push(SyncOutput::FetchBlock { height });
            } else {
                break;
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_fetches, 32);
        assert_eq!(config.sync_window_size, 64);
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert_eq!(status.state, SyncStateKind::Idle);
        assert_eq!(status.current_height, 0);
        assert!(status.target_height.is_none());
    }

    #[test]
    fn test_start_sync_emits_fetches() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 4,
            sync_window_size: 10,
        });

        let outputs = protocol.handle(SyncInput::StartSync {
            target_height: 5,
            target_hash: Hash::ZERO,
        });

        assert!(protocol.is_syncing());
        // Should emit FetchBlock for heights 1..=5
        let fetch_heights: Vec<u64> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::FetchBlock { height } => Some(*height),
                _ => None,
            })
            .collect();
        assert_eq!(fetch_heights.len(), 4); // limited by max_concurrent_fetches
    }

    #[test]
    fn test_sync_complete() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 32,
            sync_window_size: 64,
        });

        protocol.handle(SyncInput::StartSync {
            target_height: 2,
            target_hash: Hash::ZERO,
        });

        assert!(protocol.is_syncing());

        // Commit up to target
        let outputs = protocol.handle(SyncInput::BlockCommitted { height: 2 });

        assert!(!protocol.is_syncing());
        assert!(outputs
            .iter()
            .any(|o| matches!(o, SyncOutput::SyncComplete { height: 2 })));
    }

    #[test]
    fn test_failed_fetch_requeues() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });

        protocol.handle(SyncInput::StartSync {
            target_height: 3,
            target_hash: Hash::ZERO,
        });

        // Fail the first fetch
        let outputs = protocol.handle(SyncInput::BlockFetchFailed { height: 1 });

        // Should re-emit a FetchBlock for height 1
        assert!(outputs
            .iter()
            .any(|o| matches!(o, SyncOutput::FetchBlock { height: 1 })));
    }
}
