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

use hyperscale_messages::request::GetBlockRequest;
use hyperscale_messages::response::GetBlockResponse;
use hyperscale_metrics as metrics;
use hyperscale_storage::ChainReader;
use hyperscale_types::{BlockHeight, CertifiedBlock, Hash, Provision};
use quick_cache::sync::Cache as QuickCache;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;
use tracing::{info, trace, warn};

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
        target_height: BlockHeight,
        target_hash: Hash,
    },
    /// A block response was received.
    /// `None` means the peer did not have the block.
    BlockResponseReceived {
        height: BlockHeight,
        block: Option<Box<CertifiedBlock>>,
    },
    /// A block fetch failed after all retries.
    BlockFetchFailed { height: BlockHeight },
    /// A block was committed by the state machine.
    BlockCommitted { height: BlockHeight },
}

/// Outputs from the sync protocol state machine.
#[derive(Debug)]
pub enum SyncOutput {
    /// Request the runner to fetch a block at this height. `target_height`
    /// is the sync target, passed through to the serving peer so it can
    /// choose between `Block::Live` and `Block::Sealed`.
    FetchBlock {
        height: BlockHeight,
        target_height: BlockHeight,
    },
    /// A validated block is ready to deliver to BFT.
    DeliverBlock { certified: Box<CertifiedBlock> },
    /// Sync is complete (reached target).
    SyncComplete { height: BlockHeight },
}

/// Sync protocol state machine.
///
/// Tracks which heights need fetching and validates responses.
/// The runner drives this by calling `handle()` with inputs and
/// executing the returned outputs.
pub struct SyncProtocol {
    config: SyncConfig,
    sync_target: Option<(BlockHeight, Hash)>,
    committed_height: BlockHeight,
    heights_to_fetch: BinaryHeap<Reverse<BlockHeight>>,
    heights_queued: HashSet<BlockHeight>,
    heights_in_flight: HashSet<BlockHeight>,
}

impl SyncProtocol {
    /// Create a new sync protocol state machine.
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            sync_target: None,
            committed_height: BlockHeight::GENESIS,
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
                self.handle_block_response(height, block.map(|b| *b))
            }
            SyncInput::BlockFetchFailed { height } => self.handle_block_fetch_failed(height),
            SyncInput::BlockCommitted { height } => self.handle_block_committed(height),
        }
    }

    /// Check if currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_target.is_some()
    }

    /// Number of blocks behind target (for metrics).
    pub fn blocks_behind(&self) -> u64 {
        self.sync_target
            .map(|(t, _)| t.0.saturating_sub(self.committed_height.0))
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
            current_height: self.committed_height.0,
            target_height: self.sync_target.map(|(h, _)| h.0),
            blocks_behind: self
                .sync_target
                .map(|(t, _)| t.0.saturating_sub(self.committed_height.0))
                .unwrap_or(0),
            pending_fetches: self.heights_in_flight.len(),
            queued_heights: self.heights_queued.len(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(
        &mut self,
        target_height: BlockHeight,
        target_hash: Hash,
    ) -> Vec<SyncOutput> {
        if self.sync_target.is_some_and(|(t, _)| t >= target_height) {
            return vec![];
        }

        info!(
            target_height = target_height.0,
            ?target_hash,
            committed = self.committed_height.0,
            "Starting sync"
        );

        self.sync_target = Some((target_height, target_hash));
        self.queue_heights_in_window();
        self.emit_fetch_outputs()
    }

    fn handle_block_response(
        &mut self,
        height: BlockHeight,
        response: Option<CertifiedBlock>,
    ) -> Vec<SyncOutput> {
        self.heights_in_flight.remove(&height);

        match response {
            Some(CertifiedBlock { block, qc }) => {
                // Validate
                if block.height() != height {
                    warn!(
                        expected = height.0,
                        got = block.height().0,
                        "Height mismatch in sync response"
                    );
                    metrics::record_sync_block_filtered("height_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                let block_hash = block.hash();
                if qc.block_hash != block_hash {
                    warn!(height = height.0, "QC block hash mismatch in sync response");
                    metrics::record_sync_block_filtered("qc_hash_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                if qc.height != height {
                    warn!(height = height.0, "QC height mismatch in sync response");
                    metrics::record_sync_block_filtered("qc_height_mismatch");
                    self.queue_height(height);
                    return self.emit_fetch_outputs();
                }

                trace!(height = height.0, "Valid sync block received");
                metrics::record_sync_block_downloaded();
                metrics::record_sync_block_verified();
                let certified = CertifiedBlock::new_unchecked(block, qc);
                let mut outputs = vec![SyncOutput::DeliverBlock {
                    certified: Box::new(certified),
                }];
                outputs.extend(self.emit_fetch_outputs());
                outputs
            }
            None => {
                warn!(height = height.0, "Empty sync response, re-queuing");
                metrics::record_sync_response_error("empty_response");
                self.queue_height(height);
                self.emit_fetch_outputs()
            }
        }
    }

    fn handle_block_fetch_failed(&mut self, height: BlockHeight) -> Vec<SyncOutput> {
        self.heights_in_flight.remove(&height);
        warn!(height = height.0, "Sync fetch failed, re-queuing");
        metrics::record_sync_response_error("fetch_failed");
        self.queue_height(height);
        self.emit_fetch_outputs()
    }

    fn handle_block_committed(&mut self, height: BlockHeight) -> Vec<SyncOutput> {
        self.committed_height = height;
        self.remove_heights_at_or_below(height);

        if let Some((target, _)) = self.sync_target {
            metrics::record_sync_block_applied();
            if height >= target {
                info!(height = height.0, target = target.0, "Sync complete");
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

    fn queue_height(&mut self, height: BlockHeight) {
        if !self.heights_in_flight.contains(&height) && self.heights_queued.insert(height) {
            self.heights_to_fetch.push(Reverse(height));
        }
    }

    fn pop_next_height(&mut self) -> Option<BlockHeight> {
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

    fn remove_heights_at_or_below(&mut self, threshold: BlockHeight) {
        self.heights_queued.retain(|&h| h > threshold);
        self.heights_in_flight.retain(|&h| h > threshold);
    }

    fn queue_heights_in_window(&mut self) {
        let Some((target_height, _)) = self.sync_target else {
            return;
        };

        let first_height = self.committed_height.0 + 1;
        let window_end = if self.config.sync_window_size == 0 {
            target_height.0
        } else {
            (self.committed_height.0 + self.config.sync_window_size).min(target_height.0)
        };

        for height in first_height..=window_end {
            let h = BlockHeight(height);
            if !self.heights_in_flight.contains(&h) {
                self.queue_height(h);
            }
        }
    }

    /// Emit FetchBlock outputs for pending heights up to concurrent limit.
    /// Short-circuits when no sync target is set — heights are only queued
    /// after `handle_start_sync`, so a missing target means nothing to
    /// fetch.
    fn emit_fetch_outputs(&mut self) -> Vec<SyncOutput> {
        let Some((target_height, _)) = self.sync_target else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        while self.heights_in_flight.len() < self.config.max_concurrent_fetches {
            if let Some(height) = self.pop_next_height() {
                self.heights_in_flight.insert(height);
                outputs.push(SyncOutput::FetchBlock {
                    height,
                    target_height,
                });
            } else {
                break;
            }
        }
        outputs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Inbound request serving
// ═══════════════════════════════════════════════════════════════════════

/// Serve an inbound block sync request.
///
/// Storage always returns `Block::Sealed` — the persisted shape carries no
/// provisions. If the requester is still within the cross-shard execution
/// window relative to their `target_height`, this function must upgrade
/// to `Block::Live` by attaching the matching provisions from the local
/// in-memory cache. If the provisions have already aged out of the cache,
/// returns `not_found` rather than silently downgrading to `Sealed` — the
/// requester genuinely needs `Live` and will try another peer.
pub fn serve_block_request(
    storage: &impl ChainReader,
    provision_cache: &QuickCache<Hash, Arc<Provision>>,
    req: GetBlockRequest,
) -> GetBlockResponse {
    trace!(
        height = req.height.0,
        target_height = req.target_height.0,
        "Handling block sync request"
    );
    let Some(hyperscale_storage::BlockForSync {
        block,
        qc,
        provision_hashes,
    }) = storage.get_block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    // Block-count heuristic for "requester might still need provisions."
    // Sized generously so a Sealed block is only served when the requester
    // is clearly past the cross-shard execution window; if they need Live
    // and this peer can't attach provisions, they fall through to another
    // peer via `not_found`.
    const LIVE_BLOCK_WINDOW: u64 = 64;
    let needs_live =
        req.height.0 + LIVE_BLOCK_WINDOW > req.target_height.0 && !provision_hashes.is_empty();

    if !needs_live {
        return GetBlockResponse::found(CertifiedBlock::new_unchecked(block, qc));
    }

    let resolved: Option<Vec<Arc<Provision>>> = provision_hashes
        .iter()
        .map(|h| provision_cache.get(h))
        .collect();
    let Some(provisions) = resolved else {
        trace!(
            height = req.height.0,
            target_height = req.target_height.0,
            "Provisions no longer cached — requester must try another peer"
        );
        return GetBlockResponse::not_found();
    };

    GetBlockResponse::found(CertifiedBlock::new_unchecked(
        block.into_live(provisions),
        qc,
    ))
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
            target_height: BlockHeight(5),
            target_hash: Hash::ZERO,
        });

        assert!(protocol.is_syncing());
        // Should emit FetchBlock for heights 1..=5
        let fetch_heights: Vec<BlockHeight> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::FetchBlock { height, .. } => Some(*height),
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
            target_height: BlockHeight(2),
            target_hash: Hash::ZERO,
        });

        assert!(protocol.is_syncing());

        // Commit up to target
        let outputs = protocol.handle(SyncInput::BlockCommitted {
            height: BlockHeight(2),
        });

        assert!(!protocol.is_syncing());
        assert!(outputs
            .iter()
            .any(|o| matches!(o, SyncOutput::SyncComplete { height } if height.0 == 2)));
    }

    #[test]
    fn test_failed_fetch_requeues() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });

        protocol.handle(SyncInput::StartSync {
            target_height: BlockHeight(3),
            target_hash: Hash::ZERO,
        });

        // Fail the first fetch
        let outputs = protocol.handle(SyncInput::BlockFetchFailed {
            height: BlockHeight(1),
        });

        // Should re-emit a FetchBlock for height 1
        assert!(outputs
            .iter()
            .any(|o| matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1)));
    }
}
