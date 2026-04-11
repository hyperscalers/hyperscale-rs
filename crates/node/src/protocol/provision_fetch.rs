//! Provision fetch protocol state machine.
//!
//! Pure synchronous state machine for cross-shard provision fetching with
//! per-peer rotation. Sits between the `ProvisionCoordinator`'s
//! `FetchProvisionsRemote` action and the actual `network.request()` call,
//! rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► ProvisionFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_messages::request::GetProvisionsRequest;
use hyperscale_messages::response::GetProvisionsResponse;
use hyperscale_metrics as metrics;
use hyperscale_storage::{ChainReader, SubstateStore};
use hyperscale_types::{BlockHeight, ProvisionBatch, ShardGroupId, StateProvision, ValidatorId};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, trace, warn};

/// Configuration for the provision fetch protocol.
#[derive(Debug, Clone)]
pub struct ProvisionFetchConfig {
    /// Maximum number of concurrent provision fetch operations.
    pub max_concurrent: usize,
    /// Maximum number of pending fetch entries per source shard.
    ///
    /// Prevents unbounded accumulation when a remote shard is down. When the
    /// cap is reached, the oldest entry for that shard is evicted.
    pub max_pending_per_shard: usize,
}

impl Default for ProvisionFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_pending_per_shard: 8,
        }
    }
}

/// Inputs to the provision fetch protocol state machine.
#[derive(Debug)]
pub enum ProvisionFetchInput {
    /// A new provision fetch request from the coordinator.
    Request {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        target_shard: ShardGroupId,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    },
    /// Provisions were successfully received for a request.
    Received {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        batch: ProvisionBatch,
    },
    /// A fetch attempt failed (network error or peer returned None).
    Failed {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    },
    /// Cancel a pending provision fetch (proactive provisions verified before fallback).
    Cancel {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    },
    /// Periodic tick — spawn pending fetch operations.
    Tick { now: Instant },
}

/// Outputs from the provision fetch protocol state machine.
#[derive(Debug)]
pub enum ProvisionFetchOutput {
    /// Request the runner to fetch provisions from a specific peer.
    Fetch {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        target_shard: ShardGroupId,
        peer: ValidatorId,
    },
    /// Deliver fetched provisions to the state machine.
    Deliver { batch: ProvisionBatch },
}

/// State for a single pending provision fetch.
#[derive(Debug)]
struct PendingProvisionFetch {
    target_shard: ShardGroupId,
    peers: Vec<ValidatorId>,
    preferred_peer: ValidatorId,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
    rounds: u32,
    next_retry_at: Option<Instant>,
}

/// Provision fetch protocol state machine.
pub struct ProvisionFetchProtocol {
    config: ProvisionFetchConfig,
    /// Pending fetches keyed by (source_shard, block_height).
    pending: BTreeMap<(ShardGroupId, BlockHeight), PendingProvisionFetch>,
}

impl ProvisionFetchProtocol {
    /// Create a new provision fetch protocol state machine.
    pub fn new(config: ProvisionFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: ProvisionFetchInput) -> Vec<ProvisionFetchOutput> {
        match input {
            ProvisionFetchInput::Request {
                source_shard,
                block_height,
                target_shard,
                peers,
                preferred_peer,
            } => self.handle_request(
                source_shard,
                block_height,
                target_shard,
                peers,
                preferred_peer,
            ),
            ProvisionFetchInput::Received {
                source_shard,
                block_height,
                batch,
            } => self.handle_received(source_shard, block_height, batch),
            ProvisionFetchInput::Failed {
                source_shard,
                block_height,
            } => self.handle_failed(source_shard, block_height),
            ProvisionFetchInput::Cancel {
                source_shard,
                block_height,
            } => self.handle_cancel(source_shard, block_height),
            ProvisionFetchInput::Tick { now } => self.spawn_pending_fetches(now),
        }
    }

    /// Check whether there are any pending provision fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Returns the number of pending fetches for a given source shard.
    #[allow(dead_code)] // Used in tests; will be used for metrics/coordinator integration.
    pub fn pending_count_for_shard(&self, shard: ShardGroupId) -> usize {
        self.pending.keys().filter(|(s, _)| *s == shard).count()
    }

    /// Returns true if the given source shard has reached its pending fetch limit.
    #[allow(dead_code)] // Used in tests; will be used for metrics/coordinator integration.
    pub fn is_shard_saturated(&self, shard: ShardGroupId) -> bool {
        self.pending_count_for_shard(shard) >= self.config.max_pending_per_shard
    }

    /// Returns the number of currently in-flight fetch operations.
    pub fn in_flight_count(&self) -> usize {
        self.pending.values().filter(|s| s.in_flight).count()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_request(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        target_shard: ShardGroupId,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);

        if let Some(existing) = self.pending.get_mut(&key) {
            // Duplicate request: refresh peer list, reset rounds and backoff.
            existing.peers = peers;
            existing.preferred_peer = preferred_peer;
            existing.rounds = 0;
            existing.next_retry_at = None;
            trace!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Refreshed peer list for pending provision fetch"
            );
            return vec![];
        }

        // Check per-shard cap to prevent unbounded accumulation when a shard is down.
        // When the cap is reached, evict the oldest (lowest block height) entry for
        // that shard. Newer heights are more relevant for making progress.
        let shard_pending = self
            .pending
            .keys()
            .filter(|(s, _)| *s == source_shard)
            .count();
        if shard_pending >= self.config.max_pending_per_shard {
            // Find the oldest entry (lowest block height) for this shard.
            let oldest_key = self
                .pending
                .keys()
                .filter(|(s, _)| *s == source_shard)
                .min_by_key(|(_, h)| *h)
                .copied();
            if let Some(oldest) = oldest_key {
                warn!(
                    source_shard = source_shard.0,
                    evicted_height = oldest.1 .0,
                    new_height = block_height.0,
                    limit = self.config.max_pending_per_shard,
                    "Evicting oldest provision fetch to make room (shard pending limit)"
                );
                self.pending.remove(&oldest);
            }
        }

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            peer_count = peers.len(),
            "Starting provision fetch"
        );
        metrics::record_fetch_started("provision");

        self.pending.insert(
            key,
            PendingProvisionFetch {
                target_shard,
                peers,
                preferred_peer,
                tried: HashSet::new(),
                in_flight: false,
                rounds: 0,
                next_retry_at: None,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        batch: ProvisionBatch,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                count = batch.transactions.len(),
                "Provision fetch complete"
            );
            metrics::record_fetch_completed("provision");
            vec![ProvisionFetchOutput::Deliver { batch }]
        } else {
            trace!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Provisions received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_cancel(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Provision fetch cancelled (proactive provisions verified)"
            );
        }
        vec![]
    }

    fn handle_failed(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);
        if let Some(state) = self.pending.get_mut(&key) {
            state.in_flight = false;
            metrics::record_fetch_failed("provision");
            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                tried = state.tried.len(),
                remaining = state.peers.len().saturating_sub(state.tried.len()),
                "Provision fetch failed, will try next peer"
            );
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<ProvisionFetchOutput> {
        let mut outputs = Vec::new();

        let in_flight_count = self.pending.values().filter(|s| s.in_flight).count();
        let mut available_slots = self.config.max_concurrent.saturating_sub(in_flight_count);

        for (&(source_shard, block_height), state) in &mut self.pending {
            if available_slots == 0 {
                break;
            }
            if state.in_flight {
                continue;
            }
            if let Some(retry_at) = state.next_retry_at {
                if now < retry_at {
                    continue;
                }
                state.next_retry_at = None;
            }

            let peer = if !state.tried.contains(&state.preferred_peer) {
                Some(state.preferred_peer)
            } else {
                state
                    .peers
                    .iter()
                    .find(|p| !state.tried.contains(p))
                    .copied()
            };

            match peer {
                Some(peer) => {
                    state.tried.insert(peer);
                    state.in_flight = true;
                    available_slots -= 1;
                    trace!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        peer = peer.0,
                        "Fetching provisions from peer"
                    );
                    outputs.push(ProvisionFetchOutput::Fetch {
                        source_shard,
                        block_height,
                        target_shard: state.target_shard,
                        peer,
                    });
                }
                None => {
                    state.rounds += 1;
                    state.tried.clear();
                    let backoff = std::time::Duration::from_millis(
                        (500u64 * 2u64.saturating_pow(state.rounds)).min(30_000),
                    );
                    state.next_retry_at = Some(now + backoff);
                    info!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        round = state.rounds,
                        backoff_ms = backoff.as_millis(),
                        "Provision fetch exhausted peers, backing off"
                    );
                }
            }
        }

        outputs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Inbound request serving
// ═══════════════════════════════════════════════════════════════════════

/// Serve an inbound provision request from a target shard needing our state.
///
/// Looks up the block at the requested height, identifies transactions
/// that involve the requesting shard, collects the local state entries
/// and merkle proofs, and returns them as `StateProvision`s.
///
/// Takes `local_shard` and `num_shards` instead of `&TopologyState`
/// to avoid topology dependency in the I/O layer.
pub fn serve_provision_request(
    storage: &(impl ChainReader + SubstateStore),
    local_shard: ShardGroupId,
    num_shards: u64,
    req: GetProvisionsRequest,
) -> GetProvisionsResponse {
    let (block, _qc) = match storage.get_block(req.block_height) {
        Some(pair) => pair,
        None => {
            warn!(
                block_height = req.block_height.0,
                "Provision request: block not found"
            );
            return GetProvisionsResponse {
                provisions: None,
                proof: None,
            };
        }
    };

    let jvt_version = block.header.height.0;

    let all_txs = block.transactions.iter();

    // Phase 1: Fetch state entries for all matching transactions.
    let mut per_tx: Vec<(
        hyperscale_types::Hash,
        Arc<Vec<hyperscale_types::StateEntry>>,
    )> = Vec::new();
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for tx in all_txs {
        // Check if this transaction involves the requesting target shard
        let involves_target = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .any(|node_id| {
                hyperscale_types::shard_for_node(node_id, num_shards) == req.target_shard
            });
        if !involves_target {
            continue;
        }

        let mut owned_nodes: Vec<_> = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .filter(|&node_id| hyperscale_types::shard_for_node(node_id, num_shards) == local_shard)
            .copied()
            .collect();
        owned_nodes.sort();
        owned_nodes.dedup();

        if owned_nodes.is_empty() {
            continue;
        }

        let entries =
            match hyperscale_engine::fetch_state_entries(storage, &owned_nodes, jvt_version) {
                Some(entries) => entries,
                None => {
                    warn!(
                        block_height = req.block_height.0,
                        jvt_version, "Provision request: historical JVT version unavailable"
                    );
                    return GetProvisionsResponse {
                        provisions: None,
                        proof: None,
                    };
                }
            };
        for e in &entries {
            all_storage_keys.push(e.storage_key.clone());
        }
        per_tx.push((tx.hash(), Arc::new(entries)));
    }

    if per_tx.is_empty() {
        return GetProvisionsResponse {
            provisions: Some(vec![]),
            proof: None,
        };
    }

    // Phase 2: Generate ONE batched proof covering all entries.
    all_storage_keys.sort();
    all_storage_keys.dedup();
    let proof = match storage.generate_verkle_proofs(&all_storage_keys, jvt_version) {
        Some(p) => Arc::new(p),
        None => {
            tracing::warn!(
                block_height = req.block_height.0,
                "Fallback provision: batched proof generation failed (version unavailable)"
            );
            return GetProvisionsResponse {
                provisions: None,
                proof: None,
            };
        }
    };

    // Phase 3: Build provisions sharing the single proof.
    let mut provisions = Vec::with_capacity(per_tx.len());
    for (tx_hash, entries) in per_tx {
        provisions.push(StateProvision {
            transaction_hash: tx_hash,
            target_shard: req.target_shard,
            source_shard: local_shard,
            block_height: req.block_height,
            block_timestamp: block.header.timestamp,
            entries,
        });
    }

    GetProvisionsResponse {
        provisions: Some(provisions),
        proof: Some((*proof).clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn default_config() -> ProvisionFetchConfig {
        ProvisionFetchConfig::default()
    }

    fn shard(id: u64) -> ShardGroupId {
        ShardGroupId(id)
    }

    fn height(h: u64) -> BlockHeight {
        BlockHeight(h)
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn tick(now: Instant) -> ProvisionFetchInput {
        ProvisionFetchInput::Tick { now }
    }

    #[test]
    fn test_config_defaults() {
        let config = ProvisionFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_pending_per_shard, 8);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        // Submit a request.
        let outputs = protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the preferred peer.
        let now = Instant::now();
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ProvisionFetchOutput::Fetch {
                source_shard,
                block_height,
                target_shard,
                peer,
            } => {
                assert_eq!(*source_shard, shard(1));
                assert_eq!(*block_height, height(10));
                assert_eq!(*target_shard, shard(0));
                assert_eq!(*peer, vid(1)); // preferred peer first
            }
            _ => panic!("Expected Fetch output"),
        }
    }

    #[test]
    fn test_peer_rotation_on_failure() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });

        // Tick 1: preferred peer (vid(1)).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail → frees in_flight.
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // Tick 2: next untried peer (vid(2)).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));

        // Fail again.
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // Tick 3: last peer (vid(3)).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(3)
        ));
    }

    #[test]
    fn test_all_peers_exhausted_backs_off_and_retries() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        // Try vid(1), fail.
        protocol.handle(tick(now));
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // All peers exhausted → backoff. Tick during backoff: no fetch.
        let outputs = protocol.handle(tick(now));
        assert!(outputs.is_empty());
        assert!(protocol.has_pending(), "Should NOT be dropped");

        // Tick after backoff expires: should retry.
        let outputs = protocol.handle(tick(now + Duration::from_secs(2)));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));
    }

    #[test]
    fn test_successful_receive() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Tick → fetch from vid(1).
        protocol.handle(tick(now));

        // Receive provisions.
        let outputs = protocol.handle(ProvisionFetchInput::Received {
            source_shard: shard(1),
            block_height: height(10),
            batch: ProvisionBatch::dummy(shard(1), height(10)),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Deliver { batch } if batch.transactions.is_empty()
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_duplicate_request_refreshes_peers() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Try vid(1) and fail.
        protocol.handle(tick(now));
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // Duplicate request with fresh peer list.
        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });

        // vid(1) already tried, so should try vid(2).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }

    #[test]
    fn test_max_concurrent_respected() {
        let now = Instant::now();
        let config = ProvisionFetchConfig {
            max_concurrent: 2,
            ..default_config()
        };
        let mut protocol = ProvisionFetchProtocol::new(config);

        // Submit 3 requests.
        for h in 10..13 {
            protocol.handle(ProvisionFetchInput::Request {
                source_shard: shard(1),
                block_height: height(h),
                target_shard: shard(0),
                peers: vec![vid(1)],
                preferred_peer: vid(1),
            });
        }

        // Tick should only emit 2 fetches (max_concurrent = 2).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_receive_for_unknown_fetch_ignored() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        let outputs = protocol.handle(ProvisionFetchInput::Received {
            source_shard: shard(99),
            block_height: height(999),
            batch: ProvisionBatch::dummy(shard(99), height(999)),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // First tick dispatches.
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);

        // Second tick while still in-flight: no new dispatch.
        let outputs = protocol.handle(tick(now));
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_removes_pending_fetch() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        // Submit a request.
        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });
        assert!(protocol.has_pending());

        // Cancel the request.
        let outputs = protocol.handle(ProvisionFetchInput::Cancel {
            source_shard: shard(1),
            block_height: height(10),
        });
        assert!(outputs.is_empty());
        assert!(
            !protocol.has_pending(),
            "Cancel should remove the pending fetch"
        );

        // Tick should have nothing to dispatch.
        let outputs = protocol.handle(tick(now));
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_unknown_fetch_is_noop() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        // Cancel for non-existent fetch — should not panic.
        let outputs = protocol.handle(ProvisionFetchInput::Cancel {
            source_shard: shard(99),
            block_height: height(999),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_in_flight_fetch() {
        let now = Instant::now();
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        // Tick dispatches the fetch (in-flight).
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        assert!(protocol.has_pending());

        // Cancel while in-flight — should still remove the pending entry.
        protocol.handle(ProvisionFetchInput::Cancel {
            source_shard: shard(1),
            block_height: height(10),
        });
        assert!(
            !protocol.has_pending(),
            "Cancel should remove even in-flight fetches"
        );
    }

    #[test]
    fn test_per_shard_pending_cap_evicts_oldest() {
        let config = ProvisionFetchConfig {
            max_pending_per_shard: 3,
            ..default_config()
        };
        let mut protocol = ProvisionFetchProtocol::new(config);

        // Fill up to the cap for shard 1.
        for h in 10..13 {
            protocol.handle(ProvisionFetchInput::Request {
                source_shard: shard(1),
                block_height: height(h),
                target_shard: shard(0),
                peers: vec![vid(1), vid(2)],
                preferred_peer: vid(1),
            });
        }
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 3);
        assert!(protocol.is_shard_saturated(shard(1)));

        // 4th request should evict the oldest (height 10) and insert height 13.
        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(13),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });
        assert_eq!(
            protocol.pending_count_for_shard(shard(1)),
            3,
            "Should still be 3 after eviction"
        );
        // Height 10 should be gone, height 13 should be present.
        assert!(
            !protocol.pending.contains_key(&(shard(1), height(10))),
            "Oldest entry (height 10) should have been evicted"
        );
        assert!(
            protocol.pending.contains_key(&(shard(1), height(13))),
            "New entry (height 13) should be present"
        );

        // Requests for a DIFFERENT shard should still be accepted independently.
        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(2),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(3)],
            preferred_peer: vid(3),
        });
        assert_eq!(protocol.pending_count_for_shard(shard(2)), 1);
    }

    #[test]
    fn test_per_shard_cap_frees_on_receive() {
        let config = ProvisionFetchConfig {
            max_pending_per_shard: 2,
            ..default_config()
        };
        let mut protocol = ProvisionFetchProtocol::new(config);

        // Fill to cap.
        for h in 10..12 {
            protocol.handle(ProvisionFetchInput::Request {
                source_shard: shard(1),
                block_height: height(h),
                target_shard: shard(0),
                peers: vec![vid(1)],
                preferred_peer: vid(1),
            });
        }
        assert!(protocol.is_shard_saturated(shard(1)));

        // Complete one fetch — should free a slot.
        protocol.handle(ProvisionFetchInput::Received {
            source_shard: shard(1),
            block_height: height(10),
            batch: ProvisionBatch::dummy(shard(1), height(10)),
        });
        assert!(!protocol.is_shard_saturated(shard(1)));

        // New request should now be accepted without eviction.
        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(12),
            target_shard: shard(0),
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);
    }
}
