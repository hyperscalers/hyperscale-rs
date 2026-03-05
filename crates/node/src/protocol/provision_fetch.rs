//! Provision fetch protocol state machine.
//!
//! Pure synchronous state machine for cross-shard provision fetching with
//! per-peer rotation. Sits between the `ProvisionCoordinator`'s
//! `RequestMissingProvisions` action and the actual `network.request()` call,
//! rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► ProvisionFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_types::{BlockHeight, ShardGroupId, StateProvision, ValidatorId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace};

/// Configuration for the provision fetch protocol.
#[derive(Debug, Clone)]
pub struct ProvisionFetchConfig {
    /// Maximum number of concurrent provision fetch operations.
    pub max_concurrent: usize,
}

impl Default for ProvisionFetchConfig {
    fn default() -> Self {
        Self { max_concurrent: 4 }
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
        provisions: Vec<StateProvision>,
    },
    /// A fetch attempt failed (network error or peer returned None).
    Failed {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    },
    /// Periodic tick — spawn pending fetch operations.
    Tick,
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
    Deliver { provisions: Vec<StateProvision> },
}

/// State for a single pending provision fetch.
#[derive(Debug)]
struct PendingProvisionFetch {
    target_shard: ShardGroupId,
    peers: Vec<ValidatorId>,
    preferred_peer: ValidatorId,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
}

/// Provision fetch protocol state machine.
pub struct ProvisionFetchProtocol {
    config: ProvisionFetchConfig,
    /// Pending fetches keyed by (source_shard, block_height).
    pending: HashMap<(ShardGroupId, BlockHeight), PendingProvisionFetch>,
}

impl ProvisionFetchProtocol {
    /// Create a new provision fetch protocol state machine.
    pub fn new(config: ProvisionFetchConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
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
                provisions,
            } => self.handle_received(source_shard, block_height, provisions),
            ProvisionFetchInput::Failed {
                source_shard,
                block_height,
            } => self.handle_failed(source_shard, block_height),
            ProvisionFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Check whether there are any pending provision fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
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
            // Duplicate request: refresh peer list but keep tried set.
            existing.peers = peers;
            existing.preferred_peer = preferred_peer;
            trace!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Refreshed peer list for pending provision fetch"
            );
            return vec![];
        }

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            peer_count = peers.len(),
            "Starting provision fetch"
        );

        self.pending.insert(
            key,
            PendingProvisionFetch {
                target_shard,
                peers,
                preferred_peer,
                tried: HashSet::new(),
                in_flight: false,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        provisions: Vec<StateProvision>,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                count = provisions.len(),
                "Provision fetch complete"
            );
            vec![ProvisionFetchOutput::Deliver { provisions }]
        } else {
            trace!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Provisions received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_failed(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    ) -> Vec<ProvisionFetchOutput> {
        let key = (source_shard, block_height);
        if let Some(state) = self.pending.get_mut(&key) {
            state.in_flight = false;
            debug!(
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
    fn spawn_pending_fetches(&mut self) -> Vec<ProvisionFetchOutput> {
        let mut outputs = Vec::new();
        let mut to_remove = Vec::new();

        // Count current in-flight to respect max_concurrent.
        let in_flight_count = self.pending.values().filter(|s| s.in_flight).count();
        let mut available_slots = self.config.max_concurrent.saturating_sub(in_flight_count);

        for (&(source_shard, block_height), state) in &mut self.pending {
            if available_slots == 0 {
                break;
            }
            if state.in_flight {
                continue;
            }

            // Pick the next peer to try.
            let peer = if !state.tried.contains(&state.preferred_peer) {
                // Prefer the proposer if not yet tried.
                Some(state.preferred_peer)
            } else {
                // Pick the first untried peer.
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
                    // All peers exhausted — drop entry so coordinator can re-emit.
                    debug!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        "All peers exhausted for provision fetch, dropping entry"
                    );
                    to_remove.push((source_shard, block_height));
                }
            }
        }

        for key in to_remove {
            self.pending.remove(&key);
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_config_defaults() {
        let config = ProvisionFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
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
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
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
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });

        // Tick 1: preferred peer (vid(1)).
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
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
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
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
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(3)
        ));
    }

    #[test]
    fn test_all_peers_exhausted() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Try vid(1).
        protocol.handle(ProvisionFetchInput::Tick);
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // Try vid(2).
        protocol.handle(ProvisionFetchInput::Tick);
        protocol.handle(ProvisionFetchInput::Failed {
            source_shard: shard(1),
            block_height: height(10),
        });

        // All peers exhausted — tick should drop the entry.
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Tick → fetch from vid(1).
        protocol.handle(ProvisionFetchInput::Tick);

        // Receive provisions.
        let outputs = protocol.handle(ProvisionFetchInput::Received {
            source_shard: shard(1),
            block_height: height(10),
            provisions: vec![], // empty but valid
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Deliver { provisions } if provisions.is_empty()
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_duplicate_request_refreshes_peers() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Try vid(1) and fail.
        protocol.handle(ProvisionFetchInput::Tick);
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
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ProvisionFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }

    #[test]
    fn test_max_concurrent_respected() {
        let config = ProvisionFetchConfig { max_concurrent: 2 };
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
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_receive_for_unknown_fetch_ignored() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        let outputs = protocol.handle(ProvisionFetchInput::Received {
            source_shard: shard(99),
            block_height: height(999),
            provisions: vec![],
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let mut protocol = ProvisionFetchProtocol::new(default_config());

        protocol.handle(ProvisionFetchInput::Request {
            source_shard: shard(1),
            block_height: height(10),
            target_shard: shard(0),
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // First tick dispatches.
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert_eq!(outputs.len(), 1);

        // Second tick while still in-flight: no new dispatch.
        let outputs = protocol.handle(ProvisionFetchInput::Tick);
        assert!(outputs.is_empty());
    }
}
