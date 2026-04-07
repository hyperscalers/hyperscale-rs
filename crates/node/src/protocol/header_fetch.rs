//! Committed block header fetch protocol state machine.
//!
//! Pure synchronous state machine for cross-shard committed block header
//! fetching with per-peer rotation. Sits between the `RemoteHeaderCoordinator`'s
//! `RequestMissingCommittedBlockHeader` action and the actual `network.request()`
//! call, rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► HeaderFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId, ValidatorId};
use std::collections::{BTreeMap, HashSet};
use tracing::{debug, trace, warn};

/// Configuration for the header fetch protocol.
#[derive(Debug, Clone)]
pub struct HeaderFetchConfig {
    /// Maximum number of concurrent fetch operations.
    pub max_concurrent: usize,
    /// Maximum full rounds through all peers before giving up.
    pub max_rounds: u32,
    /// Maximum number of pending fetch entries per source shard.
    pub max_pending_per_shard: usize,
}

impl Default for HeaderFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_rounds: 3,
            max_pending_per_shard: 8,
        }
    }
}

/// Inputs to the header fetch protocol state machine.
#[derive(Debug)]
pub enum HeaderFetchInput {
    /// A new fetch request from the remote header coordinator.
    Request {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        peers: Vec<ValidatorId>,
    },
    /// A committed block header was successfully received.
    Received {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        header: Box<CommittedBlockHeader>,
    },
    /// A fetch attempt failed (network error or peer returned None).
    Failed {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    },
    /// Cancel a pending fetch (header arrived via gossip).
    #[allow(dead_code)]
    Cancel {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    },
    /// Periodic tick — spawn pending fetch operations.
    Tick,
}

/// Outputs from the header fetch protocol state machine.
#[derive(Debug)]
pub enum HeaderFetchOutput {
    /// Request the runner to fetch a committed block header from a specific peer.
    Fetch {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        peer: ValidatorId,
    },
    /// Deliver fetched header to the state machine.
    Deliver { header: Box<CommittedBlockHeader> },
}

/// State for a single pending header fetch.
#[derive(Debug)]
struct PendingHeaderFetch {
    peers: Vec<ValidatorId>,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
    rounds: u32,
}

/// Committed block header fetch protocol state machine.
pub struct HeaderFetchProtocol {
    config: HeaderFetchConfig,
    /// Pending fetches keyed by (source_shard, from_height).
    pending: BTreeMap<(ShardGroupId, BlockHeight), PendingHeaderFetch>,
}

impl HeaderFetchProtocol {
    /// Create a new header fetch protocol state machine.
    pub fn new(config: HeaderFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: HeaderFetchInput) -> Vec<HeaderFetchOutput> {
        match input {
            HeaderFetchInput::Request {
                source_shard,
                from_height,
                peers,
            } => self.handle_request(source_shard, from_height, peers),
            HeaderFetchInput::Received {
                source_shard,
                from_height,
                header,
            } => self.handle_received(source_shard, from_height, header),
            HeaderFetchInput::Failed {
                source_shard,
                from_height,
            } => self.handle_failed(source_shard, from_height),
            HeaderFetchInput::Cancel {
                source_shard,
                from_height,
            } => self.handle_cancel(source_shard, from_height),
            HeaderFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Check whether there are any pending header fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Returns the number of pending fetches for a given source shard.
    #[allow(dead_code)]
    pub fn pending_count_for_shard(&self, shard: ShardGroupId) -> usize {
        self.pending.keys().filter(|(s, _)| *s == shard).count()
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
        from_height: BlockHeight,
        peers: Vec<ValidatorId>,
    ) -> Vec<HeaderFetchOutput> {
        let key = (source_shard, from_height);

        if let Some(existing) = self.pending.get_mut(&key) {
            // Duplicate request: refresh peers, reset rounds.
            existing.peers = peers;
            existing.rounds = 0;
            trace!(
                source_shard = source_shard.0,
                from_height = from_height.0,
                "Refreshed peer list for pending header fetch"
            );
            return vec![];
        }

        // Check per-shard cap — evict oldest if at limit.
        let shard_pending = self
            .pending
            .keys()
            .filter(|(s, _)| *s == source_shard)
            .count();
        if shard_pending >= self.config.max_pending_per_shard {
            let oldest_key = self
                .pending
                .keys()
                .filter(|(s, _)| *s == source_shard)
                .min_by_key(|(_, h)| h.0)
                .copied();
            if let Some(oldest) = oldest_key {
                warn!(
                    source_shard = source_shard.0,
                    evicted_height = oldest.1 .0,
                    new_height = from_height.0,
                    limit = self.config.max_pending_per_shard,
                    "Evicting oldest header fetch to make room (shard pending limit)"
                );
                self.pending.remove(&oldest);
            }
        }

        debug!(
            source_shard = source_shard.0,
            from_height = from_height.0,
            peer_count = peers.len(),
            "Starting committed block header fetch"
        );
        metrics::record_fetch_started("header");

        self.pending.insert(
            key,
            PendingHeaderFetch {
                peers,
                tried: HashSet::new(),
                in_flight: false,
                rounds: 0,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        header: Box<CommittedBlockHeader>,
    ) -> Vec<HeaderFetchOutput> {
        let key = (source_shard, from_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                from_height = from_height.0,
                "Header fetch complete"
            );
            metrics::record_fetch_completed("header");
            vec![HeaderFetchOutput::Deliver { header }]
        } else {
            trace!(
                source_shard = source_shard.0,
                from_height = from_height.0,
                "Header received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_cancel(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    ) -> Vec<HeaderFetchOutput> {
        let key = (source_shard, from_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                from_height = from_height.0,
                "Header fetch cancelled"
            );
        }
        vec![]
    }

    fn handle_failed(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    ) -> Vec<HeaderFetchOutput> {
        let key = (source_shard, from_height);
        if let Some(state) = self.pending.get_mut(&key) {
            state.in_flight = false;
            metrics::record_fetch_failed("header");
            warn!(
                source_shard = source_shard.0,
                from_height = from_height.0,
                tried = state.tried.len(),
                remaining = state.peers.len().saturating_sub(state.tried.len()),
                "Header fetch failed, will try next peer"
            );
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    fn spawn_pending_fetches(&mut self) -> Vec<HeaderFetchOutput> {
        let mut outputs = Vec::new();
        let mut to_remove = Vec::new();

        // Count current in-flight to respect max_concurrent.
        let in_flight_count = self.pending.values().filter(|s| s.in_flight).count();
        let mut available_slots = self.config.max_concurrent.saturating_sub(in_flight_count);

        for (&(source_shard, from_height), state) in &mut self.pending {
            if available_slots == 0 {
                break;
            }
            if state.in_flight {
                continue;
            }

            // Pick the first untried peer.
            let peer = state
                .peers
                .iter()
                .find(|p| !state.tried.contains(p))
                .copied();

            match peer {
                Some(peer) => {
                    state.tried.insert(peer);
                    state.in_flight = true;
                    available_slots -= 1;
                    trace!(
                        source_shard = source_shard.0,
                        from_height = from_height.0,
                        peer = peer.0,
                        "Fetching committed block header from peer"
                    );
                    outputs.push(HeaderFetchOutput::Fetch {
                        source_shard,
                        from_height,
                        peer,
                    });
                }
                None => {
                    state.rounds += 1;
                    if state.rounds >= self.config.max_rounds {
                        warn!(
                            source_shard = source_shard.0,
                            from_height = from_height.0,
                            rounds = state.rounds,
                            "Header fetch exhausted all rounds, dropping"
                        );
                        to_remove.push((source_shard, from_height));
                    } else {
                        warn!(
                            source_shard = source_shard.0,
                            from_height = from_height.0,
                            round = state.rounds,
                            "Header fetch starting new round"
                        );
                        state.tried.clear();
                    }
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

    fn default_config() -> HeaderFetchConfig {
        HeaderFetchConfig::default()
    }

    fn shard(id: u64) -> ShardGroupId {
        ShardGroupId(id)
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn height(h: u64) -> BlockHeight {
        BlockHeight(h)
    }

    #[test]
    fn test_config_defaults() {
        let config = HeaderFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_rounds, 3);
        assert_eq!(config.max_pending_per_shard, 8);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = HeaderFetchProtocol::new(default_config());

        let outputs = protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(10),
            peers: vec![vid(1), vid(2), vid(3)],
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the first peer.
        let outputs = protocol.handle(HeaderFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            HeaderFetchOutput::Fetch {
                source_shard,
                from_height,
                peer,
            } => {
                assert_eq!(*source_shard, shard(1));
                assert_eq!(*from_height, height(10));
                assert_eq!(*peer, vid(1));
            }
            _ => panic!("Expected Fetch output"),
        }
    }

    #[test]
    fn test_peer_rotation_on_failure() {
        let mut protocol = HeaderFetchProtocol::new(default_config());

        protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(10),
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // Tick 1: vid(1).
        let outputs = protocol.handle(HeaderFetchInput::Tick);
        assert!(matches!(
            &outputs[0],
            HeaderFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail → frees in_flight.
        protocol.handle(HeaderFetchInput::Failed {
            source_shard: shard(1),
            from_height: height(10),
        });

        // Tick 2: next untried peer (vid(2)).
        let outputs = protocol.handle(HeaderFetchInput::Tick);
        assert!(matches!(
            &outputs[0],
            HeaderFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }

    #[test]
    fn test_all_peers_exhausted_after_max_rounds() {
        let config = HeaderFetchConfig {
            max_rounds: 2,
            ..default_config()
        };
        let mut protocol = HeaderFetchProtocol::new(config);

        protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(10),
            peers: vec![vid(1)],
        });

        // Round 0: try vid(1), fail.
        protocol.handle(HeaderFetchInput::Tick);
        protocol.handle(HeaderFetchInput::Failed {
            source_shard: shard(1),
            from_height: height(10),
        });
        // All peers exhausted → round 0→1, reset tried.
        protocol.handle(HeaderFetchInput::Tick);

        // Round 1: try vid(1) again, fail.
        let outputs = protocol.handle(HeaderFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        protocol.handle(HeaderFetchInput::Failed {
            source_shard: shard(1),
            from_height: height(10),
        });
        // All peers exhausted → round 1→2, but max_rounds=2 → drop.
        protocol.handle(HeaderFetchInput::Tick);
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = HeaderFetchProtocol::new(default_config());

        protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(10),
            peers: vec![vid(1)],
        });

        protocol.handle(HeaderFetchInput::Tick);

        let header = make_test_header(1, 10);
        let outputs = protocol.handle(HeaderFetchInput::Received {
            source_shard: shard(1),
            from_height: height(10),
            header: Box::new(header),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(&outputs[0], HeaderFetchOutput::Deliver { .. }));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_removes_pending() {
        let mut protocol = HeaderFetchProtocol::new(default_config());

        protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(10),
            peers: vec![vid(1)],
        });
        assert!(protocol.has_pending());

        protocol.handle(HeaderFetchInput::Cancel {
            source_shard: shard(1),
            from_height: height(10),
        });
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_per_shard_cap_evicts_oldest() {
        let config = HeaderFetchConfig {
            max_pending_per_shard: 2,
            ..default_config()
        };
        let mut protocol = HeaderFetchProtocol::new(config);

        for h in 10..12 {
            protocol.handle(HeaderFetchInput::Request {
                source_shard: shard(1),
                from_height: height(h),
                peers: vec![vid(1)],
            });
        }
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);

        // 3rd request should evict height 10.
        protocol.handle(HeaderFetchInput::Request {
            source_shard: shard(1),
            from_height: height(12),
            peers: vec![vid(1)],
        });
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);
        assert!(!protocol.pending.contains_key(&(shard(1), height(10))));
        assert!(protocol.pending.contains_key(&(shard(1), height(12))));
    }

    #[test]
    fn test_max_concurrent_respected() {
        let config = HeaderFetchConfig {
            max_concurrent: 2,
            ..default_config()
        };
        let mut protocol = HeaderFetchProtocol::new(config);

        for h in 10..13 {
            protocol.handle(HeaderFetchInput::Request {
                source_shard: shard(1),
                from_height: height(h),
                peers: vec![vid(1)],
            });
        }

        let outputs = protocol.handle(HeaderFetchInput::Tick);
        assert_eq!(outputs.len(), 2);
    }

    fn make_test_header(shard_id: u64, h: u64) -> CommittedBlockHeader {
        use hyperscale_types::{BlockHeader, Hash, QuorumCertificate};

        let header = BlockHeader {
            shard_group_id: ShardGroupId(shard_id),
            height: BlockHeight(h),
            parent_hash: Hash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 0,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            receipt_root: Hash::ZERO,
            waves: vec![],
        };
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header.hash();
        qc.shard_group_id = ShardGroupId(shard_id);
        qc.height = BlockHeight(h);
        CommittedBlockHeader::new(header, qc)
    }
}
