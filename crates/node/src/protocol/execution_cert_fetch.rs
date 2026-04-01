//! Execution certificate fetch protocol state machine.
//!
//! Pure synchronous state machine for cross-shard execution certificate
//! fetching with per-peer rotation. Sits between the `ExecutionState`'s
//! `RequestMissingExecutionCerts` action and the actual `network.request()`
//! call, rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► ExecCertFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_metrics as metrics;
use hyperscale_types::{ExecutionCertificate, ShardGroupId, ValidatorId, WaveId};
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace, warn};

/// Configuration for the execution certificate fetch protocol.
#[derive(Debug, Clone)]
pub struct ExecCertFetchConfig {
    /// Maximum number of concurrent fetch operations.
    pub max_concurrent: usize,
    /// Maximum full rounds through all peers before giving up.
    pub max_rounds: u32,
    /// Maximum number of pending fetch entries per source shard.
    ///
    /// Prevents unbounded accumulation when a remote shard is down: without
    /// this cap, every timed-out block height adds a new entry, each of which
    /// goes through max_rounds × peers retries before draining.
    /// When the cap is reached, the oldest entry for that shard is evicted.
    pub max_pending_per_shard: usize,
}

impl Default for ExecCertFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_rounds: 3,
            max_pending_per_shard: 8,
        }
    }
}

/// Inputs to the execution certificate fetch protocol state machine.
#[derive(Debug)]
pub enum ExecCertFetchInput {
    /// A new fetch request from the execution state machine.
    Request {
        source_shard: ShardGroupId,
        block_height: u64,
        wave_ids: Vec<WaveId>,
        peers: Vec<ValidatorId>,
    },
    /// Execution certificates were successfully received.
    Received {
        source_shard: ShardGroupId,
        block_height: u64,
        certificates: Vec<ExecutionCertificate>,
    },
    /// A fetch attempt failed (network error or peer returned None).
    Failed {
        source_shard: ShardGroupId,
        block_height: u64,
    },
    /// Cancel a pending fetch (cert arrived via proactive path).
    #[allow(dead_code)]
    Cancel {
        source_shard: ShardGroupId,
        block_height: u64,
    },
    /// Periodic tick — spawn pending fetch operations.
    Tick,
}

/// Outputs from the execution certificate fetch protocol state machine.
#[derive(Debug)]
pub enum ExecCertFetchOutput {
    /// Request the runner to fetch execution certs from a specific peer.
    Fetch {
        source_shard: ShardGroupId,
        block_height: u64,
        wave_ids: Vec<WaveId>,
        peer: ValidatorId,
    },
    /// Deliver fetched certificates to the state machine.
    Deliver {
        certificates: Vec<ExecutionCertificate>,
    },
}

/// State for a single pending execution certificate fetch.
#[derive(Debug)]
struct PendingExecCertFetch {
    wave_ids: Vec<WaveId>,
    peers: Vec<ValidatorId>,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
    rounds: u32,
}

/// Execution certificate fetch protocol state machine.
pub struct ExecCertFetchProtocol {
    config: ExecCertFetchConfig,
    /// Pending fetches keyed by (source_shard, block_height).
    pending: HashMap<(ShardGroupId, u64), PendingExecCertFetch>,
}

impl ExecCertFetchProtocol {
    /// Create a new execution certificate fetch protocol state machine.
    pub fn new(config: ExecCertFetchConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: ExecCertFetchInput) -> Vec<ExecCertFetchOutput> {
        match input {
            ExecCertFetchInput::Request {
                source_shard,
                block_height,
                wave_ids,
                peers,
            } => self.handle_request(source_shard, block_height, wave_ids, peers),
            ExecCertFetchInput::Received {
                source_shard,
                block_height,
                certificates,
            } => self.handle_received(source_shard, block_height, certificates),
            ExecCertFetchInput::Failed {
                source_shard,
                block_height,
            } => self.handle_failed(source_shard, block_height),
            ExecCertFetchInput::Cancel {
                source_shard,
                block_height,
            } => self.handle_cancel(source_shard, block_height),
            ExecCertFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Check whether there are any pending execution certificate fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Returns the number of pending fetches for a given source shard.
    #[allow(dead_code)]
    pub fn pending_count_for_shard(&self, shard: ShardGroupId) -> usize {
        self.pending.keys().filter(|(s, _)| *s == shard).count()
    }

    /// Returns true if the given source shard has reached its pending fetch limit.
    #[allow(dead_code)]
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
        block_height: u64,
        wave_ids: Vec<WaveId>,
        peers: Vec<ValidatorId>,
    ) -> Vec<ExecCertFetchOutput> {
        let key = (source_shard, block_height);

        if let Some(existing) = self.pending.get_mut(&key) {
            // Duplicate request: merge wave_ids, refresh peers, reset rounds.
            for wid in &wave_ids {
                if !existing.wave_ids.contains(wid) {
                    existing.wave_ids.push(wid.clone());
                }
            }
            existing.peers = peers;
            existing.rounds = 0;
            trace!(
                source_shard = source_shard.0,
                block_height,
                "Refreshed peer list for pending exec cert fetch"
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
                .min_by_key(|(_, h)| *h)
                .copied();
            if let Some(oldest) = oldest_key {
                warn!(
                    source_shard = source_shard.0,
                    evicted_height = oldest.1,
                    new_height = block_height,
                    limit = self.config.max_pending_per_shard,
                    "Evicting oldest exec cert fetch to make room (shard pending limit)"
                );
                self.pending.remove(&oldest);
            }
        }

        debug!(
            source_shard = source_shard.0,
            block_height,
            wave_count = wave_ids.len(),
            peer_count = peers.len(),
            "Starting exec cert fetch"
        );
        metrics::record_fetch_started("exec_cert");

        self.pending.insert(
            key,
            PendingExecCertFetch {
                wave_ids,
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
        block_height: u64,
        certificates: Vec<ExecutionCertificate>,
    ) -> Vec<ExecCertFetchOutput> {
        let key = (source_shard, block_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                block_height,
                count = certificates.len(),
                "Exec cert fetch complete"
            );
            metrics::record_fetch_completed("exec_cert");
            vec![ExecCertFetchOutput::Deliver { certificates }]
        } else {
            trace!(
                source_shard = source_shard.0,
                block_height,
                "Exec certs received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_cancel(
        &mut self,
        source_shard: ShardGroupId,
        block_height: u64,
    ) -> Vec<ExecCertFetchOutput> {
        let key = (source_shard, block_height);
        if self.pending.remove(&key).is_some() {
            debug!(
                source_shard = source_shard.0,
                block_height, "Exec cert fetch cancelled"
            );
        }
        vec![]
    }

    fn handle_failed(
        &mut self,
        source_shard: ShardGroupId,
        block_height: u64,
    ) -> Vec<ExecCertFetchOutput> {
        let key = (source_shard, block_height);
        if let Some(state) = self.pending.get_mut(&key) {
            state.in_flight = false;
            metrics::record_fetch_failed("exec_cert");
            warn!(
                source_shard = source_shard.0,
                block_height,
                tried = state.tried.len(),
                remaining = state.peers.len().saturating_sub(state.tried.len()),
                "Exec cert fetch failed, will try next peer"
            );
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    fn spawn_pending_fetches(&mut self) -> Vec<ExecCertFetchOutput> {
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

            // Pick the first untried peer (no preferred peer for exec certs).
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
                        block_height,
                        peer = peer.0,
                        "Fetching exec certs from peer"
                    );
                    outputs.push(ExecCertFetchOutput::Fetch {
                        source_shard,
                        block_height,
                        wave_ids: state.wave_ids.clone(),
                        peer,
                    });
                }
                None => {
                    state.rounds += 1;
                    if state.rounds >= self.config.max_rounds {
                        warn!(
                            source_shard = source_shard.0,
                            block_height,
                            rounds = state.rounds,
                            "Exec cert fetch exhausted all rounds, dropping"
                        );
                        to_remove.push((source_shard, block_height));
                    } else {
                        warn!(
                            source_shard = source_shard.0,
                            block_height,
                            round = state.rounds,
                            "Exec cert fetch starting new round"
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

    fn default_config() -> ExecCertFetchConfig {
        ExecCertFetchConfig::default()
    }

    fn shard(id: u64) -> ShardGroupId {
        ShardGroupId(id)
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn wave(shards: &[u64]) -> WaveId {
        WaveId(shards.iter().map(|&s| ShardGroupId(s)).collect())
    }

    #[test]
    fn test_config_defaults() {
        let config = ExecCertFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_rounds, 3);
        assert_eq!(config.max_pending_per_shard, 8);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        // Submit a request.
        let outputs = protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2), vid(3)],
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the first peer.
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            ExecCertFetchOutput::Fetch {
                source_shard,
                block_height,
                wave_ids,
                peer,
            } => {
                assert_eq!(*source_shard, shard(1));
                assert_eq!(*block_height, 10);
                assert_eq!(wave_ids.len(), 1);
                assert_eq!(*peer, vid(1));
            }
            _ => panic!("Expected Fetch output"),
        }
    }

    #[test]
    fn test_peer_rotation_on_failure() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // Tick 1: vid(1).
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail → frees in_flight.
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });

        // Tick 2: next untried peer (vid(2)).
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));

        // Fail again.
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });

        // Tick 3: last peer (vid(3)).
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(3)
        ));
    }

    #[test]
    fn test_all_peers_exhausted_after_max_rounds() {
        let config = ExecCertFetchConfig {
            max_rounds: 2,
            ..default_config()
        };
        let mut protocol = ExecCertFetchProtocol::new(config);

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });

        // --- Round 0 ---
        protocol.handle(ExecCertFetchInput::Tick);
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        protocol.handle(ExecCertFetchInput::Tick);
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        // All peers exhausted → round 0→1, tried reset.
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(
            protocol.has_pending(),
            "Should still be pending after round 0"
        );

        // --- Round 1 ---
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1, "Should retry vid(1) in round 1");
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        protocol.handle(ExecCertFetchInput::Tick);
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        // All peers exhausted → round 1→2, but max_rounds=2 → drop.
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert!(outputs.is_empty());
        assert!(
            !protocol.has_pending(),
            "Should be dropped after max_rounds"
        );
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });

        // Tick → fetch from vid(1).
        protocol.handle(ExecCertFetchInput::Tick);

        // Receive certificates.
        let outputs = protocol.handle(ExecCertFetchInput::Received {
            source_shard: shard(1),
            block_height: 10,
            certificates: vec![],
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Deliver { certificates } if certificates.is_empty()
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_duplicate_request_merges_wave_ids() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });

        // Duplicate request with additional wave_ids.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1]), wave(&[0, 2])],
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // Should have merged wave_ids.
        let state = protocol.pending.get(&(shard(1), 10)).unwrap();
        assert_eq!(state.wave_ids.len(), 2); // original + new unique one
        assert_eq!(state.peers.len(), 3); // refreshed
    }

    #[test]
    fn test_max_concurrent_respected() {
        let config = ExecCertFetchConfig {
            max_concurrent: 2,
            ..default_config()
        };
        let mut protocol = ExecCertFetchProtocol::new(config);

        // Submit 3 requests.
        for h in 10..13 {
            protocol.handle(ExecCertFetchInput::Request {
                source_shard: shard(1),
                block_height: h,
                wave_ids: vec![wave(&[0, 1])],
                peers: vec![vid(1)],
            });
        }

        // Tick should only emit 2 fetches (max_concurrent = 2).
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_receive_for_unknown_fetch_ignored() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        let outputs = protocol.handle(ExecCertFetchInput::Received {
            source_shard: shard(99),
            block_height: 999,
            certificates: vec![],
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });

        // First tick dispatches.
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);

        // Second tick while still in-flight: no new dispatch.
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_removes_pending_fetch() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });
        assert!(protocol.has_pending());

        let outputs = protocol.handle(ExecCertFetchInput::Cancel {
            source_shard: shard(1),
            block_height: 10,
        });
        assert!(outputs.is_empty());
        assert!(
            !protocol.has_pending(),
            "Cancel should remove the pending fetch"
        );
    }

    #[test]
    fn test_cancel_unknown_fetch_is_noop() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        let outputs = protocol.handle(ExecCertFetchInput::Cancel {
            source_shard: shard(99),
            block_height: 999,
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_in_flight_fetch() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1)],
        });

        // Tick dispatches the fetch (in-flight).
        let outputs = protocol.handle(ExecCertFetchInput::Tick);
        assert_eq!(outputs.len(), 1);
        assert!(protocol.has_pending());

        // Cancel while in-flight — should still remove.
        protocol.handle(ExecCertFetchInput::Cancel {
            source_shard: shard(1),
            block_height: 10,
        });
        assert!(
            !protocol.has_pending(),
            "Cancel should remove even in-flight fetches"
        );
    }

    #[test]
    fn test_per_shard_pending_cap_evicts_oldest() {
        let config = ExecCertFetchConfig {
            max_pending_per_shard: 3,
            ..default_config()
        };
        let mut protocol = ExecCertFetchProtocol::new(config);

        // Fill up to the cap for shard 1.
        for h in 10..13 {
            protocol.handle(ExecCertFetchInput::Request {
                source_shard: shard(1),
                block_height: h,
                wave_ids: vec![wave(&[0, 1])],
                peers: vec![vid(1), vid(2)],
            });
        }
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 3);
        assert!(protocol.is_shard_saturated(shard(1)));

        // 4th request should evict the oldest (height 10) and insert height 13.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 13,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1), vid(2)],
        });
        assert_eq!(
            protocol.pending_count_for_shard(shard(1)),
            3,
            "Should still be 3 after eviction"
        );
        assert!(
            !protocol.pending.contains_key(&(shard(1), 10)),
            "Oldest entry (height 10) should have been evicted"
        );
        assert!(
            protocol.pending.contains_key(&(shard(1), 13)),
            "New entry (height 13) should be present"
        );

        // Requests for a DIFFERENT shard should still be accepted independently.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(2),
            block_height: 10,
            wave_ids: vec![wave(&[0, 2])],
            peers: vec![vid(3)],
        });
        assert_eq!(protocol.pending_count_for_shard(shard(2)), 1);
    }

    #[test]
    fn test_per_shard_cap_frees_on_receive() {
        let config = ExecCertFetchConfig {
            max_pending_per_shard: 2,
            ..default_config()
        };
        let mut protocol = ExecCertFetchProtocol::new(config);

        // Fill to cap.
        for h in 10..12 {
            protocol.handle(ExecCertFetchInput::Request {
                source_shard: shard(1),
                block_height: h,
                wave_ids: vec![wave(&[0, 1])],
                peers: vec![vid(1)],
            });
        }
        assert!(protocol.is_shard_saturated(shard(1)));

        // Complete one fetch — should free a slot.
        protocol.handle(ExecCertFetchInput::Received {
            source_shard: shard(1),
            block_height: 10,
            certificates: vec![],
        });
        assert!(!protocol.is_shard_saturated(shard(1)));

        // New request should now be accepted without eviction.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 12,
            wave_ids: vec![wave(&[0, 1])],
            peers: vec![vid(1)],
        });
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);
    }
}
