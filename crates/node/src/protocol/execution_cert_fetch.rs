//! Execution certificate fetch protocol state machine.
//!
//! Pure synchronous state machine for cross-shard execution certificate
//! fetching with per-peer rotation. Sits between the `ExecutionState`'s
//! `RequestMissingExecutionCert` action and the actual `network.request()`
//! call, rotating through available peers on failure before giving up.
//!
//! # Usage
//!
//! ```text
//! Runner ──► ExecCertFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_metrics as metrics;
use hyperscale_types::{ExecutionCertificate, ShardGroupId, ValidatorId, WaveId};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Configuration for the execution certificate fetch protocol.
#[derive(Debug, Clone)]
pub struct ExecCertFetchConfig {
    /// Maximum number of concurrent fetch operations.
    pub max_concurrent: usize,
    /// Maximum number of pending fetch entries per source shard.
    ///
    /// Prevents unbounded accumulation when a remote shard is down: without
    /// this cap, every timed-out block height adds a new entry.
    /// When the cap is reached, tiered eviction removes the least valuable entry.
    pub max_pending_per_shard: usize,
}

impl Default for ExecCertFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
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
        wave_id: WaveId,
        /// Wave leader for the missing wave (tried first as preferred peer).
        wave_leader: ValidatorId,
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
    Tick { now: Instant, committed_height: u64 },
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
    /// Wave leaders for the missing waves (tried first as preferred peers).
    wave_leaders: Vec<ValidatorId>,
    peers: Vec<ValidatorId>,
    tried: HashSet<ValidatorId>,
    in_flight: bool,
    rounds: u32,
    /// Backoff: don't retry until this instant (set after exhausting all peers).
    next_retry_at: Option<Instant>,
}

/// Execution certificate fetch protocol state machine.
pub struct ExecCertFetchProtocol {
    config: ExecCertFetchConfig,
    /// Pending fetches keyed by (source_shard, block_height).
    pending: BTreeMap<(ShardGroupId, u64), PendingExecCertFetch>,
}

impl ExecCertFetchProtocol {
    /// Create a new execution certificate fetch protocol state machine.
    pub fn new(config: ExecCertFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: ExecCertFetchInput) -> Vec<ExecCertFetchOutput> {
        match input {
            ExecCertFetchInput::Request {
                source_shard,
                block_height,
                wave_id,
                wave_leader,
                peers,
            } => self.handle_request(source_shard, block_height, wave_id, wave_leader, peers),
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
            ExecCertFetchInput::Tick {
                now,
                committed_height,
            } => self.spawn_pending_fetches(now, committed_height),
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
        wave_id: WaveId,
        wave_leader: ValidatorId,
        peers: Vec<ValidatorId>,
    ) -> Vec<ExecCertFetchOutput> {
        let key = (source_shard, block_height);

        if let Some(existing) = self.pending.get_mut(&key) {
            // Duplicate request: merge wave_id + wave_leader, refresh peers, reset rounds.
            if !existing.wave_ids.contains(&wave_id) {
                existing.wave_ids.push(wave_id);
            }
            if !existing.wave_leaders.contains(&wave_leader) {
                existing.wave_leaders.push(wave_leader);
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

        // Check per-shard cap — evict via tiered policy if at limit.
        let shard_pending = self
            .pending
            .keys()
            .filter(|(s, _)| *s == source_shard)
            .count();
        if shard_pending >= self.config.max_pending_per_shard {
            // Use block_height as a proxy for committed_height in eviction —
            // entries below the new request's height are likely stale.
            self.evict_one(source_shard, block_height.saturating_sub(1));
        }

        debug!(
            source_shard = source_shard.0,
            block_height,
            wave = %wave_id,
            peer_count = peers.len(),
            "Starting exec cert fetch"
        );
        metrics::record_fetch_started("exec_cert");

        self.pending.insert(
            key,
            PendingExecCertFetch {
                wave_ids: vec![wave_id],
                wave_leaders: vec![wave_leader],
                peers,
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
            debug!(
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
    fn spawn_pending_fetches(
        &mut self,
        now: Instant,
        _committed_height: u64,
    ) -> Vec<ExecCertFetchOutput> {
        let mut outputs = Vec::new();

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

            // Respect backoff: skip entries that haven't reached their retry time.
            if let Some(retry_at) = state.next_retry_at {
                if now < retry_at {
                    continue;
                }
                // Backoff expired — clear it and proceed.
                state.next_retry_at = None;
            }

            // Prefer wave leaders first (if in peer list), then rotate through remaining peers.
            let peer = state
                .wave_leaders
                .iter()
                .find(|p| !state.tried.contains(p) && state.peers.contains(p))
                .or_else(|| state.peers.iter().find(|p| !state.tried.contains(p)))
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
                    // All peers exhausted — start new round with exponential backoff.
                    state.rounds += 1;
                    state.tried.clear();
                    let backoff = Duration::from_millis(
                        (500u64 * 2u64.saturating_pow(state.rounds)).min(30_000),
                    );
                    state.next_retry_at = Some(now + backoff);
                    info!(
                        source_shard = source_shard.0,
                        block_height,
                        round = state.rounds,
                        backoff_ms = backoff.as_millis(),
                        "Exec cert fetch exhausted peers, backing off"
                    );
                }
            }
        }

        outputs
    }

    /// Tiered eviction: prefer entries below committed_height (truly stale),
    /// fall back to oldest-by-height.
    fn evict_one(&mut self, source_shard: ShardGroupId, committed_height: u64) {
        // Tier 1: below committed_height (truly stale)
        let stale = self
            .pending
            .keys()
            .filter(|(s, _)| *s == source_shard)
            .filter(|(_, h)| *h <= committed_height)
            .min_by_key(|(_, h)| *h)
            .copied();
        // Tier 2: oldest by height (fallback)
        let target = stale.or_else(|| {
            self.pending
                .keys()
                .filter(|(s, _)| *s == source_shard)
                .min_by_key(|(_, h)| *h)
                .copied()
        });
        if let Some(key) = target {
            warn!(
                source_shard = source_shard.0,
                evicted_height = key.1,
                committed_height,
                "Evicting exec cert fetch entry (tiered eviction)"
            );
            self.pending.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ExecCertFetchConfig {
        ExecCertFetchConfig::default()
    }

    fn tick() -> ExecCertFetchInput {
        ExecCertFetchInput::Tick {
            now: Instant::now(),
            committed_height: 0,
        }
    }

    fn tick_at(now: Instant, committed_height: u64) -> ExecCertFetchInput {
        ExecCertFetchInput::Tick {
            now,
            committed_height,
        }
    }

    fn shard(id: u64) -> ShardGroupId {
        ShardGroupId(id)
    }

    fn vid(id: u64) -> ValidatorId {
        ValidatorId(id)
    }

    fn wave(shards: &[u64]) -> WaveId {
        WaveId::new(
            ShardGroupId(0),
            1,
            shards.iter().map(|&s| ShardGroupId(s)).collect(),
        )
    }

    #[test]
    fn test_config_defaults() {
        let config = ExecCertFetchConfig::default();
        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_pending_per_shard, 8);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        // Submit a request.
        let outputs = protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2), vid(3)],
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a Fetch with the first peer.
        let outputs = protocol.handle(tick());
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
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // Tick 1: vid(1).
        let outputs = protocol.handle(tick());
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
        let outputs = protocol.handle(tick());
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
        let outputs = protocol.handle(tick());
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(3)
        ));
    }

    #[test]
    fn test_entries_survive_exhausting_all_peers() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2)],
        });

        let now = Instant::now();

        // Exhaust all peers in round 0.
        protocol.handle(tick_at(now, 0));
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        protocol.handle(tick_at(now, 0));
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });

        // All peers exhausted → backoff set, entry NOT dropped.
        let outputs = protocol.handle(tick_at(now, 0));
        assert!(outputs.is_empty(), "Should be in backoff");
        assert!(
            protocol.has_pending(),
            "Entry must survive peer exhaustion (durable fetch)"
        );

        // Tick during backoff window → still no fetch.
        let outputs = protocol.handle(tick_at(now + Duration::from_millis(500), 0));
        assert!(outputs.is_empty(), "Still in backoff window");

        // Tick after backoff expires → retry with reset peers.
        let outputs = protocol.handle(tick_at(now + Duration::from_secs(2), 0));
        assert_eq!(outputs.len(), 1, "Should retry after backoff");
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));
    }

    #[test]
    fn test_backoff_increases_exponentially() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1)],
        });

        let now = Instant::now();

        // Exhaust round 0 (1 peer).
        protocol.handle(tick_at(now, 0));
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        // All peers exhausted → round 1, backoff = 500ms * 2^1 = 1000ms
        protocol.handle(tick_at(now, 0));

        // Check state: rounds=1, next_retry_at set.
        let state = protocol.pending.get(&(shard(1), 10)).unwrap();
        assert_eq!(state.rounds, 1);
        assert!(state.next_retry_at.is_some());

        // Tick at 999ms → still backing off.
        let outputs = protocol.handle(tick_at(now + Duration::from_millis(999), 0));
        assert!(outputs.is_empty());

        // Tick at 1001ms → retry.
        let outputs = protocol.handle(tick_at(now + Duration::from_millis(1001), 0));
        assert_eq!(outputs.len(), 1);

        // Fail again, exhaust round 1 → round 2, backoff = 500ms * 2^2 = 2000ms
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        let now2 = now + Duration::from_millis(1001);
        protocol.handle(tick_at(now2, 0));
        let state = protocol.pending.get(&(shard(1), 10)).unwrap();
        assert_eq!(state.rounds, 2);
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2)],
        });

        // Tick → fetch from vid(1).
        protocol.handle(tick());

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
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2)],
        });

        // Duplicate request with a different wave_id.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 2]),
            wave_leader: vid(99),
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
                wave_id: wave(&[0, 1]),
                wave_leader: vid(99),
                peers: vec![vid(1)],
            });
        }

        // Tick should only emit 2 fetches (max_concurrent = 2).
        let outputs = protocol.handle(tick());
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
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1), vid(2)],
        });

        // First tick dispatches.
        let outputs = protocol.handle(tick());
        assert_eq!(outputs.len(), 1);

        // Second tick while still in-flight: no new dispatch.
        let outputs = protocol.handle(tick());
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_cancel_removes_pending_fetch() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
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
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1)],
        });

        // Tick dispatches the fetch (in-flight).
        let outputs = protocol.handle(tick());
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
                wave_id: wave(&[0, 1]),
                wave_leader: vid(99),
                peers: vec![vid(1), vid(2)],
            });
        }
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 3);
        assert!(protocol.is_shard_saturated(shard(1)));

        // 4th request should evict the oldest (height 10) and insert height 13.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 13,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
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
            wave_id: wave(&[0, 2]),
            wave_leader: vid(99),
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
                wave_id: wave(&[0, 1]),
                wave_leader: vid(99),
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
            wave_id: wave(&[0, 1]),
            wave_leader: vid(99),
            peers: vec![vid(1)],
        });
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);
    }

    #[test]
    fn test_tiered_eviction_prefers_stale() {
        let config = ExecCertFetchConfig {
            max_pending_per_shard: 3,
            ..default_config()
        };
        let mut protocol = ExecCertFetchProtocol::new(config);

        // Add entries at heights 5, 15, 25.
        for h in [5, 15, 25] {
            protocol.handle(ExecCertFetchInput::Request {
                source_shard: shard(1),
                block_height: h,
                wave_id: wave(&[0, 1]),
                wave_leader: vid(99),
                peers: vec![vid(1)],
            });
        }
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 3);

        // Evict with committed_height=20 — should prefer height 5 (below committed).
        protocol.evict_one(shard(1), 20);
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 2);
        assert!(
            !protocol.pending.contains_key(&(shard(1), 5)),
            "Stale entry (height 5 < committed 20) should be evicted first"
        );
        assert!(protocol.pending.contains_key(&(shard(1), 15)));
        assert!(protocol.pending.contains_key(&(shard(1), 25)));

        // Evict again with committed_height=14 — height 15 is above, no stale entries.
        // Falls back to oldest-by-height → evicts 15.
        protocol.evict_one(shard(1), 14);
        assert_eq!(protocol.pending_count_for_shard(shard(1)), 1);
        assert!(
            protocol.pending.contains_key(&(shard(1), 25)),
            "Only height 25 should remain"
        );
    }

    #[test]
    fn test_wave_leader_preferred_first() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        // vid(5) is the wave leader, peers are vid(1)..vid(5).
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(5),
            peers: vec![vid(1), vid(2), vid(3), vid(4), vid(5)],
        });

        // First tick should prefer the wave leader vid(5).
        let outputs = protocol.handle(tick());
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(5)
        ));

        // Fail → next tick should fall back to regular peer rotation.
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        let outputs = protocol.handle(tick());
        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));
    }

    #[test]
    fn test_wave_leader_skipped_when_already_tried() {
        let mut protocol = ExecCertFetchProtocol::new(default_config());

        // Wave leader is vid(1), which is also the first regular peer.
        protocol.handle(ExecCertFetchInput::Request {
            source_shard: shard(1),
            block_height: 10,
            wave_id: wave(&[0, 1]),
            wave_leader: vid(1),
            peers: vec![vid(1), vid(2), vid(3)],
        });

        // First tick: wave leader vid(1).
        let outputs = protocol.handle(tick());
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(1)
        ));

        // Fail → wave leader already tried, should go to vid(2).
        protocol.handle(ExecCertFetchInput::Failed {
            source_shard: shard(1),
            block_height: 10,
        });
        let outputs = protocol.handle(tick());
        assert!(matches!(
            &outputs[0],
            ExecCertFetchOutput::Fetch { peer, .. } if *peer == vid(2)
        ));
    }
}
