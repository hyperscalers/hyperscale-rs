//! Inclusion proof fetch protocol state machine.
//!
//! Pure synchronous state machine for fetching transaction inclusion proofs
//! from source shards during livelock resolution. Sits between the livelock
//! system's `RequestTxInclusionProofs` action and the actual `network.request()`
//! call, rotating through available peers on failure with exponential backoff.
//!
//! Multiple proofs for the same `(source_shard, block_height, peer)` are
//! batched into a single `FetchBatch` output to reduce network round-trips.
//!
//! # Usage
//!
//! ```text
//! Runner ──► InclusionProofFetchProtocol::handle(Input) ──► Vec<Output>
//! ```

use hyperscale_core::InclusionProofFetchReason;
use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHeight, Hash, ShardGroupId, TransactionInclusionProof, ValidatorId};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// Configuration for the inclusion proof fetch protocol.
#[derive(Debug, Clone)]
pub struct InclusionProofFetchConfig {
    /// Maximum number of retries per peer before rotating to the next.
    pub max_retries_per_peer: u32,
    /// Maximum number of concurrent in-flight fetch batches.
    pub max_concurrent: usize,
}

impl Default for InclusionProofFetchConfig {
    fn default() -> Self {
        Self {
            max_retries_per_peer: 3,
            max_concurrent: 8,
        }
    }
}

/// Inputs to the inclusion proof fetch protocol state machine.
#[derive(Debug)]
pub enum InclusionProofFetchInput {
    /// A new fetch request (livelock deferral or priority tx proof).
    Request {
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        winner_tx_hash: Hash,
        reason: InclusionProofFetchReason,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    },
    /// Proof was successfully received.
    Received {
        winner_tx_hash: Hash,
        reason: InclusionProofFetchReason,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    },
    /// A fetch attempt failed.
    Failed { winner_tx_hash: Hash },
    /// Cancel a pending fetch.
    #[allow(dead_code)]
    Cancel { winner_tx_hash: Hash },
    /// Periodic tick — spawn pending fetch operations.
    Tick { now: Instant },
}

/// Outputs from the inclusion proof fetch protocol state machine.
#[derive(Debug)]
pub enum InclusionProofFetchOutput {
    /// Send a batched network request to a peer for multiple proofs from the same block.
    FetchBatch {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        /// Each entry: (tx_hash, reason) — reason needed for routing the response.
        entries: Vec<(Hash, InclusionProofFetchReason)>,
        peer: ValidatorId,
    },
    /// Deliver the proof to the state machine.
    Deliver {
        winner_tx_hash: Hash,
        reason: InclusionProofFetchReason,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    },
}

/// State for a single pending inclusion proof fetch.
#[derive(Debug)]
struct PendingInclusionProofFetch {
    source_shard: ShardGroupId,
    source_block_height: BlockHeight,
    reason: InclusionProofFetchReason,
    peers: Vec<ValidatorId>,
    preferred_peer: ValidatorId,
    tried: HashSet<ValidatorId>,
    retries_on_current: u32,
    current_peer: Option<ValidatorId>,
    in_flight: bool,
    /// How many full rounds through all peers have been completed.
    rounds: u32,
    /// When set, the fetch is in backoff and should not be retried until this time.
    next_retry_at: Option<Instant>,
}

/// Inclusion proof fetch protocol state machine.
pub struct InclusionProofFetchProtocol {
    config: InclusionProofFetchConfig,
    /// Pending fetches keyed by winner_tx_hash.
    pending: BTreeMap<Hash, PendingInclusionProofFetch>,
}

impl InclusionProofFetchProtocol {
    /// Create a new inclusion proof fetch protocol state machine.
    pub fn new(config: InclusionProofFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: InclusionProofFetchInput) -> Vec<InclusionProofFetchOutput> {
        match input {
            InclusionProofFetchInput::Request {
                source_shard,
                source_block_height,
                winner_tx_hash,
                reason,
                peers,
                preferred_peer,
            } => self.handle_request(
                source_shard,
                source_block_height,
                winner_tx_hash,
                reason,
                peers,
                preferred_peer,
            ),
            InclusionProofFetchInput::Received {
                winner_tx_hash,
                reason,
                source_shard,
                source_block_height,
                proof,
            } => self.handle_received(
                winner_tx_hash,
                reason,
                source_shard,
                source_block_height,
                proof,
            ),
            InclusionProofFetchInput::Failed { winner_tx_hash } => {
                self.handle_failed(winner_tx_hash)
            }
            InclusionProofFetchInput::Cancel { winner_tx_hash } => {
                self.handle_cancel(winner_tx_hash)
            }
            InclusionProofFetchInput::Tick { now } => self.spawn_pending_fetches(now),
        }
    }

    /// Check whether there are any pending inclusion proof fetches.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
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
        source_block_height: BlockHeight,
        winner_tx_hash: Hash,
        reason: InclusionProofFetchReason,
        peers: Vec<ValidatorId>,
        preferred_peer: ValidatorId,
    ) -> Vec<InclusionProofFetchOutput> {
        if let Some(existing) = self.pending.get_mut(&winner_tx_hash) {
            // Duplicate request: refresh peer list, reset retries for fresh cycle.
            existing.peers = peers;
            existing.preferred_peer = preferred_peer;
            existing.retries_on_current = 0;
            existing.current_peer = None;
            existing.tried.clear();
            trace!(
                winner_tx = %winner_tx_hash,
                "Refreshed peer list for pending inclusion proof fetch"
            );
            return vec![];
        }

        debug!(
            winner_tx = %winner_tx_hash,
            source_shard = source_shard.0,
            block_height = source_block_height.0,
            peer_count = peers.len(),
            "Starting inclusion proof fetch"
        );
        metrics::record_fetch_started("inclusion_proof");

        self.pending.insert(
            winner_tx_hash,
            PendingInclusionProofFetch {
                source_shard,
                source_block_height,
                reason,
                peers,
                preferred_peer,
                tried: HashSet::new(),
                retries_on_current: 0,
                current_peer: None,
                in_flight: false,
                rounds: 0,
                next_retry_at: None,
            },
        );
        vec![]
    }

    fn handle_received(
        &mut self,
        winner_tx_hash: Hash,
        reason: InclusionProofFetchReason,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    ) -> Vec<InclusionProofFetchOutput> {
        if self.pending.remove(&winner_tx_hash).is_some() {
            debug!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof fetch complete"
            );
            metrics::record_fetch_completed("inclusion_proof");
            vec![InclusionProofFetchOutput::Deliver {
                winner_tx_hash,
                reason,
                source_shard,
                source_block_height,
                proof,
            }]
        } else {
            trace!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof received for unknown fetch"
            );
            vec![]
        }
    }

    fn handle_cancel(&mut self, winner_tx_hash: Hash) -> Vec<InclusionProofFetchOutput> {
        if self.pending.remove(&winner_tx_hash).is_some() {
            debug!(
                winner_tx = %winner_tx_hash,
                "Inclusion proof fetch cancelled"
            );
        }
        vec![]
    }

    fn handle_failed(&mut self, winner_tx_hash: Hash) -> Vec<InclusionProofFetchOutput> {
        if let Some(state) = self.pending.get_mut(&winner_tx_hash) {
            state.in_flight = false;
            state.retries_on_current += 1;
            metrics::record_fetch_failed("inclusion_proof");

            // If we've exhausted retries on the current peer, mark it as tried
            // and move to the next one.
            if state.retries_on_current >= self.config.max_retries_per_peer {
                if let Some(peer) = state.current_peer.take() {
                    state.tried.insert(peer);
                }
                state.retries_on_current = 0;
            }

            debug!(
                winner_tx = %winner_tx_hash,
                tried = state.tried.len(),
                retries_on_current = state.retries_on_current,
                "Inclusion proof fetch failed, will retry"
            );
        }
        vec![]
    }

    /// Spawn pending fetch operations (called on Tick).
    ///
    /// Groups ready-to-fetch entries by `(source_shard, block_height, peer)` and
    /// emits one `FetchBatch` output per group to reduce network round-trips.
    /// Respects `max_concurrent` to avoid saturating the network.
    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<InclusionProofFetchOutput> {
        // Respect concurrency limit — count current in-flight entries.
        let in_flight_count = self.pending.values().filter(|s| s.in_flight).count();
        if in_flight_count >= self.config.max_concurrent {
            return vec![];
        }
        let mut available_slots = self.config.max_concurrent - in_flight_count;

        // Phase 1: determine peer for each non-in-flight pending entry.
        // Collect (tx_hash, resolved_peer) for entries that have a peer,
        // and tx_hashes for entries that need backoff reset.
        let mut ready: Vec<(Hash, ValidatorId)> = Vec::new();
        let mut backoff_reset: Vec<Hash> = Vec::new();

        for (&winner_tx_hash, state) in &self.pending {
            if state.in_flight {
                continue;
            }
            if available_slots == 0 {
                break;
            }

            // If in backoff, skip until the retry time has elapsed.
            if let Some(retry_at) = state.next_retry_at {
                if now < retry_at {
                    continue;
                }
            }

            // If we have a current peer that hasn't exhausted retries, reuse it.
            if let Some(peer) = state.current_peer {
                ready.push((winner_tx_hash, peer));
                continue;
            }

            // Pick the next peer to try.
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
                    ready.push((winner_tx_hash, peer));
                    available_slots -= 1;
                }
                None => {
                    // All peers exhausted — enter exponential backoff and retry from scratch.
                    backoff_reset.push(winner_tx_hash);
                }
            }
        }

        for key in backoff_reset {
            let state = self.pending.get_mut(&key).unwrap();
            state.rounds += 1;
            state.tried.clear();
            state.current_peer = None;
            state.retries_on_current = 0;
            let backoff = Duration::from_millis(500)
                .saturating_mul(1u32.checked_shl(state.rounds.min(16)).unwrap_or(u32::MAX));
            let backoff = backoff.min(Duration::from_secs(30));
            state.next_retry_at = Some(now + backoff);
            info!(
                winner_tx = %key,
                round = state.rounds,
                backoff_ms = backoff.as_millis() as u64,
                "Inclusion proof fetch exhausted all peers, backing off"
            );
        }

        // Phase 2: group by (source_shard, block_height, peer) and build batch outputs.
        let mut batches: BTreeMap<
            (ShardGroupId, BlockHeight, ValidatorId),
            Vec<(Hash, InclusionProofFetchReason)>,
        > = BTreeMap::new();

        for (winner_tx_hash, peer) in &ready {
            let state = self.pending.get_mut(winner_tx_hash).unwrap();
            // Update peer state (may be setting a new peer or reusing current).
            if state.current_peer.is_none() {
                state.current_peer = Some(*peer);
                state.retries_on_current = 0;
            }
            state.in_flight = true;

            let key = (state.source_shard, state.source_block_height, *peer);
            batches
                .entry(key)
                .or_default()
                .push((*winner_tx_hash, state.reason.clone()));
        }

        // Phase 3: emit one FetchBatch per group.
        let mut outputs = Vec::with_capacity(batches.len());
        for ((source_shard, block_height, peer), entries) in batches {
            trace!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                peer = peer.0,
                batch_size = entries.len(),
                "Fetching inclusion proof batch from peer"
            );
            outputs.push(InclusionProofFetchOutput::FetchBatch {
                source_shard,
                block_height,
                entries,
                peer,
            });
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn default_config() -> InclusionProofFetchConfig {
        InclusionProofFetchConfig::default()
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

    fn tx_hash(val: u8) -> Hash {
        let bytes = [val; 1];
        Hash::from_bytes(&bytes)
    }

    fn dummy_proof() -> TransactionInclusionProof {
        TransactionInclusionProof {
            siblings: vec![],
            leaf_index: 0,
        }
    }

    fn tick(now: Instant) -> InclusionProofFetchInput {
        InclusionProofFetchInput::Tick { now }
    }

    /// Helper: extract the single FetchBatch from outputs, panicking if not exactly one.
    fn expect_single_fetch_batch(
        outputs: &[InclusionProofFetchOutput],
    ) -> (
        &ShardGroupId,
        &BlockHeight,
        &[(Hash, InclusionProofFetchReason)],
        &ValidatorId,
    ) {
        assert_eq!(outputs.len(), 1, "Expected exactly one FetchBatch output");
        match &outputs[0] {
            InclusionProofFetchOutput::FetchBatch {
                source_shard,
                block_height,
                entries,
                peer,
            } => (source_shard, block_height, entries, peer),
            other => panic!("Expected FetchBatch, got {:?}", other),
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = InclusionProofFetchConfig::default();
        assert_eq!(config.max_retries_per_peer, 3);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        let outputs = protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(1),
        });
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // Tick should emit a FetchBatch with the preferred peer.
        let outputs = protocol.handle(tick(now));
        let (src_shard, blk_height, entries, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*src_shard, shard(1));
        assert_eq!(*blk_height, height(10));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, tx_hash(1));
        assert_eq!(*peer, vid(1));
    }

    #[test]
    fn test_retry_same_peer_then_rotate() {
        let config = InclusionProofFetchConfig {
            max_retries_per_peer: 2,
            ..default_config()
        };
        let mut protocol = InclusionProofFetchProtocol::new(config);
        let now = Instant::now();

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Tick 1: preferred peer (vid(1)).
        let outputs = protocol.handle(tick(now));
        let (_, _, _, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*peer, vid(1));

        // Fail once — should retry same peer (retries_on_current < 2).
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });
        let outputs = protocol.handle(tick(now));
        let (_, _, _, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*peer, vid(1));

        // Fail again — now retries_on_current reaches 2, rotate to vid(2).
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });
        let outputs = protocol.handle(tick(now));
        let (_, _, _, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*peer, vid(2));
    }

    #[test]
    fn test_all_peers_exhausted_backs_off_then_retries() {
        let config = InclusionProofFetchConfig {
            max_retries_per_peer: 1,
            ..default_config()
        };
        let mut protocol = InclusionProofFetchProtocol::new(config);
        let now = Instant::now();

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        // Try vid(1), fail (exhausted after 1 retry).
        protocol.handle(tick(now));
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });

        // Try vid(2), fail.
        protocol.handle(tick(now));
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });

        // All peers exhausted — should enter backoff (round 1 = 1s).
        // Tick immediately: still in backoff, no output.
        let outputs = protocol.handle(tick(now));
        assert!(outputs.is_empty());
        // Entry is still pending (not dropped).
        assert!(protocol.has_pending());

        // Tick too early (500ms) — still in backoff.
        let outputs = protocol.handle(tick(now + Duration::from_millis(500)));
        assert!(outputs.is_empty());

        // Tick after backoff expires (1s) — should retry from scratch with preferred peer.
        let outputs = protocol.handle(tick(
            now + Duration::from_secs(1) + Duration::from_millis(1),
        ));
        let (_, _, _, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*peer, vid(1));

        // Exhaust all peers again — round 2, backoff = 2s.
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });
        let later = now + Duration::from_secs(2);
        protocol.handle(tick(later));
        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(1),
        });

        // Trigger backoff reset (round 2).
        let outputs = protocol.handle(tick(later));
        assert!(outputs.is_empty());
        assert!(protocol.has_pending());

        // After 2s backoff — should retry again.
        let outputs = protocol.handle(tick(
            later + Duration::from_secs(2) + Duration::from_millis(1),
        ));
        assert_eq!(outputs.len(), 1);
    }

    #[test]
    fn test_successful_receive() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        protocol.handle(tick(now));

        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });

        assert_eq!(outputs.len(), 1);
        assert!(matches!(
            &outputs[0],
            InclusionProofFetchOutput::Deliver { winner_tx_hash, .. } if *winner_tx_hash == tx_hash(1)
        ));
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_removes_pending() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });
        assert!(protocol.has_pending());

        protocol.handle(InclusionProofFetchInput::Cancel {
            winner_tx_hash: tx_hash(1),
        });
        assert!(!protocol.has_pending());
    }

    #[test]
    fn test_cancel_unknown_is_noop() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let outputs = protocol.handle(InclusionProofFetchInput::Cancel {
            winner_tx_hash: tx_hash(99),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_receive_for_unknown_ignored() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(99),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(100),
            },
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_in_flight_not_double_dispatched() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1), vid(2)],
            preferred_peer: vid(1),
        });

        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);

        // Second tick while in-flight: no new dispatch.
        let outputs = protocol.handle(tick(now));
        assert!(outputs.is_empty());
    }

    #[test]
    fn test_duplicate_request_refreshes_peers() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        // Submit duplicate with different peers.
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(2),
            },
            peers: vec![vid(1), vid(2), vid(3)],
            preferred_peer: vid(2),
        });

        // Should use the new preferred peer.
        let outputs = protocol.handle(tick(now));
        let (_, _, _, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*peer, vid(2));
    }

    #[test]
    fn test_batching_same_block_same_peer() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        // Register 3 fetches for the same (shard, height) with same preferred peer.
        for i in 1..=3u8 {
            protocol.handle(InclusionProofFetchInput::Request {
                source_shard: shard(1),
                source_block_height: height(10),
                winner_tx_hash: tx_hash(i),
                reason: InclusionProofFetchReason::Deferral {
                    loser_tx_hash: tx_hash(0),
                },
                peers: vec![vid(1), vid(2)],
                preferred_peer: vid(1),
            });
        }

        // Tick should produce a single FetchBatch with all 3 entries.
        let outputs = protocol.handle(tick(now));
        let (src_shard, blk_height, entries, peer) = expect_single_fetch_batch(&outputs);
        assert_eq!(*src_shard, shard(1));
        assert_eq!(*blk_height, height(10));
        assert_eq!(*peer, vid(1));
        assert_eq!(entries.len(), 3);

        let mut hashes: Vec<Hash> = entries.iter().map(|(h, _)| *h).collect();
        hashes.sort();
        let mut expected = vec![tx_hash(1), tx_hash(2), tx_hash(3)];
        expected.sort();
        assert_eq!(hashes, expected);
    }

    #[test]
    fn test_batching_different_blocks_separate() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        // Two fetches for different block heights.
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(20),
            winner_tx_hash: tx_hash(2),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });

        // Should produce two separate FetchBatch outputs.
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 2);
        for output in &outputs {
            match output {
                InclusionProofFetchOutput::FetchBatch { entries, .. } => {
                    assert_eq!(entries.len(), 1);
                }
                other => panic!("Expected FetchBatch, got {:?}", other),
            }
        }
    }

    #[test]
    fn test_batching_different_shards_separate() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        // Two fetches for different source shards (same height).
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(1),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            peers: vec![vid(1)],
            preferred_peer: vid(1),
        });
        protocol.handle(InclusionProofFetchInput::Request {
            source_shard: shard(2),
            source_block_height: height(10),
            winner_tx_hash: tx_hash(2),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            peers: vec![vid(3)],
            preferred_peer: vid(3),
        });

        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 2);
    }

    #[test]
    fn test_partial_batch_failure() {
        let mut protocol = InclusionProofFetchProtocol::new(default_config());
        let now = Instant::now();

        // Register 3 fetches that will batch together.
        for i in 1..=3u8 {
            protocol.handle(InclusionProofFetchInput::Request {
                source_shard: shard(1),
                source_block_height: height(10),
                winner_tx_hash: tx_hash(i),
                reason: InclusionProofFetchReason::Deferral {
                    loser_tx_hash: tx_hash(0),
                },
                peers: vec![vid(1), vid(2)],
                preferred_peer: vid(1),
            });
        }

        // Tick to dispatch the batch.
        protocol.handle(tick(now));

        // Receive proofs for tx 1 and 3 (success), fail tx 2.
        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(1),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });
        assert_eq!(outputs.len(), 1); // Deliver for tx 1

        let outputs = protocol.handle(InclusionProofFetchInput::Received {
            winner_tx_hash: tx_hash(3),
            reason: InclusionProofFetchReason::Deferral {
                loser_tx_hash: tx_hash(0),
            },
            source_shard: shard(1),
            source_block_height: height(10),
            proof: dummy_proof(),
        });
        assert_eq!(outputs.len(), 1); // Deliver for tx 3

        protocol.handle(InclusionProofFetchInput::Failed {
            winner_tx_hash: tx_hash(2),
        });

        // tx 2 should still be pending and retryable.
        assert!(protocol.has_pending());
        let outputs = protocol.handle(tick(now));
        assert_eq!(outputs.len(), 1);
        let (_, _, entries, _) = expect_single_fetch_batch(&outputs);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, tx_hash(2));
    }
}
