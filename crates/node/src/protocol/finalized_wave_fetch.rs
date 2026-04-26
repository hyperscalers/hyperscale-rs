//! Finalized wave fetch protocol state machine.
//!
//! Fetches missing finalized wave data for a pending block from the proposer
//! first, falling back to other local-committee peers when the proposer
//! returns nothing or an empty response. Mirrors `LocalProvisionFetchProtocol`
//! and `ExecCertFetchProtocol` — tracks missing `wave_id_hashes` per block,
//! rotates peers on failure, and backs off exponentially when all peers
//! have been exhausted.
//!
//! Why protocol-level rotation: the network layer rotates on timeout/error,
//! but treats `Ok(empty_response)` as success and returns it. A peer that
//! has dropped the wave from its in-memory cache responds with no waves —
//! the network is satisfied, we move the hashes back to `missing`, and on
//! the next tick we re-prefer the same proposer, hitting the same dead
//! cache. Tracking tried peers here breaks that loop.

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHash, FinalizedWave, ValidatorId, WaveIdHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

/// Configuration for the finalized wave fetch protocol.
#[derive(Debug, Clone)]
pub struct FinalizedWaveFetchConfig {
    pub max_concurrent_per_block: usize,
    pub max_hashes_per_request: usize,
    pub parallel_fetches: usize,
}

impl Default for FinalizedWaveFetchConfig {
    fn default() -> Self {
        Self {
            // Conservative defaults — finalized waves are large (contain receipts + ECs).
            max_concurrent_per_block: 2,
            max_hashes_per_request: 4,
            parallel_fetches: 1,
        }
    }
}

/// Inputs to the finalized wave fetch protocol.
#[derive(Debug)]
pub enum FinalizedWaveFetchInput {
    /// Request finalized waves for a pending block.
    Request {
        block_hash: BlockHash,
        proposer: ValidatorId,
        wave_id_hashes: Vec<WaveIdHash>,
        /// Local-committee peers (excluding self). The proposer is tried
        /// first; on failure or empty response we rotate through these.
        peers: Vec<ValidatorId>,
    },
    /// Finalized waves were received from `peer`.
    Received {
        block_hash: BlockHash,
        peer: ValidatorId,
        waves: Vec<Arc<FinalizedWave>>,
    },
    /// A fetch operation against `peer` failed (network error or timeout).
    Failed {
        block_hash: BlockHash,
        peer: ValidatorId,
        hashes: Vec<WaveIdHash>,
    },
    /// Cancel fetch for a specific block.
    CancelFetch { block_hash: BlockHash },
    /// Tick: spawn pending fetch operations.
    Tick { now: Instant },
}

/// Outputs from the finalized wave fetch protocol.
#[derive(Debug)]
pub enum FinalizedWaveFetchOutput {
    /// Request the runner to fetch finalized waves from a peer.
    Fetch {
        block_hash: BlockHash,
        peer: ValidatorId,
        wave_id_hashes: Vec<WaveIdHash>,
    },
    /// Deliver fetched finalized waves to the state machine.
    Deliver { waves: Vec<Arc<FinalizedWave>> },
}

/// Per-block fetch state.
#[derive(Debug)]
struct BlockFetchState {
    /// Rotation pool. Proposer first, then everyone else in `peers` order.
    rotation: Vec<ValidatorId>,
    missing_hashes: HashSet<WaveIdHash>,
    in_flight_hashes: HashSet<WaveIdHash>,
    received_hashes: HashSet<WaveIdHash>,
    in_flight_count: usize,
    /// Peers we've sent at least one request to and haven't yet succeeded
    /// with. Cleared when a round completes (every peer tried).
    tried: HashSet<ValidatorId>,
    /// Each in-flight chunk needs to remember which peer it was sent to so
    /// `Failed` / `Received` can mark the right peer as tried.
    in_flight_peers: HashMap<WaveIdHash, ValidatorId>,
    /// Round counter: incremented when every peer in the rotation has been
    /// tried at least once and we wrap. Drives exponential backoff.
    rounds: u32,
    /// Deadline before the next attempt is allowed. `None` if ready now.
    next_retry_at: Option<Instant>,
}

impl BlockFetchState {
    fn new(proposer: ValidatorId, peers: Vec<ValidatorId>, hashes: Vec<WaveIdHash>) -> Self {
        // Build rotation: proposer first (most likely to have the data —
        // they built the block), then every other peer that isn't already
        // the proposer.
        let mut rotation = vec![proposer];
        for p in peers {
            if p != proposer {
                rotation.push(p);
            }
        }
        Self {
            rotation,
            missing_hashes: hashes.into_iter().collect(),
            in_flight_hashes: HashSet::new(),
            received_hashes: HashSet::new(),
            in_flight_count: 0,
            tried: HashSet::new(),
            in_flight_peers: HashMap::new(),
            rounds: 0,
            next_retry_at: None,
        }
    }

    fn is_complete(&self) -> bool {
        self.missing_hashes.is_empty() && self.in_flight_hashes.is_empty()
    }

    fn hashes_to_fetch(&self) -> Vec<WaveIdHash> {
        self.missing_hashes
            .difference(&self.in_flight_hashes)
            .copied()
            .collect()
    }

    /// Pick the next peer to try, or `None` if every peer in the rotation
    /// has been tried this round (caller backs off and resets).
    fn next_peer(&self) -> Option<ValidatorId> {
        self.rotation
            .iter()
            .find(|p| !self.tried.contains(p))
            .copied()
    }

    fn mark_in_flight(&mut self, hashes: &[WaveIdHash], peer: ValidatorId) {
        for hash in hashes {
            self.in_flight_hashes.insert(*hash);
            self.in_flight_peers.insert(*hash, peer);
        }
        self.in_flight_count += 1;
        self.tried.insert(peer);
    }

    fn mark_received(&mut self, hashes: impl IntoIterator<Item = WaveIdHash>) {
        for hash in hashes {
            self.missing_hashes.remove(&hash);
            self.in_flight_hashes.remove(&hash);
            self.in_flight_peers.remove(&hash);
            self.received_hashes.insert(hash);
        }
    }

    fn was_received(&self, hash: &WaveIdHash) -> bool {
        self.received_hashes.contains(hash)
    }

    fn mark_fetch_failed(&mut self, hashes: &[WaveIdHash]) {
        for hash in hashes {
            self.in_flight_hashes.remove(hash);
            self.in_flight_peers.remove(hash);
        }
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    fn mark_fetch_complete(&mut self) {
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    /// Move any in-flight hashes that weren't received back to missing.
    fn reclaim_unreceived(&mut self) {
        if self.in_flight_count == 0 && !self.in_flight_hashes.is_empty() {
            let stuck: Vec<WaveIdHash> = self
                .in_flight_hashes
                .iter()
                .filter(|h| !self.received_hashes.contains(h))
                .copied()
                .collect();
            for h in stuck {
                self.in_flight_hashes.remove(&h);
                self.in_flight_peers.remove(&h);
                self.missing_hashes.insert(h);
            }
        }
    }
}

/// Finalized wave fetch protocol state machine.
pub struct FinalizedWaveFetchProtocol {
    config: FinalizedWaveFetchConfig,
    fetches: BTreeMap<BlockHash, BlockFetchState>,
}

impl FinalizedWaveFetchProtocol {
    pub fn new(config: FinalizedWaveFetchConfig) -> Self {
        Self {
            config,
            fetches: BTreeMap::new(),
        }
    }

    pub fn handle(&mut self, input: FinalizedWaveFetchInput) -> Vec<FinalizedWaveFetchOutput> {
        match input {
            FinalizedWaveFetchInput::Request {
                block_hash,
                proposer,
                wave_id_hashes,
                peers,
            } => self.handle_request(block_hash, proposer, wave_id_hashes, peers),
            FinalizedWaveFetchInput::Received {
                block_hash,
                peer,
                waves,
            } => self.handle_received(block_hash, peer, waves),
            FinalizedWaveFetchInput::Failed {
                block_hash,
                peer,
                hashes,
            } => self.handle_failed(block_hash, peer, &hashes),
            FinalizedWaveFetchInput::CancelFetch { block_hash } => {
                self.fetches.remove(&block_hash);
                debug!(?block_hash, "Cancelled finalized wave fetch");
                vec![]
            }
            FinalizedWaveFetchInput::Tick { now } => self.spawn_pending_fetches(now),
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.fetches.is_empty()
    }

    pub fn in_flight_count(&self) -> usize {
        self.fetches.values().map(|s| s.in_flight_count).sum()
    }

    /// Returns the number of blocks with pending or in-flight wave fetches.
    pub fn pending_count(&self) -> usize {
        self.fetches.len()
    }

    fn handle_request(
        &mut self,
        block_hash: BlockHash,
        proposer: ValidatorId,
        wave_id_hashes: Vec<WaveIdHash>,
        peers: Vec<ValidatorId>,
    ) -> Vec<FinalizedWaveFetchOutput> {
        if wave_id_hashes.is_empty() {
            return vec![];
        }

        if let Some(state) = self.fetches.get_mut(&block_hash) {
            for hash in wave_id_hashes {
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            return vec![];
        }

        info!(
            ?block_hash,
            count = wave_id_hashes.len(),
            proposer = proposer.0,
            peer_pool = peers.len(),
            "Starting finalized wave fetch"
        );
        metrics::record_fetch_started("finalized_wave");

        let state = BlockFetchState::new(proposer, peers, wave_id_hashes);
        self.fetches.insert(block_hash, state);
        vec![]
    }

    fn handle_received(
        &mut self,
        block_hash: BlockHash,
        peer: ValidatorId,
        waves: Vec<Arc<FinalizedWave>>,
    ) -> Vec<FinalizedWaveFetchOutput> {
        let Some(state) = self.fetches.get_mut(&block_hash) else {
            trace!(?block_hash, "Finalized wave received for unknown fetch");
            return vec![];
        };

        state.mark_fetch_complete();

        let received_hashes: Vec<WaveIdHash> = waves.iter().map(|fw| fw.wave_id_hash()).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);
        // An empty (or partial) response means this peer didn't have what we
        // need. Mark them tried so the next round picks someone else; without
        // this we'd loop the same preferred-peer hint forever.
        state.tried.insert(peer);
        state.reclaim_unreceived();
        metrics::record_fetch_items_received("finalized_wave", received_count);

        debug!(
            ?block_hash,
            peer = peer.0,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received finalized waves"
        );

        let mut outputs = Vec::new();

        if !waves.is_empty() {
            outputs.push(FinalizedWaveFetchOutput::Deliver { waves });
        }

        if state.is_complete() {
            info!(?block_hash, "Finalized wave fetch complete");
            metrics::record_fetch_completed("finalized_wave");
            self.fetches.remove(&block_hash);
        }

        outputs
    }

    fn handle_failed(
        &mut self,
        block_hash: BlockHash,
        peer: ValidatorId,
        hashes: &[WaveIdHash],
    ) -> Vec<FinalizedWaveFetchOutput> {
        if let Some(state) = self.fetches.get_mut(&block_hash) {
            state.mark_fetch_failed(hashes);
            state.tried.insert(peer);
            metrics::record_fetch_failed("finalized_wave");
        }
        vec![]
    }

    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<FinalizedWaveFetchOutput> {
        let mut outputs = Vec::new();

        for (block_hash, state) in &mut self.fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            // Respect per-round backoff.
            if let Some(retry_at) = state.next_retry_at {
                if now < retry_at {
                    continue;
                }
                state.next_retry_at = None;
            }

            // If every peer in the rotation has been tried, start a new round
            // with exponential backoff (matches `execution_cert_fetch`).
            if state.next_peer().is_none() && !state.rotation.is_empty() {
                state.tried.clear();
                state.rounds += 1;
                let backoff =
                    Duration::from_millis((500u64 * 2u64.saturating_pow(state.rounds)).min(30_000));
                state.next_retry_at = Some(now + backoff);
                info!(
                    ?block_hash,
                    round = state.rounds,
                    backoff_ms = backoff.as_millis(),
                    missing = state.missing_hashes.len(),
                    "Finalized wave fetch exhausted peers, backing off"
                );
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            let Some(peer) = state.next_peer() else {
                continue;
            };

            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                state.mark_in_flight(chunk, peer);
                outputs.push(FinalizedWaveFetchOutput::Fetch {
                    block_hash: *block_hash,
                    peer,
                    wave_id_hashes: chunk.to_vec(),
                });
            }
        }

        outputs
    }
}
