//! Finalized wave fetch protocol state machine.
//!
//! Fetches missing finalized wave data from the block proposer or local peers.
//! Mirrors `LocalProvisionFetchProtocol` — tracks missing wave_id_hashes per block,
//! rotates through peers on failure.

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHash, FinalizedWave, ValidatorId, WaveIdHash};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
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
    },
    /// Finalized waves were received.
    Received {
        block_hash: BlockHash,
        waves: Vec<Arc<FinalizedWave>>,
    },
    /// A fetch operation failed.
    Failed {
        block_hash: BlockHash,
        hashes: Vec<WaveIdHash>,
    },
    /// Cancel fetch for a specific block.
    CancelFetch { block_hash: BlockHash },
    /// Tick: spawn pending fetch operations.
    Tick,
}

/// Outputs from the finalized wave fetch protocol.
#[derive(Debug)]
pub enum FinalizedWaveFetchOutput {
    /// Request the runner to fetch finalized waves from a peer.
    Fetch {
        block_hash: BlockHash,
        proposer: ValidatorId,
        wave_id_hashes: Vec<WaveIdHash>,
    },
    /// Deliver fetched finalized waves to the state machine.
    Deliver { waves: Vec<Arc<FinalizedWave>> },
}

/// Per-block fetch state.
#[derive(Debug)]
struct BlockFetchState {
    proposer: ValidatorId,
    missing_hashes: HashSet<WaveIdHash>,
    in_flight_hashes: HashSet<WaveIdHash>,
    received_hashes: HashSet<WaveIdHash>,
    in_flight_count: usize,
}

impl BlockFetchState {
    fn new(proposer: ValidatorId, hashes: Vec<WaveIdHash>) -> Self {
        Self {
            proposer,
            missing_hashes: hashes.into_iter().collect(),
            in_flight_hashes: HashSet::new(),
            received_hashes: HashSet::new(),
            in_flight_count: 0,
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

    fn mark_in_flight(&mut self, hashes: &[WaveIdHash]) {
        for hash in hashes {
            self.in_flight_hashes.insert(*hash);
        }
        self.in_flight_count += 1;
    }

    fn mark_received(&mut self, hashes: impl IntoIterator<Item = WaveIdHash>) {
        for hash in hashes {
            self.missing_hashes.remove(&hash);
            self.in_flight_hashes.remove(&hash);
            self.received_hashes.insert(hash);
        }
    }

    fn was_received(&self, hash: &WaveIdHash) -> bool {
        self.received_hashes.contains(hash)
    }

    fn mark_fetch_failed(&mut self, hashes: &[WaveIdHash]) {
        for hash in hashes {
            self.in_flight_hashes.remove(hash);
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
            } => self.handle_request(block_hash, proposer, wave_id_hashes),
            FinalizedWaveFetchInput::Received { block_hash, waves } => {
                self.handle_received(block_hash, waves)
            }
            FinalizedWaveFetchInput::Failed { block_hash, hashes } => {
                self.handle_failed(block_hash, hashes)
            }
            FinalizedWaveFetchInput::CancelFetch { block_hash } => {
                self.fetches.remove(&block_hash);
                debug!(?block_hash, "Cancelled finalized wave fetch");
                vec![]
            }
            FinalizedWaveFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.fetches.is_empty()
    }

    pub fn in_flight_count(&self) -> usize {
        self.fetches.values().map(|s| s.in_flight_count).sum()
    }

    fn handle_request(
        &mut self,
        block_hash: BlockHash,
        proposer: ValidatorId,
        wave_id_hashes: Vec<WaveIdHash>,
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
            "Starting finalized wave fetch"
        );
        metrics::record_fetch_started("finalized_wave");

        let state = BlockFetchState::new(proposer, wave_id_hashes);
        self.fetches.insert(block_hash, state);
        vec![]
    }

    fn handle_received(
        &mut self,
        block_hash: BlockHash,
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
        state.reclaim_unreceived();
        metrics::record_fetch_items_received("finalized_wave", received_count);

        info!(
            ?block_hash,
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
        hashes: Vec<WaveIdHash>,
    ) -> Vec<FinalizedWaveFetchOutput> {
        if let Some(state) = self.fetches.get_mut(&block_hash) {
            state.mark_fetch_failed(&hashes);
            metrics::record_fetch_failed("finalized_wave");
        }
        vec![]
    }

    fn spawn_pending_fetches(&mut self) -> Vec<FinalizedWaveFetchOutput> {
        let mut outputs = Vec::new();

        for (block_hash, state) in &mut self.fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                state.mark_in_flight(chunk);
                outputs.push(FinalizedWaveFetchOutput::Fetch {
                    block_hash: *block_hash,
                    proposer: state.proposer,
                    wave_id_hashes: chunk.to_vec(),
                });
            }
        }

        outputs
    }
}
