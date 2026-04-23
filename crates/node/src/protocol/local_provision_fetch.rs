//! Local provision fetch protocol state machine.
//!
//! Fetches missing provision batch data from the block proposer or local peers.
//! Mirrors `TransactionFetchProtocol` — tracks missing hashes per block, rotates
//! through peers on failure.

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHash, Provision, ProvisionHash, ValidatorId};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, trace};

/// Configuration for the local provision fetch protocol.
#[derive(Debug, Clone)]
pub struct LocalProvisionFetchConfig {
    pub max_concurrent_per_block: usize,
    pub max_hashes_per_request: usize,
    pub parallel_fetches: usize,
}

impl Default for LocalProvisionFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_block: 4,
            max_hashes_per_request: 16,
            parallel_fetches: 2,
        }
    }
}

/// Inputs to the local provision fetch protocol.
#[derive(Debug)]
pub enum LocalProvisionFetchInput {
    /// Request provision batches for a pending block.
    Request {
        block_hash: BlockHash,
        proposer: ValidatorId,
        batch_hashes: Vec<ProvisionHash>,
    },
    /// Provision batches were received.
    Received {
        block_hash: BlockHash,
        batches: Vec<Arc<Provision>>,
    },
    /// A fetch operation failed.
    Failed {
        block_hash: BlockHash,
        hashes: Vec<ProvisionHash>,
    },
    /// Cancel fetch for a specific block.
    CancelFetch { block_hash: BlockHash },
    /// Tick: spawn pending fetch operations.
    Tick,
}

/// Outputs from the local provision fetch protocol.
#[derive(Debug)]
pub enum LocalProvisionFetchOutput {
    /// Request the runner to fetch provision batches from a peer.
    Fetch {
        block_hash: BlockHash,
        proposer: ValidatorId,
        batch_hashes: Vec<ProvisionHash>,
    },
    /// Deliver fetched provision batches to BFT.
    Deliver { batches: Vec<Arc<Provision>> },
}

/// Per-block fetch state.
#[derive(Debug)]
struct BlockFetchState {
    proposer: ValidatorId,
    missing_hashes: HashSet<ProvisionHash>,
    in_flight_hashes: HashSet<ProvisionHash>,
    received_hashes: HashSet<ProvisionHash>,
    in_flight_count: usize,
}

impl BlockFetchState {
    fn new(proposer: ValidatorId, hashes: Vec<ProvisionHash>) -> Self {
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

    fn hashes_to_fetch(&self) -> Vec<ProvisionHash> {
        self.missing_hashes
            .difference(&self.in_flight_hashes)
            .copied()
            .collect()
    }

    fn mark_in_flight(&mut self, hashes: &[ProvisionHash]) {
        for hash in hashes {
            self.in_flight_hashes.insert(*hash);
        }
        self.in_flight_count += 1;
    }

    fn mark_received(&mut self, hashes: impl IntoIterator<Item = ProvisionHash>) {
        for hash in hashes {
            self.missing_hashes.remove(&hash);
            self.in_flight_hashes.remove(&hash);
            self.received_hashes.insert(hash);
        }
    }

    fn was_received(&self, hash: &ProvisionHash) -> bool {
        self.received_hashes.contains(hash)
    }

    fn mark_fetch_failed(&mut self, hashes: &[ProvisionHash]) {
        for hash in hashes {
            self.in_flight_hashes.remove(hash);
        }
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    fn mark_fetch_complete(&mut self) {
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    /// Move any in-flight hashes that weren't received back to missing.
    /// Called after marking received items to handle partial/empty responses.
    fn reclaim_unreceived(&mut self) {
        if self.in_flight_count == 0 && !self.in_flight_hashes.is_empty() {
            let stuck: Vec<ProvisionHash> = self
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

/// Local provision fetch protocol state machine.
pub struct LocalProvisionFetchProtocol {
    config: LocalProvisionFetchConfig,
    fetches: BTreeMap<BlockHash, BlockFetchState>,
}

impl LocalProvisionFetchProtocol {
    pub fn new(config: LocalProvisionFetchConfig) -> Self {
        Self {
            config,
            fetches: BTreeMap::new(),
        }
    }

    pub fn handle(&mut self, input: LocalProvisionFetchInput) -> Vec<LocalProvisionFetchOutput> {
        match input {
            LocalProvisionFetchInput::Request {
                block_hash,
                proposer,
                batch_hashes,
            } => self.handle_request(block_hash, proposer, batch_hashes),
            LocalProvisionFetchInput::Received {
                block_hash,
                batches,
            } => self.handle_received(block_hash, batches),
            LocalProvisionFetchInput::Failed { block_hash, hashes } => {
                self.handle_failed(block_hash, hashes)
            }
            LocalProvisionFetchInput::CancelFetch { block_hash } => {
                self.fetches.remove(&block_hash);
                debug!(?block_hash, "Cancelled local provision fetch");
                vec![]
            }
            LocalProvisionFetchInput::Tick => self.spawn_pending_fetches(),
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
        batch_hashes: Vec<ProvisionHash>,
    ) -> Vec<LocalProvisionFetchOutput> {
        if batch_hashes.is_empty() {
            return vec![];
        }

        if let Some(state) = self.fetches.get_mut(&block_hash) {
            for hash in batch_hashes {
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            return vec![];
        }

        info!(
            ?block_hash,
            count = batch_hashes.len(),
            proposer = proposer.0,
            "Starting local provision fetch"
        );
        metrics::record_fetch_started("local_provision");

        let state = BlockFetchState::new(proposer, batch_hashes);
        self.fetches.insert(block_hash, state);
        vec![]
    }

    fn handle_received(
        &mut self,
        block_hash: BlockHash,
        batches: Vec<Arc<Provision>>,
    ) -> Vec<LocalProvisionFetchOutput> {
        let Some(state) = self.fetches.get_mut(&block_hash) else {
            trace!(?block_hash, "Provision received for unknown fetch");
            return vec![];
        };

        state.mark_fetch_complete();

        let received_hashes: Vec<ProvisionHash> = batches.iter().map(|b| b.hash()).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);
        // Move any in-flight hashes not in the response back to missing for retry.
        state.reclaim_unreceived();
        metrics::record_fetch_items_received("local_provision", received_count);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received local provisions"
        );

        let mut outputs = Vec::new();

        if !batches.is_empty() {
            outputs.push(LocalProvisionFetchOutput::Deliver { batches });
        }

        if state.is_complete() {
            info!(?block_hash, "Local provision fetch complete");
            metrics::record_fetch_completed("local_provision");
            self.fetches.remove(&block_hash);
        }

        outputs
    }

    fn handle_failed(
        &mut self,
        block_hash: BlockHash,
        hashes: Vec<ProvisionHash>,
    ) -> Vec<LocalProvisionFetchOutput> {
        if let Some(state) = self.fetches.get_mut(&block_hash) {
            state.mark_fetch_failed(&hashes);
            metrics::record_fetch_failed("local_provision");
        }
        vec![]
    }

    fn spawn_pending_fetches(&mut self) -> Vec<LocalProvisionFetchOutput> {
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
                outputs.push(LocalProvisionFetchOutput::Fetch {
                    block_hash: *block_hash,
                    proposer: state.proposer,
                    batch_hashes: chunk.to_vec(),
                });
            }
        }

        outputs
    }
}
