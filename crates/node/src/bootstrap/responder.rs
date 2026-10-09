//! Answering a bootstrap's requests in process from a store in hand.
//!
//! A host rebuilding a shard it already runs reads the anchor from its
//! own store before asking peers: the store committed through the
//! anchor, so it holds everything the bootstrap asks for until its pin
//! ring evicts the anchor. The answers come from the same serve
//! functions a peer runs, and the sequencer verifies them against the
//! attested anchor exactly as it verifies a peer's.

use std::sync::Arc;

use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::response::{
    GetBlockResponse, GetStateRangeResponse, GetWitnessHistoryResponse,
};
use hyperscale_types::{BlockHeight, ChainOrigin};

use super::BootstrapRequest;
use super::state_range_serve::serve_state_range_request;
use super::witness_history_serve::serve_witness_history_request;
use crate::shard::consensus::serve_block_request;

/// A served answer to one [`BootstrapRequest`], carrying the id the
/// sequencer echoes.
#[derive(Debug)]
pub enum BootstrapResponse {
    /// A state range chunk for the numbered sub-range.
    StateRange(usize, GetStateRangeResponse),
    /// A witness-history page.
    WitnessHistory(Box<GetWitnessHistoryResponse>),
    /// One committed block below the anchor.
    History(BlockHeight, Box<GetBlockResponse>),
}

/// Serves [`BootstrapRequest`]s from one store.
pub struct StoreResponder<S: ShardStorage> {
    storage: Arc<S>,
    chain: PendingChain<S>,
    provisions: ProvisionStore,
}

impl<S: ShardStorage> StoreResponder<S> {
    /// A responder over `storage`'s committed chain.
    #[must_use]
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            // The origin only floors committed-window walks, and the
            // serve functions read single heights, never a window.
            chain: PendingChain::new(Arc::clone(&storage), ChainOrigin::ROOT),
            storage,
            // History blocks are served sealed, so no provision body is
            // ever looked up.
            provisions: ProvisionStore::new(),
        }
    }

    /// The answer a peer serving `request` off this store sends back:
    /// [`Self::answer`]'s, and a history block beneath the store's chain
    /// floor answered as below it, which tells the walk the height is gone
    /// rather than leaving it to ask again.
    #[must_use]
    pub fn peer_answer(&self, request: &BootstrapRequest) -> Option<BootstrapResponse> {
        if let BootstrapRequest::History(height, request) = request {
            let response = serve_block_request(&self.chain, &self.provisions, request);
            return (response.has_block()
                || matches!(response, GetBlockResponse::BelowFloor { .. }))
            .then(|| BootstrapResponse::History(*height, Box::new(response)));
        }
        self.answer(request)
    }

    /// The store's answer to `request`, or `None` when it cannot serve
    /// it — an anchor its ring evicted, pruned witness leaves, a block it
    /// never held, a block beneath its chain floor — and the driver has to
    /// ask a peer.
    #[must_use]
    pub fn answer(&self, request: &BootstrapRequest) -> Option<BootstrapResponse> {
        match request {
            BootstrapRequest::StateRange(id, request) => {
                let response = serve_state_range_request(&self.storage, request);
                response
                    .chunk
                    .is_some()
                    .then_some(BootstrapResponse::StateRange(*id, response))
            }
            BootstrapRequest::WitnessHistory(request) => {
                let response = serve_witness_history_request(&self.chain, request);
                response
                    .history
                    .is_some()
                    .then(|| BootstrapResponse::WitnessHistory(Box::new(response)))
            }
            BootstrapRequest::History(height, request) => {
                let response = serve_block_request(&self.chain, &self.provisions, request);
                response
                    .has_block()
                    .then(|| BootstrapResponse::History(*height, Box::new(response)))
            }
        }
    }
}
