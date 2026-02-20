//! Production network adapter implementing the Network trait.
//!
//! [`ProdNetwork`] wraps [`Libp2pAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `NodeLoop` in the production runner.

use crate::adapter::{compute_peer_id_for_validator, Libp2pAdapter};
use crate::request_manager::{RequestManager, RequestPriority};
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_network::{
    encode_to_wire, BlockResponseCallback, CertificatesResponseCallback, Network, RequestError,
    Topic, TransactionsResponseCallback,
};
use hyperscale_types::{
    Block, BlockHeight, Hash, NetworkMessage, QuorumCertificate, Request, ShardGroupId,
    ShardMessage, Topology, ValidatorId,
};
use libp2p::PeerId;
use std::sync::Arc;
use tracing::{debug, warn};

// ═══════════════════════════════════════════════════════════════════════
// ProdNetwork
// ═══════════════════════════════════════════════════════════════════════

/// Production network adapter implementing the Network trait.
///
/// Wraps `Arc<Libp2pAdapter>` and encodes messages to wire format before
/// publishing via the adapter's priority channels. The `publish()` call
/// is sync-safe (non-blocking channel send), so this works from the
/// pinned state machine thread without a tokio runtime context.
///
/// Also owns a `RequestManager` for typed request methods (`request_block`,
/// `request_transactions`, `request_certificates`). These spawn async tasks
/// via `tokio_handle` since the pinned thread has no tokio runtime.
pub struct ProdNetwork {
    adapter: Arc<Libp2pAdapter>,
    request_manager: Arc<RequestManager>,
    topology: Arc<dyn Topology>,
    tokio_handle: tokio::runtime::Handle,
}

impl ProdNetwork {
    pub fn new(
        adapter: Arc<Libp2pAdapter>,
        request_manager: Arc<RequestManager>,
        topology: Arc<dyn Topology>,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            adapter,
            request_manager,
            topology,
            tokio_handle,
        }
    }

    /// Get peer IDs for same-shard committee members (excluding self).
    fn get_committee_peers(&self) -> Vec<PeerId> {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&v| {
                let pk = self.topology.public_key(v)?;
                Some(compute_peer_id_for_validator(&pk))
            })
            .collect()
    }

    /// Get the PeerId for a specific validator, if known.
    fn validator_peer_id(&self, validator: ValidatorId) -> Option<PeerId> {
        self.topology
            .public_key(validator)
            .map(|pk| compute_peer_id_for_validator(&pk))
    }
}

impl Network for ProdNetwork {
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M) {
        let topic = Topic::shard(M::message_type_id(), shard);
        match encode_to_wire(message) {
            Ok(data) => {
                if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
                    debug!(error = ?e, "ProdNetwork: broadcast_to_shard failed");
                }
            }
            Err(e) => {
                debug!(error = ?e, "ProdNetwork: failed to encode message");
            }
        }
    }

    fn broadcast_global<M: NetworkMessage>(&self, message: &M) {
        let topic = Topic::global(M::message_type_id());
        match encode_to_wire(message) {
            Ok(data) => {
                if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
                    debug!(error = ?e, "ProdNetwork: broadcast_global failed");
                }
            }
            Err(e) => {
                debug!(error = ?e, "ProdNetwork: failed to encode message");
            }
        }
    }

    fn send_to<M: NetworkMessage>(&self, _peer: ValidatorId, _message: &M) {
        // Point-to-point sends are not used by NodeLoop.
        // Sync/fetch use RunnerRequest which goes through the async output handler.
        unimplemented!("ProdNetwork::send_to is not used by NodeLoop")
    }

    fn subscribe_shard(&self, _shard: ShardGroupId) {
        // Subscription is handled during runner setup via adapter.subscribe_shard().
        // Not called from NodeLoop.
    }

    fn on_message<M: NetworkMessage + 'static>(
        &self,
        _handler: Box<dyn Fn(ValidatorId, M) + Send + Sync>,
    ) {
        // Message handlers are registered during runner setup.
        // The Libp2p adapter has its own internal routing.
        // Not called from NodeLoop.
    }

    fn request<R: Request + 'static>(
        &self,
        _peer: ValidatorId,
        _request: &R,
        _on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    ) {
        // Low-level request/response is not used by NodeLoop.
        // Use typed request methods (request_block, etc.) instead.
        unimplemented!("ProdNetwork::request is not used; use typed request methods")
    }

    fn request_block(&self, height: BlockHeight, on_response: BlockResponseCallback) {
        let peers = self.get_committee_peers();
        if peers.is_empty() {
            on_response(Err(RequestError::PeerUnreachable(ValidatorId(0))));
            return;
        }
        let rm = self.request_manager.clone();
        self.tokio_handle.spawn(async move {
            match rm.request_block(&peers, height, RequestPriority::Background).await {
                Ok((_peer, bytes)) => {
                    match sbor::basic_decode::<Option<(Block, QuorumCertificate)>>(&bytes) {
                        Ok(block) => on_response(Ok(block)),
                        Err(e) => {
                            warn!(height = height.0, error = ?e, "Failed to decode sync block response");
                            on_response(Err(RequestError::PeerError(format!("decode error: {e:?}"))));
                        }
                    }
                }
                Err(e) => {
                    on_response(Err(RequestError::PeerError(format!("{e}"))));
                }
            }
        });
    }

    fn request_transactions(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: TransactionsResponseCallback,
    ) {
        let peers = self.get_committee_peers();
        if peers.is_empty() {
            on_response(Err(RequestError::PeerUnreachable(proposer)));
            return;
        }
        let preferred = self.validator_peer_id(proposer);
        let rm = self.request_manager.clone();
        self.tokio_handle.spawn(async move {
            match rm
                .request_transactions(
                    &peers,
                    preferred,
                    block_hash,
                    hashes.clone(),
                    RequestPriority::Critical,
                )
                .await
            {
                Ok((_peer, bytes)) => match sbor::basic_decode::<GetTransactionsResponse>(&bytes) {
                    Ok(response) => on_response(Ok(response.into_transactions())),
                    Err(e) => {
                        warn!(?block_hash, error = ?e, "Failed to decode transaction response");
                        on_response(Err(RequestError::PeerError(format!("decode error: {e:?}"))));
                    }
                },
                Err(e) => {
                    on_response(Err(RequestError::PeerError(format!("{e}"))));
                }
            }
        });
    }

    fn request_certificates(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: CertificatesResponseCallback,
    ) {
        let peers = self.get_committee_peers();
        if peers.is_empty() {
            on_response(Err(RequestError::PeerUnreachable(proposer)));
            return;
        }
        let preferred = self.validator_peer_id(proposer);
        let rm = self.request_manager.clone();
        self.tokio_handle.spawn(async move {
            match rm
                .request_certificates(
                    &peers,
                    preferred,
                    block_hash,
                    hashes.clone(),
                    RequestPriority::Critical,
                )
                .await
            {
                Ok((_peer, bytes)) => match sbor::basic_decode::<GetCertificatesResponse>(&bytes) {
                    Ok(response) => on_response(Ok(response.into_certificates())),
                    Err(e) => {
                        warn!(?block_hash, error = ?e, "Failed to decode certificate response");
                        on_response(Err(RequestError::PeerError(format!("decode error: {e:?}"))));
                    }
                },
                Err(e) => {
                    on_response(Err(RequestError::PeerError(format!("{e}"))));
                }
            }
        });
    }
}
