//! Stream I/O entry point for the request manager.
//!
//! Delegates to the shared [`RequestStreamPool`], which multiplexes
//! request/response pairs over a persistent stream per peer.

use hyperscale_types::{MessageClass, ShardGroupId};
use libp2p::PeerId;

use super::RequestManager;
use crate::adapter::NetworkError;

impl RequestManager {
    /// Send a request to `peer` over `shard`'s request protocol and await
    /// the response.
    ///
    /// All stream management (open, write, read, reconnect) lives in the
    /// pool — this method just picks an RTT-informed timeout and delegates.
    pub(super) async fn send_request(
        &self,
        peer: &PeerId,
        shard: ShardGroupId,
        type_id: &'static str,
        data: &[u8],
        _class: MessageClass,
    ) -> Result<Vec<u8>, NetworkError> {
        let timeout = self.compute_stream_timeout(peer);
        self.pool
            .send(*peer, shard, type_id, data.to_vec(), timeout)
            .await
    }
}
