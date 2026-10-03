//! Stream I/O entry point for the request manager.
//!
//! Delegates to the shared [`RequestStreamPool`], which multiplexes
//! request/response pairs over a persistent stream per peer.

use std::time::Duration;

use hyperscale_types::ShardId;
use libp2p::PeerId;

use super::RequestManager;
use crate::adapter::NetworkError;

impl RequestManager {
    /// Send a request to `peer` over `shard`'s request protocol and await
    /// the response for at most `timeout`.
    ///
    /// All stream management (open, write, read, reconnect) lives in the
    /// pool.
    pub(super) async fn send_request(
        &self,
        peer: &PeerId,
        shard: ShardId,
        type_id: &'static str,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, NetworkError> {
        self.pool
            .send(*peer, shard, type_id, data.to_vec(), timeout)
            .await
    }
}
