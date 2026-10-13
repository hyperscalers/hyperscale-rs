//! Network error types.

use thiserror::Error;

/// Errors from the iroh transport.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The endpoint could not be built or bound.
    #[error("Endpoint setup failed: {0}")]
    Endpoint(String),

    /// The network key file could not be read, written, or parsed.
    #[error("Network key error: {0}")]
    Key(String),

    /// The transport has shut down and services nothing further.
    #[error("Network shutdown")]
    NetworkShutdown,

    /// Operation did not complete within its timeout.
    #[error("Request timeout")]
    Timeout,

    /// No bound connection to the peer exists.
    #[error("Not connected to peer")]
    NotConnected,

    /// Stream I/O failed during read or write.
    #[error("Stream I/O error: {0}")]
    StreamIo(String),

    /// Could not open a new stream to the peer.
    #[error("Stream open failed: {0}")]
    StreamOpenFailed(String),

    /// The peer answered that it does not serve the shard asked for: a
    /// definitive answer, unlike the transient faults above. A peer starts
    /// or stops serving a shard only when a reshape seats or unseats a
    /// vnode there.
    #[error("Shard not served by peer: {0}")]
    ShardUnsupported(String),
}
