//! Network error types.

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Generic network-layer failure passed up as a string.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Failed to establish a connection to the named peer.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// The network adapter has shut down and cannot service new requests.
    #[error("Network shutdown")]
    NetworkShutdown,

    /// Operation did not complete within the configured timeout.
    #[error("Request timeout")]
    Timeout,

    /// Supplied identifier could not be parsed as a libp2p `PeerId`.
    #[error("Invalid peer ID")]
    InvalidPeerId,

    /// Underlying stream I/O failed during read or write.
    #[error("Stream I/O error: {0}")]
    StreamIo(String),

    /// Could not open a new stream to the peer.
    #[error("Stream open failed: {0}")]
    StreamOpenFailed(String),

    /// The peer's live protocol table does not include the requested
    /// protocol — a definitive "not serving" answer, unlike the transient
    /// faults above. A peer only starts or stops serving a shard's request
    /// protocol when a reshape seats or unseats a vnode there.
    #[error("Protocol unsupported by peer: {0}")]
    ProtocolUnsupported(String),
}
