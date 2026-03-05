//! Network error types.

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Network shutdown")]
    NetworkShutdown,

    #[error("Request timeout")]
    Timeout,

    #[error("Invalid peer ID")]
    InvalidPeerId,

    #[error("Stream I/O error: {0}")]
    StreamIo(String),

    #[error("Stream open failed: {0}")]
    StreamOpenFailed(String),
}
