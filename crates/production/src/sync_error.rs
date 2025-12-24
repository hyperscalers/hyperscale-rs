//! Sync response error types.
//!
//! This module provides categorized error types for sync response validation.
//! Errors are classified as either malicious (warranting a peer ban) or
//! non-malicious (transient issues that should be retried).

use std::fmt;

/// Sync response validation errors.
///
/// Errors are categorized as malicious or non-malicious to determine
/// whether to ban the peer that sent the response.
///
/// # Malicious Errors
///
/// These errors indicate the peer sent intentionally invalid data and
/// should be banned:
/// - [`QcBlockHashMismatch`](Self::QcBlockHashMismatch) - QC doesn't match the block
/// - [`QcHeightMismatch`](Self::QcHeightMismatch) - QC height doesn't match block height
/// - [`QcSignatureInvalid`](Self::QcSignatureInvalid) - QC signature verification failed
/// - [`QcInsufficientQuorum`](Self::QcInsufficientQuorum) - QC lacks required voting power
/// - [`BlockHashMismatch`](Self::BlockHashMismatch) - Block hash doesn't match expected
/// - [`BlockParentMismatch`](Self::BlockParentMismatch) - Block parent doesn't chain correctly
///
/// # Non-Malicious Errors
///
/// These errors indicate transient issues and should not result in bans:
/// - [`NoRequestPending`](Self::NoRequestPending) - Stale/delayed response
/// - [`PeerMismatch`](Self::PeerMismatch) - Response from wrong peer (routing issue)
/// - [`RequestIdMismatch`](Self::RequestIdMismatch) - Response for different request
/// - [`StateMismatch`](Self::StateMismatch) - Block doesn't extend current state
/// - [`Timeout`](Self::Timeout) - Request timed out
/// - [`NetworkError`](Self::NetworkError) - Network-level failure
/// - [`EmptyResponse`](Self::EmptyResponse) - Peer doesn't have the requested block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResponseError {
    // === Non-malicious errors (don't ban, just retry with different peer) ===
    /// Response received when no request was pending.
    /// Could be a delayed response from a previous request.
    NoRequestPending,

    /// Response from a different peer than expected.
    /// Could be a delayed response after peer rotation.
    PeerMismatch,

    /// Request ID doesn't match pending request.
    RequestIdMismatch {
        /// Expected request ID.
        expected: u64,
        /// Actual request ID received.
        actual: u64,
    },

    /// Block doesn't extend our current state.
    /// Could be a delayed response after we already synced past this height.
    StateMismatch {
        /// Height of the received block.
        height: u64,
        /// Current committed height.
        current: u64,
    },

    /// Request timed out waiting for response.
    Timeout {
        /// Height that was being requested.
        height: u64,
    },

    /// Network-level error (connection lost, send failed, etc.).
    NetworkError {
        /// Description of the network error.
        reason: String,
    },

    /// Empty response - peer doesn't have the requested block.
    /// This is non-malicious because peers may have pruned old blocks
    /// or may be behind in sync themselves.
    EmptyResponse {
        /// Height that was requested.
        height: u64,
    },

    // === Malicious errors (ban the peer) ===
    /// QC doesn't match the block it claims to certify.
    QcBlockHashMismatch {
        /// Height where mismatch occurred.
        height: u64,
    },

    /// QC height doesn't match block height.
    QcHeightMismatch {
        /// Block height.
        block_height: u64,
        /// QC height.
        qc_height: u64,
    },

    /// QC signature verification failed.
    QcSignatureInvalid {
        /// Height where verification failed.
        height: u64,
    },

    /// QC doesn't have sufficient voting power (quorum).
    QcInsufficientQuorum {
        /// Height where quorum check failed.
        height: u64,
        /// Voting power present.
        voting_power: u64,
        /// Voting power required.
        required: u64,
    },

    /// Block hash doesn't match expected hash (from parent QC or sync target).
    BlockHashMismatch {
        /// Height where mismatch occurred.
        height: u64,
    },

    /// Block parent hash doesn't match previous block.
    BlockParentMismatch {
        /// Height where mismatch occurred.
        height: u64,
    },
}

impl SyncResponseError {
    /// Returns true if this error indicates malicious peer behavior.
    ///
    /// Malicious errors warrant banning the peer, while non-malicious
    /// errors should just trigger a retry with a different peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use hyperscale_production::SyncResponseError;
    /// // Malicious: peer sent invalid block
    /// let err = SyncResponseError::QcSignatureInvalid { height: 100 };
    /// assert!(err.is_malicious());
    ///
    /// // Non-malicious: network timeout
    /// let err = SyncResponseError::Timeout { height: 100 };
    /// assert!(!err.is_malicious());
    /// ```
    pub fn is_malicious(&self) -> bool {
        matches!(
            self,
            Self::QcBlockHashMismatch { .. }
                | Self::QcHeightMismatch { .. }
                | Self::QcSignatureInvalid { .. }
                | Self::QcInsufficientQuorum { .. }
                | Self::BlockHashMismatch { .. }
                | Self::BlockParentMismatch { .. }
        )
    }

    /// Returns true if this is an empty response error.
    ///
    /// Empty responses indicate the peer doesn't have the requested block,
    /// which typically means they are also behind in sync.
    pub fn is_empty_response(&self) -> bool {
        matches!(self, Self::EmptyResponse { .. })
    }

    /// Returns the metric label for this error type.
    ///
    /// Labels are designed to be low-cardinality for Prometheus metrics.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::NoRequestPending => "no_request",
            Self::PeerMismatch => "peer_mismatch",
            Self::RequestIdMismatch { .. } => "request_id_mismatch",
            Self::StateMismatch { .. } => "state_mismatch",
            Self::Timeout { .. } => "timeout",
            Self::NetworkError { .. } => "network_error",
            Self::EmptyResponse { .. } => "empty_response",
            Self::QcBlockHashMismatch { .. } => "qc_hash_mismatch",
            Self::QcHeightMismatch { .. } => "qc_height_mismatch",
            Self::QcSignatureInvalid { .. } => "qc_sig_invalid",
            Self::QcInsufficientQuorum { .. } => "qc_no_quorum",
            Self::BlockHashMismatch { .. } => "block_hash_mismatch",
            Self::BlockParentMismatch { .. } => "block_parent_mismatch",
        }
    }
}

impl fmt::Display for SyncResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRequestPending => write!(f, "no sync request pending"),
            Self::PeerMismatch => write!(f, "response from unexpected peer"),
            Self::RequestIdMismatch { expected, actual } => {
                write!(
                    f,
                    "request ID mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::StateMismatch { height, current } => {
                write!(
                    f,
                    "block at height {} doesn't extend current state at {}",
                    height, current
                )
            }
            Self::Timeout { height } => {
                write!(f, "sync request timed out for height {}", height)
            }
            Self::NetworkError { reason } => {
                write!(f, "network error: {}", reason)
            }
            Self::EmptyResponse { height } => {
                write!(f, "empty sync response for height {}", height)
            }
            Self::QcBlockHashMismatch { height } => {
                write!(f, "QC block hash mismatch at height {}", height)
            }
            Self::QcHeightMismatch {
                block_height,
                qc_height,
            } => {
                write!(
                    f,
                    "QC height mismatch: block {}, QC {}",
                    block_height, qc_height
                )
            }
            Self::QcSignatureInvalid { height } => {
                write!(f, "QC signature verification failed at height {}", height)
            }
            Self::QcInsufficientQuorum {
                height,
                voting_power,
                required,
            } => {
                write!(
                    f,
                    "QC lacks quorum at height {}: {} < {}",
                    height, voting_power, required
                )
            }
            Self::BlockHashMismatch { height } => {
                write!(f, "block hash mismatch at height {}", height)
            }
            Self::BlockParentMismatch { height } => {
                write!(f, "block parent hash mismatch at height {}", height)
            }
        }
    }
}

impl std::error::Error for SyncResponseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_errors() {
        // All malicious errors - these indicate the peer sent intentionally invalid data
        let malicious = [
            SyncResponseError::QcBlockHashMismatch { height: 1 },
            SyncResponseError::QcHeightMismatch {
                block_height: 1,
                qc_height: 2,
            },
            SyncResponseError::QcSignatureInvalid { height: 1 },
            SyncResponseError::QcInsufficientQuorum {
                height: 1,
                voting_power: 50,
                required: 67,
            },
            SyncResponseError::BlockHashMismatch { height: 1 },
            SyncResponseError::BlockParentMismatch { height: 1 },
        ];

        for err in malicious {
            assert!(err.is_malicious(), "{} should be malicious", err);
        }
    }

    #[test]
    fn test_non_malicious_errors() {
        // All non-malicious errors - transient issues that don't warrant banning
        let non_malicious = [
            SyncResponseError::NoRequestPending,
            SyncResponseError::PeerMismatch,
            SyncResponseError::RequestIdMismatch {
                expected: 1,
                actual: 2,
            },
            SyncResponseError::StateMismatch {
                height: 10,
                current: 20,
            },
            SyncResponseError::Timeout { height: 5 },
            SyncResponseError::NetworkError {
                reason: "connection lost".to_string(),
            },
            // EmptyResponse is non-malicious - peer may have pruned the block
            // or be behind in sync themselves
            SyncResponseError::EmptyResponse { height: 1 },
        ];

        for err in non_malicious {
            assert!(!err.is_malicious(), "{} should not be malicious", err);
        }
    }

    #[test]
    fn test_metric_labels_are_unique() {
        let errors = [
            SyncResponseError::NoRequestPending,
            SyncResponseError::PeerMismatch,
            SyncResponseError::RequestIdMismatch {
                expected: 1,
                actual: 2,
            },
            SyncResponseError::StateMismatch {
                height: 1,
                current: 2,
            },
            SyncResponseError::Timeout { height: 1 },
            SyncResponseError::NetworkError {
                reason: "test".to_string(),
            },
            SyncResponseError::EmptyResponse { height: 1 },
            SyncResponseError::QcBlockHashMismatch { height: 1 },
            SyncResponseError::QcHeightMismatch {
                block_height: 1,
                qc_height: 2,
            },
            SyncResponseError::QcSignatureInvalid { height: 1 },
            SyncResponseError::QcInsufficientQuorum {
                height: 1,
                voting_power: 1,
                required: 2,
            },
            SyncResponseError::BlockHashMismatch { height: 1 },
            SyncResponseError::BlockParentMismatch { height: 1 },
        ];

        let mut labels: Vec<_> = errors.iter().map(|e| e.metric_label()).collect();
        let original_len = labels.len();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), original_len, "metric labels should be unique");
    }

    #[test]
    fn test_display() {
        let err = SyncResponseError::QcInsufficientQuorum {
            height: 100,
            voting_power: 50,
            required: 67,
        };
        assert_eq!(err.to_string(), "QC lacks quorum at height 100: 50 < 67");
    }
}
