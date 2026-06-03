//! `Timeout` notification message.

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, Timeout, Verifiable};

/// A validator's timeout for a shard consensus round. 2f+1 matching timeouts
/// drive a synchronised view change.
///
/// Broadcast to the local-shard committee. The inner [`Timeout`] carries the
/// voter identity, its BLS share, and the signer's `high_qc`, so it is
/// self-authenticating.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TimeoutNotification {
    /// The timeout — wire bytes always land in [`Verifiable::Unverified`];
    /// local-dispatched sends from a colocated signer preserve
    /// [`Verifiable::Verified`].
    pub timeout: Verifiable<Timeout>,
}

impl TimeoutNotification {
    /// Create a new timeout notification message.
    #[must_use]
    pub fn new(timeout: impl Into<Verifiable<Timeout>>) -> Self {
        Self {
            timeout: timeout.into(),
        }
    }

    /// Get the inner timeout (raw view, regardless of verification state).
    #[must_use]
    pub fn timeout(&self) -> &Timeout {
        self.timeout.as_unverified()
    }

    /// Consume and return the inner timeout wrapper.
    #[must_use]
    pub fn into_timeout(self) -> Verifiable<Timeout> {
        self.timeout
    }
}

impl NetworkMessage for TimeoutNotification {
    fn message_type_id() -> &'static str {
        "shard.timeout"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}
