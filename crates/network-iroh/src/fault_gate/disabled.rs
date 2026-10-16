//! The no-op fault gate, compiled when `test-utils` is off.
//!
//! A zero-sized stand-in for the real gate: every consult returns "deliver", so
//! the transport's delivery seams call the gate unconditionally at no cost and
//! no fault machinery reaches the validator binary. The installation surface
//! (`configure`, `install_drop`, `block_host`, …) exists only on the real gate,
//! so test-only code that drives it is gated out alongside this stub.

use hyperscale_network::fault::Tier;
use iroh::EndpointId;

/// Zero-sized no-op fault gate. See the module docs.
#[derive(Debug, Default)]
pub struct FaultState;

#[allow(clippy::unused_self)] // signatures match the real gate's, so either is called identically
impl FaultState {
    /// Build the inert gate.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Never suppresses an outbound unicast — no rules can be installed.
    #[inline]
    #[must_use]
    pub(crate) const fn drop_outbound(
        &self,
        _peer: EndpointId,
        _type_id: &str,
        _tier: Tier,
    ) -> bool {
        false
    }

    /// Never suppresses an outbound delivery by partition.
    #[inline]
    #[must_use]
    pub(crate) const fn blocked_outbound(&self, _peer: EndpointId) -> bool {
        false
    }

    /// Answers with exactly what the handler answered.
    #[inline]
    #[must_use]
    pub(crate) const fn rewrite_response(
        &self,
        _peer: EndpointId,
        _type_id: &str,
        _asked: &[u8],
        answer: Vec<u8>,
    ) -> Vec<u8> {
        answer
    }

    /// Never suppresses an inbound gossip item.
    #[inline]
    #[must_use]
    pub(crate) const fn drop_inbound_gossip(&self, _sender: EndpointId, _type_id: &str) -> bool {
        false
    }
}
