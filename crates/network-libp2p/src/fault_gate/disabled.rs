//! The no-op fault gate, compiled when `test-utils` is off.
//!
//! A zero-sized stand-in for the real gate: every consult returns "deliver", so
//! the transport's delivery seams call the gate unconditionally at no cost and
//! no fault machinery reaches the validator binary. The installation surface
//! (`configure`, `install_drop`, `block_host`, …) exists only on the real gate,
//! so test-only code that drives it is gated out alongside this stub.

use hyperscale_network::fault::Tier;
use libp2p::PeerId;

/// Zero-sized no-op fault gate. See the module docs.
#[derive(Debug, Default)]
pub struct FaultState;

// The no-op methods keep `&self` to match the real gate's signatures, so the
// delivery seams call either gate identically.
#[allow(clippy::unused_self)]
impl FaultState {
    /// Build the inert gate.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Never suppresses an outbound unicast — no rules can be installed.
    #[inline]
    #[must_use]
    pub(crate) const fn drop_outbound(&self, _peer: PeerId, _type_id: &str, _tier: Tier) -> bool {
        false
    }

    /// Never suppresses an outbound delivery by partition.
    #[inline]
    #[must_use]
    pub(crate) const fn blocked_outbound(&self, _peer: PeerId) -> bool {
        false
    }

    /// Never suppresses an inbound gossip message.
    #[inline]
    #[must_use]
    pub(crate) const fn drop_inbound_gossip(&self, _origin: PeerId, _type_id: &str) -> bool {
        false
    }
}
