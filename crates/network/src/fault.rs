//! Portable per-host fault-injection vocabulary.
//!
//! The lightweight types the transport's delivery seams name unconditionally —
//! [`HostId`], [`Tier`], [`MessageContext`], [`Decision`] — live here and are
//! always compiled. The engine that holds the rules, the partition block-set,
//! and the seeded probability RNG lives in the `engine` submodule behind the
//! `test-utils` feature; a transport consults a gate that is a no-op unless that
//! feature is on.
//!
//! Faults are **host-granular**: co-hosted vnodes share one transport, so a
//! fault targets a [`HostId`], not a validator. Both harnesses map their native
//! routing id to it — the in-memory sim's `NodeIndex` is numerically identical,
//! the libp2p gate keeps a `PeerId ↔ HostId` map.

#[cfg(feature = "test-utils")]
mod engine;

#[cfg(feature = "test-utils")]
pub use engine::{DropSpec, Engine, FaultBuilder, RuleBuilder, RuleHandle};

/// A cluster host — the granularity at which faults apply.
///
/// Co-hosted vnodes share one transport, so a fault targets the host, not a
/// validator. The sim's `NodeIndex` maps here one to one; the libp2p gate keeps
/// a `PeerId ↔ HostId` map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId(pub u32);

/// Transport tier on which a message is dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Broadcast gossip to all peers in a shard or globally.
    Gossip,
    /// Unicast notification with no response.
    Notification,
    /// Outbound request leg of a request/response RPC.
    Request,
    /// Inbound response leg of a request/response RPC. No transport gates the
    /// response leg today — both harnesses model response-direction loss through
    /// the request leg and packet loss — so this tier is part of the vocabulary
    /// but never consulted at a live delivery seam.
    Response,
}

/// Context passed to fault rules at each dispatch site.
#[derive(Debug, Clone, Copy)]
pub struct MessageContext<'a> {
    /// Host sending the message.
    pub sender: HostId,
    /// Host receiving the message.
    pub recipient: HostId,
    /// Message type id (e.g. `"transaction.gossip"`).
    pub type_id: &'a str,
    /// Transport tier.
    pub tier: Tier,
}

/// Decision returned by the engine for a single dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Deliver normally.
    Pass,
    /// Drop the message; bumps the rule's fired counter.
    Drop,
}
