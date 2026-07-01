//! The real per-host fault gate, compiled when `test-utils` is enabled.
//!
//! Wraps the shared fault [`Engine`] with the identity plumbing the libp2p
//! transport needs — a `PeerId → HostId` map the harness populates and this
//! host's own [`HostId`] — and is consulted at the outbound send seams and the
//! inbound gossip receive seam.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyperscale_network::fault::{
    Decision, DropSpec, Engine, HostId, MessageContext, RuleHandle, Tier,
};
use libp2p::PeerId;
use parking_lot::Mutex;

/// Sentinel for "this host's id has not been configured yet".
const UNSET_HOST: u32 = u32::MAX;

/// Fault state for one host, consulted at its delivery seams.
///
/// Holds the shared [`Engine`] (drop rules + partition block-set), the harness's
/// `PeerId → HostId` map, and this host's id. Cheaply shared via `Arc`.
pub struct FaultState {
    engine: Mutex<Engine>,
    host_of_peer: DashMap<PeerId, HostId>,
    self_host: AtomicU32,
    start: Instant,
}

impl Default for FaultState {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultState {
    /// Build an inert gate — no rules, no partitions, no host map. The harness
    /// calls [`Self::configure`] before installing faults.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            // Prod needs no deterministic replay, so any seed serves.
            engine: Mutex::new(Engine::new(0)),
            host_of_peer: DashMap::new(),
            self_host: AtomicU32::new(UNSET_HOST),
            start: Instant::now(),
        }
    }

    /// Harness setup: record this host's id and the full `PeerId → HostId` map.
    ///
    /// The map is a one-shot snapshot: partition and gossip-origin filtering
    /// resolve peers against exactly the hosts passed here. A host that joins
    /// after this call (a reshape-seated peer) is invisible to `block_all_hosts`
    /// and the origin lookup until a fresh `configure`, so re-run this after any
    /// topology growth that adds hosts, before installing partitions.
    pub(crate) fn configure(
        &self,
        self_host: HostId,
        peers: impl IntoIterator<Item = (PeerId, HostId)>,
    ) {
        self.self_host.store(self_host.0, Ordering::Relaxed);
        self.host_of_peer.clear();
        for (peer, host) in peers {
            self.host_of_peer.insert(peer, host);
        }
    }

    fn self_host(&self) -> HostId {
        HostId(self.self_host.load(Ordering::Relaxed))
    }

    fn host_of(&self, peer: &PeerId) -> Option<HostId> {
        self.host_of_peer.get(peer).map(|r| *r)
    }

    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    // ── Consulted at delivery seams ──────────────────────────────────────

    /// Whether an outbound unicast to `peer` is suppressed — by a partition
    /// against its host or a matching drop rule. A peer absent from the host
    /// map is never dropped: the gate acts only on configured hosts.
    #[must_use]
    pub(crate) fn drop_outbound(&self, peer: PeerId, type_id: &str, tier: Tier) -> bool {
        let Some(recipient) = self.host_of(&peer) else {
            return false;
        };
        let sender = self.self_host();
        let engine = self.engine.lock();
        engine.is_blocked(sender, recipient)
            || engine.decide(
                &MessageContext {
                    sender,
                    recipient,
                    type_id,
                    tier,
                },
                self.now(),
            ) == Decision::Drop
    }

    /// Whether an outbound delivery to `peer` is suppressed by a partition
    /// only (ignoring drop rules) — the request path's peer filter, which drops
    /// blocked committee members without consulting per-type drop rules.
    #[must_use]
    pub(crate) fn blocked_outbound(&self, peer: PeerId) -> bool {
        let Some(recipient) = self.host_of(&peer) else {
            return false;
        };
        self.engine.lock().is_blocked(self.self_host(), recipient)
    }

    /// Whether an inbound gossip message from `origin` is suppressed — by a
    /// partition against its host or a matching drop rule. Reporting
    /// `Ignore` for a suppressed message stops both local delivery and mesh
    /// relay. An unknown origin still matches type-only drop rules (which use
    /// an any-host filter); only partition needs the resolved origin.
    ///
    /// `origin` is the immediate gossipsub relay hop (`propagation_source`), not
    /// necessarily the message author, so a partition is enforced against the
    /// relay — a host reachable from both halves of a cut would bridge gossip
    /// across it. Portable scenarios avoid such bridging topologies (see
    /// `FaultableCluster::partition`).
    #[must_use]
    pub(crate) fn drop_inbound_gossip(&self, origin: PeerId, type_id: &str) -> bool {
        let recipient = self.self_host();
        let sender = self.host_of(&origin).unwrap_or(recipient);
        let engine = self.engine.lock();
        engine.is_blocked(sender, recipient)
            || engine.decide(
                &MessageContext {
                    sender,
                    recipient,
                    type_id,
                    tier: Tier::Gossip,
                },
                self.now(),
            ) == Decision::Drop
    }

    // ── Control (driven by the harness through the adapter gate) ─────────

    /// Install a drop rule; returns its handle.
    #[must_use]
    pub fn install_drop(&self, spec: DropSpec) -> RuleHandle {
        self.engine.lock().install_spec(spec)
    }

    /// Remove a previously installed drop rule.
    pub fn remove_fault(&self, handle: &RuleHandle) {
        self.engine.lock().remove(handle);
    }

    /// Remove every installed drop rule (leaves partitions intact).
    pub fn clear_faults(&self) {
        self.engine.lock().clear();
    }

    /// Partition this host from `host` (both directions).
    pub fn block_host(&self, host: HostId) {
        let me = self.self_host();
        let mut engine = self.engine.lock();
        engine.block(me, host);
        engine.block(host, me);
    }

    /// Lift a partition against `host`.
    pub fn unblock_host(&self, host: HostId) {
        let me = self.self_host();
        let mut engine = self.engine.lock();
        engine.unblock(me, host);
        engine.unblock(host, me);
    }

    /// Partition this host from every other configured host — full isolation.
    pub fn block_all_hosts(&self) {
        let me = self.self_host();
        let others: Vec<HostId> = self
            .host_of_peer
            .iter()
            .map(|r| *r.value())
            .filter(|h| *h != me)
            .collect();
        let mut engine = self.engine.lock();
        for host in others {
            engine.block(me, host);
            engine.block(host, me);
        }
    }

    /// Lift every partition against this host.
    pub fn heal(&self) {
        self.engine.lock().unblock_all();
    }
}
