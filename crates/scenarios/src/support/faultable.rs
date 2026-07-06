//! The [`FaultableCluster`] surface: a [`Cluster`] whose deliveries can be
//! faulted.
//!
//! Portable fault scenarios drive this surface. Hosts are addressed by index
//! `0..host_count()`; each harness maps that index onto its native identity
//! (the sim's `NodeIndex`, the libp2p gate's `HostId`). A [`drop_type`] rule
//! returns a [`FaultHandle`] whose `fired()` count aggregates across every host
//! the rule was installed on.
//!
//! [`drop_type`]: FaultableCluster::drop_type

use hyperscale_types::{BlockHeight, ShardId, StateRoot};

use super::Cluster;

/// Handle to an installed drop rule.
///
/// `fired()` reads the current cluster-wide fire count — one rule on the sim's
/// global engine, or the sum across every host's gate on production.
pub struct FaultHandle {
    fired: Box<dyn Fn() -> u64>,
}

impl FaultHandle {
    /// Wrap a cluster-wide fire-count reader.
    #[must_use]
    pub fn new(fired: impl Fn() -> u64 + 'static) -> Self {
        Self {
            fired: Box::new(fired),
        }
    }

    /// The number of times the rule has dropped a message, cluster-wide.
    #[must_use]
    pub fn fired(&self) -> u64 {
        (self.fired)()
    }
}

/// A [`Cluster`] whose deliveries can be faulted — the portable fault-scenario
/// surface.
///
/// Faults are host-granular; hosts are addressed by index `0..host_count()`.
/// Drops suppress a message class; [`partition`](Self::partition) and
/// [`isolate`](Self::isolate) cut delivery between host groups (a partition),
/// leaving connections warm so a [`heal_all`](Self::heal_all) resumes catch-up
/// sync at once. [`metric`](Self::metric) reads a counter emitted by node code,
/// identically on both harnesses.
pub trait FaultableCluster: Cluster {
    /// The number of hosts in the cluster.
    fn host_count(&self) -> usize;

    /// Drop every delivery of `type_id`, on every host.
    fn drop_type(&mut self, type_id: &'static str) -> FaultHandle;

    /// Drop deliveries of `type_id` with the given probability `[0.0, 1.0]`, on
    /// every host.
    fn drop_type_with_probability(
        &mut self,
        type_id: &'static str,
        probability: f64,
    ) -> FaultHandle;

    /// Drop deliveries of `type_id` sent by a host in `from` to a host in `to`,
    /// that direction only. The reverse direction and every other host pair
    /// flow untouched. Fault rules gate pushes (gossip) and request legs, never
    /// response legs — so isolating a fetched payload cuts the *requester's*
    /// outbound request, not the response.
    ///
    /// Gossip caveat as [`partition`](Self::partition): production attributes a
    /// gossip message to its immediate relay hop, so keep `from` and `to`
    /// bridged by no third host. Returns a handle summing fires across every
    /// installed edge.
    fn drop_type_between(
        &mut self,
        from: &[usize],
        to: &[usize],
        type_id: &'static str,
    ) -> FaultHandle;

    /// The hosts whose vnode sits in `shard`'s live committee — the copy
    /// currently seated, not a terminated chain lingering on old hosts.
    fn committee_hosts(&self, shard: ShardId) -> Vec<usize>;

    /// The highest committed height on `shard` at host `host` specifically,
    /// or `None` if that host serves no vnode there. Per-host — unlike
    /// [`Cluster::committed_height`], which reports the cluster-wide max — so a
    /// scenario can confirm a lagging fragment actually caught up to the
    /// majority rather than reading the majority's own tip.
    fn host_committed_height(&self, host: usize, shard: ShardId) -> Option<BlockHeight>;

    /// The committed state root at `shard`'s tip on host `host`, or `None` if
    /// that host serves no vnode there. Per-host, so a scenario can assert
    /// every host converged on one root after a heal — the stall-not-fork
    /// guarantee a cluster-wide read cannot see.
    fn host_committed_state_root(&self, host: usize, shard: ShardId) -> Option<StateRoot>;

    /// Remove every installed drop rule, on every host — lifting any transient
    /// outage so the suppressed channel flows again. Leaves partitions intact
    /// ([`heal_all`](Self::heal_all) lifts those); the fire counts on handles
    /// already returned stay readable, frozen at their final value.
    fn clear_drops(&mut self);

    /// Partition the two host groups from each other (both directions).
    ///
    /// Cuts A↔B only; any third group stays connected to both. The two
    /// harnesses agree only when there is no bridging group: the sim delivers
    /// gossip directly (no relay), so a host reachable from both halves never
    /// bridges them, whereas production relays gossip through the gossipsub mesh
    /// and enforces the cut against the immediate relay hop — so a bridging host
    /// would carry gossip across the partition. Keep portable partition
    /// scenarios to a full bipartition (or [`isolate`](Self::isolate)) with no
    /// host reachable from both sides.
    fn partition(&mut self, group_a: &[usize], group_b: &[usize]);

    /// Isolate one host from every other host.
    fn isolate(&mut self, host: usize);

    /// Heal the partition between hosts `a` and `b` only (both directions),
    /// leaving every other cut intact — the staged counterpart to
    /// [`heal_all`](Self::heal_all). Maps to `Engine::unblock` both ways on
    /// each harness, so a test can restore connectivity one edge at a time
    /// (e.g. bring a partition back up to exactly quorum before the final
    /// heal).
    fn heal_between(&mut self, a: usize, b: usize);

    /// Lift every partition — restore full connectivity.
    fn heal_all(&mut self);

    /// Read a cluster-wide metric counter (e.g. `("fetch_items_sent",
    /// Some("transaction"))`), summed across hosts.
    fn metric(&self, name: &'static str, label: Option<&str>) -> u64;
}
