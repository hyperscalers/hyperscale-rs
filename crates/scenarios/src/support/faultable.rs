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

    /// Lift every partition — restore full connectivity.
    fn heal_all(&mut self);

    /// Read a cluster-wide metric counter (e.g. `("fetch_items_sent",
    /// Some("transaction"))`), summed across hosts.
    fn metric(&self, name: &'static str, label: Option<&str>) -> u64;
}
