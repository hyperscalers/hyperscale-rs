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

use std::ops::Range;
use std::time::Duration;

use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{BlockHeight, ShardId, StateRoot, ValidatorId};

use super::{Budget, Cluster};

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

    /// The host running `validator`, or `None` when no host runs it.
    fn host_of(&self, validator: ValidatorId) -> Option<usize>;

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

    /// Make `validators` withhold exactly `withheld` of their shard
    /// consensus from now on, replacing what they withheld before, so
    /// [`Withheld::Nothing`] lifts the fault: each signature it names is
    /// refused, on whichever hosts run them, while their beacon duties,
    /// execution and serving carry on.
    /// Unlike a host cut, it touches no other vnode sharing their hosts
    /// and no validator drawn later. The handle counts the refusals.
    fn withhold(&mut self, validators: &[ValidatorId], withheld: Withheld) -> FaultHandle;

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

    /// Partition the two host groups from each other (both directions)
    /// during each of `windows`, given as offsets from now. Between windows
    /// the groups connect; a window past the end of the run never opens.
    /// [`heal_all`](Self::heal_all) lifts every window. The same bridging
    /// caveat as [`partition`](Self::partition) applies.
    fn partition_during(
        &mut self,
        group_a: &[usize],
        group_b: &[usize],
        windows: &[Range<Duration>],
    );

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
    /// Some("transaction"))`), summed across hosts. An unlabelled read of
    /// a labelled counter is the sum over its labels.
    fn metric(&self, name: &'static str, label: Option<&str>) -> u64;

    /// Read the `q` quantile of a cluster-wide histogram over the
    /// observations above `floor`, within an eighth above the true value;
    /// `None` before any such observation.
    fn metric_quantile_above(
        &self,
        name: &'static str,
        label: Option<&str>,
        q: f64,
        floor: f64,
    ) -> Option<f64>;

    /// Read how many observations a cluster-wide histogram holds.
    fn metric_count(&self, name: &'static str, label: Option<&str>) -> u64;
}

/// What a crash takes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crash {
    /// The process dies; every write it completed survives.
    Process,
    /// The machine loses power; each store keeps only what its last
    /// synced write covered.
    Machine,
}

/// A [`FaultableCluster`] that can crash its hosts and start them again
/// on the disk they left.
///
/// A down host is absent: nothing reaches it and its copy of a shard
/// reads as none until it restarts and catches up, which is how a fault
/// drawn while it is down counts it.
pub trait CrashableCluster: FaultableCluster {
    /// Whether host `host`'s process is running.
    fn is_up(&self, host: usize) -> bool;

    /// Crash host `host` now, as `crash` says, and start its process
    /// again `downtime` later.
    fn crash(&mut self, host: usize, crash: Crash, downtime: Budget);

    /// Crash host `host`, as `crash` says, at the storage write it makes
    /// after `writes_before` more — the write itself does not happen —
    /// and start its process again `downtime` after that.
    fn crash_at_write(&mut self, host: usize, writes_before: u64, crash: Crash, downtime: Budget);

    /// Lift a crash armed at one of `host`'s writes that has not yet
    /// fired.
    fn disarm_crash(&mut self, host: usize);
}

/// The hosts of `a`'s and `b`'s live committees, in that order, which
/// share no host.
///
/// A host serving a shard answers its own requests to that shard from
/// its own handler and puts nothing on the wire, so a host seating a
/// vnode of each shard reads the other in-process, past every drop and
/// rewrite. A scenario whose fault sits on the road between two shards
/// takes the hosts its rules name from here, which also holds the
/// harness to a layout where that road exists.
///
/// # Panics
///
/// Panics if the two committees share a host.
pub fn committees_on_separate_hosts(
    c: &impl FaultableCluster,
    a: ShardId,
    b: ShardId,
) -> (Vec<usize>, Vec<usize>) {
    let a_hosts = c.committee_hosts(a);
    let b_hosts = c.committee_hosts(b);
    assert!(
        a_hosts.iter().all(|host| !b_hosts.contains(host)),
        "{a:?}'s and {b:?}'s committees must sit on hosts of their own, or reads between \
         them never reach the wire: {a:?} on {a_hosts:?}, {b:?} on {b_hosts:?}",
    );
    (a_hosts, b_hosts)
}

/// Report what the run's crossings cost: the fenced claims `c`'s
/// replicas carried and refused, by what each read, and the weight of
/// the claims section each committed block carried.
pub fn report_crossing_measures(c: &impl FaultableCluster, scenario: &str) {
    for reading in ["record", "removed"] {
        let carried = c.metric("fenced_claims_carried", Some(reading));
        let refused = c.metric("fenced_claims_refused", Some(reading));
        println!("{scenario}: fenced `{reading}` claims carried {carried}, refused {refused}");
    }
    let blocks = c.metric_count("state_claims_weight", None);
    let carrying = |q| {
        c.metric_quantile_above("state_claims_weight", None, q, 0.0)
            .unwrap_or(0.0)
    };
    println!(
        "{scenario}: claims weight over the blocks carrying claims of {blocks} committed: \
         p99 {:.0}, max {:.0} bytes",
        carrying(0.99),
        carrying(1.0),
    );
}
