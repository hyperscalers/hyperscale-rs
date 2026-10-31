//! The [`FaultableCluster`] surface: a [`Cluster`] whose deliveries can be
//! faulted.
//!
//! Portable fault scenarios drive this surface. Hosts are addressed by index
//! `0..host_count()`; each harness maps that index onto its native identity
//! (the sim's `NodeIndex`, the iroh gate's `HostId`). A [`drop_type`] rule
//! returns a [`FaultHandle`] whose `fired()` count aggregates across every host
//! the rule was installed on.
//!
//! [`drop_type`]: FaultableCluster::drop_type

use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{
    BlockHeight, MAX_CLAIMS_BYTES, MAX_STATE_CLAIMS_BYTES, PendingReshape, ShardId, StateRoot,
    Transaction, ValidatorId,
};

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

    /// Drop deliveries of `type_id` sent by a host that serves `from` to a
    /// host that serves `to`, as [`member_hosts`] reads both sides, that
    /// direction only. Unlike [`drop_type_between`](Self::drop_type_between)
    /// the rule follows membership: the harness re-reads both sides as the
    /// run advances, so a host that joins either shard after the rule is
    /// installed is cut too. A host stays cut once it has served a side,
    /// since it keeps the store it served it from, and a host named for a
    /// seat counts before it takes it, which covers the gap between two
    /// reads. The same response-leg and gossip caveats apply. The handle
    /// sums fires over every host pair the rule has covered.
    fn drop_type_between_members(
        &mut self,
        from: ShardId,
        to: ShardId,
        type_id: &'static str,
    ) -> FaultHandle;

    /// Make every host serving `shard`'s live committee answer a block
    /// sync for a block of `shard` above `height` as not found, until
    /// [`clear_drops`](Self::clear_drops). A requester syncing the shard
    /// from those hosts reaches `height` and no further; a host answering
    /// its own requests in-process is not capped. The handle counts the
    /// blocks refused.
    fn cap_block_serving(&mut self, shard: ShardId, height: BlockHeight) -> FaultHandle;

    /// The host running `validator`, or `None` when no host runs it.
    fn host_of(&self, validator: ValidatorId) -> Option<usize>;

    /// Submit `tx` at `host` itself, whatever it serves, as a client
    /// talking to its own node does.
    fn submit_at_host(&mut self, host: usize, tx: Transaction);

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
    /// bridges them, whereas production forwards global gossip on through
    /// sampled hosts and enforces the cut against the immediate hop — so a
    /// bridging host would carry global gossip across the partition. Keep portable partition
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

/// Every host that runs or is about to run a member of `shard`: the
/// seated copies, the hosts of the members the beacon names for this
/// epoch and the next, and the hosts of the cohort syncing `shard`
/// toward its split. A member the beacon has named joins once its host
/// reads the shard's anchor, and a cohort member serves the shard's state
/// while it syncs, so a cut drawn from the seated copies alone would leave
/// their channels open.
pub fn member_hosts(c: &impl FaultableCluster, shard: ShardId) -> Vec<usize> {
    let mut hosts: BTreeSet<usize> = c.committee_hosts(shard).into_iter().collect();
    if let Some(state) = c.beacon_state() {
        let named = [&state.shard_committees, &state.next_shard_committees]
            .into_iter()
            .filter_map(|committees| committees.get(&shard))
            .flat_map(|committee| committee.members.iter().copied());
        let cohort = match state.pending_reshapes.get(&shard) {
            Some(PendingReshape::Split { cohort, .. }) => cohort.keys().copied().collect(),
            _ => Vec::new(),
        };
        hosts.extend(named.chain(cohort).filter_map(|member| c.host_of(member)));
    }
    hosts.into_iter().collect()
}

/// The two sides of a [`FaultableCluster::drop_type_between_members`]
/// rule, and every host each side has counted since it was installed.
pub struct MemberEdge {
    from: ShardId,
    to: ShardId,
    type_id: &'static str,
    covered: (BTreeSet<usize>, BTreeSet<usize>),
}

impl MemberEdge {
    /// An edge from `from`'s hosts to `to`'s for `type_id`, covering no
    /// host until it is first read.
    #[must_use]
    pub const fn new(from: ShardId, to: ShardId, type_id: &'static str) -> Self {
        Self {
            from,
            to,
            type_id,
            covered: (BTreeSet::new(), BTreeSet::new()),
        }
    }

    /// The message type the edge drops.
    #[must_use]
    pub const fn type_id(&self) -> &'static str {
        self.type_id
    }

    /// The `(from, to)` host sets the edge covers now, when a host has
    /// joined either side since it was last read. A side never drops a
    /// host: one that leaves a shard keeps the store it served it from.
    pub fn moved(&mut self, c: &impl FaultableCluster) -> Option<(Vec<usize>, Vec<usize>)> {
        let joined = member_hosts(c, self.from)
            .into_iter()
            .filter(|host| self.covered.0.insert(*host))
            .count()
            + member_hosts(c, self.to)
                .into_iter()
                .filter(|host| self.covered.1.insert(*host))
                .count();
        (joined > 0).then(|| {
            (
                self.covered.0.iter().copied().collect(),
                self.covered.1.iter().copied().collect(),
            )
        })
    }
}

/// What a host under [`FaultableCluster::cap_block_serving`] answers a
/// block sync with: not found for a block of `shard` above `height`, and
/// the honest answer for anything else.
#[derive(Clone)]
pub struct BlockServingCap {
    shard: ShardId,
    height: BlockHeight,
    refused: Arc<AtomicU64>,
    not_found: Arc<[u8]>,
}

impl BlockServingCap {
    /// A cap on `shard`'s blocks above `height`, having refused none.
    ///
    /// # Panics
    ///
    /// If a not-found block response does not encode.
    #[must_use]
    pub fn new(shard: ShardId, height: BlockHeight) -> Self {
        let not_found =
            to_vec(&GetBlockResponse::not_found()).expect("a not-found block response encodes");
        Self {
            shard,
            height,
            refused: Arc::new(AtomicU64::new(0)),
            not_found: Arc::from(not_found),
        }
    }

    /// The bytes to answer with in place of `honest`, a `block.request`
    /// handler's own answer. An answer that is no block response, such as
    /// the empty one a failed handler sends, passes untouched.
    #[must_use]
    pub fn answer(&self, honest: &[u8]) -> Vec<u8> {
        let Ok(response) = from_slice::<GetBlockResponse>(honest) else {
            return honest.to_vec();
        };
        let capped = response.block().is_some_and(|block| {
            block.header().shard_id() == self.shard && block.header().height() > self.height
        });
        if !capped {
            return honest.to_vec();
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        self.not_found.to_vec()
    }

    /// A handle counting the blocks this cap refused, on every host it is
    /// installed on.
    #[must_use]
    pub fn handle(&self) -> FaultHandle {
        let refused = Arc::clone(&self.refused);
        FaultHandle::new(move || refused.load(Ordering::Relaxed))
    }
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

/// A [`FaultableCluster`] that can stop a host's process and start it
/// again on the disk it left.
///
/// A down host is absent: nothing reaches it and its copy of a shard
/// reads as none until it restarts and catches up, which is how a fault
/// drawn while it is down counts it.
pub trait RestartableCluster: FaultableCluster {
    /// Whether host `host`'s process is running.
    fn is_up(&self, host: usize) -> bool;

    /// Stop host `host`'s process now and start it again on the disk it
    /// left `downtime` later; every write it completed survives. A fault
    /// installed before the stop, or while the host is down, is not
    /// promised to cover it once it is back.
    ///
    /// # Panics
    ///
    /// Panics if `host` is down.
    fn stop_host(&mut self, host: usize, downtime: Budget);
}

/// A [`RestartableCluster`] that can also crash its hosts, mid-write or
/// with the machine's unsynced writes lost.
pub trait CrashableCluster: RestartableCluster {
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

/// What `c`'s committed blocks carried in their claims that one of the
/// committed blocks just below carried too, by kind, summed over
/// replicas and shards as the counters are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimsRecarried {
    /// Cells read at one anchor by claims that delete, return and retire
    /// nothing.
    pub cells: u64,
    /// Record keys read absent.
    pub deletions: u64,
    /// `Taken` and `Never` keys read present.
    pub answers: u64,
    /// Crossings read at the parent.
    pub local: u64,
}

/// Report what `c`'s committed blocks carried twice, by kind and per
/// committed block, and hand the counts back.
///
/// A proposer passes over what the chain to its parent carries, so an
/// honest run carries no cell and no deletion twice. An answer read
/// present or a crossing read at the parent that its carrier does not
/// settle is offered again once the carrier folds, so those two are
/// reported and not held to zero.
///
/// # Panics
///
/// Panics if a committed block carried a cell or a deletion that one of
/// the four below it carried.
pub fn report_claims_recarried(c: &impl FaultableCluster, scenario: &str) -> ClaimsRecarried {
    let recarried = ClaimsRecarried {
        cells: c.metric("claims_recarried", Some("cells")),
        deletions: c.metric("claims_recarried", Some("deletions")),
        answers: c.metric("claims_recarried", Some("answers")),
        local: c.metric("claims_recarried", Some("local")),
    };
    let blocks = c.metric_count("state_claims_weight", None);
    let per_block = |count: u64| {
        let exact = |count: u64| f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        if blocks == 0 {
            0.0
        } else {
            exact(count) / exact(blocks)
        }
    };
    println!(
        "{scenario} [claims a committed block carried that one of the four below it carried, \
         summed over replicas and shards, over {blocks} commits]: cells {} ({:.2} a block), \
         deletions {} ({:.2} a block), answers {} ({:.2} a block), local crossings {} ({:.2} \
         a block)",
        recarried.cells,
        per_block(recarried.cells),
        recarried.deletions,
        per_block(recarried.deletions),
        recarried.answers,
        per_block(recarried.answers),
        recarried.local,
        per_block(recarried.local),
    );
    assert_eq!(
        (recarried.cells, recarried.deletions),
        (0, 0),
        "{scenario}: no committed block carries a cell or a deletion the chain below it carried",
    );
    recarried
}

/// Report what the run's crossings cost: the record presences `c`'s
/// replicas carried and the read frontier refused, the boundary claims
/// its blocks carried to delete answers, and the weight of the claims
/// each committed block carried: the claims that are not verdict claims
/// against their budget, and the verdict claims against the section's,
/// of which they spend what the others leave.
pub fn report_crossing_measures(c: &impl FaultableCluster, scenario: &str) {
    println!(
        "{scenario}: claims carrying a record presence: carried {}, refused below the read \
         frontier {}",
        c.metric("fenced_claims_carried", Some("record")),
        c.metric("fenced_claims_refused", Some("record")),
    );
    println!(
        "{scenario}: boundary claims carrying a deletion {}, reading {} answer deletions in \
         {} bytes; cells asked at boundaries {}",
        c.metric("fenced_claims_carried", Some("removed")),
        c.metric("boundary_deletions_carried", None),
        c.metric("boundary_claim_bytes", None),
        c.metric("boundary_cells_asked", None),
    );
    let blocks = c.metric_count("state_claims_weight", None);
    for (metric, kind, budget) in [
        (
            "state_claims_weight",
            "other claims",
            MAX_STATE_CLAIMS_BYTES,
        ),
        (
            "verdict_claims_block_weight",
            "verdict claims",
            MAX_CLAIMS_BYTES,
        ),
    ] {
        let carrying = |q| c.metric_quantile_above(metric, None, q, 0.0).unwrap_or(0.0);
        println!(
            "{scenario}: {kind} weight against {budget} over the blocks carrying them of \
             {blocks} committed: p99 {:.0}, max {:.0} bytes",
            carrying(0.99),
            carrying(1.0),
        );
    }
    // Counters sum over replicas and shards, so each is read against
    // the core members settled, summed the same way.
    let settled = c.metric("core_members_settled", None);
    let per_member = |count: u64| {
        let exact = |count: u64| f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        if settled == 0 {
            0.0
        } else {
            exact(count) / exact(settled)
        }
    };
    let cells_named = c.metric("verdict_cells_named", None);
    let cells = c.metric("verdict_cells_carried", None);
    let cells_changed = c.metric("verdict_cells_changed", None);
    println!(
        "{scenario}: verdict cells in claims naming a member {cells_named}, \
         verdict_cells_carried to a hearing row {cells}, of which {cells_changed} changed an \
         entry, over {settled} core members settled: {:.2}, {:.2} and {:.2} a member",
        per_member(cells_named),
        per_member(cells),
        per_member(cells_changed),
    );
    let weight_named = c.metric("verdict_claims_weight_named", None);
    let weight = c.metric("verdict_claims_weight", None);
    let weight_changed = c.metric("verdict_claims_weight_changed", None);
    println!(
        "{scenario}: bytes of the claims naming a member {weight_named}, verdict_claims_weight \
         carried to a hearing row {weight}, of which {weight_changed} changed an entry: {:.0}, \
         {:.0} and {:.0} bytes a member",
        per_member(weight_named),
        per_member(weight),
        per_member(weight_changed),
    );
    let heard = c.metric_count("blocks_from_stated_to_heard", None);
    let waited = |q| {
        c.metric_quantile_above("blocks_from_stated_to_heard", None, q, f64::NEG_INFINITY)
            .unwrap_or(0.0)
    };
    println!(
        "{scenario}: blocks_from_stated_to_heard over {heard} rows that heard every sibling: \
         p50 {:.0}, p99 {:.0}, max {:.0}",
        waited(0.5),
        waited(0.99),
        waited(1.0),
    );
    report_accepted_measures(c, scenario);
}

/// Report what the run's accepted rows show: how many stood toward one
/// sibling at a commit, waiting for an end line.
pub fn report_accepted_measures(c: &impl FaultableCluster, scenario: &str) {
    let standing = |q| {
        c.metric_quantile_above("accepted_rows_toward_a_sibling", None, q, f64::NEG_INFINITY)
            .unwrap_or(0.0)
    };
    println!(
        "{scenario}: accepted_rows_toward_a_sibling at each commit: p50 {:.0}, p99 {:.0}, \
         max {:.0}",
        standing(0.5),
        standing(0.99),
        standing(1.0),
    );
}
