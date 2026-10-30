//! What a host starting on the disk it left behind runs.
//!
//! Participation is a projection of the committed beacon state, and a
//! store is only as good as the chain it holds: a validator placed
//! `OnShard` resumes its shard's loop when the store there committed past
//! genesis on that shard's own chain, and is otherwise the join's to seat.
//! A running host keeps a validator seated on a live shard for as long as
//! routing names it there, since the chain may still need its signature to
//! cross out of the window it is in; a restart resumes that seat from the
//! store as well. A shard this host ran before a cut is served from its
//! store for as long as a local validator holds a window role on it.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::ops::Deref;
use std::sync::Arc;

use hyperscale_beacon::coordinator::{resumed_schedule, retention_floor};
use hyperscale_storage::{
    BeaconStorage, BoundaryStore, RecoveryAnchor, ShardChainReader, SubstateStore, holds_state,
};
use hyperscale_types::{
    BeaconState, BlockHeight, EpochWindows, LocalTimestamp, NetworkDefinition, RecoveryBinding,
    RecoveryCause, RoutingCommittees, ShardBoundary, ShardId, ShardRecovery, Signer,
    TopologySchedule, TopologySnapshot, ValidatorId, ValidatorStatus,
};
use tracing::info;

/// The `(validator, signer)` pairs attached to one shard's replica.
pub type ShardSigners = Vec<(ValidatorId, Arc<dyn Signer>)>;

/// How a starting host seats the validators it runs.
pub struct SeatPlan<S> {
    /// Shards whose store committed past genesis on their own chain, each
    /// with that open store and the validators it resumes: those placed
    /// there and those routing still names there.
    pub resumed: BTreeMap<ShardId, (S, ShardSigners)>,
    /// Shards a local validator is placed on whose store holds no chain of
    /// its own — fresh, or a split clone no adoption ran over — each with
    /// the validators a join seats there. They follow the beacon until it
    /// does.
    pub joins: BTreeMap<ShardId, ShardSigners>,
    /// Validators the beacon places on no shard.
    pub unplaced: ShardSigners,
}

impl<S> SeatPlan<S> {
    /// Every shard a local validator is placed on, resumed or joining.
    #[must_use]
    pub fn placed_shards(&self) -> BTreeSet<ShardId> {
        self.resumed
            .keys()
            .chain(self.joins.keys())
            .copied()
            .collect()
    }
}

/// The routing committees a host starting now on `beacon_storage` boots
/// on: the schedule a fold resumed over the committed chain holds.
///
/// No shard chain is open yet, so no local frontier holds the schedule's
/// floor.
///
/// # Panics
///
/// Panics if `beacon_storage` holds no committed beacon block — every
/// host commits the genesis pair before it seats anything.
#[must_use]
pub fn boot_routing(
    beacon_storage: &dyn BeaconStorage,
    network: &NetworkDefinition,
    now: LocalTimestamp,
) -> RoutingCommittees {
    let (_, latest) = beacon_storage
        .latest_committed()
        .expect("beacon chain is non-empty after the genesis commit");
    let floor = retention_floor(&latest, None, now);
    resumed_schedule(&beacon_storage.states_since(floor), network).routing_committees()
}

/// Seat `validators` against the committed beacon state `head` and the
/// `routing` the host boots on, opening each store a seat may resume from
/// with `open`.
///
/// A validator resumes on a live shard routing names it on as well as on
/// the one it is placed on, when the store there holds that shard's own
/// chain: a chain lagging the beacon's epoch needs the committee of the
/// window it is in to cross out of it, and a running host keeps that seat
/// until routing drops it. Live is the head's word: a shard it seats a
/// committee on and holds no terminal record for. Routing reaches back
/// across every window the schedule retains, so it still names shards a
/// reshape dissolved; their stores may outlive them on disk, and none is
/// resumed. An observer is never seated, and a shard no local validator
/// is placed on resumes only from a store already on disk (`on_disk`).
///
/// A store whose tip a recovery discarded for good
/// ([`committed_on_discarded_tail`]) resumes no placed validator: they
/// join, and the join wipes it. Nor does one committed past a pending
/// fork's frontier that was not seated at the anchor under that fork
/// ([`unanchored_past_fork_frontier`]): its placed validators join, which
/// wipes it where the fork's band holds its tip.
///
/// A store that is not resumed is dropped before this returns, so its
/// join can open it again.
///
/// # Errors
///
/// Returns the first error `open` does.
pub fn plan_seats<S, E>(
    head: &BeaconState,
    routing: &RoutingCommittees,
    validators: &[(ValidatorId, Arc<dyn Signer>)],
    on_disk: impl Fn(ShardId) -> bool,
    mut open: impl FnMut(ShardId) -> Result<S, E>,
) -> Result<SeatPlan<S>, E>
where
    S: Deref<Target: ShardChainReader + BoundaryStore>,
{
    let mut placed: BTreeMap<ShardId, ShardSigners> = BTreeMap::new();
    let mut unplaced = ShardSigners::new();
    let records = &head.validators;
    for (validator, signer) in validators {
        match records.get(validator).map(|record| record.status) {
            Some(ValidatorStatus::OnShard { shard, .. }) => placed
                .entry(shard)
                .or_default()
                .push((*validator, Arc::clone(signer))),
            _ => unplaced.push((*validator, Arc::clone(signer))),
        }
    }
    let mut routed: BTreeMap<ShardId, ShardSigners> = BTreeMap::new();
    let live = |shard: &ShardId| {
        head.shard_committees.contains_key(shard)
            && head
                .boundaries
                .get(shard)
                .is_none_or(|boundary| boundary.terminal_epoch.is_none())
    };
    for (&shard, members) in routing.iter().filter(|(shard, _)| live(shard)) {
        for (validator, signer) in validators {
            let seatable = match records.get(validator).map(|record| record.status) {
                Some(ValidatorStatus::OnShard { shard: on, .. }) => on != shard,
                Some(ValidatorStatus::Observing { .. }) => false,
                _ => true,
            };
            if seatable && members.contains(validator) {
                routed
                    .entry(shard)
                    .or_default()
                    .push((*validator, Arc::clone(signer)));
            }
        }
    }
    let shards: BTreeSet<ShardId> = placed
        .keys()
        .copied()
        .chain(routed.keys().copied().filter(|&shard| on_disk(shard)))
        .collect();
    let windows = head.chain_config.epoch_windows();
    let mut resumed = BTreeMap::new();
    let mut joins = BTreeMap::new();
    for shard in shards {
        let store = open(shard)?;
        let foreign = store.holds_foreign_chain(shard);
        let mut vnodes = placed.remove(&shard).unwrap_or_default();
        let pending = head.pending_recoveries.get(&shard);
        let discarded = !vnodes.is_empty()
            && committed_on_discarded_tail(
                &*store,
                head.recoveries.get(&shard).map_or(&[], Vec::as_slice),
                pending,
                windows,
            );
        let unanchored =
            !vnodes.is_empty() && unanchored_past_fork_frontier(&*store, shard, pending);
        if store.committed_height() > BlockHeight::GENESIS && !foreign && !discarded && !unanchored
        {
            vnodes.extend(routed.remove(&shard).unwrap_or_default());
            resumed.insert(shard, (store, vnodes));
            continue;
        }
        if vnodes.is_empty() {
            continue;
        }
        if discarded {
            info!(
                ?shard,
                "Seated shard's store committed a tail a recovery discarded; joining it"
            );
        } else if unanchored {
            info!(
                ?shard,
                "Seated shard's store committed past a pending fork's frontier it was not \
                 seated under; joining it"
            );
        } else if foreign {
            info!(
                ?shard,
                "Seated shard's store holds a clone its reshape never adopted; joining it"
            );
        } else {
            info!(
                ?shard,
                "No committed block past genesis for a seated shard; joining it"
            );
        }
        joins.insert(shard, vnodes);
    }
    Ok(SeatPlan {
        resumed,
        joins,
        unplaced,
    })
}

/// Whether `store`'s committed tip is a block a recovery of its shard
/// discarded for good ([`RecoveryBinding::discards`]): one in `history`
/// that has completed, or a `pending` fork.
///
/// A completed recovery's chain has crossed its bridge, and a fork's
/// chain extends no block above the frontier, so neither ever builds on
/// such a tip. Block sync carries a store only along its own chain and a
/// store cannot un-commit, so a seat on it would never move. A pending
/// halt's harvest may yet extend the tail it discards, and its replaced
/// committee's stores hold what the harvest reads, so its band is read as
/// nobody's verdict yet; a superseded recovery shares its successor's
/// frontier and lies inside its band. A tip the fresh committee
/// certified, a coast block included, is certified no earlier than the
/// window before the bridge and never reads as discarded.
fn committed_on_discarded_tail<R: ShardChainReader + ?Sized>(
    store: &R,
    history: &[RecoveryBinding],
    pending: Option<&ShardRecovery>,
    windows: EpochWindows,
) -> bool {
    let pending_fork = pending
        .filter(|recovery| recovery.cause == RecoveryCause::Fork)
        .map(|recovery| RecoveryBinding {
            rotated_at: recovery.rotated_at,
            attested_frontier: recovery.attested_frontier,
            completed: false,
        });
    let height = store.committed_height();
    store.get_certified_header(height).is_some_and(|certified| {
        let at = certified.qc().weighted_timestamp();
        history
            .iter()
            .copied()
            .filter(|binding| binding.completed)
            .chain(pending_fork)
            .any(|binding| binding.discards(windows, height, at))
    })
}

/// Record on `store`, snap-synced at `shard`'s attested anchor under
/// `head`, the shard's pending recovery when a fork caused it
/// ([`BoundaryStore::record_recovery_anchor`]).
///
/// A store seated at the anchor holds nothing above the fork's frontier,
/// and every block it commits above it afterwards passes a fence that
/// knows the fork, so the record is what lets a restart tell such a store
/// from one holding the replaced committee's branch
/// ([`unanchored_past_fork_frontier`]). Call it before the store is
/// seated: until then it holds nothing above the frontier, where the
/// restart does not read the record.
pub fn record_fork_anchor<S: BoundaryStore + ?Sized>(
    store: &S,
    head: &TopologySnapshot,
    shard: ShardId,
) {
    if let Some(anchor) = head
        .pending_recoveries()
        .get(&shard)
        .and_then(|recovery| fork_anchor(shard, recovery))
    {
        store.record_recovery_anchor(anchor);
    }
}

/// The record naming `shard`'s `recovery`, when a fork caused it.
fn fork_anchor(shard: ShardId, recovery: &ShardRecovery) -> Option<RecoveryAnchor> {
    (recovery.cause == RecoveryCause::Fork).then_some(RecoveryAnchor {
        shard,
        rotated_at: recovery.rotated_at,
    })
}

/// Whether `store` committed past the frontier of `shard`'s `pending`
/// fork without having been seated at the anchor under that fork.
///
/// Above the frontier a store may hold the fresh committee's chain or
/// the replaced committee's other branch. The replaced committee's
/// certificates may be dated in the window the recovery rotated in,
/// where the fresh committee certifies too, or later still on a host
/// whose beacon had not folded the fork, so neither a block's height nor
/// its certificate's date tells the two apart. Only a store seated at the anchor under this fork
/// ([`record_fork_anchor`]) is known to hold nothing of the replaced
/// committee's past the frontier; any other is read as on the discarded
/// branch. A record naming another recovery, completed or superseded,
/// says nothing about this one.
fn unanchored_past_fork_frontier<R: ShardChainReader + BoundaryStore + ?Sized>(
    store: &R,
    shard: ShardId,
    pending: Option<&ShardRecovery>,
) -> bool {
    pending.is_some_and(|recovery| {
        fork_anchor(shard, recovery).is_some_and(|anchor| {
            store.committed_height() > recovery.attested_frontier
                && store.recovery_anchor() != Some(anchor)
        })
    })
}

/// Whether a join opening `store` for `shard` starts it over.
#[must_use]
pub fn join_wipes<R: ShardChainReader + BoundaryStore + ?Sized>(
    store: &R,
    shard: ShardId,
    schedule: &TopologySchedule,
) -> bool {
    let pending = schedule.head().pending_recoveries().get(&shard);
    let seated_under_fork = pending
        .and_then(|recovery| fork_anchor(shard, recovery))
        .is_some_and(|anchor| store.recovery_anchor() == Some(anchor));
    !seated_under_fork
        && (store.committed_in_recovery_band(shard, schedule)
            || unanchored_past_fork_frontier(store, shard, pending))
}

/// Why a join opening a shard's store wipes it and joins from nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wipe {
    /// The store holds a reshape's work no adoption finished: a split
    /// child's clone still holding its parent's chain, or state a child
    /// span's import wrote under no chain, which a snap-sync import
    /// refuses to write over.
    Unadopted,
    /// A recovery leaves the store's tip behind: the recovered chain need
    /// not extend it.
    Recovered,
}

/// Whether a join opening `store` for `shard` wipes it first, and why.
///
/// A store seated at the anchor of the fork now pending
/// ([`record_fork_anchor`]) holds nothing of the replaced committee's past
/// the frontier, though the fresh committee's own blocks there sit in the
/// recovery's band. Any other store is a recovery's to wipe when its tip
/// sits in a recovery's band, where the recovered chain need not extend
/// it, or past a pending fork's frontier
/// ([`unanchored_past_fork_frontier`]), where it may hold the replaced
/// committee's branch.
#[must_use]
pub fn join_wipe<R>(store: &R, shard: ShardId, schedule: &TopologySchedule) -> Option<Wipe>
where
    R: ShardChainReader + BoundaryStore + SubstateStore + ?Sized,
{
    if store.holds_foreign_chain(shard)
        || (store.is_fresh() && holds_state(store.jmt_height(), store.state_root()))
    {
        return Some(Wipe::Unadopted);
    }
    let pending = schedule.head().pending_recoveries().get(&shard);
    let seated_under_fork = pending
        .and_then(|recovery| fork_anchor(shard, recovery))
        .is_some_and(|anchor| store.recovery_anchor() == Some(anchor));
    (!seated_under_fork
        && (store.committed_in_recovery_band(shard, schedule)
            || unanchored_past_fork_frontier(store, shard, pending)))
    .then_some(Wipe::Recovered)
}

/// Why a rebuild replaces a shard's store, which decides what the rebuilt
/// store takes from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replaced {
    /// The store holds only the chain the anchor continues: it fell
    /// beneath every peer's chain floor, or was never seated at the anchor
    /// of the fork now pending. The rounds signed on it stay consumed.
    Behind,
    /// The store committed a tail a recovery discarded: past a fork
    /// recovery's attested frontier, or on a tail no recovered chain
    /// extends. The recovered chain leaves the frontier anew, and nothing
    /// signed on the abandoned tail binds it.
    Forked,
}

/// Whether `shard`'s running loop is rebuilt at its attested anchor
/// before it carries the validators `placed` there, and why.
///
/// `store` is the loop's and `head` the committed snapshot read on the
/// epoch grid `windows`. With nothing placed, the loop is left to the
/// teardown. A store on a tail a recovery discarded for good
/// ([`committed_on_discarded_tail`]) is rebuilt as [`Replaced::Forked`]:
/// the loop cannot move. Under a pending fork every placed validator
/// sits on a store seated at the anchor under that fork
/// ([`record_fork_anchor`]), the only kind a restart resumes: an unmarked
/// store past the frontier may hold the replaced committee's branch and
/// is rebuilt as [`Replaced::Forked`]; one at or below it holds only the
/// chain the anchor continues and is rebuilt as [`Replaced::Behind`],
/// keeping its signed rounds.
#[must_use]
pub fn rebuild_due<R: ShardChainReader + BoundaryStore + ?Sized>(
    store: &R,
    shard: ShardId,
    head: &TopologySnapshot,
    windows: EpochWindows,
    placed: &[ValidatorId],
) -> Option<Replaced> {
    if placed.is_empty() {
        return None;
    }
    let pending = head.pending_recoveries().get(&shard);
    if committed_on_discarded_tail(store, head.recoveries(shard), pending, windows) {
        return Some(Replaced::Forked);
    }
    let recovery = pending?;
    let anchor = fork_anchor(shard, recovery)?;
    if store.recovery_anchor() == Some(anchor) {
        return None;
    }
    Some(if store.committed_height() > recovery.attested_frontier {
        Replaced::Forked
    } else {
        Replaced::Behind
    })
}

/// The validators a loop re-seated at `shard`'s attested anchor carries:
/// those `placed` on it, and those it `carried` that a pending recovery
/// of the shard did not replace.
///
/// A replaced member signs nothing on the recovered chain, so a store
/// rebuilt at the anchor holds no seat for it, as [`placed_validators`]
/// reads. When nothing else remains, the loop carries what it did: it
/// keeps a signer for as long as it stays up, and the replaced committee
/// keeps serving while routing retains it.
#[must_use]
pub fn reseated_validators(
    shard: ShardId,
    schedule: &TopologySchedule,
    carried: &[ValidatorId],
    placed: Vec<ValidatorId>,
) -> Vec<ValidatorId> {
    let replaced = schedule
        .head()
        .pending_recoveries()
        .get(&shard)
        .map_or(&[][..], |recovery| recovery.retained.as_slice());
    let mut seats = placed;
    for &validator in carried {
        if !replaced.contains(&validator) && !seats.contains(&validator) {
            seats.push(validator);
        }
    }
    if seats.is_empty() {
        return carried.to_vec();
    }
    seats
}

/// Departed shards whose store is on disk, each with the local
/// validators that still serve from it: every one holding a window role
/// on it.
///
/// A shard the beacon still holds a terminal boundary for is one whose
/// ex-members routing may still name, so its counterparts may still ask
/// them for the settled sets and terminal evidence it left. Seating is a
/// placement question and the answer is no — the chain terminated — but
/// serving is a storage one, and the store is there or it is not. A
/// store no local validator serves from is left closed.
#[must_use]
pub fn departed_to_serve(
    boundaries: &BTreeMap<ShardId, ShardBoundary>,
    placed: &BTreeSet<ShardId>,
    on_disk: impl Fn(ShardId) -> bool,
    topology: &TopologySnapshot,
    routing: &RoutingCommittees,
    validators: &[(ValidatorId, Arc<dyn Signer>)],
) -> Vec<(ShardId, ShardSigners)> {
    departed_shards_on_disk(boundaries, placed, on_disk)
        .into_iter()
        .filter_map(|shard| {
            let serving: ShardSigners = validators
                .iter()
                .filter(|(validator, _)| {
                    holds_window_role(shard, topology, routing, &HashSet::from([*validator]))
                })
                .map(|(validator, signer)| (*validator, Arc::clone(signer)))
                .collect();
            if serving.is_empty() {
                info!(
                    ?shard,
                    "Departed shard's store on disk holds no serving duty here; left closed"
                );
                return None;
            }
            Some((shard, serving))
        })
        .collect()
}

fn departed_shards_on_disk(
    boundaries: &BTreeMap<ShardId, ShardBoundary>,
    placed: &BTreeSet<ShardId>,
    on_disk: impl Fn(ShardId) -> bool,
) -> Vec<ShardId> {
    boundaries
        .iter()
        .filter(|(shard, boundary)| {
            boundary.terminal_epoch.is_some() && !placed.contains(shard) && on_disk(**shard)
        })
        .map(|(shard, _)| *shard)
        .collect()
}

/// Whether a local validator in `host_ids` sits in `shard`'s committed
/// committee in any window role or in its routing committee: the serving
/// obligation a hosted shard's replica keeps it up for.
#[must_use]
pub fn holds_window_role<H: BuildHasher>(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    routing: &RoutingCommittees,
    host_ids: &HashSet<ValidatorId, H>,
) -> bool {
    host_in_committee(shard, topology_snapshot, host_ids)
        || routing
            .get(&shard)
            .is_some_and(|committee| committee.iter().any(|v| host_ids.contains(v)))
}

/// Whether `shard`'s committed committee includes a local validator in any
/// window role — a consensus seat or a split-observer ride.
///
/// The teardown half's membership question: an observer rides the
/// committee for serving, gossip, and ready-signal admission, so a shard
/// it rides stays up.
#[must_use]
pub fn host_in_committee<H: BuildHasher>(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    host_ids: &HashSet<ValidatorId, H>,
) -> bool {
    topology_snapshot
        .committee_for_shard(shard)
        .iter()
        .any(|v| host_ids.contains(v))
}

/// The local validators placed on `shard`: each `is_local` validator
/// holding a consensus seat in the head window's committee or in the
/// newest window's.
///
/// The join half's membership question, read from the seatable view. A
/// split observer riding the committee never reads as a seat: seating it
/// would emit a shard-joiner ready signal that classifies as the cohort's
/// `ReshapeReady` and could fire the split gate before its child store has
/// synced.
///
/// The newest window is the one the beacon has drawn a full window ahead,
/// so a validator it seats joins an epoch before its seat opens and spends
/// that epoch syncing; one the head still seats stays placed until its
/// window closes.
///
/// Under a pending recovery only the members the newest window seats are
/// placed. In the window the recovery is drawn in, the head's committee is
/// the one it replaced, and live work on the shard already binds to the
/// fresh one, so a replaced member signs nothing more on the recovered
/// chain; seated beside a fresh member on a store rebuilt at the attested
/// frontier, it would hold a seat that chain does not have. Its replicas
/// keep serving: routing retains the replaced committee until the recovery
/// completes, and the teardown half reads routing.
#[must_use]
pub fn placed_validators(
    shard: ShardId,
    schedule: &TopologySchedule,
    is_local: impl Fn(ValidatorId) -> bool,
) -> Vec<ValidatorId> {
    let head = schedule.head();
    let newest = schedule.newest_window();
    let recovering = head.pending_recoveries().contains_key(&shard);
    let current = head
        .seatable_committee_for_shard(shard)
        .filter(|validator| !recovering || newest.committee_for_shard(shard).contains(validator));
    let mut placed: Vec<ValidatorId> = Vec::new();
    for validator in current.chain(newest.seatable_committee_for_shard(shard)) {
        if is_local(validator) && !placed.contains(&validator) {
            placed.push(validator);
        }
    }
    placed
}

/// The local validators a reshape seat, or a relinquished seat's join,
/// attaches.
///
/// Each member of `shard`'s seatable committee in `snapshot` that
/// `is_local` holds. A split observer riding the committee is never
/// attached as a signer beside co-hosted real members.
#[must_use]
pub fn seat_validators(
    snapshot: &TopologySnapshot,
    shard: ShardId,
    is_local: impl Fn(ValidatorId) -> bool,
) -> Vec<ValidatorId> {
    snapshot
        .seatable_committee_for_shard(shard)
        .filter(|&validator| is_local(validator))
        .collect()
}

/// Whether a hosted shard has aged out of this host's serving duty: no
/// local validator holds any role in its active committee and none sits
/// in its routing committee (no serve obligation).
///
/// The active-committee guard keeps a shard up through its current window
/// even after a lookahead delta has moved the validator on in the routing
/// view; the routing guard keeps a dissolved shard served for as long as
/// a fetch can still resolve this host among its peers. A reshape
/// predecessor mid-handoff stays up even once it ages out of the routable
/// window: under make-before-break its committee stays seated, serving its
/// terminal, until the successors are live, so they can seed and finalize
/// against it.
#[must_use]
pub fn shard_retired<H: BuildHasher>(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    routing: &RoutingCommittees,
    host_ids: &HashSet<ValidatorId, H>,
) -> bool {
    !holds_window_role(shard, topology_snapshot, routing, host_ids)
        && !topology_snapshot.reshape_handoff_pending(shard)
}

/// The signers attached to a shard that stays up which detach from it.
///
/// Each one [`shard_retired`] retires on its own detaches while another
/// stays attached. The last signer stays with the loop until the shard itself retires,
/// since the host keeps the shard for a validator not attached yet.
#[must_use]
pub fn retired_signers(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    routing: &RoutingCommittees,
    attached: &[ValidatorId],
) -> Vec<ValidatorId> {
    let mut remaining = attached.len();
    attached
        .iter()
        .copied()
        .filter(|&validator| {
            let detach = remaining > 1
                && shard_retired(
                    shard,
                    topology_snapshot,
                    routing,
                    &HashSet::from([validator]),
                );
            if detach {
                remaining -= 1;
            }
            detach
        })
        .collect()
}

/// A change to the seats a host runs, which its runner carries out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeatChange {
    /// Tear the shard's loop down: it has aged out of this host's serving
    /// duty ([`shard_retired`]).
    Retire(ShardId),
    /// Detach the validator from the shard's loop, which stays up
    /// ([`retired_signers`]).
    Detach(ShardId, ValidatorId),
    /// Rebuild a shard's loop at its attested anchor.
    Rebuild {
        /// The shard whose loop is rebuilt.
        shard: ShardId,
        /// The validators seated on the rebuilt store.
        seats: Vec<ValidatorId>,
        /// Why the old store is replaced, which decides what the rebuilt
        /// one takes from it.
        replaced: Replaced,
    },
    /// Attach the validator to the shard's running loop.
    Attach(ShardId, ValidatorId),
    /// Bring the shard up for the validators placed on it.
    Join(ShardId, Vec<ValidatorId>),
}

/// One shard a host runs, as [`reconcile`] reads it.
pub struct HostedView<'a, R: ?Sized> {
    /// The shard the loop runs; each view names a different one.
    pub shard: ShardId,
    /// The loop's store, where the runner holds one.
    pub store: Option<&'a R>,
    /// The validators attached to the loop's replica.
    pub attached: Vec<ValidatorId>,
    /// Validators whose attach to the loop is in flight: attached again by
    /// nothing, and not yet counted among those a retirement keeps.
    pub attaching: Vec<ValidatorId>,
    /// Whether the plan may seat validators on the loop. A loop a rebuild
    /// or a reshape duty is seating still retires, and still detaches its
    /// retired signers, but gains no seat from the plan.
    pub seatable: bool,
}

/// The seat changes that bring the shards a host runs in line with what
/// it committed.
///
/// `schedule` is the committed schedule, `head` the snapshot the host
/// publishes for it, `routing` the committees its network resolves
/// against, and `local` the validators it holds keys for. Placement reads the schedule's windows ([`placed_validators`]); every
/// other question reads `head`.
///
/// The changes come in the order the runner carries them out. Each hosted
/// shard [`shard_retired`] retires is torn down, and every other one
/// detaches its [`retired_signers`]. Each surviving seatable loop then
/// seats the validators [`placed_validators`] places on it
/// ([`seat_running`]), and last each leaf of the head that `joinable`
/// admits and no hosted loop covers is joined for the validators placed
/// on it. A placed validator holds a role in the head's committee or in a
/// window routing retains, so no shard both retires and gains a seat, and
/// no signer both detaches and attaches.
pub fn reconcile<R, H>(
    schedule: &TopologySchedule,
    head: &TopologySnapshot,
    routing: &RoutingCommittees,
    hosted: &[HostedView<'_, R>],
    local: &HashSet<ValidatorId, H>,
    joinable: impl Fn(ShardId) -> bool,
) -> Vec<SeatChange>
where
    R: ShardChainReader + BoundaryStore + ?Sized,
    H: BuildHasher,
{
    let is_local = |validator| local.contains(&validator);
    let mut changes = Vec::new();
    let mut staying = Vec::new();
    for view in hosted {
        if shard_retired(view.shard, head, routing, local) {
            changes.push(SeatChange::Retire(view.shard));
            continue;
        }
        changes.extend(
            retired_signers(view.shard, head, routing, &view.attached)
                .into_iter()
                .map(|validator| SeatChange::Detach(view.shard, validator)),
        );
        staying.push(view);
    }
    for view in staying.into_iter().filter(|view| view.seatable) {
        let placed = placed_validators(view.shard, schedule, is_local);
        changes.extend(seat_running(view, head, schedule.windows(), placed));
    }
    for shard in head.shard_trie().leaves() {
        if hosted.iter().any(|view| view.shard == shard) || !joinable(shard) {
            continue;
        }
        let placed = placed_validators(shard, schedule, is_local);
        if !placed.is_empty() {
            changes.push(SeatChange::Join(shard, placed));
        }
    }
    changes
}

/// The changes that seat `placed` on a running loop, read against the
/// committed `head` on the epoch grid `windows`.
///
/// A loop whose store [`rebuild_due`] says cannot carry them is rebuilt at
/// the attested anchor; otherwise each one the loop neither carries nor is
/// attaching attaches.
#[must_use]
pub fn seat_running<R>(
    view: &HostedView<'_, R>,
    head: &TopologySnapshot,
    windows: EpochWindows,
    placed: Vec<ValidatorId>,
) -> Vec<SeatChange>
where
    R: ShardChainReader + BoundaryStore + ?Sized,
{
    let shard = view.shard;
    if let Some(replaced) = view
        .store
        .and_then(|store| rebuild_due(store, shard, head, windows, &placed))
    {
        return vec![SeatChange::Rebuild {
            shard,
            seats: placed,
            replaced,
        }];
    }
    placed
        .into_iter()
        .filter(|validator| {
            !view.attached.contains(validator) && !view.attaching.contains(validator)
        })
        .map(|validator| SeatChange::Attach(shard, validator))
        .collect()
}

/// The rebuild a running loop of `shard` takes when its store needs a
/// height beneath every serving peer's chain floor, so block sync cannot
/// carry it forward and a snap-sync at the attested anchor must.
///
/// The rebuilt store seats [`reseated_validators`]: every validator in
/// `local` the shard places, and every one the loop `carried` that a
/// pending recovery did not replace. The rounds signed on the old store
/// stay consumed ([`Replaced::Behind`]). `None` where the committed `head`
/// holds no attested anchor to rebuild at.
#[must_use]
pub fn reseat<H: BuildHasher>(
    shard: ShardId,
    schedule: &TopologySchedule,
    head: &TopologySnapshot,
    carried: &[ValidatorId],
    local: &HashSet<ValidatorId, H>,
) -> Option<SeatChange> {
    head.boundary(shard)?;
    let placed = placed_validators(shard, schedule, |validator| local.contains(&validator));
    Some(SeatChange::Rebuild {
        shard,
        seats: reseated_validators(shard, schedule, carried, placed),
        replaced: Replaced::Behind,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_storage::test_helpers::{commit_one, commit_writes_at, make_settled_writes};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{TestCommittee, test_pool};
    use hyperscale_types::{
        BeaconChainConfig, BeaconWitnessLeafCount, BlockHash, DeclaredWork, Epoch, EpochWindows,
        JailReason, RecoveryCause, ReshapeSeat, ShardAnchor, ShardCommittee, ShardRecovery,
        StateRoot, ValidatorInfo, ValidatorRecord, ValidatorSet, WeightedTimestamp,
        shard_prefix_path,
    };

    use super::*;

    fn local(committee: &TestCommittee) -> ShardSigners {
        (0..committee.size())
            .map(|i| (validator(i), committee.signer(i)))
            .collect()
    }

    fn validator(i: usize) -> ValidatorId {
        ValidatorId::new(u64::try_from(i).expect("index fits u64"))
    }

    /// A committed head carrying `committee`'s records under `statuses`,
    /// a committee seated on each of the `live` shards, and `boundaries`.
    fn head(
        committee: &TestCommittee,
        statuses: &[ValidatorStatus],
        live: &[ShardId],
        boundaries: BTreeMap<ShardId, ShardBoundary>,
    ) -> BeaconState {
        let mut head = BeaconState::empty(BeaconChainConfig::default());
        head.validators = records(committee, statuses);
        head.shard_committees = live
            .iter()
            .map(|&shard| (shard, ShardCommittee::default()))
            .collect();
        head.boundaries = boundaries;
        head
    }

    fn records(
        committee: &TestCommittee,
        statuses: &[ValidatorStatus],
    ) -> BTreeMap<ValidatorId, ValidatorRecord> {
        statuses
            .iter()
            .enumerate()
            .map(|(i, status)| {
                let id = validator(i);
                let record = ValidatorRecord {
                    id,
                    pool: test_pool(1),
                    status: *status,
                    registered_at_epoch: Epoch::GENESIS,
                    pubkey: *committee.public_key(i),
                };
                (id, record)
            })
            .collect()
    }

    const fn on(shard: ShardId) -> ValidatorStatus {
        ValidatorStatus::OnShard {
            shard,
            ready: true,
            placed_at_epoch: Epoch::GENESIS,
        }
    }

    fn ids(vnodes: &ShardSigners) -> Vec<ValidatorId> {
        vnodes.iter().map(|(validator, _)| *validator).collect()
    }

    /// A store with a chain of its own resumes; a fresh one and a clone
    /// still holding its parent's chain are joins; an unplaced validator
    /// is neither.
    #[test]
    fn only_a_store_holding_its_own_chain_resumes() {
        let child = ShardId::leaf(1, 0);
        let fresh = ShardId::leaf(1, 1);
        let committee = TestCommittee::new(4, 7);
        let head = head(
            &committee,
            &[
                on(ShardId::ROOT),
                on(child),
                on(fresh),
                ValidatorStatus::Pooled,
            ],
            &[ShardId::ROOT, child, fresh],
            BTreeMap::new(),
        );
        let plan = plan_seats(
            &head,
            &RoutingCommittees::new(),
            &local(&committee),
            |_| true,
            |shard| {
                // Every other store holds one block of the root's chain.
                let store = SimShardStorage::new(shard_prefix_path(shard));
                if shard != fresh {
                    commit_one(&store, 1);
                }
                Ok::<_, Infallible>(Arc::new(store))
            },
        )
        .expect("opening cannot fail");

        assert_eq!(
            plan.resumed.keys().copied().collect::<Vec<_>>(),
            vec![ShardId::ROOT]
        );
        assert_eq!(ids(&plan.resumed[&ShardId::ROOT].1), vec![validator(0)]);
        assert_eq!(
            plan.joins.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([child, fresh]),
            "a clone holding its parent's chain joins like a fresh store",
        );
        assert_eq!(ids(&plan.unplaced), vec![validator(3)]);
        assert_eq!(
            plan.placed_shards(),
            BTreeSet::from([ShardId::ROOT, child, fresh])
        );
    }

    /// The root's store, holding one block of its own chain.
    fn root_store(shard: ShardId) -> Arc<SimShardStorage> {
        let store = SimShardStorage::new(shard_prefix_path(shard));
        commit_one(&store, 1);
        Arc::new(store)
    }

    /// A member jailed off a shard whose chain still signs under the
    /// committee it sat in keeps its seat across a restart, beside the
    /// validator placed there; neither an observer routing names nor a
    /// validator routing does not name is seated.
    #[test]
    fn a_validator_routing_still_names_resumes_beside_the_placed_one() {
        let committee = TestCommittee::new(4, 7);
        let jailed = ValidatorStatus::Jailed {
            since_epoch: Epoch::new(3),
            reason: JailReason::Performance,
        };
        let observing = ValidatorStatus::Observing {
            shard: ShardId::ROOT,
            placed_at_epoch: Epoch::new(3),
        };
        let head = head(
            &committee,
            &[
                on(ShardId::ROOT),
                jailed,
                observing,
                ValidatorStatus::Pooled,
            ],
            &[ShardId::ROOT],
            BTreeMap::new(),
        );
        let routing: RoutingCommittees = BTreeMap::from([(
            ShardId::ROOT,
            vec![validator(0), validator(1), validator(2)],
        )]);
        let plan = plan_seats(
            &head,
            &routing,
            &local(&committee),
            |_| true,
            |shard| Ok::<_, Infallible>(root_store(shard)),
        )
        .expect("opening cannot fail");

        assert_eq!(
            ids(&plan.resumed[&ShardId::ROOT].1),
            vec![validator(0), validator(1)]
        );
    }

    /// A store on disk that routing still names a local validator on
    /// resumes for it alone; a store not on disk, or a shard the beacon
    /// holds terminal, is not resumed this way.
    #[test]
    fn a_routed_store_on_disk_resumes_with_nobody_placed_there() {
        let committee = TestCommittee::new(1, 7);
        let routing: RoutingCommittees = BTreeMap::from([(ShardId::ROOT, vec![validator(0)])]);
        let plan_under = |boundaries: BTreeMap<ShardId, ShardBoundary>, on_disk: bool| {
            plan_seats(
                &head(
                    &committee,
                    &[ValidatorStatus::Pooled],
                    &[ShardId::ROOT],
                    boundaries,
                ),
                &routing,
                &local(&committee),
                |_| on_disk,
                |shard| Ok::<_, Infallible>(root_store(shard)),
            )
            .expect("opening cannot fail")
        };

        let plan = plan_under(BTreeMap::new(), true);
        assert_eq!(ids(&plan.resumed[&ShardId::ROOT].1), vec![validator(0)]);

        for plan in [
            plan_under(BTreeMap::new(), false),
            plan_under(BTreeMap::from([(ShardId::ROOT, boundary(Some(4)))]), true),
        ] {
            assert!(plan.resumed.is_empty());
        }
    }

    /// A shard the head no longer seats a committee on, its terminal record
    /// long dropped, is a reshape predecessor that has dissolved: routing
    /// may still name an ex-member there from a window the schedule
    /// retains, and its store may still sit on disk with its own chain,
    /// but nothing resumes on it.
    #[test]
    fn a_routed_store_on_a_dissolved_shard_is_not_resumed() {
        let dissolved = ShardId::ROOT;
        let committee = TestCommittee::new(1, 7);
        let routing: RoutingCommittees = BTreeMap::from([(dissolved, vec![validator(0)])]);
        let plan = plan_seats(
            &head(
                &committee,
                &[ValidatorStatus::Pooled],
                &[ShardId::leaf(1, 0), ShardId::leaf(1, 1)],
                BTreeMap::new(),
            ),
            &routing,
            &local(&committee),
            |shard| shard == dissolved,
            |shard| Ok::<_, Infallible>(root_store(shard)),
        )
        .expect("opening cannot fail");

        assert!(
            plan.resumed.is_empty(),
            "the dissolved shard is not resumed"
        );
    }

    /// The root's store holding one block of its own chain, certified at
    /// `certified_ms`.
    fn root_store_certified_at(certified_ms: u64) -> Arc<SimShardStorage> {
        let store = SimShardStorage::new(shard_prefix_path(ShardId::ROOT));
        commit_writes_at(
            &store,
            &make_settled_writes(1, 1, vec![1]),
            WeightedTimestamp::from_millis(certified_ms),
        );
        Arc::new(store)
    }

    /// Epochs a thousand milliseconds wide from a zero origin.
    const EPOCH_MS: u64 = 1000;
    const WINDOWS: EpochWindows = EpochWindows::new(0, EPOCH_MS);

    /// A recovery of the root seated at epoch 3 above the genesis
    /// frontier: its bridge is epoch 4, so a block certified in epoch 0
    /// has the shape it discards and one certified in epoch 3, the window
    /// before the bridge, is the fresh committee's.
    const ROTATED_AT: Epoch = Epoch::new(3);
    const DISCARDED_MS: u64 = 500;
    const FRESH_MS: u64 = 3 * EPOCH_MS + 500;

    fn binding(completed: bool) -> RecoveryBinding {
        RecoveryBinding {
            rotated_at: ROTATED_AT,
            attested_frontier: BlockHeight::GENESIS,
            completed,
        }
    }

    fn pending(cause: RecoveryCause, retained: Vec<ValidatorId>) -> ShardRecovery {
        ShardRecovery {
            cause,
            rotated_at: ROTATED_AT,
            retained,
            attested_frontier: BlockHeight::GENESIS,
        }
    }

    /// A restart over the root's store certified at `certified_ms`, with
    /// validator 0 placed on the root, validator 1 pooled and named by
    /// routing, and the root's recovery history `history` beside any
    /// `pending` recovery.
    fn restart_over(
        certified_ms: u64,
        history: Vec<RecoveryBinding>,
        pending: Option<ShardRecovery>,
        placed: bool,
    ) -> SeatPlan<Arc<SimShardStorage>> {
        restart_on(
            &root_store_certified_at(certified_ms),
            history,
            pending,
            placed,
        )
    }

    /// [`restart_over`] the root's `store`.
    fn restart_on(
        store: &Arc<SimShardStorage>,
        history: Vec<RecoveryBinding>,
        pending: Option<ShardRecovery>,
        placed: bool,
    ) -> SeatPlan<Arc<SimShardStorage>> {
        let committee = TestCommittee::new(2, 7);
        let first = if placed {
            on(ShardId::ROOT)
        } else {
            ValidatorStatus::Pooled
        };
        let mut head = head(
            &committee,
            &[first, ValidatorStatus::Pooled],
            &[ShardId::ROOT],
            BTreeMap::new(),
        );
        head.chain_config.genesis_timestamp_ms = 0;
        head.chain_config.epoch_duration_ms = EPOCH_MS;
        head.recoveries = BTreeMap::from([(ShardId::ROOT, history)]);
        head.pending_recoveries = pending
            .map(|recovery| (ShardId::ROOT, recovery))
            .into_iter()
            .collect();
        let routing: RoutingCommittees = BTreeMap::from([(ShardId::ROOT, vec![validator(1)])]);
        plan_seats(
            &head,
            &routing,
            &local(&committee),
            |_| true,
            |_| Ok::<_, Infallible>(Arc::clone(store)),
        )
        .expect("opening cannot fail")
    }

    /// A store whose tip a completed recovery discarded resumes nobody
    /// placed on it: the placed validator joins, which wipes the store,
    /// and the routed one goes with the store.
    #[test]
    fn a_store_on_a_tail_a_completed_recovery_discarded_is_a_join() {
        let plan = restart_over(DISCARDED_MS, vec![binding(true)], None, true);
        assert!(plan.resumed.is_empty());
        assert_eq!(ids(&plan.joins[&ShardId::ROOT]), vec![validator(0)]);
    }

    /// A pending fork extends no block above its frontier the replaced
    /// committee certified, so such a tip is a join too.
    #[test]
    fn a_store_on_a_pending_forks_discarded_branch_is_a_join() {
        let plan = restart_over(
            DISCARDED_MS,
            vec![binding(false)],
            Some(pending(RecoveryCause::Fork, vec![validator(1)])),
            true,
        );
        assert!(plan.resumed.is_empty());
        assert_eq!(ids(&plan.joins[&ShardId::ROOT]), vec![validator(0)]);
    }

    /// Past a pending fork's frontier, a block the fresh committee
    /// certified in the window the recovery rotated in and one of the
    /// replaced committee's other branch read alike, so a store there
    /// resumes only if it was seated at the anchor under that same fork;
    /// one seated under another recovery, or another shard's, is a join.
    #[test]
    fn a_store_past_a_pending_forks_frontier_resumes_only_if_seated_under_it() {
        let restart = |anchor: Option<RecoveryAnchor>| {
            let store = root_store_certified_at(FRESH_MS);
            if let Some(anchor) = anchor {
                store.record_recovery_anchor(anchor);
            }
            restart_on(
                &store,
                vec![binding(false)],
                Some(pending(RecoveryCause::Fork, vec![validator(1)])),
                true,
            )
        };
        let joins = |plan: SeatPlan<Arc<SimShardStorage>>| {
            assert!(plan.resumed.is_empty());
            assert_eq!(ids(&plan.joins[&ShardId::ROOT]), vec![validator(0)]);
        };
        let under = |shard, rotated_at| Some(RecoveryAnchor { shard, rotated_at });

        joins(restart(None));
        joins(restart(under(ShardId::ROOT, Epoch::new(1))));
        joins(restart(under(ShardId::leaf(1, 0), ROTATED_AT)));

        let plan = restart(under(ShardId::ROOT, ROTATED_AT));
        assert!(plan.joins.is_empty());
        assert_eq!(
            ids(&plan.resumed[&ShardId::ROOT].1),
            vec![validator(0), validator(1)]
        );
    }

    /// The stores a pending halt's harvest reads, a superseded recovery's
    /// band, the fresh committee's coast blocks, and a store only routing
    /// names a validator on all resume.
    #[test]
    fn a_store_no_recovery_has_discarded_for_good_resumes() {
        let resumes = |plan: &SeatPlan<Arc<SimShardStorage>>, seated: Vec<ValidatorId>| {
            assert!(plan.joins.is_empty());
            assert_eq!(ids(&plan.resumed[&ShardId::ROOT].1), seated);
        };
        resumes(
            &restart_over(
                DISCARDED_MS,
                vec![binding(false)],
                Some(pending(RecoveryCause::Halt, vec![validator(1)])),
                true,
            ),
            vec![validator(0), validator(1)],
        );
        resumes(
            &restart_over(DISCARDED_MS, vec![binding(false)], None, true),
            vec![validator(0), validator(1)],
        );
        resumes(
            &restart_over(FRESH_MS, vec![binding(true)], None, true),
            vec![validator(0), validator(1)],
        );
        resumes(
            &restart_over(DISCARDED_MS, vec![binding(true)], None, false),
            vec![validator(1)],
        );
    }

    /// A schedule of the root alone seating `committee`, over the
    /// recovery history `history` and any `pending` recovery.
    fn recovering(
        committee: Vec<ValidatorId>,
        history: Vec<RecoveryBinding>,
        pending: Option<ShardRecovery>,
    ) -> TopologySchedule {
        let head = explicit_head(HashMap::from([(ShardId::ROOT, committee)]))
            .with_recoveries(BTreeMap::from([(ShardId::ROOT, history)]))
            .with_pending_recoveries(
                pending
                    .map(|recovery| (ShardId::ROOT, recovery))
                    .into_iter()
                    .collect(),
            );
        TopologySchedule::new(
            EpochWindows::new(0, EPOCH_MS),
            Epoch::new(5),
            Arc::new(head),
        )
    }

    /// A running loop on a tail a completed recovery discarded is rebuilt
    /// as forked. Under a pending fork a loop not seated at its anchor is
    /// rebuilt, as forked past the frontier and as behind at or below it,
    /// while one seated at the anchor is left be; a pending halt's band and
    /// a loop with nobody placed are left be too.
    #[test]
    fn a_running_loop_is_rebuilt_where_its_store_cannot_carry_the_seat() {
        let placed = [HOST];
        let discarded = root_store_certified_at(DISCARDED_MS);
        let fresh = root_store_certified_at(FRESH_MS);
        let at_frontier = SimShardStorage::new(shard_prefix_path(ShardId::ROOT));
        let due = |store: &SimShardStorage, schedule: &TopologySchedule, placed: &[ValidatorId]| {
            rebuild_due(store, ShardId::ROOT, schedule.head(), WINDOWS, placed)
        };

        let completed = recovering(vec![HOST], vec![binding(true)], None);
        assert_eq!(due(&discarded, &completed, &placed), Some(Replaced::Forked));
        assert_eq!(due(&discarded, &completed, &[]), None);
        assert_eq!(due(&fresh, &completed, &placed), None);
        assert_eq!(due(&at_frontier, &completed, &placed), None);

        let fork = recovering(
            vec![HOST],
            vec![binding(false)],
            Some(pending(RecoveryCause::Fork, vec![validator(9)])),
        );
        assert_eq!(due(&fresh, &fork, &placed), Some(Replaced::Forked));
        assert_eq!(due(&discarded, &fork, &placed), Some(Replaced::Forked));
        assert_eq!(due(&at_frontier, &fork, &placed), Some(Replaced::Behind));
        let anchor = RecoveryAnchor {
            shard: ShardId::ROOT,
            rotated_at: ROTATED_AT,
        };
        fresh.record_recovery_anchor(anchor);
        at_frontier.record_recovery_anchor(anchor);
        assert_eq!(due(&fresh, &fork, &placed), None);
        assert_eq!(due(&at_frontier, &fork, &placed), None);

        let halt = recovering(
            vec![HOST],
            vec![binding(false)],
            Some(pending(RecoveryCause::Halt, vec![validator(9)])),
        );
        assert_eq!(due(&discarded, &halt, &placed), None);
        assert_eq!(due(&at_frontier, &halt, &placed), None);
    }

    /// A join starts over a store past a pending fork's frontier unless it
    /// was seated under that fork, and keeps a store no recovery touched.
    #[test]
    fn a_join_starts_over_a_store_a_pending_fork_did_not_seat() {
        let fresh = root_store_certified_at(FRESH_MS);
        let fork = recovering(
            vec![HOST],
            vec![binding(false)],
            Some(pending(RecoveryCause::Fork, vec![validator(9)])),
        );
        assert!(join_wipes(&*fresh, ShardId::ROOT, &fork));
        fresh.record_recovery_anchor(RecoveryAnchor {
            shard: ShardId::ROOT,
            rotated_at: ROTATED_AT,
        });
        assert!(!join_wipes(&*fresh, ShardId::ROOT, &fork));

        let untouched = recovering(vec![HOST], Vec::new(), None);
        assert!(!join_wipes(
            &*root_store_certified_at(FRESH_MS),
            ShardId::ROOT,
            &untouched
        ));
    }

    /// A join wipes a store holding a chain that is not its shard's, and
    /// one a pending fork did not seat past its frontier; it keeps one the
    /// fork seated, and one no recovery touched.
    #[test]
    fn a_join_wipes_an_unadopted_clone_and_a_store_a_recovery_leaves() {
        let child = ShardId::leaf(1, 0);
        let clone = SimShardStorage::new(shard_prefix_path(child));
        commit_one(&clone, 1);
        let untouched = recovering(vec![HOST], Vec::new(), None);
        assert_eq!(join_wipe(&clone, child, &untouched), Some(Wipe::Unadopted));
        assert_eq!(
            join_wipe(
                &*root_store_certified_at(FRESH_MS),
                ShardId::ROOT,
                &untouched
            ),
            None
        );

        let fresh = root_store_certified_at(FRESH_MS);
        let fork = recovering(
            vec![HOST],
            vec![binding(false)],
            Some(pending(RecoveryCause::Fork, vec![validator(9)])),
        );
        assert_eq!(
            join_wipe(&*fresh, ShardId::ROOT, &fork),
            Some(Wipe::Recovered)
        );
        fresh.record_recovery_anchor(RecoveryAnchor {
            shard: ShardId::ROOT,
            rotated_at: ROTATED_AT,
        });
        assert_eq!(join_wipe(&*fresh, ShardId::ROOT, &fork), None);
    }

    /// A view of a hosted shard with no store, carrying `attached`.
    fn view(shard: ShardId, attached: &[ValidatorId]) -> HostedView<'static, SimShardStorage> {
        HostedView {
            shard,
            store: None,
            attached: attached.to_vec(),
            attaching: Vec::new(),
            seatable: true,
        }
    }

    /// Four leaves: `a` seats the host beside another, `b`, `c` and `d`
    /// each seat one validator.
    fn four_leaves() -> (TopologySchedule, [ShardId; 4]) {
        let shards = [
            ShardId::leaf(2, 0),
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
            ShardId::leaf(2, 3),
        ];
        let head = explicit_head(HashMap::from([
            (shards[0], vec![HOST, validator(2)]),
            (shards[1], vec![validator(3)]),
            (shards[2], vec![validator(10)]),
            (shards[3], vec![validator(11)]),
        ]));
        (TopologySchedule::single(Arc::new(head)), shards)
    }

    /// Retirements and detaches come first, then the seats a running loop
    /// gains, then joins of the leaves the runner admits.
    #[test]
    fn a_reconcile_tears_down_before_it_seats() {
        let (schedule, [a, b, c, d]) = four_leaves();
        let routing = schedule.routing_committees();
        let local = HashSet::from([
            HOST,
            validator(6),
            validator(7),
            validator(8),
            validator(10),
            validator(11),
        ]);
        let hosted = [
            view(a, &[validator(6), validator(7)]),
            view(b, &[validator(8)]),
        ];
        assert_eq!(
            reconcile(
                &schedule,
                schedule.head(),
                &routing,
                &hosted,
                &local,
                |shard| shard != d
            ),
            vec![
                SeatChange::Detach(a, validator(6)),
                SeatChange::Retire(b),
                SeatChange::Attach(a, HOST),
                SeatChange::Join(c, vec![validator(10)]),
            ]
        );
    }

    /// A loop the runner holds unseatable still detaches its retired
    /// signers but gains no seat, and a validator already attaching is not
    /// attached again.
    #[test]
    fn a_reconcile_seats_nothing_on_a_loop_it_may_not_seat() {
        let (schedule, [a, ..]) = four_leaves();
        let routing = schedule.routing_committees();
        let local = HashSet::from([HOST, validator(6), validator(7)]);
        let mut busy = view(a, &[validator(6), validator(7)]);
        busy.seatable = false;
        assert_eq!(
            reconcile(
                &schedule,
                schedule.head(),
                &routing,
                &[busy],
                &local,
                |_| false
            ),
            vec![SeatChange::Detach(a, validator(6))]
        );
        let mut attaching = view(a, &[]);
        attaching.attaching = vec![HOST];
        assert!(
            reconcile(
                &schedule,
                schedule.head(),
                &routing,
                &[attaching],
                &local,
                |_| false
            )
            .is_empty()
        );
    }

    /// A running loop on a tail a completed recovery discarded seats its
    /// placed validators on a rebuilt store instead of attaching them.
    #[test]
    fn a_reconcile_rebuilds_a_loop_its_store_cannot_carry() {
        let schedule = recovering(vec![HOST], vec![binding(true)], None);
        let routing = schedule.routing_committees();
        let store = root_store_certified_at(DISCARDED_MS);
        let hosted = [HostedView {
            store: Some(&*store),
            ..view(ShardId::ROOT, &[])
        }];
        assert_eq!(
            reconcile(
                &schedule,
                schedule.head(),
                &routing,
                &hosted,
                &HashSet::from([HOST]),
                |_| { true }
            ),
            vec![SeatChange::Rebuild {
                shard: ShardId::ROOT,
                seats: vec![HOST],
                replaced: Replaced::Forked,
            }]
        );
    }

    /// A re-seat rebuilds behind at the attested anchor, carrying what the
    /// loop carried beside what the shard places; with no anchor it has
    /// nothing to rebuild at.
    #[test]
    fn a_reseat_rebuilds_behind_only_at_an_attested_anchor() {
        let lagging = validator(3);
        let local = HashSet::from([HOST]);
        let unanchored = recovering(vec![HOST], Vec::new(), None);
        assert_eq!(
            reseat(
                ShardId::ROOT,
                &unanchored,
                unanchored.head(),
                &[lagging],
                &local
            ),
            None
        );
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::new(4),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        let anchored = TopologySchedule::new(
            WINDOWS,
            Epoch::new(5),
            Arc::new(
                explicit_head(HashMap::from([(ShardId::ROOT, vec![HOST])]))
                    .with_boundaries(BTreeMap::from([(ShardId::ROOT, anchor)])),
            ),
        );
        assert_eq!(
            reseat(
                ShardId::ROOT,
                &anchored,
                anchored.head(),
                &[lagging],
                &local
            ),
            Some(SeatChange::Rebuild {
                shard: ShardId::ROOT,
                seats: vec![HOST, lagging],
                replaced: Replaced::Behind,
            })
        );
    }

    /// A re-seat drops a carried member a pending recovery replaced unless
    /// it is all the loop has, and keeps every other carried validator.
    #[test]
    fn a_reseat_carries_no_member_a_pending_recovery_replaced() {
        let replaced = validator(2);
        let lagging = validator(3);
        let schedule = recovering(
            vec![HOST],
            vec![binding(false)],
            Some(pending(RecoveryCause::Fork, vec![replaced])),
        );
        assert_eq!(
            reseated_validators(ShardId::ROOT, &schedule, &[replaced, lagging], vec![HOST]),
            vec![HOST, lagging]
        );
        assert_eq!(
            reseated_validators(ShardId::ROOT, &schedule, &[replaced], Vec::new()),
            vec![replaced]
        );
        let settled = recovering(vec![HOST], vec![binding(true)], None);
        assert_eq!(
            reseated_validators(ShardId::ROOT, &settled, &[replaced], vec![HOST]),
            vec![HOST, replaced]
        );
    }

    /// A boundary record that is terminal or live; nothing else here
    /// reads any other field.
    fn boundary(terminal: Option<u64>) -> ShardBoundary {
        ShardBoundary {
            boundary_qc: None,
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            used: DeclaredWork::ZERO,
            blocks: 0,
            cumulative_fees: 0,
            substate_bytes: 0,
            formed: Epoch::GENESIS,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: 0,
            terminal_epoch: terminal.map(Epoch::new),
            handoff_complete: None,
            terminal_delivered: false,
            terminal_settled_txs: None,
            reshape_admitted_epoch: None,
        }
    }

    /// The three terms, each shown to matter: a live shard is not
    /// departed, a placed one is already served, and a shard whose store
    /// this host never kept has nothing to answer with.
    #[test]
    fn a_departed_shard_is_served_where_its_store_is_on_disk() {
        let departed = ShardId::leaf(1, 0);
        let live = ShardId::leaf(1, 1);
        let placed = ShardId::ROOT;
        let elsewhere = ShardId::leaf(2, 3);
        let boundaries = BTreeMap::from([
            (departed, boundary(Some(4))),
            (live, boundary(None)),
            (placed, boundary(Some(4))),
            (elsewhere, boundary(Some(4))),
        ]);

        assert_eq!(
            departed_shards_on_disk(&boundaries, &BTreeSet::from([placed]), |shard| {
                shard != elsewhere
            }),
            vec![departed],
        );
    }

    /// A boundary the beacon has dropped is a shard nobody asks about,
    /// so a store left on disk past the window opens for nothing.
    #[test]
    fn a_shard_the_beacon_no_longer_bounds_is_not_served() {
        assert!(
            departed_shards_on_disk(&BTreeMap::new(), &BTreeSet::new(), |_| true).is_empty(),
            "the retention window is the beacon's to keep"
        );
    }

    /// Only the validators routing still names serve a departed store;
    /// with none, the store stays closed.
    #[test]
    fn a_departed_store_is_served_by_the_validators_routing_names() {
        let departed = ShardId::leaf(1, 0);
        let committee = TestCommittee::new(2, 7);
        let boundaries = BTreeMap::from([(departed, boundary(Some(4)))]);
        let topology = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        );
        let named: RoutingCommittees = BTreeMap::from([(departed, vec![validator(1)])]);
        let serving_under = |routing: &RoutingCommittees| {
            departed_to_serve(
                &boundaries,
                &BTreeSet::new(),
                |_| true,
                &topology,
                routing,
                &local(&committee),
            )
        };

        let served = serving_under(&named);
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].0, departed);
        assert_eq!(ids(&served[0].1), vec![validator(1)]);
        assert!(serving_under(&RoutingCommittees::new()).is_empty());
    }

    const HOST: ValidatorId = ValidatorId::new(1);

    /// A head snapshot carrying `committees` as each shard's active
    /// membership — a complete sibling set so the trie is well-formed.
    fn explicit_head(committees: HashMap<ShardId, Vec<ValidatorId>>) -> TopologySnapshot {
        explicit_head_with_observers(committees, BTreeMap::new())
    }

    /// [`explicit_head`] with pending-split observer cohorts riding the committees.
    fn explicit_head_with_observers(
        committees: HashMap<ShardId, Vec<ValidatorId>>,
        observers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    ) -> TopologySnapshot {
        let ids: BTreeSet<ValidatorId> = committees.values().flatten().copied().collect();
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&validator_id| ValidatorInfo {
                validator_id,
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committees,
            HashMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            observers
                .into_iter()
                .map(|(parent, cohort)| {
                    let seats = cohort
                        .into_iter()
                        .map(|(id, shard)| {
                            (
                                id,
                                ReshapeSeat {
                                    shard,
                                    ready: false,
                                },
                            )
                        })
                        .collect();
                    (parent, seats)
                })
                .collect(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )
    }

    fn routing_of(entries: &[(ShardId, Vec<ValidatorId>)]) -> RoutingCommittees {
        entries.iter().cloned().collect()
    }

    /// A live shard the host rotated off — gone from both its active and
    /// its routing committee — retires.
    #[test]
    fn retires_a_shard_absent_from_active_and_routing() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let others = vec![ValidatorId::new(2), ValidatorId::new(3)];
        let topology_snapshot = explicit_head(HashMap::from([
            (shard, others.clone()),
            (sibling, vec![ValidatorId::new(4)]),
        ]));
        let routing = routing_of(&[(shard, others)]);
        assert!(shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A merge child gone from the head but retained in routing with the
    /// host among its terminal committee stays served — the keeper-fetch
    /// case the fix exists for.
    #[test]
    fn keeps_a_dissolved_shard_the_host_still_routes() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = explicit_head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = routing_of(&[(child, vec![HOST, ValidatorId::new(2)])]);
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The host still sits in the active committee — kept even after the
    /// routing lookahead has moved it on, so the current window is served
    /// to its end.
    #[test]
    fn keeps_a_shard_with_an_active_consensus_role() {
        let shard = ShardId::leaf(1, 0);
        let topology_snapshot = explicit_head(HashMap::from([
            (shard, vec![HOST, ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![ValidatorId::new(4)]),
        ]));
        // The lookahead already moved the host off in routing.
        let routing = routing_of(&[(shard, vec![ValidatorId::new(2), ValidatorId::new(3)])]);
        assert!(!shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A dissolved shard aged out of routing entirely retires — once its
    /// reshape handoff has completed. Here `leaf(2, 2)` merged into `leaf(1, 1)`,
    /// which is now live (advanced past genesis), so the predecessor is free.
    #[test]
    fn retires_a_shard_evicted_from_routing() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = explicit_head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]))
        .with_advanced([ShardId::leaf(1, 1)].into());
        let routing = RoutingCommittees::new();
        assert!(shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A reshape predecessor mid-handoff is held up even once it has aged out of
    /// routing: its successors aren't live yet, so it keeps serving its terminal.
    #[test]
    fn holds_a_reshape_predecessor_until_its_successor_is_live() {
        let child = ShardId::leaf(2, 2);
        // `leaf(2, 2)` merged into `leaf(1, 1)`, which is seated but not yet live.
        let topology_snapshot = explicit_head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = RoutingCommittees::new();
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The join reconcile targets exactly the committed committees a local
    /// validator belongs to; without a pending split the two membership
    /// views agree.
    #[test]
    fn placement_tracks_committed_committee_membership() {
        let mine = ShardId::leaf(1, 0);
        let theirs = ShardId::leaf(1, 1);
        let topology_snapshot = explicit_head(HashMap::from([
            (mine, vec![HOST, ValidatorId::new(2)]),
            (theirs, vec![ValidatorId::new(3)]),
        ]));
        let host_ids = HashSet::from([HOST]);
        let is_local = |v| host_ids.contains(&v);
        let schedule = TopologySchedule::single(Arc::new(topology_snapshot.clone()));
        assert_eq!(placed_validators(mine, &schedule, is_local), vec![HOST]);
        assert!(placed_validators(theirs, &schedule, is_local).is_empty());
        assert!(host_in_committee(mine, &topology_snapshot, &host_ids));
        assert!(!host_in_committee(theirs, &topology_snapshot, &host_ids));
    }

    /// A split-observer ride is a committee role but not a consensus seat:
    /// the join reconcile must not bring the splitting parent up on a host
    /// whose only stake in it is the observer, while a co-hosted real
    /// member still reads as a seat.
    #[test]
    fn an_observer_ride_is_not_a_consensus_seat() {
        let parent = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (child, _) = parent.children();
        let member = ValidatorId::new(2);
        let topology_snapshot = explicit_head_with_observers(
            HashMap::from([
                (parent, vec![member, ValidatorId::new(3), HOST]),
                (sibling, vec![ValidatorId::new(4)]),
            ]),
            BTreeMap::from([(parent, BTreeMap::from([(HOST, child)]))]),
        );

        let schedule = TopologySchedule::single(Arc::new(topology_snapshot.clone()));
        assert!(placed_validators(parent, &schedule, |v| v == HOST).is_empty());
        assert!(host_in_committee(
            parent,
            &topology_snapshot,
            &HashSet::from([HOST])
        ));

        let co_hosting = HashSet::from([HOST, member]);
        assert_eq!(
            placed_validators(parent, &schedule, |v| co_hosting.contains(&v)),
            vec![member]
        );
    }

    /// A reshape seat attaches only the local seatable members: never a
    /// riding observer, even a local one, and never a member another host
    /// holds the key for.
    #[test]
    fn a_reshape_seat_skips_a_riding_observer_and_a_remote_member() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (child, _) = shard.children();
        let member = ValidatorId::new(2);
        let remote = ValidatorId::new(3);
        let topology_snapshot = explicit_head_with_observers(
            HashMap::from([
                (shard, vec![member, remote, HOST]),
                (sibling, vec![ValidatorId::new(4)]),
            ]),
            BTreeMap::from([(shard, BTreeMap::from([(HOST, child)]))]),
        );
        let local = HashSet::from([HOST, member]);
        assert_eq!(
            seat_validators(&topology_snapshot, shard, |v| local.contains(&v)),
            vec![member]
        );
    }

    /// A schedule whose head seats `current` and whose next window, as
    /// the head's fold published it, seats `next`.
    fn drawn_ahead(
        current: HashMap<ShardId, Vec<ValidatorId>>,
        next: HashMap<ShardId, Vec<ValidatorId>>,
        recovery: Option<(ShardId, ShardRecovery)>,
    ) -> TopologySchedule {
        let head = explicit_head(current)
            .with_pending_recoveries(recovery.into_iter().collect::<BTreeMap<_, _>>());
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(3), Arc::new(head));
        schedule.insert_lookahead(Epoch::new(4), Arc::new(explicit_head(next)));
        schedule
    }

    /// A validator the beacon drew a window ahead is placed beside the
    /// one whose seat it takes, so it syncs through the epoch before its
    /// window opens.
    #[test]
    fn a_validator_drawn_a_window_ahead_is_placed_before_its_window_opens() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let leaving = ValidatorId::new(2);
        let drawn = ValidatorId::new(3);
        let schedule = drawn_ahead(
            HashMap::from([(shard, vec![leaving]), (sibling, vec![HOST])]),
            HashMap::from([(shard, vec![drawn]), (sibling, vec![HOST])]),
            None,
        );
        let local = HashSet::from([leaving, drawn]);
        assert_eq!(
            placed_validators(shard, &schedule, |v| local.contains(&v)),
            vec![leaving, drawn]
        );
    }

    /// Under a pending recovery the committee it replaced is not placed,
    /// fork or halt alike, and the fresh committee is placed from the
    /// window the recovery is drawn in.
    #[test]
    fn a_pending_recovery_places_only_the_committee_it_seats() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let replaced = ValidatorId::new(2);
        let fresh = ValidatorId::new(3);
        let local = HashSet::from([replaced, fresh]);
        for cause in [RecoveryCause::Fork, RecoveryCause::Halt] {
            let recovery = ShardRecovery {
                cause,
                rotated_at: Epoch::new(3),
                retained: vec![replaced],
                attested_frontier: BlockHeight::new(10),
            };
            let drawn = drawn_ahead(
                HashMap::from([(shard, vec![replaced]), (sibling, vec![HOST])]),
                HashMap::from([(shard, vec![fresh]), (sibling, vec![HOST])]),
                Some((shard, recovery.clone())),
            );
            assert_eq!(
                placed_validators(shard, &drawn, |v| local.contains(&v)),
                vec![fresh],
                "{cause:?}: only the fresh committee is placed in the window the recovery is drawn in",
            );
            let opened = drawn_ahead(
                HashMap::from([(shard, vec![fresh]), (sibling, vec![HOST])]),
                HashMap::from([(shard, vec![fresh]), (sibling, vec![HOST])]),
                Some((shard, recovery)),
            );
            assert_eq!(
                placed_validators(shard, &opened, |v| local.contains(&v)),
                vec![fresh],
                "{cause:?}: the fresh committee stays placed once its window opens",
            );
        }
    }

    /// The teardown half deliberately reads full membership: a hosted shard
    /// whose only local committee link is an observer ride stays up for the
    /// window even with no routing entry.
    #[test]
    fn keeps_a_shard_the_host_only_observes() {
        let parent = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (child, _) = parent.children();
        let topology_snapshot = explicit_head_with_observers(
            HashMap::from([
                (parent, vec![ValidatorId::new(2), HOST]),
                (sibling, vec![ValidatorId::new(3)]),
            ]),
            BTreeMap::from([(parent, BTreeMap::from([(HOST, child)]))]),
        );
        let routing = RoutingCommittees::new();
        assert!(!shard_retired(
            parent,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// Every attached signer the rule retires detaches except the last,
    /// which stays with the loop until the shard itself retires.
    #[test]
    fn the_last_retired_signer_stays_attached() {
        let shard = ShardId::leaf(1, 0);
        let kept = ValidatorId::new(2);
        let gone = [ValidatorId::new(5), ValidatorId::new(6)];
        let topology_snapshot = explicit_head(HashMap::from([
            (shard, vec![kept, ValidatorId::new(3)]),
            (ShardId::leaf(1, 1), vec![ValidatorId::new(4)]),
        ]));
        let routing = routing_of(&[(shard, vec![kept, ValidatorId::new(3)])]);

        let detached = retired_signers(
            shard,
            &topology_snapshot,
            &routing,
            &[gone[0], kept, gone[1]],
        );
        assert_eq!(detached, gone.to_vec());

        let detached = retired_signers(shard, &topology_snapshot, &routing, &gone);
        assert_eq!(detached, vec![gone[0]]);
    }
}
