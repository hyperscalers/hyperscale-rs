//! The supervisor's per-shard seat bookkeeping: which shards run here, which
//! are opening, syncing or registering a seat, parked on their anchor,
//! rebuilding or draining, and the reshape store preps held behind any of
//! them.
//!
//! [`SeatTable`] performs no io. The supervisor spawns, sends and logs; the
//! table answers which transition a command or a completion takes and keeps
//! the maps that record it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crossbeam::channel::Sender;
use hyperscale_node::event::ShardInbox;
use hyperscale_node::reshape::ReshapeRequest;
use hyperscale_node::seating::Replaced;
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{Block, ShardId, ValidatorId};

use super::membership::CompletedBootstrap;
use crate::runner::VnodeConfig;
use crate::shard_thread::{ShardChannels, ShardControl};

/// A seat whose chain is registering with the host's beacon loop: what
/// its loop is built from once the registration comes back.
pub struct Registering {
    pub shard: ShardId,
    pub vnodes: Vec<VnodeConfig>,
    pub storage: Arc<RocksDbShardStorage>,
    pub recovered: RecoveredState,
    pub genesis: Option<Block>,
    pub channels: ShardChannels,
    pub sender: ShardInbox,
}

/// A torn down shard's thread, joined by whichever comes first: its
/// off-loop join or the supervisor's shutdown.
pub type DrainingThread = Arc<Mutex<Option<std::thread::JoinHandle<()>>>>;

/// One hosted shard's runtime: its pinned thread plus the handles the
/// supervisor needs to stop it.
pub struct ShardThread {
    pub join: std::thread::JoinHandle<()>,
    pub shutdown_tx: Sender<()>,
    /// Signer changes into the running loop.
    pub control_tx: Sender<ShardControl>,
    /// Validators whose attach was sent to the loop and not yet reported
    /// back.
    pub queued: Vec<u64>,
    /// The ids of the validators attached to the shard's replica. The
    /// shard tears down when the last leaves, and teardown scrubs their
    /// slots from the validator-keyed RPC state maps.
    pub validator_ids: Vec<u64>,
}

/// A running shard's rebuild at its attested anchor.
enum Rebuild {
    /// The staging store of the numbered rebuild is syncing while the old
    /// loop keeps running.
    Staging(u64),
    /// The staging store verified; the old loop is tearing down, and
    /// these vnodes seat on the staging store once it is renamed into
    /// the shard's directory.
    Swapping(Box<CompletedBootstrap>, Replaced),
}

/// Where a join for a shard goes, decided in this order: a shard opening
/// or syncing a join rejects it, a draining one queues it, a reshape claim
/// supersedes it, a registering seat takes its validators, a running loop
/// seats them, a parked join takes them, and otherwise the shard opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinStep {
    /// The shard is opening or syncing an earlier join.
    Rejected,
    /// The shard is draining; the join replays once its thread joins.
    Queued {
        /// Whether it replaced a join queued earlier.
        replaced: bool,
    },
    /// A reshape duty owns seating the shard.
    Superseded,
    /// The validators seat with the shard's registration in flight.
    Registering,
    /// The shard runs here; its loop seats the validators.
    OnRunning,
    /// The validators wait with the shard's join parked on its anchor.
    Parked,
    /// The shard opens: the caller dispatches its storage open.
    Open,
}

/// How a settled rebuild is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuiltStep {
    /// A teardown or a later rebuild superseded it.
    Superseded,
    /// It failed, or the shard's loop stopped while it synced: nothing to
    /// swap, and the shard rebuilds no more.
    Abandoned,
    /// The caller swaps its staging store in through [`SeatTable::swap`].
    Swap,
}

/// What a leave released.
#[cfg(feature = "test-utils")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaveStep {
    /// The last pending validator of an opening, syncing or registering
    /// seat left; the seat is abandoned.
    Abandoned,
    /// A pending validator left; the seat continues for the rest.
    Continues {
        /// Pending validators left.
        remaining: usize,
    },
    /// A validator left a join parked on its anchor.
    Unparked {
        /// Whether it was the last, abandoning the parked join.
        abandoned: bool,
    },
    /// Nothing pending holds the shard; any running loop handles the leave.
    NotPending,
}

/// A loop taken off the running set: the caller signals its shutdown and
/// joins its thread off the supervisor loop.
pub struct Departing {
    pub shutdown_tx: Sender<()>,
    pub draining: DrainingThread,
    pub validator_ids: Vec<u64>,
}

/// What a finished teardown leaves to replay.
pub struct Drained {
    /// A join that arrived while the shard drained.
    pub queued: Option<Vec<VnodeConfig>>,
    /// A rebuild whose old loop the teardown stopped, ready to swap in.
    pub swap: Option<(Box<CompletedBootstrap>, Replaced)>,
}

/// Every shard-keyed seat record the supervisor holds.
#[derive(Default)]
pub struct SeatTable {
    shards: BTreeMap<ShardId, ShardThread>,
    /// Shards whose join is parked on background work — the off-loop
    /// storage open, an in-flight snap-sync bootstrap, or the beacon
    /// registration — mapped to the validators still pending. Guards against
    /// a second join racing a double import; a leave meanwhile releases its
    /// validator, abandoning the join when none is left.
    bootstrapping: BTreeMap<ShardId, BTreeSet<ValidatorId>>,
    /// Running shards rebuilding at their attested anchor, after a fork
    /// recovery or once block sync can no longer carry the store forward.
    /// A join for one waits for the swap, which seats every placed local
    /// validator.
    rebuilding: BTreeMap<ShardId, Rebuild>,
    /// How many rebuilds have started, numbering each so its completion is
    /// matched to the staging that is still current.
    rebuilds: u64,
    /// Shards whose teardown is parked on the off-loop thread join, each
    /// with its thread's handle until that join takes it. A join arriving
    /// meanwhile queues in `pending_joins`. The handle stays here because
    /// the runtime drops a queued blocking job unrun when it shuts down; the
    /// supervisor's shutdown joins what is left.
    draining: BTreeMap<ShardId, DrainingThread>,
    /// Joins that arrived while their shard was draining, replayed once the
    /// teardown finishes. Dropping them instead would lose the join until
    /// the next reconcile.
    pending_joins: BTreeMap<ShardId, Vec<VnodeConfig>>,
    /// Joins whose fresh store found no attested anchor for a shard that
    /// did not begin at network genesis. Nothing is seated; each is retried
    /// once this host's topology carries the anchor.
    awaiting_anchor: BTreeMap<ShardId, Vec<VnodeConfig>>,
    /// Seats whose chain is registering with the beacon loop, by seat
    /// number. A shard has at most one, and while it does its
    /// `bootstrapping` entry holds the seat's pending validators.
    registering: BTreeMap<u64, Registering>,
    /// How many seats have registered, numbering each so its reply is
    /// matched to the seat that sent it.
    registrations: u64,
    /// Reshape store-prep requests (`OpenStore` / `SeedFromParent`) held while
    /// an ordinary join is still opening the same shard's store directory, or
    /// a torn down loop still holds its store there, keyed by that store
    /// shard. A reshape duty owns its successor's store, but a join that
    /// slipped past the reshape suppression (a lagging topology snapshot) may
    /// already be mid-open, and a draining thread closes its store only once
    /// it joins; holding the prep until then keeps the two off the same
    /// `RocksDB` directory, which the prep wipes and whose exclusive lock
    /// would otherwise fail the second open.
    pending_reshape_prep: BTreeMap<ShardId, ReshapeRequest>,
}

impl SeatTable {
    /// Route a join for `shard` ([`JoinStep`]), recording what the route
    /// keeps: a queued join, validators merged into a registration or a
    /// parked join, or a fresh open's pending validators. `claimed` answers
    /// whether a reshape duty owns seating the shard; it is asked only once
    /// the shard is neither opening nor draining.
    pub fn join(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        claimed: impl FnOnce() -> bool,
    ) -> JoinStep {
        let registering = self.registering.values().any(|r| r.shard == shard);
        if self.bootstrapping.contains_key(&shard) && !registering {
            return JoinStep::Rejected;
        }
        if self.draining.contains_key(&shard) {
            let replaced = self.pending_joins.insert(shard, vnodes.to_vec()).is_some();
            return JoinStep::Queued { replaced };
        }
        if claimed() || self.pending_reshape_prep.contains_key(&shard) {
            return JoinStep::Superseded;
        }
        if let Some(pending) = self.registering.values_mut().find(|r| r.shard == shard) {
            let ids = self.bootstrapping.entry(shard).or_default();
            for vnode in vnodes {
                if ids.insert(vnode.validator_id) {
                    pending.vnodes.push(vnode.clone());
                }
            }
            return JoinStep::Registering;
        }
        if self.shards.contains_key(&shard) {
            return JoinStep::OnRunning;
        }
        if let Some(parked) = self.awaiting_anchor.get_mut(&shard) {
            for vnode in vnodes {
                if !parked.iter().any(|v| v.validator_id == vnode.validator_id) {
                    parked.push(vnode.clone());
                }
            }
            return JoinStep::Parked;
        }
        self.sync(shard, vnodes);
        JoinStep::Open
    }

    /// The validators still pending on `shard`'s join, whose storage open
    /// landed; `None` for a join abandoned meanwhile.
    pub fn opened(&self, shard: ShardId) -> Option<BTreeSet<ValidatorId>> {
        self.bootstrapping.get(&shard).cloned()
    }

    /// Drop `shard`'s pending join.
    pub fn abandon_join(&mut self, shard: ShardId) {
        self.bootstrapping.remove(&shard);
    }

    /// Park `shard`'s join until this host's topology carries its anchor.
    pub fn park(&mut self, shard: ShardId, vnodes: Vec<VnodeConfig>) {
        self.bootstrapping.remove(&shard);
        self.awaiting_anchor.insert(shard, vnodes);
    }

    /// Take every parked join whose anchor `anchored` now finds, in shard
    /// order.
    pub fn unpark(
        &mut self,
        anchored: impl Fn(ShardId) -> bool,
    ) -> Vec<(ShardId, Vec<VnodeConfig>)> {
        let ready: Vec<ShardId> = self
            .awaiting_anchor
            .keys()
            .copied()
            .filter(|&shard| anchored(shard))
            .collect();
        ready
            .into_iter()
            .filter_map(|shard| Some((shard, self.awaiting_anchor.remove(&shard)?)))
            .collect()
    }

    /// Hold `shard` pending on background work for `vnodes`.
    pub fn sync(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        self.bootstrapping
            .insert(shard, vnodes.iter().map(|v| v.validator_id).collect());
    }

    /// Settle `shard`'s sync: the validators still pending, or `None` for
    /// a join abandoned meanwhile.
    pub fn synced(&mut self, shard: ShardId) -> Option<BTreeSet<ValidatorId>> {
        self.bootstrapping.remove(&shard)
    }

    /// Record a seat registering with the beacon loop, superseding any
    /// earlier one for its shard, and number it.
    pub fn register(&mut self, pending: Registering) -> u64 {
        let shard = pending.shard;
        self.registering.retain(|_, earlier| earlier.shard != shard);
        self.sync(shard, &pending.vnodes);
        self.registrations += 1;
        let seat = self.registrations;
        self.registering.insert(seat, pending);
        seat
    }

    /// Settle registration `seat` of `shard`: the seat and its pending
    /// validators, or `None` for a seat superseded or abandoned meanwhile.
    pub fn registered(
        &mut self,
        shard: ShardId,
        seat: u64,
    ) -> Option<(Registering, BTreeSet<ValidatorId>)> {
        let pending = self.registering.remove(&seat)?;
        let ids = self.bootstrapping.remove(&shard)?;
        Some((pending, ids))
    }

    /// Record `shard`'s loop as running.
    pub fn run(&mut self, shard: ShardId, thread: ShardThread) {
        self.shards.insert(shard, thread);
    }

    /// Number a rebuild of `shard` and record it as staging.
    pub fn start_rebuild(&mut self, shard: ShardId) -> u64 {
        self.rebuilds += 1;
        let number = self.rebuilds;
        self.rebuilding.insert(shard, Rebuild::Staging(number));
        number
    }

    /// Settle rebuild `rebuild` of `shard`, which `succeeded` or not.
    pub fn rebuilt(&mut self, shard: ShardId, rebuild: u64, succeeded: bool) -> RebuiltStep {
        if !self.stages(shard, rebuild) {
            return RebuiltStep::Superseded;
        }
        if !succeeded || !self.shards.contains_key(&shard) {
            self.rebuilding.remove(&shard);
            return RebuiltStep::Abandoned;
        }
        RebuiltStep::Swap
    }

    /// Whether rebuild `number` is the one `shard` is staging: a completion of
    /// any other answers a rebuild a teardown or a later rebuild superseded.
    fn stages(&self, shard: ShardId, number: u64) -> bool {
        matches!(self.rebuilding.get(&shard), Some(Rebuild::Staging(current)) if *current == number)
    }

    /// Hold `shard`'s verified staging store for its old loop's teardown.
    pub fn swap(&mut self, shard: ShardId, done: Box<CompletedBootstrap>, replaced: Replaced) {
        self.rebuilding
            .insert(shard, Rebuild::Swapping(done, replaced));
    }

    /// Take `shard`'s loop off the running set and record it draining.
    pub fn tear_down(&mut self, shard: ShardId) -> Option<Departing> {
        let thread = self.shards.remove(&shard)?;
        let draining = Arc::new(Mutex::new(Some(thread.join)));
        self.draining.insert(shard, Arc::clone(&draining));
        Some(Departing {
            shutdown_tx: thread.shutdown_tx,
            draining,
            validator_ids: thread.validator_ids,
        })
    }

    /// Settle `shard`'s drain: the join queued behind it, and the swap its
    /// rebuild holds. A rebuild still staging ends with the loop it staged
    /// beside.
    pub fn torn_down(&mut self, shard: ShardId) -> Drained {
        self.draining.remove(&shard);
        let queued = self.pending_joins.remove(&shard);
        let swap = match self.rebuilding.remove(&shard) {
            Some(Rebuild::Swapping(done, replaced)) => Some((done, replaced)),
            _ => None,
        };
        Drained { queued, swap }
    }

    /// Release `validator`'s pending membership in `shard`.
    #[cfg(feature = "test-utils")]
    pub fn leave(&mut self, shard: ShardId, validator: ValidatorId) -> LeaveStep {
        if let Some(pending) = self.bootstrapping.get_mut(&shard) {
            pending.remove(&validator);
            if !pending.is_empty() {
                return LeaveStep::Continues {
                    remaining: pending.len(),
                };
            }
            self.bootstrapping.remove(&shard);
            // A seat registering releases its store now; its reply,
            // finding no seat, releases the registration.
            self.registering.retain(|_, pending| pending.shard != shard);
            return LeaveStep::Abandoned;
        }
        if let Some(parked) = self.awaiting_anchor.get_mut(&shard) {
            parked.retain(|vnode| vnode.validator_id != validator);
            let abandoned = parked.is_empty();
            if abandoned {
                self.awaiting_anchor.remove(&shard);
            }
            return LeaveStep::Unparked { abandoned };
        }
        LeaveStep::NotPending
    }

    /// Whether `shard` holds no seat here in any phase: not running,
    /// pending, draining, queued behind a drain, or parked on its anchor.
    pub fn vacant(&self, shard: ShardId) -> bool {
        !self.shards.contains_key(&shard)
            && !self.bootstrapping.contains_key(&shard)
            && !self.draining.contains_key(&shard)
            && !self.pending_joins.contains_key(&shard)
            && !self.awaiting_anchor.contains_key(&shard)
    }

    pub fn is_running(&self, shard: ShardId) -> bool {
        self.shards.contains_key(&shard)
    }

    pub fn is_rebuilding(&self, shard: ShardId) -> bool {
        self.rebuilding.contains_key(&shard)
    }

    pub fn is_draining(&self, shard: ShardId) -> bool {
        self.draining.contains_key(&shard)
    }

    pub fn is_bootstrapping(&self, shard: ShardId) -> bool {
        self.bootstrapping.contains_key(&shard)
    }

    /// `shard`'s running loop.
    pub fn thread_mut(&mut self, shard: ShardId) -> Option<&mut ShardThread> {
        self.shards.get_mut(&shard)
    }

    /// Every running shard, in shard order.
    pub fn running(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.shards.keys().copied()
    }

    /// Take every running loop and every draining thread, for shutdown.
    pub fn drain_all(&mut self) -> (BTreeMap<ShardId, ShardThread>, Vec<DrainingThread>) {
        let running = std::mem::take(&mut self.shards);
        let draining = std::mem::take(&mut self.draining).into_values().collect();
        (running, draining)
    }

    /// Whether a join or a teardown still holds `shard`'s store directory:
    /// a join opening or seating it, or a torn down loop whose thread has
    /// not yet joined and closed its store.
    pub fn holds_store_dir(&self, shard: ShardId) -> bool {
        self.bootstrapping.contains_key(&shard) || self.draining.contains_key(&shard)
    }

    /// Hold a reshape store prep for `shard` until its directory is free.
    pub fn hold_prep(&mut self, shard: ShardId, request: ReshapeRequest) {
        self.pending_reshape_prep.insert(shard, request);
    }

    /// The shards whose held prep no join or teardown blocks any more, in
    /// shard order.
    pub fn ready_preps(&self) -> Vec<ShardId> {
        self.pending_reshape_prep
            .keys()
            .copied()
            .filter(|&shard| !self.holds_store_dir(shard))
            .collect()
    }

    /// Take `shard`'s held prep.
    pub fn take_prep(&mut self, shard: ShardId) -> Option<ReshapeRequest> {
        self.pending_reshape_prep.remove(&shard)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crossbeam::channel::unbounded;
    use hyperscale_node::reshape::ReshapeRequest;
    use hyperscale_storage::RecoveredState;
    use hyperscale_storage_rocksdb::RocksDbShardStorage;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{ShardId, ValidatorId, shard_prefix_path};
    use tempfile::TempDir;

    use super::{JoinStep, RebuiltStep, Registering, SeatTable, ShardThread};
    use crate::runner::VnodeConfig;
    use crate::shard_thread::ShardChannels;

    const SHARD: ShardId = ShardId::ROOT;

    fn vnodes(committee: &TestCommittee, ids: &[usize]) -> Vec<VnodeConfig> {
        ids.iter()
            .map(|&i| VnodeConfig {
                validator_id: ValidatorId::new(i as u64),
                local_shard: SHARD,
                signer: committee.signer(i),
            })
            .collect()
    }

    fn thread() -> ShardThread {
        let (shutdown_tx, _) = unbounded();
        let (control_tx, _) = unbounded();
        ShardThread {
            join: std::thread::spawn(|| {}),
            shutdown_tx,
            control_tx,
            queued: Vec::new(),
            validator_ids: vec![0],
        }
    }

    fn registering(dir: &TempDir, vnodes: Vec<VnodeConfig>) -> Registering {
        let storage =
            RocksDbShardStorage::open(dir.path(), shard_prefix_path(SHARD)).expect("open a store");
        let (channels, sender) = ShardChannels::new();
        Registering {
            shard: SHARD,
            vnodes,
            storage: Arc::new(storage),
            recovered: RecoveredState::default(),
            genesis: None,
            channels,
            sender,
        }
    }

    fn ids(table: &SeatTable) -> Vec<u64> {
        table
            .bootstrapping
            .get(&SHARD)
            .into_iter()
            .flatten()
            .map(|id| id.inner())
            .collect()
    }

    /// Each phase a shard can hold routes a join one way, and a phase that
    /// overlaps another takes the earlier route in the guard order.
    #[test]
    fn a_join_routes_by_the_phase_its_shard_holds() {
        let committee = TestCommittee::new(3, 7);
        let first = vnodes(&committee, &[0]);
        let second = vnodes(&committee, &[1]);
        let dir = TempDir::new().expect("tempdir");

        let mut absent = SeatTable::default();
        assert_eq!(absent.join(SHARD, &first, || false), JoinStep::Open);
        assert_eq!(ids(&absent), [0], "an open holds its validators pending");

        // Opening: a second join is rejected, before any reshape claim.
        assert_eq!(absent.join(SHARD, &second, || true), JoinStep::Rejected);
        assert_eq!(ids(&absent), [0]);

        let mut registering_table = SeatTable::default();
        let seat = registering_table.register(registering(&dir, first.clone()));
        assert_eq!(seat, 1);
        assert_eq!(
            registering_table.join(SHARD, &second, || false),
            JoinStep::Registering,
        );
        assert_eq!(ids(&registering_table), [0, 1]);
        assert_eq!(
            registering_table.registering[&seat].vnodes.len(),
            2,
            "the joiner seats with the registration",
        );
        // A registration still yields to a reshape claim.
        assert_eq!(
            registering_table.join(SHARD, &second, || true),
            JoinStep::Superseded,
        );

        let mut draining = SeatTable::default();
        draining.run(SHARD, thread());
        assert!(draining.tear_down(SHARD).is_some());
        assert_eq!(
            draining.join(SHARD, &first, || true),
            JoinStep::Queued { replaced: false },
            "a drain queues before any reshape claim",
        );
        assert_eq!(
            draining.join(SHARD, &second, || false),
            JoinStep::Queued { replaced: true },
        );

        let mut running = SeatTable::default();
        running.run(SHARD, thread());
        assert_eq!(running.join(SHARD, &first, || true), JoinStep::Superseded);
        assert_eq!(running.join(SHARD, &first, || false), JoinStep::OnRunning);

        let mut held = SeatTable::default();
        held.hold_prep(SHARD, ReshapeRequest::OpenStore { shard: SHARD });
        assert_eq!(
            held.join(SHARD, &first, || false),
            JoinStep::Superseded,
            "a held prep claims the shard",
        );
        assert!(held.vacant(SHARD), "the superseded join records nothing");

        let mut parked = SeatTable::default();
        parked.park(SHARD, first.clone());
        assert_eq!(parked.join(SHARD, &second, || false), JoinStep::Parked);
        assert_eq!(parked.join(SHARD, &first, || false), JoinStep::Parked);
        assert_eq!(parked.awaiting_anchor[&SHARD].len(), 2);
        assert_eq!(parked.join(SHARD, &first, || true), JoinStep::Superseded);
    }

    /// A shard is vacant only while it holds no seat in any phase; a
    /// rebuilding shard is still running, and a held prep is no seat.
    #[test]
    fn a_shard_is_vacant_only_in_no_phase() {
        let committee = TestCommittee::new(1, 7);
        let vnodes = vnodes(&committee, &[0]);

        let mut table = SeatTable::default();
        assert!(table.vacant(SHARD));
        table.hold_prep(SHARD, ReshapeRequest::OpenStore { shard: SHARD });
        assert!(table.vacant(SHARD));

        table.sync(SHARD, &vnodes);
        assert!(!table.vacant(SHARD), "pending");
        table.park(SHARD, vnodes.clone());
        assert!(!table.vacant(SHARD), "parked");
        assert_eq!(table.unpark(|_| true).len(), 1);
        assert!(table.vacant(SHARD));

        table.run(SHARD, thread());
        assert!(!table.vacant(SHARD), "running");
        table.tear_down(SHARD).expect("running");
        assert!(!table.vacant(SHARD), "draining");
        assert_eq!(
            table.join(SHARD, &vnodes, || false),
            JoinStep::Queued { replaced: false }
        );
        table.torn_down(SHARD);
        assert!(table.vacant(SHARD));
    }

    /// A teardown moves a loop to draining and holds the store directory
    /// until its thread joins; the drain settles with the join queued behind
    /// it and ends a rebuild still staging.
    #[test]
    fn a_drain_holds_the_directory_and_settles_its_queue() {
        let committee = TestCommittee::new(1, 7);
        let vnodes = vnodes(&committee, &[0]);
        let mut table = SeatTable::default();
        table.run(SHARD, thread());
        let rebuild = table.start_rebuild(SHARD);
        assert!(
            !table.holds_store_dir(SHARD),
            "a running loop holds no prep"
        );

        let departing = table.tear_down(SHARD).expect("running");
        assert_eq!(departing.validator_ids, [0]);
        assert!(table.tear_down(SHARD).is_none(), "torn down once");
        assert!(!table.is_running(SHARD));
        assert!(table.is_draining(SHARD));
        assert!(table.holds_store_dir(SHARD));
        table.hold_prep(SHARD, ReshapeRequest::OpenStore { shard: SHARD });
        assert!(table.ready_preps().is_empty(), "the drain holds the prep");
        table.join(SHARD, &vnodes, || false);

        let drained = table.torn_down(SHARD);
        assert_eq!(drained.queued.map(|queued| queued.len()), Some(1));
        assert!(drained.swap.is_none());
        assert!(!table.is_draining(SHARD));
        assert!(
            !table.is_rebuilding(SHARD),
            "the staging ends with its loop"
        );
        assert_eq!(table.ready_preps(), [SHARD]);
        assert!(table.take_prep(SHARD).is_some());

        table.run(SHARD, thread());
        assert_eq!(
            table.rebuilt(SHARD, rebuild, true),
            RebuiltStep::Superseded,
            "a rebuild of the torn down loop settles nothing",
        );
    }

    /// A rebuild a teardown cleared and a re-seated loop's later rebuild
    /// superseded settles nothing, whichever way it settles; only the
    /// rebuild the shard still stages does.
    #[test]
    fn only_the_rebuild_a_shard_still_stages_settles() {
        let other = ShardId::leaf(1, 0);
        let mut table = SeatTable::default();
        table.run(SHARD, thread());

        let first = table.start_rebuild(SHARD);
        assert!(table.stages(SHARD, first));
        assert!(!table.stages(other, first), "another shard stages nothing");
        let second = table.start_rebuild(SHARD);
        assert_eq!(table.rebuilt(SHARD, first, true), RebuiltStep::Superseded);
        assert_eq!(table.rebuilt(SHARD, second, false), RebuiltStep::Abandoned);
        assert!(!table.is_rebuilding(SHARD));

        let third = table.start_rebuild(SHARD);
        assert_eq!(table.rebuilt(SHARD, third, true), RebuiltStep::Swap);
    }

    /// A registration settles only for the seat that sent it, and only while
    /// its validators are still pending.
    #[test]
    fn only_the_current_seat_settles_its_registration() {
        let committee = TestCommittee::new(2, 7);
        let dir = TempDir::new().expect("tempdir");
        let other_dir = TempDir::new().expect("tempdir");
        let mut table = SeatTable::default();

        let first = table.register(registering(&dir, vnodes(&committee, &[0])));
        let second = table.register(registering(&other_dir, vnodes(&committee, &[1])));
        assert!(table.registered(SHARD, first).is_none(), "superseded seat");
        let (pending, ids) = table.registered(SHARD, second).expect("current seat");
        assert_eq!(pending.vnodes.len(), 1);
        assert_eq!(
            ids.into_iter().map(ValidatorId::inner).collect::<Vec<_>>(),
            [1]
        );
        assert!(table.vacant(SHARD));
    }
}
