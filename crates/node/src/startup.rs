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
use hyperscale_storage::{BeaconStorage, ShardChainReader};
use hyperscale_types::{
    BeaconState, BlockHeight, LocalTimestamp, NetworkDefinition, RoutingCommittees, ShardBoundary,
    ShardId, Signer, TopologySnapshot, ValidatorId, ValidatorStatus,
};
use tracing::info;

/// The `(validator, signer)` pairs seated together on one shard.
pub type ShardVnodes = Vec<(ValidatorId, Arc<dyn Signer>)>;

/// How a starting host seats the validators it runs.
pub struct SeatPlan<S> {
    /// Shards whose store committed past genesis on their own chain, each
    /// with that open store and the validators it resumes: those placed
    /// there and those routing still names there.
    pub resumed: BTreeMap<ShardId, (S, ShardVnodes)>,
    /// Shards a local validator is placed on whose store holds no chain of
    /// its own — fresh, or a split clone no adoption ran over — each with
    /// the validators a join seats there. They follow the beacon until it
    /// does.
    pub joins: BTreeMap<ShardId, ShardVnodes>,
    /// Validators the beacon places on no shard.
    pub unplaced: ShardVnodes,
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

    /// The validators that follow the beacon: every one seated nowhere,
    /// unplaced or waiting on a join.
    #[must_use]
    pub fn followers(&self) -> ShardVnodes {
        let seated: BTreeSet<ValidatorId> = self
            .resumed
            .values()
            .flat_map(|(_, vnodes)| vnodes.iter().map(|(validator, _)| *validator))
            .collect();
        let mut followers = ShardVnodes::new();
        for (validator, signer) in self.unplaced.iter().chain(self.joins.values().flatten()) {
            if !seated.contains(validator)
                && !followers
                    .iter()
                    .any(|(following, _)| following == validator)
            {
                followers.push((*validator, Arc::clone(signer)));
            }
        }
        followers
    }
}

/// The routing committees a host starting now on `beacon_storage` boots
/// on: the schedule a beacon follower resumed over the committed chain
/// holds.
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
    S: Deref<Target: ShardChainReader>,
{
    let mut placed: BTreeMap<ShardId, ShardVnodes> = BTreeMap::new();
    let mut unplaced = ShardVnodes::new();
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
    let mut routed: BTreeMap<ShardId, ShardVnodes> = BTreeMap::new();
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
    let mut resumed = BTreeMap::new();
    let mut joins = BTreeMap::new();
    for shard in shards {
        let store = open(shard)?;
        let foreign = store.holds_foreign_chain(shard);
        let mut vnodes = placed.remove(&shard).unwrap_or_default();
        if store.committed_height() > BlockHeight::GENESIS && !foreign {
            vnodes.extend(routed.remove(&shard).unwrap_or_default());
            resumed.insert(shard, (store, vnodes));
            continue;
        }
        if vnodes.is_empty() {
            continue;
        }
        if foreign {
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
) -> Vec<(ShardId, ShardVnodes)> {
    departed_shards_on_disk(boundaries, placed, on_disk)
        .into_iter()
        .filter_map(|shard| {
            let serving: ShardVnodes = validators
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
/// obligation a hosted shard's vnode keeps it up for.
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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use hyperscale_storage::test_helpers::commit_one;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        BeaconChainConfig, BeaconWitnessLeafCount, BlockHash, DeclaredWork, Epoch, JailReason,
        ShardCommittee, StakePoolId, StateRoot, ValidatorRecord, ValidatorSet, WeightedTimestamp,
        shard_prefix_path,
    };

    use super::*;

    fn local(committee: &TestCommittee) -> ShardVnodes {
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
                    pool: StakePoolId::new(1),
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

    fn ids(vnodes: &ShardVnodes) -> Vec<ValidatorId> {
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
    /// validator placed there; an observer routing names is never
    /// seated, and a validator routing does not name follows the beacon.
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
        assert_eq!(ids(&plan.followers()), vec![validator(2), validator(3)]);
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
        assert!(plan.followers().is_empty());

        for plan in [
            plan_under(BTreeMap::new(), false),
            plan_under(BTreeMap::from([(ShardId::ROOT, boundary(Some(4)))]), true),
        ] {
            assert!(plan.resumed.is_empty());
            assert_eq!(ids(&plan.followers()), vec![validator(0)]);
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
        assert_eq!(ids(&plan.followers()), vec![validator(0)]);
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
}
