//! Who on the host wants each beacon fetch, and the fetches the beacon
//! loop drives for them.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_core::BeaconFetchIds;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    Address, BeaconBlockHash, BlockHash, BlockHeight, Epoch, Hash, LeafIndex, MessageClass,
    ShardId, TopologySnapshot, ValidatorId, ValidatorStatus,
};
use tracing::warn;

use super::BeaconLoop;
use super::records::{InstanceRecordBinding, PackageArtifactBinding};
use crate::beacon::{
    self, BeaconCandidateBinding, BeaconFetchState, BeaconProposalBinding, ShardWitnessBinding,
};
use crate::event::{BeaconOwner, TimerOwner};
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Release};

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Ask for `ids` on `owner`'s behalf, of the committee
    /// [`Asked::ROUTE`] picks.
    pub(super) fn ask(
        &mut self,
        owner: BeaconOwner,
        ids: BeaconFetchIds,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        self.visit_ids(
            ids,
            &mut Ask {
                owner,
                shard,
                preferred,
                class,
            },
        );
    }

    pub(super) fn ask_for<B: Asked>(
        &mut self,
        owner: BeaconOwner,
        ids: Vec<B::Id>,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        let askers = B::askers(&mut self.interest);
        for id in &ids {
            askers.entry(id.clone()).or_default().insert(owner);
        }
        self.drive_fetch::<B>(FetchInput::Request {
            ids,
            shard,
            preferred,
            class,
        });
    }

    /// `owner` no longer wants `ids`. An id another owner still asks for
    /// stays in flight.
    pub(super) fn abandon(&mut self, owner: BeaconOwner, ids: BeaconFetchIds) {
        self.visit_ids(ids, &mut Abandon(owner));
    }

    pub(super) fn abandon_for<B: Asked>(&mut self, owner: BeaconOwner, ids: Vec<B::Id>) {
        let askers = B::askers(&mut self.interest);
        let released: Vec<B::Id> = ids
            .into_iter()
            .filter(|id| {
                let Some(owners) = askers.get_mut(id) else {
                    return true;
                };
                owners.remove(&owner);
                let unwanted = owners.is_empty();
                if unwanted {
                    askers.remove(id);
                }
                unwanted
            })
            .collect();
        if !released.is_empty() {
            self.drive_fetch::<B>(FetchInput::Abandoned { ids: released });
        }
    }

    /// Drop every interest `owner` holds in `B`'s ids.
    pub(super) fn forget<B: Asked>(&mut self, owner: BeaconOwner) {
        let held: Vec<B::Id> = B::askers(&mut self.interest)
            .iter()
            .filter(|(_, owners)| owners.contains(&owner))
            .map(|(id, _)| id.clone())
            .collect();
        self.abandon_for::<B>(owner, held);
    }

    /// A response boundary released `ids`.
    pub(super) fn release(&mut self, ids: BeaconFetchIds, how: Release) {
        self.visit_ids(ids, &mut Let(how));
    }

    /// The loop's fetch tick: every fetch retries what its backoff lets go.
    pub(super) fn tick_fetches(&mut self) {
        self.visit_each(&mut Tick);
    }

    /// Whether any beacon fetch has work outstanding, in flight or queued.
    pub(super) fn fetches_pending(&mut self) -> bool {
        let mut pending = Pending(false);
        self.visit_each(&mut pending);
        pending.0
    }

    /// Hand `ids` to `visitor` under the binding whose arm carries them:
    /// the one place a [`BeaconFetchIds`] arm meets its binding.
    fn visit_ids(&mut self, ids: BeaconFetchIds, visitor: &mut impl FetchVisitor<S, N, D>) {
        match ids {
            BeaconFetchIds::Witnesses(ids) => visitor.visit::<ShardWitnessBinding>(self, ids),
            BeaconFetchIds::Proposals(ids) => visitor.visit::<BeaconProposalBinding>(self, ids),
            BeaconFetchIds::Candidates(ids) => visitor.visit::<BeaconCandidateBinding>(self, ids),
            BeaconFetchIds::InstanceRecords(ids) => {
                visitor.visit::<InstanceRecordBinding>(self, ids);
            }
            BeaconFetchIds::PackageArtifacts(ids) => {
                visitor.visit::<PackageArtifactBinding>(self, ids);
            }
        }
    }

    /// Hand every binding to `visitor`, with no ids.
    fn visit_each(&mut self, visitor: &mut impl FetchVisitor<S, N, D>) {
        visitor.visit::<ShardWitnessBinding>(self, Vec::new());
        visitor.visit::<BeaconProposalBinding>(self, Vec::new());
        visitor.visit::<BeaconCandidateBinding>(self, Vec::new());
        visitor.visit::<InstanceRecordBinding>(self, Vec::new());
        visitor.visit::<PackageArtifactBinding>(self, Vec::new());
    }

    fn release_for<B: Asked>(&mut self, ids: Vec<B::Id>, how: Release) {
        if how == Release::Admitted {
            let askers = B::askers(&mut self.interest);
            for id in &ids {
                askers.remove(id);
            }
        }
        self.drive_fetch::<B>(how.input(ids));
    }

    /// Feed `B`'s fetch an input and send what it emits.
    pub(super) fn drive_fetch<B: FetchedBy<BeaconFetchState>>(&mut self, input: FetchInput<B::Id>) {
        let outputs = B::fetch_mut(&mut self.fetches).handle(input);
        let network = &*self.process.network;
        for FetchOutput::Send { ids, route } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(vec![id], route, network, &self.reply);
                }
            } else {
                B::dispatch_chunk(ids, route, network, &self.reply);
            }
        }
    }

    /// Keep the loop's one fetch tick armed exactly while its fetches or
    /// its catch-up sync have work pending, or a submission waits to be
    /// swept at its window's end.
    pub(super) fn update_fetch_tick_timer(&mut self) {
        let pending = self.fetches_pending()
            || beacon::has_pending(&self.beacon_block)
            || !self.submissions.is_empty();
        if let Some(op) = self
            .fetch_tick
            .refresh(TimerOwner::Beacon, self.now, pending)
        {
            self.pending_timer_ops.push(op);
        }
    }

    /// The shard a participant's ask goes to: the shard of the member it
    /// prefers, whose committee holds that member, or a live leaf by
    /// [`Self::fetch_shard`] spread by the asker when the member sits on
    /// no live shard with a committee.
    fn ask_shard(&self, owner: BeaconOwner, preferred: Option<ValidatorId>) -> Option<ShardId> {
        let topology = self.process.topology_snapshot.load();
        let asker = match owner {
            BeaconOwner::Participant(attachment) => attachment.validator.inner(),
            BeaconOwner::Fold | BeaconOwner::Chain(_) | BeaconOwner::Submissions => 0,
        };
        preferred
            .and_then(
                |member| match self.fold.state().validators.get(&member)?.status {
                    ValidatorStatus::OnShard { shard, .. } => Some(shard),
                    _ => None,
                },
            )
            .filter(|&shard| answers(&topology, shard))
            .or_else(|| self.fetch_shard(asker))
    }

    /// Pick a shard whose committee a beacon ask goes to. Every shard
    /// member holds the beacon chain, so any live leaf with a committee
    /// answers; spreading by `spread` keeps a host's asks from all
    /// hammering one committee.
    pub(super) fn fetch_shard(&self, spread: u64) -> Option<ShardId> {
        let topology = self.process.topology_snapshot.load();
        let leaves: Vec<ShardId> = topology
            .shard_trie()
            .leaves()
            .filter(|&leaf| answers(&topology, leaf))
            .collect();
        if leaves.is_empty() {
            return None;
        }
        let idx = usize::try_from(spread % leaves.len() as u64)
            .expect("modulo of leaves.len() fits usize");
        Some(leaves[idx])
    }
}

/// Drop a record or artifact fetch the fold or a participant named; see
/// [`AskRoute::ChainsOnly`].
fn warn_record_fetch(owner: BeaconOwner) {
    warn!(
        ?owner,
        "BeaconLoop: a record fetch from a beacon owner — dropping"
    );
}

/// Whether a beacon ask over `shard` reaches anyone: a live leaf with a
/// committee.
fn answers(topology: &TopologySnapshot, shard: ShardId) -> bool {
    topology.shard_trie().contains(shard) && !topology.committee_for_shard(shard).is_empty()
}

/// Who still wants each id of one fetch. An id is released only when the
/// last owner asking for it abandons it.
pub(super) type Askers<Id> = BTreeMap<Id, BTreeSet<BeaconOwner>>;

/// The owners asking each id the loop fetches. The entry's route,
/// in-flight slot, failure count and tick hold stay one per id in
/// [`BeaconFetchState`], shared by every owner that wants it.
#[derive(Default)]
pub(super) struct Interest {
    pub(super) witnesses: Askers<(ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex)>,
    proposals: Askers<(Epoch, ValidatorId)>,
    candidates: Askers<(Epoch, BeaconBlockHash)>,
    pub(super) records: Askers<Address>,
    pub(super) packages: Askers<Hash>,
}

/// A beacon fetch the loop drives on behalf of several owners.
pub(super) trait Asked: FetchedBy<BeaconFetchState> {
    /// Whose committee an ask for this binding's ids goes to.
    const ROUTE: AskRoute;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id>;
}

/// Whose committee a beacon fetch asks.
pub(super) enum AskRoute {
    /// The shard the ask names: a witness run's source shard.
    Named,
    /// The shard of the member the ask prefers, or a live leaf with a
    /// committee when it sits on none.
    Preferred,
    /// None from the fold or a participant: a record or artifact is
    /// wanted only by a chain's loop, through
    /// [`BeaconInput::RecordsWanted`](crate::event::BeaconInput::RecordsWanted),
    /// which tells it when each arrives.
    ChainsOnly,
}

/// What the loop does to one beacon fetch, whichever binding it is.
trait FetchVisitor<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, ids: Vec<B::Id>);
}

/// An owner's ask.
struct Ask {
    owner: BeaconOwner,
    shard: ShardId,
    preferred: Option<ValidatorId>,
    class: Option<MessageClass>,
}

impl<S: ShardStorage, N: Network, D: Dispatch> FetchVisitor<S, N, D> for Ask {
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, ids: Vec<B::Id>) {
        let shard = match B::ROUTE {
            AskRoute::Named => self.shard,
            AskRoute::Preferred => {
                let Some(shard) = beacon.ask_shard(self.owner, self.preferred) else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                    return;
                };
                shard
            }
            AskRoute::ChainsOnly => return warn_record_fetch(self.owner),
        };
        beacon.ask_for::<B>(self.owner, ids, shard, self.preferred, self.class);
    }
}

/// An owner's abandon.
struct Abandon(BeaconOwner);

impl<S: ShardStorage, N: Network, D: Dispatch> FetchVisitor<S, N, D> for Abandon {
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, ids: Vec<B::Id>) {
        match B::ROUTE {
            AskRoute::ChainsOnly => warn_record_fetch(self.0),
            AskRoute::Named | AskRoute::Preferred => beacon.abandon_for::<B>(self.0, ids),
        }
    }
}

/// A response boundary's release.
struct Let(Release);

impl<S: ShardStorage, N: Network, D: Dispatch> FetchVisitor<S, N, D> for Let {
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, ids: Vec<B::Id>) {
        beacon.release_for::<B>(ids, self.0);
    }
}

/// The fetch tick.
struct Tick;

impl<S: ShardStorage, N: Network, D: Dispatch> FetchVisitor<S, N, D> for Tick {
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, _: Vec<B::Id>) {
        beacon.drive_fetch::<B>(FetchInput::Tick);
    }
}

/// Whether any fetch has work outstanding.
struct Pending(bool);

impl<S: ShardStorage, N: Network, D: Dispatch> FetchVisitor<S, N, D> for Pending {
    fn visit<B: Asked>(&mut self, beacon: &mut BeaconLoop<S, N, D>, _: Vec<B::Id>) {
        self.0 |= B::fetch_mut(&mut beacon.fetches).has_pending();
    }
}

impl Asked for ShardWitnessBinding {
    const ROUTE: AskRoute = AskRoute::Named;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.witnesses
    }
}

impl Asked for BeaconProposalBinding {
    const ROUTE: AskRoute = AskRoute::Preferred;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.proposals
    }
}

impl Asked for BeaconCandidateBinding {
    const ROUTE: AskRoute = AskRoute::Preferred;

    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.candidates
    }
}
