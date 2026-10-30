//! Who on the host wants each beacon fetch, and the fetches the beacon
//! loop drives for them.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_core::{BeaconFetchIds, FetchIds};
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
use crate::event::BeaconOwner;
use crate::fetch::{FetchInput, FetchOutput, FetchedBy, Release};
use crate::shard::TimerOwner;

impl<S, N, D> BeaconLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Ask for `ids` on `owner`'s behalf. A witness run goes to its
    /// source shard's committee; a proposal or candidate ask to the
    /// committee of the member it prefers.
    pub(super) fn ask(
        &mut self,
        owner: BeaconOwner,
        ids: FetchIds,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) {
        let FetchIds::Beacon(ids) = ids else {
            warn!(
                ?ids,
                "BeaconLoop: dropping a fetch the beacon loop does not drive"
            );
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => {
                self.ask_for::<ShardWitnessBinding>(owner, ids, shard, preferred, class);
            }
            BeaconFetchIds::Proposals(ids) => {
                if let Some(shard) = self.ask_shard(owner, preferred) {
                    self.ask_for::<BeaconProposalBinding>(owner, ids, shard, preferred, class);
                } else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                }
            }
            BeaconFetchIds::Candidates(ids) => {
                if let Some(shard) = self.ask_shard(owner, preferred) {
                    self.ask_for::<BeaconCandidateBinding>(owner, ids, shard, preferred, class);
                } else {
                    warn!("BeaconLoop: no live shard with a committee to ask; dropping");
                }
            }
            BeaconFetchIds::InstanceRecords(_) | BeaconFetchIds::PackageArtifacts(_) => {
                warn_record_fetch(owner);
            }
        }
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
    pub(super) fn abandon(&mut self, owner: BeaconOwner, ids: FetchIds) {
        let FetchIds::Beacon(ids) = ids else {
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => self.abandon_for::<ShardWitnessBinding>(owner, ids),
            BeaconFetchIds::Proposals(ids) => self.abandon_for::<BeaconProposalBinding>(owner, ids),
            BeaconFetchIds::Candidates(ids) => {
                self.abandon_for::<BeaconCandidateBinding>(owner, ids);
            }
            BeaconFetchIds::InstanceRecords(_) | BeaconFetchIds::PackageArtifacts(_) => {
                warn_record_fetch(owner);
            }
        }
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
    pub(super) fn release(&mut self, ids: FetchIds, how: Release) {
        let FetchIds::Beacon(ids) = ids else {
            return;
        };
        match ids {
            BeaconFetchIds::Witnesses(ids) => self.release_for::<ShardWitnessBinding>(ids, how),
            BeaconFetchIds::Proposals(ids) => self.release_for::<BeaconProposalBinding>(ids, how),
            BeaconFetchIds::Candidates(ids) => {
                self.release_for::<BeaconCandidateBinding>(ids, how);
            }
            BeaconFetchIds::InstanceRecords(ids) => {
                self.release_for::<InstanceRecordBinding>(ids, how);
            }
            BeaconFetchIds::PackageArtifacts(ids) => {
                self.release_for::<PackageArtifactBinding>(ids, how);
            }
        }
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
        let pending = self.fetches.has_pending()
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

/// A record or artifact is wanted by a chain's loop through
/// [`BeaconInput::RecordsWanted`], which tells it when each arrives; the
/// fold and the participants want none, so a fetch action naming one is
/// dropped.
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
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id>;
}

impl Asked for ShardWitnessBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.witnesses
    }
}

impl Asked for BeaconProposalBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.proposals
    }
}

impl Asked for BeaconCandidateBinding {
    fn askers(interest: &mut Interest) -> &mut Askers<Self::Id> {
        &mut interest.candidates
    }
}
