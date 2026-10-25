//! What the host's beacon thread observes, kept for an embedder to read.
//!
//! Every certified header a chain loop reports to the beacon thread, its own
//! shard's or a remote one's, is summarised once against the committee that
//! signed it and kept for an hour. Every epoch the fold adopts is kept with
//! what it settled. After each step that changed either, the beacon thread
//! publishes an [`Observation`] on a watch channel.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use hyperscale_types::{
    BeaconState, BlockHash, BlockHeight, CertifiedBlockHeader, Epoch, GenesisConfigHash,
    ProposerTimestamp, Round, ScheduleLookup, ShardId, ShardWitnessPayload, SlotEffects,
    TopologySchedule, ValidatorId, Verified, WeightedTimestamp, missed_proposals_since_prev_commit,
};
use tokio::sync::watch;

/// How far behind a shard's newest header the ring keeps its older ones.
const KEPT_MS: u64 = 60 * 60 * 1000;

/// How many adopted epochs' effects an observation carries: a day of
/// five-minute epochs.
const EFFECTS_KEPT: usize = 288;

/// The channel observations are published on; `None` until the beacon
/// thread's first publish.
pub type Observations = watch::Sender<Option<Arc<Observation>>>;

/// Everything the host's beacon thread has seen, as of one step.
#[derive(Debug)]
pub struct Observation {
    /// The genesis this host's network started from.
    pub genesis: GenesisConfigHash,
    /// The latest committed beacon state.
    pub beacon: Arc<BeaconState>,
    /// The newest certified header kept for each shard. A host that hosts
    /// no shard admits no headers and has none.
    pub tips: BTreeMap<ShardId, HeaderSummary>,
    /// The epochs adopted since the host started, the last day of them,
    /// oldest first, each with what its fold settled: the registrations,
    /// jailings, readies and committee moves the beacon applied. Epochs
    /// adopted before a restart and not adopted again after it are absent.
    pub effects: Arc<VecDeque<(Epoch, Arc<SlotEffects>)>>,
}

/// The bytes each shard's snap-sync import has staged so far, while it
/// runs. A shard's entry appears with its first round and leaves when the
/// import ends, however it ends.
#[derive(Debug, Default)]
pub struct Importing {
    shards: Mutex<BTreeMap<ShardId, u64>>,
}

impl Importing {
    /// Every import in progress, with the bytes it has staged.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<ShardId, u64> {
        self.lock().clone()
    }

    /// The gauge one import of `shard` reports through.
    pub fn gauge(self: &Arc<Self>, shard: ShardId) -> ImportGauge {
        ImportGauge {
            importing: Arc::clone(self),
            shard,
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<ShardId, u64>> {
        self.shards.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One import's report into [`Importing`]; its shard's entry goes when the
/// gauge does.
pub struct ImportGauge {
    importing: Arc<Importing>,
    shard: ShardId,
}

impl ImportGauge {
    pub fn record(&self, staged_bytes: u64) {
        self.importing.lock().insert(self.shard, staged_bytes);
    }
}

impl Drop for ImportGauge {
    fn drop(&mut self) {
        self.importing.lock().remove(&self.shard);
    }
}

/// The beacon thread's half: folds each step's adopted epochs and reported
/// headers in and publishes when anything changed.
pub struct Observer {
    genesis: GenesisConfigHash,
    headers: Arc<HeaderRing>,
    observations: Observations,
    effects: VecDeque<(Epoch, Arc<SlotEffects>)>,
    beacon: Option<Arc<BeaconState>>,
}

impl Observer {
    pub const fn new(
        genesis: GenesisConfigHash,
        headers: Arc<HeaderRing>,
        observations: Observations,
    ) -> Self {
        Self {
            genesis,
            headers,
            observations,
            effects: VecDeque::new(),
            beacon: None,
        }
    }

    /// Take in one step's adopted epochs and reported headers, and publish
    /// if they changed anything, or on the first step.
    pub fn step(
        &mut self,
        adopted: Vec<(Epoch, SlotEffects)>,
        admitted: Vec<Arc<Verified<CertifiedBlockHeader>>>,
        state: &BeaconState,
        schedule: &TopologySchedule,
    ) {
        let first = self.beacon.is_none();
        if adopted.is_empty() && admitted.is_empty() && !first {
            return;
        }
        if first || !adopted.is_empty() {
            self.beacon = Some(Arc::new(state.clone()));
        }
        for (epoch, effects) in adopted {
            self.effects.push_back((epoch, Arc::new(effects)));
        }
        while self.effects.len() > EFFECTS_KEPT {
            self.effects.pop_front();
        }
        self.headers.admit(admitted, schedule);
        let observation = Observation {
            genesis: self.genesis,
            beacon: self
                .beacon
                .clone()
                .unwrap_or_else(|| Arc::new(state.clone())),
            tips: self.headers.tips(),
            effects: Arc::new(self.effects.clone()),
        };
        self.observations.send_replace(Some(Arc::new(observation)));
    }
}

/// One certified header: who proposed it, whose votes its certificate
/// carries, and whose turns failed before it.
///
/// Certified is not committed: a block at a held height can be replaced by
/// the one the chain keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSummary {
    /// The block's height on its shard's chain.
    pub height: BlockHeight,
    /// The certified block; at a held height the kept block is the latest
    /// seen, not necessarily the one the chain commits.
    pub block: BlockHash,
    /// The consensus round the block was certified in.
    pub round: Round,
    /// The proposer's own claim of when it proposed; not BFT-authenticated.
    pub timestamp: ProposerTimestamp,
    /// The validator whose turn produced the block.
    pub proposer: ValidatorId,
    /// The validators whose votes the certificate carries, in committee
    /// order. `None` when the committee that signed is no longer or not yet
    /// retained by this host's schedule.
    pub signers: Option<Vec<ValidatorId>>,
    /// The scheduled proposers of the rounds that failed between this
    /// block's parent and it, oldest first: failed rounds, not jail counts.
    /// `None` when `signers` is.
    pub missed: Option<Vec<ValidatorId>>,
    /// The shard's state size behind this block's parent, as the block
    /// attests it. `None` across a halt recovery's unresolved suffix.
    pub substate_bytes: Option<u64>,
    /// This header's parent-QC timestamp: the anchor its child's committee
    /// resolves by.
    anchor: WeightedTimestamp,
}

/// The last hour of certified headers per shard, keyed by height.
#[derive(Default)]
pub struct HeaderRing {
    shards: Mutex<BTreeMap<ShardId, BTreeMap<BlockHeight, HeaderSummary>>>,
}

impl HeaderRing {
    /// The shard's kept headers from `since` on, oldest first.
    #[must_use]
    pub fn since(&self, shard: ShardId, since: BlockHeight) -> Vec<HeaderSummary> {
        self.lock().get(&shard).map_or_else(Vec::new, |kept| {
            kept.range(since..).map(|(_, s)| s.clone()).collect()
        })
    }

    /// The newest kept header of every shard.
    #[must_use]
    pub fn tips(&self) -> BTreeMap<ShardId, HeaderSummary> {
        self.lock()
            .iter()
            .filter_map(|(shard, kept)| {
                kept.last_key_value()
                    .map(|(_, summary)| (*shard, summary.clone()))
            })
            .collect()
    }

    /// Summarise and keep each reported header. A header already kept for
    /// its block keeps its first summary; a different block at a kept
    /// height replaces it.
    pub fn admit(
        &self,
        headers: Vec<Arc<Verified<CertifiedBlockHeader>>>,
        schedule: &TopologySchedule,
    ) {
        if headers.is_empty() {
            return;
        }
        let mut shards = self.lock();
        for certified in headers {
            let header = certified.header();
            let kept = shards.entry(header.shard_id()).or_default();
            if kept
                .get(&header.height())
                .is_some_and(|summary| summary.block == header.hash())
            {
                continue;
            }
            let parent_anchor = header
                .height()
                .prev()
                .and_then(|height| kept.get(&height))
                .filter(|parent| parent.block == header.parent_block_hash())
                .map(|parent| parent.anchor);
            let summary = summarise(&certified, parent_anchor, schedule);
            let newest = summary.timestamp.as_millis();
            kept.insert(summary.height, summary);
            let floor = newest.saturating_sub(KEPT_MS);
            kept.retain(|_, s| s.timestamp.as_millis() >= floor);
        }
        drop(shards);
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<ShardId, BTreeMap<BlockHeight, HeaderSummary>>> {
        self.shards.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The header's summary, its committee resolved as remote-header
/// verification resolves it.
fn summarise(
    certified: &CertifiedBlockHeader,
    parent_anchor: Option<WeightedTimestamp>,
    schedule: &TopologySchedule,
) -> HeaderSummary {
    let header = certified.header();
    let qc = certified.qc();
    let shard = header.shard_id();
    let anchor = schedule.signing_anchor(shard, header, parent_anchor);
    let committee =
        match schedule.lookup_for_shard_certified_fenced(shard, anchor, qc.weighted_timestamp()) {
            Some((ScheduleLookup::Committee(snapshot), _)) => Some(Arc::clone(snapshot)),
            _ => None,
        };
    let signers = committee.as_ref().map(|snapshot| {
        let members = snapshot.consensus_committee_for_shard(shard);
        qc.signers()
            .set_indices()
            .filter_map(|i| members.get(i).copied())
            .collect()
    });
    let missed = committee.as_ref().map(|snapshot| {
        missed_proposals_since_prev_commit(
            shard,
            header.height(),
            header.parent_qc().round(),
            header.round(),
            snapshot,
        )
        .into_iter()
        .filter_map(|payload| match payload {
            ShardWitnessPayload::MissedProposal { proposer_id, .. } => Some(proposer_id),
            _ => None,
        })
        .collect()
    });
    HeaderSummary {
        height: header.height(),
        block: header.hash(),
        round: header.round(),
        timestamp: header.timestamp(),
        proposer: header.proposer(),
        signers,
        missed,
        substate_bytes: header.load().substate_bytes,
        anchor: header.parent_qc().weighted_timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{TestCommittee, make_live_block, signed_child_block};
    use hyperscale_types::{Block, TopologySnapshot};

    use super::*;

    const ROOT: ShardId = ShardId::ROOT;

    fn setup() -> (TestCommittee, Arc<TopologySnapshot>, TopologySchedule) {
        let committee = TestCommittee::new(4, 7);
        let snapshot = Arc::new(committee.topology_snapshot(1));
        let schedule = TopologySchedule::single(Arc::clone(&snapshot));
        (committee, snapshot, schedule)
    }

    fn parent() -> Block {
        make_live_block(
            ROOT,
            BlockHeight::new(1),
            0,
            ValidatorId::new(0),
            vec![],
            vec![],
        )
    }

    fn child(committee: &TestCommittee, round: Round) -> Block {
        signed_child_block(
            committee,
            &parent(),
            round,
            WeightedTimestamp::from_millis(5),
        )
    }

    fn certified(
        committee: &TestCommittee,
        block: &Block,
        seats: &[usize],
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let qc = committee.sign_qc(block.header(), seats, WeightedTimestamp::from_millis(10));
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            block.header().clone(),
            qc,
        )))
    }

    #[test]
    fn signers_are_the_certificates_seats() {
        let (committee, snapshot, schedule) = setup();
        let members = snapshot.consensus_committee_for_shard(ROOT).to_vec();
        assert_eq!(members.len(), 4, "the committee signs the root shard");
        let ring = HeaderRing::default();
        let block = child(&committee, Round::INITIAL.next());
        ring.admit(vec![certified(&committee, &block, &[0, 2, 3])], &schedule);

        let kept = ring.since(ROOT, BlockHeight::new(0));
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].signers,
            Some(vec![members[0], members[2], members[3]])
        );
        assert_eq!(kept[0].missed, Some(vec![]));
    }

    #[test]
    fn failed_rounds_name_their_scheduled_proposers() {
        let (committee, snapshot, schedule) = setup();
        let ring = HeaderRing::default();
        let block = child(&committee, Round::new(3));
        ring.admit(vec![certified(&committee, &block, &[0, 1, 2])], &schedule);

        let expected = vec![
            snapshot.proposer_for(ROOT, Round::new(1)),
            snapshot.proposer_for(ROOT, Round::new(2)),
        ];
        assert_eq!(
            ring.since(ROOT, BlockHeight::new(0))[0].missed,
            Some(expected)
        );
    }

    #[test]
    fn a_block_seen_twice_keeps_its_first_summary() {
        let (committee, snapshot, schedule) = setup();
        let members = snapshot.consensus_committee_for_shard(ROOT).to_vec();
        let ring = HeaderRing::default();
        let block = child(&committee, Round::INITIAL.next());
        ring.admit(vec![certified(&committee, &block, &[0, 1, 2])], &schedule);
        ring.admit(vec![certified(&committee, &block, &[1, 2, 3])], &schedule);

        let kept = ring.since(ROOT, BlockHeight::new(0));
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].signers,
            Some(vec![members[0], members[1], members[2]])
        );
    }

    #[test]
    fn an_import_leaves_when_its_gauge_goes() {
        let importing = Arc::new(Importing::default());
        let gauge = importing.gauge(ROOT);
        gauge.record(10);
        gauge.record(25);
        assert_eq!(importing.snapshot().get(&ROOT), Some(&25));
        drop(gauge);
        assert!(importing.snapshot().is_empty());
    }

    #[test]
    fn another_block_at_a_held_height_replaces_it() {
        let (committee, _, schedule) = setup();
        let ring = HeaderRing::default();
        let first = child(&committee, Round::INITIAL.next());
        let second = child(&committee, Round::new(2));
        ring.admit(vec![certified(&committee, &first, &[0, 1, 2])], &schedule);
        ring.admit(vec![certified(&committee, &second, &[0, 1, 2])], &schedule);

        let kept = ring.since(ROOT, BlockHeight::new(0));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].block, second.hash());
    }
}
