//! Safety properties checked across every replica of a simulated run.
//!
//! [`Invariants::check`] runs at the end of every
//! [`SimulationRunner::run_until`](super::SimulationRunner::run_until), so
//! every test that drives a runner is checked without opting in. Each check
//! walks only the heights a store committed since the last visit.
//!
//! What must hold:
//! - Replicas of a shard commit the same block at each height. A shard id
//!   names one chain across its whole life — a split child's heights
//!   continue its parent's, and a merged successor's continue its
//!   children's — so `(shard, height)` identifies one committed slot.
//! - Each committed block names the committed block below it as parent.
//! - The weighted timestamp a chain's QCs carry never runs backwards.
//! - A store's JMT root is the root the block at its JMT height commits to.
//! - Hosts that committed the same beacon epoch committed the same block.

use std::collections::BTreeMap;

use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    BeaconBlockHash, BlockHash, BlockHeight, Epoch, ShardId, StateRoot, WeightedTimestamp,
};

use super::SimulationRunner;
use crate::NodeIndex;

/// One committed block as the first replica to commit it recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    hash: BlockHash,
    parent: BlockHash,
    state_root: StateRoot,
    parent_qc_wt: WeightedTimestamp,
    host: NodeIndex,
}

/// Cross-replica safety state for one run.
#[derive(Default)]
pub struct Invariants {
    /// First recorded block per committed slot.
    slots: BTreeMap<(ShardId, BlockHeight), Slot>,
    /// Highest height walked per `(host, shard)` store.
    walked: BTreeMap<(NodeIndex, ShardId), BlockHeight>,
    /// First recorded block per committed beacon epoch.
    beacon: BTreeMap<Epoch, (BeaconBlockHash, NodeIndex)>,
    /// Record conflicting commits instead of panicking, for runs that
    /// drive a shard past its fault bound on purpose.
    forks_permitted: bool,
}

impl Invariants {
    pub const fn permit_forks(&mut self) {
        self.forks_permitted = true;
    }

    /// Walk every store's newly committed heights and every host's latest
    /// beacon block against what the other replicas committed.
    pub fn check(&mut self, runner: &SimulationRunner) {
        for host in 0..runner.num_hosts() {
            for shard in runner.hosted_shards_of(host) {
                if let Some(store) = runner.hosts_shard(host, shard) {
                    self.walk_store(host, shard, store);
                }
            }
            self.check_beacon(runner, host);
        }
        self.prune(runner);
    }

    fn walk_store<S: ShardChainReader + SubstateStore>(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        store: &S,
    ) {
        let committed = store.committed_height();
        let walked = self.walked.entry((host, shard)).or_default();
        // A store replaced under the host (a wipe and re-sync) restarts
        // below where the last one stood; walk it from its own head on.
        if committed < *walked {
            *walked = committed;
        }
        let from = *walked + 1u64;
        *walked = committed;
        let mut height = from;
        while height <= committed {
            if let Some(meta) = store.get_block_metadata(height) {
                let header = meta.header();
                self.record(
                    shard,
                    height,
                    Slot {
                        hash: header.hash(),
                        parent: header.parent_block_hash(),
                        state_root: header.state_root(),
                        parent_qc_wt: header.parent_qc().weighted_timestamp(),
                        host,
                    },
                );
            }
            height += 1u64;
        }
        self.check_jmt_root(host, shard, store);
    }

    fn record(&mut self, shard: ShardId, height: BlockHeight, slot: Slot) {
        match self.slots.get(&(shard, height)) {
            Some(first) if first.hash != slot.hash => {
                assert!(
                    self.forks_permitted,
                    "fork: shard {shard:?} height {height:?} committed as {:?} on host {} \
                     and as {:?} on host {}",
                    first.hash, first.host, slot.hash, slot.host,
                );
            }
            Some(_) => {}
            None => {
                if let Some(below) = height.prev().and_then(|h| self.slots.get(&(shard, h))) {
                    assert!(
                        self.forks_permitted || slot.parent == below.hash,
                        "broken chain: shard {shard:?} height {height:?} on host {} names parent \
                         {:?}, but height {:?} committed {:?}",
                        slot.host,
                        slot.parent,
                        height.prev(),
                        below.hash,
                    );
                    assert!(
                        slot.parent_qc_wt >= below.parent_qc_wt,
                        "time ran backwards: shard {shard:?} height {height:?} carries QC time \
                         {:?} below its parent's {:?}",
                        slot.parent_qc_wt,
                        below.parent_qc_wt,
                    );
                }
                self.slots.insert((shard, height), slot);
            }
        }
    }

    /// A store's JMT root is the root its block at the JMT height names.
    fn check_jmt_root<S: SubstateStore>(&self, host: NodeIndex, shard: ShardId, store: &S) {
        let jmt_height = store.jmt_height();
        let Some(slot) = self.slots.get(&(shard, jmt_height)) else {
            return;
        };
        if self.forks_permitted {
            return;
        }
        let root = store.state_root();
        assert_eq!(
            root, slot.state_root,
            "state divergence: host {host} shard {shard:?} holds JMT root {root:?} at height \
             {jmt_height:?}, but the block committed there names {:?}",
            slot.state_root,
        );
    }

    fn check_beacon(&mut self, runner: &SimulationRunner, host: NodeIndex) {
        let Some((block, _)) = runner
            .beacon_storage(host)
            .and_then(|storage| storage.latest_committed())
        else {
            return;
        };
        let epoch = block.epoch();
        let hash = block.block_hash();
        match self.beacon.get(&epoch) {
            Some(&(first, first_host)) => assert_eq!(
                first, hash,
                "beacon fork: epoch {epoch:?} committed as {first:?} on host {first_host} and as \
                 {hash:?} on host {host}",
            ),
            None => {
                self.beacon.insert(epoch, (hash, host));
            }
        }
    }

    /// Drop slots every live store of their shard has walked past, and
    /// beacon epochs below every host's latest, so the record stays
    /// bounded by the spread between the slowest and fastest replica.
    fn prune(&mut self, runner: &SimulationRunner) {
        let mut floors: BTreeMap<ShardId, BlockHeight> = BTreeMap::new();
        for (&(host, shard), &walked) in &self.walked {
            if runner.hosts_shard(host, shard).is_some() {
                floors
                    .entry(shard)
                    .and_modify(|floor| *floor = (*floor).min(walked))
                    .or_insert(walked);
            }
        }
        // Keep one height below each floor so the next walk can still
        // check parent linkage against it.
        self.slots.retain(|&(shard, height), _| {
            floors
                .get(&shard)
                .is_none_or(|&floor| height + 1u64 >= floor)
        });
        let beacon_floor = (0..runner.num_hosts())
            .filter_map(|host| runner.beacon_storage(host)?.latest_committed_epoch())
            .min();
        if let Some(floor) = beacon_floor {
            self.beacon.retain(|&epoch, _| epoch >= floor);
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Hash;

    use super::*;

    fn hash(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    fn slot(own: &[u8], parent: &[u8], wt: u64, host: NodeIndex) -> Slot {
        Slot {
            hash: hash(own),
            parent: hash(parent),
            state_root: StateRoot::ZERO,
            parent_qc_wt: WeightedTimestamp::from_millis(wt),
            host,
        }
    }

    const SHARD: ShardId = ShardId::ROOT;

    #[test]
    fn replicas_committing_one_chain_pass() {
        let mut invariants = Invariants::default();
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 0));
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 1));
        invariants.record(SHARD, BlockHeight::new(2), slot(b"b", b"a", 20, 1));
    }

    #[test]
    #[should_panic(expected = "fork")]
    fn two_blocks_at_one_height_panic() {
        let mut invariants = Invariants::default();
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 0));
        invariants.record(SHARD, BlockHeight::new(1), slot(b"x", b"g", 10, 1));
    }

    #[test]
    fn a_permitted_fork_is_recorded_not_raised() {
        let mut invariants = Invariants::default();
        invariants.permit_forks();
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 0));
        invariants.record(SHARD, BlockHeight::new(1), slot(b"x", b"g", 10, 1));
    }

    #[test]
    #[should_panic(expected = "broken chain")]
    fn a_block_naming_the_wrong_parent_panics() {
        let mut invariants = Invariants::default();
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 0));
        invariants.record(SHARD, BlockHeight::new(2), slot(b"b", b"z", 20, 0));
    }

    #[test]
    #[should_panic(expected = "time ran backwards")]
    fn a_qc_time_below_its_parents_panics() {
        let mut invariants = Invariants::default();
        invariants.record(SHARD, BlockHeight::new(1), slot(b"a", b"g", 10, 0));
        invariants.record(SHARD, BlockHeight::new(2), slot(b"b", b"a", 5, 0));
    }
}
