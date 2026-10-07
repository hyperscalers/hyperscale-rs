//! A held execution vote outlives its holder's committee seat.
//!
//! A committee member keeps every execution vote it casts for retry until
//! its tick certifies. When the shuffle rotates that member off while one
//! of its votes is still needed, the vote has to land after the crossing,
//! from a member that no longer sits in the committee its successors read.
//!
//! The test grows to two shards of four, so the beacon has enough eligible
//! validators to rotate a committee, and cuts one member out of execution
//! voting for the whole run: with three of four voting, every remaining
//! vote is needed, as in a committee of three. Once the shuffle names a
//! departing member, its execution votes are cut too, until the committee a
//! current member holds no longer carries it; then they flow again, and
//! the shard's settled frontier must move past where it stood at the
//! crossing.
//!
//! A cut runs both ways. A voter's retry reaches its own tally as well as
//! its peers', so a member that can still hear its peers certifies the
//! tick itself, its own vote included, however many of its sends drop.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::ParticipationChange;
use hyperscale_network_memory::NodeIndex;
use hyperscale_scenarios::tx::{account_routing_to, build_transfer_tx, validity_around};
use hyperscale_scenarios::{Cluster, FaultHandle, FaultableCluster, ScenarioConfig, assume};
use hyperscale_simulation::EPOCH_MS;
use hyperscale_types::{BlockHeight, Ed25519PrivateKey, PrincipalAddr, ShardId, ValidatorId};

mod support;

use support::{SimCluster, rotation_config};

/// Seed for the grown placement the shuffle runs against: its first
/// rotation retires a member from a leaf under steady load, on a host
/// that seats nothing else.
const SEED: u64 = 7;

/// The two leaves the grow seats.
const LEAVES: [ShardId; 2] = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)];

/// Transfer pairs per leaf, each paying within its own leaf, cycled one
/// per leaf per second.
const PAIRS_PER_LEAF: usize = 4;

/// Epochs the shuffle gets to name a departing member: its first interval
/// plus the entrant's sync.
const SHUFFLE_BUDGET_EPOCHS: u64 = 40;

/// Epochs the departing member gets to drop out of the committee once
/// named.
const CROSSING_BUDGET_EPOCHS: u64 = 4;

/// What the settled frontier gets to pass the crossing in: a few vote
/// retry periods, and short of when the departing member's host retires
/// it and its held votes with it.
const SETTLE_BUDGET: Duration = Duration::from_secs(30);

/// What each paying account starts with: enough fees for one transfer a
/// second through the longest run, the production epoch's included, so
/// the load never stops for want of funds.
const SENDER_FUNDS: u128 = 10_000_000;

type Pair = (Ed25519PrivateKey, PrincipalAddr, PrincipalAddr);

/// Steady transfers on both leaves, and the placement deltas the slices
/// surface.
struct Load {
    pairs: Vec<Vec<Pair>>,
    round: usize,
    moves: Vec<(NodeIndex, ParticipationChange)>,
}

impl Load {
    fn new() -> Self {
        let mut taken = Vec::new();
        let pairs = LEAVES
            .iter()
            .map(|&leaf| {
                (0..PAIRS_PER_LEAF)
                    .map(|_| {
                        let (key, from) = account_routing_to(leaf, &mut taken);
                        let (_, to) = account_routing_to(leaf, &mut taken);
                        (key, from, to)
                    })
                    .collect()
            })
            .collect();
        Self {
            pairs,
            round: 0,
            moves: Vec::new(),
        }
    }

    fn accounts(&self) -> Vec<(PrincipalAddr, u128)> {
        self.pairs
            .iter()
            .flatten()
            .flat_map(|(_, from, to)| [(*from, SENDER_FUNDS), (*to, 10)])
            .collect()
    }

    /// Submit one transfer per leaf and run a one-second slice, seating and
    /// retiring vnodes against the committed placement first.
    fn slice(&mut self, cluster: &mut SimCluster) {
        for leaf_pairs in &self.pairs {
            let (key, from, to) = &leaf_pairs[self.round % PAIRS_PER_LEAF];
            let tx = build_transfer_tx(key, *from, *to, 1, validity_around(cluster.now()));
            cluster.submit(Arc::new(tx));
        }
        self.round += 1;
        let runner = cluster.runner_mut();
        runner.topology_step();
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        self.moves.extend(runner.take_participation_changes());
    }
}

/// Drop every execution vote `host` sends or is sent.
fn cut_votes(cluster: &mut SimCluster, host: usize) -> FaultHandle {
    let rest: Vec<usize> = (0..cluster.host_count()).filter(|&h| h != host).collect();
    let sent = cluster.drop_type_between(&[host], &rest, "execution.vote");
    let received = cluster.drop_type_between(&rest, &[host], "execution.vote");
    FaultHandle::new(move || sent.fired() + received.fired())
}

/// A host running a current member of `shard` other than `except`.
fn member_host(cluster: &SimCluster, shard: ShardId, except: ValidatorId) -> usize {
    let state = cluster.beacon_state().expect("beacon committed");
    state
        .shard_consensus_members
        .get(&shard)
        .expect("shard has a committee")
        .iter()
        .filter(|&&member| member != except)
        .filter_map(|&member| cluster.host_of(member))
        .find(|&host| cluster.host_committed_height(host, shard).is_some())
        .expect("a current member of the shard is hosted")
}

/// The settled tick frontier on the tip `host` holds certified for `shard`.
fn settled_frontier(cluster: &SimCluster, host: usize, shard: ShardId) -> BlockHeight {
    let tip = cluster
        .host_committed_height(host, shard)
        .expect("member host serves the shard");
    cluster
        .certified_header(host, shard, tip)
        .expect("the committed tip is certified")
        .settled_tick_frontier()
}

/// The validators `host` seats on `shard`.
fn seated(cluster: &SimCluster, host: usize, shard: ShardId) -> Vec<ValidatorId> {
    let host = NodeIndex::try_from(host).expect("host index fits a NodeIndex");
    cluster
        .runner()
        .shard_vnodes_in(host, shard)
        .iter()
        .map(|vnode| vnode.validator_id())
        .collect()
}

#[test]
fn a_vote_holder_rotating_off_still_certifies_its_tick() {
    let config = ScenarioConfig {
        num_shards: 2,
        split_bytes: u64::MAX,
        ..rotation_config()
    };
    let mut load = Load::new();
    let mut cluster =
        SimCluster::with_grown_accounts_on_dedicated_pool_hosts(&config, SEED, &load.accounts());
    let _ = cluster.runner_mut().take_participation_changes();

    // A leave names a member still in the active window, so it holds votes
    // the committee needs until its successor's window opens.
    let deadline = cluster.now() + Duration::from_millis(EPOCH_MS * SHUFFLE_BUDGET_EPOCHS);
    let (v, shard) = loop {
        assert!(
            cluster.now() < deadline,
            "the shuffle named no departing member; got {:?}",
            load.moves,
        );
        load.slice(&mut cluster);
        if let Some((_, change)) = load.moves.iter().find(|(_, c)| c.leave.is_some()) {
            break (change.validator, change.leave.expect("just matched"));
        }
    };
    let host_v = cluster.host_of(v).expect("the departing member is hosted");
    assume(
        seated(&cluster, host_v, shard) == [v],
        "the departing member's host seats another member of its shard; pick a seed \
         that places it alone",
    );
    let w = cluster
        .beacon_state()
        .expect("beacon committed")
        .shard_consensus_members[&shard]
        .iter()
        .copied()
        .find(|&member| member != v)
        .expect("the committee has another member");
    let host_w = cluster.host_of(w).expect("the silenced member is hosted");

    let _silenced = cut_votes(&mut cluster, host_w);
    let held = cut_votes(&mut cluster, host_v);
    let deadline = cluster.now() + Duration::from_millis(EPOCH_MS * CROSSING_BUDGET_EPOCHS);
    let member = loop {
        assert!(
            cluster.now() < deadline,
            "{v:?} never left {shard:?}'s committee"
        );
        load.slice(&mut cluster);
        let member = member_host(&cluster, shard, v);
        let topology = cluster
            .runner()
            .host_topology(NodeIndex::try_from(member).expect("host index fits a NodeIndex"))
            .expect("member host holds a topology");
        if !topology.consensus_committee_for_shard(shard).contains(&v) {
            break member;
        }
    };
    assume(
        held.fired() > 0,
        "none of the departing member's votes dropped before it crossed",
    );
    assume(
        seated(&cluster, host_v, shard).contains(&v),
        "the departing member's host retired it before the crossing; cut its votes earlier",
    );
    let noted = settled_frontier(&cluster, member, shard).inner() + 1;
    let deadline = cluster.now() + SETTLE_BUDGET;

    // Clearing lifts the silenced member's cut too, and the three voters it
    // leaves must stay the only ones.
    cluster.clear_drops();
    let _silenced = cut_votes(&mut cluster, host_w);
    loop {
        load.slice(&mut cluster);
        let member = member_host(&cluster, shard, v);
        let frontier = settled_frontier(&cluster, member, shard);
        if frontier.inner() > noted + 2 {
            break;
        }
        assert!(
            cluster.now() < deadline,
            "{shard:?}'s settled frontier is stuck at {frontier:?}, not yet past {} \
             {SETTLE_BUDGET:?} after {v:?} crossed",
            noted + 2,
        );
    }
}
