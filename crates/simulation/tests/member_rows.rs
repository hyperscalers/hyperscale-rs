//! A shard coordinator's tick membership is its committed state's own.
//!
//! The coordinator loads the family from state at its seat and advances it
//! by the fold every commit runs, so it never reads the store again. This
//! holds the copy to the store under cross-shard traffic, across a replica
//! that restarts and one that snap-syncs: wherever a replica's coordinator
//! and store stand at one height, they hold one set of rows, every replica
//! at that height holds the same set, and execution there seats every row
//! in flight in the tick its row names.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_scenarios::tx::{account_routing_to, build_transfer_tx, validity_around};
use hyperscale_scenarios::{Cluster, FaultableCluster, ScenarioConfig};
use hyperscale_storage::{BoundaryStore, MemberIndex, RowState, ShardChainReader};
use hyperscale_types::{BlockHeight, Ed25519PrivateKey, PrincipalAddr, ShardId, TickId};

mod support;

use support::SimCluster;

const SEED: u64 = 7;
const ACCOUNTS: u8 = 8;
const TRANSFERS: u32 = 16;
const SPACING: Duration = Duration::from_secs(4);
/// The distinct commits the comparison must reach.
const COMMITS: usize = 64;

const fn config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        pool_surplus: 4,
        vnodes_per_host: 1,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// Accounts alternating leaves, so every transfer crosses.
fn cast() -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
    let mut taken = Vec::new();
    (0..ACCOUNTS)
        .map(|index| {
            let shard = if index % 2 == 0 { left } else { right };
            account_routing_to(shard, &mut taken)
        })
        .collect()
}

/// What the comparisons have seen: every family stored at each
/// `(shard, height)` a replica stood at, how many held a row at all, how
/// many rows in flight execution was held to, and which rejoined replicas
/// were compared holding one.
#[derive(Default)]
struct Seen {
    families: BTreeMap<(ShardId, BlockHeight), MemberIndex>,
    populated: usize,
    in_flight: usize,
    /// The replicas that restarted or snap-synced, from the moment they
    /// did.
    rejoined: BTreeSet<(usize, ShardId)>,
    /// The rejoined replicas that stood at a family holding a row.
    rejoined_populated: BTreeSet<(usize, ShardId)>,
}

/// Every replica whose coordinator and store stand at one height holds
/// one set of rows, the set every other replica at that height holds, and
/// execution there assigns each row in flight to its tick.
fn compare(cluster: &SimCluster, shards: [ShardId; 2], seen: &mut Seen) {
    let runner = cluster.runner();
    for host in 0..runner.num_hosts() {
        for shard in shards {
            let (Some(storage), Some(state)) = (
                runner.hosts_shard(host, shard),
                runner.vnode_state_in(host, shard),
            ) else {
                continue;
            };
            let coordinator = state.shard_coordinator();
            if coordinator.committed_height() != storage.committed_height() {
                continue;
            }
            let height = storage.committed_height();
            let stored = storage.member_index(shard);
            assert_eq!(
                coordinator.member_rows(),
                &stored,
                "host {host} on {shard:?} at {height:?}",
            );
            let agreed = seen
                .families
                .entry((shard, height))
                .or_insert_with(|| stored.clone());
            assert_eq!(
                &*agreed, &stored,
                "host {host} on {shard:?} at {height:?} holds another replica's family",
            );
            let execution = state.execution_coordinator();
            if execution.committed_height() == storage.committed_height() {
                for row in stored.members.values() {
                    if let RowState::InFlight { tick, .. } = row.state {
                        seen.in_flight += 1;
                        assert_eq!(
                            execution.tick_assignment_for(row.tx),
                            Some(TickId::new(shard, tick)),
                            "host {host} on {shard:?}: execution seats {:?} where its row says",
                            row.tx,
                        );
                    }
                }
            }
            if !stored.members.is_empty() {
                seen.populated += 1;
                let replica = (host as usize, shard);
                if seen.rejoined.contains(&replica) {
                    seen.rejoined_populated.insert(replica);
                }
            }
        }
    }
}

/// A live-committee host carrying `shard` other than `except`.
fn a_member_of(cluster: &SimCluster, shard: ShardId, except: Option<usize>) -> usize {
    cluster
        .committee_hosts(shard)
        .into_iter()
        .find(|&host| Some(host) != except)
        .expect("the shard seats a committee")
}

#[test]
fn a_coordinators_rows_are_its_stores() {
    let cast = cast();
    let accounts: Vec<_> = cast
        .iter()
        .map(|(_, account)| (*account, 100_000u128))
        .collect();
    let mut cluster =
        SimCluster::with_grown_accounts_on_dedicated_pool_hosts(&config(), SEED, &accounts);
    let shards: [ShardId; 2] = ShardId::ROOT.children().into();
    let settled = cluster.runner().now() + Duration::from_secs(10);
    cluster.runner_mut().run_until(settled);

    let restarted = a_member_of(&cluster, shards[0], None);
    let mut seen = Seen::default();
    for nonce in 0..TRANSFERS {
        match nonce {
            4 => {
                cluster.restart_host(restarted, shards[0]);
                seen.rejoined.insert((restarted, shards[0]));
            }
            8 => {
                let synced = a_member_of(&cluster, shards[1], Some(restarted));
                cluster.resync_host(synced, shards[1]);
                seen.rejoined.insert((synced, shards[1]));
            }
            _ => {}
        }
        let from = (nonce % u32::from(ACCOUNTS)) as usize;
        let to = (from + 1) % cast.len();
        let transfer = build_transfer_tx(
            &cast[from].0,
            cast[from].1,
            cast[to].1,
            u128::from(nonce) + 1,
            validity_around(cluster.now()),
        );
        cluster.submit(Arc::new(transfer));
        for _ in 0..8 {
            let next = cluster.runner().now() + SPACING / 8;
            cluster.runner_mut().run_until(next);
            compare(&cluster, shards, &mut seen);
        }
    }
    assert_eq!(
        seen.rejoined_populated, seen.rejoined,
        "each rejoined replica must be compared holding a row after it rejoins",
    );
    assert!(
        seen.populated > 0 && seen.in_flight > 0 && seen.families.len() >= COMMITS,
        "the load must leave rows standing, some in flight, at {COMMITS} compared commits, \
         or the check is vacuous: {} populated, {} in flight, {} commits",
        seen.populated,
        seen.in_flight,
        seen.families.len(),
    );

    // Once every transfer resolves the family is empty on every replica.
    let idle = cluster.runner().now() + Duration::from_secs(30);
    cluster.runner_mut().run_until(idle);
    compare(&cluster, shards, &mut seen);
    let runner = cluster.runner();
    for host in 0..runner.num_hosts() {
        for shard in shards {
            if let Some(storage) = runner.hosts_shard(host, shard) {
                let family = storage.member_index(shard);
                assert!(
                    family.members.is_empty() && family.ticks.is_empty(),
                    "host {host} on {shard:?} holds rows after the load resolved: {family:?}",
                );
            }
        }
    }
}
