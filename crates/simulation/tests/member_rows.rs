//! A shard coordinator's tick membership is its committed state's own.
//!
//! The coordinator loads the family from state at its seat and advances it
//! by the fold every commit runs, so it never reads the store again. This
//! holds the copy to the store under cross-shard traffic: wherever a
//! replica's coordinator and store stand at one height, they hold one set
//! of rows.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_scenarios::tx::{account_routing_to, build_transfer_tx, validity_around};
use hyperscale_scenarios::{Cluster, ScenarioConfig};
use hyperscale_storage::{BoundaryStore, ShardChainReader};
use hyperscale_types::{Ed25519PrivateKey, PrincipalAddr, ShardId};

mod support;

use support::SimCluster;

const SEED: u64 = 7;
const ACCOUNTS: u8 = 8;
const TRANSFERS: u32 = 16;
const SPACING: Duration = Duration::from_secs(4);

const fn config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        pool_surplus: 4,
        vnodes_per_host: 1,
        num_shards: 1,
        split_bytes: 0,
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

/// Every replica whose coordinator and store stand at one height holds
/// one set of rows, and returns how many such pairs held a row at all.
fn compare(cluster: &SimCluster, shards: [ShardId; 2]) -> usize {
    let runner = cluster.runner();
    let mut populated = 0;
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
            let stored = storage.member_index(shard);
            assert_eq!(
                coordinator.member_rows(),
                &stored,
                "host {host} on {shard:?} at {:?}",
                storage.committed_height(),
            );
            if !stored.members.is_empty() {
                populated += 1;
            }
        }
    }
    populated
}

#[test]
fn a_coordinators_rows_are_its_stores() {
    let cast = cast();
    let accounts: Vec<_> = cast
        .iter()
        .map(|(_, account)| (*account, 100_000u128))
        .collect();
    let mut cluster = SimCluster::with_accounts(&config(), SEED, &accounts);
    cluster.runner_mut().grow_to(2);
    let shards: [ShardId; 2] = ShardId::ROOT.children().into();
    let settled = cluster.runner().now() + Duration::from_secs(10);
    cluster.runner_mut().run_until(settled);

    let mut populated = 0;
    for nonce in 0..TRANSFERS {
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
            populated += compare(&cluster, shards);
        }
    }
    assert!(
        populated > 0,
        "the load must leave rows standing at a compared height, or the check is vacuous"
    );
}
