//! Surviving-sibling split lifecycle, composed over `split_straddler_atomic`.
//!
//! `split_straddler_atomic` grows the root into the heavier `leaf(1,0)` splitter
//! and the lighter `leaf(1,1)` survivor, votes the reshape threshold down so only
//! the splitter crosses, and asserts the settled-waves fence across the boundary
//! (a straddler settles atomically with what the splitter settled by its terminal
//! block, or aborts — never one-sided). This bespoke sim test layers the sim-only
//! **post-lifecycle** facts on top: the second-generation split seats correctly
//! while the sibling survives — the splitter retires, its two children each seat
//! a full committee, and the survivor keeps its own — both children commit past
//! their seeded genesis, and each child's chain is structurally continuous with
//! the splitter it forked from (a committed block carries a genesis QC).
//!
//! The straddler's **settled-set** machinery is not re-asserted here: the
//! acquisition host is unit-tested in `crates/node/src/shard/cross_shard/settled_set.rs`
//! (`acquires_against_a_served_chain`, `root_mismatch_parks_and_rotates`,
//! `expires_past_the_retention_horizon`, `dedupes_by_terminal_block`), the
//! counterpart abort and the lock release it triggers in `hyperscale_mempool`
//! (`abort_in_flight_drives_committed_txs_terminal`,
//! `abort_transactions_releases_only_the_named_txs`), and the atomic-settlement
//! outcome is `split_straddler_atomic`'s fence.

mod support;

use hyperscale_scenarios::tx::{STRADDLER_SPLITTER, STRADDLER_SURVIVOR, split_straddler_setup};
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs, split_straddler_atomic};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId, ValidatorStatus};
use support::sim_cluster::SimCluster;

/// Committee validators per shard.
const PER_SHARD: u32 = 4;

/// Single-shard genesis with the grow trigger armed (`split_bytes` above each
/// child but below ROOT) and two cohorts of pool surplus — one grows ROOT into
/// the splitter and survivor siblings, the other splits the heavier splitter
/// once the threshold vote lands.
const fn sibling_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: PER_SHARD,
        vnodes_per_host: 1,
        pool_surplus: 2 * PER_SHARD,
        num_shards: 1,
        split_bytes: 800_000,
        latency: std::time::Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn surviving_sibling_split_seats_children_with_chains_continuous_from_the_splitter() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&sibling_config(), 11, &setup.balances);
    let splitter = STRADDLER_SPLITTER;
    let survivor = STRADDLER_SURVIVOR;
    let (child_left, child_right) = splitter.children();

    split_straddler_atomic(&mut cluster);

    // Placement: the splitter retired into its two children — each seats a full
    // committee — while the survivor kept its own across the split.
    let state = cluster
        .beacon_state()
        .expect("the split committed a beacon state");
    let seated_on = |shard: ShardId| {
        state
            .validators
            .values()
            .filter(|record| {
                matches!(record.status, ValidatorStatus::OnShard { shard: s, .. } if s == shard)
            })
            .count()
    };
    assert_eq!(
        seated_on(survivor),
        PER_SHARD as usize,
        "the survivor must keep a full committee across the splitter's split",
    );
    assert_eq!(
        seated_on(child_left),
        PER_SHARD as usize,
        "the splitter's left child must seat a full committee",
    );
    assert_eq!(
        seated_on(child_right),
        PER_SHARD as usize,
        "the splitter's right child must seat a full committee",
    );
    assert_eq!(
        seated_on(splitter),
        0,
        "the splitter must retire once its children seat",
    );

    // Forward progress: the children reach their seeded genesis (a single block)
    // during the scenario, so prove they keep committing past it.
    let left_base = cluster
        .committed_height(child_left)
        .expect("left child commits");
    let right_base = cluster
        .committed_height(child_right)
        .expect("right child commits");
    assert!(
        cluster.run_until(epochs(6), |c| {
            c.committed_height(child_left)
                .is_some_and(|h| h > left_base)
                && c.committed_height(child_right)
                    .is_some_and(|h| h > right_base)
        }),
        "both children must keep committing blocks past the split",
    );

    // Chain continuity: each child's committed chain is consensus-rooted in a
    // structural genesis — some committed block carries a genesis QC, the fork
    // point where the splitter's terminal root was adopted as the child's base.
    let runner = cluster.runner();
    for child in [child_left, child_right] {
        for node in 0..runner.num_hosts() {
            let Some(storage) = runner.hosts_shard(node, child) else {
                continue;
            };
            let tip = storage.committed_height();
            let mut height = BlockHeight::new(1);
            let mut rooted = false;
            while height <= tip {
                if storage
                    .get_block(height)
                    .is_some_and(|block| block.block().header().parent_qc().is_genesis())
                {
                    rooted = true;
                    break;
                }
                height = height.next();
            }
            assert!(
                rooted,
                "child {child:?} on node {node} has no structural-genesis block — \
                 its committed chain is not rooted in the splitter fork",
            );
        }
    }
}
