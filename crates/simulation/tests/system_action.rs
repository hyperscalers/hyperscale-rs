//! End-to-end: a committed system transaction reports its beacon action.
//!
//! Drives a real `StakeDeposit` system transaction from submission through the
//! shard commit, the shard's beacon-witness root, and the beacon fold — then
//! asserts the deposited stake appears on the folded `BeaconState`. No witness
//! is injected; the action travels the same rail a real staking transaction
//! would.

use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{
    BeaconChainConfig, BeaconWitnessEvent, Ed25519PrivateKey, Stake, StakePoolId,
};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;

const TEST_EPOCH_MS: u64 = 2000;

/// One shard, four validators, beacon committee four.
fn single_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(100),
        cross_shard_latency: Duration::from_millis(100),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 1,
            shard_size: 4,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

fn account_of(key: &Ed25519PrivateKey) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&key.public_key())
}

/// Host 0's folded stake for `pool`, or `None` if the pool has no entry yet.
fn pool_stake(runner: &SimulationRunner, pool: StakePoolId) -> Option<Stake> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    state.pools.get(&pool).map(|p| p.total_stake)
}

#[test]
fn stake_deposit_system_tx_folds_into_beacon_state() {
    let mut runner = SimulationRunner::new(&single_shard_config(), 0x57AC);
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    runner.initialize_genesis_with_balances(&[(account_of(&payer), Decimal::from(100_000))]);

    // Warm up so the shard is producing blocks and the beacon is folding.
    runner.run_until(Duration::from_secs(8));

    // A pool id no genesis validator uses, so the deposit is the only source of
    // its stake.
    let pool = StakePoolId::new(7777);
    let amount = Stake::from_whole_tokens(1_000);
    assert_eq!(pool_stake(&runner, pool), None, "pool must not exist yet");

    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount,
        },
    );

    // The transaction commits on the shard, the shard's witness root carries the
    // deposit, and the next beacon fold credits the pool.
    let deadline = runner.now() + Duration::from_secs(60);
    let mut folded = false;
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if pool_stake(&runner, pool) == Some(amount) {
            folded = true;
            break;
        }
    }
    assert!(folded, "beacon never folded the stake deposit");
}
