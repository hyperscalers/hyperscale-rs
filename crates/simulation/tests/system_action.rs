//! End-to-end beacon lifecycle through committed system transactions.
//!
//! Each test drives a real system transaction from submission through the shard
//! commit, the shard's beacon-witness root, and the beacon fold, then asserts
//! the folded `BeaconState`. No witness is injected; every action travels the
//! same rail a real staking or registration transaction would. The deposited /
//! withdrawn amounts are asserted by the transaction message (the stop-gap
//! trust model), so a pool can be funded past genesis capacity regardless of
//! the payer's balance.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BeaconWitnessEvent, Bls12381G1PublicKey, Ed25519PrivateKey,
    Stake, StakePool, StakePoolId, UNBONDING_WINDOW_EPOCHS, ValidatorId, ValidatorStatus,
    bls_keypair_from_seed,
};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;

/// The single genesis pool every genesis validator belongs to.
const GENESIS_POOL: StakePoolId = StakePoolId::new(0);

/// One shard of `validators` nodes, the committee sized to the whole set. With
/// no validators left over for the pool, the shuffle has no stock and never
/// fires, so committee membership stays put for the test's duration.
fn single_shard_config(validators: u32) -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: validators,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 1,
            shard_size: validators,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

/// Boot a single-shard network of `validators` nodes with `payer`'s account
/// funded, warmed up to where the shard is producing blocks and the beacon is
/// folding.
fn booted(validators: u32, seed: u64, payer: &Ed25519PrivateKey) -> SimulationRunner {
    let mut runner = SimulationRunner::new(&single_shard_config(validators), seed);
    let account = ComponentAddress::preallocated_account_from_public_key(&payer.public_key());
    runner.initialize_genesis_with_balances(&[(account, Decimal::from(100_000))]);
    runner.run_until(epochs(1) + Duration::from_secs(2));
    runner
}

/// `n` beacon epochs as wall-clock — the unit every fold and lifecycle budget
/// is counted in, since a witness folds at the next epoch boundary.
const fn epochs(n: u64) -> Duration {
    Duration::from_millis(EPOCH_MS * n)
}

/// Host 0's latest committed beacon state.
fn committed_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    runner
        .beacon_storage(0)?
        .latest_committed()
        .map(|(_, state)| state)
}

fn pool_total_stake(runner: &SimulationRunner, pool: StakePoolId) -> Option<Stake> {
    committed_state(runner)?
        .pools
        .get(&pool)
        .map(|p| p.total_stake)
}

fn pool_effective_stake(runner: &SimulationRunner, pool: StakePoolId) -> Option<Stake> {
    committed_state(runner)?
        .pools
        .get(&pool)
        .map(StakePool::effective_stake)
}

fn validator_status(runner: &SimulationRunner, id: ValidatorId) -> Option<ValidatorStatus> {
    committed_state(runner)?
        .validators
        .get(&id)
        .map(|r| r.status)
}

fn validator_pubkey(runner: &SimulationRunner, id: ValidatorId) -> Option<Bls12381G1PublicKey> {
    committed_state(runner)?
        .validators
        .get(&id)
        .map(|r| r.pubkey)
}

/// A well-formed 48-byte BLS pubkey for a registration — never verified, since
/// no host runs the registered validator.
fn dummy_pubkey(seed: u8) -> Bls12381G1PublicKey {
    bls_keypair_from_seed(&[seed; 32]).public_key()
}

/// Run in one-second slices until `pred` holds or `budget` elapses; returns
/// whether it held.
fn run_until(
    runner: &mut SimulationRunner,
    budget: Duration,
    mut pred: impl FnMut(&SimulationRunner) -> bool,
) -> bool {
    let deadline = runner.now() + budget;
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if pred(runner) {
            return true;
        }
    }
    pred(runner)
}

#[test]
fn stake_deposit_folds_into_beacon_state() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0x57AC, &payer);

    // A pool id no genesis validator uses, so the deposit is the only source of
    // its stake.
    let pool = StakePoolId::new(7777);
    let amount = Stake::from_whole_tokens(1_000);
    assert_eq!(
        pool_total_stake(&runner, pool),
        None,
        "pool must not exist yet"
    );

    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount,
        },
    );

    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool) == Some(amount)
        }),
        "beacon never folded the stake deposit",
    );
}

#[test]
fn register_validator_pools_a_node() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0x5EED, &payer);

    // Fund a fresh pool well above min_stake so it can support a validator.
    let pool = StakePoolId::new(7777);
    let newcomer = ValidatorId::new(1000);
    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool).is_some()
        }),
        "deposit never folded",
    );

    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: newcomer,
            pubkey: dummy_pubkey(9),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            validator_status(r, newcomer) == Some(ValidatorStatus::Pooled)
        }),
        "registered validator never reached the pool",
    );
}

#[test]
fn register_without_capacity_is_rejected() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0x0CA9, &payer);

    // The pool exists but holds less than one min_stake, so it can support no
    // validator — the registration must be rejected on the capacity gate.
    let pool = StakePoolId::new(8888);
    let newcomer = ValidatorId::new(2000);
    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(500_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool).is_some()
        }),
        "deposit never folded",
    );

    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: newcomer,
            pubkey: dummy_pubkey(11),
        },
    );
    // Run long enough that the registration has committed and folded; an
    // accepted one would surface within a couple of epochs.
    run_until(&mut runner, epochs(3), |_| false);
    assert_eq!(
        validator_status(&runner, newcomer),
        None,
        "under-capacity registration must not create a validator record",
    );
}

#[test]
fn stake_withdraw_drops_effective_stake() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0xD7A1, &payer);

    let pool = StakePoolId::new(9999);
    let deposited = Stake::from_whole_tokens(5_000_000);
    let withdrawn = Stake::from_whole_tokens(2_000_000);
    let remaining = Stake::from_whole_tokens(3_000_000);

    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: deposited,
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool) == Some(deposited)
        }),
        "deposit never folded",
    );

    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::StakeWithdraw {
            pool_id: pool,
            amount: withdrawn,
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_effective_stake(r, pool) == Some(remaining)
        }),
        "withdrawal never dropped effective stake",
    );
    // `total_stake` holds through the unbonding window; only `effective_stake`
    // drops immediately.
    assert_eq!(
        pool_total_stake(&runner, pool),
        Some(deposited),
        "total stake must hold until the withdrawal unbonds",
    );
}

#[test]
fn registered_validator_activates_onto_a_shard() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0xAC11, &payer);

    let newcomer = ValidatorId::new(1000);

    // Grow the genesis pool past its capacity so it can support another node.
    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, GENESIS_POOL)
                .is_some_and(|s| s >= Stake::from_whole_tokens(13_000_000))
        }),
        "capacity deposit never folded",
    );

    // Register a new validator; with the committee full it parks in the pool.
    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: GENESIS_POOL,
            validator_id: newcomer,
            pubkey: dummy_pubkey(9),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            validator_status(r, newcomer) == Some(ValidatorStatus::Pooled)
        }),
        "newcomer never reached the pool",
    );

    // Retire a genesis validator; the freed committee slot draws the only pooled
    // validator — the newcomer — onto the shard. It enters `OnShard { ready:
    // false }`; the ready flip follows later via the shard's `Ready` witness or
    // the ready-timeout, neither of which this host-less validator drives, so the
    // placement is the activation milestone.
    runner.submit_system_action(
        &payer,
        3,
        &BeaconWitnessEvent::DeactivateValidator {
            validator_id: ValidatorId::new(0),
        },
    );
    assert!(
        run_until(&mut runner, epochs(4), |r| {
            matches!(
                validator_status(r, newcomer),
                Some(ValidatorStatus::OnShard { .. })
            )
        }),
        "newcomer never drew onto the shard after a slot freed",
    );
}

#[test]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    // Seven nodes give the committee slack to keep quorum while a couple are
    // ejected; `shard_size == validators` keeps the shuffle dormant.
    let mut runner = booted(7, 0xE1EC, &payer);

    // The highest-id genesis validator is the first the over-capacity sweep
    // ejects, so it is the one to watch.
    let victim = ValidatorId::new(6);
    assert!(
        matches!(
            validator_status(&runner, victim),
            Some(ValidatorStatus::OnShard { .. } | ValidatorStatus::Pooled)
        ),
        "victim should start active",
    );

    // The withdrawal blocks new support immediately but only releases stake —
    // and forces the over-capacity ejection — once it unbonds, an
    // UNBONDING_WINDOW_EPOCHS later.
    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeWithdraw {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(1_500_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(UNBONDING_WINDOW_EPOCHS + 6), |r| {
            validator_status(r, victim) == Some(ValidatorStatus::InsufficientStake)
        }),
        "the matured withdrawal never ejected the over-capacity validator",
    );

    // Top the pool back up; `auto_reactivate` promotes the ejected validator
    // back into service once capacity returns.
    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(4), |r| {
            matches!(
                validator_status(r, victim),
                Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
            )
        }),
        "the deposit never reactivated the ejected validator",
    );
}

#[test]
fn re_registration_of_a_live_validator_is_a_no_op() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0xDEAD, &payer);

    let pool = StakePoolId::new(7777);
    let id = ValidatorId::new(1000);
    let first = dummy_pubkey(9);
    let second = dummy_pubkey(99);

    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool).is_some()
        }),
        "deposit never folded",
    );

    runner.submit_system_action(
        &payer,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: id,
            pubkey: first,
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            validator_pubkey(r, id) == Some(first)
        }),
        "validator never registered",
    );

    // Re-register the same id with a different key; the id is dead for the life
    // of the chain, so the record keeps its first key.
    runner.submit_system_action(
        &payer,
        3,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: id,
            pubkey: second,
        },
    );
    run_until(&mut runner, epochs(3), |_| false);
    assert_eq!(
        validator_pubkey(&runner, id),
        Some(first),
        "re-registration must not overwrite the existing record",
    );
}

#[test]
fn pool_capacity_caps_registrations() {
    let payer = Ed25519PrivateKey::from_u64(42).unwrap();
    let mut runner = booted(4, 0xCA9A, &payer);

    // Fund the pool for exactly three validators at the 1M floor.
    let pool = StakePoolId::new(7777);
    let candidates = [
        ValidatorId::new(1000),
        ValidatorId::new(1001),
        ValidatorId::new(1002),
        ValidatorId::new(1003),
    ];
    runner.submit_system_action(
        &payer,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            pool_total_stake(r, pool).is_some()
        }),
        "deposit never folded",
    );

    // Four registrations against capacity three: exactly three take.
    for (i, id) in candidates.iter().enumerate() {
        let offset = u8::try_from(i).expect("candidate index fits u8");
        runner.submit_system_action(
            &payer,
            u32::from(offset) + 2,
            &BeaconWitnessEvent::RegisterValidator {
                pool_id: pool,
                validator_id: *id,
                pubkey: dummy_pubkey(20 + offset),
            },
        );
    }
    assert!(
        run_until(&mut runner, epochs(3), |r| {
            candidates
                .iter()
                .filter(|id| validator_status(r, **id).is_some())
                .count()
                >= 3
        }),
        "registrations never folded",
    );
    // Let any fourth attempt commit; the cap must hold at three.
    run_until(&mut runner, epochs(2), |_| false);
    let registered = candidates
        .iter()
        .filter(|id| validator_status(&runner, **id).is_some())
        .count();
    assert_eq!(
        registered, 3,
        "pool capacity must cap registrations at three",
    );
}
