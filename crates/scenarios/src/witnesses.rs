//! Beacon-witness scenarios.
//!
//! Each scenario drives a real system transaction — a `lock_fee` no-op carrying
//! a [`BeaconWitnessEvent`] — from submission through the shard commit, the
//! shard's beacon-witness root, and the beacon fold, then asserts the folded
//! [`BeaconState`]. No witness is injected: every action travels the same rail an
//! operator's staking, registration, or governance transaction would, so the
//! same body validates the witness rail on both harnesses.
//!
//! The deposited and withdrawn amounts are asserted by the transaction message
//! (the stop-gap trust model), so a pool can be funded past genesis capacity
//! regardless of the payer's balance.
//!
//! [`BeaconState`]: hyperscale_types::BeaconState

use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessEvent, Bls12381G1PublicKey, Stake, StakePoolId, UNBONDING_WINDOW_EPOCHS,
    ValidatorId, ValidatorStatus, bls_keypair_from_seed,
};
use radix_common::network::NetworkDefinition;

use crate::support::query::{
    pool_effective_stake, pool_total_stake, validator_pubkey, validator_status,
};
use crate::support::tx::{build_witness_tx, validity_around, witness_payer};
use crate::support::wait::await_beacon_epoch;
use crate::support::{Cluster, epochs};

/// The single genesis stake pool every genesis validator belongs to.
const GENESIS_POOL: StakePoolId = StakePoolId::new(0);

/// Warm the cluster until the beacon folds its first epoch — the precondition a
/// system action needs to land on a live shard and witness through.
fn warm_up<C: Cluster>(c: &mut C) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "beacon never folded its first epoch",
    );
}

/// Build and submit a system action from the witness payer at `nonce`.
fn submit_action<C: Cluster>(c: &mut C, nonce: u32, event: &BeaconWitnessEvent) {
    let tx = build_witness_tx(
        &witness_payer(),
        event,
        &NetworkDefinition::simulator(),
        nonce,
        validity_around(c.now()),
    );
    c.submit(Arc::new(tx));
}

/// A well-formed BLS pubkey for a registration. Never verified — no host runs
/// the registered validator — so any deterministic key serves.
fn dummy_pubkey(seed: u8) -> Bls12381G1PublicKey {
    bls_keypair_from_seed(&[seed; 32]).public_key()
}

/// A stake deposit to a fresh pool folds into the beacon state.
///
/// # Panics
///
/// Panics if the beacon never folds the deposit within budget.
pub fn stake_deposit_folds_into_beacon_state(c: &mut impl Cluster) {
    warm_up(c);

    // A pool id no genesis validator uses, so the deposit is the only source of
    // its stake.
    let pool = StakePoolId::new(7777);
    let amount = Stake::from_whole_tokens(1_000);
    assert_eq!(pool_total_stake(c, pool), None, "pool must not exist yet");

    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount,
        },
    );

    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool) == Some(amount)),
        "beacon never folded the stake deposit",
    );
}

/// Registering a validator against a funded pool seats it in the pool.
///
/// # Panics
///
/// Panics if the deposit or the registration never folds within budget.
pub fn register_validator_pools_a_node(c: &mut impl Cluster) {
    warm_up(c);

    // Fund a fresh pool well above min_stake so it can support a validator.
    let pool = StakePoolId::new(7777);
    let newcomer = ValidatorId::new(1000);
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(
        c,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: newcomer,
            pubkey: dummy_pubkey(9),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "registered validator never reached the pool",
    );
}

/// A registration against a pool below one `min_stake` is rejected on the
/// capacity gate, leaving no validator record.
///
/// # Panics
///
/// Panics if the deposit never folds, or if the under-capacity registration
/// creates a validator record.
pub fn register_without_capacity_is_rejected(c: &mut impl Cluster) {
    warm_up(c);

    // The pool exists but holds less than one min_stake, so it can support no
    // validator — the registration must be rejected on the capacity gate.
    let pool = StakePoolId::new(8888);
    let newcomer = ValidatorId::new(2000);
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(500_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(
        c,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: newcomer,
            pubkey: dummy_pubkey(11),
        },
    );
    // Run long enough that the registration has committed and folded; an
    // accepted one would surface within a couple of epochs.
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_status(c, newcomer),
        None,
        "under-capacity registration must not create a validator record",
    );
}

/// A withdrawal drops the pool's effective stake immediately while its total
/// stake holds until the unbond matures.
///
/// # Panics
///
/// Panics if the deposit or withdrawal never folds, or if total stake drops
/// before the unbond matures.
pub fn stake_withdraw_drops_effective_stake(c: &mut impl Cluster) {
    warm_up(c);

    let pool = StakePoolId::new(9999);
    let deposited = Stake::from_whole_tokens(5_000_000);
    let withdrawn = Stake::from_whole_tokens(2_000_000);
    let remaining = Stake::from_whole_tokens(3_000_000);

    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: deposited,
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool) == Some(deposited)),
        "deposit never folded",
    );

    submit_action(
        c,
        2,
        &BeaconWitnessEvent::StakeWithdraw {
            pool_id: pool,
            amount: withdrawn,
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_effective_stake(c, pool)
            == Some(remaining)),
        "withdrawal never dropped effective stake",
    );
    // `total_stake` holds through the unbonding window; only `effective_stake`
    // drops immediately.
    assert_eq!(
        pool_total_stake(c, pool),
        Some(deposited),
        "total stake must hold until the withdrawal unbonds",
    );
}

/// A pooled validator draws onto the shard once a committee slot frees.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn registered_validator_activates_onto_a_shard(c: &mut impl Cluster) {
    warm_up(c);

    let newcomer = ValidatorId::new(1000);

    // Grow the genesis pool past its capacity so it can support another node.
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, GENESIS_POOL)
            .is_some_and(|s| s >= Stake::from_whole_tokens(13_000_000))),
        "capacity deposit never folded",
    );

    // Register a new validator; with the committee full it parks in the pool.
    submit_action(
        c,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: GENESIS_POOL,
            validator_id: newcomer,
            pubkey: dummy_pubkey(9),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "newcomer never reached the pool",
    );

    // Retire a genesis validator; the freed committee slot draws the only pooled
    // validator — the newcomer — onto the shard. It enters `OnShard { ready:
    // false }`; the ready flip follows later via the shard's `Ready` witness,
    // which this host-less validator never drives, so the placement is the
    // activation milestone.
    submit_action(
        c,
        3,
        &BeaconWitnessEvent::DeactivateValidator {
            validator_id: ValidatorId::new(0),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::OnShard { .. })
        )),
        "newcomer never drew onto the shard after a slot freed",
    );
}

/// A matured withdrawal ejects an over-capacity validator; a later deposit
/// reactivates it once capacity returns.
///
/// Requires a committee with enough slack to keep quorum while a member ejects
/// (the harness seats a seven-validator committee).
///
/// # Panics
///
/// Panics if the ejection or the reactivation misses its budget.
pub fn withdrawal_ejects_a_validator_that_a_deposit_reactivates(c: &mut impl Cluster) {
    // The highest-id genesis validator is the first the over-capacity sweep
    // ejects, so it is the one to watch.
    let victim = ValidatorId::new(6);
    assert!(
        c.run_until(epochs(6), |c| matches!(
            validator_status(c, victim),
            Some(ValidatorStatus::OnShard { .. } | ValidatorStatus::Pooled)
        )),
        "victim should start active",
    );

    // The withdrawal blocks new support immediately but only releases stake —
    // and forces the over-capacity ejection — once it unbonds, an
    // UNBONDING_WINDOW_EPOCHS later.
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeWithdraw {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(1_500_000),
        },
    );
    let unbond_budget = u32::try_from(UNBONDING_WINDOW_EPOCHS).expect("unbonding window fits u32");
    assert!(
        c.run_until(epochs(unbond_budget + 10), |c| validator_status(c, victim)
            == Some(ValidatorStatus::InsufficientStake)),
        "the matured withdrawal never ejected the over-capacity validator",
    );

    // Top the pool back up; `auto_reactivate` promotes the ejected validator
    // back into service once capacity returns.
    submit_action(
        c,
        2,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, victim),
            Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
        )),
        "the deposit never reactivated the ejected validator",
    );
}

/// Re-registering a live validator id is a no-op: the record keeps its first
/// key, since the id is dead for the life of the chain.
///
/// # Panics
///
/// Panics if the first registration never folds, or if the re-registration
/// overwrites the existing record.
pub fn re_registration_of_a_live_validator_is_a_no_op(c: &mut impl Cluster) {
    warm_up(c);

    let pool = StakePoolId::new(7777);
    let id = ValidatorId::new(1000);
    let first = dummy_pubkey(9);
    let second = dummy_pubkey(99);

    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(
        c,
        2,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: id,
            pubkey: first,
        },
    );
    assert!(
        c.run_until(epochs(8), |c| validator_pubkey(c, id) == Some(first)),
        "validator never registered",
    );

    // Re-register the same id with a different key; the id is dead for the life
    // of the chain, so the record keeps its first key.
    submit_action(
        c,
        3,
        &BeaconWitnessEvent::RegisterValidator {
            pool_id: pool,
            validator_id: id,
            pubkey: second,
        },
    );
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_pubkey(c, id),
        Some(first),
        "re-registration must not overwrite the existing record",
    );
}

/// Pool capacity caps registrations: four registrations against a pool funded
/// for three take exactly three.
///
/// # Panics
///
/// Panics if the deposit or registrations never fold, or if more than three
/// take.
pub fn pool_capacity_caps_registrations(c: &mut impl Cluster) {
    warm_up(c);

    // Fund the pool for exactly three validators at the 1M floor.
    let pool = StakePoolId::new(7777);
    let candidates = [
        ValidatorId::new(1000),
        ValidatorId::new(1001),
        ValidatorId::new(1002),
        ValidatorId::new(1003),
    ];
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    // Four registrations against capacity three: exactly three take.
    for (i, id) in candidates.iter().enumerate() {
        let offset = u8::try_from(i).expect("candidate index fits u8");
        submit_action(
            c,
            u32::from(offset) + 2,
            &BeaconWitnessEvent::RegisterValidator {
                pool_id: pool,
                validator_id: *id,
                pubkey: dummy_pubkey(20 + offset),
            },
        );
    }
    assert!(
        c.run_until(epochs(8), |c| candidates
            .iter()
            .filter(|id| validator_status(c, **id).is_some())
            .count()
            >= 3),
        "registrations never folded",
    );
    // Let any fourth attempt commit; the cap must hold at three.
    c.run_until(epochs(4), |_| false);
    let registered = candidates
        .iter()
        .filter(|id| validator_status(c, **id).is_some())
        .count();
    assert_eq!(
        registered, 3,
        "pool capacity must cap registrations at three",
    );
}
