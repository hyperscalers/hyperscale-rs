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
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_engine::genesis::{OWNER_BADGE_ID, pool_owner_badge};
use hyperscale_types::{
    ComponentAddr, ConsensusPublicKey, ConsensusSignature, Epoch, MIN_STAKE_FLOOR,
    NetworkDefinition, SPC_VIEW_TIMEOUT, ShardId, Stake, StakePoolId, Transaction,
    TransactionDecision, TransactionStatus, UNBONDING_WINDOW_EPOCHS, ValidatorId, ValidatorStatus,
    validator_possession_proof_sign,
};
use hyperscale_vm_types::PrincipalAddr;

use crate::support::conservation::{Charges, World};
use crate::support::query::{
    beacon_epoch, epoch_windows, holds_instance, live_shards, pool_effective_stake,
    pool_total_stake, validator_pubkey, validator_status,
};
use crate::support::tx::{
    FOUNDER_FUNDING, GENESIS_POOL, SECOND_POOL, STAKE_POOL, badge_buyer, build_badge_sale_tx,
    build_deactivate_tx, build_found_tx, build_founded_stake_tx, build_join_tx, build_register_tx,
    build_reshape_threshold_vote_tx, build_sponsored_unjail_tx, build_stake_tx, build_transfer_tx,
    build_unjail_tx, build_unstake_tx, delegator, founded_at, founded_id, newcomer_founder,
    pool_at, pool_id, pool_operator, pool_vault_cell, validity_around,
};
use crate::support::wait::{await_beacon_epoch, await_tx_terminal};
use crate::support::{Cluster, RestartableCluster, epochs, found_staged};

/// The single genesis stake pool every genesis validator belongs to.
/// Warm the cluster until the beacon folds its first epoch — the precondition a
/// system action needs to land on a live shard and witness through.
fn warm_up<C: Cluster>(c: &mut C) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "beacon never folded its first epoch",
    );
}

/// A well-formed consensus pubkey for a registration, derived under the
/// cluster's own scheme. No host runs the registered validator, so any
/// deterministic key serves.
fn dummy_pubkey(c: &impl Cluster, seed: u8) -> ConsensusPublicKey {
    c.signer_from_seed(&[seed; 32]).public_key()
}

/// Everything a pool scenario's protocol resource can reach: the accounts that pay —
/// the delegator, the pool's operator and the badge buyer — and each
/// pool's own vault, where a delegation lands.
///
/// Opened after [`warm_up`], so a stake into a pool is measured as a
/// move between the delegator and the pool rather than as a loss.
fn pool_world<C: Cluster>(c: &C, pools: impl IntoIterator<Item = ComponentAddr>) -> World {
    World::open(
        c,
        *PROTOCOL_RESOURCE,
        [
            delegator().1.address(),
            pool_operator().1.address(),
            badge_buyer().1.address(),
        ],
        pools.into_iter().map(pool_vault_cell),
    )
}

/// Delegate `amount` to `pool` and wait for the beacon to hold it.
///
/// A pool's capacity is its stake, so most operator scenarios open by
/// buying the capacity they are about to spend.
fn delegate<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    pool: ComponentAddr,
    id: StakePoolId,
    amount: u128,
) {
    let (key, delegator) = delegator();
    let before = pool_total_stake(c, id).unwrap_or(Stake::ZERO);
    submit_committed(
        c,
        charges,
        build_stake_tx(&key, delegator, pool, amount, validity_around(c.now())),
    );
    let expected = before.saturating_add(Stake::from_quanta(amount));
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, id) == Some(expected)),
        "the delegation never folded; pool stake = {:?}",
        pool_total_stake(c, id),
    );
}

/// Register `validator` against `pool` under the operator's signature,
/// with a genuine proof-of-possession — the fold rejects a registration
/// whose proof does not verify, so the signing scheme must be the
/// cluster's own.
fn register<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    pool: ComponentAddr,
    seed: u8,
    validator: ValidatorId,
) {
    let keypair = c.signer_from_seed(&[seed; 32]);
    let proof = validator_possession_proof_sign(
        keypair.as_ref(),
        &NetworkDefinition::simulator(),
        validator,
        StakePoolId::of(pool),
    )
    .expect("sign");
    let (operator, _) = pool_operator();
    submit_committed(
        c,
        charges,
        build_register_tx(
            &operator,
            pool,
            validator,
            &keypair.public_key(),
            &proof,
            validity_around(c.now()),
        ),
    );
}

/// A delegation through a stake pool contract folds into the beacon
/// state — the control plane's whole rail, driven by contract code.
///
/// The scenarios above assert a witness a *keyholder signed*: the
/// action rides a no-op transaction's plaintext message, so the beacon
/// takes the sender's word for it. This one asserts a witness a *contract
/// emitted*: the delegator's funds actually move into the pool's vault,
/// the pool's code records what happened, and the beacon folds that.
/// Nothing is asserted about the amount by the transaction — the amount
/// is the delta that occurred.
///
/// Every layer between is the same: the same receipt field, the same
/// witness leaves, the same windowed root on the boundary header, the
/// same fold. Only the source differs, which is what makes this the
/// assertion that the source is all that differs.
///
/// # Panics
///
/// Panics if the delegation never commits, or the beacon never folds it
/// within budget.
pub fn delegation_folds_into_beacon_state(c: &mut impl Cluster) {
    warm_up(c);

    let pool = pool_id(STAKE_POOL);
    assert_eq!(
        pool_total_stake(c, pool),
        None,
        "the pool must have no stake before anyone delegates to it",
    );

    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    let (key, delegator) = delegator();
    let tx = build_stake_tx(
        &key,
        delegator,
        pool_at(STAKE_POOL),
        DELEGATION,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, tx);

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the delegation must commit before it can be witnessed; status = {status:?}",
    );

    // The pool's stake is the delegation, in the units the beacon counts:
    // a amount cell is quanta, which is what `Stake` is denominated in,
    // so nothing rescales on the way through.
    assert!(
        c.run_until(epochs(10), |c| pool_total_stake(c, pool)
            == Some(Stake::from_quanta(DELEGATION))),
        "the beacon never folded the delegation; pool stake = {:?}",
        pool_total_stake(c, pool),
    );
    // The delegation moved into the pool's vault and nowhere else.
    world.assert_settles_within(c, &charges, epochs(4), "a delegation");
}

/// What the staking scenario delegates: `MIN_STAKE_FLOOR` plus a
/// remainder that keeps the folded stake from reading as the floor
/// itself, and well inside the delegator's genesis funding.
const DELEGATION: u128 = MIN_STAKE_FLOOR.quanta() + 250_000;

/// Registering a validator against a funded pool seats it in the pool.
///
/// # Panics
///
/// Panics if the deposit or the registration never folds within budget.
pub fn register_validator_pools_a_node(c: &mut impl Cluster) {
    warm_up(c);

    let newcomer = ValidatorId::new(1000);
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        MIN_STAKE_FLOOR.quanta() * 10,
    );
    register(c, &mut charges, pool_at(STAKE_POOL), 9, newcomer);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "registered validator never reached the pool",
    );
    world.assert_settles_within(c, &charges, epochs(4), "a delegation and a registration");
}

/// A registration a pool's stake cannot cover is rejected on the capacity
/// gate, leaving no validator record.
///
/// # Panics
///
/// Panics if the deposit never folds, if the covered registration does not
/// take, or if the uncovered one creates a validator record.
pub fn register_without_capacity_is_rejected(c: &mut impl Cluster) {
    warm_up(c);

    // Funded for one and a half seats at the current price, the first
    // registration takes and the second is the one the capacity gate
    // must refuse.
    let seated = ValidatorId::new(1999);
    let newcomer = ValidatorId::new(2000);
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    let price = c
        .beacon_state()
        .expect("a committed beacon state")
        .min_stake();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        price.quanta() * 3 / 2,
    );
    register(c, &mut charges, pool_at(STAKE_POOL), 10, seated);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, seated)
            == Some(ValidatorStatus::Pooled)),
        "the seat the pool covers must take",
    );

    // The registration itself commits — it is a well-formed action by the
    // pool's own operator, and what refuses it is the beacon's capacity
    // gate rather than anything the transaction did wrong.
    register(c, &mut charges, pool_at(STAKE_POOL), 11, newcomer);
    // Run long enough that the registration has folded; an accepted one
    // would surface within a couple of epochs.
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_status(c, newcomer),
        None,
        "under-capacity registration must not create a validator record",
    );

    // The control, without which the assertion above is satisfied by a
    // rail that carries nothing at all: buy the capacity that was
    // missing and the very next registration takes. A fresh id, because
    // the refused one is not spent — nothing recorded it — but a pool
    // that already holds a record for an id refuses to ask again.
    let funded = ValidatorId::new(2001);
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        MIN_STAKE_FLOOR.quanta() * 2,
    );
    register(c, &mut charges, pool_at(STAKE_POOL), 12, funded);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, funded)
            == Some(ValidatorStatus::Pooled)),
        "a registration against capacity must take",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a refused registration and the one after it",
    );
}

/// Returning part of a staking position drops the pool's effective stake
/// immediately while its total stake holds until the unbond matures.
///
/// The position is an ordinary fungible balance, so unwinding one is an
/// ordinary withdrawal from the delegator's own account handed back to
/// the pool — and what the beacon folds is the pool's own account of
/// what left, not an amount the transaction asserted.
///
/// # Panics
///
/// Panics if the delegation or the return never folds, or if total stake
/// drops before the unbond matures.
pub fn stake_withdraw_drops_effective_stake(c: &mut impl Cluster) {
    warm_up(c);

    let pool = pool_id(STAKE_POOL);
    let delegated = MIN_STAKE_FLOOR.quanta() * 5;
    let returned = MIN_STAKE_FLOOR.quanta() * 2;
    let remaining = Stake::from_quanta(delegated - returned);
    let (key, delegator) = delegator();
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();

    submit_committed(
        c,
        &mut charges,
        build_stake_tx(
            &key,
            delegator,
            pool_at(STAKE_POOL),
            delegated,
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool)
            == Some(Stake::from_quanta(delegated))),
        "the delegation never folded; pool stake = {:?}",
        pool_total_stake(c, pool),
    );

    submit_committed(
        c,
        &mut charges,
        build_unstake_tx(
            &key,
            delegator,
            pool_at(STAKE_POOL),
            returned,
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(8), |c| pool_effective_stake(c, pool)
            == Some(remaining)),
        "the return never dropped effective stake; effective = {:?}",
        pool_effective_stake(c, pool),
    );
    // `total_stake` holds through the unbonding window; only `effective_stake`
    // drops immediately.
    assert_eq!(
        pool_total_stake(c, pool),
        Some(Stake::from_quanta(delegated)),
        "total stake must hold until the withdrawal unbonds",
    );
    // The unbond destroys units and moves no protocol resource yet: the pool still
    // holds the whole delegation.
    world.assert_settles_within(c, &charges, epochs(4), "a delegation and its unbond");
}

/// A matured withdrawal ejects a pool's validator; a later deposit
/// reactivates it once capacity returns.
///
/// The whole loop rides the VM rail: a delegation buys the capacity, a
/// registration seats the validator against it, the unstake's unbond
/// matures into the over-capacity sweep, and the re-deposit is what the
/// beacon's reactivation pass promotes from. Nothing asserts an amount
/// by message — every stake figure is what the pool contract recorded.
///
/// # Panics
///
/// Panics if any stage misses its budget: the registration, the matured
/// withdrawal's ejection, or the reactivation.
pub fn withdrawal_ejects_a_validator_that_a_deposit_reactivates(c: &mut impl Cluster) {
    warm_up(c);

    let member = ValidatorId::new(3000);
    let funded = MIN_STAKE_FLOOR.quanta() * 10;
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        funded,
    );
    register(c, &mut charges, pool_at(STAKE_POOL), 13, member);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, member)
            == Some(ValidatorStatus::Pooled)),
        "registered validator never reached the pool",
    );

    // Return most of the position. The unbond leaves total stake in
    // place until it matures; the release then drops the pool below one
    // `min_stake` and the over-capacity sweep deactivates its member.
    let (key, delegator) = delegator();
    let returned = funded - MIN_STAKE_FLOOR.quanta() / 2;
    submit_committed(
        c,
        &mut charges,
        build_unstake_tx(
            &key,
            delegator,
            pool_at(STAKE_POOL),
            returned,
            validity_around(c.now()),
        ),
    );
    let unbond = u32::try_from(UNBONDING_WINDOW_EPOCHS).expect("unbonding window fits u32");
    assert!(
        c.run_until(epochs(unbond + 10), |c| validator_status(c, member)
            == Some(ValidatorStatus::InsufficientStake)),
        "the matured withdrawal never ejected the pool's validator; status = {:?}",
        validator_status(c, member),
    );

    // Buy the capacity back; the beacon's reactivation pass promotes
    // the ejected validator once the pool supports it again.
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        funded,
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, member),
            Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
        )),
        "the deposit never reactivated the ejected validator; status = {:?}",
        validator_status(c, member),
    );
    world.assert_settles_within(c, &charges, epochs(4), "an ejection and a reactivation");
}

/// Selling a pool is transferring its owner badge, and the sale itself is
/// the custody handover: the buyer's presentation operates from then on,
/// and the seller's key stops.
///
/// The buyer's account is funded on the shard the pool does not live on,
/// so the buyer's vote is a cross-shard custody transaction — the badge
/// holdings provisioned as a declared interval from the buyer's shard,
/// the vote leaf written on the pool's — and both legs' chains must
/// carry it.
///
/// # Panics
///
/// Panics if the sale or the buyer's vote misses its budget, if either
/// shard's chain never carries the vote, or if the seller's post-sale
/// vote is not refused.
pub fn pool_transfer_moves_operatorship(c: &mut impl Cluster) {
    warm_up(c);
    let (seller, _) = pool_operator();
    let (buyer_key, buyer) = badge_buyer();
    let world = pool_world(c, [pool_at(GENESIS_POOL)]);
    let mut charges = Charges::default();

    // The sale: an ordinary NF transfer of the badge.
    submit_committed(
        c,
        &mut charges,
        build_badge_sale_tx(&seller, buyer, validity_around(c.now())),
    );

    // The buyer operates, across shards, and both chains carry it. An
    // inert ballot: the disarmed threshold it votes for is the one the
    // cluster already runs under, so the vote proves custody and moves
    // no parameter. The buyer's shard runs the leg presenting the badge
    // and the pool's shard is the core, so the two commit a hop apart
    // and the second is waited for.
    let live = c.beacon_state().expect("a committed beacon state").params;
    let vote = build_reshape_threshold_vote_tx(
        &buyer_key,
        &live,
        u64::MAX,
        Epoch::new(u64::MAX),
        validity_around(c.now()),
    );
    let vote_hash = vote.hash();
    submit_committed(c, &mut charges, vote);
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
    assert!(
        c.run_until(epochs(6), |c| c.chain_fate(left, vote_hash).0.is_some()
            && c.chain_fate(right, vote_hash).0.is_some()),
        "a cross-shard custody vote must commit on both legs: left={:?}, right={:?}",
        c.chain_fate(left, vote_hash).0,
        c.chain_fate(right, vote_hash).0,
    );

    // The seller no longer holds the badge, and the gate says so.
    let stale = build_reshape_threshold_vote_tx(
        &seller,
        &live,
        u64::MAX,
        Epoch::new(u64::MAX),
        validity_around(c.now()),
    );
    let stale_hash = charges.submit(c, stale);
    let status = await_tx_terminal(c, stale_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Reject))
        ),
        "the seller's key must stop operating after the sale; status = {status:?}",
    );
    // Custody moved and protocol resource did not: three prices, and nothing else.
    world.assert_settles_within(c, &charges, epochs(4), "a badge sale and two votes");
}

/// Submit `tx` and wait for it to commit, failing on any other outcome.
///
/// A witness only exists if its transaction settled, so a scenario that
/// waited on the fold alone would report "the beacon never folded it"
/// for a transaction that never ran.
fn submit_committed<C: Cluster>(c: &mut C, charges: &mut Charges, tx: Transaction) {
    let hash = charges.submit(c, tx);
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the action must commit before it can be witnessed; status = {status:?}",
    );
}

/// A pooled validator draws onto the shard once a committee slot frees.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn registered_validator_activates_onto_a_shard(c: &mut impl Cluster) {
    warm_up(c);

    // Register a new validator into a funded pool; with the committee
    // full it parks in the pool. Which pool it joins does not matter to
    // the draw — the committee fills from the pooled set network-wide.
    let newcomer = ValidatorId::new(1000);
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        MIN_STAKE_FLOOR.quanta() * 10,
    );
    register(c, &mut charges, pool_at(STAKE_POOL), 9, newcomer);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "newcomer never reached the pool",
    );

    // Retire a genesis validator through its own pool's operator. The
    // freed committee slot draws the only pooled validator — the
    // newcomer — onto the shard. It enters `OnShard { ready: false }`;
    // the ready flip follows later via the shard's `Ready` witness, which
    // this host-less validator never drives, so the placement is the
    // activation milestone.
    let (operator, _) = pool_operator();
    submit_committed(
        c,
        &mut charges,
        build_deactivate_tx(
            &operator,
            pool_at(GENESIS_POOL),
            ValidatorId::new(0),
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::OnShard { .. })
        )),
        "newcomer never drew onto the shard after a slot freed",
    );
    world.assert_settles_within(c, &charges, epochs(4), "a registration and a retirement");
}

/// A validator id another pool already registered is dead: the record
/// keeps its first key, whoever asks for it next.
///
/// The claim needs two pools to state. A pool refuses to register an id
/// it already holds — the record under its own prefix says it does — so
/// the only party that can ask for a live id is a pool that has never
/// seen it, and what refuses *that* is the beacon's rule that an id is
/// spent for the life of the chain.
///
/// # Panics
///
/// Panics if the first registration never folds, or if the second
/// overwrites the existing record.
pub fn re_registration_of_a_live_validator_is_a_no_op(c: &mut impl Cluster) {
    warm_up(c);

    let id = ValidatorId::new(1000);
    let first = dummy_pubkey(c, 9);
    let capacity = MIN_STAKE_FLOOR.quanta() * 10;
    let world = pool_world(c, [pool_at(STAKE_POOL), pool_at(SECOND_POOL)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        capacity,
    );
    delegate(
        c,
        &mut charges,
        pool_at(SECOND_POOL),
        pool_id(SECOND_POOL),
        capacity,
    );

    register(c, &mut charges, pool_at(STAKE_POOL), 9, id);
    assert!(
        c.run_until(epochs(8), |c| validator_pubkey(c, id) == Some(first)),
        "validator never registered",
    );

    // A second pool, funded and with capacity to spare, claims the same
    // id under a different key. The id is dead, so the record stands.
    register(c, &mut charges, pool_at(SECOND_POOL), 99, id);
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_pubkey(c, id),
        Some(first),
        "a second pool's claim must not overwrite the existing record",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "two delegations and two registrations",
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

    // Fund the pool for exactly three validators at the floor.
    let candidates = [
        ValidatorId::new(1000),
        ValidatorId::new(1001),
        ValidatorId::new(1002),
        ValidatorId::new(1003),
    ];
    let world = pool_world(c, [pool_at(STAKE_POOL)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL),
        pool_id(STAKE_POOL),
        MIN_STAKE_FLOOR.quanta() * 3,
    );

    // Four registrations against capacity three: every one is a valid
    // action by the pool's own operator, and exactly three take.
    for (i, id) in candidates.iter().enumerate() {
        let offset = u8::try_from(i).expect("candidate index fits u8");
        register(c, &mut charges, pool_at(STAKE_POOL), 20 + offset, *id);
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
    world.assert_settles_within(c, &charges, epochs(4), "four registrations against three");
}

/// A newcomer founds its own pool in one sponsored transaction.
///
/// The newcomer signs it and a sponsor funds and pays for it: the pool's
/// bring-up stakes the sponsor's funds and registers the newcomer's validator
/// in the node that makes the pool actual, the beacon folds both under
/// the pool's address, and the pool's owner badge lands in the newcomer's
/// account.
///
/// # Panics
///
/// Panics if the founding does not commit, the beacon never pools the
/// validator under the founded pool's address with the founding stake, or
/// the badge is not in the founder's account.
pub fn a_newcomer_founds_its_own_pool(c: &mut impl Cluster) {
    warm_up(c);
    let (_, founder) = newcomer_founder();
    let pool = founded_id(founder);
    let validator = ValidatorId::new(1000);
    assert_eq!(
        pool_total_stake(c, pool),
        None,
        "no pool stands at the founder's address before it founds one",
    );
    let world = pool_world(c, [founded_at(founder)]);
    let mut charges = Charges::default();

    let founding = found(c, &mut charges, 9, validator);
    await_pooled(c, validator, "the founded pool's first validator");
    let record = c
        .beacon_state()
        .and_then(|s| s.validators.get(&validator).map(|r| r.pool));
    assert_eq!(
        record,
        Some(pool),
        "the validator is the founded pool's, keyed by its address",
    );
    assert_eq!(
        pool_total_stake(c, pool),
        Some(Stake::from_quanta(founding)),
        "the founded pool holds the founding stake",
    );
    assert!(
        holds_instance(
            c,
            founder.address(),
            pool_owner_badge(founded_at(founder)),
            OWNER_BADGE_ID,
        ),
        "the founded pool's owner badge is in the founder's account",
    );
    world.assert_settles_within(c, &charges, epochs(4), "a founding");
}

/// A founded pool seats another validator only once its stake covers it.
///
/// A join into a pool whose stake covers the seats it holds commits and
/// is refused at the beacon's capacity gate: the pool registers whoever
/// its badge holder names, and what refuses the seat is the beacon. Once
/// a delegation covers another seat, the next join takes.
///
/// # Panics
///
/// Panics if any transaction does not commit, if the uncovered join
/// creates a validator record, or if the covered one never pools.
pub fn a_founded_pool_seats_another_validator_once_its_stake_covers_it(c: &mut impl Cluster) {
    warm_up(c);
    let (_, founder) = newcomer_founder();
    let pool = founded_id(founder);
    let world = pool_world(c, [founded_at(founder)]);
    let mut charges = Charges::default();
    found(c, &mut charges, 9, ValidatorId::new(1000));
    await_pooled(
        c,
        ValidatorId::new(1000),
        "the founded pool's first validator",
    );

    let uncovered = ValidatorId::new(1001);
    join(c, &mut charges, 10, uncovered);
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_status(c, uncovered),
        None,
        "a join the pool's stake cannot cover must not create a validator record",
    );

    // A fresh id, because the refused join spent its own in the pool's
    // record.
    let covering = shortfall(c, pool, 2);
    let expected = pool_total_stake(c, pool)
        .unwrap_or(Stake::ZERO)
        .saturating_add(Stake::from_quanta(covering));
    let (key, from) = delegator();
    submit_committed(
        c,
        &mut charges,
        build_founded_stake_tx(&key, from, founder, covering, validity_around(c.now())),
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool) == Some(expected)),
        "the delegation never folded; pool stake = {:?}",
        pool_total_stake(c, pool),
    );
    let covered = ValidatorId::new(1002);
    join(c, &mut charges, 11, covered);
    await_pooled(c, covered, "the covered second validator");
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a founding, two joins and a delegation",
    );
}

/// [`newcomer_founder`]'s founding of its own pool with `validator`, keyed
/// by `seed`, staked one seat at the price the beacon holds now, plus
/// [`seat_slack`]; returns the founding stake.
fn found<C: Cluster>(c: &mut C, charges: &mut Charges, seed: u8, validator: ValidatorId) -> u128 {
    let (founder_key, founder) = newcomer_founder();
    let (sponsor, _) = delegator();
    let (pubkey, proof) = founded_validator(c, seed, validator, founder);
    let amount = shortfall(c, founded_id(founder), 1);
    submit_committed(
        c,
        charges,
        build_found_tx(
            &sponsor,
            &founder_key,
            validator,
            &pubkey,
            &proof,
            amount,
            validity_around(c.now()),
        ),
    );
    amount
}

/// [`newcomer_founder`]'s join of `validator`, keyed by `seed`, to the pool
/// it founded, sponsored by the delegator's account.
fn join<C: Cluster>(c: &mut C, charges: &mut Charges, seed: u8, validator: ValidatorId) {
    let (founder_key, founder) = newcomer_founder();
    let (sponsor, _) = delegator();
    let (pubkey, proof) = founded_validator(c, seed, validator, founder);
    submit_committed(
        c,
        charges,
        build_join_tx(
            &sponsor,
            &founder_key,
            validator,
            &pubkey,
            &proof,
            validity_around(c.now()),
        ),
    );
}

/// The key `seed` derives under the cluster's scheme and its proof of
/// possession as `validator` of `founder`'s founded pool.
fn founded_validator(
    c: &impl Cluster,
    seed: u8,
    validator: ValidatorId,
    founder: PrincipalAddr,
) -> (ConsensusPublicKey, ConsensusSignature) {
    let keypair = c.signer_from_seed(&[seed; 32]);
    let proof = validator_possession_proof_sign(
        keypair.as_ref(),
        &NetworkDefinition::simulator(),
        validator,
        founded_id(founder),
    )
    .expect("sign");
    (keypair.public_key(), proof)
}

/// What `pool` lacks to cover `seats` at the `min_stake` the beacon holds
/// now, plus [`seat_slack`].
fn shortfall(c: &impl Cluster, pool: StakePoolId, seats: u128) -> u128 {
    let price = c
        .beacon_state()
        .expect("a committed beacon state")
        .min_stake();
    let held = pool_effective_stake(c, pool).unwrap_or(Stake::ZERO);
    (price.quanta() * seats + seat_slack(price)).saturating_sub(held.quanta())
}

/// What a founded pool is staked past the seats it covers: a tenth of a
/// seat, so a `min_stake` that moves between reading it and the fold
/// still finds every seat covered, and never a whole further seat.
const fn seat_slack(price: Stake) -> u128 {
    price.quanta() / 10
}

/// Wait until the beacon pools `validator`.
///
/// # Panics
///
/// Panics if it never does within budget.
fn await_pooled<C: Cluster>(c: &mut C, validator: ValidatorId, what: &str) {
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, validator)
            == Some(ValidatorStatus::Pooled)),
        "{what} never reached the pool; status = {:?}",
        validator_status(c, validator),
    );
}

/// A newcomer seated and signing whose host then goes away for good
/// is jailed, and the network carries on without it.
///
/// While it sits silent in the beacon committee each epoch still commits
/// within one SPC view timeout of its start; once it is jailed the shard
/// keeps committing and no draw seats the dead validator again.
///
/// # Panics
///
/// Panics if the newcomer is never seated ready, if an epoch it sits
/// through silent commits a view timeout late, if it is not jailed once its
/// host is gone or is seated again, or if the shard stops committing.
pub fn an_offline_newcomer_leaves_the_network_live(c: &mut impl RestartableCluster) {
    let newcomer = seat_the_staged_newcomer(c);
    let host = c.host_of(newcomer).expect("the newcomer has a host");
    c.stop_host(host, epochs(100_000));
    let crashed_at = c.beacon_state().map(|s| s.current_epoch);

    // Every epoch the silent newcomer sits through commits within one SPC
    // view timeout of its start: its missing input costs the committee a
    // bounded wait, not a view.
    let windows = epoch_windows(c).expect("a committed beacon state");
    while matches!(
        validator_status(c, newcomer),
        Some(ValidatorStatus::OnShard { .. })
    ) {
        let Some(next) = beacon_epoch(c).map(|epoch| epoch.inner() + 1) else {
            break;
        };
        if !c.run_until(epochs(2), |c| {
            beacon_epoch(c).is_some_and(|e| e.inner() >= next)
        }) {
            break;
        }
        let start = Duration::from_millis(windows.window_of(Epoch::new(next)).start.as_millis());
        let lag = c.now().saturating_sub(start);
        assert!(
            lag < SPC_VIEW_TIMEOUT,
            "epoch {next} committed {lag:?} past its start with the newcomer silent; \
             a silent member must cost less than a view timeout",
        );
    }
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::Jailed { .. })
        )),
        "the newcomer was never jailed after its host went away at {crashed_at:?}; \
         status = {:?}, beacon at {:?}",
        validator_status(c, newcomer),
        c.beacon_state().map(|s| s.current_epoch),
    );
    for _ in 0..10 {
        let height = c.committed_height(ShardId::ROOT);
        assert!(
            c.run_until(epochs(3), |c| c.committed_height(ShardId::ROOT) > height),
            "the shard stopped committing at {height:?}",
        );
        assert!(
            !matches!(
                validator_status(c, newcomer),
                Some(ValidatorStatus::OnShard { .. })
            ),
            "a draw seated the dead newcomer again; status = {:?}",
            validator_status(c, newcomer),
        );
    }
}

/// A timed out newcomer is let back in from its own host, seated nowhere.
///
/// It founded its own pool from an account of its own; that account
/// signs the unjail, and the newcomer's host submits it.
///
/// # Panics
///
/// As [`time_out_a_founding_newcomer`], or if the unjail never returns the
/// newcomer to the pool.
pub fn a_timed_out_newcomer_is_let_back_in_from_its_own_host<C: RestartableCluster>(c: &mut C) {
    let (founder_key, founder) = newcomer_founder();
    let (newcomer, host) = time_out_a_founding_newcomer(c, true);
    let attempt = |c: &mut C| {
        let unjail = build_unjail_tx(
            &founder_key,
            founded_at(founder),
            newcomer,
            validity_around(c.now()),
        );
        c.submit_at_host(host, Arc::new(unjail));
    };
    let_back_in(c, newcomer, attempt);
}

/// A timed out newcomer whose pool's owner holds nothing is let back in by
/// an unjail it declares and a sponsor composes and pays for.
///
/// # Panics
///
/// As [`time_out_a_founding_newcomer`], or if the sponsored unjail never
/// returns the newcomer to the pool.
pub fn a_timed_out_newcomer_is_let_back_in_by_a_sponsored_intent<C: RestartableCluster>(c: &mut C) {
    let (founder_key, founder) = newcomer_founder();
    let (newcomer, _) = time_out_a_founding_newcomer(c, false);
    let (sponsor_key, _) = delegator();
    let attempt = |c: &mut C| {
        let unjail = build_sponsored_unjail_tx(
            &sponsor_key,
            &founder_key,
            founded_at(founder),
            newcomer,
            validity_around(c.now()),
        );
        c.submit(Arc::new(unjail));
    };
    let_back_in(c, newcomer, attempt);
}

/// Seat the staged newcomer in the pool it founds, its founder funded for
/// its own fees when `funded`; stop its host until it is jailed; bring the
/// host back; and wait until its time-out is over and the host, its loop
/// retired, is seated nowhere. Returns the newcomer and its host.
///
/// # Panics
///
/// Panics if the newcomer is never seated ready, is not jailed while its
/// host is down, its host never comes back or keeps a shard loop, or its
/// time-out never ends.
fn time_out_a_founding_newcomer(
    c: &mut impl RestartableCluster,
    funded: bool,
) -> (ValidatorId, usize) {
    let (_, founder) = newcomer_founder();
    let pool = founded_id(founder);
    let newcomer = seat_the_staged_newcomer(c);
    if funded {
        let (key, from) = delegator();
        c.submit(Arc::new(build_transfer_tx(
            &key,
            from,
            founder,
            FOUNDER_FUNDING,
            validity_around(c.now()),
        )));
    }
    let host = c.host_of(newcomer).expect("the newcomer has a host");
    c.stop_host(host, epochs(12));
    assert!(
        c.run_until(epochs(12), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::Jailed { .. })
        )),
        "the newcomer was never jailed while its host was down; status = {:?}",
        validator_status(c, newcomer),
    );
    assert!(
        c.run_until(epochs(16), |c| c.is_up(host)),
        "the newcomer's host never came back",
    );
    assert!(
        c.run_until(epochs(40), |c| c
            .beacon_state()
            .is_some_and(|s| s.unjail_refusal(newcomer, pool).is_none())),
        "the newcomer's time-out never ended; refusal = {:?}",
        c.beacon_state()
            .and_then(|s| s.unjail_refusal(newcomer, pool)),
    );
    // The placement scan retires the jailed newcomer's loop; from then on
    // its host is seated nowhere.
    assert!(
        c.run_until(epochs(40), |c| live_shards(c)
            .iter()
            .all(|&shard| c.host_committed_height(host, shard).is_none())),
        "the jailed newcomer's host kept a shard loop",
    );
    (newcomer, host)
}

/// Make `attempt` until `newcomer` is back in the pool.
///
/// # Panics
///
/// Panics if it never is.
fn let_back_in<C: RestartableCluster>(c: &mut C, newcomer: ValidatorId, attempt: impl Fn(&mut C)) {
    let back = |c: &C| {
        matches!(
            validator_status(c, newcomer),
            Some(
                ValidatorStatus::Pooled
                    | ValidatorStatus::Observing { .. }
                    | ValidatorStatus::OnShard { .. }
            )
        )
    };
    for _ in 0..UNJAIL_ATTEMPTS {
        attempt(c);
        if c.run_until(epochs(4), back) {
            return;
        }
    }
    panic!(
        "the unjail never returned the newcomer to the pool; status = {:?}",
        validator_status(c, newcomer),
    );
}

/// Submissions of the unjail before the scenario gives up: the host binds
/// its peers again after its restart, and a submission before that reaches
/// nobody.
const UNJAIL_ATTEMPTS: usize = 4;

/// The host carrying every genesis validator restarts beside a seated
/// newcomer, live or gone the same instant, and the network resumes.
///
/// After the restart the beacon folds past it and the shard commits again.
///
/// # Panics
///
/// Panics if the newcomer is never seated ready, the restarted host
/// never comes back, or the beacon or the shard stays stopped after it.
pub fn a_restarted_genesis_host_resumes_beside_a_newcomer(
    c: &mut impl RestartableCluster,
    newcomer_gone: bool,
) {
    let newcomer = seat_the_staged_newcomer(c);
    if newcomer_gone {
        let host = c.host_of(newcomer).expect("the newcomer has a host");
        c.stop_host(host, epochs(100_000));
    }
    let genesis = c.host_of(ValidatorId::new(0)).expect("genesis has a host");
    c.stop_host(genesis, epochs(1));
    assert!(
        c.run_until(epochs(4), |c| c.is_up(genesis)),
        "the genesis host never came back",
    );
    let epoch = beacon_epoch(c);
    let height = c.committed_height(ShardId::ROOT);
    assert!(
        c.run_until(epochs(8), |c| beacon_epoch(c)
            > epoch.map(|e| e.saturating_add(2))),
        "the beacon never folded past {epoch:?} after the restart; at {:?}, newcomer {:?}",
        beacon_epoch(c),
        validator_status(c, newcomer),
    );
    for _ in 0..5 {
        let before = c.committed_height(ShardId::ROOT);
        assert!(
            c.run_until(epochs(3), |c| c.committed_height(ShardId::ROOT) > before),
            "the shard stopped committing at {before:?} after the restart from {height:?}",
        );
    }
}

/// Seat the cluster's one staged validator in the pool it founds from
/// [`newcomer_founder`]'s account, wait until it is seated ready, and let
/// it sign a few epochs; returns its id.
fn seat_the_staged_newcomer(c: &mut impl Cluster) -> ValidatorId {
    warm_up(c);
    let staged = c.staged_validators();
    let [(newcomer, _)] = staged[..] else {
        panic!(
            "this scenario stages exactly one newcomer, not {}",
            staged.len()
        );
    };
    found_staged(c, &newcomer_founder().0);
    assert!(
        c.run_until(epochs(60), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::OnShard { ready: true, .. })
        )),
        "the newcomer was never seated ready; status = {:?}",
        validator_status(c, newcomer),
    );
    c.run_until(epochs(3), |_| false);
    newcomer
}
