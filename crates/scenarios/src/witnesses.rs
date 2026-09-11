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

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    ComponentAddr, ConsensusPublicKey, Epoch, MIN_STAKE_FLOOR, NetworkDefinition, ShardId, Stake,
    StakePoolId, Transaction, TransactionDecision, TransactionStatus, UNBONDING_WINDOW_EPOCHS,
    ValidatorId, ValidatorStatus, validator_possession_proof_sign,
};

use crate::support::conservation::{Charges, World};
use crate::support::query::{
    pool_effective_stake, pool_total_stake, validator_pubkey, validator_status,
};
use crate::support::tx::{
    GENESIS_POOL_ID, SECOND_POOL_ID, STAKE_POOL_ID, badge_buyer, build_badge_sale_tx,
    build_deactivate_tx, build_register_tx, build_reshape_threshold_vote_tx, build_stake_tx,
    build_unstake_tx, delegator, pool_at, pool_operator, pool_vault_cell, validity_around,
};
use crate::support::wait::{await_beacon_epoch, await_tx_terminal};
use crate::support::{Cluster, epochs};

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

    let pool = STAKE_POOL_ID;
    assert_eq!(
        pool_total_stake(c, pool),
        None,
        "the pool must have no stake before anyone delegates to it",
    );

    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    let (key, delegator) = delegator();
    let tx = build_stake_tx(
        &key,
        delegator,
        pool_at(STAKE_POOL_ID),
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

/// What the staking scenario delegates. Large enough that the folded
/// stake cannot be confused with a rounding artefact and small enough to
/// sit well inside the delegator's genesis funding.
const DELEGATION: u128 = 250_000;

/// Registering a validator against a funded pool seats it in the pool.
///
/// # Panics
///
/// Panics if the deposit or the registration never folds within budget.
pub fn register_validator_pools_a_node(c: &mut impl Cluster) {
    warm_up(c);

    let newcomer = ValidatorId::new(1000);
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        MIN_STAKE_FLOOR.quanta() * 10,
    );
    register(c, &mut charges, pool_at(STAKE_POOL_ID), 9, newcomer);
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "registered validator never reached the pool",
    );
    world.assert_settles_within(c, &charges, epochs(4), "a delegation and a registration");
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
    let newcomer = ValidatorId::new(2000);
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        MIN_STAKE_FLOOR.quanta() / 2,
    );

    // The registration itself commits — it is a well-formed action by the
    // pool's own operator, and what refuses it is the beacon's capacity
    // gate rather than anything the transaction did wrong.
    register(c, &mut charges, pool_at(STAKE_POOL_ID), 11, newcomer);
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
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        MIN_STAKE_FLOOR.quanta() * 2,
    );
    register(c, &mut charges, pool_at(STAKE_POOL_ID), 12, funded);
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

    let pool = STAKE_POOL_ID;
    let delegated = MIN_STAKE_FLOOR.quanta() * 5;
    let returned = MIN_STAKE_FLOOR.quanta() * 2;
    let remaining = Stake::from_quanta(delegated - returned);
    let (key, delegator) = delegator();
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();

    submit_committed(
        c,
        &mut charges,
        build_stake_tx(
            &key,
            delegator,
            pool_at(STAKE_POOL_ID),
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
            pool_at(STAKE_POOL_ID),
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
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        funded,
    );
    register(c, &mut charges, pool_at(STAKE_POOL_ID), 13, member);
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
            pool_at(STAKE_POOL_ID),
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
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
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
    let world = pool_world(c, [pool_at(GENESIS_POOL_ID)]);
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
    let vote = build_reshape_threshold_vote_tx(
        &buyer_key,
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
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        MIN_STAKE_FLOOR.quanta() * 10,
    );
    register(c, &mut charges, pool_at(STAKE_POOL_ID), 9, newcomer);
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
            pool_at(GENESIS_POOL_ID),
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
    let world = pool_world(c, [pool_at(STAKE_POOL_ID), pool_at(SECOND_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        capacity,
    );
    delegate(
        c,
        &mut charges,
        pool_at(SECOND_POOL_ID),
        SECOND_POOL_ID,
        capacity,
    );

    register(c, &mut charges, pool_at(STAKE_POOL_ID), 9, id);
    assert!(
        c.run_until(epochs(8), |c| validator_pubkey(c, id) == Some(first)),
        "validator never registered",
    );

    // A second pool, funded and with capacity to spare, claims the same
    // id under a different key. The id is dead, so the record stands.
    register(c, &mut charges, pool_at(SECOND_POOL_ID), 99, id);
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
    let world = pool_world(c, [pool_at(STAKE_POOL_ID)]);
    let mut charges = Charges::default();
    delegate(
        c,
        &mut charges,
        pool_at(STAKE_POOL_ID),
        STAKE_POOL_ID,
        MIN_STAKE_FLOOR.quanta() * 3,
    );

    // Four registrations against capacity three: every one is a valid
    // action by the pool's own operator, and exactly three take.
    for (i, id) in candidates.iter().enumerate() {
        let offset = u8::try_from(i).expect("candidate index fits u8");
        register(c, &mut charges, pool_at(STAKE_POOL_ID), 20 + offset, *id);
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
