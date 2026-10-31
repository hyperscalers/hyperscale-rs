//! Two transactions of one payer whose debits settle apart.
//!
//! A vault promises three things before any of them reaches its settled
//! balance: the fee ceiling of every committed transaction whose price is
//! yet to burn, what a pending member reserved, and what a tick that ran
//! and has not settled already took. Each scenario here submits a second
//! transaction of the payer inside that gap and reports where the pair
//! landed, for [`assert_pair_rule`] to hold it to what a chain owes the
//! pair: if the second committed, both ended and both paid in full.

use std::time::Duration;

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_effects_bridge::vm_statics::package_key;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, PrincipalAddr, ShardId, SubstateKey, TimestampRange,
    TransactionDecision, TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::package_hash;

use crate::route::{
    FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, route_worlds, sponsor, stand_up_venues,
    traders,
};
use crate::straddler::{isolate_crossing_intake, isolate_ec_intake};
use crate::support::conservation::{Charges, World};
use crate::support::query::{declared_price, owning_shard, vault_balance};
use crate::support::tx::{
    MAX_FEE, PUBLISH_MAX_FEE, account_routing_to, build_publish_tx, build_route_paying_out_tx,
    build_sponsored_route_tx, build_transfer_at_max_fee, build_transfer_tx, storm_artifact,
    validity_around,
};
use crate::support::wait::{await_blocks, await_height};
use crate::support::{Budget, Cluster, FaultableCluster, committees_on_separate_hosts};
use crate::venue::grind_onto;

/// The shard holding the payer and the neighbour it pays.
pub const PAYER_SHARD: ShardId = ShardId::leaf(1, 0);

/// The shard holding the recipient of the payer's cross-shard transfer.
pub const REMOTE_SHARD: ShardId = ShardId::leaf(1, 1);

/// What the payer of a pending leg is funded with.
const LEG_FUNDING: u128 = 10_000;

/// What the publisher is funded with: the fee ceilings of its transfer
/// and its publish, which is the least a vault covers the two holds
/// with.
const PUBLISH_FUNDING: u128 = MAX_FEE + PUBLISH_MAX_FEE;

/// Blocks each shard must commit after the pair ends, and the blocks
/// past the first's settlement a second that never commits is watched
/// for.
const BLOCKS_AFTER: u64 = 3;

/// The payer, a neighbour on its shard, and a recipient on the other.
struct Cast {
    payer_key: Ed25519PrivateKey,
    payer: PrincipalAddr,
    neighbour: PrincipalAddr,
    remote: PrincipalAddr,
}

fn cast() -> Cast {
    let mut taken = Vec::new();
    let (payer_key, payer) = account_routing_to(PAYER_SHARD, &mut taken);
    let (_, neighbour) = account_routing_to(PAYER_SHARD, &mut taken);
    let (_, remote) = account_routing_to(REMOTE_SHARD, &mut taken);
    Cast {
        payer_key,
        payer,
        neighbour,
        remote,
    }
}

/// Genesis funding for [`a_payer_spends_beside_its_pending_leg`].
#[must_use]
pub fn pending_leg_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let cast = cast();
    vec![
        (cast.payer, LEG_FUNDING),
        (cast.neighbour, 10),
        (cast.remote, 10),
    ]
}

/// Genesis funding for [`a_payer_publishes_beside_its_unsettled_spend`].
#[must_use]
pub fn publish_beside_spend_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let cast = cast();
    vec![(cast.payer, PUBLISH_FUNDING), (cast.neighbour, 10)]
}

/// The fee ceiling the pending leg signs, and with it what the leg
/// reserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceiling {
    /// The scenario fee terms, well past the leg's price. The leg
    /// reserves everything the payer holds less its own ceiling and the
    /// ceiling of the spend beside it, so the vault covers both holds
    /// and the reservation together.
    Roomy,
    /// The leg's own price, so its fee hold is exactly what it burns.
    /// The leg reserves everything the payer holds less that price, and
    /// leaves the spend's ceiling no cover.
    Price,
}

/// What the second transaction moves besides paying its price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    /// One unit.
    Dust,
    /// Everything the vault holds past the pending member's reservation
    /// and price, less the spend's own price.
    Rest,
}

/// Where one transaction landed on the payer's chain.
#[derive(Debug, Clone, Copy)]
pub struct Landed {
    /// The block that committed it.
    pub committed: BlockHeight,
    /// The block that committed its finalization.
    pub settled: BlockHeight,
    /// How it ended.
    pub decision: TransactionDecision,
    /// Its declared price.
    pub price: u128,
}

/// Where a pair of one payer's transactions landed.
#[derive(Debug, Clone, Copy)]
pub struct Pair {
    /// The transaction submitted first.
    pub first: Landed,
    /// The one submitted beside it, or nothing where the payer's chain
    /// had not committed it [`BLOCKS_AFTER`] blocks past the first's
    /// settlement.
    pub second: Option<Landed>,
    /// The payer chain's height when the second was submitted.
    pub pooled: BlockHeight,
    /// What the payer's vault held before either.
    pub funded: u128,
    /// What the bodies that ended accepted moved out of the vault.
    pub moved: u128,
    /// What the vault holds once the pair has landed.
    pub left: u128,
}

/// Hold `pair` to what a chain owes two transactions of one payer.
///
/// If the second committed, both ended and both prices were charged in
/// full: the vault holds what it was funded with, less what the accepted
/// bodies moved and less both prices. Otherwise the second was not
/// committed while the first was pending, and the vault holds what the
/// first alone left. The scenario that built the pair has already held
/// the protocol resource to conservation across it.
///
/// # Panics
///
/// Panics if the vault holds anything else.
pub fn assert_pair_rule(pair: &Pair) {
    let prices = pair.first.price + pair.second.map_or(0, |second| second.price);
    assert_eq!(
        Some(pair.left),
        pair.funded
            .checked_sub(pair.moved)
            .and_then(|left| left.checked_sub(prices)),
        "every transaction of the pair that committed pays its price in full: {pair:?}",
    );
}

fn landed<C: Cluster>(c: &C, shard: ShardId, hash: TxHash, price: u128) -> Option<Landed> {
    let (committed, fate) = c.chain_fate(shard, hash);
    let committed = committed?;
    let (settled, decision) = fate.expect("a committed transaction of a landed pair has ended");
    Some(Landed {
        committed,
        settled,
        decision,
        price,
    })
}

/// What `landed` moved out of the payer's vault, given its body moves
/// `amount` where it is accepted.
fn moved_by(landed: Option<Landed>, amount: u128) -> u128 {
    match landed {
        Some(landed) if landed.decision == TransactionDecision::Accept => amount,
        _ => 0,
    }
}

/// Run until the pair has landed on the payer's chain, the first of
/// `shards`, then until each of them has committed further.
///
/// The first must end. The second is watched for [`BLOCKS_AFTER`] blocks
/// past the block that settled the first: committed by then, it must end
/// too; not committed by then, it never committed while the first was
/// pending.
fn await_pair<C: Cluster>(
    c: &mut C,
    budget: Budget,
    shards: &[ShardId],
    (first, second): (TxHash, TxHash),
    world: &str,
) {
    let payer_shard = shards[0];
    assert!(
        c.run_until(budget, |c| c.chain_fate(payer_shard, first).1.is_some()),
        "{world}: the first of the payer's transactions must end; first = {:?}, second = {:?}",
        c.chain_fate(payer_shard, first),
        c.chain_fate(payer_shard, second),
    );
    let (settled, _) = c
        .chain_fate(payer_shard, first)
        .1
        .expect("the first just ended");
    assert!(
        await_height(c, payer_shard, settled.inner() + BLOCKS_AFTER, budget),
        "{world}: {payer_shard:?} must keep committing once the first has ended",
    );
    if c.chain_fate(payer_shard, second).0.is_some() {
        assert!(
            c.run_until(budget, |c| c.chain_fate(payer_shard, second).1.is_some()),
            "{world}: a second the payer's chain committed must end; first = {:?}, second = {:?}",
            c.chain_fate(payer_shard, first),
            c.chain_fate(payer_shard, second),
        );
    }
    for &shard in shards {
        assert!(
            await_blocks(c, shard, BLOCKS_AFTER, budget),
            "{world}: {shard:?} must keep committing once the pair has landed",
        );
    }
}

/// The payer chain's height now: where a transaction submitted next is
/// pooled.
fn pooled_at<C: Cluster>(c: &C, shard: ShardId) -> BlockHeight {
    c.committed_height(shard)
        .expect("the payer's shard is served")
}

/// A payer that spends beside its own pending cross-shard leg.
///
/// The leg is a transfer to the other shard, signing and reserving what
/// `ceiling` says: the payer's shard runs the withdrawal as a leg that
/// awaits nobody, so its debit is determined by its own tick and settles
/// a few blocks later. Beside it the payer submits a transfer to a
/// neighbour on its own shard, moving `spend`.
///
/// # Panics
///
/// Panics if the leg never ends, if a second transaction the payer's
/// chain committed never ends, if a shard stops committing, or if the
/// protocol resource is not conserved across the pair.
pub fn a_payer_spends_beside_its_pending_leg<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
    ceiling: Ceiling,
    spend: Spend,
    between: impl FnOnce(&mut C, TxHash),
) -> Pair {
    let Cast {
        payer_key,
        payer,
        neighbour,
        remote,
    } = cast();
    let funded = vault_balance(c, PAYER_SHARD, payer);
    assert_eq!(funded, LEG_FUNDING, "the payer holds its genesis funding");
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [payer.address(), neighbour.address(), remote.address()],
        [],
    );
    let mut charges = Charges::default();

    let validity = validity_around(c.now());
    let leg_of = |amount, max_fee| {
        build_transfer_at_max_fee(&payer_key, payer, remote, amount, validity, max_fee)
    };
    let leg_price = declared_price(c, &leg_of(1, MAX_FEE));
    let (max_fee, reserved) = match ceiling {
        Ceiling::Roomy => (MAX_FEE, funded - MAX_FEE - MAX_FEE),
        Ceiling::Price => (leg_price, funded - leg_price),
    };
    let leg = leg_of(reserved, max_fee);
    assert_eq!(
        declared_price(c, &leg),
        leg_price,
        "the leg's price turns on neither its amount nor its ceiling",
    );
    let leg_hash = charges.submit(c, leg);
    between(c, leg_hash);

    let spend_of = |amount, c: &C| {
        build_transfer_tx(
            &payer_key,
            payer,
            neighbour,
            amount,
            validity_around(c.now()),
        )
    };
    let spend_price = declared_price(c, &spend_of(1, c));
    let amount = match spend {
        Spend::Dust => 1,
        Spend::Rest => funded - reserved - leg_price - spend_price,
    };
    let spend_tx = spend_of(amount, c);
    assert_eq!(
        declared_price(c, &spend_tx),
        spend_price,
        "the spend's price does not turn on its amount",
    );
    let pooled = pooled_at(c, PAYER_SHARD);
    // Every member of the payer's committee holds the spend at once: the
    // window it is measured in is the two blocks after the leg's, and a
    // spend that reached the next proposers only by gossip would arrive a
    // hop and a dwell behind wherever the leg's proposer sat.
    let spend_hash = charges.submit_to_committee(c, PAYER_SHARD, &spend_tx);

    let context = format!(
        "a {spend:?} spend of {amount} beside a pending leg of {reserved} under a {ceiling:?} \
         ceiling"
    );
    await_pair(
        c,
        budget,
        &[PAYER_SHARD, REMOTE_SHARD],
        (leg_hash, spend_hash),
        &context,
    );
    let first = landed(c, PAYER_SHARD, leg_hash, leg_price);
    let second = landed(c, PAYER_SHARD, spend_hash, spend_price);
    let pair = Pair {
        first: first.expect("the leg ended"),
        second,
        pooled,
        funded,
        moved: moved_by(first, reserved) + moved_by(second, amount),
        left: vault_balance(c, PAYER_SHARD, payer),
    };
    world.assert_settles_within(c, &charges, budget, &format!("{context}, {pair:?}"));
    pair
}

/// Whose vault a route's core member on the first venue's shard debits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePayer {
    /// A sponsor on the first venue's shard pays the fee of a route a
    /// trader on a third shard pays into: the member burns the fee from
    /// the sponsor's vault and reserves nothing of it.
    Sponsor,
    /// The payer is its own trader and banks the output with its
    /// neighbour: the member reserves the input from the payer's vault
    /// and burns the fee from the same vault. The input is everything
    /// the vault holds less the route's ceiling and the ceiling of the
    /// spend beside it, which is the most the vault covers beside both
    /// holds, and `past` units more.
    Trader {
        /// How far past that cover the route reaches.
        past: u128,
    },
}

/// A payer that spends beside its route's pending core member.
///
/// The route runs through two venues on two shards, so its core spans
/// both and each member's effects wait on the other's certificate. The
/// payer sits on the first venue's shard, where the member debits its
/// vault as `payer` says. Beside the route the payer submits a transfer
/// to a neighbour on that shard, moving `spend`.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the route
/// never ends, if a second transaction the payer's chain committed never
/// ends, if a venue's shard stops committing, or if either side of the
/// pair is not conserved across it.
pub fn a_payer_spends_beside_its_routes_pending_core<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
    payer: RoutePayer,
    spend: Spend,
    between: impl FnOnce(&mut C, TxHash),
) -> Pair {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let (trader_key, trader) = traders(&mut taken).swap_remove(0);
    let (payer_key, payer_account) = sponsor(&mut taken);
    let (_, neighbour) = grind_onto(FIRST_VENUE_SHARD, &mut Vec::new());
    assert_ne!(neighbour, payer_account, "the neighbour is another account");
    let (protocol_resource, units) =
        route_worlds(c, &first, &second, [trader, payer_account, neighbour]);
    let mut charges = Charges::default();

    let funded = vault_balance(c, FIRST_VENUE_SHARD, payer_account);
    let validity = validity_around(c.now());
    let venues = (&first.meta, &second.meta);
    let (route, reserved) = match payer {
        RoutePayer::Sponsor => (
            build_sponsored_route_tx(
                &payer_key,
                &trader_key,
                trader,
                venues,
                ROUTE_INPUT,
                validity,
            ),
            0,
        ),
        RoutePayer::Trader { past } => {
            // The route signs the scenario ceiling, as the spend does.
            let input = funded - MAX_FEE - MAX_FEE + past;
            (
                build_route_paying_out_tx(
                    &payer_key,
                    payer_account,
                    trader,
                    venues,
                    input,
                    validity,
                ),
                input,
            )
        }
    };
    let route_price = declared_price(c, &route);
    let route_hash = charges.submit(c, route);
    between(c, route_hash);

    let spend_of = |amount, c: &C| {
        build_transfer_tx(
            &payer_key,
            payer_account,
            neighbour,
            amount,
            validity_around(c.now()),
        )
    };
    let spend_price = declared_price(c, &spend_of(1, c));
    let amount = match spend {
        Spend::Dust => 1,
        Spend::Rest => funded - reserved - spend_price,
    };
    let spend_tx = spend_of(amount, c);
    assert_eq!(
        declared_price(c, &spend_tx),
        spend_price,
        "the spend's price does not turn on its amount",
    );
    let pooled = pooled_at(c, FIRST_VENUE_SHARD);
    // At every member of the payer's committee at once, so the next
    // proposer holds it after its own dwell rather than a gossip hop
    // later: the window it is measured in is a few blocks wide.
    let spend_hash = charges.submit_to_committee(c, FIRST_VENUE_SHARD, &spend_tx);

    let context = format!(
        "a {spend:?} spend of {amount} beside a route's pending core reserving {reserved} of its \
         {payer:?}'s {funded}",
    );
    await_pair(
        c,
        budget,
        &[FIRST_VENUE_SHARD, SECOND_VENUE_SHARD],
        (route_hash, spend_hash),
        &context,
    );
    let route_landed = landed(c, FIRST_VENUE_SHARD, route_hash, route_price);
    let spend_landed = landed(c, FIRST_VENUE_SHARD, spend_hash, spend_price);
    let pair = Pair {
        first: route_landed.expect("the route ended"),
        second: spend_landed,
        pooled,
        funded,
        moved: moved_by(route_landed, reserved) + moved_by(spend_landed, amount),
        left: vault_balance(c, FIRST_VENUE_SHARD, payer_account),
    };
    let world = format!("{context}, {pair:?}");
    protocol_resource.assert_settles_within(c, &charges, budget, &world);
    units.assert_settles_within(c, &Charges::default(), budget, &world);
    pair
}

/// A payer that publishes beside its own unsettled spend.
///
/// The spend is a transfer to a neighbour on the payer's shard of
/// everything the vault holds less the transfer's price. The publish is
/// of an artifact whose package cell the payer's shard keeps, so the
/// one shard runs it whole. The vault is funded with exactly the two
/// fee ceilings.
///
/// # Panics
///
/// Panics if the transfer never ends, if a publish the payer's chain
/// committed never ends, if a shard stops committing, or if the protocol
/// resource is not conserved across the pair.
pub fn a_payer_publishes_beside_its_unsettled_spend<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
    between: impl FnOnce(&mut C, TxHash),
) -> Pair {
    let Cast {
        payer_key,
        payer,
        neighbour,
        ..
    } = cast();
    let funded = vault_balance(c, PAYER_SHARD, payer);
    assert_eq!(
        funded, PUBLISH_FUNDING,
        "the payer holds its genesis funding"
    );
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [payer.address(), neighbour.address()],
        [],
    );
    let mut charges = Charges::default();

    let validity = validity_around(c.now());
    let spend_of = |amount| build_transfer_tx(&payer_key, payer, neighbour, amount, validity);
    let spend_price = declared_price(c, &spend_of(1));
    let amount = funded - spend_price;
    let spend = spend_of(amount);
    assert_eq!(
        declared_price(c, &spend),
        spend_price,
        "the spend's price does not turn on its amount",
    );
    let artifact = artifact_kept_on(c, PAYER_SHARD);

    // Both at every member of the payer's committee at once, so the next
    // proposer holds each after its own dwell rather than a gossip hop
    // later: the window the publish is measured in is a few blocks wide,
    // and two submitted together reach the same proposer together.
    let spend_hash = charges.submit_to_committee(c, PAYER_SHARD, &spend);
    between(c, spend_hash);
    let publish = build_publish_tx(&payer_key, artifact, validity_around(c.now()));
    let publish_price = declared_price(c, &publish);
    let pooled = pooled_at(c, PAYER_SHARD);
    let publish_hash = charges.submit_to_committee(c, PAYER_SHARD, &publish);

    let context = "a publish beside an unsettled spend";
    await_pair(
        c,
        budget,
        &[PAYER_SHARD, REMOTE_SHARD],
        (spend_hash, publish_hash),
        context,
    );
    let spend_landed = landed(c, PAYER_SHARD, spend_hash, spend_price);
    let pair = Pair {
        first: spend_landed.expect("the spend ended"),
        second: landed(c, PAYER_SHARD, publish_hash, publish_price),
        pooled,
        funded,
        moved: moved_by(spend_landed, amount),
        left: vault_balance(c, PAYER_SHARD, payer),
    };
    world.assert_settles_within(c, &charges, budget, &format!("{context}, {pair:?}"));
    pair
}

/// The first publisher of a contested artifact, the payer that publishes
/// it second, and the neighbour the payer then spends to: all on the
/// payer's shard.
struct Contest {
    rival_key: Ed25519PrivateKey,
    rival: PrincipalAddr,
    payer_key: Ed25519PrivateKey,
    payer: PrincipalAddr,
    neighbour: PrincipalAddr,
}

fn contest() -> Contest {
    let mut taken = Vec::new();
    let (rival_key, rival) = account_routing_to(PAYER_SHARD, &mut taken);
    let (payer_key, payer) = account_routing_to(PAYER_SHARD, &mut taken);
    let (_, neighbour) = account_routing_to(PAYER_SHARD, &mut taken);
    Contest {
        rival_key,
        rival,
        payer_key,
        payer,
        neighbour,
    }
}

/// Genesis funding for
/// [`a_publish_its_packages_shard_refuses_pays_and_ends_its_hold`].
#[must_use]
pub fn contested_publish_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let contest = contest();
    vec![
        (contest.rival, PUBLISH_MAX_FEE),
        (contest.payer, PUBLISH_FUNDING),
        (contest.neighbour, 10),
    ]
}

/// How long the payer's publish stays valid: long enough to commit on
/// both shards, and short enough that its deadline passes while the
/// rival's publish, signed for the widest window, is still in flight.
const CONTESTED_LIFE: Duration = Duration::from_secs(30);

/// A publish its package's shard refuses after the payer's shard
/// completed it still pays, and leaves its payer's vault free.
///
/// Two payers on one shard publish the same artifact, whose package cell
/// the other shard keeps, so each publish runs whole on both shards and
/// either shard can refuse it. The package's shard is cut off from the
/// payers' shard's state and certificates, so it never reads the
/// rival's publish accepted there and its own row stays stated holding
/// the package cell, and the payer's publish, committed behind it,
/// waits on that hold until its deadline and is aborted unrun. The
/// payers' shard reads everything: it accepts the rival's publish, runs
/// the payer's to completion and states it, and then reads the package
/// shard's abort, on which it aborts its own row, discarding what it
/// wrote, the burn and the end of the fee hold among it.
///
/// What a chain owes the payer then is what it owes any refused attempt:
/// the price once, no fee hold left standing for it, and a vault whose
/// whole remaining balance a later transfer can move.
///
/// # Panics
///
/// Panics if the rival's publish is not in flight on the package's shard
/// when the payer's ends, if the payers' shard does not complete the
/// payer's publish, if the package's shard does not abort it, if the
/// payer is not charged its price exactly once, if its fee hold stands,
/// or if a transfer of everything the vault has left does not accept.
pub fn a_publish_its_packages_shard_refuses_pays_and_ends_its_hold<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let Contest {
        rival_key,
        rival,
        payer_key,
        payer,
        neighbour,
    } = contest();
    committees_on_separate_hosts(c, PAYER_SHARD, REMOTE_SHARD);
    let funded = vault_balance(c, PAYER_SHARD, payer);
    assert_eq!(
        funded, PUBLISH_FUNDING,
        "the payer holds its genesis funding"
    );
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [rival.address(), payer.address(), neighbour.address()],
        [],
    );
    let mut charges = Charges::default();
    let artifact = artifact_kept_on(c, REMOTE_SHARD);
    let cell = package_key(package_hash(&ProtocolHasher, &artifact));

    let cut = [
        isolate_ec_intake(c, REMOTE_SHARD, PAYER_SHARD),
        isolate_crossing_intake(c, REMOTE_SHARD, PAYER_SHARD),
    ];
    let first = build_publish_tx(&rival_key, artifact.clone(), validity_around(c.now()));
    let first_hash = charges.submit(c, first);
    assert!(
        c.run_until(budget, |c| c
            .chain_fate(PAYER_SHARD, first_hash)
            .1
            .is_some()
            && c.chain_fate(REMOTE_SHARD, first_hash).0.is_some()),
        "the rival's publish must commit on the package's shard and end on its own; \
         payers = {:?}, package = {:?}",
        c.chain_fate(PAYER_SHARD, first_hash),
        c.chain_fate(REMOTE_SHARD, first_hash),
    );

    let now = c.now();
    let validity = TimestampRange::new(
        validity_around(now).start_timestamp_inclusive,
        WeightedTimestamp::ZERO.plus(now + CONTESTED_LIFE),
    );
    let publish = build_publish_tx(&payer_key, artifact, validity);
    let publish_price = declared_price(c, &publish);
    let publish_hash = charges.submit(c, publish);

    let ended = |c: &C, shard| c.chain_fate(shard, publish_hash).1;
    assert!(
        c.run_until(budget, |c| ended(c, PAYER_SHARD).is_some()
            && ended(c, REMOTE_SHARD).is_some()),
        "the payer's publish must end on both shards; payers = {:?}, package = {:?}",
        c.chain_fate(PAYER_SHARD, publish_hash),
        c.chain_fate(REMOTE_SHARD, publish_hash),
    );
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "the certificates and readings must have been cut",
    );
    assert!(
        c.chain_fate(REMOTE_SHARD, first_hash).1.is_none(),
        "the rival's publish must still be in flight on the package's shard: {:?}",
        c.chain_fate(REMOTE_SHARD, first_hash),
    );
    assert_completed_then_refused(c, publish_hash);
    c.clear_drops();

    let context = "a publish its package's shard refused";
    assert!(
        c.run_until(budget, |c| c
            .chain_fate(REMOTE_SHARD, first_hash)
            .1
            .is_some()),
        "{context}: the rival's publish must end on the package's shard once readings flow",
    );
    world.assert_settles_within(c, &charges, budget, context);
    assert_package_stands_where_accepted(c, first_hash, cell, context);
    let left = vault_balance(c, PAYER_SHARD, payer);
    assert_eq!(
        left,
        funded - publish_price,
        "{context}: the payer is charged the publish's price exactly once",
    );

    spend_all_that_is_left(
        c,
        &mut charges,
        (&payer_key, payer, neighbour),
        budget,
        context,
    );
    world.assert_settles_within(c, &charges, budget, context);
    assert_eq!(
        vault_balance(c, PAYER_SHARD, payer),
        0,
        "{context}: the transfer moved everything the publish left",
    );
}

/// Some storm artifact whose package cell `shard` keeps.
fn artifact_kept_on<C: Cluster>(c: &C, shard: ShardId) -> Vec<u8> {
    (0u16..64)
        .map(storm_artifact)
        .find(|artifact| {
            let cell = package_key(package_hash(&ProtocolHasher, artifact));
            owning_shard(c, cell.owner) == shard
        })
        .unwrap_or_else(|| panic!("no artifact's package cell falls on {shard:?}"))
}

/// Assert the payers' shard attested `publish` completed, the package's
/// shard attested only a refusal of it, and both ended it aborted.
fn assert_completed_then_refused<C: Cluster>(c: &C, publish: TxHash) {
    let ran = c.ran(PAYER_SHARD, publish);
    assert!(
        ran.iter().any(|ran| ran.succeeded),
        "the payers' shard must have completed the publish before it was refused: {ran:?}",
    );
    let refused = c.ran(REMOTE_SHARD, publish);
    assert!(
        !refused.is_empty() && refused.iter().all(|ran| !ran.succeeded),
        "the package's shard must have refused the publish: {refused:?}",
    );
    for shard in [PAYER_SHARD, REMOTE_SHARD] {
        assert_eq!(
            c.chain_fate(shard, publish).1.map(|(_, decision)| decision),
            Some(TransactionDecision::Aborted),
            "{shard:?} ends the publish its package's shard refused as aborted",
        );
    }
}

/// Transfer everything `payer`'s vault holds, less the transfer's own
/// price, to `neighbour`, and assert the payer's chain accepts it.
fn spend_all_that_is_left<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    (payer_key, payer, neighbour): (&Ed25519PrivateKey, PrincipalAddr, PrincipalAddr),
    budget: Budget,
    context: &str,
) {
    let left = vault_balance(c, PAYER_SHARD, payer);
    let spend_of = |amount, c: &C| {
        build_transfer_tx(
            payer_key,
            payer,
            neighbour,
            amount,
            validity_around(c.now()),
        )
    };
    let spend_price = declared_price(c, &spend_of(1, c));
    let spend = spend_of(left - spend_price, c);
    let spend_hash = charges.submit(c, spend);
    assert!(
        c.run_until(budget, |c| c
            .chain_fate(PAYER_SHARD, spend_hash)
            .1
            .is_some()),
        "{context}: a transfer of everything the vault has left must end; {:?}",
        c.chain_fate(PAYER_SHARD, spend_hash),
    );
    assert_eq!(
        c.chain_fate(PAYER_SHARD, spend_hash)
            .1
            .map(|(_, decision)| decision),
        Some(TransactionDecision::Accept),
        "{context}: nothing of the publish still holds the payer's balance",
    );
}

/// Assert `publish` ended alike on both shards, and that `cell`, the
/// package cell it writes, stands exactly where it was accepted.
fn assert_package_stands_where_accepted<C: Cluster>(
    c: &C,
    publish: TxHash,
    cell: SubstateKey,
    context: &str,
) {
    let ended = |shard| c.chain_fate(shard, publish).1.map(|(_, decision)| decision);
    assert_eq!(
        ended(PAYER_SHARD),
        ended(REMOTE_SHARD),
        "{context}: the rival's publish ends alike on both shards",
    );
    assert_eq!(
        c.substate(REMOTE_SHARD, cell.owner, cell.local.0).is_some(),
        ended(REMOTE_SHARD) == Some(TransactionDecision::Accept),
        "{context}: the package stands exactly where a publish of it was accepted",
    );
}
