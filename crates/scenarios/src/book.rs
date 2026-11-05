//! A route through an order book on one shard and a venue on another.
//!
//! The book's fill reads a capped interval of its ladder and writes what
//! it takes, so it is core; the venue's swap is core for the same
//! reason. With the two on different shards the core spans both, and
//! the venue's shard executes the fill over the entries the book's shard
//! provisions it: the interval as the book's committing block left it,
//! cut at the declared cap. What the trader banks is a closed form over
//! the lowest asks of that interval, priced through the venue, so a
//! provision that served other entries than the source committed shows
//! as a payout that is not that figure, or as a route that never settles.

use std::time::Duration;

use hyperscale_effects_bridge::genesis::GenesisPackages;
use hyperscale_effects_bridge::vm_statics::{config_key, crossing_records};
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::RowState;
use hyperscale_types::{
    BlockHeight, ConsensusReceipt, DeclaredRange, Ed25519PrivateKey, MIN_STAKE_FLOOR, Movement,
    NAMING_WINDOW, PrincipalAddr, ProtocolHasher, ResourceAddr, ShardId, SubstateKey,
    TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::{InstanceMeta, SlotId, Value, child_key, collection_id};
use hyperscale_vm_fixtures::book::{self, FILL_CAP};
use hyperscale_vm_sdk::client::VaultField;

use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::straddler::isolate_provision_intake;
use crate::support::conservation::{Charges, World};
use crate::support::query::{declared_price, held, held_at, owning_shard, stands_at};
use crate::support::tx::{
    FILL_TICKS, GENESIS_POOL, ballast_to, book_on, build_book_route_tx, build_fill_asks_tx,
    build_instantiate_tx, build_place_asks_tx, build_stake_tx, departing_target, pool_at,
    validity_around, venue_quote,
};
use crate::support::wait::await_tx_terminal;
use crate::support::{Budget, Cluster, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAPPER_FUNDING, StockedVenue, accepted, grind_onto, reserve_cell,
    stand_up_venue,
};

/// Where the book sits: the route world's second venue shard, which no
/// reshape in these scenarios moves.
pub const BOOK_SHARD: ShardId = SECOND_VENUE_SHARD;

/// Where the venue the route sells into sits: the shard the departing
/// scenarios ballast to split.
pub const BOOK_VENUE_SHARD: ShardId = FIRST_VENUE_SHARD;

/// The base every ask escrows.
const ASK_SIZE: u128 = 100;

/// Asks one placement rests.
const ASKS_PER_PLACEMENT: u64 = 16;

/// Placements the maker makes: enough asks that three routes and the
/// local fills beside them leave more than a fill's cap standing for the
/// last route.
const PLACEMENTS: u64 = 20;

/// What a local fill pays: a few of the cheapest asks' worth, so each
/// one deletes entries the next route's interval would otherwise read.
const LOCAL_FILL: u128 = 20_000;

/// Genesis funding for the book route.
///
/// The venue's quarter is ballasted over the threshold the split
/// scenarios vote in. The venue's provider, the maker and a local taker
/// on the book's shard, and the trader on a shard of its own are ground
/// in the order [`BookRoute::stand_up`] stands them up.
#[must_use]
pub fn book_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let packages = GenesisPackages::with_fixtures();
    let mut accounts = ballast_to(BOOK_VENUE_SHARD, 4, departing_target(&packages), &packages);
    let mut taken = Vec::new();
    accounts.extend([
        (grind_onto(BOOK_VENUE_SHARD, &mut taken).1, PROVIDER_FUNDING),
        (grind_onto(BOOK_SHARD, &mut taken).1, PROVIDER_FUNDING),
        (grind_onto(BOOK_SHARD, &mut taken).1, SWAPPER_FUNDING),
        (grind_onto(TRADER_SHARD, &mut taken).1, SWAPPER_FUNDING),
    ]);
    accounts
}

/// A stocked venue, a book with its ladder rested, the accounts that
/// call them, and the worlds every route and local fill can reach.
pub struct BookRoute {
    venue: StockedVenue,
    book: InstanceMeta,
    /// A taker on the book's shard whose fills run beside the routes.
    local: (Ed25519PrivateKey, PrincipalAddr),
    trader: (Ed25519PrivateKey, PrincipalAddr),
    protocol_resource: World,
    units: World,
    charges: Charges,
}

/// What one route's oracle read: the height of the book's block that
/// served the venue its part, the asks standing in the interval there,
/// and what the route bought and paid.
#[derive(Debug)]
pub struct RouteFill {
    /// The route's hash.
    pub hash: TxHash,
    /// The height of the book's block that made the route's member there
    /// head, which served the venue's shard its part.
    pub source_height: BlockHeight,
    /// The asks standing in the fill's interval at that height.
    pub standing: usize,
    /// The base the capped walk buys.
    pub bought: u128,
    /// The quote it spends.
    pub spent: u128,
}

impl BookRoute {
    /// Stand the venue up, seal the book, rest its ladder, and open the
    /// worlds over everything the routes reach.
    ///
    /// # Panics
    ///
    /// Panics if a quarter is unserved, if any stand-up step misses its
    /// budget or is not accepted, or if the ladder does not read back
    /// whole.
    pub fn stand_up<C: Cluster>(c: &mut C) -> Self {
        assert!(
            (0..4).all(|path| c.serves_shard(ShardId::leaf(2, path))),
            "the grown four-shard topology must seat every quarter",
        );
        let mut taken = Vec::new();
        let venue = stand_up_venue(c, BOOK_VENUE_SHARD, &mut taken);
        let (maker_key, maker) = grind_onto(BOOK_SHARD, &mut taken);
        let local = grind_onto(BOOK_SHARD, &mut taken);
        let trader = grind_onto(TRADER_SHARD, &mut taken);

        let rested = u128::from(ASKS_PER_PLACEMENT * PLACEMENTS) * ASK_SIZE;
        accepted(
            c,
            build_stake_tx(
                &maker_key,
                maker,
                pool_at(GENESIS_POOL),
                MIN_STAKE_FLOOR.quanta(),
                validity_around(c.now()),
            ),
            "the maker must hold the base its asks escrow",
        );
        assert!(
            c.run_until(epochs(8), |c| held(c, maker.address(), venue.unit)
                >= rested),
            "the maker's stake must mint the base its asks escrow",
        );
        let book = book_on(BOOK_SHARD, (venue.unit, *PROTOCOL_RESOURCE));
        accepted(
            c,
            build_instantiate_tx(
                &maker_key,
                std::slice::from_ref(&book),
                validity_around(c.now()),
            ),
            "the book must be sealed before it can be called",
        );
        // A status is reported at the commit, and a call's derivation
        // resolves the book through the seal as its shard has applied it.
        assert!(
            c.run_until(epochs(1), |c| stands_at(
                c,
                config_key(book.address(&ProtocolHasher))
            )),
            "the book's seal must apply on its shard",
        );
        // One ask a tick, from the first: every ask prices apart, so which
        // asks a walk reads decides what it pays.
        for placement in 0..PLACEMENTS {
            let asks: Vec<(u64, u128)> = (1..=ASKS_PER_PLACEMENT)
                .map(|at| (placement * ASKS_PER_PLACEMENT + at, ASK_SIZE))
                .collect();
            accepted(
                c,
                build_place_asks_tx(
                    &maker_key,
                    maker,
                    &book,
                    venue.unit,
                    &asks,
                    validity_around(c.now()),
                ),
                "every placement must rest its asks",
            );
        }
        let total = usize::try_from(ASKS_PER_PLACEMENT * PLACEMENTS).expect("a few hundred asks");
        assert!(
            c.run_until(epochs(1), |c| {
                c.entries(BOOK_SHARD, ladder(&book, u32::MAX))
                    .is_some_and(|asks| asks.len() == total)
            }),
            "the book's ladder must read back every ask rested",
        );

        let holders = [local.1.address(), trader.1.address()];
        let protocol_resource = World::open(
            c,
            *PROTOCOL_RESOURCE,
            holders,
            [
                reserve_cell(&venue.meta, *PROTOCOL_RESOURCE),
                book_vault(&book, BOOK_QUOTE, *PROTOCOL_RESOURCE),
            ],
        );
        let units = World::open(
            c,
            venue.unit,
            holders,
            [
                reserve_cell(&venue.meta, venue.unit),
                book_vault(&book, BOOK_BASE, venue.unit),
            ],
        );
        Self {
            venue,
            book,
            local,
            trader,
            protocol_resource,
            units,
            charges: Charges::default(),
        }
    }

    /// The venue the routes sell into.
    #[must_use]
    pub const fn venue(&self) -> &InstanceMeta {
        &self.venue.meta
    }

    /// The book the routes walk.
    #[must_use]
    pub const fn book(&self) -> &InstanceMeta {
        &self.book
    }

    /// The venue's reserve of the base the book sells, which names the
    /// shard holding the venue wherever a reshape has put it.
    #[must_use]
    pub fn venue_reserve(&self) -> SubstateKey {
        reserve_cell(&self.venue.meta, self.venue.unit)
    }

    /// One route, between a local fill on the book's shard just before it
    /// and one beside it, held to its closed form: the trader banks the
    /// venue's quote for the lowest [`FILL_CAP`] asks the book's block
    /// that served the venue its part left standing, and the change of
    /// the walk over them.
    ///
    /// # Panics
    ///
    /// Panics if the route or a local fill does not accept within
    /// `budget`, if fewer than [`FILL_CAP`] asks stood in the interval at
    /// that block's height, if the venue's shard banks other
    /// base than the book's shard removed from its asks, or if the
    /// venue's reserve or the trader's balance does not settle at the
    /// closed form.
    pub fn run<C: Cluster>(&mut self, c: &mut C, budget: Budget, label: &str) -> RouteFill {
        self.run_scheduled(c, budget, label, Second::Beside)
    }

    /// [`run`](Self::run), with the second local fill submitted only once
    /// the book's shard has committed the route, so it commits after the
    /// route there.
    ///
    /// # Panics
    ///
    /// As [`run`](Self::run) does, and if the book's shard does not
    /// commit the route within `budget`.
    pub fn run_with_a_later_fill<C: Cluster>(
        &mut self,
        c: &mut C,
        budget: Budget,
        label: &str,
    ) -> RouteFill {
        self.run_scheduled(c, budget, label, Second::AfterTheRoute)
    }

    /// [`run`](Self::run), with `fills` more local fills submitted one a
    /// block of the book's shard after the route, so the ladder the route
    /// reads moves under it every block until it heads.
    ///
    /// # Panics
    ///
    /// As [`run`](Self::run) does, and if a streamed fill does not
    /// accept, or the book's shard commits no block within `budget`.
    pub fn run_with_fills_every_block<C: Cluster>(
        &mut self,
        c: &mut C,
        budget: Budget,
        label: &str,
        fills: usize,
    ) -> RouteFill {
        self.run_scheduled(c, budget, label, Second::EveryBlock(fills))
    }

    /// Submit `more` local fills, one each time the book's shard commits
    /// a block, owing each to `charges`.
    fn stream_fills<C: Cluster>(
        (local_key, local): &(Ed25519PrivateKey, PrincipalAddr),
        book: &InstanceMeta,
        charges: &mut Charges,
        c: &mut C,
        budget: Budget,
        more: usize,
    ) -> Vec<TxHash> {
        let mut streamed = Vec::with_capacity(more);
        for at in 0..more {
            let tip = c.committed_height(BOOK_SHARD);
            assert!(
                c.run_until(budget, |c| c.committed_height(BOOK_SHARD) > tip),
                "the book's shard must commit a block for each streamed fill",
            );
            let fill = build_fill_asks_tx(
                local_key,
                *local,
                book,
                *PROTOCOL_RESOURCE,
                LOCAL_FILL + 2 + u128::try_from(at).expect("a few fills"),
                validity_around(c.now()),
            );
            streamed.push(charges.submit(c, fill));
        }
        streamed
    }

    fn run_scheduled<C: Cluster>(
        &mut self,
        c: &mut C,
        budget: Budget,
        label: &str,
        second: Second,
    ) -> RouteFill {
        let (trader_key, trader) = &self.trader;
        let (local_key, local) = &self.local;
        let unit_reserve = reserve_cell(&self.venue.meta, self.venue.unit);
        let quote_reserve = reserve_cell(&self.venue.meta, *PROTOCOL_RESOURCE);
        let reserves = (held_at(c, unit_reserve), held_at(c, quote_reserve));
        let funded = held(c, trader.address(), *PROTOCOL_RESOURCE);

        // Two budgets, so the two fills built at one instant are two
        // transactions.
        let fill = |budget| {
            build_fill_asks_tx(
                local_key,
                *local,
                &self.book,
                *PROTOCOL_RESOURCE,
                budget,
                validity_around(c.now()),
            )
        };
        let before = fill(LOCAL_FILL);
        let route = build_book_route_tx(
            trader_key,
            *trader,
            (&self.book, &self.venue.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            validity_around(c.now()),
        );
        let beside = fill(LOCAL_FILL + 1);
        let price = declared_price(c, &route);
        let records = crossing_records(
            &c.with_derivation(|derivation| route.try_derived(derivation))
                .expect("a scenario route derives")
                .legs,
        );
        self.protocol_resource.owing(records.iter().copied());
        self.units.owing(records);

        let before = self.charges.submit(c, before);
        let hash = self.charges.submit(c, route);
        if second == Second::AfterTheRoute {
            assert!(
                c.run_until(budget, |c| c.chain_fate(BOOK_SHARD, hash).0.is_some()),
                "{label}: the book's shard must commit the route before the later fill",
            );
        }
        let beside = self.charges.submit(c, beside);
        let mut submitted = vec![
            ("route", hash),
            ("fill before", before),
            ("fill beside", beside),
        ];
        if let Second::EveryBlock(more) = second {
            submitted.extend(
                Self::stream_fills(&self.local, &self.book, &mut self.charges, c, budget, more)
                    .into_iter()
                    .map(|tx| ("streamed fill", tx)),
            );
        }
        accept_all(c, &submitted, budget, label);

        // The venue's member shares the core's verdict, so the book's
        // shard serves it from the block that makes the book's member
        // head: the ladder that block left is the one both walk.
        let venue_shard = owning_shard(c, unit_reserve.owner);
        assert!(
            c.run_until(budget, |c| c
                .served_at(BOOK_SHARD, venue_shard, hash)
                .is_some()),
            "{label}: the venue's shard must commit the book's part of the route",
        );
        let source_height = c
            .served_at(BOOK_SHARD, venue_shard, hash)
            .unwrap_or_else(|| panic!("{label}: the venue's shard committed the book's part"));
        let standing = c
            .entries_at(BOOK_SHARD, ladder(&self.book, u32::MAX), source_height)
            .unwrap_or_else(|| panic!("{label}: the book's shard holds {source_height:?}"));
        assert!(
            standing.len() > FILL_CAP as usize,
            "{label}: more asks than the fill's cap must stand at {source_height:?}, \
             or the cap bites nothing: {}",
            standing.len(),
        );
        self.assert_one_base(c, hash, budget, label);

        let (bought, spent) = capped_walk(&standing, ROUTE_INPUT);
        let out = venue_quote(reserves, bought);
        let banked = funded - ROUTE_INPUT - price + (ROUTE_INPUT - spent) + out;
        let settled = |c: &C| {
            held_at(c, unit_reserve) == reserves.0 + bought
                && held(c, trader.address(), *PROTOCOL_RESOURCE) == banked
        };
        assert!(
            c.run_until(budget, settled),
            "{label}: the route must settle at the lowest {FILL_CAP} asks standing at \
             {source_height:?}: the venue's base reserve {} against {}, the trader's balance \
             {} against {banked} (bought {bought}, spent {spent}, payout {out}, price {price})",
            held_at(c, unit_reserve),
            reserves.0 + bought,
            held(c, trader.address(), *PROTOCOL_RESOURCE),
        );
        RouteFill {
            hash,
            source_height,
            standing: standing.len(),
            bought,
            spent,
        }
    }

    /// Assert the route's two core members banked one base: what the
    /// venue's shard credits the venue's base reserve is what the book's
    /// shard takes out of the book's base vault, the asks its own walk
    /// removed.
    ///
    /// Each shard certifies its own projection of the core, and a leaf
    /// carries no content, so two members that walked two ladders both
    /// settle, and the difference between their walks is base minted or
    /// burned. Only the two receipts side by side name it.
    fn assert_one_base<C: Cluster>(&self, c: &mut C, hash: TxHash, budget: Budget, label: &str) {
        let unit_reserve = reserve_cell(&self.venue.meta, self.venue.unit);
        let book_base = book_vault(&self.book, BOOK_BASE, self.venue.unit);
        let venue_shard = owning_shard(c, unit_reserve.owner);
        assert!(
            c.run_until(budget, |c| {
                c.receipt(BOOK_SHARD, hash).is_some() && c.receipt(venue_shard, hash).is_some()
            }),
            "{label}: the book's shard and the venue's {venue_shard:?} must each settle the route \
             under a receipt",
        );
        let moved = |shard, cell| {
            let receipt = c
                .receipt(shard, hash)
                .expect("a receipt once held stays held");
            match receipt.as_ref() {
                ConsensusReceipt::Succeeded { writes, .. } => writes
                    .movements
                    .get(&cell)
                    .copied()
                    .unwrap_or_else(|| Movement::none(self.venue.unit)),
                ConsensusReceipt::Failed => {
                    panic!("{label}: {shard:?} settled an accepted route as failed")
                }
            }
        };
        let removed = moved(BOOK_SHARD, book_base);
        let banked = moved(venue_shard, unit_reserve);
        assert!(
            removed.credit == 0
                && banked.debit == 0
                && removed.unjudged_debit == 0
                && banked.unjudged_debit == 0
                && removed.debit == banked.credit,
            "{label}: the venue's shard banks {} base and the book's shard removed {} from its \
             asks: the two members of one core walked two ladders (book vault {removed:?}, venue \
             reserve {banked:?})",
            banked.credit,
            removed.debit,
        );
    }

    /// Assert both worlds settle across every route and local fill run.
    ///
    /// # Panics
    ///
    /// Panics if either world does not settle within `budget`.
    pub fn assert_conserved<C: Cluster>(&self, c: &mut C, budget: Budget) {
        self.protocol_resource.assert_settles_within(
            c,
            &self.charges,
            budget,
            "the book route's quote",
        );
        self.units
            .assert_settles_within(c, &Charges::default(), budget, "the book route's base");
    }
}

/// A route the book's own taker paid for, standing head of the book's
/// queue, and a local fill it refused there.
#[derive(Debug)]
struct HeldLadder {
    route: TxHash,
    fill: TxHash,
    /// When the book's shard first showed the route refusing the fill.
    blocked_at: WeightedTimestamp,
    /// When the fill committed on the book's shard.
    fill_committed: WeightedTimestamp,
}

impl BookRoute {
    /// Submit a route the book's local taker pays for, so the book's
    /// member is the payer's core and is placed at its commit, and once
    /// the book's shard holds it head of its queue, a local fill on the
    /// ladder behind it. Answers with the two once the fill has
    /// committed and the route stands refusing it.
    ///
    /// # Panics
    ///
    /// Panics if the route never stands head on the book's shard, or if
    /// the fill does not commit there behind it within `budget`.
    fn hold_the_ladder<C: Cluster>(
        &mut self,
        c: &mut C,
        budget: Budget,
        label: &str,
    ) -> HeldLadder {
        let (key, taker) = &self.local;
        let route = build_book_route_tx(
            key,
            *taker,
            (&self.book, &self.venue.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            validity_around(c.now()),
        );
        let records = crossing_records(
            &c.with_derivation(|derivation| route.try_derived(derivation))
                .expect("a scenario route derives")
                .legs,
        );
        self.protocol_resource.owing(records.iter().copied());
        self.units.owing(records);
        let route = self.charges.submit(c, route);
        let head = |c: &C| {
            c.queued_rows(BOOK_SHARD).is_some_and(|rows| {
                rows.get(&route)
                    .is_some_and(|row| row.state == RowState::Pending && row.head.is_some())
            })
        };
        assert!(
            c.run_until(budget, head),
            "{label}: the book's shard must hold the route head of its queue",
        );
        let fill = build_fill_asks_tx(
            key,
            *taker,
            &self.book,
            *PROTOCOL_RESOURCE,
            LOCAL_FILL,
            validity_around(c.now()),
        );
        let fill = self.charges.submit(c, fill);
        let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
        let refused = |c: &C| {
            c.queued_rows(BOOK_SHARD).and_then(|rows| {
                let waiting = rows
                    .get(&fill)
                    .is_some_and(|row| row.state == RowState::Pending);
                rows.get(&route)
                    .filter(|row| waiting && row.state == RowState::Pending)
                    .and_then(|row| row.blocked_at)
            })
        };
        assert!(
            c.run_until(budget, |c| refused(c).is_some()),
            "{label}: the fill must commit and wait behind the route",
        );
        HeldLadder {
            route,
            fill,
            blocked_at: refused(c).expect("the route refuses the fill"),
            fill_committed: clock(c),
        }
    }

    /// Assert `held`'s route leaves the book's shard by an abort at its
    /// naming window, unnamed, and the fill behind it is named and
    /// accepted within the window and a finalization's slack of being
    /// refused.
    ///
    /// # Panics
    ///
    /// Panics if the route is named on the book's shard, leaves it
    /// outside its window, or does not abort, or if the fill does not
    /// accept in time.
    fn assert_freed_at_the_window<C: Cluster>(
        c: &mut C,
        held: &HeldLadder,
        budget: Budget,
        label: &str,
    ) {
        let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
        let gone = |c: &C| {
            !c.queued_rows(BOOK_SHARD).is_some_and(|rows| {
                rows.get(&held.route)
                    .is_some_and(|row| row.state == RowState::Pending)
            })
        };
        assert!(
            c.run_until(budget, gone),
            "{label}: the route must leave the book's queue"
        );
        let left = clock(c);
        let closes = held.blocked_at.plus(NAMING_WINDOW);
        assert!(
            left >= closes && left <= closes.plus(WINDOW_SLACK),
            "{label}: the route must leave at its window, closing at {closes:?}: left at {left:?}",
        );
        assert!(
            c.ran(BOOK_SHARD, held.route)
                .iter()
                .all(|ran| !ran.succeeded),
            "{label}: the route is aborted unnamed on the book's shard",
        );
        let status = await_tx_terminal(c, held.fill, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "{label}: the fill must accept once the route leaves; status = {status:?}",
        );
        let named = clock(c);
        assert!(
            named <= held.fill_committed.plus(NAMING_WINDOW).plus(WINDOW_SLACK),
            "{label}: the fill must run within the window of being refused: committed at {:?}, \
             accepted at {named:?}",
            held.fill_committed,
        );
        let status = await_tx_terminal(c, held.route, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            ),
            "{label}: the route must abort; status = {status:?}",
        );
    }
}

/// What a window's close and the abort it names take past the anchor
/// that closes it: a block's naming and a certificate's settling.
const WINDOW_SLACK: Duration = Duration::from_secs(8);

/// Routes a venue never commits run back to back, each pausing the
/// ladder it reads for no more than a naming window.
const GRIEF_ROUTES: usize = 3;

/// Routes back to back through a venue whose committee drops every
/// bundle the book's shard sends it, so it never commits one.
///
/// Each route's payer is the book's own taker, so the book's member of
/// it is the payer's core: placed at its commit, head of the book's
/// queue, and waiting on the venue's committed bundle, which never
/// comes. A local fill on the ladder behind it waits, and the route
/// takes the clock of that refusal: its window aborts it unnamed, its
/// payer paying its abort charge, and the fill runs. A freeze costs its
/// griefer a charge per window and pauses the ladder no longer.
///
/// # Panics
///
/// Panics if the cut never fires, if a route is named or does not abort
/// at its window, if a fill does not run within its window, or if the
/// quote or the base is not conserved.
pub fn a_route_whose_venue_never_commits_frees_the_ladder<C: FaultableCluster>(c: &mut C) {
    let mut route = BookRoute::stand_up(c);
    let cut = isolate_provision_intake(c, BOOK_VENUE_SHARD, BOOK_SHARD);
    for at in 0..GRIEF_ROUTES {
        let label = format!("griefing route {at}");
        let held = route.hold_the_ladder(c, epochs(4), &label);
        BookRoute::assert_freed_at_the_window(c, &held, epochs(4), &label);
    }
    assert!(cut.fired() > 0, "the venue must have been cut off");
    c.clear_drops();
    route.assert_conserved(c, epochs(12));
}

/// How long the venue's part to the book stays undelivered: past one
/// naming window.
const STALL: Duration = Duration::from_secs(30);

/// A venue that commits a route and then leaves its part to the book
/// undelivered past the naming window.
///
/// The route's payer is the book's own taker, so the book's member is
/// the payer's core, placed at its commit and head. The venue commits
/// the route on the book's bundle, then every part it sends the book is
/// dropped for [`STALL`]. A fill behind the route on the ladder waits,
/// the route takes the clock of that refusal and is aborted unnamed at
/// its window, and the fill runs. Once the venue's parts flow again it
/// reads the abort, and nothing moves but the payer's charge: no base
/// is banked off a walk the book never took.
///
/// # Panics
///
/// Panics if the venue never commits the route, if the route is named
/// or does not abort at its window, if the fill does not run, or if the
/// quote or the base is not conserved.
pub fn a_stalled_venue_aborts_its_route_at_the_window<C: FaultableCluster>(c: &mut C) {
    let mut route = BookRoute::stand_up(c);
    let cut = isolate_provision_intake(c, BOOK_SHARD, BOOK_VENUE_SHARD);
    let stalled = c.now();
    let held = route.hold_the_ladder(c, epochs(4), "a stalled venue");
    assert!(
        c.run_until(epochs(4), |c| c
            .chain_fate(BOOK_VENUE_SHARD, held.route)
            .0
            .is_some()),
        "the venue must commit the route on the book's bundle",
    );
    BookRoute::assert_freed_at_the_window(c, &held, epochs(4), "a stalled venue");
    let _ = c.run_until(epochs(4), |c| c.now() >= stalled + STALL);
    assert!(cut.fired() > 0, "the venue's parts must have been dropped");
    c.clear_drops();
    assert!(
        c.run_until(epochs(8), |c| c
            .tx_statuses(held.route)
            .iter()
            .all(|(status, _)| status.is_final())),
        "the venue must read the abort once its parts flow",
    );
    route.assert_conserved(c, epochs(12));
}

/// Assert each of `submitted`, named by what it is, accepts within
/// `budget`.
fn accept_all<C: Cluster>(c: &mut C, submitted: &[(&str, TxHash)], budget: Budget, label: &str) {
    for &(what, tx) in submitted {
        let status = await_tx_terminal(c, tx, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "{label}: the {what} must accept; status = {status:?}",
        );
    }
}

/// When a route's second local fill is submitted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Second {
    /// With the route.
    Beside,
    /// Once the book's shard has committed the route.
    AfterTheRoute,
    /// With the route, and then this many more, one a block of the
    /// book's shard.
    EveryBlock(usize),
}

/// The book's whole ladder as a declared interval, cut at `cap`.
fn ladder(book: &InstanceMeta, cap: u32) -> DeclaredRange {
    let owner = book.address(&ProtocolHasher).address();
    DeclaredRange {
        owner,
        collection: collection_id(&ProtocolHasher, owner, book::ASKS, &[]),
        lo: u128::from(FILL_TICKS.0) << 64,
        hi: (u128::from(FILL_TICKS.1) << 64) | u128::from(u64::MAX),
        cap,
    }
}

/// The book's two declared vaults, at the slots their typed markers
/// carry.
const BOOK_BASE: SlotId = SlotId(<book::Base as VaultField>::SLOT);
const BOOK_QUOTE: SlotId = SlotId(<book::Quote as VaultField>::SLOT);

/// The cell the book keeps its vault of `resource` in, at `slot`.
fn book_vault(book: &InstanceMeta, slot: SlotId, resource: ResourceAddr) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        book.address(&ProtocolHasher).address(),
        slot,
        &[Value::Address(resource.address()).canonical_bytes()],
    )
}

/// The book's walk over the lowest [`FILL_CAP`] of `standing` with
/// `budget` of quote at one quote subunit a tick: what it buys and what
/// it spends.
fn capped_walk(standing: &[(u128, Vec<u8>)], budget: u128) -> (u128, u128) {
    let mut left = budget;
    let mut bought = 0;
    for (order, value) in standing.iter().take(FILL_CAP as usize) {
        let ticks = order >> 64;
        let available = u128::from_le_bytes(
            value
                .as_slice()
                .try_into()
                .expect("an ask stands as an amount"),
        );
        let take = available.min(left / ticks);
        if take == 0 {
            break;
        }
        left -= take * ticks;
        bought += take;
    }
    (bought, budget - left)
}
