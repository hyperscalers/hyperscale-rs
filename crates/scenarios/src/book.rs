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

use hyperscale_effects_bridge::genesis::GenesisPackages;
use hyperscale_effects_bridge::vm_statics::{config_key, crossing_records};
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_types::{
    BlockHeight, DeclaredRange, Ed25519PrivateKey, MIN_STAKE_FLOOR, PrincipalAddr, ProtocolHasher,
    ResourceAddr, ShardId, SubstateKey, TransactionDecision, TransactionStatus, TxHash,
};
use hyperscale_vm_effects::{InstanceMeta, SlotId, Value, child_key, collection_id};
use hyperscale_vm_fixtures::book::{self, FILL_CAP};
use hyperscale_vm_sdk::client::VaultField;

use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::support::conservation::{Charges, World};
use crate::support::query::{declared_price, held, held_at, stands_at};
use crate::support::tx::{
    FILL_TICKS, GENESIS_POOL, ballast_to, book_on, build_book_route_tx, build_fill_asks_tx,
    build_instantiate_tx, build_place_asks_tx, build_stake_tx, departing_target, pool_at,
    validity_around, venue_quote,
};
use crate::support::wait::await_tx_terminal;
use crate::support::{Budget, Cluster, epochs};
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

/// What one route's oracle read: the book's committing height, the asks
/// standing in the interval there, and what the route bought and paid.
#[derive(Debug)]
pub struct RouteFill {
    /// The route's hash.
    pub hash: TxHash,
    /// The height the book's shard committed the route at.
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
    /// venue's quote for the lowest [`FILL_CAP`] asks the book's
    /// committing block left standing, and the change of the walk over
    /// them.
    ///
    /// # Panics
    ///
    /// Panics if the route or a local fill does not accept within
    /// `budget`, if fewer than [`FILL_CAP`] asks stood in the interval at
    /// the book's committing height, or if the venue's reserve or the
    /// trader's balance does not settle at the closed form.
    pub fn run<C: Cluster>(&mut self, c: &mut C, budget: Budget, label: &str) -> RouteFill {
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
        let beside = self.charges.submit(c, beside);
        for (what, tx) in [
            ("route", hash),
            ("fill before", before),
            ("fill beside", beside),
        ] {
            let status = await_tx_terminal(c, tx, budget);
            assert!(
                matches!(
                    status,
                    Some(TransactionStatus::Completed(TransactionDecision::Accept))
                ),
                "{label}: the {what} must accept; status = {status:?}",
            );
        }

        let source_height = c
            .chain_fate(BOOK_SHARD, hash)
            .0
            .unwrap_or_else(|| panic!("{label}: the book's shard committed the route"));
        let standing = c
            .entries_at(BOOK_SHARD, ladder(&self.book, u32::MAX), source_height)
            .unwrap_or_else(|| panic!("{label}: the book's shard holds {source_height:?}"));
        assert!(
            standing.len() > FILL_CAP as usize,
            "{label}: more asks than the fill's cap must stand at {source_height:?}, \
             or the cap bites nothing: {}",
            standing.len(),
        );
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
