//! Cycles through a payer core, and the naming window that ends them.
//!
//! A sponsored route's payer core is placed on its sponsor's shard at its
//! commit, before its trader's leg has written the record the core
//! consumes, and stands head there until it settles. A member placed
//! behind it on a key it pins waits for it. Where that member is what the
//! route's own leg waits on, or is the leg of a second route whose payer
//! core holds the first route's leg off, the waits close a cycle that no
//! record can break. Every head in it refuses someone, so each takes the
//! clock of its first refusal, and the first naming window to close
//! aborts its head unnamed: at most two honest aborts, and nothing moves
//! for an aborted route but its sponsor's charge.
//!
//! Each trader pays its route in stake units, and a route that sets out
//! to hold a leg off presents its sponsor's vault of them as a badge: a
//! read of the vault the leg reserves and credits on that shard.
//!
//! Sim-only. The cuts that order the commits hook the in-memory
//! transport, and require disjoint committees.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::RowState;
use hyperscale_types::{
    Deadline, Ed25519PrivateKey, NAMING_WINDOW, PrincipalAddr, ResourceAddr, ShardId,
    TimestampRange, TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp,
};

use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::straddler::isolate_provision_intake;
use crate::support::conservation::{Charges, World};
use crate::support::query::held;
use crate::support::tx::{build_sponsored_route_presenting_tx, build_swap_tx, validity_around};
use crate::support::{Cluster, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAPPER_FUNDING, StockedVenue, accepted, grind_onto, reserve_cell,
    stand_up_venue,
};

/// Where the sponsor sits, and so where a route it pays for is a payer
/// core placed at its commit.
const SPONSOR_SHARD: ShardId = FIRST_VENUE_SHARD;

/// Where the taker sits: a shard no route but its own reaches, so its
/// withdraw is a leg of nothing else.
const TAKER_SHARD: ShardId = ShardId::leaf(2, 3);

/// A venue on every quarter, in the order they are stood up.
const VENUES: [ShardId; 4] = [SPONSOR_SHARD, SECOND_VENUE_SHARD, TRADER_SHARD, TAKER_SHARD];

/// What the sponsor and the trader each swap into stake units before
/// any route: enough for a route's input and a badge left behind it.
const UNITS_BOUGHT: u128 = 4 * ROUTE_INPUT;

/// How long past a window's close an abort may take to show: the window
/// closes at an anchor, the abort is named in the block anchored there
/// and folds a block or two later, and the run reads the row once a
/// second. Honest runs show it about 3.5 s past the close.
const SLACK: Duration = Duration::from_secs(6);

/// A provider on every venue's quarter, then the sponsor, the trader and
/// the taker, each funded for what it does.
#[must_use]
pub fn payer_cycle_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts: Vec<(PrincipalAddr, u128)> = VENUES
        .iter()
        .map(|&venue| (grind_onto(venue, &mut taken).1, PROVIDER_FUNDING))
        .collect();
    accounts.extend(
        cast(&mut taken)
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts
}

/// The sponsor, the trader and the taker, ground after the providers.
fn cast(taken: &mut Vec<u8>) -> [(Ed25519PrivateKey, PrincipalAddr); 3] {
    [
        grind_onto(SPONSOR_SHARD, taken),
        grind_onto(TRADER_SHARD, taken),
        grind_onto(TAKER_SHARD, taken),
    ]
}

/// One of the cast.
#[derive(Clone, Copy)]
enum Party {
    /// On [`SPONSOR_SHARD`].
    Sponsor,
    /// On [`TRADER_SHARD`].
    Trader,
    /// On [`TAKER_SHARD`].
    Taker,
}

/// What a route's trader pays in.
#[derive(Clone, Copy)]
enum Paying {
    /// Stake units.
    Units,
    /// The protocol resource.
    Protocol,
}

/// One sponsored route of a cycle.
#[derive(Clone, Copy)]
struct Route {
    /// Who pays its fee, and on whose shard it is a payer core.
    sponsor: Party,
    /// Whose withdraw is its leg.
    trader: Party,
    /// Indexes into [`VENUES`] of its two hops.
    venues: (usize, usize),
    paying: Paying,
    /// Whether the sponsor presents its vault of stake units beside it.
    presenting: bool,
}

/// A route submitted: whose input it took, and what that trader held of
/// it just before.
struct Submitted {
    hash: TxHash,
    trader: PrincipalAddr,
    resource: ResourceAddr,
    before: u128,
}

/// Four stocked venues, the cast holding stake units, and the worlds
/// every route can reach.
struct Cycle {
    venues: Vec<StockedVenue>,
    cast: [(Ed25519PrivateKey, PrincipalAddr); 3],
    unit: ResourceAddr,
    protocol_resource: World,
    units: World,
    charges: Charges,
    validity: TimestampRange,
    submitted: Vec<Submitted>,
}

impl Cycle {
    /// Stand every venue up, swap the sponsor and the trader into stake
    /// units on their own quarters, and open the worlds.
    fn stand_up<C: Cluster>(c: &mut C) -> Self {
        assert!(
            VENUES.iter().all(|&shard| c.serves_shard(shard)),
            "the grown four-shard topology must seat every quarter",
        );
        let mut taken = Vec::new();
        let venues: Vec<StockedVenue> = VENUES
            .iter()
            .map(|&shard| stand_up_venue(c, shard, &mut taken))
            .collect();
        let cast = cast(&mut taken);
        let unit = venues[0].unit;
        for (party, venue) in [(Party::Sponsor, 0), (Party::Trader, 2)] {
            let (key, account) = &cast[party as usize];
            accepted(
                c,
                build_swap_tx(
                    key,
                    *account,
                    &venues[venue].meta,
                    *PROTOCOL_RESOURCE,
                    UNITS_BOUGHT,
                    0,
                    validity_around(c.now()),
                ),
                "a local swap must hand its caller stake units",
            );
            assert!(
                c.run_until(epochs(4), |c| held(c, account.address(), unit)
                    >= ROUTE_INPUT),
                "the swap's units must land before a route spends them",
            );
        }
        let world = |c: &C, resource| {
            World::open(
                c,
                resource,
                cast.iter().map(|(_, account)| account.address()),
                venues
                    .iter()
                    .map(|venue| reserve_cell(&venue.meta, resource)),
            )
        };
        let protocol_resource = world(c, *PROTOCOL_RESOURCE);
        let units = world(c, unit);
        Self {
            venues,
            cast,
            unit,
            protocol_resource,
            units,
            charges: Charges::default(),
            validity: validity_around(c.now()),
            submitted: Vec::new(),
        }
    }

    /// Submit `route`, owing its price.
    fn submit<C: Cluster>(&mut self, c: &mut C, route: Route) -> TxHash {
        let resource = match route.paying {
            Paying::Units => self.unit,
            Paying::Protocol => *PROTOCOL_RESOURCE,
        };
        let (sponsor, _) = &self.cast[route.sponsor as usize];
        let (key, trader) = &self.cast[route.trader as usize];
        let tx = build_sponsored_route_presenting_tx(
            sponsor,
            key,
            *trader,
            (
                &self.venues[route.venues.0].meta,
                &self.venues[route.venues.1].meta,
            ),
            (resource, ROUTE_INPUT),
            route.presenting.then_some(self.unit),
            self.validity,
        );
        let trader = *trader;
        let before = held(c, trader.address(), resource);
        let hash = self.charges.submit(c, tx);
        self.submitted.push(Submitted {
            hash,
            trader,
            resource,
            before,
        });
        hash
    }

    /// Hold the cycle to ending at its windows: every route final before
    /// its deadline, one or two aborted, each aborted one gone from a
    /// head it held unnamed within its naming window of the later
    /// refusal and not before the earlier window, its trader holding what
    /// it held, and both sides conserved.
    ///
    /// `heads` are the rows the cycle armed: each shard where a route
    /// stood head, unnamed and refusing someone.
    fn assert_ends_at_the_window<C: Cluster>(
        self,
        c: &mut C,
        heads: &[(ShardId, TxHash)],
        context: &str,
    ) {
        let refused: Vec<(ShardId, TxHash, WeightedTimestamp)> = heads
            .iter()
            .filter_map(|&(shard, tx)| {
                c.queued_rows(shard)
                    .and_then(|rows| rows.get(&tx).and_then(|row| row.blocked_at))
                    .map(|at| (shard, tx, at))
            })
            .collect();
        let earlier = refused.iter().map(|&(_, _, at)| at).min();
        let later = refused.iter().map(|&(_, _, at)| at).max();
        let (Some(earlier), Some(later)) = (earlier, later) else {
            panic!("{context}: the cycle must arm a head");
        };

        let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
        let left: RefCell<BTreeMap<TxHash, WeightedTimestamp>> = RefCell::new(BTreeMap::new());
        let hashes: Vec<TxHash> = self.submitted.iter().map(|route| route.hash).collect();
        let resolved = c.run_until(epochs(8), |c| {
            for &(shard, tx, _) in &refused {
                let waits = c.queued_rows(shard).is_some_and(|rows| {
                    rows.get(&tx)
                        .is_some_and(|row| row.state == RowState::Pending)
                });
                if !waits {
                    left.borrow_mut().entry(tx).or_insert_with(|| clock(c));
                }
            }
            hashes
                .iter()
                .all(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final()))
        });
        let deadline = Deadline::of(self.validity.end_timestamp_exclusive).at();
        assert!(
            resolved && clock(c) < deadline,
            "{context}: the windows must resolve every route before its deadline: {:?}",
            hashes
                .iter()
                .map(|hash| c.tx_status(*hash))
                .collect::<Vec<_>>(),
        );

        let left = left.into_inner();
        let mut aborted = 0;
        for route in &self.submitted {
            match c.tx_status(route.hash) {
                Some(TransactionStatus::Completed(TransactionDecision::Accept)) => {}
                Some(TransactionStatus::Completed(TransactionDecision::Aborted)) => {
                    aborted += 1;
                    let gone = left.get(&route.hash).copied().unwrap_or_else(|| {
                        panic!("{context}: an aborted route must have stood head refusing someone")
                    });
                    assert!(
                        gone >= earlier.plus(NAMING_WINDOW)
                            && gone <= later.plus(NAMING_WINDOW).plus(SLACK),
                        "{context}: a route must leave its head at a naming window: refused \
                         from {earlier:?} to {later:?}, gone at {gone:?}",
                    );
                    for &(shard, tx, _) in &refused {
                        assert!(
                            tx != route.hash || c.ran(shard, tx).iter().all(|ran| !ran.succeeded),
                            "{context}: an aborted route is aborted unnamed where it stood \
                             head: {:?}",
                            c.ran(shard, tx),
                        );
                    }
                }
                other => panic!("{context}: a route in the cycle resolved as {other:?}"),
            }
        }
        assert!(
            (1..=2).contains(&aborted),
            "{context}: the windows must end the cycle with one or two aborts, not {aborted}",
        );

        let Self {
            protocol_resource,
            units,
            charges,
            submitted,
            ..
        } = self;
        protocol_resource.assert_settles_within(c, &charges, epochs(8), context);
        units.assert_settles_within(c, &Charges::default(), epochs(8), context);
        for route in &submitted {
            if c.tx_status(route.hash)
                == Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            {
                assert_eq!(
                    held(c, route.trader.address(), route.resource),
                    route.before,
                    "{context}: an aborted route moves nothing of its trader's but its charge",
                );
            }
        }
    }
}

/// Whether `tx` stands head on `shard`, unnamed.
fn heads<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    c.queued_rows(shard).is_some_and(|rows| {
        rows.get(&tx)
            .is_some_and(|row| row.state == RowState::Pending && row.head.is_some())
    })
}

/// Whether `tx` stands head on `shard`, unnamed and refusing someone.
fn heads_refusing<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    heads(c, shard, tx)
        && c.queued_rows(shard)
            .is_some_and(|rows| rows.get(&tx).is_some_and(|row| row.blocked_at.is_some()))
}

/// Whether `tx` is placed on `shard`.
fn placed<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    c.queued_rows(shard)
        .is_some_and(|rows| rows.get(&tx).is_some_and(|row| row.queued.is_some()))
}

/// Whether `tx` is placed on `shard` and waits there, not head.
fn waits<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    c.queued_rows(shard).is_some_and(|rows| {
        rows.get(&tx).is_some_and(|row| {
            row.state == RowState::Pending && row.queued.is_some() && row.head.is_none()
        })
    })
}

/// The three-member cycle through a payer core, ended at a window.
///
/// A route sponsored on the sponsor's shard, through the venues there
/// and on the second quarter, takes the trader's units: its payer core P
/// heads on the sponsor's shard at its commit, its leg L stands on the
/// trader's. A second route M, sponsored by the trader and taken by the
/// taker through the trader's venue and the sponsor's, presents the
/// trader's vault of units. The route's bundle is held off the trader's
/// shard until M is placed there, so M, a payer core on the trader's
/// shard, stands ahead of L on the vault L reserves, and L waits on M.
/// On the sponsor's shard M is placed once the taker's record arrives,
/// behind P on the venue's reserve, so M waits on P, and P's naming waits
/// on L's record. P refuses M, so P takes a clock, as M does if it still
/// stands unnamed when L arrives; the first window to close aborts its
/// head, and the other route settles.
///
/// # Panics
///
/// Panics if a venue or a swap misses its budget, if the cut never fires,
/// if the cycle does not stand, or if it ends otherwise than
/// [`Cycle::assert_ends_at_the_window`] asks.
pub fn a_cycle_through_a_payer_core_aborts_at_the_window<C: FaultableCluster>(c: &mut C) {
    let mut cycle = Cycle::stand_up(c);
    let held_back = isolate_provision_intake(c, TRADER_SHARD, SPONSOR_SHARD);
    let route = cycle.submit(
        c,
        Route {
            sponsor: Party::Sponsor,
            trader: Party::Trader,
            venues: (0, 1),
            paying: Paying::Units,
            presenting: false,
        },
    );
    assert!(
        c.run_until(epochs(4), |c| heads(c, SPONSOR_SHARD, route)),
        "the sponsor's shard must place the route's payer core head at its commit",
    );
    let member = cycle.submit(
        c,
        Route {
            sponsor: Party::Trader,
            trader: Party::Taker,
            venues: (2, 0),
            paying: Paying::Protocol,
            presenting: true,
        },
    );
    assert!(
        c.run_until(epochs(4), |c| placed(c, TRADER_SHARD, member)),
        "the trader's shard must place the second route's payer core at its commit",
    );
    assert!(
        held_back.fired() > 0,
        "the route's bundle must have been held off the trader's shard",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(4), |c| {
            heads_refusing(c, SPONSOR_SHARD, route)
                && waits(c, SPONSOR_SHARD, member)
                && waits(c, TRADER_SHARD, route)
                && placed(c, TRADER_SHARD, member)
        }),
        "the payer core must head refusing the second route on the sponsor's shard, while \
         its leg waits behind the second route on the trader's",
    );
    cycle.assert_ends_at_the_window(
        c,
        &[(SPONSOR_SHARD, route), (TRADER_SHARD, member)],
        "a cycle through a payer core",
    );
}

/// Two sponsored routes crossed through their legs, ended at a window.
///
/// The first route is sponsored on the sponsor's shard and taken by the
/// trader, the second sponsored on the trader's shard and taken by the
/// sponsor, each through the venue on its sponsor's shard and one of its
/// own, and each presenting its sponsor's vault of units. Each bundle is
/// held off the other shard until both payer cores are placed, so on each
/// shard a payer core heads ahead of the other route's leg on the vault
/// that leg reserves. Each core's naming waits on its own leg's record,
/// which the other core holds off: both heads take a clock, the first
/// window to close aborts its head, and the other route settles.
///
/// # Panics
///
/// As [`a_cycle_through_a_payer_core_aborts_at_the_window`].
pub fn sponsored_routes_crossed_through_their_legs_abort_at_the_window<C: FaultableCluster>(
    c: &mut C,
) {
    let mut cycle = Cycle::stand_up(c);
    let held_back = [
        isolate_provision_intake(c, TRADER_SHARD, SPONSOR_SHARD),
        isolate_provision_intake(c, SPONSOR_SHARD, TRADER_SHARD),
    ];
    let first = cycle.submit(
        c,
        Route {
            sponsor: Party::Sponsor,
            trader: Party::Trader,
            venues: (0, 1),
            paying: Paying::Units,
            presenting: true,
        },
    );
    let second = cycle.submit(
        c,
        Route {
            sponsor: Party::Trader,
            trader: Party::Sponsor,
            venues: (2, 3),
            paying: Paying::Units,
            presenting: true,
        },
    );
    assert!(
        c.run_until(epochs(4), |c| heads(c, SPONSOR_SHARD, first)
            && heads(c, TRADER_SHARD, second)),
        "each sponsor's shard must place its route's payer core head at its commit",
    );
    assert!(
        held_back.iter().all(|handle| handle.fired() > 0),
        "each route's bundle must have been held off the other's sponsor",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(4), |c| {
            heads_refusing(c, SPONSOR_SHARD, first)
                && waits(c, SPONSOR_SHARD, second)
                && heads_refusing(c, TRADER_SHARD, second)
                && waits(c, TRADER_SHARD, first)
        }),
        "each payer core must head refusing the other route's leg on its shard",
    );
    cycle.assert_ends_at_the_window(
        c,
        &[(SPONSOR_SHARD, first), (TRADER_SHARD, second)],
        "two sponsored routes crossed through their legs",
    );
}
