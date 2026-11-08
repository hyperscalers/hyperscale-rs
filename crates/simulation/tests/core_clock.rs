//! What the members of a multi-shard core read, and whether they read
//! the same thing.
//!
//! A core spanning two shards runs every core node on each of them, and
//! each shard applies its own projection of its own run. The book route
//! is such a core: the book's fill on the book's shard and the venue's
//! swap on the venue's. The venue's shard runs the fill over the ladder
//! the book's committing block left, served in the book's bundle; the
//! book's shard runs it over its own ladder as its tick reads it.
//!
//! Sim-only. The delay hooks the in-memory transport's notification leg.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::{
    BOOK_SHARD, BOOK_VENUE_SHARD, BookRoute, Cluster, FaultableCluster, ScenarioConfig,
    a_divided_core_pays_out_under_one_clock, book_route_genesis_accounts, cutoff_genesis_accounts,
    departing_venue_split_bytes, epochs,
};
use support::{SimCluster, sim_seed};

/// Four quarters on hosts of their own: the cutoffs on two, the payer on
/// a third.
fn cutoff_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 14,
            num_shards: 4,
            split_bytes: 0,
            latency: std::time::Duration::from_millis(150),
        },
        seed,
        &cutoff_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Two core shards that commit a payment on either side of its deadline
/// run its core under one clock, the earliest of theirs, so the payment
/// lands in one cutoff.
#[test]
fn a_divided_core_runs_under_its_earliest_clock() {
    let mut cluster = cutoff_cluster(sim_seed(42));
    cluster.run_faultable(a_divided_core_pays_out_under_one_clock);
}

/// A core one of whose shards commits it again past a fork recovery.
///
/// Its recovery's bridge has to fall inside the payment's window, which
/// only the short test epochs allow.
#[cfg(not(feature = "production-epochs"))]
mod recommitted_core {
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_engine::PROTOCOL_RESOURCE;
    use hyperscale_engine::genesis::GenesisPackages;
    use hyperscale_node::event::{HostEvent, ShardScopedInput};
    use hyperscale_scenarios::conservation::{Charges, World};
    use hyperscale_scenarios::{
        Cluster, CutoffStage, FIRST_VENUE_SHARD, FaultHandle, FaultableCluster, SECOND_VENUE_SHARD,
        ScenarioConfig, TRADER_SHARD, committees_on_separate_hosts, cutoff_genesis_accounts,
        epochs, seal_cutoffs,
    };
    use hyperscale_storage::{RowState, ShardChainReader};
    use hyperscale_types::test_utils::{Withheld, shard_fork_proof_signed_by};
    use hyperscale_types::{
        BlockHeight, RecoveryCause, ShardId, ShardRecovery, TimestampRange, Transaction,
        TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp,
    };

    use super::support::{SimCluster, sim_seed};

    /// The shard that commits the payment short of its cutoff and again,
    /// past its recovery, beyond it.
    const A: ShardId = FIRST_VENUE_SHARD;
    /// The shard that commits the payment once, past its cutoff.
    const B: ShardId = SECOND_VENUE_SHARD;
    const CUTOFF_AHEAD: Duration = Duration::from_secs(4);
    /// Long enough to outlast the recovery's bridge: the start of the
    /// epoch after the one its fold rotates the fresh committee in at.
    const WINDOW: Duration = Duration::from_secs(115);

    /// Four quarters on hosts of their own that never reshape, the pool
    /// deep enough to seat a fresh committee for one.
    fn recovered_cutoff_cluster(seed: u64) -> SimCluster {
        SimCluster::with_grown_packages_on_dedicated_pool_hosts(
            &ScenarioConfig {
                shard_size: 4,
                vnodes_per_host: 1,
                pool_surplus: 24,
                num_shards: 4,
                split_bytes: u64::MAX,
                latency: Duration::from_millis(150),
            },
            seed,
            &cutoff_genesis_accounts(),
            GenesisPackages::with_fixtures(),
        )
    }

    /// Seal both cutoffs under a boundary of A's, which a recovery of A
    /// rewinds to, and return just after the next fold.
    fn seal_under_a_boundary(c: &mut SimCluster) -> CutoffStage {
        let stage = seal_cutoffs(c);
        let sealed = c.committed_height(A).expect("A commits");
        assert!(
            c.run_until(epochs(8), |c| c.beacon_state().is_some_and(|s| s
                .boundaries
                .get(&A)
                .is_some_and(|boundary| boundary.height >= sealed))),
            "A's boundary must reach its seal",
        );
        let epoch = c.beacon_state().expect("a beacon").current_epoch;
        assert!(
            c.run_until(epochs(2), |c| c
                .beacon_state()
                .is_some_and(|s| s.current_epoch > epoch)),
            "the beacon must fold an epoch",
        );
        stage
    }

    /// The payment, kept by the first cutoff short of `CUTOFF_AHEAD` from
    /// now and by the second past it, valid over [`WINDOW`]; and its
    /// cutoff.
    fn payment(c: &SimCluster, stage: &CutoffStage) -> (Transaction, WeightedTimestamp) {
        let start = c.now();
        let cutoff = WeightedTimestamp::ZERO.plus(start + CUTOFF_AHEAD);
        let opens = start.saturating_sub(Duration::from_secs(1));
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO.plus(opens),
            WeightedTimestamp::ZERO.plus(start + WINDOW),
        );
        (stage.payment(cutoff, validity), cutoff)
    }

    /// Record `tx` in `charges`, derived at `host`, which admitted it: it
    /// holds the records `tx` derives over, which the harness's own host
    /// may not.
    fn record_admitted(c: &SimCluster, charges: &mut Charges, tx: &Transaction, host: usize) {
        let host = u32::try_from(host).expect("a host index");
        let derivation = c.runner().host_derivation(host).expect("a host up");
        assert!(
            tx.try_derived(derivation.as_ref()).is_ok(),
            "the payment must derive at a host that admitted it",
        );
        charges.record(tx);
    }

    /// Fold a fork recovery of A from a proof above its tip, and hold the
    /// replaced committee short of certifying past the proof: two of its
    /// members stop voting for as long as the handle is held.
    fn recover_a_by_fork(c: &mut SimCluster) -> (ShardRecovery, FaultHandle) {
        let tip = c.committed_height(A).expect("A commits").inner();
        let member = u32::try_from(c.committee_hosts(A)[0]).expect("a host index");
        let proof = {
            let runner = c.runner();
            let schedule = runner
                .first_replica(member)
                .expect("a committee host")
                .schedule();
            let storage = runner.hosts_shard(member, A).expect("it serves A");
            let header = storage
                .get_certified_header(storage.committed_height())
                .expect("a tip");
            let wt = header.header().parent_qc().weighted_timestamp();
            let committee = schedule
                .live_committee(A, wt)
                .committee()
                .expect("a committee");
            let keys: Vec<_> = committee
                .snapshot
                .consensus_committee_for_shard(A)
                .iter()
                .map(|validator| runner.validator_signer(*validator).expect("a key"))
                .collect();
            shard_fork_proof_signed_by(
                runner.verifier().as_ref(),
                &keys,
                A,
                BlockHeight::new(tip + 1),
                committee.epoch,
                wt,
            )
        };
        let members = c
            .beacon_state()
            .and_then(|s| s.shard_consensus_members.get(&A).cloned())
            .expect("A's committee");
        let withheld = c.withhold(&members[..2], Withheld::Votes);
        c.runner_mut().schedule_initial_event(
            member,
            Duration::ZERO,
            HostEvent::shard(
                A,
                ShardScopedInput::ShardForkProofGossipReceived {
                    proof: Arc::new(proof),
                },
            ),
        );
        assert!(
            c.run_until(epochs(4), |c| c.beacon_state().is_some_and(|s| s
                .pending_recoveries
                .get(&A)
                .is_some_and(|recovery| recovery.cause == RecoveryCause::Fork))),
            "the proof must fold a fork recovery of A",
        );
        let recovery = c.beacon_state().expect("a beacon").pending_recoveries[&A].clone();
        (recovery, withheld)
    }

    /// Wait for A and B to resolve `tx`, and require that each refused it.
    fn assert_refused_on_both(c: &mut SimCluster, tx: TxHash) {
        assert!(
            c.run_until(epochs(4), |c| [A, B]
                .iter()
                .all(|shard| c.chain_fate(*shard, tx).1.is_some())),
            "both shards must resolve the payment",
        );
        for shard in [A, B] {
            assert!(
                matches!(
                    c.chain_fate(shard, tx).1,
                    Some((_, TransactionDecision::Aborted))
                ),
                "{shard:?} must refuse the payment",
            );
        }
        assert_eq!(
            c.tx_status(tx),
            Some(TransactionStatus::Completed(TransactionDecision::Aborted)),
            "the payment must abort",
        );
    }

    /// A core shard that commits a payment again past its recovery, under
    /// a clock past the cutoff its lost commit ran short of, states other
    /// effects than its sibling stated over the lost run, and both refuse.
    ///
    /// A loses its own execution votes, so its commit short of the cutoff
    /// never states. B commits past the cutoff, runs under A's lost clock,
    /// and states the payment kept by the first cutoff. A fork proof above
    /// A's tip recovers it at its last boundary, which the lost commit
    /// lies past. A's fresh committee commits the payment again past the
    /// bridge, runs under its own clock, past the cutoff, and states the
    /// payment kept by the second. Each shard reads the other's digest as
    /// neither value it would hash.
    ///
    /// Both shards must refuse, the payer charged its price alone and
    /// neither cutoff credited, and the readings counted as differing
    /// must not grow once the refusal has settled.
    #[test]
    fn a_recommit_past_a_recovery_refuses_on_both() {
        let mut cluster = recovered_cutoff_cluster(sim_seed(42));
        cluster.runner_mut().permit_forks();
        cluster.run_faultable(|c| {
            let stage = seal_under_a_boundary(c);
            let (a_hosts, b_hosts) = committees_on_separate_hosts(c, A, B);
            let cut_votes = |c: &mut SimCluster| {
                let _ = c.drop_type_between(&a_hosts, &a_hosts, "execution.vote");
            };
            cut_votes(c);
            let others: Vec<usize> = (0..c.host_count())
                .filter(|host| !b_hosts.contains(host))
                .collect();
            let _ = c.drop_type_between(&others, &b_hosts, "transaction.gossip");
            let _ = c.drop_type_between(&b_hosts, &others, "transaction.request");

            // The payer alone: its shard accepts its leg, which moves the
            // payment into a record for A; the refusal leaves the record
            // to return at the close of its window, so the payer settles
            // down by its price.
            let payer = World::open(c, *PROTOCOL_RESOURCE, [stage.payer().address()], []);
            let mut charges = Charges::default();
            let (tx, cutoff) = payment(c, &stage);
            let hash = tx.hash();
            c.submit_to(TRADER_SHARD, tx.clone());
            assert!(
                c.run_until(epochs(1), |c| c.chain_fate(A, hash).0.is_some()),
                "A must commit the payment",
            );
            record_admitted(c, &mut charges, &tx, a_hosts[0]);
            let lost = c.chain_fate(A, hash).0.expect("A committed it");
            assert!(
                c.committed_clock(A, lost)
                    .is_some_and(|clock| clock < cutoff),
                "A must commit the payment short of the cutoff",
            );

            let past = cutoff.plus(Duration::from_secs(2));
            let _ = c.run_until(epochs(1), |c| WeightedTimestamp::ZERO.plus(c.now()) >= past);
            assert!(
                c.chain_fate(B, hash).0.is_none(),
                "B must not hold the payment before the cutoff",
            );
            c.clear_drops();
            cut_votes(c);
            c.submit_to(B, tx.clone());
            let stated = |c: &SimCluster, shard| {
                c.member_rows(shard)
                    .is_some_and(|rows| matches!(rows.get(&hash), Some(RowState::Stated { .. })))
            };
            assert!(
                c.run_until(epochs(2), |c| stated(c, B)),
                "B must state the payment over A's lost part",
            );
            assert!(!stated(c, A), "A must not state while its votes are lost");

            let (recovery, _withheld) = recover_a_by_fork(c);
            assert!(
                lost > recovery.attested_frontier,
                "A's lost commit must lie past the recovery's frontier",
            );
            assert!(stated(c, B), "B must have stated before the recovery folds");
            assert!(
                c.run_until(epochs(4), |c| c
                    .beacon_state()
                    .is_some_and(|s| s.current_epoch > recovery.rotated_at)),
                "the beacon must fold past the recovery",
            );
            c.submit_to(A, tx);
            let recommitted = |c: &SimCluster| {
                c.chain_fate(A, hash).0.is_some_and(|height| {
                    c.committed_clock(A, height)
                        .is_some_and(|clock| clock >= cutoff)
                })
            };
            assert!(
                c.run_until(epochs(3), recommitted),
                "A's fresh committee must commit the payment again past the cutoff",
            );

            assert_refused_on_both(c, hash);
            assert!(
                c.effects_differed(hash),
                "A and B must state the payment under two digests",
            );
            let locked =
                payer.assert_settles_within(c, &charges, epochs(8), "a payment refused on both");
            assert!(locked.is_empty(), "a refusal locks nothing: {locked:?}");
            assert!(charges.burned(c) > 0, "the payer must be charged its price");
            assert_eq!(stage.banked(c), [0, 0], "neither cutoff may be credited");

            for shard in [A, B] {
                assert!(
                    c.metric(
                        "verdict_differed_by_shard",
                        Some(&shard.inner().to_string())
                    ) > 0,
                    "{shard:?}'s rows must read the other's digest as differing",
                );
            }
            let differed = c.metric("verdict_differed", None);
            let _ = c.run_until(epochs(2), |_| false);
            assert_eq!(
                c.metric("verdict_differed", None),
                differed,
                "a reading counted once must not count again",
            );
        });
    }
}

/// Execution votes the book's committee sends that are lost before the
/// rest go through: enough that the local fills beside a route certify
/// only after the route has committed on the book's shard.
const LOST_VOTES: usize = 120;

/// The book route's four quarters, grown on dedicated pool hosts, the
/// reshape trigger armed above every quarter and never voted down.
fn book_route_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 18,
            num_shards: 4,
            split_bytes: departing_venue_split_bytes(),
            latency: std::time::Duration::from_millis(150),
        },
        seed,
        &book_route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// A local fill the book's shard has run but not yet settled when it
/// commits a route leaves the route's book member behind the fill's
/// tick, and both core members walk the ladder the block making it head
/// left.
///
/// The book's committee loses its first execution votes, so the fills
/// beside the route run in their own block's tick and certify only after
/// the route commits. The book's member reads the ladder, so it heads
/// only once the fills' ticks have settled, and the book's shard serves
/// the venue's its part from that block: the ladder it left holds the
/// fills' output, which is what the book's member reads through its
/// tick.
///
/// The route must settle at the closed form over the ladder that block
/// left, with the quote and the base conserved, as one run of the core
/// would.
#[test]
fn a_core_member_reads_its_own_cells_as_its_bundle_served_them() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let lost = Arc::new(AtomicUsize::new(0));
        for host in c.committee_hosts(BOOK_SHARD) {
            let lost = Arc::clone(&lost);
            let _ = c.rewrite_notifications(
                host,
                "execution.vote",
                Arc::new(move |_asked: &[u8], honest: &[u8]| {
                    if lost.fetch_add(1, Ordering::Relaxed) < LOST_VOTES {
                        Vec::new()
                    } else {
                        honest.to_vec()
                    }
                }),
            );
        }

        let fill = route.run(c, epochs(12), "fills certified after the route");
        assert!(
            lost.load(Ordering::Relaxed) > LOST_VOTES,
            "the book's votes have to have been lost and then flowed, or nothing raced: {fill:?}",
        );
        route.assert_conserved(c, epochs(12));
        c.assert_effects_agreed(fill.hash);
    });
}

/// Provision broadcasts the venue's committee sends that are lost before
/// the rest go through: every one the route's core sends, so the book's
/// shard holds the route pending until it fetches the venue's part.
const LOST_PROVISIONS: usize = 64;

/// A local fill the book's shard commits after a route, while the route
/// waits on the venue's part, settles before the route reads the ladder.
///
/// The venue's committee loses its first provision broadcasts, so the
/// book's shard holds the route pending until it fetches the venue's
/// part. A local fill submitted once the book's shard has committed the
/// route commits after it. The book's member of the route pays nowhere
/// and consumes the trader's escrow, so the book places it only at the
/// block whose claims read the trader's record, which may land before or
/// after the fill commits. Either way the route heads only once nothing
/// placed ahead of it, and no tick below its place, still moves the
/// ladder, and the book's shard serves the venue's member its part from
/// that block: both walk one ladder.
///
/// The route must bank one base on both shards, as one run of the core
/// would.
#[test]
fn a_route_placed_after_a_fill_waits_for_the_fill() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let lost = Arc::new(AtomicUsize::new(0));
        for host in c.committee_hosts(BOOK_VENUE_SHARD) {
            let lost = Arc::clone(&lost);
            let _ = c.rewrite_notifications(
                host,
                "provisions.broadcast",
                Arc::new(move |_asked: &[u8], honest: &[u8]| {
                    if lost.fetch_add(1, Ordering::Relaxed) < LOST_PROVISIONS {
                        Vec::new()
                    } else {
                        honest.to_vec()
                    }
                }),
            );
        }

        let fill = route.run_with_a_later_fill(c, epochs(12), "a fill committed after the route");
        assert!(
            lost.load(Ordering::Relaxed) > 0,
            "the venue's broadcasts have to have been lost, or the route never waited: {fill:?}",
        );
        route.assert_conserved(c, epochs(12));
        c.assert_effects_agreed(fill.hash);
    });
}
