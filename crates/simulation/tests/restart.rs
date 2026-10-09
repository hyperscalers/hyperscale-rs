//! A replica that restarts rejoins the committee it left.
//!
//! The committed chain survives a restart and everything execution held
//! does not: which tick holds which transaction, and what each tick's
//! baseline was. Both are functions of committed content, and a replica
//! that fails to rebuild them composes a tick its peers do not — which
//! is a fail-stop, not a dropped vote.
//!
//! Sim-only. The restart primitive tears a vnode down and seats it again
//! on the storage it kept, which production would have to do by bouncing
//! a process.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_network_memory::NodeIndex;
use hyperscale_scenarios::query::{declared_price, vault_balance};
use hyperscale_scenarios::tx::{
    HALT_STRADDLER_BATCH, build_leg_payment_tx, build_sponsored_swap_tx, build_swap_tx,
    build_transfer_tx, cross_shard_genesis_accounts, genesis_accounts, halt_straddler_setup,
    recipient, sender, validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{
    Cluster, Crash, CrashableCluster, FaultableCluster, SWAP_INPUT, SWAPPER_SHARD, SWAPPERS,
    ScenarioConfig, VENUE_SHARD, a_rejoined_producer_asks_a_lost_answer, epochs, grind_onto,
    split_lifecycle, stand_up_venue, venue_genesis_accounts,
};
use hyperscale_simulation::{CrashKind, EPOCH_MS, ProcessingTimes};
use hyperscale_storage::{BoundaryStore, RowState, ShardChainReader};
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, GlobalReceiptRoot, HALT_THRESHOLD_EPOCHS, PrincipalAddr,
    ShardId, TRANSACTION_EVIDENCE_HORIZON, TransactionDecision, TransactionStatus, TxHash,
};
use support::{SimCluster, committee_member_host, seeded};

/// The halt scenarios' topology: a split leaves a live sibling to carry
/// the beacon through the folds that detect a stalled shard, and the pool
/// holds the spares a re-draw seats.
const fn halt_recovery_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 14,
        num_shards: 1,
        split_bytes: 36_000,
        latency: Duration::from_millis(150),
    }
}

/// A venue on one shard and its callers on the other, resharding
/// disarmed so the committees a restart bounces are the ones that were
/// seated.
const fn venue_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// Single shard with the split trigger armed and one cohort of pool
/// surplus: the root splits on its own.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

/// Single shard, four-validator committee, resharding disarmed.
const fn one_shard() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// Whether `shard` has committed `tx` and still owes it an outcome —
/// exactly the window a restart has to replay across. Restarting outside
/// it replays nothing and measures nothing.
fn owed_an_outcome(c: &SimCluster, shard: ShardId, tx: TxHash) -> bool {
    let (committed, outcome) = c.chain_fate(shard, tx);
    committed.is_some() && outcome.is_none()
}

// Every restart here runs at eight seeds: one seed is one leader schedule,
// and a restart lands differently against each.

/// Every host's committed height on `shard`, `None` where the host does
/// not carry it — the stall report a wedge is read from.
fn heights(c: &SimCluster, shard: ShardId) -> Vec<(usize, Option<u64>)> {
    (0..c.runner().num_hosts() as usize)
        .map(|host| {
            (
                host,
                c.host_committed_height(host, shard).map(BlockHeight::inner),
            )
        })
        .collect()
}

/// The chain advances again after `restarted` of four members bounce
/// together, with traffic either side of the bounce.
fn restart_and_advance(restarted: usize, seed: u64) {
    let mut cluster = SimCluster::with_accounts(&one_shard(), seed, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    let (payer, from) = sender(0);

    for index in 0..4u8 {
        let tx = build_transfer_tx(
            &payer,
            from,
            recipient(index),
            10,
            validity_around(cluster.now()),
        );
        cluster.submit(Arc::new(tx));
    }
    assert!(
        cluster.run_until(epochs(8), |c| c
            .committed_height(shard)
            .is_some_and(|h| h.inner() > 3)),
        "the chain must be running before the restart",
    );

    let hosts = cluster.committee_hosts(shard);
    let before = cluster
        .committed_height(shard)
        .expect("the chain is running");
    for &host in hosts.iter().take(restarted) {
        cluster.restart_host(host);
    }

    let target = before.inner() + 5;
    assert!(
        cluster.run_until(epochs(24), |c| c
            .committed_height(shard)
            .is_some_and(|h| h.inner() >= target)),
        "seed {seed}: the chain must advance past {target:?} after {restarted} of four \
         restart; hosts sit at {:?}",
        heights(&cluster, shard),
    );
}

/// A committee keeps committing when part of it restarts at once.
///
/// One of four is carried by the three that stayed up, and the survivor
/// count is what makes that case say so little: the chain commits without
/// the restarted replica, and the commit is what reseats whatever its
/// rebuild missed. At two the quorum needs them back, so anything a
/// restart fails to rebuild stops the shard instead of healing behind it
/// — which is why the sweep runs to the largest minority rather than
/// asserting one restart and calling the path covered.
fn a_committee_advances_after_part_of_it_restarts(seed: u64) {
    for restarted in 1..=3 {
        restart_and_advance(restarted, seed);
    }
}

seeded!(
    a_committee_advances_after_part_of_it_restarts:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
    seed_2026 = 2026,
    seed_99 = 99,
    seed_5 = 5,
    seed_8 = 8,
);

/// A member whose process crashes for an epoch, with traffic either
/// side of it, comes back on the disk it left and catches up with its
/// committee.
fn a_crashed_member_catches_up_on_its_disk(seed: u64) {
    let mut cluster = SimCluster::with_accounts(&one_shard(), seed, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    let (payer, from) = sender(0);
    let transfer = |c: &mut SimCluster, index: u8| {
        let tx = build_transfer_tx(&payer, from, recipient(index), 10, validity_around(c.now()));
        c.submit(Arc::new(tx));
    };

    for index in 0..4u8 {
        transfer(&mut cluster, index);
    }
    assert!(
        cluster.run_until(epochs(8), |c| c
            .committed_height(shard)
            .is_some_and(|h| h.inner() > 3)),
        "the chain must be running before the crash",
    );
    let host = cluster.committee_hosts(shard)[0];
    cluster.crash(host, Crash::Process, epochs(1));
    for index in 4..8u8 {
        transfer(&mut cluster, index);
    }
    assert!(
        cluster.run_until(epochs(1), |c| c
            .host_committed_height(host, shard)
            .is_some()),
        "seed {seed}: host {host} must be back once its downtime is over",
    );

    let target = cluster
        .committed_height(shard)
        .expect("the chain is running")
        .inner()
        + 5;
    assert!(
        cluster.run_until(epochs(24), |c| c
            .host_committed_height(host, shard)
            .is_some_and(|h| h.inner() >= target)),
        "seed {seed}: the restarted host must catch up past {target}; hosts sit at {:?}",
        heights(&cluster, shard),
    );
}

seeded!(
    a_crashed_member_catches_up_on_its_disk:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
);

/// A member whose store is restored from a copy its peers have since
/// pruned beneath needs, on restart, a height beneath every peer's chain
/// floor: block sync cannot carry it forward. Its loop re-seats on a store
/// snap-synced at the attested anchor, and block sync carries that one
/// past the anchor.
///
/// The member is down for an instant, not for the span the floor moves
/// over: a member absent that long is jailed and placed off the shard,
/// and its store is never seated again until it is drawn back on.
fn a_member_behind_every_floor_reseats(seed: u64) {
    let mut cluster = SimCluster::with_accounts(&one_shard(), seed, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    assert!(
        cluster.run_until(epochs(8), |c| c
            .committed_height(shard)
            .is_some_and(|h| h.inner() > 3)),
        "seed {seed}: the chain must be running before the copy",
    );
    let (host, _) = committee_member_host(cluster.runner(), shard, None);
    let disk = cluster
        .runner()
        .hosts_shard(host, shard)
        .expect("the member carries the shard")
        .clone();
    let old = disk.image();
    let behind = disk.committed_height();
    let peers: Vec<NodeIndex> = (0..cluster.runner().num_hosts())
        .filter(|&peer| peer != host)
        .collect();
    assert!(
        cluster.run_until(epochs(80), |c| peers.iter().all(|&peer| c
            .runner()
            .hosts_shard(peer, shard)
            .is_some_and(|store| store.chain_floor() > behind.next()
                && store.get_block(behind.next()).is_none()))),
        "seed {seed}: every peer's floor must pass the height after the copy's tip {behind:?}",
    );
    let anchor = cluster
        .runner()
        .host_topology(peers[0])
        .and_then(|topology| topology.boundary(shard))
        .expect("a pruned shard has an attested anchor")
        .height;

    cluster
        .runner_mut()
        .crash_host(host, CrashKind::Process, Duration::from_millis(1));
    disk.restore(&old);
    assert!(
        cluster.run_until(epochs(4), |c| c
            .runner()
            .hosts_shard(host, shard)
            .is_some_and(
                |store| store.installed_genesis().is_none() && store.committed_height() > anchor
            )),
        "seed {seed}: the member must re-seat on a store snap-synced at the anchor {anchor:?} \
         and sync past it; hosts sit at {:?}",
        heights(&cluster, shard),
    );
}

seeded!(
    a_member_behind_every_floor_reseats:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
);

/// The attested boundary `shard` stands at on `host`'s topology.
fn attested(c: &SimCluster, host: NodeIndex, shard: ShardId) -> Option<BlockHeight> {
    c.runner()
        .host_topology(host)
        .and_then(|topology| topology.boundary(shard))
        .map(|anchor| anchor.height)
}

/// A four-member shard with no pool to refill from keeps its beacon
/// proposing through a member's outage. The beacon draws its committee
/// from four eligible members; jailing the absent one would leave three,
/// no committee could form again, and the skips that followed would fold
/// nothing that could ever lift the jail or attest another boundary.
fn the_beacon_outlives_a_member_down_for_epochs(seed: u64) {
    let mut cluster = SimCluster::with_accounts(&one_shard(), seed, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    let (host, _) = committee_member_host(cluster.runner(), shard, None);
    let peer = (0..cluster.runner().num_hosts())
        .find(|&peer| peer != host)
        .expect("a four-member shard has other hosts");
    assert!(
        cluster.run_until(epochs(8), |c| attested(c, peer, shard).is_some()),
        "seed {seed}: the shard must cross its first boundary",
    );
    cluster.runner_mut().crash_host(
        host,
        CrashKind::Process,
        Duration::from_millis(EPOCH_MS * 3),
    );
    assert!(
        cluster.run_until(epochs(6), |c| c.runner().is_up(host)),
        "seed {seed}: the member comes back once its downtime is over",
    );
    let returned = attested(&cluster, peer, shard).expect("an attested boundary stays");
    assert!(
        cluster.run_until(epochs(12), |c| attested(c, peer, shard)
            .is_some_and(|height| height > returned)),
        "seed {seed}: the beacon must attest a boundary past {returned:?} after the member \
         returns; it stands at {:?}",
        attested(&cluster, peer, shard),
    );
}

seeded!(
    the_beacon_outlives_a_member_down_for_epochs:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
);

/// Crash a member of a running shard at each of a spread of its coming
/// storage writes, as `kind` says, under `processing`, and require it
/// back and caught up with its committee each time.
fn crashes_at_writes_and_catches_up(seed: u64, kind: Crash, processing: ProcessingTimes) {
    for writes_before in [0, 1, 2, 3, 5, 8, 13, 21] {
        let mut cluster = SimCluster::with_accounts_and_processing(
            &one_shard(),
            seed,
            &genesis_accounts(8, 1),
            processing,
        );
        let shard = ShardId::ROOT;
        let (payer, from) = sender(0);
        let transfer = |c: &mut SimCluster, index: u8| {
            let tx =
                build_transfer_tx(&payer, from, recipient(index), 10, validity_around(c.now()));
            c.submit(Arc::new(tx));
        };
        for index in 0..4u8 {
            transfer(&mut cluster, index);
        }
        assert!(
            cluster.run_until(epochs(8), |c| c
                .committed_height(shard)
                .is_some_and(|h| h.inner() > 3)),
            "the chain must be running before the crash",
        );

        let host = cluster.committee_hosts(shard)[0];
        let crashes = cluster.runner().stats().crashes;
        cluster.crash_at_write(host, writes_before, kind, epochs(1));
        for index in 4..8u8 {
            transfer(&mut cluster, index);
        }
        assert!(
            cluster.run_until(epochs(4), |c| c.runner().stats().crashes > crashes),
            "seed {seed}: host {host} must reach its write {writes_before} and crash there",
        );

        let target = cluster
            .committed_height(shard)
            .expect("the chain is running")
            .inner()
            + 5;
        assert!(
            cluster.run_until(epochs(24), |c| c
                .host_committed_height(host, shard)
                .is_some_and(|h| h.inner() >= target)),
            "seed {seed}: crashed ({kind:?}) at write {writes_before}, host {host} must catch \
             up past {target}; hosts sit at {:?}",
            heights(&cluster, shard),
        );
    }
}

/// A member whose process dies at one of its storage writes comes back
/// on the writes that landed before it and catches up with its
/// committee, wherever the write falls: a vote register, a block
/// commit, a beacon commit.
fn a_member_crashed_at_a_write_catches_up(seed: u64) {
    crashes_at_writes_and_catches_up(seed, Crash::Process, ProcessingTimes::INSTANT);
}

/// A member whose machine loses power at one of its storage writes
/// comes back on what its last synced write covered and catches up.
///
/// Its writes lag, so one Io run commits several blocks and syncs only
/// the last: a crash inside the run loses the deferred blocks before
/// it, which the replica may already have announced as committed.
fn a_member_that_loses_power_at_a_write_catches_up(seed: u64) {
    crashes_at_writes_and_catches_up(
        seed,
        Crash::Machine,
        ProcessingTimes {
            io: Duration::from_secs(2),
            ..ProcessingTimes::INSTANT
        },
    );
}

seeded!(
    a_member_that_loses_power_at_a_write_catches_up:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
);

seeded!(
    a_member_crashed_at_a_write_catches_up:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
);

/// A committee whose every replica restarts mid-traffic resumes, given a
/// live counterpart.
///
/// Restarting the whole committee is the case nothing local carries: the
/// certified block above the committed tip goes down with every replica
/// at once, and the QC each one recovers certifies a block none of them
/// holds. On a shard with no counterpart that is terminal — see
/// [`a_committee_advances_after_all_of_it_restarts`]. Here the shard has a
/// live sibling and the network recovers it, so the case that matters
/// operationally — a coordinated bounce of one shard's validators — is
/// covered rather than assumed.
///
/// The assertion is deliberately over the outcome and not the path: the
/// shard has to commit again, and the beacon and sibling have to stay live
/// while it does, whether it resumes on its own or the beacon misses its
/// boundary for `HALT_THRESHOLD_EPOCHS` folds and re-draws the committee.
/// It takes the first path today. The topology is the halt scenarios' one
/// because both paths need it: a lone stalled shard leaves no sibling to
/// carry the beacon through the folds that do the detecting, and no
/// counterpart to hold what the committee dropped.
#[test]
fn a_restarted_committee_resumes_beside_a_live_sibling() {
    let setup = halt_straddler_setup();
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &halt_recovery_config(),
        11,
        &setup.accounts,
    );
    cluster.run_faultable(|c| {
        split_lifecycle(c);
        let (halting, sibling) = ShardId::ROOT.children();
        let before = c
            .committed_height(halting)
            .expect("the split child commits")
            .inner();
        let sibling_before = c
            .committed_height(sibling)
            .expect("the sibling commits")
            .inner();

        // Restart the committee mid-pipeline. An idle committee loses
        // nothing — its certified tip is its committed tip, so the QC each
        // replica recovers certifies a block they all hold. The wedge needs
        // a certified block above the commit tip at the instant they go
        // down, which is what an owed outcome marks.
        let mut submitted = Vec::new();
        for leg in &setup.straddlers[..HALT_STRADDLER_BATCH] {
            let tx = build_leg_payment_tx(leg, 100, validity_around(c.now()));
            submitted.push(tx.hash());
            c.submit(Arc::new(tx));
        }
        let held = submitted[0];
        assert!(
            c.run_until(epochs(12), |c| {
                let (committed, _) = c.chain_fate(halting, held);
                committed.is_some()
            }),
            "the shard must be holding something for the restart to lose",
        );

        for host in c.committee_hosts(halting) {
            c.restart_host(host);
        }

        // Detection is a fold-driven miss count, so the budget is the
        // threshold plus room for the re-draw and the fresh committee's
        // sync — the same ceiling the staged-freeze scenarios allow.
        let threshold = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("threshold fits u32");
        let flagged = c.run_until(epochs(threshold + 25), |c| {
            c.beacon_state()
                .is_some_and(|state| state.pending_recoveries.contains_key(&halting))
                || c.committed_height(halting)
                    .is_some_and(|h| h.inner() > before + 2)
        });
        assert!(
            flagged,
            "a shard whose whole committee restarts must resume or be flagged \
             for re-draw; it sat at {:?}",
            c.committed_height(halting),
        );
        assert!(
            c.committed_height(sibling)
                .is_some_and(|h| h.inner() > sibling_before),
            "the sibling shard and the beacon must stay live throughout",
        );

        // Whichever path it took, the shard has to commit again.
        assert!(
            c.run_until(epochs(threshold + 25), |c| c
                .committed_height(halting)
                .is_some_and(|h| h.inner() > before + 2)),
            "the shard must commit again; it sat at {:?}",
            c.committed_height(halting),
        );
    });
}

/// A host that sat on a split's parent keeps the parent's store on disk
/// after the beacon has dropped the parent's terminal record, and the
/// committees it signed under stay in the windows a restarted host's
/// schedule may resume. Its restart resumes nothing on the dissolved
/// parent, and the children carry on.
fn a_restart_resumes_nothing_on_a_dissolved_parent(seed: u64) {
    let mut cluster = SimCluster::with_accounts(&split_config(), seed, &genesis_accounts(1, 1));
    split_lifecycle(&mut cluster);
    let root = ShardId::ROOT;
    let children: [ShardId; 2] = root.children().into();
    let host = (0..cluster.runner().num_hosts())
        .find(|&host| cluster.runner().hosts_shard(host, root).is_some())
        .expect("a parent member's host keeps the parent's store");
    let dropped = |c: &SimCluster| {
        c.runner()
            .beacon_storage(host)
            .and_then(|storage| storage.latest_committed())
            .is_some_and(|(_, state)| !state.boundaries.contains_key(&root))
    };
    assert!(
        cluster.run_until(epochs(24), dropped),
        "seed {seed}: host {host}'s beacon must drop the parent's terminal record",
    );
    assert!(
        cluster.runner().hosts_shard(host, root).is_some(),
        "seed {seed}: host {host} still holds the parent's store",
    );

    cluster.restart_host(host as usize);
    assert!(
        cluster.runner().hosts_shard(host, root).is_none(),
        "seed {seed}: host {host} must not resume a seat on the dissolved parent",
    );

    let past = |c: &SimCluster| {
        children.map(|child| c.committed_height(child).map_or(0, BlockHeight::inner))
    };
    let before = past(&cluster);
    assert!(
        cluster.run_until(epochs(8), |c| {
            let now = past(c);
            now[0] > before[0] + 2 && now[1] > before[1] + 2
        }),
        "seed {seed}: both children must keep committing past {before:?}; they sit at {:?}",
        past(&cluster),
    );
    assert!(
        cluster.runner().hosts_shard(host, root).is_none(),
        "seed {seed}: host {host} must stay off the dissolved parent",
    );
}

seeded!(
    a_restart_resumes_nothing_on_a_dissolved_parent:
    seed_11 = 11,
    seed_42 = 42,
);

/// Every replica restarting at once, on a shard with no counterpart.
///
/// The committee comes back holding its committed tip; the certified
/// block above it goes down with every replica at once, and the lock each
/// one recovers is on the QC certifying that block.
///
/// The single shard is the whole of the condition — with a live sibling
/// the shard resumes on what the sibling's committee still holds
/// ([`a_restarted_committee_resumes_beside_a_live_sibling`]), so what is
/// absent here is any counterpart holding what the committee dropped. The
/// lock cannot be lowered instead: nothing in a shard's own state
/// distinguishes "nothing was committed above me" from "an absent replica
/// committed and I would be forking away from it". So the block travels
/// with the record that locks on it, and the committee comes back able to
/// extend its own certificate.
fn a_committee_advances_after_all_of_it_restarts(seed: u64) {
    restart_and_advance(4, seed);
}

seeded!(
    a_committee_advances_after_all_of_it_restarts:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
    seed_2026 = 2026,
    seed_99 = 99,
    seed_5 = 5,
    seed_8 = 8,
);

/// The lowest tick any host's store holds in flight on `shard`, with its
/// members.
fn a_tick_in_flight(c: &SimCluster, shard: ShardId) -> Option<(BlockHeight, Vec<TxHash>)> {
    let runner = c.runner();
    (0..runner.num_hosts())
        .filter_map(|host| runner.hosts_shard(host, shard))
        .filter_map(|storage| {
            let family = storage.member_index(shard);
            let (height, tick) = family.ticks.first_key_value()?;
            Some((*height, tick.members.to_vec()))
        })
        .min_by_key(|(height, _)| *height)
}

/// More than f of four replicas restart while a tick is in flight, and
/// the tick still settles.
///
/// With a quorum down at once no survivor carries the tick for the
/// restarted replicas: each comes back to the rows its store holds and
/// seats the tick its manifest named, and a certificate not yet formed
/// needs their votes. Every member then reaches an outcome, every store
/// lets the tick's row go, and every replica holds one state at a height
/// they all reached.
fn a_tick_in_flight_survives(restarted: usize, seed: u64) {
    let mut cluster = SimCluster::with_accounts(&one_shard(), seed, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    let (payer, from) = sender(0);
    for index in 0..4u8 {
        let tx = build_transfer_tx(
            &payer,
            from,
            recipient(index),
            10,
            validity_around(cluster.now()),
        );
        cluster.submit(Arc::new(tx));
    }
    assert!(
        cluster.run_until(epochs(8), |c| a_tick_in_flight(c, shard).is_some()),
        "seed {seed}: a tick must be in flight for the restart to land in",
    );
    let (tick, members) = a_tick_in_flight(&cluster, shard).expect("just seen");
    for &host in cluster.committee_hosts(shard).iter().take(restarted) {
        cluster.restart_host(host);
    }

    for tx in members {
        let status = await_tx_terminal(&mut cluster, tx, epochs(24));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "seed {seed}: a member of tick {tick:?} must reach an outcome after {restarted} \
             of four restart; status = {status:?}, hosts at {:?}",
            heights(&cluster, shard),
        );
    }
    let hosts = cluster.committee_hosts(shard);
    let settled_everywhere = |c: &SimCluster| {
        hosts.iter().all(|&host| {
            c.runner()
                .hosts_shard(u32::try_from(host).expect("a host index"), shard)
                .is_some_and(|storage| !storage.member_index(shard).ticks.contains_key(&tick))
        })
    };
    assert!(
        cluster.run_until(epochs(24), settled_everywhere),
        "seed {seed}: every replica must commit the settlement of tick {tick:?} after \
         {restarted} of four restart; hosts at {:?}",
        heights(&cluster, shard),
    );
    let height = hosts
        .iter()
        .map(|&host| {
            cluster
                .host_committed_height(host, shard)
                .expect("every member commits again")
        })
        .min()
        .expect("a committee");
    let runner = cluster.runner();
    let replicas: Vec<_> = hosts
        .iter()
        .map(|&host| {
            let storage = runner
                .hosts_shard(u32::try_from(host).expect("a host index"), shard)
                .expect("every member stores the shard");
            let root = cluster
                .host_block(host, shard, height)
                .map(|certified| certified.block().header().state_root());
            (root, storage.member_index(shard))
        })
        .collect();
    for (root, family) in &replicas {
        assert!(root.is_some(), "seed {seed}: every member holds {height:?}");
        assert!(
            !family.ticks.contains_key(&tick),
            "seed {seed}: the settled tick's row is gone: {family:?}",
        );
    }
    assert!(
        replicas.windows(2).all(|pair| pair[0].0 == pair[1].0),
        "seed {seed}: every replica holds one state at {height:?}",
    );
}

/// [`a_tick_in_flight_survives`] with two and with three of four
/// restarted, across the seeds.
fn a_tick_in_flight_survives_more_than_f_restarting(seed: u64) {
    for restarted in 2..=3 {
        a_tick_in_flight_survives(restarted, seed);
    }
}

seeded!(
    a_tick_in_flight_survives_more_than_f_restarting:
    seed_42 = 42,
    seed_7 = 7,
    seed_11 = 11,
    seed_1337 = 1337,
    seed_2026 = 2026,
    seed_99 = 99,
    seed_5 = 5,
    seed_8 = 8,
);

/// A restarted member agrees with its peers about what it executed.
///
/// The membership assertion in its strong form. Composing a tick alone
/// aborts the process through `escalate_divergence` — which a replayed
/// replica is exposed to whether or not its vote reaches anyone, since
/// building the vote is what latches the local root the returning
/// certificate is reconciled against. So surviving the run says
/// something; agreeing on the committed state root at one height says
/// the whole of it.
#[test]
fn a_restarted_member_agrees_on_the_state_it_rebuilt() {
    let mut cluster = SimCluster::with_accounts(&one_shard(), 42, &genesis_accounts(8, 1));
    let shard = ShardId::ROOT;
    let (payer, from) = sender(0);

    // Traffic either side of the restart, so the replica comes back with
    // something outstanding and keeps composing afterwards.
    let mut submitted = Vec::new();
    for index in 0..4u8 {
        let tx = build_transfer_tx(
            &payer,
            from,
            recipient(index),
            10,
            validity_around(cluster.now()),
        );
        submitted.push(tx.hash());
        cluster.submit(Arc::new(tx));
    }
    let held = submitted[0];
    assert!(
        cluster.run_until(epochs(8), |c| owed_an_outcome(c, shard, held)),
        "the shard must be holding something for the restart to have to rebuild",
    );

    let host = *cluster
        .committee_hosts(shard)
        .first()
        .expect("the shard has a seated committee");
    cluster.restart_host(host);

    for tx in submitted {
        let status = await_tx_terminal(&mut cluster, tx, epochs(24));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "every transaction must reach an outcome across the restart; status = {status:?}",
        );
    }

    // And the restarted replica computed the same state as a peer that
    // never went down, at a height they both hold.
    let peer = *cluster
        .committee_hosts(shard)
        .iter()
        .find(|&&h| h != host)
        .expect("a peer that never restarted");
    let height = cluster
        .host_committed_height(host, shard)
        .expect("the restarted host is committing")
        .min(
            cluster
                .host_committed_height(peer, shard)
                .expect("the peer is committing"),
        );
    let root_at = |c: &SimCluster, h: usize| {
        c.host_block(h, shard, height)
            .map(|certified| certified.block().header().state_root())
    };
    assert!(
        root_at(&cluster, host).is_some(),
        "the restarted host must hold the height it is compared at",
    );
    assert_eq!(
        root_at(&cluster, host),
        root_at(&cluster, peer),
        "a restarted replica's fold must be the one its committee agreed on",
    );
}

/// A leg's reclaim survives its committee restarting between the leg's
/// own finalization and the core's refusal.
///
/// The window this opens is the one the replay fold has to reach. The
/// caller's shard runs the swap's withdraw as a leg: it pays, issues the
/// crossing and certifies, and its own finalization decides nothing —
/// the venue's does, later. A restart in between loses everything
/// execution held in memory, so the entry that names what the reclaim
/// would take back has to come back off the chain: a leg's own
/// finalization retires nothing from the replay floor, and the fold
/// reads to a leg entry's horizon rather than to a whole entry's
/// deadline. A replay that stopped at either would come back to a
/// refusal holding nothing for the transaction, no reclaim would be
/// composed, and the caller's input would sit in a record cell until
/// its grace sweeps it.
///
/// The whole committee restarts, not one member: a single replica would
/// be carried by its peers, and what is under test is the entry rather
/// than the vote.
#[test]
fn a_restarted_payer_still_reclaims_its_refused_leg() {
    payer_reclaims_after_restart(42, &venue_config());
}

/// A restart brings back every member the host carried.
///
/// Two validators to a host leave every four-member committee on at
/// most two hosts, so the payer shard's restarted hosts each carry more
/// than one of its members. A restart that reseated one of them would
/// leave the committee a member short of its quorum with nothing failed:
/// the shard commits the block its survivors had already voted, then
/// never another.
#[test]
fn a_restarted_host_reseats_every_member_it_carries() {
    payer_reclaims_after_restart(
        1,
        &ScenarioConfig {
            vnodes_per_host: 2,
            ..venue_config()
        },
    );
}

fn payer_reclaims_after_restart(seed: u64, config: &ScenarioConfig) {
    let mut cluster = SimCluster::with_grown_packages(
        config,
        seed,
        &venue_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(&mut cluster, VENUE_SHARD, &mut taken);
    let (caller_key, caller) = grind_onto(SWAPPER_SHARD, &mut taken);

    // A floor no pool this size can pay, so the venue declines and the
    // caller's leg is left holding a crossing nobody claims.
    let refused = build_swap_tx(
        &caller_key,
        caller,
        &venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        SWAP_INPUT * 100,
        validity_around(cluster.now()),
    );
    let price = declared_price(&cluster, &refused);
    let funded = vault_balance(&cluster, SWAPPER_SHARD, caller);
    let hash = refused.hash();
    cluster.submit(Arc::new(refused));

    // The leg has paid and certified: its own finalization is on the
    // caller's chain, naming a transaction it does not decide.
    assert!(
        cluster.run_until(epochs(12), |c| {
            vault_balance(c, SWAPPER_SHARD, caller) == funded - SWAP_INPUT - price
                && c.chain_fate(SWAPPER_SHARD, hash).0.is_some()
        }),
        "the caller's leg must pay and commit before the restart",
    );
    assert!(
        cluster.chain_fate(VENUE_SHARD, hash).1.is_none(),
        "the venue must not have refused yet, or the restart lands after \
         the evidence rather than before it",
    );

    let hosts = cluster.committee_hosts(SWAPPER_SHARD);
    let before = cluster.committed_height(SWAPPER_SHARD).expect("running");
    for host in hosts {
        cluster.restart_host(host);
    }

    // The refusal arrives to a restarted shard, and the reclaim it
    // licenses is composed from the entry the replay rebuilt.
    assert!(
        cluster.run_until(epochs(24), |c| vault_balance(c, SWAPPER_SHARD, caller)
            == funded - price),
        "a restarted payer must still reclaim what its leg issued: holds {}, \
         expected {}; the payer shard committed {before:?} before the restart and \
         its hosts sit at {:?}",
        vault_balance(&cluster, SWAPPER_SHARD, caller),
        funded - price,
        heights(&cluster, SWAPPER_SHARD),
    );
}

/// A payer replica restarted past a crossing's deadline asks the answer
/// whose push was lost at once, carrying no backoff across the restart.
#[test]
fn a_restarted_producer_asks_a_lost_answer_at_once() {
    let mut cluster = SimCluster::with_grown_accounts_on_dedicated_pool_hosts(
        &venue_config(),
        42,
        &cross_shard_genesis_accounts(),
    );
    cluster.run_faultable(|c| {
        a_rejoined_producer_asks_a_lost_answer(c, |c, host, _| c.restart_host(host));
    });
}

/// A payer replica snap-synced past a crossing's deadline asks the
/// answer whose push was lost at once, off the rows it imported.
#[test]
fn a_snap_synced_producer_asks_a_lost_answer_at_once() {
    let mut cluster = SimCluster::with_grown_accounts_on_dedicated_pool_hosts(
        &venue_config(),
        42,
        &cross_shard_genesis_accounts(),
    );
    cluster.run_faultable(|c| {
        a_rejoined_producer_asks_a_lost_answer(c, |c, host, shard| {
            c.resync_host(host, shard);
        });
    });
}

/// Submit a transfer of most of sender 0's funding to `recipient`, and
/// wait for it to commit: its transaction and the height it committed at.
/// Two of them overdraw the sender, so the second one's outcome turns on
/// whether its baseline holds the first's debit.
fn commit_overdrawing_transfer(
    cluster: &mut SimCluster,
    recipient_index: u8,
) -> (TxHash, BlockHeight) {
    let (payer, from) = sender(0);
    let tx = build_transfer_tx(
        &payer,
        from,
        recipient(recipient_index),
        6_000,
        validity_around(cluster.now()),
    );
    let hash = tx.hash();
    cluster.submit(Arc::new(tx));
    assert!(
        cluster.run_until(epochs(4), |c| c.chain_fate(ShardId::ROOT, hash).0.is_some()),
        "transfer to recipient {recipient_index} must commit",
    );
    let committed = cluster
        .chain_fate(ShardId::ROOT, hash)
        .0
        .expect("just committed");
    (hash, committed)
}

/// A replica that snap-syncs at a boundary crossed while a tick below it
/// had run but not settled reads that tick's writes in every tick it runs
/// before the settlement commits.
///
/// The anchor's state carries what had settled at the boundary and no
/// more, so the unsettled tick's writes live only in the incumbents' tick
/// chains. Here that tick drains most of a payer's balance and the next
/// transfer off the same payer commits above the anchor, before the first
/// settles: the incumbents refuse it as an overdraw, and a joiner reading
/// the balance off its anchor alone pays it.
#[test]
fn a_snap_sync_joiner_reads_an_unsettled_tick_below_its_anchor() {
    let shard = ShardId::ROOT;
    let mut cluster = SimCluster::with_accounts(
        &one_shard(),
        42,
        &[
            (sender(0).1, 10_000),
            (recipient(0), 10),
            (recipient(1), 10),
        ],
    );
    let warm = cluster.runner().now() + Duration::from_secs(5);
    cluster.runner_mut().run_until(warm);

    // No tick certifies while the votes are dropped, so the first
    // transfer's tick runs everywhere and settles nowhere.
    let _votes = cluster.drop_type("execution.vote");
    let (first_hash, first_committed) = commit_overdrawing_transfer(&mut cluster, 0);

    // Until the beacon attests a boundary above its commit, so the
    // joiner's anchor sits above the tick.
    let joiner = cluster.committee_hosts(shard)[0];
    let peer = cluster.committee_hosts(shard)[1];
    let attested = |c: &SimCluster| {
        c.runner()
            .host_topology(u32::try_from(joiner).expect("a host index"))
            .and_then(|topology| topology.boundary(shard))
            .map(|anchor| anchor.height)
    };
    assert!(
        cluster.run_until(epochs(4), |c| attested(c)
            .is_some_and(|height| height >= first_committed)),
        "the beacon must attest a boundary above the first transfer's commit",
    );
    assert!(
        owed_an_outcome(&cluster, shard, first_hash),
        "the first transfer's tick must still be unsettled at the boundary",
    );

    let anchor = attested(&cluster).expect("just attested");
    cluster.resync_host(joiner, shard);
    assert!(
        cluster.run_until(epochs(4), |c| c
            .host_committed_height(joiner, shard)
            .is_some_and(|h| h > anchor)),
        "the joiner must snap-sync and commit again",
    );
    assert!(
        cluster
            .runner()
            .hosts_shard(u32::try_from(joiner).expect("a host index"), shard)
            .is_some_and(|store| store.installed_genesis().is_none()),
        "the joiner must have snap-synced rather than replayed from genesis",
    );
    assert!(
        anchor >= first_committed,
        "the joiner's anchor {anchor:?} must sit at or above the first transfer's commit \
         {first_committed:?}",
    );
    assert!(
        owed_an_outcome(&cluster, shard, first_hash),
        "the first transfer's tick must still be unsettled once the joiner is seated",
    );

    let (second_hash, second_committed) = commit_overdrawing_transfer(&mut cluster, 1);
    assert!(
        second_committed > anchor && owed_an_outcome(&cluster, shard, first_hash),
        "the second transfer must commit above the anchor {anchor:?} (at {second_committed:?}) \
         before the first settles",
    );
    cluster.clear_drops();
    assert_ran_alike(&mut cluster, shard, joiner, peer, second_hash);
    for tx in [first_hash, second_hash] {
        let status = await_tx_terminal(&mut cluster, tx, epochs(8));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "both transfers must reach an outcome once the votes flow; status = {status:?}",
        );
    }
}

/// The receipt root `host` voted for the tick holding `tx` on `shard`,
/// while that tick is seated there and `host` has run it.
fn voted_root(
    c: &SimCluster,
    host: usize,
    shard: ShardId,
    tx: TxHash,
) -> Option<GlobalReceiptRoot> {
    let execution = c
        .runner()
        .vnode_state_in(u32::try_from(host).expect("a host index"), shard)?
        .execution_coordinator();
    execution.voted_receipt_root(&execution.tick_assignment_for(tx)?)
}

/// Run until `replica` and `peer` have each voted on the tick holding
/// `tx` on `shard`, and assert they voted one receipt root for it.
///
/// What a replica computed is read off its own vote rather than off
/// anything its committee certified: a block header, a settled state root
/// and a stored receipt are each one value every replica holds alike,
/// whatever its own run said. A vote is readable only while its tick is
/// seated, so the run steps finely enough to read each one between the
/// run that cast it and the commit that settles the tick, and the first
/// read comes before any step, while a vote cast under dropped traffic
/// is still uncertified.
fn assert_ran_alike(c: &mut SimCluster, shard: ShardId, replica: usize, peer: usize, tx: TxHash) {
    const STEP: Duration = Duration::from_millis(10);
    let deadline = c.now() + Duration::from_millis(EPOCH_MS * 4);
    let (mut ran, mut incumbent) = (None, None);
    loop {
        ran = ran.or_else(|| voted_root(c, replica, shard, tx));
        incumbent = incumbent.or_else(|| voted_root(c, peer, shard, tx));
        if (ran.is_some() && incumbent.is_some()) || c.now() >= deadline {
            break;
        }
        c.runner_mut().topology_step();
        let next = c.now() + STEP;
        c.runner_mut().run_until(next);
    }
    assert!(
        ran.is_some() && incumbent.is_some(),
        "replica {replica} and incumbent {peer} must each vote on the tick holding {tx:?}: \
         {ran:?}, {incumbent:?}",
    );
    assert_eq!(
        ran, incumbent,
        "replica {replica} must run the tick holding {tx:?} as incumbent {peer} did",
    );
}

/// The venue world's genesis funding with a recipient of its own beside
/// it on the venue's shard, the caller the world funds there, and that
/// recipient: the venue world's grind, in its order, carried one account
/// further.
fn venue_caller_accounts() -> (
    Vec<(PrincipalAddr, u128)>,
    (Ed25519PrivateKey, PrincipalAddr),
    PrincipalAddr,
) {
    let mut grind = Vec::new();
    let _provider = grind_onto(VENUE_SHARD, &mut grind);
    for _ in 0..SWAPPERS {
        let _swapper = grind_onto(SWAPPER_SHARD, &mut grind);
    }
    let caller = grind_onto(VENUE_SHARD, &mut grind);
    let (_, local) = grind_onto(VENUE_SHARD, &mut grind);
    let mut accounts = venue_genesis_accounts();
    accounts.push((local, 10));
    (accounts, caller, local)
}

/// The tick `host`'s store for `shard` holds `tx` in, while that tick has
/// settled its determined half and still owes its legs half.
fn legs_owed(c: &SimCluster, host: usize, shard: ShardId, tx: TxHash) -> Option<BlockHeight> {
    let family = c
        .runner()
        .hosts_shard(u32::try_from(host).expect("a host index"), shard)?
        .member_index(shard);
    let RowState::InFlight { tick, .. } = family.members.get(&tx)?.state else {
        return None;
    };
    let row = family.ticks.get(&tick)?;
    (row.legs_unsettled && !row.determined_unsettled).then_some(tick)
}

/// A replica that snap-syncs at a boundary crossed while a tick below it
/// still owed its legs half holds what those legs reserved against every
/// tick it runs before they settle.
///
/// A swap by a caller on the venue's own shard, its fee paid by a sponsor
/// on the other shard, runs whole on both: the caller's member on the
/// venue's shard awaits the sponsor's shard's certificate, and its
/// withdraw reserves the caller's vault until that certificate lands. The
/// sponsor's shard certifies nothing while its votes are dropped, so the
/// venue's tick settles its determined half and stays owed its legs half
/// across the boundary the joiner snap-syncs at. A local transfer off the
/// caller's vault then commits above the anchor, overdrawing it beside
/// the reservation: the incumbents judge it against the hold and refuse
/// it, and a joiner holding no reservation pays it.
#[test]
fn a_snap_sync_joiner_holds_what_a_pending_leg_below_its_anchor_reserved() {
    /// What the swap withdraws: more than half the caller's funding, so
    /// the transfer cannot be paid beside it.
    const RESERVED: u128 = 120_000_000;
    /// What the local transfer moves: covered by the caller's balance and
    /// not by what the swap leaves unreserved.
    const OVERDRAWN: u128 = 100_000_000;

    let shard = VENUE_SHARD;
    let (accounts, (caller_key, caller), local) = venue_caller_accounts();
    let mut cluster = SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &venue_config(),
        42,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(&mut cluster, shard, &mut taken);
    let (sponsor_key, _) = grind_onto(SWAPPER_SHARD, &mut taken);
    let funded = vault_balance(&cluster, shard, caller);
    assert!(
        (OVERDRAWN..RESERVED + OVERDRAWN).contains(&funded),
        "the transfer must be covered alone and not beside the swap: the caller holds {funded}",
    );

    let hosts = cluster.committee_hosts(shard);
    let (joiner, peer) = (hosts[0], hosts[1]);
    let sponsors = cluster.committee_hosts(SWAPPER_SHARD);

    // The sponsor's shard certifies no tick, so the caller's member never
    // learns its verdict.
    let _votes = cluster.drop_type_between(&sponsors, &sponsors, "execution.vote");
    let first = build_sponsored_swap_tx(
        &sponsor_key,
        &caller_key,
        caller,
        &venue.meta,
        RESERVED,
        0,
        validity_around(cluster.now()),
    );
    let first_hash = first.hash();
    cluster.submit(Arc::new(first));

    let legs_owed = |c: &SimCluster| legs_owed(c, peer, shard, first_hash);
    assert!(
        cluster.run_until(epochs(8), |c| legs_owed(c).is_some()),
        "the swap must run on the venue's shard and stay owed its legs half",
    );
    let leg_tick = legs_owed(&cluster).expect("just seen");

    let joiner_index = u32::try_from(joiner).expect("a host index");
    assert!(
        cluster.run_until(epochs(4), |c| attested(c, joiner_index, shard)
            .is_some_and(|h| h >= leg_tick)),
        "the beacon must attest a venue boundary at or above the swap's tick {leg_tick:?}",
    );
    let anchor = attested(&cluster, joiner_index, shard).expect("just attested");
    assert_eq!(
        legs_owed(&cluster),
        Some(leg_tick),
        "the swap must still be owed its verdict at the boundary {anchor:?}",
    );

    snap_sync_past(&mut cluster, joiner, shard, anchor);
    assert_eq!(
        legs_owed(&cluster),
        Some(leg_tick),
        "the swap must still be owed its verdict once the joiner is seated",
    );

    // The venue's shard certifies no tick either, so the transfer's tick
    // is still seated everywhere when the joiner, held behind the swap's
    // legs, gets to run it.
    let _venue_votes = cluster.drop_type_between(&hosts, &hosts, "execution.vote");
    let (second_hash, second_committed) =
        commit_transfer(&mut cluster, shard, (&caller_key, caller), local, OVERDRAWN);
    assert!(
        second_committed > anchor,
        "the local transfer must commit above the anchor {anchor:?}, at {second_committed:?}",
    );
    assert_eq!(
        legs_owed(&cluster),
        Some(leg_tick),
        "the local transfer must commit while the swap is still owed its verdict",
    );

    // The sponsor's shard certifies again; the venue's still does not.
    cluster.clear_drops();
    let _venue_votes = cluster.drop_type_between(&hosts, &hosts, "execution.vote");
    assert_ran_alike(&mut cluster, shard, joiner, peer, second_hash);
    cluster.clear_drops();
    let second_status = await_tx_terminal(&mut cluster, second_hash, epochs(8));
    assert!(
        matches!(
            second_status,
            Some(TransactionStatus::Completed(decision)) if decision != TransactionDecision::Accept
        ),
        "the local transfer must be refused beside the swap's reservation; \
         status = {second_status:?}",
    );
    let status = await_tx_terminal(&mut cluster, first_hash, epochs(8));
    assert!(
        matches!(status, Some(TransactionStatus::Completed(_))),
        "the swap must reach an outcome once the votes flow; status = {status:?}",
    );
}

/// Submit a transfer of `amount` from `payer` to `to`, and wait for
/// `shard` to commit it: its transaction and the height it committed at.
fn commit_transfer(
    c: &mut SimCluster,
    shard: ShardId,
    (key, payer): (&Ed25519PrivateKey, PrincipalAddr),
    to: PrincipalAddr,
    amount: u128,
) -> (TxHash, BlockHeight) {
    let tx = build_transfer_tx(key, payer, to, amount, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));
    assert!(
        c.run_until(epochs(4), |c| c.chain_fate(shard, hash).0.is_some()),
        "the transfer to {to:?} must commit",
    );
    let committed = c.chain_fate(shard, hash).0.expect("just committed");
    (hash, committed)
}

/// Delete `joiner`'s store for `shard` and run until it has snap-synced
/// and committed past `anchor`.
fn snap_sync_past(c: &mut SimCluster, joiner: usize, shard: ShardId, anchor: BlockHeight) {
    c.resync_host(joiner, shard);
    assert!(
        c.run_until(epochs(4), |c| c
            .host_committed_height(joiner, shard)
            .is_some_and(|h| h > anchor)),
        "the joiner must snap-sync and commit past {anchor:?}",
    );
    assert!(
        c.runner()
            .hosts_shard(u32::try_from(joiner).expect("a host index"), shard)
            .is_some_and(|store| store.installed_genesis().is_none()),
        "the joiner must have snap-synced rather than replayed from genesis",
    );
}

/// A replica restarted while a transaction above a tick is still owed
/// holds what that tick's legs reserved, though their verdict committed
/// before the restart.
///
/// The sponsored swap of
/// `a_snap_sync_joiner_holds_what_a_pending_leg_below_its_anchor_reserved`
/// reserves the caller's vault until the sponsor's shard certifies it. A
/// local transfer off the same vault then commits above the swap's tick,
/// overdrawing it beside the reservation, and is refused. The transfer's
/// tick certifies only after the swap's verdict commits, so all a restart
/// then owes starts at the transfer's commit, above the swap's tick, and
/// the replay reruns the transfer: a replica that reads no hold there
/// pays it, against a committee that refused it.
#[test]
fn a_restarted_replica_holds_what_a_leg_settled_in_its_replay_reserved() {
    /// What the swap withdraws: more than half the caller's funding, so
    /// the transfer cannot be paid beside it.
    const RESERVED: u128 = 120_000_000;
    /// What the local transfer moves: covered by the caller's balance and
    /// not by what the swap leaves unreserved.
    const OVERDRAWN: u128 = 100_000_000;

    let shard = VENUE_SHARD;
    let (accounts, (caller_key, caller), local) = venue_caller_accounts();
    let mut cluster = SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &venue_config(),
        42,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(&mut cluster, shard, &mut taken);
    let (sponsor_key, _) = grind_onto(SWAPPER_SHARD, &mut taken);
    let funded = vault_balance(&cluster, shard, caller);
    assert!(
        (OVERDRAWN..RESERVED + OVERDRAWN).contains(&funded),
        "the transfer must be covered alone and not beside the swap: the caller holds {funded}",
    );

    // Standing the venue up leaves a leg on its shard that no
    // finalization there decides, which holds the replay floor until it
    // ages past the evidence horizon. Past it, the floor is the
    // scenario's own.
    let aged = cluster.runner().now() + TRANSACTION_EVIDENCE_HORIZON + Duration::from_secs(60);
    cluster.runner_mut().run_until(aged);

    let hosts = cluster.committee_hosts(shard);
    let (restarted, peer) = (hosts[0], hosts[1]);
    let sponsors = cluster.committee_hosts(SWAPPER_SHARD);

    // The sponsor's shard certifies no tick, so the caller's member never
    // learns its verdict.
    let _sponsor_votes = cluster.drop_type_between(&sponsors, &sponsors, "execution.vote");
    let first = build_sponsored_swap_tx(
        &sponsor_key,
        &caller_key,
        caller,
        &venue.meta,
        RESERVED,
        0,
        validity_around(cluster.now()),
    );
    let first_hash = first.hash();
    cluster.submit(Arc::new(first));
    assert!(
        cluster.run_until(epochs(8), |c| legs_owed(c, peer, shard, first_hash)
            .is_some()),
        "the swap must run on the venue's shard and stay owed its legs half",
    );
    let leg_tick = legs_owed(&cluster, peer, shard, first_hash).expect("just seen");

    // The venue's shard certifies no tick either, so the transfer runs
    // against the reservation everywhere and settles nowhere.
    let _venue_votes = cluster.drop_type_between(&hosts, &hosts, "execution.vote");
    let (second_hash, second_committed) =
        commit_transfer(&mut cluster, shard, (&caller_key, caller), local, OVERDRAWN);
    assert!(
        second_committed > leg_tick,
        "the local transfer must commit above the swap's tick {leg_tick:?}, at \
         {second_committed:?}",
    );

    // The sponsor's shard certifies again; the venue's still does not.
    cluster.clear_drops();
    let _venue_votes = cluster.drop_type_between(&hosts, &hosts, "execution.vote");
    assert!(
        cluster.run_until(epochs(8), |c| c.chain_fate(shard, first_hash).1.is_some()),
        "the swap's verdict must commit on the venue's shard",
    );
    let (verdict, _) = cluster
        .chain_fate(shard, first_hash)
        .1
        .expect("just committed");
    assert!(
        verdict >= second_committed && owed_an_outcome(&cluster, shard, second_hash),
        "the swap's verdict must commit at or above the transfer's commit \
         {second_committed:?} (at {verdict:?}) while the transfer is owed its outcome",
    );

    cluster.restart_host(restarted);
    assert_ran_alike(&mut cluster, shard, restarted, peer, second_hash);
    cluster.clear_drops();
    let second_status = await_tx_terminal(&mut cluster, second_hash, epochs(8));
    assert!(
        matches!(
            second_status,
            Some(TransactionStatus::Completed(decision)) if decision != TransactionDecision::Accept
        ),
        "the local transfer must be refused beside the swap's reservation; \
         status = {second_status:?}",
    );
}
