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

use hyperscale_engine::XRD;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::query::{declared_price, vault_balance};
use hyperscale_scenarios::tx::{
    HALT_STRADDLER_BATCH, build_swap_tx, build_transfer_tx, genesis_accounts, halt_straddler_setup,
    recipient, sender, validity_around,
};
use hyperscale_scenarios::wait::await_tx_terminal;
use hyperscale_scenarios::{
    Cluster, FaultableCluster, SWAP_INPUT, SWAPPER_SHARD, ScenarioConfig, VENUE_SHARD, epochs,
    grind_onto, split_lifecycle, stand_up_venue, venue_genesis_accounts,
};
use hyperscale_types::{BlockHeight, HALT_THRESHOLD_EPOCHS, ShardId, TransactionStatus, TxHash};
use support::SimCluster;

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

/// The seeds every restart here runs under: one seed is one leader
/// schedule, and a restart lands differently against each.
const SEEDS: [u64; 8] = [42, 7, 11, 1337, 2026, 99, 5, 8];

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
        cluster.restart_host(host, shard);
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
#[test]
fn a_committee_advances_after_part_of_it_restarts() {
    for seed in SEEDS {
        for restarted in 1..=3 {
            restart_and_advance(restarted, seed);
        }
    }
}

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
        for (key, from, to) in &setup.straddlers[..HALT_STRADDLER_BATCH] {
            let tx = build_transfer_tx(key, *from, *to, 100, validity_around(c.now()));
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
            c.restart_host(host, halting);
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
#[test]
fn a_committee_advances_after_all_of_it_restarts() {
    for seed in SEEDS {
        restart_and_advance(4, seed);
    }
}

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
    cluster.restart_host(host, shard);

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
    payer_reclaims_after_restart(42, false);
}

/// A restart brings back every member the host carried.
///
/// The committee is drawn from validators the hosts co-host, so a seed
/// can place two of the payer shard's four members on one host. A
/// restart that reseated one of them would leave the committee a member
/// short of its quorum with nothing failed: the shard commits the block
/// its survivors had already voted, then never another. The seed is
/// chosen for that placement and the test insists on it, so a change to
/// the draw shows up as a failed premise rather than a pass that covers
/// nothing.
#[test]
fn a_restarted_host_reseats_every_member_it_carries() {
    payer_reclaims_after_restart(5, true);
}

fn payer_reclaims_after_restart(seed: u64, co_hosted: bool) {
    let mut cluster = SimCluster::with_grown_packages(
        &venue_config(),
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
        *XRD,
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
    if co_hosted {
        assert!(
            hosts.len() < venue_config().shard_size as usize,
            "the seed must place two of the payer shard's members on one host; \
             its {} members sit on hosts {hosts:?}",
            venue_config().shard_size,
        );
    }
    let before = cluster.committed_height(SWAPPER_SHARD).expect("running");
    for host in hosts {
        cluster.restart_host(host, SWAPPER_SHARD);
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
