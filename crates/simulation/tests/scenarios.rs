//! Portable scenarios run on the simulation harness.
//!
//! Each `#[test]` builds a [`SimCluster`] and drives a `hyperscale_scenarios`
//! body. The identical body runs on production under `#[cfg(feature = "ci")]`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ShardScopedInput};
use hyperscale_scenarios::tx::{
    halt_recovery_genesis_balances, halt_straddler_setup, intershard_partition_genesis_balances,
    merge_straddler_setup, split_straddler_setup, witness_genesis_balances,
};
use hyperscale_scenarios::{
    Cluster, FaultableCluster, ScenarioConfig, beacon_pool_partition_stalls_epoch_production,
    cross_shard_compound_drop_fetch_fallback, cross_shard_exec_cert_drop_fetch_fallback,
    cross_shard_header_fetch_fallback, cross_shard_provisions_drop_fetch_fallback,
    cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, cross_shard_tx, epochs,
    gossip_drop_engages_fetch_fallback, grow_reaches_four_shard_topology,
    grow_reaches_two_shard_topology, halted_shard_recovers_by_committee_redraw,
    halted_shard_straddler_atomic, inter_shard_partition_aborts_waves_at_deadline,
    isolated_validator_still_settles, livelock_resolves_promptly, liveness_baseline,
    merge_lifecycle, merge_seats_full_keeper_committee, merge_straddler_atomic,
    minority_fragment_rejoins_after_partition, multi_vnode_progress, partition_halts_and_heals,
    partition_heals_at_exact_quorum, pool_capacity_caps_registrations,
    re_registration_of_a_live_validator_is_a_no_op, register_validator_pools_a_node,
    register_without_capacity_is_rejected, registered_validator_activates_onto_a_shard,
    single_shard_tx, split_lifecycle, split_straddler_atomic, split_straddler_ec_partition_atomic,
    stake_deposit_folds_into_beacon_state, stake_withdraw_drops_effective_stake,
    surviving_sibling_split_seats_full_committees,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates,
};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::test_utils::shard_fork_proof_signed_by;
use hyperscale_types::{BlockHash, BlockHeight, RecoveryCause, ShardId};
use support::SimCluster;

/// Baseline single-shard config: resharding disarmed, four-validator committee.
const fn liveness_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn liveness_baseline_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 11);
    liveness_baseline(&mut cluster);
}

#[test]
fn single_shard_tx_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    single_shard_tx(&mut cluster);
}

#[test]
fn gossip_drop_engages_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(gossip_drop_engages_fetch_fallback);
}

#[test]
fn partition_halts_and_heals_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(partition_halts_and_heals);
}

#[test]
fn isolated_validator_still_settles_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(isolated_validator_still_settles);
}

/// Seven-host single-shard config: quorum is five, so a connected two-host
/// fragment can partition off while the majority keeps consensus live.
const fn seven_host_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 7,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn minority_fragment_rejoins_after_partition_sim() {
    let mut cluster = SimCluster::new(&seven_host_config(), 42);
    cluster.run_faultable(minority_fragment_rejoins_after_partition);
}

#[test]
fn partition_heals_at_exact_quorum_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(partition_heals_at_exact_quorum);
}

/// Single-shard config with the split trigger armed (`split_bytes = 0`) and one
/// cohort of pool surplus — drives an organic root split.
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

#[test]
fn split_lifecycle_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    split_lifecycle(&mut cluster);
}

#[test]
fn cross_shard_tx_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cross_shard_tx(&mut cluster);
}

#[test]
fn cross_shard_provisions_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_provisions_drop_fetch_fallback);
}

#[test]
fn cross_shard_exec_cert_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_exec_cert_drop_fetch_fallback);
}

#[test]
fn cross_shard_transaction_da_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_transaction_da_fetch_fallback);
}

#[test]
fn cross_shard_header_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_header_fetch_fallback);
}

#[test]
fn cross_shard_compound_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_compound_drop_fetch_fallback);
}

#[test]
fn cross_shard_provisions_recovers_after_transient_outage_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_provisions_recovers_after_transient_outage);
}

#[test]
fn inter_shard_partition_aborts_waves_at_deadline_sim() {
    // A dedicated host per pool validator, so the split seats the two children on
    // disjoint host sets — matching production's one-validator-per-host layout —
    // and a host partition can sever every inter-shard edge without cutting
    // intra-shard consensus.
    let mut cluster = SimCluster::with_dedicated_pool_hosts(
        &split_config(),
        11,
        &intershard_partition_genesis_balances(),
    );
    cluster.run_faultable(inter_shard_partition_aborts_waves_at_deadline);
}

#[test]
fn beacon_pool_partition_stalls_epoch_production_sim() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(
        &split_config(),
        11,
        &intershard_partition_genesis_balances(),
    );
    cluster.run_faultable(beacon_pool_partition_stalls_epoch_production);
}

/// Single-shard genesis armed so the funded root splits exactly once and the
/// grown pair holds (each child sits between the derived merge floor and the
/// split threshold), with two cohorts of pool surplus — one grows the root,
/// the other is the halted shard's recovery committee — plus two spares of
/// jail slack: the recovery draw needs a full free committee, and over the
/// scenario's ~40 epochs an organic `Performance` jail on the healthy shard
/// refills its seat from the pool, which with zero slack would starve the
/// draw and park the recovery.
const fn halt_recovery_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 10,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn halted_shard_recovers_by_committee_redraw_sim() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(
        &halt_recovery_config(),
        11,
        &halt_recovery_genesis_balances(),
    );
    cluster.run_faultable(halted_shard_recovers_by_committee_redraw);
}

#[test]
fn halted_shard_straddler_atomic_sim() {
    for seed in [7u64, 11, 42, 2026, 1337] {
        let mut cluster = SimCluster::with_dedicated_pool_hosts(
            &halt_recovery_config(),
            seed,
            &halt_straddler_setup().balances,
        );
        cluster.run_faultable(halted_shard_straddler_atomic);
    }
}

/// A provable committee-level fork drives the same full re-draw a halt does.
///
/// There is no Byzantine consensus stack in the harness to run two live heads
/// (deferred, as the halt plan defers its local-orphan gap), so the loud path
/// is exercised by synthesizing a `ConflictingCommits` proof — signed by the
/// shard's *live* committee keys so it authenticates against the running
/// topology exactly as an organically assembled one would — and injecting it
/// on the real gossip ingress. From there it rides the production pipeline:
/// verify, engage the local fences, re-gossip, the beacon buffers and folds
/// it, and `RecoveryCause::Fork` re-draws the committee. The fresh committee
/// resumes and its first crossing clears the record — the same completion a
/// halt recovery reaches, reached from the fork cause.
///
/// The scenario is a forking committee that then goes quiet (the shape the
/// plan notes collapses into the halt signature): the forked committee is
/// silenced before the proof lands, so the re-draw's fresh committee resumes a
/// settled tip rather than racing a still-live honest one — the synthetic
/// proof stands in for the Byzantine committee a live fork would need, which
/// stays deferred.
#[test]
fn shard_fork_drives_committee_recovery_sim() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(
        &halt_recovery_config(),
        11,
        &halt_recovery_genesis_balances(),
    );
    // Grow to two children before injecting the fork. Recovering the sole
    // ROOT committee would starve beacon epoch production: in a single-shard
    // topology the beacon committee *is* the ROOT committee, so re-drawing it
    // leaves no seated validator to ratify the next epoch and the whole chain
    // wedges. A child fork keeps the beacon — seated across the other active
    // validators — live to drive the recovery to completion, and is the
    // realistic shape besides (the loud path funnels a child's fork proof).
    split_lifecycle(&mut cluster);
    let (shard, _sibling) = ShardId::ROOT.children();

    // Warm up until the beacon has folded a real boundary for the shard, not
    // just until it commits a few blocks. The fork-caused re-draw seats the
    // fresh committee against the shard's attested boundary anchor and skips a
    // shard still on its genesis ZERO placeholder (a shard that never
    // produced needs an operator, not a rotation). A committed-height check
    // alone races ahead of the first epoch crossing's fold, so the proof would
    // fold while the boundary is still ZERO and the recovery would never arm.
    assert!(
        cluster.run_until(epochs(8), |c| c.beacon_state().is_some_and(|s| s
            .boundaries
            .get(&shard)
            .is_some_and(|b| b.block_hash != BlockHash::ZERO))),
        "the shard must fold a real boundary before the fork is injected"
    );
    let frozen = cluster
        .committed_height(shard)
        .expect("root committed")
        .inner();
    let member = cluster
        .committee_hosts(shard)
        .into_iter()
        .next()
        .expect("root has a committee host");
    let member = u32::try_from(member).expect("host index fits a node index");

    // Build a proof that authenticates against the live committee: resolve the
    // seated committee (and the anchor weighted timestamp that resolves it)
    // from a real committed tip, sign both branches with those seats' keys,
    // and confirm it verifies against the running schedule before injecting —
    // a wrong committee or timestamp would silently never fold.
    let proof = {
        let runner = cluster.runner();
        let vnode = runner
            .first_vnode_state(member)
            .expect("committee host runs a vnode");
        let schedule = vnode.beacon_coordinator().topology_schedule();
        let storage = runner
            .hosts_shard(member, shard)
            .expect("committee host serves the shard");
        let tip = storage
            .get_certified_header(storage.committed_height())
            .expect("committed tip header");
        let wt = tip.header().parent_qc().weighted_timestamp();
        let (snapshot, _bridged) = schedule
            .at_for_shard_certified(shard, wt, wt)
            .expect("the committed tip's committee resolves");
        let keys: Vec<_> = snapshot
            .consensus_committee_for_shard(shard)
            .iter()
            .map(|v| {
                runner
                    .validator_signing_key(*v)
                    .expect("seated validator has a signing key")
            })
            .collect();
        let proof = shard_fork_proof_signed_by(&keys, shard, BlockHeight::new(frozen + 1), wt);
        proof
            .verify(schedule)
            .expect("synthesized fork proof verifies against the live schedule");
        proof
    };

    // Silence the forked committee before injecting. The synthetic proof
    // stands in for a Byzantine committee; a live *honest* committee would
    // keep extending its own chain, and the re-draw seating a second committee
    // over a still-advancing tip forks the chain for real (a `commit linkage
    // broken` panic). A forking attacker that then goes quiet — the shape the
    // plan notes collapses into the halt signature — lets the fresh committee
    // resume a settled tip, exactly the handover the halt recovery completes.
    // Cut the committee in half on the consensus channels so neither half
    // reaches quorum; the global fork-proof gossip below is untouched.
    let committee = cluster.committee_hosts(shard);
    let withholding: Vec<usize> = committee[..2].to_vec();
    let others: Vec<usize> = (0..cluster.host_count())
        .filter(|h| !withholding.contains(h))
        .collect();
    cluster.drop_type_between(&others, &withholding, "block.vote");
    cluster.run_until(epochs(1), |_| false);
    cluster.drop_type_between(&withholding, &others, "block.vote");
    cluster.drop_type_between(&withholding, &others, "block.header");
    cluster.drop_type_between(&withholding, &others, "shard.timeout");
    cluster.run_until(epochs(1), |_| false);

    // Inject on the real gossip ingress of a committee member. The fork-proof
    // gossip is global scope, so the silenced committee still relays it to the
    // beacon proposers that fold the recovery.
    cluster.runner_mut().schedule_initial_event(
        member,
        Duration::ZERO,
        HostEvent::shard(
            shard,
            ShardScopedInput::ShardForkProofGossipReceived {
                proof: Arc::new(proof),
            },
        ),
    );

    // The beacon folds a fork-caused recovery.
    assert!(
        cluster.run_until(epochs(30), |c| c.beacon_state().is_some_and(|s| s
            .pending_recoveries
            .get(&shard)
            .map(|r| r.cause)
            == Some(RecoveryCause::Fork))),
        "the fork proof must fold a RecoveryCause::Fork recovery"
    );

    // The fresh committee resumes past the fork height, and its first crossing
    // clears the record.
    assert!(
        cluster.run_until(epochs(40), |c| c
            .committed_height(shard)
            .is_some_and(|h| h.inner() > frozen + 1)),
        "the recovered shard must resume committing under its fresh committee"
    );
    assert!(
        cluster.run_until(epochs(30), |c| c
            .beacon_state()
            .is_some_and(|s| !s.pending_recoveries.contains_key(&shard))),
        "the fresh committee's crossing must clear the fork recovery"
    );
}

/// Assert the seeded 50%-request-loss scenario at `seed`: the shared body's
/// liveness invariants plus the sim-deterministic engagement — at least one
/// `provision.request` leg drop landed at this seed. Production can't assert
/// engagement (its async retry path is nondeterministic), so that check lives
/// here, keyed on the exact seed.
fn request_loss_engages_at_seed(seed: u64) {
    let mut cluster = SimCluster::new(&split_config(), seed);
    let request_drops = cluster.run_faultable(cross_shard_provisions_fetch_with_request_loss);
    assert!(
        request_drops >= 1,
        "the 50% provision.request loss must engage at seed {seed}; drops = {request_drops}",
    );
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_42_sim() {
    request_loss_engages_at_seed(42);
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_1337_sim() {
    request_loss_engages_at_seed(1337);
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_2026_sim() {
    request_loss_engages_at_seed(2026);
}

#[test]
fn livelock_resolves_promptly_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    livelock_resolves_promptly(&mut cluster);
}

#[test]
fn merge_lifecycle_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    merge_lifecycle(&mut cluster);
}

/// Single-shard genesis with the grow trigger armed (`split_bytes` above each
/// child but below ROOT) and two cohorts of pool surplus — one grows ROOT to the
/// two siblings, the other splits the heavier one after the vote.
const fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn split_straddler_atomic_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    split_straddler_atomic(&mut cluster);
}

/// Straddler atomicity under an asymmetric EC partition across a split boundary.
///
/// Drives the portable [`split_straddler_ec_partition_atomic`] scenario across a
/// seed sweep, seating disjoint splitter/survivor committees via dedicated pool
/// hosts so no co-hosted vnode bridges the EC cut in-process. The seeds vary how
/// the survivor's finalization races its own counterpart-abort sweep; none may
/// resolve one-sided.
#[test]
fn split_straddler_ec_partition_atomic_sim() {
    for seed in [7u64, 11, 42, 2026, 1337] {
        let setup = split_straddler_setup();
        let mut cluster =
            SimCluster::with_dedicated_pool_hosts(&straddler_config(), seed, &setup.balances);
        split_straddler_ec_partition_atomic(&mut cluster);
    }
}

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the survivor pair (`leaf(2,0)`/`leaf(2,1)`, the latter
/// bulk-funded) sits above it, the light merging pair (`leaf(2,2)`/`leaf(2,3)`)
/// below it, so only the merging pair auto-merges into `leaf(1,1)`. Three cohorts
/// of pool surplus staff the two split generations the grow walks through; the
/// merge keepers then come from the merging children's own committees.
const fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: 2_880_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn merge_straddler_atomic_sim() {
    let setup = merge_straddler_setup();
    let mut cluster =
        SimCluster::with_grown_balances(&merge_straddler_config(), 11, &setup.balances);
    merge_straddler_atomic(&mut cluster);
}

/// Multi-vnode config: two vnodes per host (same-shard multi-vnode hosting), the
/// split disarmed, no pool surplus — a single shard whose committee is hosted at
/// two vnodes per host.
const fn multi_vnode_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn multi_vnode_progress_sim() {
    let mut cluster = SimCluster::new(&multi_vnode_config(), 11);
    multi_vnode_progress(&mut cluster);
}

/// Single-shard witness config: the committee equals the whole validator set
/// (`pool_surplus = 0`, so the shuffle has no stock and never fires) with
/// resharding disarmed — the stable ground the beacon-witness scenarios fold
/// system actions against. `validators` sizes the committee.
const fn witness_config(validators: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: validators,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn stake_deposit_folds_into_beacon_state_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x57AC, &witness_genesis_balances());
    stake_deposit_folds_into_beacon_state(&mut cluster);
}

#[test]
fn register_validator_pools_a_node_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x5EED, &witness_genesis_balances());
    register_validator_pools_a_node(&mut cluster);
}

#[test]
fn register_without_capacity_is_rejected_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x0CA9, &witness_genesis_balances());
    register_without_capacity_is_rejected(&mut cluster);
}

#[test]
fn stake_withdraw_drops_effective_stake_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xD7A1, &witness_genesis_balances());
    stake_withdraw_drops_effective_stake(&mut cluster);
}

#[test]
fn registered_validator_activates_onto_a_shard_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xAC11, &witness_genesis_balances());
    registered_validator_activates_onto_a_shard(&mut cluster);
}

#[test]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_sim() {
    // Seven validators give the committee slack to keep quorum while a couple
    // eject; `pool_surplus = 0` keeps the shuffle dormant.
    let mut cluster =
        SimCluster::with_balances(&witness_config(7), 0xE1EC, &witness_genesis_balances());
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
}

#[test]
fn re_registration_of_a_live_validator_is_a_no_op_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xDEAD, &witness_genesis_balances());
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
}

#[test]
fn pool_capacity_caps_registrations_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xCA9A, &witness_genesis_balances());
    pool_capacity_caps_registrations(&mut cluster);
}

/// Single-shard genesis with the split armed (`split_bytes = 0`) and
/// `(target - 1)` cohorts of pool surplus to staff the split generations the
/// grow walks through, plus two spares of jail slack: an organic
/// `Performance` jail refills its committee seat from the pool, which with
/// zero slack would leave a leaf short of full strength with nothing to
/// refill from. The leftover stays below a committee's worth, so split
/// admission's pool gate can't staff another cohort and the partition still
/// stabilizes at `target` leaves.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: (target_shards - 1) * 4 + 2,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn grow_reaches_two_shard_topology_sim() {
    let mut cluster = SimCluster::new(&grow_config(2), 11);
    grow_reaches_two_shard_topology(&mut cluster);
}

#[test]
fn grow_reaches_four_shard_topology_sim() {
    let mut cluster = SimCluster::new(&grow_config(4), 11);
    grow_reaches_four_shard_topology(&mut cluster);
}

#[test]
fn merge_seats_full_keeper_committee_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    merge_seats_full_keeper_committee(&mut cluster);
}

#[test]
fn surviving_sibling_split_seats_full_committees_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    surviving_sibling_split_seats_full_committees(&mut cluster);
}
