//! Monte Carlo validation of the committee-security analysis
//! (`specs/committee_security.md`) against the real beacon fold.
//!
//! Drives [`apply_epoch`] over synthetic epochs with a marked corrupt
//! subset of the validator population and tallies each shard
//! committee's corrupt-seat transition at every shuffle event,
//! comparing the empirical kernel against the Bernoulli–Laplace
//! birth–death chain the analysis note prices: victim uniform over the
//! committee, replacement uniform over the unseated remainder, and the
//! hypergeometric stationary law those rates imply.
//!
//! At production parameters the compromise tail (~1e-10/event) is
//! unobservable by simulation. These tests validate the *kernel* —
//! measurable at every occupied corrupt count — and the note's chain
//! arithmetic extrapolates the tail from it.
//!
//! The seeded cells run in CI as a regression net over
//! victim-selection and pool-draw uniformity; the `#[ignore]`d
//! generator prints the note's comparison tables (run with `--ignored`
//! and `--no-capture`).

#![allow(clippy::cast_precision_loss)] // statistical tallies: every count ≪ 2^52

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, Epoch, MIN_STAKE_FLOOR, NetworkDefinition, NetworkParams,
    Randomness, SHUFFLE_INTERVAL_EPOCHS, ShardCommittee, ShardId, Stake, StakePool, StakePoolId,
    ValidatorId, ValidatorRecord, ValidatorStatus, bls_keypair_from_seed,
};

// ─── The analysis note's chain (committee_security.py §2) ───────────────────

/// `P[k → k+1]` per shuffle event: the victim (uniform over `seats`) is
/// honest and the replacement (uniform over the unseated remainder) is
/// corrupt.
fn p_up(population: u64, corrupt: u64, seats: u64, k: u64) -> f64 {
    let (population, corrupt, seats, k) =
        (population as f64, corrupt as f64, seats as f64, k as f64);
    ((seats - k) / seats) * ((corrupt - k) / (population - seats))
}

/// `P[k → k−1]` per shuffle event: the victim is corrupt and the
/// replacement is honest.
fn p_down(population: u64, corrupt: u64, seats: u64, k: u64) -> f64 {
    let (population, corrupt, seats, k) =
        (population as f64, corrupt as f64, seats as f64, k as f64);
    (k / seats) * ((population - corrupt - (seats - k)) / (population - seats))
}

/// Hypergeometric pmf over the reachable support, via the weight
/// recurrence `w(k+1)/w(k) = (corrupt−k)(seats−k) / (k+1)(population−corrupt−seats+k+1)`
/// — exact up to float rounding, no log-gamma needed.
fn hyper_pmf(population: u64, corrupt: u64, seats: u64) -> BTreeMap<u64, f64> {
    let lo = seats.saturating_sub(population - corrupt);
    let hi = seats.min(corrupt);
    let mut weights = vec![1.0_f64];
    for k in lo..hi {
        let (c, s, k_f) = (corrupt as f64, seats as f64, k as f64);
        let rest = (population - corrupt - seats + k + 1) as f64;
        let next =
            weights.last().expect("non-empty") * ((c - k_f) * (s - k_f)) / ((k_f + 1.0) * rest);
        weights.push(next);
    }
    let total: f64 = weights.iter().sum();
    (lo..=hi)
        .zip(weights)
        .map(|(k, w)| (k, w / total))
        .collect()
}

// ─── Cells and tallies ───────────────────────────────────────────────────────

/// One Monte Carlo configuration: `shards × shard_size` seats drawn
/// against a shared population, `corrupt` of which are marked.
struct Cell {
    shards: u64,
    shard_size: u32,
    population: u64,
    corrupt: u64,
    epochs: u64,
    /// Epochs a fresh draw waits before the harness flips it ready —
    /// emulating the `Ready` witness the production path delivers.
    /// Zero grants instant readiness, making the victim set the full
    /// committee (the note's idealized chain). Victim eligibility is
    /// only sampled at shuffle epochs, so the effective granularity is
    /// `SHUFFLE_INTERVAL_EPOCHS`.
    ready_lag_epochs: u64,
    seed: u8,
}

/// Per-`k` transition counts at shuffle events, aggregated over shards.
/// `visits[k]` doubles as the empirical occupancy: it is the number of
/// (event, shard) samples that saw `k` corrupt seats going in.
#[derive(Default)]
struct KernelTally {
    visits: BTreeMap<u64, u64>,
    ups: BTreeMap<u64, u64>,
    downs: BTreeMap<u64, u64>,
    events: u64,
}

const BURN_IN_EVENTS: u64 = 64;

/// Corrupt ids spread evenly across the id space, so the marking is
/// uncorrelated with the initial block seating.
fn spread_corrupt(population: u64, corrupt: u64) -> BTreeSet<ValidatorId> {
    (0..corrupt)
        .map(|i| ValidatorId::new(i * population / corrupt))
        .collect()
}

fn shard_ids(shards: u64) -> Vec<ShardId> {
    assert!(
        shards.is_power_of_two(),
        "cells use power-of-two shard counts"
    );
    let depth = shards.ilog2().max(1);
    (0..shards).map(|path| ShardId::leaf(depth, path)).collect()
}

/// A population in one generously funded stake pool, the first
/// `shards × shard_size` ids seated ready in id blocks, the rest
/// `Pooled`. One shared pubkey: the fold reads pubkeys only on
/// VRF/signature verification paths, which empty `committed` never
/// reaches.
fn mc_state(cell: &Cell) -> BeaconState {
    let pubkey = bls_keypair_from_seed(&[0x5e; 32]).public_key();
    let pool_id = StakePoolId::new(0);
    let ids = shard_ids(cell.shards);
    let seats_total = cell.shards * u64::from(cell.shard_size);
    assert!(
        cell.population > seats_total,
        "population must leave a non-empty pool"
    );

    let mut validators = BTreeMap::new();
    let mut pool_validators = BTreeSet::new();
    let mut committees: BTreeMap<ShardId, ShardCommittee> = ids
        .iter()
        .map(|s| (*s, ShardCommittee::default()))
        .collect();

    for i in 0..cell.population {
        let id = ValidatorId::new(i);
        let status = if i < seats_total {
            let block = usize::try_from(i / u64::from(cell.shard_size)).expect("shard index fits");
            let shard = ids[block];
            committees
                .get_mut(&shard)
                .expect("seat shard exists")
                .members
                .push(id);
            ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            }
        } else {
            ValidatorStatus::Pooled
        };
        validators.insert(
            id,
            ValidatorRecord {
                id,
                pool: pool_id,
                status,
                registered_at_epoch: Epoch::GENESIS,
                pubkey,
            },
        );
        pool_validators.insert(id);
    }

    let mut pools = BTreeMap::new();
    pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            // Generous so `min_stake` stays clamped at the floor and no
            // admission gate trips over long runs.
            total_stake: Stake::from_attos(
                u128::from(cell.population) * 5 * MIN_STAKE_FLOOR.attos(),
            ),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
        },
    );

    let chain_config = BeaconChainConfig {
        shard_size: cell.shard_size,
        ..BeaconChainConfig::default()
    };
    let beacon_committee_size = chain_config.beacon_committee_size;

    let mut state = BeaconState {
        chain_config,
        params: NetworkParams::default(),
        next_params: NetworkParams::default(),
        param_votes: BTreeMap::new(),
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: Randomness::new([cell.seed; 32]),
        committee: (0..u64::from(beacon_committee_size))
            .map(ValidatorId::new)
            .collect(),
        shard_committees: committees.clone(),
        next_shard_committees: committees,
        shard_consensus_members: BTreeMap::new(),
        witness_window_bases: BTreeMap::new(),
        split_pending_window: BTreeSet::new(),
        settled_window_floors: BTreeMap::new(),
        reshape_observers_window: BTreeMap::new(),
        reshape_keepers_window: BTreeMap::new(),
        reshape_parent_halves: BTreeMap::new(),
        boundaries: BTreeMap::new(),
        advanced: BTreeSet::new(),
        pending_reshapes: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    };
    state.shard_consensus_members = state.ready_consensus_members(&state.shard_committees);
    state
}

/// Flip fresh draws ready once they have waited `lag` epochs —
/// emulating the `Ready` shard witness the production path delivers.
fn flip_ready(state: &mut BeaconState, lag: u64) {
    let now = state.current_epoch.inner();
    for record in state.validators.values_mut() {
        if let ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch,
        } = record.status
            && now.saturating_sub(placed_at_epoch.inner()) >= lag
        {
            record.status = ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch,
            };
        }
    }
}

fn count_corrupt(members: &[ValidatorId], corrupt: &BTreeSet<ValidatorId>) -> u64 {
    members.iter().filter(|id| corrupt.contains(id)).count() as u64
}

/// Drive the fold for `cell.epochs` and tally the shuffle kernel.
/// Asserts the structural facts the tally depends on: membership only
/// changes at shuffle epochs, and every shuffle swaps exactly one
/// member per shard.
fn run_cell(cell: &Cell) -> KernelTally {
    let network = NetworkDefinition::simulator();
    let corrupt = spread_corrupt(cell.population, cell.corrupt);
    let mut state = mc_state(cell);
    let mut tally = KernelTally::default();
    let no_contributions = BTreeMap::new();

    for e in 1..=cell.epochs {
        let before = state.next_shard_committees.clone();
        apply_epoch(
            &mut state,
            &network,
            Epoch::new(e),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &no_contributions,
            },
        );
        flip_ready(&mut state, cell.ready_lag_epochs);

        if !e.is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
            assert_eq!(
                before, state.next_shard_committees,
                "membership changed outside a shuffle epoch (epoch {e})"
            );
            continue;
        }

        tally.events += 1;
        let burned_in = tally.events > BURN_IN_EVENTS;
        for (shard, committee_before) in &before {
            let after = &state.next_shard_committees[shard];
            let prior: BTreeSet<_> = committee_before.members.iter().copied().collect();
            let current: BTreeSet<_> = after.members.iter().copied().collect();
            let removed = prior.difference(&current).count();
            let added = current.difference(&prior).count();
            assert_eq!(
                (removed, added),
                (1, 1),
                "shuffle at epoch {e} must swap exactly one member of {shard:?}"
            );
            if !burned_in {
                continue;
            }
            let k_before = count_corrupt(&committee_before.members, &corrupt);
            let k_after = count_corrupt(&after.members, &corrupt);
            *tally.visits.entry(k_before).or_default() += 1;
            // One swap bounds the move to ±1, asserted above.
            match k_after.cmp(&k_before) {
                Ordering::Greater => *tally.ups.entry(k_before).or_default() += 1,
                Ordering::Less => *tally.downs.entry(k_before).or_default() += 1,
                Ordering::Equal => {}
            }
        }
    }
    tally
}

// ─── Comparison against the chain ────────────────────────────────────────────

/// Empirical up/down rates at every `k` visited at least `min_visits`
/// times must sit within `band_sigma` binomial standard errors of the
/// chain's `p_up`/`p_down`. Returns the number of bins asserted.
fn assert_kernel(cell: &Cell, tally: &KernelTally, min_visits: u64, band_sigma: f64) -> usize {
    let mut asserted = 0;
    for (&k, &visits) in &tally.visits {
        if visits < min_visits {
            continue;
        }
        let ups = tally.ups.get(&k).copied().unwrap_or(0);
        let downs = tally.downs.get(&k).copied().unwrap_or(0);
        for (label, count, theory) in [
            (
                "up",
                ups,
                p_up(cell.population, cell.corrupt, u64::from(cell.shard_size), k),
            ),
            (
                "down",
                downs,
                p_down(cell.population, cell.corrupt, u64::from(cell.shard_size), k),
            ),
        ] {
            let empirical = count as f64 / visits as f64;
            let sigma = (theory * (1.0 - theory) / visits as f64).sqrt();
            assert!(
                (empirical - theory).abs() <= band_sigma * sigma,
                "p_{label}({k}) = {empirical:.5} deviates from the chain's {theory:.5} \
                 by more than {band_sigma}σ (σ = {sigma:.5}, visits = {visits})"
            );
            asserted += 1;
        }
    }
    asserted
}

/// Total-variation distance between the empirical occupancy and the
/// chain's hypergeometric stationary law.
fn occupancy_tv(cell: &Cell, tally: &KernelTally) -> f64 {
    let pmf = hyper_pmf(cell.population, cell.corrupt, u64::from(cell.shard_size));
    let total: u64 = tally.visits.values().sum();
    let keys: BTreeSet<u64> = pmf.keys().chain(tally.visits.keys()).copied().collect();
    keys.iter()
        .map(|k| {
            let empirical = tally.visits.get(k).copied().unwrap_or(0) as f64 / total as f64;
            (empirical - pmf.get(k).copied().unwrap_or(0.0)).abs()
        })
        .sum::<f64>()
        / 2.0
}

// ─── CI cells ────────────────────────────────────────────────────────────────

/// The shipped shuffle's transition kernel matches the analysis note's
/// birth–death chain at every well-visited corrupt count: victim
/// uniform over the committee, replacement uniform over the pool.
/// Instant-ready flips emulate prompt `Ready` witnesses so the victim
/// set is the full committee — the note's idealization; the ready-lag
/// deviation is measured separately. Seeded and deterministic.
#[test]
fn shuffle_kernel_matches_birth_death_chain() {
    let cell = Cell {
        shards: 1,
        shard_size: 8,
        population: 160,
        corrupt: 40,
        epochs: 160_000,
        ready_lag_epochs: 0,
        seed: 0x07,
    };
    let tally = run_cell(&cell);
    assert!(
        tally.events >= 10_000,
        "expected ≥10k shuffle events, got {}",
        tally.events
    );
    let asserted = assert_kernel(&cell, &tally, 800, 4.0);
    assert!(
        asserted >= 8,
        "kernel comparison covered only {asserted} bins — the cell is too small"
    );
}

/// A second seed and geometry (smaller corrupt fraction), so a
/// uniformity regression that happens to cancel at one operating point
/// still trips.
#[test]
fn shuffle_kernel_matches_at_low_corruption() {
    let cell = Cell {
        shards: 1,
        shard_size: 8,
        population: 160,
        corrupt: 16,
        epochs: 160_000,
        ready_lag_epochs: 0,
        seed: 0x2a,
    };
    let tally = run_cell(&cell);
    let asserted = assert_kernel(&cell, &tally, 800, 4.0);
    assert!(
        asserted >= 6,
        "kernel comparison covered only {asserted} bins"
    );
}

// ─── Table generator ─────────────────────────────────────────────────────────

/// Prints the kernel-comparison tables for
/// `specs/committee_security.md` Phase 2. Long-running; every number in
/// the note's Phase 2 section regenerates from here.
#[test]
#[ignore = "table generator for specs/committee_security.md — run with --ignored and --no-capture"]
fn kernel_comparison_tables() {
    // corrupt = population/10 and population/4 (β = 0.10 / 0.25).
    for (shard_size, corrupt) in [(4, 8), (4, 20), (16, 32), (16, 80), (32, 64), (32, 160)] {
        let population = 20 * u64::from(shard_size);
        let cell = Cell {
            shards: 1,
            shard_size,
            population,
            corrupt,
            epochs: 200_000 * SHUFFLE_INTERVAL_EPOCHS,
            ready_lag_epochs: 0,
            seed: 0x11,
        };
        let started = Instant::now();
        let tally = run_cell(&cell);
        println!(
            "\nn={shard_size} population={population} corrupt={} (beta={:.2}) — {} events, {:.1}s",
            cell.corrupt,
            cell.corrupt as f64 / population as f64,
            tally.events,
            started.elapsed().as_secs_f64(),
        );
        println!("  k | visits  | emp p_up  thy p_up  z     | emp p_dn  thy p_dn  z     ");
        for (&k, &visits) in &tally.visits {
            let seats = u64::from(cell.shard_size);
            let up_thy = p_up(cell.population, cell.corrupt, seats, k);
            let dn_thy = p_down(cell.population, cell.corrupt, seats, k);
            let up_emp = tally.ups.get(&k).copied().unwrap_or(0) as f64 / visits as f64;
            let dn_emp = tally.downs.get(&k).copied().unwrap_or(0) as f64 / visits as f64;
            let z = |emp: f64, thy: f64| {
                let sigma = (thy * (1.0 - thy) / visits as f64).sqrt();
                if sigma > 0.0 {
                    (emp - thy) / sigma
                } else {
                    0.0
                }
            };
            println!(
                "  {k} | {visits:>7} | {up_emp:.5}   {up_thy:.5}  {:+5.2} | {dn_emp:.5}   {dn_thy:.5}  {:+5.2}",
                z(up_emp, up_thy),
                z(dn_emp, dn_thy),
            );
        }
        println!(
            "  occupancy TV vs hypergeometric: {:.4}",
            occupancy_tv(&cell, &tally)
        );
    }
}
