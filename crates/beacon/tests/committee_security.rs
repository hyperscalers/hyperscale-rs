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
//! The shipped shuffle evicts the *longest-tenured* member, not a
//! uniform one, yet its per-`k` transition rates match this chain: the
//! committee is a FIFO queue of the last `shard_size` entrants, and a
//! seat's corruptness is independent of its arrival order, so
//! conditioned on `k` corrupt seats the oldest is corrupt with
//! probability `k / shard_size` — the uniform victim's rate. These
//! tests drive the fold with an *unsteered* seed (empty committed set),
//! so the match is the natural kernel, the baseline the grind defence
//! ([`randomness_grinding`]) departs from.
//!
//! At production parameters the compromise tail (~1e-10/event) is
//! unobservable by simulation. These tests validate the *kernel* —
//! measurable at every occupied corrupt count — and the note's chain
//! arithmetic extrapolates the tail from it.
//!
//! The seeded cells run in CI as a regression net over the tenure
//! victim's kernel and pool-draw uniformity; the `#[ignore]`d generator
//! prints the note's comparison tables (run with `--ignored` and
//! `--no-capture`).

#![allow(clippy::cast_precision_loss)] // statistical tallies: every count ≪ 2^52

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, Epoch, MIN_STAKE_FLOOR, NetworkDefinition, NetworkParams,
    PendingReshape, Randomness, SHUFFLE_INTERVAL_EPOCHS, ShardCommittee, ShardId, Stake, StakePool,
    StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus, bls_keypair_from_seed,
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
    /// `SHUFFLE_INTERVAL_EPOCHS`; `auto_ready_timeout` caps the
    /// achievable lag at `READY_TIMEOUT_EPOCHS`, the fold's own worst
    /// case.
    ready_lag_epochs: u64,
    /// `Some(size)`: set `beacon_committee_size` and tally each epoch's
    /// beacon-committee resample.
    beacon_size: Option<u32>,
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
    /// Rotated-out members' seat tenure in whole shuffle intervals,
    /// split by corruption class. Little's law fixes both means at
    /// `committee size × interval`; the ready-lag deviation moves the
    /// *shape* (a floor below which no seat can be flushed).
    tenure_corrupt: BTreeMap<u64, u64>,
    tenure_honest: BTreeMap<u64, u64>,
    /// Beacon-committee resample outcomes: (corrupt among the eligible
    /// set, corrupt on the drawn committee) → epochs observed. Only
    /// filled when the cell sets `beacon_size`.
    beacon: BTreeMap<(u64, u64), u64>,
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

    let mut chain_config = BeaconChainConfig {
        shard_size: cell.shard_size,
        ..BeaconChainConfig::default()
    };
    if let Some(size) = cell.beacon_size {
        chain_config.beacon_committee_size = size;
    }
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
        pending_recoveries: BTreeMap::new(),
        completed_recoveries: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
        last_beacon_service: BTreeMap::new(),
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
fn run_cell(cell: &Cell, corrupt: &BTreeSet<ValidatorId>) -> KernelTally {
    let network = NetworkDefinition::simulator();
    let mut state = mc_state(cell);
    let mut tally = KernelTally::default();
    let no_contributions = BTreeMap::new();
    // Seat-tenure tracker: seating epoch per current member.
    let mut seated_at: BTreeMap<ValidatorId, u64> = state
        .next_shard_committees
        .values()
        .flat_map(|c| c.members.iter().copied())
        .map(|id| (id, 0))
        .collect();

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

        if cell.beacon_size.is_some() {
            let eligible = state.beacon_eligible();
            let m = eligible.iter().filter(|id| corrupt.contains(id)).count() as u64;
            let k = count_corrupt(&state.committee, corrupt);
            *tally.beacon.entry((m, k)).or_default() += 1;
        }

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
            let removed: Vec<_> = prior.difference(&current).copied().collect();
            let added: Vec<_> = current.difference(&prior).copied().collect();
            assert_eq!(
                (removed.len(), added.len()),
                (1, 1),
                "shuffle at epoch {e} must swap exactly one member of {shard:?}"
            );
            let out = removed[0];
            let seated = seated_at.remove(&out).expect("rotated member was seated");
            seated_at.insert(added[0], e);
            if !burned_in {
                continue;
            }
            let intervals = (e - seated) / SHUFFLE_INTERVAL_EPOCHS;
            let tenure = if corrupt.contains(&out) {
                &mut tally.tenure_corrupt
            } else {
                &mut tally.tenure_honest
            };
            *tenure.entry(intervals).or_default() += 1;
            let k_before = count_corrupt(&committee_before.members, corrupt);
            let k_after = count_corrupt(&after.members, corrupt);
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
/// birth–death chain at every well-visited corrupt count. The note
/// models a uniform victim; the fold evicts the longest-tenured, whose
/// corruptness — being independent of tenure order — is corrupt with
/// the same `k / seats` probability, so the per-`k` up/down rates agree.
/// Instant-ready flips emulate prompt `Ready` witnesses so the whole
/// committee is tenure-eligible; the ready-lag deviation is measured
/// separately. Seeded and deterministic.
#[test]
fn shuffle_kernel_matches_birth_death_chain() {
    let cell = Cell {
        shards: 1,
        shard_size: 8,
        population: 160,
        corrupt: 40,
        epochs: 160_000,
        ready_lag_epochs: 0,
        beacon_size: None,
        seed: 0x07,
    };
    let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
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
        beacon_size: None,
        seed: 0x2a,
    };
    let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
    let asserted = assert_kernel(&cell, &tally, 800, 4.0);
    assert!(
        asserted >= 6,
        "kernel comparison covered only {asserted} bins"
    );
}

// ─── Table generator ─────────────────────────────────────────────────────────

/// Print one cell's kernel table against the note's chain: per-`k`
/// empirical vs theoretical up/down rates with z-scores, and the
/// occupancy TV distance.
fn print_kernel_table(cell: &Cell, tally: &KernelTally, elapsed_secs: f64) {
    println!(
        "\nshards={} n={} population={} corrupt={} (beta={:.2}) lag={} — {} events, {elapsed_secs:.1}s",
        cell.shards,
        cell.shard_size,
        cell.population,
        cell.corrupt,
        cell.corrupt as f64 / cell.population as f64,
        cell.ready_lag_epochs,
        tally.events,
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
        occupancy_tv(cell, tally)
    );
}

/// Mean tenure (in shuffle intervals) and the survival fractions
/// `P[tenure ≥ t]` for the given thresholds.
fn tenure_stats(tenure: &BTreeMap<u64, u64>, thresholds: &[u64]) -> (f64, Vec<f64>) {
    let total: u64 = tenure.values().sum();
    let sum: u64 = tenure.iter().map(|(&t, &c)| t * c).sum();
    let survival = thresholds
        .iter()
        .map(|&threshold| {
            let at_least: u64 = tenure
                .iter()
                .filter(|&(&t, _)| t >= threshold)
                .map(|(_, &c)| c)
                .sum();
            at_least as f64 / total as f64
        })
        .collect();
    (sum as f64 / total as f64, survival)
}

/// Prints the single-shard kernel-comparison tables for
/// `specs/committee_security.md` Phase 2. Long-running; the note's
/// baseline numbers regenerate from here.
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
            beacon_size: None,
            seed: 0x11,
        };
        let started = Instant::now();
        let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
        print_kernel_table(&cell, &tally, started.elapsed().as_secs_f64());
    }
}

/// Pool depletion: shards sharing one population, at the note's pool
/// factor (20) and a deliberately starved one (2). The printed theory
/// columns are the note's single-committee formulas — under
/// exchangeability the unseated fraction cancels from the replacement
/// probability, so the naive kernel should hold in expectation even
/// when concurrent committees seat half the population.
#[test]
#[ignore = "table generator for specs/committee_security.md — run with --ignored and --no-capture"]
fn depletion_tables() {
    for (population, corrupt) in [(1280, 320), (128, 32)] {
        let cell = Cell {
            shards: 4,
            shard_size: 16,
            population,
            corrupt,
            epochs: 50_000 * SHUFFLE_INTERVAL_EPOCHS,
            ready_lag_epochs: 0,
            beacon_size: None,
            seed: 0x13,
        };
        let started = Instant::now();
        let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
        print_kernel_table(&cell, &tally, started.elapsed().as_secs_f64());
    }
}

/// Ready-lag victim immunity: fresh draws are victim-ineligible until
/// readied. Lag 0 emulates instant `Ready` witnesses; 32 is
/// `READY_TIMEOUT_EPOCHS`, the fold's own ceiling with no witness at
/// all. Prints the kernel shift and the seat-tenure shape (Little's
/// law pins the mean at `n` intervals regardless; the lag moves the
/// floor).
#[test]
#[ignore = "table generator for specs/committee_security.md — run with --ignored and --no-capture"]
fn ready_lag_tables() {
    for lag in [0, 16, 32] {
        let cell = Cell {
            shards: 1,
            shard_size: 16,
            population: 320,
            corrupt: 80,
            epochs: 100_000 * SHUFFLE_INTERVAL_EPOCHS,
            ready_lag_epochs: lag,
            beacon_size: None,
            seed: 0x17,
        };
        let started = Instant::now();
        let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
        print_kernel_table(&cell, &tally, started.elapsed().as_secs_f64());
        let thresholds = [1, 2, 4, 8];
        for (label, tenure) in [
            ("corrupt", &tally.tenure_corrupt),
            ("honest ", &tally.tenure_honest),
        ] {
            let (mean, survival) = tenure_stats(tenure, &thresholds);
            let survival: Vec<String> = thresholds
                .iter()
                .zip(&survival)
                .map(|(t, s)| format!("P[≥{t}I]={s:.3}"))
                .collect();
            println!(
                "  tenure {label}: mean {mean:.2} intervals, {}",
                survival.join(" ")
            );
        }
    }
}

/// Beacon-committee resample: the per-epoch fresh draw, binned by the
/// corrupt count `m` among the eligible set. Within each bin the draw
/// should be exactly hypergeometric over the eligible set.
#[test]
#[ignore = "table generator for specs/committee_security.md — run with --ignored and --no-capture"]
fn beacon_resample_tables() {
    let cell = Cell {
        shards: 4,
        shard_size: 16,
        population: 1280,
        corrupt: 320,
        epochs: 400_000,
        ready_lag_epochs: 0,
        beacon_size: Some(8),
        seed: 0x19,
    };
    let started = Instant::now();
    let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
    let eligible = cell.shards * u64::from(cell.shard_size);
    let committee = u64::from(cell.beacon_size.expect("cell sets beacon_size"));
    println!(
        "\nbeacon resample: eligible={eligible} committee={committee} — {} epochs, {:.1}s",
        cell.epochs,
        started.elapsed().as_secs_f64(),
    );
    println!("  m (corrupt eligible) | epochs  | emp E[k]  thy E[k] | TV vs hypergeom");
    let mut by_m: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    for (key, &count) in &tally.beacon {
        let (m, k) = *key;
        *by_m.entry(m).or_default().entry(k).or_default() += count;
    }
    for (&m, ks) in &by_m {
        let samples: u64 = ks.values().sum();
        if samples < 2_000 {
            continue;
        }
        let emp_mean = ks.iter().map(|(&k, &c)| k as f64 * c as f64).sum::<f64>() / samples as f64;
        let thy_mean = committee as f64 * m as f64 / eligible as f64;
        let pmf = hyper_pmf(eligible, m, committee);
        let keys: BTreeSet<u64> = pmf.keys().chain(ks.keys()).copied().collect();
        let tv = keys
            .iter()
            .map(|k| {
                let emp = ks.get(k).copied().unwrap_or(0) as f64 / samples as f64;
                (emp - pmf.get(k).copied().unwrap_or(0.0)).abs()
            })
            .sum::<f64>()
            / 2.0;
        println!("  {m:>20} | {samples:>7} | {emp_mean:.4}    {thy_mean:.4}  | {tv:.4}");
    }
}

// ─── Structural CI cells ─────────────────────────────────────────────────────

/// The per-epoch beacon-committee resample is recency-weighted — a
/// member drawn recently is down-weighted for a cooldown — yet its
/// corrupt-count mean still matches the uniform hypergeometric draw:
/// within each corrupt-eligible bin `m`, `E[k]` matches the
/// hypergeometric mean. A member's corruptness is independent of how
/// recently it served (service is seed-driven, not corruptness-driven),
/// so the weighting reshapes *which* members sit but leaves the corrupt
/// fraction unbiased. Seeded and deterministic.
#[test]
fn beacon_resample_matches_hypergeometric() {
    let cell = Cell {
        shards: 4,
        shard_size: 8,
        population: 640,
        corrupt: 160,
        epochs: 30_000,
        ready_lag_epochs: 0,
        beacon_size: Some(8),
        seed: 0x1f,
    };
    let tally = run_cell(&cell, &spread_corrupt(cell.population, cell.corrupt));
    let eligible = cell.shards * u64::from(cell.shard_size);
    let committee = u64::from(cell.beacon_size.expect("cell sets beacon_size"));
    let mut by_m: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    for (key, &count) in &tally.beacon {
        let (m, k) = *key;
        *by_m.entry(m).or_default().entry(k).or_default() += count;
    }
    let mut asserted = 0;
    for (&m, ks) in &by_m {
        let samples: u64 = ks.values().sum();
        if samples < 3_000 {
            continue;
        }
        let emp_mean = ks.iter().map(|(&k, &c)| k as f64 * c as f64).sum::<f64>() / samples as f64;
        let p = m as f64 / eligible as f64;
        let thy_mean = committee as f64 * p;
        // Hypergeometric variance of k, then the standard error of the mean.
        let var = committee as f64 * p * (1.0 - p) * (eligible - committee) as f64
            / (eligible - 1) as f64;
        let se = (var / samples as f64).sqrt();
        assert!(
            (emp_mean - thy_mean).abs() <= 4.0 * se,
            "beacon resample at m={m}: E[k] = {emp_mean:.4} deviates from \
             hypergeometric {thy_mean:.4} by more than 4σ (se {se:.4}, {samples} epochs)"
        );
        asserted += 1;
    }
    assert!(asserted >= 3, "only {asserted} m-bins were populated");
}

/// A shard with a pending split is skipped by the shuffle for as long
/// as the record stands, and resumes rotating once it clears — the
/// residence-time extension the analysis note prices is exactly the
/// reshape window. Deterministic.
#[test]
fn shuffle_skips_split_pending_shard() {
    let cell = Cell {
        shards: 4,
        shard_size: 8,
        population: 320,
        corrupt: 0,
        epochs: 0,
        ready_lag_epochs: 0,
        beacon_size: None,
        seed: 0x23,
    };
    let network = NetworkDefinition::simulator();
    let mut state = mc_state(&cell);
    let target = shard_ids(cell.shards)[0];
    let window = 32..=128;
    let no_contributions = BTreeMap::new();

    let mut skipped_events = 0;
    let mut rotated_events = 0;
    for e in 1..=200_u64 {
        if window.contains(&e) {
            // A live pending split: both TTL anchors are refreshed each
            // epoch — `last_asserted` emulates the trigger a splitting
            // shard keeps folding, `admitted_at` outruns the readiness
            // abandonment (an empty cohort is never ready, and the fold
            // sweeps an unready split after `RESHAPE_READY_TTL_EPOCHS`)
            // — while the empty cohort keeps the execution gate
            // unreachable.
            state.pending_reshapes.insert(
                target,
                PendingReshape::Split {
                    last_asserted: Epoch::new(e),
                    admitted_at: Epoch::new(e),
                    cohort: BTreeMap::new(),
                    cohort_seed: Randomness::new([0xaa; 32]),
                },
            );
        } else {
            state.pending_reshapes.remove(&target);
        }
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
        flip_ready(&mut state, 0);
        if !e.is_multiple_of(SHUFFLE_INTERVAL_EPOCHS) {
            continue;
        }
        for (shard, committee_before) in &before {
            let prior: BTreeSet<_> = committee_before.members.iter().copied().collect();
            let current: BTreeSet<_> = state.next_shard_committees[shard]
                .members
                .iter()
                .copied()
                .collect();
            if *shard == target && window.contains(&e) {
                assert_eq!(prior, current, "pending-split shard rotated at epoch {e}");
                skipped_events += 1;
            } else {
                assert_eq!(
                    (
                        prior.difference(&current).count(),
                        current.difference(&prior).count()
                    ),
                    (1, 1),
                    "live shard {shard:?} failed to rotate at epoch {e}"
                );
                if *shard == target {
                    rotated_events += 1;
                }
            }
        }
    }
    // The window covers shuffle epochs 32..128 (7 events); the target
    // rotates at 16 and again at 144+.
    assert_eq!(skipped_events, 7);
    assert!(rotated_events >= 5);
}
