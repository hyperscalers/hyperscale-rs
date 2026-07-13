//! Executable model of the beacon randomness grind and its
//! jail-on-first defence (`specs/committee_security.md` §10).
//!
//! The next-epoch beacon seed is `BLAKE3(prev ‖ VRF outputs of the
//! committed beacon-committee proposals)`, rolled and then consumed —
//! by the trickle shuffle and the committee resample — in the same
//! [`apply_epoch`]. A Byzantine beacon member's VRF output is key-fixed
//! (deterministic in `(key, epoch)`), so its only lever is *inclusion*:
//! reveal early ⇒ folded, withhold ⇒ absent, unfolded. With `t` such
//! members the adversary enumerates the `2^t` include/omit seeds and
//! commits the one whose shuffle best advances a targeted shard's
//! corrupt-seat count. Best-of-`2^t` on one global seed per event
//! marches the shard from `β·n` toward `f+1`.
//!
//! This harness drives the real fold with per-validator VRF keypairs so
//! each grinder's output is distinct and independently toggleable, and an
//! explicit adversary driver that clones the state, applies
//! [`apply_epoch`] under each candidate subset, scores the target shard,
//! and commits the best. It reproduces the analytic model's per-event
//! march probability, then exhibits the raw fork with the jail inert and
//! the jail-on-first cap: any withheld proposal jails its proposer on the
//! first absence, so the grind burns its own foothold and the width
//! collapses.
//!
//! The grinders sit on a *sibling* shard, not the targeted one, so a
//! jailed grinder's exit never confounds the target's corrupt-seat count
//! — the target moves only through its own shuffle, steered by the seed
//! the grinders fold. `t` is held fixed while the grinders survive: the
//! beacon committee is forced to the ready grinders each event, exactly
//! as the model idealises `t` as a given. Folding the seating dilution
//! and resample feedback back in is out of scope here.

#![allow(clippy::cast_precision_loss)] // statistical tallies: every count ≪ 2^52
#![allow(clippy::cast_possible_truncation)] // counts and masks are small by construction
#![allow(clippy::cast_sign_loss)] // rounded counts derive from positive (β·n) products

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconChainConfig, BeaconProposal, BeaconState, Bls12381G1PrivateKey, Epoch, MIN_STAKE_FLOOR,
    NetworkDefinition, NetworkParams, Randomness, SHUFFLE_INTERVAL_EPOCHS, ShardCommittee, ShardId,
    Stake, StakePool, StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus,
    bls_keypair_from_seed, vrf_sign,
};

// ─── Analytic model (ported from committee_security.py) ──────────────────────

const fn f_of(n: u32) -> u32 {
    (n - 1) / 3
}

/// Single-seed per-event gain probability: the shuffle victim (uniform
/// over the `n` seats, `c` corrupt) is honest *and* the pool entrant
/// (corrupt fraction `pool_beta`) is corrupt. The two draws are
/// domain-separated, hence independent.
fn p_gain(n: u32, c: u32, pool_beta: f64) -> f64 {
    (f64::from(n - c) / f64::from(n)) * pool_beta
}

/// Best-of-`2^t` amplification of a single-seed gain probability.
fn best_of(p_single: f64, t: u32) -> f64 {
    1.0 - (1.0 - p_single).powi(1 << t)
}

/// Expected shuffle events to march the targeted shard from `c0` to
/// `f+1` under best-of-`2^t`, holding `pool_beta` fixed — the
/// march-horizon sum in units of events.
fn model_march_events(n: u32, pool_beta: f64, t: u32, c0: u32) -> f64 {
    let mut events = 0.0;
    let mut c = c0;
    while c <= f_of(n) {
        events += 1.0 / best_of(p_gain(n, c, pool_beta), t);
        c += 1;
    }
    events
}

// ─── State construction ──────────────────────────────────────────────────────

/// Little-endian embedding of `x` into a 32-byte seed.
fn seed_bytes(x: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&x.to_le_bytes());
    b
}

/// One BLS keypair per validator id, so each validator's VRF output is
/// distinct — the grind's `2^t` seeds collapse to one if the grinders
/// share a key.
fn signing_keys(population: u64) -> Vec<Bls12381G1PrivateKey> {
    (0..population)
        .map(|i| bls_keypair_from_seed(&seed_bytes(i)))
        .collect()
}

/// The two shards: the targeted shard whose committee is ground, and the
/// sibling that carries the beacon grinders (so their jails never touch
/// the target's corrupt count).
const fn target_shard() -> ShardId {
    ShardId::leaf(1, 0)
}
const fn grinder_shard() -> ShardId {
    ShardId::leaf(1, 1)
}

/// The corrupt-validator marking: the first `seated_corrupt` seats of the
/// **target** shard (ids `0..seated_corrupt`), every grinder on the
/// sibling (ids `[n, n+grinders)`), plus a `pool_beta` fraction of the
/// free pool spread evenly so no region is starved.
fn build_corrupt(
    n: u32,
    grinders: u32,
    population: u64,
    seated_corrupt: u32,
    pool_beta: f64,
) -> BTreeSet<ValidatorId> {
    let mut corrupt: BTreeSet<ValidatorId> = (0..u64::from(seated_corrupt))
        .map(ValidatorId::new)
        .collect();
    for j in 0..u64::from(grinders) {
        corrupt.insert(ValidatorId::new(u64::from(n) + j));
    }
    let seated = u64::from(n) + u64::from(grinders);
    let pool_size = population - seated;
    let pool_corrupt = (pool_beta * pool_size as f64).round() as u64;
    if pool_corrupt > 0 {
        for j in 0..pool_corrupt {
            corrupt.insert(ValidatorId::new(seated + j * pool_size / pool_corrupt));
        }
    }
    corrupt
}

/// A targeted shard of `n` ready seats (ids `0..n`), a sibling of
/// `grinders` ready seats carrying the beacon grinders (ids
/// `[n, n+grinders)`), the rest pooled, one generously funded stake pool,
/// per-id pubkeys. The beacon committee is left empty — the adversary
/// forces it to the grinders each event.
fn build_state(
    n: u32,
    grinders: u32,
    population: u64,
    keys: &[Bls12381G1PrivateKey],
    randomness: [u8; 32],
) -> BeaconState {
    let pool_id = StakePoolId::new(0);
    let target = target_shard();
    let sibling = grinder_shard();
    let seated = u64::from(n) + u64::from(grinders);

    let mut validators = BTreeMap::new();
    let mut pool_validators = BTreeSet::new();
    let mut target_members = Vec::new();
    let mut sibling_members = Vec::new();
    for i in 0..population {
        let id = ValidatorId::new(i);
        let status = if i < u64::from(n) {
            target_members.push(id);
            ValidatorStatus::OnShard {
                shard: target,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            }
        } else if i < seated {
            sibling_members.push(id);
            ValidatorStatus::OnShard {
                shard: sibling,
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
                pubkey: keys[usize::try_from(i).expect("id fits")].public_key(),
            },
        );
        pool_validators.insert(id);
    }

    let mut pools = BTreeMap::new();
    pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            total_stake: Stake::from_attos(u128::from(population) * 5 * MIN_STAKE_FLOOR.attos()),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
        },
    );

    let chain_config = BeaconChainConfig {
        shard_size: n,
        ..BeaconChainConfig::default()
    };
    let mut committees = BTreeMap::new();
    committees.insert(
        target,
        ShardCommittee {
            members: target_members,
        },
    );
    committees.insert(
        sibling,
        ShardCommittee {
            members: sibling_members,
        },
    );

    let mut state = BeaconState {
        chain_config,
        params: NetworkParams::default(),
        next_params: NetworkParams::default(),
        param_votes: BTreeMap::new(),
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: Randomness::new(randomness),
        committee: Vec::new(),
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
        miss_counters: BTreeMap::new(),
    };
    state.shard_consensus_members = state.ready_consensus_members(&state.shard_committees);
    state
}

// ─── The grinding adversary ──────────────────────────────────────────────────

/// Immutable per-run context threaded through the grind driver: the
/// corrupt marking, one signing key per validator, and the network the
/// VRF binds to.
struct Ctx {
    corrupt: BTreeSet<ValidatorId>,
    keys: Vec<Bls12381G1PrivateKey>,
    net: NetworkDefinition,
}

/// Ready seats on `shard` of the requested corruption class, in
/// committee order.
fn ready_seats(
    state: &BeaconState,
    shard: ShardId,
    corrupt: &BTreeSet<ValidatorId>,
    want_corrupt: bool,
) -> Vec<ValidatorId> {
    state.next_shard_committees[&shard]
        .members
        .iter()
        .copied()
        .filter(|id| corrupt.contains(id) == want_corrupt)
        .filter(|id| {
            matches!(
                state.validators.get(id).map(|r| r.status),
                Some(ValidatorStatus::OnShard { shard: s, ready: true, .. }) if s == shard
            )
        })
        .collect()
}

/// Corrupt seats on the targeted shard — the quantity the grind marches.
fn target_corrupt(state: &BeaconState, corrupt: &BTreeSet<ValidatorId>) -> u32 {
    state.next_shard_committees[&target_shard()]
        .members
        .iter()
        .filter(|id| corrupt.contains(id))
        .count() as u32
}

fn proposal(
    keys: &[Bls12381G1PrivateKey],
    net: &NetworkDefinition,
    id: ValidatorId,
    epoch: Epoch,
) -> BeaconProposal {
    let sk = &keys[usize::try_from(id.inner()).expect("id fits")];
    BeaconProposal::vrf_only(vrf_sign(sk, net, epoch))
}

/// The committed proposal set for a grinder subset `mask`: the honest
/// members (always present) plus the grinders whose bit is set.
fn committed_for(
    honest: &[(ValidatorId, BeaconProposal)],
    grinders: &[(ValidatorId, BeaconProposal)],
    mask: u32,
) -> Vec<(ValidatorId, BeaconProposal)> {
    let mut committed = honest.to_vec();
    for (i, gp) in grinders.iter().enumerate() {
        if mask & (1 << i) != 0 {
            committed.push(gp.clone());
        }
    }
    committed
}

/// What one grind event did.
struct EventOutcome {
    before: u32,
    after: u32,
    /// Grinders seated this event (`min(t, corrupt sibling seats)`).
    grind_width: usize,
    jailed: Vec<ValidatorId>,
}

impl EventOutcome {
    const fn gained(&self) -> bool {
        self.after > self.before
    }
}

/// The adversary's play: how many grinders a committed subset may omit,
/// and how ties among equal-gain subsets break.
#[derive(Clone, Copy)]
struct Adversary {
    /// Cap on grinders omitted from any committed subset. `u32::MAX`
    /// leaves the full `2^t` grind open; a small cap models a grinder
    /// that reveals all but a rotating few, the leaky-bucket evader —
    /// which jail-on-first no longer spares (any absence jails).
    omit_cap: u32,
    /// Tie-break among equal-gain subsets. `false` prefers *fewer*
    /// includes — a grinder that withholds by default. `true` prefers
    /// *more* includes — a grinder that reveals unless a gain strictly
    /// needs the omission.
    minimize_absence: bool,
}

impl Adversary {
    /// Withhold by default over the full `2^t`.
    const WITHHOLDING: Self = Self {
        omit_cap: u32::MAX,
        minimize_absence: false,
    };
    /// Omit at most one rotating grinder and minimise absence — the
    /// leaky-bucket evader. Under jail-on-first the single omit still
    /// jails its proposer, so the evasion no longer holds.
    const ROTATE_ONE: Self = Self {
        omit_cap: 1,
        minimize_absence: true,
    };
}

/// Drive one shuffle event under a best-of-width grind.
///
/// Forces the beacon committee to the ready grinders (on the sibling)
/// plus `honest_committee` honest members (present every event, so a
/// withheld grinder reads as absent against a non-empty committed set —
/// the condition the absence pass charges). Enumerates the grinder
/// include/omit subsets the adversary may commit (those omitting at most
/// `adv.omit_cap` grinders), applies [`apply_epoch`] under each on a
/// clone, and commits the subset maximising the *target* shard's
/// corrupt-seat count, ties broken by `adv.minimize_absence`.
///
/// `jail_on_first = false` restores any grinder the fold jailed this
/// event to its sibling seat, modelling the raw march with the absence
/// pass inert. `true` lets the jails stand.
fn grind_event(
    state: &mut BeaconState,
    ctx: &Ctx,
    epoch: Epoch,
    t: u32,
    honest_committee: u32,
    adv: Adversary,
    jail_on_first: bool,
) -> EventOutcome {
    let mut grinders = ready_seats(state, grinder_shard(), &ctx.corrupt, true);
    grinders.truncate(t as usize);
    let mut honest = ready_seats(state, grinder_shard(), &ctx.corrupt, false);
    honest.truncate(honest_committee as usize);

    let mut panel: Vec<ValidatorId> = grinders.iter().chain(honest.iter()).copied().collect();
    panel.sort_unstable();
    state.committee = panel;

    let honest_props: Vec<(ValidatorId, BeaconProposal)> = honest
        .iter()
        .map(|id| (*id, proposal(&ctx.keys, &ctx.net, *id, epoch)))
        .collect();
    let grinder_props: Vec<(ValidatorId, BeaconProposal)> = grinders
        .iter()
        .map(|id| (*id, proposal(&ctx.keys, &ctx.net, *id, epoch)))
        .collect();

    let before = target_corrupt(state, &ctx.corrupt);
    let width = grinder_props.len() as u32;
    debug_assert!(width < 24, "subset enumeration blows up past ~24 grinders");

    let mut best_mask = (1u32 << width) - 1; // default: reveal all
    let mut best_score = i64::MIN;
    let mut best_includes = u32::MAX;
    for mask in 0..(1u32 << width) {
        if width - mask.count_ones() > adv.omit_cap {
            continue; // omits more grinders than the adversary can afford
        }
        let committed = committed_for(&honest_props, &grinder_props, mask);
        let mut probe = state.clone();
        apply_epoch(
            &mut probe,
            &ctx.net,
            epoch,
            ApplyEpochInput::Normal {
                committed: &committed,
                shard_contributions: &BTreeMap::new(),
            },
        );
        let score = i64::from(target_corrupt(&probe, &ctx.corrupt));
        let includes = mask.count_ones();
        let tie_wins = if adv.minimize_absence {
            includes > best_includes
        } else {
            includes < best_includes
        };
        if score > best_score || (score == best_score && tie_wins) {
            best_score = score;
            best_mask = mask;
            best_includes = includes;
        }
    }

    let committed = committed_for(&honest_props, &grinder_props, best_mask);
    let effects = apply_epoch(
        state,
        &ctx.net,
        epoch,
        ApplyEpochInput::Normal {
            committed: &committed,
            shard_contributions: &BTreeMap::new(),
        },
    );
    let grinder_jails: Vec<ValidatorId> = effects
        .jailed
        .iter()
        .copied()
        .filter(|id| grinders.contains(id))
        .collect();
    // In jail-inert mode the fold still runs its (unconditional) absence
    // pass, so restore any grinder it jailed — the raw march measures the
    // shuffle alone. The recorded `jailed` reflects only the jails that
    // *stand*, so the baseline reads as strike-free.
    let stood = if jail_on_first {
        grinder_jails
    } else {
        for &id in &grinder_jails {
            restore_grinder(state, id);
        }
        Vec::new()
    };

    EventOutcome {
        before,
        after: target_corrupt(state, &ctx.corrupt),
        grind_width: grinder_props.len(),
        jailed: stood,
    }
}

/// Undo an absence jail: re-seat `id` on the sibling as a ready member,
/// so the next event's grind still has it. The pool-draw refill the jail
/// triggered is left in place — a benign committee over-count on the
/// sibling, which the harness never measures.
fn restore_grinder(state: &mut BeaconState, id: ValidatorId) {
    if let Some(rec) = state.validators.get_mut(&id) {
        rec.status = ValidatorStatus::OnShard {
            shard: grinder_shard(),
            ready: true,
            placed_at_epoch: Epoch::GENESIS,
        };
    }
    let members = &mut state
        .next_shard_committees
        .get_mut(&grinder_shard())
        .expect("sibling committee present")
        .members;
    if !members.contains(&id) {
        members.push(id);
    }
}

/// One targeted-shard grind configuration.
#[derive(Clone, Copy)]
struct GrindParams {
    n: u32,
    grinders: u32,
    pool_factor: u64,
    pool_beta: f64,
    t: u32,
    honest_committee: u32,
    adv: Adversary,
}

/// Run the grind for up to `max_events`, one shuffle per event (epoch
/// advances by [`SHUFFLE_INTERVAL_EPOCHS`], so each [`apply_epoch`] lands
/// on a shuffle boundary). Returns the final state, the run context, and
/// the per-event outcomes.
fn run_march(
    p: GrindParams,
    seed: u64,
    jail_on_first: bool,
    max_events: u64,
) -> (BeaconState, Ctx, Vec<EventOutcome>) {
    let population = p.pool_factor * u64::from(p.n);
    let c0 = (p.pool_beta * f64::from(p.n)).round() as u32;
    let ctx = Ctx {
        corrupt: build_corrupt(p.n, p.grinders, population, c0, p.pool_beta),
        keys: signing_keys(population),
        net: NetworkDefinition::simulator(),
    };
    let mut state = build_state(p.n, p.grinders, population, &ctx.keys, seed_bytes(seed));

    let f_plus_1 = f_of(p.n) + 1;
    let mut outcomes = Vec::new();
    let mut epoch = 0u64;
    for _ in 0..max_events {
        epoch += SHUFFLE_INTERVAL_EPOCHS;
        let out = grind_event(
            &mut state,
            &ctx,
            Epoch::new(epoch),
            p.t,
            p.honest_committee,
            p.adv,
            jail_on_first,
        );
        let forked = out.after >= f_plus_1;
        let width = out.grind_width;
        outcomes.push(out);
        // Stop on a fork, or once the foothold is fully burned (no ready
        // grinders left to steer the seed).
        if forked || width == 0 {
            break;
        }
    }
    (state, ctx, outcomes)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// The best-of-`2^t` per-event gain probability the grind achieves
/// against the real fold matches the analytic `1-(1-p_gain)^(2^t)` — and
/// the `t=0` (single-seed, no grind) rate matches the bare `p_gain`, so
/// the amplification is measured, not assumed. Grinders sit on the
/// sibling, so the absence jail never confounds the target gain; the run
/// keeps the jail inert regardless.
#[test]
fn grind_gain_probability_matches_best_of_2t_model() {
    let n = 32u32;
    let grinders = 8u32;
    let pool_factor = 8u64;
    let pool_beta = 0.125;
    let seated = 4u32; // fixed c held constant for the measurement
    let honest = 3u32;
    let population = pool_factor * u64::from(n);
    let ctx = Ctx {
        corrupt: build_corrupt(n, grinders, population, seated, pool_beta),
        keys: signing_keys(population),
        net: NetworkDefinition::simulator(),
    };
    let template = build_state(n, grinders, population, &ctx.keys, seed_bytes(0));

    // The exact single-seed gain probability for this state.
    let pooled = template.pooled_validators();
    let pooled_corrupt = pooled.iter().filter(|id| ctx.corrupt.contains(id)).count();
    let realized_beta = pooled_corrupt as f64 / pooled.len() as f64;
    let p_single = p_gain(n, seated, realized_beta);

    let k = 300u64;
    for t in [0u32, 4] {
        let p_model = best_of(p_single, t);
        let mut gains = 0u64;
        for s in 0..k {
            let mut state = template.clone();
            state.randomness = Randomness::new(seed_bytes(1 + s + u64::from(t) * k));
            let out = grind_event(
                &mut state,
                &ctx,
                Epoch::new(SHUFFLE_INTERVAL_EPOCHS),
                t,
                honest,
                Adversary::WITHHOLDING,
                false,
            );
            if out.gained() {
                gains += 1;
            }
        }
        let empirical = gains as f64 / k as f64;
        // 4σ binomial band, floored so t=0's tiny p keeps a sane window.
        let tol = (4.0 * (p_model * (1.0 - p_model) / k as f64).sqrt()).max(0.03);
        assert!(
            (empirical - p_model).abs() < tol,
            "t={t}: empirical {empirical:.3} vs model {p_model:.3} (band ±{tol:.3})",
        );
    }
}

/// Jail inert, the grind marches the targeted shard from `β·n` to `f+1`
/// — the raw fork — within a bound on the analytic march horizon,
/// confirming the finding end to end.
#[test]
fn jail_inert_grind_marches_a_targeted_shard_to_a_fork() {
    let n = 64u32;
    let pool_beta = 0.10;
    let t = 4u32;
    let c0 = (pool_beta * f64::from(n)).round() as u32;
    let f_plus_1 = f_of(n) + 1;
    let params = GrindParams {
        n,
        grinders: t,
        pool_factor: 8,
        pool_beta,
        t,
        honest_committee: 3,
        adv: Adversary::WITHHOLDING,
    };
    let (state, ctx, outcomes) = run_march(params, 0x00C0_FFEE, false, 400);

    let final_corrupt = target_corrupt(&state, &ctx.corrupt);
    assert!(
        final_corrupt >= f_plus_1,
        "jail-inert grind must fork the shard: reached {final_corrupt}/{f_plus_1} corrupt",
    );
    assert!(
        outcomes.iter().all(|o| o.jailed.is_empty()),
        "jail inert, no grinder is jailed",
    );
    let model = model_march_events(n, pool_beta, t, c0);
    assert!(
        (outcomes.len() as f64) <= 4.0 * model,
        "march took {} events vs ~{model:.0} expected",
        outcomes.len(),
    );
}

/// Jail-on-first, the same withholding grind burns its own foothold: to
/// grind it must omit a grinder, and any omission jails that grinder on
/// the first absence. The grind width collapses within a handful of
/// events, and across the whole horizon in which the jail-inert grind
/// forked, the target shard never reaches `f+1`.
#[test]
fn jail_on_first_burns_the_withholding_grind() {
    let n = 64u32;
    let pool_beta = 0.10;
    let t = 4u32;
    let f_plus_1 = f_of(n) + 1;
    let params = GrindParams {
        n,
        grinders: t,
        pool_factor: 8,
        pool_beta,
        t,
        honest_committee: 3,
        adv: Adversary::WITHHOLDING,
    };

    // The jail-inert run establishes the fork and its horizon.
    let (off_state, ctx, off) = run_march(params, 0x00C0_FFEE, false, 400);
    assert!(
        target_corrupt(&off_state, &ctx.corrupt) >= f_plus_1,
        "baseline jail-inert run must fork",
    );
    let horizon = off.len().max(20) as u64;

    // Jail-on-first, matched seed.
    let (on_state, on_ctx, on) = run_march(params, 0x00C0_FFEE, true, horizon);

    let jailed: BTreeSet<ValidatorId> = on.iter().flat_map(|o| o.jailed.iter().copied()).collect();
    assert!(
        !jailed.is_empty(),
        "jail-on-first, the withholding grinders must jail on their first absence",
    );
    assert!(
        jailed.iter().all(|v| on_ctx.corrupt.contains(v)),
        "every absence jail lands on a grinder, never an honest member",
    );
    // The foothold burns: within a few events every grinder is jailed and
    // the grind can no longer steer, so the width falls to zero.
    assert!(
        on.iter().any(|o| o.grind_width == 0),
        "the grind width must collapse to zero once the grinders jail out",
    );
    assert!(
        target_corrupt(&on_state, &on_ctx.corrupt) < f_plus_1,
        "jail-on-first must hold the shard below the fork across the horizon: {}/{f_plus_1}",
        target_corrupt(&on_state, &on_ctx.corrupt),
    );
}

/// The leaky-bucket evader is closed too. A grinder that omits at most
/// one *rotating* proposal per event held its per-grinder absence near
/// `1/t` — below the old strike crossover — but jail-on-first has no
/// crossover: the single omitted proposal jails its proposer on the
/// first absence, so even the rotating grind burns out.
#[test]
fn jail_on_first_closes_the_rotate_one_evader() {
    let n = 64u32;
    let pool_beta = 0.10;
    let t = 8u32;
    let f_plus_1 = f_of(n) + 1;
    let params = GrindParams {
        n,
        grinders: t,
        pool_factor: 8,
        pool_beta,
        t,
        honest_committee: 3,
        adv: Adversary::ROTATE_ONE,
    };

    let (state, ctx, outcomes) = run_march(params, 0x00C0_FFEE, true, 400);

    let jailed: BTreeSet<ValidatorId> = outcomes
        .iter()
        .flat_map(|o| o.jailed.iter().copied())
        .collect();
    assert!(
        !jailed.is_empty(),
        "the rotating single omit still jails its proposer — no crossover to hide under",
    );
    assert!(
        jailed.iter().all(|v| ctx.corrupt.contains(v)),
        "every jail lands on a grinder",
    );
    assert!(
        target_corrupt(&state, &ctx.corrupt) < f_plus_1,
        "the rotate-one grind is capped below the fork: {}/{f_plus_1}",
        target_corrupt(&state, &ctx.corrupt),
    );
}

/// The grind is a pure function of its seed: two runs with the same seed
/// land on byte-identical committees and randomness (INV-DET-4).
#[test]
fn grind_is_deterministic_for_a_fixed_seed() {
    let params = GrindParams {
        n: 64,
        grinders: 4,
        pool_factor: 8,
        pool_beta: 0.10,
        t: 4,
        honest_committee: 3,
        adv: Adversary::WITHHOLDING,
    };
    let run = || run_march(params, 0x5EED, false, 40);
    let (a_state, _, _) = run();
    let (b_state, _, _) = run();
    assert_eq!(a_state.randomness, b_state.randomness);
    assert_eq!(
        a_state.next_shard_committees[&target_shard()].members,
        b_state.next_shard_committees[&target_shard()].members,
    );
}
