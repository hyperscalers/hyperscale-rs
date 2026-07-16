#!/usr/bin/env python3
"""Committee-security parameter tables for INV-SEC-1 (see committee_security.md).

Prices the premise every verified safety property is conditional on: that no
committee ever seats >= f+1 corrupt members. Dependency-free; exact
hypergeometric arithmetic via log-gamma, plus seeded Monte Carlo for the
coupled dynamics no closed form covers.

Units: seats (voting is per seat; stake is the admission gate). The primary
failure event is a committee reaching k >= f+1 corrupt seats, f = (n-1)//3 —
a recoverable halt; the terminal boundary 2f+1 is priced by table V.

Table index (letter -> note section):
  A fresh draws (S1)         I beacon redraw (S1)       B/C trickle chain (S2)
  D1/D2 sizing (S3)          E/J/K adaptive (S4, S8)    F seats vs stake (S5)
  G operating point (S6)     H interval sweep (S6)      L concentration (S7)
  V terminal boundary (S10.1)             W1-W4 window edge (S10.3)
  M/N fallback ceremony grind (S10.4)     R/T input-side stack (S10.5)
  S detect-and-rotate (S10.6)

Run: python3 specs/committee_security.py
"""

from math import comb, exp, lgamma, log

# ── Deployment parameters (defaults mirror intent, not the dev constants) ──
EPOCH_SECONDS = 300             # production target (BeaconChainConfig default); dev sim uses 2s
SHUFFLE_INTERVAL_EPOCHS = 16    # crates/types/src/beacon/constants.rs
EPOCHS_PER_YEAR = 365.25 * 86400 / EPOCH_SECONDS
SHUFFLE_EVENTS_PER_SHARD_YEAR = EPOCHS_PER_YEAR / SHUFFLE_INTERVAL_EPOCHS

# Candidate committee sizes, capped by message complexity (256 is already
# questionable on that axis); 4 is the current dev value, for reference.
CANDIDATES = [32, 64, 96, 128, 256]
N_SWEEP = [4] + CANDIDATES
BETA_SWEEP = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]  # corrupt fraction of the pool
POOL_FACTOR = 20                                    # pool size N = POOL_FACTOR * n


def log_comb(n: int, k: int) -> float:
    return lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)


def hyper_pmf(N: int, M: int, n: int, k: int) -> float:
    if k < max(0, n - (N - M)) or k > min(n, M):
        return 0.0
    return exp(log_comb(M, k) + log_comb(N - M, n - k) - log_comb(N, n))


def hyper_tail(N: int, M: int, n: int, t: int) -> float:
    """P[Hypergeom(N, M, n) >= t]."""
    return sum(hyper_pmf(N, M, n, k) for k in range(t, min(n, M) + 1))


def f_of(n: int) -> int:
    return (n - 1) // 3


# ── Trickle shuffle as a birth-death chain on k = corrupt seats ────────────
# One event: a uniform committee member rotates out, a uniform pool member
# replaces it. Idealizations vs the fold code are listed in the note.

def p_up(N: int, M: int, n: int, k: int) -> float:
    return ((n - k) / n) * ((M - k) / (N - n))


def p_down(N: int, M: int, n: int, k: int) -> float:
    return (k / n) * ((N - M - (n - k)) / (N - n))


def check_detailed_balance(N: int, M: int, n: int) -> None:
    """The chain's stationary law is exactly hypergeometric (Bernoulli-Laplace)."""
    for k in range(min(n, M)):
        lhs = hyper_pmf(N, M, n, k) * p_up(N, M, n, k)
        rhs = hyper_pmf(N, M, n, k + 1) * p_down(N, M, n, k + 1)
        if lhs > 1e-300 and abs(lhs - rhs) > 1e-9 * max(lhs, rhs):
            raise AssertionError(f"detailed balance broken at k={k}")


def crossing_rate(N: int, M: int, n: int, boundary: int | None = None) -> float:
    """Stationary frequency (per shuffle event) of the k = b-1 -> b crossing,
    for boundary b (default f+1; pass 2f+1 for the terminal boundary).

    Conservative failure accounting: every boundary crossing counts as a
    committee compromise, whether or not an adversary exploits the interval.
    """
    k = (f_of(n) if boundary is None else boundary - 1)
    pi = hyper_pmf(N, M, n, k)
    return pi * p_up(N, M, n, k) if pi > 0.0 else 0.0


# ── The fallback ceremony grind (tables M, N — §10.4) ───────────────────────
# The epoch seed's primary source is the reveal-leaf fold (tables W); in an
# epoch where no witness chunk folds, the seed falls back to the beacon
# ceremony mix BLAKE3(prev || VRF outputs of the COMMITTED beacon-committee
# proposals). Each VRF output is key-fixed (deterministic in (key, epoch)),
# so a Byzantine beacon member cannot choose its value — only whether it
# joins the fold: reveal early => folded, withhold => BOTTOM, not folded. The
# dense-vector PC input commits interior BOTTOMs without shortening the
# prefix, so the toggle is independent per member. With t strategically-
# releasable Byzantine proposals the adversary enumerates 2^t candidate seeds
# (ChaCha20 is a PRF: distinct seed => independent uniform draw), computes
# each one's committee, and steers the commit to the best. Best-of-2^t on one
# global seed per epoch, one-epoch lookahead (not retroactive, not
# compounding beyond the per-epoch redraw). t's natural mean is beta*b over
# the beacon committee; the resample boost lifts it above that (table T).

def grind_shard_march_days(
    n: int, beta: float, t: int, interval: int = SHUFFLE_INTERVAL_EPOCHS
) -> float:
    """Expected days to march ONE targeted shard from beta*n to f+1 corrupt
    seats under a best-of-2^t grind of the trickle shuffle. Each event the
    adversary grinds for an honest victim AND a corrupt entrant — single-seed
    p_gain(c) = ((n-c)/n) * beta — and best-of-2^t drives the per-event
    success to 1-(1-p_gain)^(2^t). Corrupt count is monotone: the grind also
    steers away from corrupt-losing rotations, so a no-gain event holds rather
    than loses. Converges to the deterministic floor (f+1-beta*n events) as
    2^t * p_gain >> 1."""
    f = f_of(n)
    c0 = round(beta * n)
    k = 2 ** t
    intervals = 0.0
    c = c0
    while c < f + 1:
        p_gain = ((n - c) / n) * beta
        p = 1 - (1 - p_gain) ** k
        if p <= 0.0:
            return float("inf")
        intervals += 1 / p
        c += 1
    return intervals * interval * EPOCH_SECONDS / 86400


def grind_resample_year(n: int, beta: float, t: int, shards: int = 100) -> float:
    """Best-of-2^t amplification of the beacon committee's per-epoch resample
    tail, expressed per network-year. Eligible ~ shards * n (one committee
    network-wide, redrawn every epoch); the single-draw tail P[>=f+1] is
    amplified to 1-(1-p)^(2^t) and scaled by draws/year. Epoch-commit safety
    rides pool ratification (INV-BEACON-1), so this prices liveness and
    randomness-bias exposure, not a fork."""
    N = shards * n
    f = f_of(n)
    p = hyper_tail(N, round(N * beta), n, f + 1)
    return (1 - (1 - p) ** (2 ** t)) * EPOCHS_PER_YEAR


def fmt_duration(days):
    """Compact days / years / never for the residual-march tables."""
    if days == float("inf"):
        return "never"
    if days < 90:
        return f"{days:.1f}d"
    yr = days / 365.25
    return f"{yr:.0f}y" if yr < 1000 else f"{yr:.0e}y"


# ── Network-wide grind: the finite shared pool the single-shard march ignores ─
# The single-shard march (table M) models one targeted shard drawing from an
# inexhaustible pool at a fixed corrupt fraction beta. That is the exchangeable
# regime, where §7's mean-field pool is exact. A *concentrating* grind breaks
# exchangeability: the corrupt population is conserved (M = beta*N seats
# network-wide), the pool is finite and SHARED, and every shard shuffles from
# it — so the target competes with the whole network for a limited corrupt
# supply, and any deterministic-longest (FIFO) eviction forces the seats it does
# win to age out on a fixed n-event clock back into that contested pool.
#
# Under all-shard FIFO the target's corrupt count is a stable equilibrium, not a
# monotone march: with pool corrupt fraction x, the grind seats a corrupt
# entrant at rate p = 1-(1-x)^width and FIFO evicts corrupt at rate c_T/n, so
# c_T = n*(1-(1-x)^width). Conserving corrupt over the target, the (shards-1)
# random-draw shards (each at fraction x), and the pool P closes the system:
#   M = c_T + (shards-1)*x*n + x*P .
# One scalar root x in (0, beta]. Three regimes: supply FLOOR (M <= f, can't
# seat f+1 at all — the note's structural bound), FIFO CAP (M > f but the
# equilibrium c_T < f+1, so a fork is only a rare crossing of the equilibrium,
# reverting to the un-steered tail), or FORK (c_T >= f+1). A victim-grind
# eviction rule — evict an honest seat to protect the corrupt ones — has no
# aging-out and forks whenever supply permits (M > f); FIFO turning that
# supply floor into a dynamic cap is why FIFO is the eviction rule.

# Unseated buffer for the NETWORK model: a small shared pool of Pooled spares
# (jail/exit refill stock + reshape cohorts), unlike §1's POOL_FACTOR=20, which
# is the eligible population a SINGLE committee draws from. Here most validators
# are seated on shards and the pool is a couple of committees the whole network
# shuffles through.
NET_POOL_FACTOR = 2


def grind_network_equilibrium(n, beta, shards, pool_factor, width):
    """Mean-field target-shard corrupt equilibrium c_T under all-shard FIFO
    eviction with a conserved corrupt population and a finite shared pool.
    Returns (c_T, pool_fraction). Validated against a Monte Carlo below."""
    pool = round(pool_factor * n)
    total = shards * n + pool
    corrupt = beta * total
    rest = (shards - 1) * n + pool
    lo, hi = 0.0, beta
    for _ in range(200):
        x = 0.5 * (lo + hi)
        if n * (1 - (1 - x) ** width) + x * rest - corrupt > 0:
            hi = x
        else:
            lo = x
    x = 0.5 * (lo + hi)
    return n * (1 - (1 - x) ** width), x


def grind_network_regime(n, beta, shards, pool_factor, width):
    """'floor' (supply M <= f), 'fork' (equilibrium c_T >= f+1), or the capped
    c_T as a float (a dynamic FIFO cap strictly below f+1)."""
    f = f_of(n)
    if beta * (shards * n + round(pool_factor * n)) <= f:
        return "floor"
    c_t, _ = grind_network_equilibrium(n, beta, shards, pool_factor, width)
    return "fork" if c_t >= f + 1 else c_t


def _grind_network_sim(n, beta, shards, pool_factor, width, intervals, seed, fifo):
    """Seeded Monte Carlo of the conserved-population network grind — validation
    for the mean field, not a table generator. `fifo` picks the eviction rule on
    the target: True = deterministic longest-seated; False = victim-grind
    (evict an honest seat to protect corrupt). One corrupt entrant
    is ground onto the target per event at effective width `width`; the other
    shards draw uniformly. Returns the fraction of events the target held f+1."""
    from random import Random

    rng = Random(seed)
    pool = round(pool_factor * n)
    total = shards * n + pool
    corrupt = round(beta * total)
    f = f_of(n)
    seats = [True] * corrupt + [False] * (total - corrupt)
    rng.shuffle(seats)
    committees = [seats[s * n:(s + 1) * n] for s in range(shards)]
    cp = sum(seats[shards * n:])
    hp = pool - cp
    forks = 0
    for _ in range(intervals):
        for s in range(shards):
            c = committees[s]
            if s == 0 and fifo:
                ev = c.pop(0)
            elif s == 0:
                idx = next((i for i, v in enumerate(c) if not v), 0)
                ev = c.pop(idx)
            else:
                idx = rng.randrange(len(c))
                ev = c.pop(idx)
            if ev:
                cp += 1
            else:
                hp += 1
        tot = cp + hp
        p_grind = 1 - (1 - cp / tot) ** width if tot else 0.0
        if tot and rng.random() < p_grind and cp > 0:
            committees[0].append(True)
            cp -= 1
        elif hp > 0:
            committees[0].append(False)
            hp -= 1
        elif cp > 0:
            committees[0].append(True)
            cp -= 1
        else:
            committees[0].append(False)
        for s in range(1, shards):
            tot = cp + hp
            if not tot:
                committees[s].append(False)
                continue
            if rng.random() < cp / tot:
                committees[s].append(True)
                cp -= 1
            else:
                committees[s].append(False)
                hp -= 1
        if sum(committees[0]) >= f + 1:
            forks += 1
    return forks / intervals


def check_grind_network() -> None:
    """The mean field and the Monte Carlo must agree on the fork/cap verdict at a
    small tractable instance (n=32, so the 20000-event sim runs fast)."""
    n, shards, pf = 32, 12, 2.0
    for beta, width in ((0.03, 4), (0.12, 64)):
        regime = grind_network_regime(n, beta, shards, pf, width)
        forks = _grind_network_sim(n, beta, shards, pf, width, 8000, 5, fifo=True)
        mf_forks = regime == "fork"
        # A capped equilibrium far below f+1 must (almost) never cross; a
        # fork equilibrium must cross often.
        if mf_forks and forks < 0.2:
            raise AssertionError(f"mean field forks but sim rarely does (beta={beta})")
        if not mf_forks and regime != "floor" and forks > 0.05:
            raise AssertionError(f"mean field caps but sim forks (beta={beta})")


# ── The adaptive adversary, computed exactly (tables J/K/L) ─────────────────
# Time step = one shuffle event, the chain's native clock. The adversary
# holds `pressure` targeted corruption attempts in flight against seated
# honest members; each attempt lands per event with probability I/tau
# (tau epochs per attempt), landings are Binomial(pressure, I/tau) with the
# tail folded into the top branch. The rotation then swaps one uniform seat
# (mean-field replacement corruption, as in the chain). Sustaining the
# pressure costs the launches that land plus the ones rotation flushes.


def landing_weights(in_flight: int, p: float, max_land: int = 3) -> list:
    """Binomial(in_flight, p) over 0..max_land, tail folded into the top."""
    weights = []
    rest = 1.0
    for j in range(max_land):
        if in_flight >= j and p > 0.0:
            w = exp(log_comb(in_flight, j)) * p**j * (1 - p) ** (in_flight - j)
        else:
            w = 1.0 if j == 0 else 0.0
        weights.append(w)
        rest -= w
    weights.append(max(rest, 0.0))
    return weights


def compromise_probability(
    n: int, beta: float, interval: int, tau: int, pressure: int, horizon_events: int
) -> tuple:
    """P[k ever >= f+1 within the horizon] under sustained pressure, from the
    stationary start conditioned below the boundary, and the launch rate
    (attempts/day) the pressure costs."""
    N = POOL_FACTOR * n
    M = round(N * beta)
    f = f_of(n)
    dist = [hyper_pmf(N, M, n, k) for k in range(f + 1)]
    z = sum(dist)
    dist = [p / z for p in dist]
    success = 0.0
    p_land = interval / tau
    weights_for = [landing_weights(a, p_land) for a in range(n + 1)]
    for _ in range(horizon_events):
        new = [0.0] * (f + 1)
        for k, pk in enumerate(dist):
            if pk == 0.0:
                continue
            in_flight = min(pressure, n - k)
            q = (M - k) / (N - n)
            for landed, w_land in enumerate(weights_for[in_flight]):
                if w_land == 0.0:
                    continue
                k1 = k + landed
                if k1 > f:
                    success += pk * w_land
                    continue
                for dk, w_rot in (
                    (-1, (k1 / n) * (1 - q)),
                    (0, (k1 / n) * q + (1 - k1 / n) * (1 - q)),
                    (1, (1 - k1 / n) * q),
                ):
                    w = pk * w_land * w_rot
                    if k1 + dk > f:
                        success += w
                    else:
                        new[k1 + dk] += w
        dist = new
    events_per_day = 86400 / (EPOCH_SECONDS * interval)
    launches_per_event = pressure * p_land + pressure / n
    return success, launches_per_event * events_per_day


def adversary_value_iteration(
    n: int,
    beta: float,
    interval: int,
    tau: int,
    budget: int,
    max_in_flight: int,
    horizon_events: int,
    greedy_only: bool,
    want_policy: bool = False,
):
    """Exact backward induction over (k, in-flight, budget): max P[compromise
    within the horizon], action = attempts launched per event (0..4). With
    `greedy_only`, evaluates the launch-maximum policy instead of optimizing —
    the gap between the two is the value of adaptivity. With `want_policy`,
    also returns the t=0 optimal launch count per k at (in-flight 0, full
    budget), which exposes the conserve-then-spend shape."""
    N = POOL_FACTOR * n
    M = round(N * beta)
    f = f_of(n)
    p_land = interval / tau
    k_dim, a_dim, b_dim = f + 1, max_in_flight + 1, budget + 1
    weights_for = [landing_weights(a, p_land) for a in range(max_in_flight + 1)]

    # value[k][a][b]; terminal value 0 (no compromise by the horizon).
    value = [[[0.0] * b_dim for _ in range(a_dim)] for _ in range(k_dim)]
    policy = [0] * k_dim
    for step in range(horizon_events):
        nxt = [[[0.0] * b_dim for _ in range(a_dim)] for _ in range(k_dim)]
        last_step = step == horizon_events - 1
        for k in range(k_dim):
            q = (M - k) / (N - n)
            for a in range(a_dim):
                for b in range(b_dim):
                    best, best_j = -1.0, 0
                    j_max = min(4, b, max_in_flight - a, n - k - a)
                    actions = (
                        (max(j_max, 0),) if greedy_only else range(max(j_max, 0) + 1)
                    )
                    for j in actions:
                        a1, b1 = a + j, b - j
                        total = 0.0
                        for landed, w_land in enumerate(weights_for[a1]):
                            if w_land == 0.0:
                                continue
                            landed = min(landed, a1)
                            k1, a2 = k + landed, a1 - landed
                            if k1 > f:
                                total += w_land
                                continue
                            for (dk, da), w_rot in (
                                ((-1, 0), (k1 / n) * (1 - q)),
                                ((0, 0), (k1 / n) * q),
                                ((0, -1), (a2 / n) * (1 - q)),
                                ((1, -1), (a2 / n) * q),
                                ((0, 0), ((n - k1 - a2) / n) * (1 - q)),
                                ((1, 0), ((n - k1 - a2) / n) * q),
                            ):
                                if w_rot == 0.0:
                                    continue
                                k2, a3 = k1 + dk, max(a2 + da, 0)
                                if k2 > f:
                                    total += w_land * w_rot
                                else:
                                    total += w_land * w_rot * value[k2][a3][b1]
                        if total > best:
                            best, best_j = total, j
                    nxt[k][a][b] = best
                    if last_step and a == 0 and b == budget:
                        policy[k] = best_j
        value = nxt
    start = value[round(beta * n)][0][budget]
    return (start, policy) if want_policy else start


# ── The ceremony grind vs the tunable parameters (table T — §10.5) ───────────
# Three knobs move the fallback ceremony grind; table T prices what each
# actually closes:
#
#   beacon committee size b  — the grind WIDTH lever. Width = 2^t with t the
#     corrupt beacon proposers; the NATURAL foothold is t ~ Binomial(b, beta),
#     and grind_width_cap prices the FIFO target equilibrium off it. The
#     natural cap is not what an adversary realizes: the resample boost
#     (steering this epoch's seed to over-represent corrupt in the next
#     epoch's beacon draw) lifts t above its Binomial mean, and the coupled
#     sim shows it surviving jail-on-first at the true eligible-pool size —
#     b=16 realizes c_T = 61 against the natural cap's 40; b=20 realizes 86,
#     over the terminal 2f+1 line.
#   withholding penalty  — jail-on-first, honest-safe because the protocol is
#     leaderless: the committed value is the f+1-shared prefix (qc1_certify),
#     so an honest proposal reaching a supermajority commits regardless of
#     delay outside bounded async windows, while a grinder is absent by
#     self-omission always. Clean (sim_async_purge: the realized honest purge
#     is a rounding error) but shallow (the eligible pool is too large for the
#     drain to deplete the corrupt supply) — a bar-raise, not a close. The
#     recency-weighted resample is what caps the SUSTAINED foothold
#     (sim_recency below).
#   shuffle interval I  — a march is linear in I, but marches are confined to
#     the fallback path (sustaining one needs self-announcing network-scale
#     suppression) and the window-edge equilibrium is I-independent, so I
#     trades chiefly against adaptive corruption (§6 Rider 1).

def grind_width_cap(n, beta, beacon_size):
    """FIFO target-shard corrupt equilibrium under a beacon committee of
    `beacon_size`, natural (jail-on-first-suppressed) foothold: the grind seats
    corrupt at rate E over T~Binomial(beacon_size, beta) of 1-(1-beta)^(2^T),
    FIFO evicts at c/n, so c_T = n * that expectation. Caps below f+1 for a
    small enough committee."""
    e_p = sum(
        exp(log_comb(beacon_size, k)) * beta**k * (1 - beta) ** (beacon_size - k)
        * (1 - (1 - beta) ** (2 ** min(k, 30)))
        for k in range(beacon_size + 1)
    )
    return n * e_p


def beacon_compromise(beta, beacon_size):
    """P[a fresh beacon committee draw is itself >= f+1 corrupt]. Rides pool
    ratification (INV-BEACON-1), so this prices beacon liveness/bias, not a
    fork — the cost of shrinking the committee to cap the grind width."""
    return sum(
        exp(log_comb(beacon_size, k)) * beta**k * (1 - beta) ** (beacon_size - k)
        for k in range(f_of(beacon_size) + 1, beacon_size + 1)
    )


def purge_beta_eff(n, beta, beacon_size, cooldown, shards=100, pool_factor=2):
    """Worst-case effective beta among the active set under jail-on-first, if the
    adversary could force f_beacon honest absent per epoch and hold them jailed
    for `cooldown` epochs. SPC censorship resistance (partial synchrony) confines
    real exclusion to bounded async windows, so this is a ceiling, not the
    expected value — and it stays near beta because a small committee has few
    honest to purge."""
    total = shards * n + pool_factor * n
    corrupt = beta * total
    honest = total - corrupt
    jailed = min(f_of(beacon_size) * cooldown, honest - 1)
    return corrupt / (corrupt + honest - jailed)


# ── The resample boost, coupled to the withholding penalty (the width cap the
# ── mean field assumes, tested against the pool it actually draws from) ──────
# grind_width_cap prices the target-shard equilibrium off the NATURAL beacon
# foothold T ~ Binomial(beacon_size, beta) — the width the adversary gets if the
# resample grind (steering this epoch's seed to over-represent itself in NEXT
# epoch's committee draw) is fully suppressed. Whether jail-on-first for
# withholding achieves that suppression is not a closed-form question: the
# beacon committee is redrawn every epoch from beacon_eligible() = every
# OnShard{ready} validator network-wide (~shards*n seats), so the corrupt supply
# the resample draws from is ~beta*shards*n, and jail-on-first only removes the
# members the winning grind pattern actually omits (~T/2 per epoch) for a
# cooldown. The two rates — supply and drain — decide whether the boost
# collapses to the natural foothold or sustains above it. This Monte Carlo
# couples them.

_WIDTH_CAP = 1 << 60   # beyond this the best-of saturates; keeps ints bounded


def _omit_width(T, s):
    """Grind width from omitting up to `s` of `T` seated corrupt beacon
    proposals: the number of distinct include/omit patterns (candidate seeds)
    the adversary can try, sum_{i<=s} C(T,i). s>=T gives the full 2^T; s=0
    gives 1 (no grind)."""
    if s >= T:
        return _WIDTH_CAP if T >= 60 else (1 << T)
    return min(sum(comb(T, i) for i in range(s + 1)), _WIDTH_CAP)


def _binom_pmf(k, b, x):
    if x <= 0.0:
        return 1.0 if k == 0 else 0.0
    if x >= 1.0:
        return 1.0 if k == b else 0.0
    return exp(log_comb(b, k) + k * log(x) + (b - k) * log(1 - x))


def _sample_best_of(rng, w, b, x):
    """Sample T = max over `w` i.i.d. Binomial(b, x) committee corrupt counts —
    the resample grind's best-of-w over candidate committee draws. Drawn from
    the max-CDF so `w` may be astronomically large (no per-candidate loop)."""
    cum, c = [], 0.0
    for k in range(b + 1):
        c += _binom_pmf(k, b, x)
        cum.append(min(c, 1.0))
    u = rng.random()
    for k in range(b + 1):
        if cum[k] ** w >= u:   # P[max <= k] = cum[k]^w
            return k
    return b


def sim_resample_boost(n, beta, beacon_size, omit_frac, jail, cooldown,
                       epochs, seed, shards=100, pool_factor=NET_POOL_FACTOR,
                       boost=True, eligible=None):
    """Couple the resample-grind boost to the withholding penalty. Each epoch
    the beacon committee is a best-of-w_prev draw off the grindable seed (the
    boost the last grind bought); the adversary omits `omit_frac` of its
    foothold to grind width w = sum_{i<=s} C(T,i), steering next epoch's
    committee and, on shuffle epochs, a corrupt entrant onto the FIFO target
    shard. Under `jail`, every omitted member jails on the first absence and
    leaves the eligible pool for `cooldown` epochs. `boost=False` disables the
    carryover (plain single draw) — the fully-suppressed reference that must
    reproduce grind_width_cap. Returns realized foothold, width, and c_T."""
    from random import Random

    rng = Random(seed)
    f = f_of(n)
    E_tot = eligible if eligible is not None else shards * n + round(pool_factor * n)
    A_c = round(beta * E_tot)          # corrupt eligible, not jailed, not on target
    ring = [0] * max(cooldown, 1)      # jail-return ring buffer
    jailed = 0

    committee = [False] * n            # target shard, FIFO (oldest at index 0)
    for i in rng.sample(range(n), round(beta * n)):
        committee[i] = True
    c = sum(committee)
    A_c -= c

    w_prev, sum_w, sum_T, max_c, fork_events, shuffle_events = 1, 0.0, 0.0, c, 0, 0
    for t in range(epochs):
        slot = t % len(ring)
        A_c += ring[slot]
        jailed -= ring[slot]
        ring[slot] = 0

        active = E_tot - jailed
        x = min(max(A_c / active, 0.0), 1.0) if active > 0 else 0.0
        T = _sample_best_of(rng, min(w_prev, _WIDTH_CAP) if boost else 1, beacon_size, x)
        s = round(omit_frac * T)
        w = _omit_width(T, s)

        if jail and s > 0:
            take = min(s, A_c)
            A_c -= take
            jailed += take
            ring[(t + cooldown) % len(ring)] += take

        if t % SHUFFLE_INTERVAL_EPOCHS == 0:
            shuffle_events += 1
            if committee.pop(0):
                A_c += 1
            if rng.random() < 1 - (1 - x) ** min(w, _WIDTH_CAP) and A_c > 0:
                committee.append(True)
                A_c -= 1
            else:
                committee.append(False)
            c = sum(committee)
            max_c = max(max_c, c)
            fork_events += c >= f + 1

        sum_w += min(w, 1 << 30)
        sum_T += T
        w_prev = w

    return {
        "mean_T": sum_T / epochs,
        "mean_width": sum_w / epochs,
        "final_c": c,
        "max_c": max_c,
        "fork_frac": fork_events / max(shuffle_events, 1),
        "x": x,
    }


def sim_async_purge(n, beta, beacon_size, p_async, cooldown, epochs, seed,
                    shards=100, pool_factor=NET_POOL_FACTOR):
    """Realized honest purge under jail-on-first vs the purge_beta_eff ceiling.
    Each epoch is synchronous w.p. 1-p_async (an honest proposal reaching f+1 of
    the committee is committed by qc1_certify, so NObody is forced absent) or
    async w.p. p_async (the adversary excludes up to f_beacon honest committee
    members, who jail for `cooldown`). Returns the realized effective beta among
    the active (non-jailed) population — the ceiling holds only if p_async=1."""
    from random import Random

    rng = Random(seed)
    total = shards * n + round(pool_factor * n)
    corrupt = round(beta * total)
    honest = total - corrupt
    f_b = f_of(beacon_size)
    ring = [0] * max(cooldown, 1)
    jailed_honest = 0
    sum_beta_eff, max_jailed = 0.0, 0
    for t in range(epochs):
        slot = t % len(ring)
        jailed_honest -= ring[slot]
        ring[slot] = 0
        if rng.random() < p_async:
            excl = max(0, min(f_b, honest - jailed_honest))
            jailed_honest += excl
            ring[(t + cooldown) % len(ring)] += excl
        active_honest = honest - jailed_honest
        sum_beta_eff += corrupt / (corrupt + active_honest)
        max_jailed = max(max_jailed, jailed_honest)
    return {"mean_beta_eff": sum_beta_eff / epochs, "max_jailed": max_jailed}


def check_resample_boost() -> None:
    """The coupled sim must (1) reproduce grind_width_cap when the boost is
    suppressed, and (2) show the boost SURVIVING jail-on-first at the true
    eligible-pool size — the two claims table T's narrative turns on."""
    n, beta = 128, 0.10
    f = f_of(n)
    # (1) boost off -> the mean-field natural foothold (Binomial mean), not the
    # runaway. A loose band: the sim's realized foothold tracks Binomial(b,beta).
    off = sim_resample_boost(n, beta, 16, 0.5, True, 64, 12000, 901, boost=False)
    if not 1.0 <= off["mean_T"] <= 2.5:   # Binomial(16, 0.10) mean 1.6
        raise AssertionError(f"boost-off foothold off-model: {off['mean_T']:.2f}")
    # (2) jail-on-first at the real eligible pool does NOT cap below f+1.
    on = sim_resample_boost(n, beta, 16, 1.0, True, 64, 12000, 902)
    if on["final_c"] < f + 1:
        raise AssertionError(
            f"jail-on-first unexpectedly capped below f+1 at eligible=all "
            f"(c_T={on['final_c']}) — re-check the boost model")
    # a small eligible pool WOULD let the drain collapse it (the mechanism).
    small = sim_resample_boost(n, beta, 20, 0.5, True, 64, 12000, 903, eligible=800)
    if small["max_c"] >= f + 1:
        raise AssertionError(
            f"small-pool boost not collapsed (max_c={small['max_c']})")
    # the full prevention stack (recency + jail + FIFO) holds the design-point
    # shard well below the terminal 2f+1 line, where the no-recency stack is thin.
    full = sim_recency(n, beta, 16, 12000, 904)
    if full["max_c"] >= 2 * f_of(n) + 1:
        raise AssertionError(
            f"full stack reached 2f+1 at design point (max_c={full['max_c']})")


# ── The recency-weighted resample: capping the boost by service rate ─────────
# The boost sustains a high foothold by re-seating corrupt every epoch; the
# withholding penalty could not drain the network-wide eligible pool. A recency
# weight instead caps the SERVICE RATE: weight 0 right after serving, recovering
# additively (+1/cooldown per epoch) to 1 over cooldown = eligible/b epochs. So
# each corrupt seat depletes its own weight, pinning the SUSTAINED foothold near
# natural (beta*b) — a rate limit the huge supply does not defeat. Stacked
# additively with jail-on-first (which plugs the ramp leak when its cooldown
# matches the recency period) and FIFO shard eviction (which stops bursts from
# accumulating), it holds the target shard's sustained corrupt below the terminal
# 2f+1 line and pushes the first 2f+1 crossing from beta~0.12 to ~0.14. Mean
# field over recency buckets (exact depletion feedback). The ramp sharpness and
# jail-cooldown coupling are tuning knobs — a sharper ramp caps tighter but
# makes the committee more predictable (the §4 trade).

def sim_recency(n, beta, b, epochs, seed, shards=100, jail=True, jail_cd=None,
                omit_frac=0.5, with_fifo=True):
    """Full prevention stack: recency-weighted resample + jail-on-first + FIFO.
    Returns the sustained foothold, the burst peak, and the target shard's
    corrupt equilibrium/peak — the margin below the terminal 2f+1 line."""
    from random import Random

    rng = Random(seed)
    E = shards * n
    cooldown = max(1, E // b)                 # additive recovery period
    jail_cd = cooldown if jail_cd is None else jail_cd
    Cn = round(beta * E)
    Hn = E - Cn
    jail_ring = [0] * max(jail_cd, 1)
    W = [min(1.0, s / cooldown) for s in range(cooldown + 1)]   # additive ramp
    corr = [0] * (cooldown + 1); corr[cooldown] = Cn
    hon = [0] * (cooldown + 1); hon[cooldown] = Hn

    committee = [False] * n
    for i in rng.sample(range(n), round(beta * n)):
        committee[i] = True
    c = sum(committee)
    w_prev, sum_T, peak_T, max_c = 1, 0.0, 0, c

    for t in range(epochs):
        due = jail_ring[t % len(jail_ring)] if jail else 0
        if jail:
            jail_ring[t % len(jail_ring)] = 0
        # age one epoch (shift toward the fully-cooled absorbing bucket)
        corr[cooldown] += corr[cooldown - 1]
        hon[cooldown] += hon[cooldown - 1]
        for s in range(cooldown - 1, 0, -1):
            corr[s] = corr[s - 1]
            hon[s] = hon[s - 1]
        corr[0] = hon[0] = 0
        corr[min(jail_cd, cooldown)] += due   # jailed return at their true recency

        Wc = sum(corr[s] * W[s] for s in range(cooldown + 1))
        Wh = sum(hon[s] * W[s] for s in range(cooldown + 1))
        p = Wc / (Wc + Wh) if (Wc + Wh) > 0 else 0.0

        T = _sample_best_of(rng, min(w_prev, _WIDTH_CAP), b, p)
        T = min(T, b, sum(corr))
        # seat T corrupt (highest weight first) + b-T honest; reset to bucket 0
        for pool, need in ((corr, T), (hon, b - T)):
            for s in range(cooldown, -1, -1):
                if need <= 0:
                    break
                take = min(pool[s], need)
                pool[s] -= take
                pool[0] += take
                need -= take
        if jail and T > 0:                    # omitters withhold to grind -> jail
            s_omit = min(round(omit_frac * T), corr[0])
            corr[0] -= s_omit
            jail_ring[(t + jail_cd) % len(jail_ring)] += s_omit

        w_prev = 1 << min(T, 60)
        sum_T += T
        peak_T = max(peak_T, T)
        if t % SHUFFLE_INTERVAL_EPOCHS == 0:
            if with_fifo:
                committee.pop(0)
            else:
                committee.pop(next((i for i, v in enumerate(committee) if not v), 0))
            committee.append(rng.random() < 1 - (1 - beta) ** min(w_prev, _WIDTH_CAP))
            c = sum(committee)
            max_c = max(max_c, c)
    return {"steady_T": sum_T / epochs, "peak_T": peak_T,
            "final_c": c, "max_c": max_c}


# ── The epoch seed: the witness-reveal fold (tables W — §10.2–§10.3) ─────
#
# Every shard block carries a mandatory reveal leaf — a deterministic
# per-proposer VRF over (shard, height), unchooseable and unforgeable —
# appended to the beacon-witness accumulator, and the epoch seed folds each
# shard's watermark-to-boundary leaf range. The include/omit lever is
# structurally gone (the folded set is a consensus-derived range, not a
# per-member choice) and interior leaves are committed before later leaves
# exist, so interior choices are blind without any network assumption. What
# remains is the WINDOW EDGE: the proposers who close the last epoch windows
# to settle can (a) rush or sandbag the boundary within the ~32s timestamp
# validity window, choosing among a handful of KNOWN candidate folds, or (b)
# forfeit the slot for a blind redraw by an unknown successor. The model
# prices exactly that edge.


def witness_edge_p_event(beta, p, sight=1.0, edge_windows=2, run_cap=16):
    """Per-event grind success of the witness-reveal fold, against a target
    predicate with single-seed success `p`.

    Only the last epoch windows still open when the rest of the fold has
    settled carry a sighted choice; `edge_windows` = m is how many windows an
    adversary can stretch into that position (the ~32s timestamp wiggle lets
    it hold a cut open briefly, so m is small — 1-4). Each of the m cut slots
    is adversary-held w.p. `beta` (placement is a random draw; slots cannot be
    concentrated) and sighted w.p. `sight` (1.0 grants a zero-latency
    full-sight network — the structural worst case; the scheme is priced to
    stand even there). A held, sighted slot yields cbar = 2 + E[run]
    candidates: close-at-me plus one sandbag step per consecutive corrupt
    successor (run ~ Geometric(beta), clamped by the timestamp window to
    `run_cap`), plus one blind forfeit counted as a full extra draw
    (conservative — it lands at base rate, and the count also absorbs the
    sibling-certificate and backlog-shift wiggles, which substitute for
    rather than multiply the close-position choice). j held slots compound:
    menu = cbar^j. So

        p_event = E_{j ~ Bin(m, beta*sight)} [ 1 - (1-p)^(cbar^j) ].

    Structurally this is the reveals-only formula with the always-present
    beacon committee b replaced by the m cut-racing slots held only
    beta-fractionally: the expected width exponent falls from beta*b to
    beta*m."""
    run = sum((beta ** k) * (1.0 - beta) * k for k in range(run_cap))
    run += (1.0 - sum((beta ** k) * (1.0 - beta) for k in range(run_cap))) * run_cap
    cbar = 2.0 + run
    q = beta * sight
    p_event = 0.0
    for j in range(edge_windows + 1):
        pj = comb(edge_windows, j) * (q ** j) * ((1.0 - q) ** (edge_windows - j))
        p_event += pj * (1.0 - (1.0 - p) ** (cbar ** j))
    return p_event


def reveal_ceremony_p_event(beta, p, beacon_size=16):
    """Per-event grind of the fallback reveal ceremony: t ~ beta*b committee
    members toggle their own reveals with full sight of the fold — a clean
    best-of-2^t. This is the NATURAL-foothold width; the coupled resample
    boost lifts realized t further (table T), so it is a floor for the
    baseline, making the comparison conservative."""
    return 1.0 - (1.0 - p) ** (2 ** round(beta * beacon_size))


def witness_march_days(n, beta, sight=1.0, edge_windows=2,
                       interval=SHUFFLE_INTERVAL_EPOCHS):
    """Days to march one targeted shard from beta*n to f+1 under the
    witness-reveal fold — grind_shard_march_days with each step's best-of-2^t
    replaced by the edge residual. Retains that model's monotone-hold grant
    (no-gain events never lose seats), which the witness fold does NOT give
    the adversary — unsighted epochs are natural mean-reverting rotations —
    so this is a strict upper bound on the march speed."""
    f = f_of(n)
    c = round(beta * n)
    intervals = 0.0
    while c < f + 1:
        p_gain = ((n - c) / n) * beta
        pe = witness_edge_p_event(beta, p_gain, sight, edge_windows)
        if pe <= 0.0:
            return float("inf")
        intervals += 1 / pe
        c += 1
    return intervals * interval * EPOCH_SECONDS / 86400


def witness_network_equilibrium(n, beta, shards, pool_factor, sight=1.0,
                                edge_windows=2):
    """grind_network_equilibrium with the seat rate 1-(1-x)^width replaced by
    the witness edge residual at pool fraction x (mean-field: cut-slot
    holding, successor runs, and the entrant draw all read x). Returns
    (c_T, x)."""
    pool = round(pool_factor * n)
    total = shards * n + pool
    corrupt = beta * total
    rest = (shards - 1) * n + pool
    lo, hi = 0.0, beta
    for _ in range(200):
        x = 0.5 * (lo + hi)
        seat = witness_edge_p_event(x, x, sight, edge_windows)
        if n * seat + x * rest - corrupt > 0:
            hi = x
        else:
            lo = x
    x = 0.5 * (lo + hi)
    return n * witness_edge_p_event(x, x, sight, edge_windows), x


# ── The weighted-timestamp cutoff variant ────────────────────────────────
#
# Anchor the fold's upper edge to a FIXED schedule line T_cut = epoch_boundary
# - Δ (Δ >= MAX_TIMESTAMP_DELAY) instead of the boundary block's own leaf count.
# A leaf enters iff its 2f+1-aggregated block weighted timestamp is <= T_cut.
# No proposer can shift a block's WT more than MAX_TIMESTAMP_RUSH early /
# MAX_TIMESTAMP_DELAY late, and the aggregate damps even that to a corrupt-
# weight fraction, so every leaf whose honest WT sits outside the drag band
# around T_cut is PROVABLY in or out — the fold's bulk is pinned by the
# timestamp-validity constants, not chosen. Two gains over the boundary edge:
# (1) the line is fixed, so the single-proposer slide of chunk_end (its own
# leaf count) is gone; (2) the residual is a CEILING independent of sight — the
# adversary can see the whole chain and still not reach the pinned bulk.
MAX_TIMESTAMP_DELAY_S = 30   # crates/types/src/time/limits.rs
MAX_TIMESTAMP_RUSH_S = 2     # crates/types/src/time/limits.rs


def wt_band_seconds(beta):
    """Width (in weighted-timestamp seconds) of the contestable band around the
    fixed cutoff line. A block WT is a 2f+1 aggregate; corrupt weight beta drags
    it by at most beta*MAX_TIMESTAMP_DELAY late / beta*MAX_TIMESTAMP_RUSH early
    (mean-field beyond-f drag, G-1), so only leaves whose honest WT lands within
    that band of T_cut can be flipped across it."""
    return beta * (MAX_TIMESTAMP_DELAY_S + MAX_TIMESTAMP_RUSH_S)


def wt_pinned_fraction(beta, epoch_seconds=EPOCH_SECONDS):
    """Fraction of an epoch's reveals that fall OUTSIDE the drag band — provably
    un-contestable, sealed by the timestamp-validity constants regardless of how
    much the adversary sees. Reveals are ~uniform in time, so this is
    1 - band/epoch."""
    return max(0.0, 1.0 - wt_band_seconds(beta) / epoch_seconds)


def wt_edge_p_event(beta, p):
    """Per-event grind of the WT-cutoff variant: a beta-gated best-of-2. The
    band holds several leaves, but the adversary proposes them sequentially and
    each commits before the next, so it is sighted only over the single last
    leaf it controls at the seal — best-of-2 (its own leaf in or out, or forfeit
    for a blind redraw). beta = it holds that sealing slot; the aggregate drag
    succeeds w.p. ~1 at these Delta (30 s >> block spacing), so it is not
    credited as extra protection. This is a CEILING: independent of sight,
    because the pinned bulk is unreachable — where the boundary edge grows with
    the number of cut-racing windows m, this does not."""
    return (1.0 - beta) * p + beta * (1.0 - (1.0 - p) ** 2)


def wt_march_days(n, beta, interval=SHUFFLE_INTERVAL_EPOCHS):
    """Days to march one shard to f+1 under the WT-cutoff residual — the
    grind_shard_march_days skeleton with the beta-gated best-of-2 per step."""
    f = f_of(n)
    c = round(beta * n)
    intervals = 0.0
    while c < f + 1:
        pe = wt_edge_p_event(beta, ((n - c) / n) * beta)
        if pe <= 0.0:
            return float("inf")
        intervals += 1 / pe
        c += 1
    return intervals * interval * EPOCH_SECONDS / 86400


def check_witness_edge() -> None:
    """Analytic limits + dominance for the witness-edge model."""
    # WT-cutoff variant: beta=0 -> base rate; a sight-independent ceiling at or
    # below the boundary edge (m=1) for every design point; pins ~all the fold.
    for p in (0.02, 0.10, 0.30):
        if abs(wt_edge_p_event(0.0, p) - p) > 1e-12:
            raise AssertionError("wt edge beta=0 != base rate")
    for beta in (0.05, 0.10, 0.15, 0.20, 0.25):
        for p in (0.02, 0.05, 0.10, 0.20, 0.30):
            wt = wt_edge_p_event(beta, p)
            if wt > witness_edge_p_event(beta, p, 1.0, 1) + 1e-12:
                raise AssertionError("wt edge above the boundary edge (m=1)")
            if wt >= reveal_ceremony_p_event(beta, p):
                raise AssertionError("wt edge not dominant vs the ceremony")
        if wt_pinned_fraction(beta) < 0.9:
            raise AssertionError("wt pinned fraction below 0.9 in the design band")
    # beta=0 and sight=0 both collapse to the base rate exactly.
    for p in (0.02, 0.10, 0.30):
        if abs(witness_edge_p_event(0.0, p) - p) > 1e-12:
            raise AssertionError("witness edge beta=0 != base rate")
        if abs(witness_edge_p_event(0.10, p, sight=0.0) - p) > 1e-12:
            raise AssertionError("witness edge sight=0 != base rate")
    # Closed form at m=1, run_cap forced degenerate: one held slot, no run —
    # keep-or-blind-redraw is best-of-2 on the held branch.
    p, beta = 0.10, 0.10
    direct = (1 - beta) * p + beta * (1.0 - (1.0 - p) ** 2)
    if abs(witness_edge_p_event(beta, p, 1.0, 1, 0) - direct) > 1e-12:
        raise AssertionError("witness edge m=1 closed form mismatch")
    # Monotone in beta, sight, and edge_windows.
    grid = [0.02, 0.05, 0.10, 0.15, 0.20, 0.25]
    for lo, hi in zip(grid, grid[1:]):
        if witness_edge_p_event(hi, 0.1) < witness_edge_p_event(lo, 0.1):
            raise AssertionError("witness edge not monotone in beta")
    for s_lo, s_hi in ((0.0, 0.5), (0.5, 1.0)):
        if (witness_edge_p_event(0.1, 0.1, s_hi)
                < witness_edge_p_event(0.1, 0.1, s_lo)):
            raise AssertionError("witness edge not monotone in sight")
    for m in (1, 2, 3):
        if (witness_edge_p_event(0.1, 0.1, 1.0, m + 1)
                < witness_edge_p_event(0.1, 0.1, 1.0, m)):
            raise AssertionError("witness edge not monotone in edge_windows")
    # Truncation insensitivity: the geometric run clamp is not load-bearing.
    if abs(witness_edge_p_event(0.2, 0.1, 1.0, 2, 8)
           - witness_edge_p_event(0.2, 0.1, 1.0, 2, 64)) > 1e-6:
        raise AssertionError("witness edge sensitive to run_cap")
    # Dominance: strictly below the reveals-only ceremony across the design
    # band, even granting the adversary full sight and four edge windows.
    for beta in (0.05, 0.10, 0.15, 0.20, 0.25):
        for p in (0.02, 0.05, 0.10, 0.20, 0.30):
            for m in (1, 2, 4):
                if (witness_edge_p_event(beta, p, 1.0, m)
                        >= reveal_ceremony_p_event(beta, p)):
                    raise AssertionError(
                        f"witness edge not dominant at beta={beta} p={p} m={m}")


def fmt(x: float) -> str:
    if x == 0.0:
        return "   ~0    "
    if x >= 1000:
        return f" >1e3    "
    if x >= 0.01:
        return f" {x:8.3f}"
    return f" {x:8.1e}"


def table(title: str, row_hdr: str, rows, cols, cell) -> None:
    print(f"\n{title}")
    print(f"  {row_hdr:>6} | " + " ".join(f"beta={b:<4}" for b in cols))
    print("  " + "-" * (9 + 10 * len(cols)))
    for r in rows:
        print(f"  {r:>6} | " + " ".join(fmt(cell(r, b)) for b in cols))


def main() -> None:
    for n in N_SWEEP:
        check_detailed_balance(POOL_FACTOR * n, int(POOL_FACTOR * n * 0.25), n)
    check_grind_network()
    check_resample_boost()
    check_witness_edge()

    # A: per-draw failure probability (genesis, split cohorts, merge keepers)
    table(
        "A. Single-draw failure P[k >= f+1]  (fresh committee draw)",
        "n",
        N_SWEEP,
        BETA_SWEEP,
        lambda n, b: hyper_tail(POOL_FACTOR * n, round(POOL_FACTOR * n * b), n, f_of(n) + 1),
    )

    # B: trickle-shuffle boundary crossings per shard-year
    table(
        f"B. Expected compromises per shard-year under the trickle shuffle\n"
        f"   ({EPOCH_SECONDS}s epochs, shuffle every {SHUFFLE_INTERVAL_EPOCHS} epochs "
        f"=> {SHUFFLE_EVENTS_PER_SHARD_YEAR:,.0f} events/shard-year)",
        "n",
        N_SWEEP,
        BETA_SWEEP,
        lambda n, b: SHUFFLE_EVENTS_PER_SHARD_YEAR
        * crossing_rate(POOL_FACTOR * n, round(POOL_FACTOR * n * b), n),
    )

    # C: trickle advantage over per-event independent redraws
    table(
        "C. Trickle advantage factor (independent-redraw failures / trickle crossings)",
        "n",
        N_SWEEP,
        BETA_SWEEP,
        lambda n, b: (
            hyper_tail(POOL_FACTOR * n, round(POOL_FACTOR * n * b), n, f_of(n) + 1)
            / max(crossing_rate(POOL_FACTOR * n, round(POOL_FACTOR * n * b), n), 1e-300)
        ),
    )

    # D1: smallest candidate size meeting a per-shard-year budget
    print("\nD1. Smallest candidate n for compromises/shard-year under budget")
    print("    budget   | " + " ".join(f"beta={b:<4}" for b in BETA_SWEEP))
    print("  " + "-" * (12 + 10 * len(BETA_SWEEP)))
    for budget in (1e-3, 1e-6, 1e-9):
        cells = []
        for b in BETA_SWEEP:
            found = "    -    "
            for n in CANDIDATES:
                rate = SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(
                    POOL_FACTOR * n, round(POOL_FACTOR * n * b), n
                )
                if rate <= budget:
                    found = f" {n:>6}  "
                    break
            cells.append(found)
        print(f"    {budget:8.0e} |" + " ".join(cells))

    # D2: the inversion the size cap forces — max tolerable pool corruption
    # per candidate size. This is the actionable number: n is capped, so the
    # budget converts into a pool-hygiene requirement.
    print("\nD2. Max tolerable pool corruption beta for each candidate n")
    print("    budget   | " + " ".join(f"n={n:<6}" for n in CANDIDATES))
    print("  " + "-" * (12 + 9 * len(CANDIDATES)))
    for budget in (1e-3, 1e-6, 1e-9):
        cells = []
        for n in CANDIDATES:
            N = POOL_FACTOR * n
            best = 0
            for M in range(0, N // 2):
                rate = SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(N, M, n)
                if rate > budget:
                    break
                best = M
            cells.append(f" {best / N:7.3f}")
        print(f"    {budget:8.0e} |" + " ".join(cells))

    # E: adaptive adversary — targeted corruption vs rotation flushing.
    # Corruption of a seated member takes tau epochs to land and lands only
    # if the target is still seated; landed corruption persists for the
    # member's residual tenure (~n * I epochs). Little's law gives the
    # equilibrium landed count; the budget is the slack f - beta*n.
    print("\nE. Max sustainable targeted corruptions/epoch against one shard")
    print("   (r_max = (f - beta*n) / (survival(tau) * n * I);  I = "
          f"{SHUFFLE_INTERVAL_EPOCHS} epochs)")
    beta = 0.10
    taus = [16, 160, 1600, 16000]
    print(f"   beta={beta}:  n  | " + " ".join(f"tau={t:<6}" for t in taus))
    print("  " + "-" * 60)
    for n in [32, 128, 256]:
        f = f_of(n)
        cells = []
        for tau in taus:
            surv = (1 - 1 / n) ** (tau / SHUFFLE_INTERVAL_EPOCHS)
            slack = f - beta * n
            r = slack / (surv * n * SHUFFLE_INTERVAL_EPOCHS) if surv > 0 else float("inf")
            cells.append(fmt(r))
        print(f"        {n:>6} | " + " ".join(cells))

    # F: seat fraction vs stake fraction (the overstake wedge)
    print("\nF. Stake share an adversary needs for seat share beta_s, when the")
    print("   average honest seat stakes c * min_stake (adversary always at 1x)")
    print("   beta_s | " + " ".join(f"c={c:<4}" for c in [1, 2, 5]))
    print("  " + "-" * 30)
    for bs in [0.10, 0.20, 0.3333]:
        row = " ".join(f"{bs / (bs + (1 - bs) * c):6.3f}" for c in [1, 2, 5])
        print(f"   {bs:5.2f}  | " + row)
    print("\n   Attack cost floor: seats * MIN_STAKE_FLOOR (1e6 tokens/seat);")
    print("   honest overstake (c > 1) proportionally DISCOUNTS the attacker's")
    print("   required stake share — vnodes exist to keep c near 1.")

    # H: shuffle-interval sweep at n=128 — rotation speed trades static
    # security (linear: more events/yr) for adaptive resistance (exponential:
    # survival = (1-1/n)^(tau/I)). One seat per event throughout; batching k
    # seats is rejected in the note (ready-margin dips, INV-SEC-2 rewrite,
    # jump-chain re-derivation).
    n = 128
    N = POOL_FACTOR * n
    f = f_of(n)
    tau = 1600
    print("\nH. Shuffle-interval sweep at n=128 (one seat per I epochs; "
          f"tau={tau} epochs = {tau * EPOCH_SECONDS / 86400:.1f} days, "
          "beta=0.10 for r_max)")
    print("    I  | tenure(h) | cross/shard-yr b=0.10 | max beta @1e-6 | r_max/epoch")
    print("  " + "-" * 74)
    for interval in [16, 8, 4, 2, 1]:
        events = EPOCHS_PER_YEAR / interval
        tenure_h = n * interval * EPOCH_SECONDS / 3600
        r10 = events * crossing_rate(N, round(N * 0.10), n)
        best = 0
        for M in range(0, N // 2):
            if events * crossing_rate(N, M, n) > 1e-6:
                break
            best = M
        surv = (1 - 1 / n) ** (tau / interval)
        rmax = (f - 0.10 * n) / (surv * n * interval) if surv > 1e-300 else float("inf")
        rm = f"{rmax:11.3g}" if rmax < 1e6 else "  flushed  "
        print(f"    {interval:2d} | {tenure_h:8.1f}  |       {r10:9.2e}       "
              f"|     {best / N:5.3f}      | {rm}")

    # G: operating-point profile for n=128 (fine beta sweep around the cliff)
    n = 128
    N = POOL_FACTOR * n
    f = f_of(n)
    shards = 100
    print(f"\nG. Operating point n=128: f={f}, quorum={2 * f + 1}, "
          f"turnover {n * SHUFFLE_INTERVAL_EPOCHS} epochs "
          f"({n * SHUFFLE_INTERVAL_EPOCHS * EPOCH_SECONDS / 3600:.1f}h at "
          f"{EPOCH_SECONDS}s epochs)")
    print(f"    beta   | per-shard-yr | {shards}-shard network")
    print("  " + "-" * 50)
    for beta in [0.08, 0.10, 0.11, 0.12, 0.122, 0.13, 0.14, 0.15]:
        rate = SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(N, round(N * beta), n)
        net = rate * shards
        right = f"1 per {1 / net:,.0f} yr" if net < 1 else f"{net:.2f} / yr"
        print(f"    {beta:5.3f}  |   {rate:8.2e}   | {right}")

    # I: the beacon committee's per-epoch resample — the independent-redraw
    # column of C made real (one committee network-wide, redrawn every epoch
    # from the seated-ready eligible set, ~shards * n at full staffing).
    # Epoch-commit safety rides the pool ratification quorum (INV-BEACON-1),
    # so an over-threshold draw here prices liveness and randomness-bias
    # exposure, not a fork.
    shards = 100
    print(f"\nI. Beacon committee: fresh draw every epoch "
          f"({EPOCHS_PER_YEAR:,.0f} draws/year; eligible = {shards} shards x n)")
    print("    n      | " + " ".join(f"beta={b:<4}" for b in BETA_SWEEP)
          + " | max beta @1e-6/yr")
    print("  " + "-" * (11 + 10 * len(BETA_SWEEP) + 20))
    for n in CANDIDATES:
        N = shards * n
        f = f_of(n)
        cells = [
            fmt(EPOCHS_PER_YEAR * hyper_tail(N, round(N * b), n, f + 1))
            for b in BETA_SWEEP
        ]
        best = 0
        for M in range(0, N // 2):
            if EPOCHS_PER_YEAR * hyper_tail(N, M, n, f + 1) > 1e-6:
                break
            best = M
        print(f"    {n:>6} | " + " ".join(cells) + f" |      {best / N:5.3f}")

    # L: corruption cost for an adversary whose unit is coarser than a seat
    # — a hacked machine or a bribed controlling entity, each flipping every
    # seat it holds at once. Conditional on M corrupt seats every table above
    # is unchanged (exchangeability — an M-subset is an M-subset), but
    # concentration collapses the units-to-subvert count. The protocol cannot
    # see or bound this: distinct stake-pool identities are indistinguishable
    # from distinct entities (the Sybil limit that makes stake, not identity,
    # the gate), so no per-identity cap binds it. Largest-first subversion
    # over three concentration profiles of one pool (N = 20 * 128 seats).
    N = POOL_FACTOR * 128
    profiles = [
        ("uniform (1 seat/entity)", [1] * N),
        ("10 seats/entity", [10] * (N // 10)),
        ("zipf, 256 entities", None),
    ]
    j_ops = 256
    harmonic = sum(1 / j for j in range(1, j_ops + 1))
    zipf = [max(1, round(N / harmonic / j)) for j in range(1, j_ops + 1)]
    profiles[2] = ("zipf, 256 entities", zipf)
    targets = [0.05, 0.10, 0.131]
    print("\nL. Units to subvert (largest-first) to reach a corrupt seat share")
    print("   (a hacked machine or bribed entity; the protocol cannot bound "
          "concentration)")
    print("   profile                 | " + " ".join(f"beta_s={t:<5}" for t in targets))
    print("  " + "-" * 60)
    for label, sizes in profiles:
        sizes = sorted(sizes, reverse=True)
        cells = []
        for t in targets:
            need = t * N
            acc = 0
            ops = 0
            for s in sizes:
                if acc >= need:
                    break
                acc += s
                ops += 1
            cells.append(f"  {ops if acc >= need else '-':>6}    ")
        print(f"   {label:<23} | " + " ".join(cells))
    top = sorted(zipf, reverse=True)
    print(f"   (zipf top entity holds {top[0] / N:.1%} of seats, "
          f"top 10 hold {sum(top[:10]) / N:.1%})")

    # J: sustained targeted pressure vs rotation, computed exactly on the
    # event chain — replaces the r_max heuristic of the note's §4. The
    # adversary holds `pressure` concurrent attempts (tau epochs each)
    # against one shard committee; the table gives P[compromise within a
    # 90-day campaign] and the sustained launch cost.
    n = 128
    beta = 0.10
    horizon_days = 90
    print(f"\nJ. n={n}, beta={beta}: P[compromise within {horizon_days} days] "
          "under sustained targeted pressure")
    print("    tau (epochs) | I  | pressure=16      32        64        85")
    print("  " + "-" * 66)
    for tau in (160, 1600):
        for interval in (16, 8, 4, 2):
            events = round(horizon_days * 86400 / (EPOCH_SECONDS * interval))
            cells = []
            cost = None
            for pressure in (16, 32, 64, 85):
                p, launches_day = compromise_probability(
                    n, beta, interval, tau, pressure, events
                )
                cells.append(fmt(p))
                cost = launches_day
            print(f"    {tau:>12} | {interval:>2} | " + " ".join(cells)
                  + f"   ({cost:.1f} launches/day at 85)")

    # K: does a budget-constrained adversary gain from adapting? Exact
    # backward induction over (k, in-flight, budget) on a small instance,
    # the optimal state-dependent policy vs blind launch-maximum. The gap
    # is the value of adaptivity; the policy row shows its mechanism.
    n, beta, interval, tau = 32, 0.10, 16, 1600
    budget, max_in_flight = 16, 8
    events = round(15 * 86400 / (EPOCH_SECONDS * interval))
    opt, policy = adversary_value_iteration(
        n, beta, interval, tau, budget, max_in_flight, events,
        greedy_only=False, want_policy=True,
    )
    greedy = adversary_value_iteration(
        n, beta, interval, tau, budget, max_in_flight, events, greedy_only=True
    )
    f = f_of(n)
    print(f"\nK. Optimal-vs-greedy budget-limited adversary (n={n}, f={f}, "
          f"I={interval}, tau={tau}, budget={budget}, in-flight cap "
          f"{max_in_flight}, 15-day horizon)")
    print(f"    optimal (state-dependent): P[compromise] = {opt:.5f}")
    print(f"    launch-maximum:            P[compromise] = {greedy:.5f}")
    print(f"    adaptivity gain: {opt - greedy:.2e}  ({opt / greedy:.1f}x) — "
          "adapting beats blind spending")
    row = " ".join(f"{policy[k]}" for k in range(f + 1))
    print(f"    t=0 optimal launches by k (0..f={f}, full budget): {row}")
    print("    conserve-then-spend: budget is held until a lucky rotation "
          "lifts k toward the boundary")

    # M: the fallback ceremony grind — best-of-2^t steering of the trickle
    # shuffle marches a TARGETED shard from beta*n to f+1 corrupt (and, at
    # ~2.5x the time, to the terminal 2f+1). t's natural mean is beta*b
    # (~1.6 at b=16); the resample boost lifts it to ~3-4 (table T) — exactly
    # the materiality band.
    n = 128
    beta = 0.10
    f = f_of(n)
    c0 = round(beta * n)
    floor_days = (f + 1 - c0) * SHUFFLE_INTERVAL_EPOCHS * EPOCH_SECONDS / 86400
    print(f"\nM. Fallback ceremony grind: days to march one targeted shard "
          f"from beta*n={c0} to f+1={f + 1} corrupt")
    print(f"   (n={n}, beta={beta}, shuffle every {SHUFFLE_INTERVAL_EPOCHS} "
          f"epochs; best-of-2^t steering of the ceremony mix)")
    print("    grind t | candidate seeds 2^t | days to fork the shard")
    print("  " + "-" * 56)
    for t in (1, 2, 3, 4, 6, 8, 13):
        print(f"    {t:>7} | {2 ** t:>19} | {grind_shard_march_days(n, beta, t):>10.1f}")
    print(f"   (deterministic floor as 2^t*p_gain >> 1: {floor_days:.1f} days; "
          "materiality threshold t ~ 3-4)")

    # Operating-point levers: the march counts shuffle EVENTS and flips f+1-c0
    # SEATS, so days-to-fork are linear in both the shuffle interval and the
    # committee size. Both trade grind resistance against their other costs
    # (I: adaptive-corruption flush, §6 Rider 1; n: message complexity, §6).
    # The ceremony width cannot be capped at the input (§10.5); for f+1 that
    # is moot (detect-and-rotate recovers, §10.6), but for the TERMINAL 2f+1
    # the fallback-path defense is prevention, not recovery (§10.1).
    print("   Cheap levers (t=4, days to fork one shard):")
    intervals = (2, 4, 8, 16, 32, 64)
    print("    shuffle interval I | "
          + " ".join(f"{i:>5}" for i in intervals) + "   (n=128)")
    print("                       | "
          + " ".join(f"{grind_shard_march_days(n, beta, 4, i):>5.1f}" for i in intervals))
    sizes = (64, 96, 128, 192, 256)
    print("    committee size n   | "
          + " ".join(f"{s:>5}" for s in sizes) + "   (I=16)")
    print("                       | "
          + " ".join(f"{grind_shard_march_days(s, beta, 4):>5.1f}" for s in sizes))
    print("   (a fallback-path march at I=2 runs ~8x the I=16 march — the "
          "residual caution §6 Rider 1")
    print("    weighs against adaptive corruption. n is capped at 128 by "
          "message complexity.)")

    # N: the beacon resample under the same grind — best-of-2^t amplification
    # of the per-epoch redraw tail, at a shard-sized beacon committee (the
    # bounding case; b=16's per-draw rate is table T's last column). Not the
    # sharp target (safety rides pool ratification), so this prices liveness
    # + bias exposure, not a fork.
    shards = 100
    N_elig = shards * n
    p_single = hyper_tail(N_elig, round(N_elig * beta), n, f + 1)
    print(f"\nN. Randomness grind: beacon resample tail under best-of-2^t "
          f"(eligible={N_elig}, single-draw P[>=f+1]={p_single:.2e})")
    print("    grind t | candidate seeds 2^t | amplified P[>=f+1]/network-year")
    print("  " + "-" * 60)
    for t in (0, 2, 4, 6, 8, 10, 13):
        print(f"    {t:>7} | {2 ** t:>19} | {grind_resample_year(n, beta, t):>18.2e}")
    print("   (epoch-commit safety rides pool ratification INV-BEACON-1; "
          "prices liveness + bias, not a fork)")

    # R: the network-wide grind under all-shard FIFO eviction. The single-shard
    # march (table M) ignores the finite shared pool; conserving corrupt and
    # letting every shard shuffle from one pool turns the target into a stable
    # equilibrium. FIFO caps it below f+1 for low beta; a victim-grind eviction
    # rule forks whenever supply permits. Width 2^t at the unconstrained
    # foothold t=round(beta*n) — the no-width-lever worst case; table T carries
    # the realized b=16 width.
    n = 128
    f = f_of(n)
    print(f"\nR. Network-wide grind under all-shard FIFO eviction (finite shared "
          f"pool, n={n}, f+1={f + 1})")
    print("   Target-shard corrupt equilibrium c_T by shard count and beta "
          "(grind width 2^t, t=round(beta*n)):")
    betas = (0.02, 0.025, 0.03, 0.04, 0.05, 0.10)
    print("    shards | " + " ".join(f"b={b:<5}" for b in betas))
    print("  " + "-" * (9 + 8 * len(betas)))
    for shards in (4, 10, 25, 100, 1000):
        cells = []
        for b in betas:
            t = max(1, round(b * n))
            r = grind_network_regime(n, b, shards, NET_POOL_FACTOR, 2 ** t)
            cells.append("flr" if r == "floor" else ("FORK" if r == "fork" else f"{r:.0f}"))
        print(f"    {shards:>6} | " + " ".join(f"{c:>7}" for c in cells))
    print("   (flr = supply floor M<=f, can't seat f+1; number = FIFO-capped "
          "c_T < f+1; FORK = c_T>=f+1)")

    # The closed band each scheme buys, on a large network (supply ample, so the
    # difference is the DYNAMICS, not the floor). Current forks whenever M>f;
    # FIFO caps at width 2^t; FIFO+strikes caps at the strike-limited width t+1.
    shards = 100
    print(f"\n   Fork verdict on a {shards}-shard network — what each eviction "
          "rule closes:")
    print("    beta  | victim-grind (no FIFO) | FIFO (width 2^t) | FIFO + strikes (width t+1)")
    print("  " + "-" * 74)
    for b in (0.02, 0.03, 0.04, 0.05, 0.07, 0.10):
        t = max(1, round(b * n))
        m_gt_f = b * (shards * n + NET_POOL_FACTOR * n) > f
        cur = "fork" if m_gt_f else "floor"
        fifo = grind_network_regime(n, b, shards, NET_POOL_FACTOR, 2 ** t)
        strk = grind_network_regime(n, b, shards, NET_POOL_FACTOR, t + 1)
        fifo_s = "FORK" if fifo == "fork" else ("flr" if fifo == "floor" else f"cap {fifo:.0f}")
        strk_s = "FORK" if strk == "fork" else ("flr" if strk == "floor" else f"cap {strk:.0f}")
        print(f"    {b:5.2f} | {cur:>22} | {fifo_s:>16} | {strk_s:>26}")
    print("   (victim-grind forks across the whole band once supply permits; "
          "FIFO closes beta<=~0.025, FIFO+strikes")
    print("    closes beta<=~0.04; neither closes the design point — see "
          "committee_security.md §10.5. Validated")
    print("    against a conserved-population Monte Carlo (check_grind_network).)")

    # V: the TERMINAL boundary priced unsteered — the k = 2f -> 2f+1 crossing
    # on the same chain (§10.1). The f+1 tables above price a RECOVERABLE
    # liveness halt, i.e. availability; the unrecoverable event is 2f+1, and
    # unsteered sampling essentially cannot produce it — its budget lines sit
    # at beta ~ 0.36-0.45, far above pool-hygiene territory (and above the 1/3
    # stake line an unsharded BFT chain fails at). Steering is the only route
    # to 2f+1 at plausible beta (table M's march at ~2.5x the f+1 time), which
    # is what the input-side stack (T) and the reveal-leaf fold (W) defend.
    # Between the two lines the network degrades but stays sound: the f+1
    # column shows halts becoming routine long before the terminal tail opens.
    n = 128
    N = POOL_FACTOR * n
    f = f_of(n)
    terminal = 2 * f + 1
    shards = 100
    print(f"\nV. Terminal boundary at n={n}: unsteered k = {terminal - 1} -> "
          f"{terminal} (= 2f+1) crossings")
    print("    beta   | terminal/shard-yr | 100-shard network | f+1 halts/shard-yr")
    print("  " + "-" * 66)
    for beta in (0.30, 0.35, 0.38, 0.40, 0.42, 0.45):
        M = round(N * beta)
        t_rate = SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(N, M, n, terminal)
        h_rate = SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(N, M, n)
        net = t_rate * shards
        right = f"1 per {1 / net:,.0f} yr" if 0 < net < 1 else f"{net:8.2f} / yr"
        print(f"    {beta:5.3f}  |     {t_rate:8.2e}  | {right:>17} | "
              f"{fmt(h_rate)}")
    print("    budget (terminal/shard-yr) | max beta")
    print("  " + "-" * 40)
    for budget in (1e-3, 1e-6, 1e-9):
        best = 0
        for M in range(0, round(N * 0.6)):
            if SHUFFLE_EVENTS_PER_SHARD_YEAR * crossing_rate(N, M, n, terminal) > budget:
                break
            best = M
        print(f"    {budget:26.0e} | {best / N:8.3f}")
    print("   (two lines, not one: HEALTHY beta <~ 0.13 — the f+1 budget of D2 "
          "holds and halts are")
    print("    negligible; SOUND beta <~ 0.40 — halts and re-draws become "
          "routine above ~0.13, at")
    print(f"    beta=0.40 the stationary mean corrupt count beta*n = "
          f"{0.40 * n:.0f} > f = {f}, but nothing mints)")

    # S: detect-and-rotate recovery for the f+1 LIVENESS halt (the 2f+1 march is
    # terminal, prevention not recovery — §10.1). The f+1 halt is detectable;
    # on a stalled shard boundary the beacon re-draws the WHOLE committee. A full fresh draw
    # is grind-resistant where the trickle is not: reaching f+1 in one
    # hypergeometric draw is a ~1e-13 tail that best-of-2^t barely lifts, versus
    # the trickle where best-of-2^t drives each single-seat STEP to ~1. So the
    # foothold the grind spent days building is flushed the moment it halts.
    n = 128
    f = f_of(n)
    pool = POOL_FACTOR * n
    halt_epochs = 20   # HALT_THRESHOLD placeholder: above RESHAPE_HANDOFF_TTL, tunable
    print(f"\nS. Detect-and-rotate: a full committee re-draw the grind cannot "
          f"steer (n={n}, f+1={f + 1})")
    print("   Grind resistance — P[the recovery re-draw itself seats >= f+1 "
          "corrupt], best-of-2^t:")
    print("    beta  | one fresh draw | best-of-2^t (t=round(beta*n)) | trickle "
          "per-STEP best-of-2^t")
    print("  " + "-" * 76)
    for beta in (0.10, 0.13, 0.15):
        t = round(beta * n)
        single = hyper_tail(pool, round(pool * beta), n, f + 1)
        redraw = 1 - (1 - single) ** (2 ** t)
        c0 = round(beta * n)
        step = 1 - (1 - ((n - c0) / n) * beta) ** (2 ** t)
        print(f"    {beta:5.2f} | {single:>14.1e} | {redraw:>28.1e} | {step:>21.3f}")
    print("   (the re-draw is a single event the grind can't march; the trickle "
          "step is ~certain -> it marches)")
    print("   Attacker duty cycle — days of grinding to f+1, then flushed on the "
          f"halt ({halt_epochs}-epoch window):")
    print("    beta  | march to f+1 | halt window | sustained downtime on ONE shard")
    print("  " + "-" * 70)
    halt_days = halt_epochs * EPOCH_SECONDS / 86400
    for beta in (0.07, 0.10, 0.13):
        march = grind_shard_march_days(n, beta, round(beta * n))
        downtime = halt_days / (march + halt_days)
        print(f"    {beta:5.2f} | {march:>10.1f}d | {halt_days * 24:>8.1f}h | "
              f"{downtime:>28.1%}")
    print("   (continuous grinding buys a few-percent downtime on one shard, "
          "flushed each cycle — this recovers")
    print("    the f+1 LIVENESS halt only; the 2f+1 safety march is terminal and "
          "prevention-only, §10.1.)")

    # T: the small-beacon width cap, tested against the pool it actually draws
    # from (§10.5). grind_width_cap prices the target equilibrium off the
    # NATURAL foothold — the width if jail-on-first fully suppresses the
    # resample boost. The coupled Monte Carlo (sim_resample_boost) plays the boost
    # out against the real eligible pool: the boost SURVIVES jail-on-first at the
    # design point, because the committee redraws from ~shards*n seats and the
    # jail drain cannot deplete that corrupt supply. So the width cap is not a
    # design-point close — it is a bar-raise that closes only the low-beta band.
    n = 128
    f = f_of(n)
    ep = 12000

    def realized_c(beta, b, cd):
        """Worst-of-omit-policy realized target corrupt under jail-on-first."""
        best = None
        for i, phi in enumerate((0.5, 1.0)):
            r = sim_resample_boost(n, beta, b, phi, True, cd, ep, 40 + i + int(beta * 100) + cd)
            if best is None or r["max_c"] > best["max_c"]:
                best = r
        return best

    print(f"\nT. Small-beacon width cap vs the coupled resample boost "
          f"(n={n}, beta=0.10, f+1={f + 1}, 2f+1={2 * f + 1})")
    print("   'assumed cap' = grind_width_cap (boost fully suppressed); "
          "'realized' = coupled sim, jail-on-first cd=64.")
    print("    beacon b | assumed cap c_T | realized c_T (max) | reaches       | "
          "beacon compromise")
    print("  " + "-" * 78)
    for b in (16, 20, 24, 32, 128):
        assumed = grind_width_cap(n, 0.10, b)
        r = realized_c(0.10, b, 64)
        c_t = r["final_c"]
        reaches = ("safety (2f+1)" if r["max_c"] >= 2 * f + 1
                   else "liveness (f+1)" if r["max_c"] >= f + 1 else "CAPPED (neither)")
        print(f"    {b:>8} | {assumed:>15.0f} | {c_t:>8d} ({r['max_c']:>3d})    | "
              f"{reaches:<13} | {beacon_compromise(0.10, b):>10.1e}")
    print("   (the boost survives: realized c_T far exceeds the assumed cap. "
          "b=16 holds the sustained")
    print("    foothold below the TERMINAL 2f+1 line; b=20 reaches it — so b=16 "
          "is non-negotiable.)")

    print("\n   Margin below 2f+1 (TERMINAL) vs beta — where the shard first "
          "crosses the doom line")
    print("   (stack without recency: b + FIFO + jail-on-first, realized c_T (max), "
          "cd=64; 2f+1=85, f+1=43):")
    print("    beta  | b=16 c_T(max) reaches | b=20 c_T(max) reaches")
    print("  " + "-" * 58)

    def reach(r):
        return ("2f+1!" if r["max_c"] >= 2 * f + 1
                else "f+1" if r["max_c"] >= f + 1 else "<f+1")

    for beta in (0.05, 0.07, 0.10, 0.12, 0.13, 0.15):
        r16, r20 = realized_c(beta, 16, 64), realized_c(beta, 20, 64)
        print(f"    {beta:.2f}  | {r16['final_c']:>3d}({r16['max_c']:>3d}) {reach(r16):>6} "
              f"     | {r20['final_c']:>3d}({r20['max_c']:>3d}) {reach(r20):>6}")
    print("   (2f+1 is TERMINAL — no recovery. b=16 holds the shard below it to "
          "beta~0.12, thin against")
    print("    the ~0.13 the sampling budget tolerates; b=20 reaches 2f+1 already "
          "at the design point.")
    print("    Pool hygiene keeping beta low is the primary means of widening the "
          "margin.)")

    print("\n   Full stack (+ recency-weighted resample) — how much it widens the "
          "2f+1 margin (b=16):")
    print("   (recency caps the SUSTAINED foothold near natural beta*b; sim_recency, "
          "sustained T then c_T(max)):")
    print("    beta  | no-recency c_T(max) reaches | full-stack c_T(max) reaches")
    print("  " + "-" * 60)
    for beta in (0.10, 0.12, 0.13, 0.15):
        d = realized_c(beta, 16, 64)
        fu = sim_recency(n, beta, 16, 12000, 400 + int(beta * 100))
        print(f"    {beta:.2f}  | {d['final_c']:>3d}({d['max_c']:>3d}) {reach(d):>6}      "
              f" | {fu['final_c']:>3d}({fu['max_c']:>3d}) {reach(fu):>6}")
    print("   (recency pushes the first 2f+1 crossing from beta~0.12 to ~0.14 — "
          "outside the ~0.13 the budget")
    print("    tolerates — and leaves a wide margin at the design point. As built: "
          "a linear-additive ramp over")
    print("    eligible/b, and the jail-on-first synergy is realized by holding the "
          "withholding jail for a full")
    print("    recency period (jail_cd = cooldown here) — the ramp alone lands at "
          "~0.12; the long jail reaches ~0.14.)")

    print("\n   Jail-on-first honest purge: worst-case ceiling vs realized under "
          "partial synchrony (b=20):")
    print("   (purge_beta_eff assumes EVERY epoch purges f_beacon; realized only "
          "in async windows, sim_async_purge)")
    print("    p_async | realized beta_eff (cd=64 / cd=256) | worst-case ceiling")
    print("  " + "-" * 62)
    wc = f"{purge_beta_eff(n, 0.10, 20, 64):.3f}/{purge_beta_eff(n, 0.10, 20, 256):.3f}"
    for pa in (0.02, 0.05, 0.20):
        a64 = sim_async_purge(n, 0.10, 20, pa, 64, ep, 11 + int(pa * 100))
        a256 = sim_async_purge(n, 0.10, 20, pa, 256, ep, 12 + int(pa * 100))
        print(f"    {pa:.2f}    | {a64['mean_beta_eff']:.4f} / "
              f"{a256['mean_beta_eff']:.4f}                | {wc} (p_async=1)")
    print("   (realized purge is a rounding error — jail-on-first is clean; qc1_certify "
          "makes honest")
    print("    un-excludable outside async windows. It is safe, but for the same "
          "reason too weak to close.)")

    # W: the epoch seed's window-edge residual (§10.3), priced against the
    # fallback ceremony baseline on the SAME march + FIFO-equilibrium
    # machinery, so the comparison is apples to apples.
    n = 128
    f = f_of(n)
    beta = 0.10

    print(f"\nW1. Witness-reveal per-event grind vs the reveal ceremony "
          f"(n={n}, single-seed p_gain at c=beta*n)")
    print("    The ceremony is a certain best-of-2^t every epoch; the witness")
    print("    edge is a beta-gated best-of-~2 only when the adversary holds a")
    print("    cut slot. 'sight=1' grants a zero-latency full-sight network —")
    print("    the structural worst case, no dilution credited.")
    p_gain = ((n - round(beta * n)) / n) * beta
    print(f"    (p_gain = {p_gain:.4f}, t=round(beta*b)={round(beta * 16)} at b=16)")
    print("    scheme                              | p_event | width (candidate seeds)")
    print("  " + "-" * 70)
    rev = reveal_ceremony_p_event(beta, p_gain, 16)
    print(f"    reveal ceremony (2^t, certain)      | {rev:.4f}  | {2 ** round(beta * 16):>6}  central, every epoch")
    for m in (1, 2, 4):
        we = witness_edge_p_event(beta, p_gain, 1.0, m)
        print(f"    witness edge  m={m}  (sight=1, worst)  | {we:.4f}  | "
              f"~2 one-sided, held w.p. beta on {m} slot(s)")
    print("   (the witness edge is below the ceremony at every m even granting "
          "full sight — the")
    print("    exponent falls from beta*b to beta*m, and m<<b. Any real network "
          "dilutes it further.)")

    print(f"\nW2. Days to march one targeted shard to f+1 (n={n}, beta={beta}, "
          f"I={SHUFFLE_INTERVAL_EPOCHS})")
    print("    scheme                         | days to f+1")
    print("  " + "-" * 48)
    cer = grind_shard_march_days(n, beta, round(beta * 16))
    print(f"    reveal ceremony (t={round(beta * 16)})            | {cer:>10.1f}")
    for m in (1, 2, 4):
        wd = witness_march_days(n, beta, 1.0, m)
        print(f"    witness edge  m={m} (sight=1)      | {wd:>10.1f}")
    floor_days = (f + 1 - round(beta * n)) * SHUFFLE_INTERVAL_EPOCHS * EPOCH_SECONDS / 86400
    print(f"   (deterministic floor {floor_days:.1f}d. The witness march is an "
          "UPPER bound on speed —")
    print("    it keeps the model's monotone-hold grant the witness fold does "
          "not actually give.)")

    print(f"\nW3. Network FIFO equilibrium c_T — witness edge vs ceremony width "
          f"2^t (n={n}, f+1={f + 1}, 2f+1={2 * f + 1})")
    print("    Same conserved-pool machinery as table R; the witness edge "
          "replaces the seat rate.")
    betas = (0.05, 0.10, 0.13, 0.15, 0.20)
    print("    scheme                   | " + " ".join(f"b={b:<5}" for b in betas))
    print("  " + "-" * (28 + 8 * len(betas)))

    def creg(v):
        return "FORK" if v == "fork" else ("flr" if v == "floor" else f"{v:.0f}")
    cer_cells = []
    for b in betas:
        t = max(1, round(b * n))
        cer_cells.append(creg(grind_network_regime(n, b, 100, NET_POOL_FACTOR, 2 ** t)))
    print("    reveal ceremony (2^t)    | " + " ".join(f"{c:>7}" for c in cer_cells))
    for m in (1, 2, 4):
        cells = []
        for b in betas:
            f_b = f_of(n)
            if b * (100 * n + round(NET_POOL_FACTOR * n)) <= f_b:
                cells.append("flr")
                continue
            c_t, _ = witness_network_equilibrium(n, b, 100, NET_POOL_FACTOR, 1.0, m)
            cells.append("FORK" if c_t >= f_b + 1 else f"{c_t:.0f}")
        print(f"    witness edge m={m} (sight=1) | " + " ".join(f"{c:>7}" for c in cells))
    print("   (the witness equilibrium sits far below f+1 across the band where "
          "the ceremony forks;")
    print("    2f+1 — the TERMINAL line — is never approached. Sight=1 is the "
          "worst case; the")
    print("    accumulator ordering blinds interior leaves unconditionally, so "
          "real sight < 1.)")

    print(f"\nW4. WT-cutoff variant — anchor the fold edge to a fixed schedule "
          f"line")
    print(f"    T_cut = boundary - Delta (Delta >= MAX_TIMESTAMP_DELAY="
          f"{MAX_TIMESTAMP_DELAY_S}s) instead of the")
    print("    boundary block's own leaf count. The timestamp-validity consts "
          "pin everything")
    print("    outside the drag band; the residual is a beta-gated best-of-2 "
          "CEILING (sight-independent).")
    print("    beta  | fold provably pinned | residual p_event  WT / boundary "
          "m=1 / m=4 / ceremony")
    print("  " + "-" * 84)
    for beta in (0.05, 0.10, 0.13, 0.15, 0.20):
        pg = ((n - round(beta * n)) / n) * beta
        wt = wt_edge_p_event(beta, pg)
        b1 = witness_edge_p_event(beta, pg, 1.0, 1)
        b4 = witness_edge_p_event(beta, pg, 1.0, 4)
        cer = reveal_ceremony_p_event(beta, pg)
        print(f"    {beta:.2f}  | {wt_pinned_fraction(beta):>17.1%}    | "
              f"{wt:.4f} / {b1:.4f} / {b4:.4f} / {cer:.4f}")
    wtm = wt_march_days(n, 0.10)
    b1m = witness_march_days(n, 0.10, 1.0, 1)
    print(f"   Days to march one shard to f+1 (beta=0.10): WT {wtm:.1f}d vs "
          f"boundary-edge m=1 {b1m:.1f}d.")
    print(f"   (Delta = one MAX_TIMESTAMP_DELAY excludes the last ~beta*"
          f"{MAX_TIMESTAMP_DELAY_S + MAX_TIMESTAMP_RUSH_S}s of reveals from each "
          "fold — they fold one")
    print("    epoch later, no entropy lost. The residual caps at beta-gated "
          "best-of-2 regardless of")
    print("    sight, where the boundary edge grows with m, and it removes the "
          "single-proposer own-count")
    print("    slide of chunk_end. Cost: the fold computes a WT->position cutoff, "
          "not a leaf-count range —")
    print("    more fork-critical arithmetic on the witness-window path.)")

    print("   The seed in one line: the include/omit lever is removed "
          "structurally (range fold),")
    print("   interior leaves are blind without a network assumption "
          "(accumulator ordering), and the")
    print("   residual edge is below the ceremony at every shard count — so NO "
          "shard-count threshold")
    print("   and NO separate blinder are needed. The ceremony survives only as "
          "the zero-crossing")
    print("   bootstrap/fallback. See §10.2-§10.3.")

    print("\n   Disposition (§10.7): the two boundaries get opposite defenses "
          "(§10.1).")
    print("   f+1 (liveness) is recoverable -> detect-and-rotate (§10.6, table S).")
    print("   2f+1 is TERMINAL — unilateral control mints stake and cascades; no "
          "recovery, so the")
    print("   defense is PREVENTION: the reveal-leaf seed removes the include/omit "
          "lever (tables W),")
    print("   the fallback ceremony is confined to zero-crossing epochs and bounded "
          "by the input-side")
    print("   stack — b=16 (b=20 reaches 2f+1), FIFO (table R), jail-on-first held "
          "for a recency")
    print("   period, recency-weighted resample -> first 2f+1 crossing beta~0.14 "
          "(table T) — and pool")
    print("   hygiene (beta low) is the deepest lever. See §10.5 + §10.7.")


if __name__ == "__main__":
    main()
