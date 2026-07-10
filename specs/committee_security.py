#!/usr/bin/env python3
"""Committee-security parameter tables for INV-SEC-1 (see committee_security.md).

Prices the premise every verified safety property is conditional on: that no
committee ever seats >= f+1 corrupt members. Dependency-free; exact
hypergeometric arithmetic via log-gamma.

Units: seats (voting is per seat; stake is the admission gate). The failure
event is a committee reaching k >= f+1 corrupt seats, f = (n-1)//3 — the
threshold at which both safety and liveness arguments lapse.

Run: python3 specs/committee_security.py
"""

from math import exp, lgamma

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


def crossing_rate(N: int, M: int, n: int) -> float:
    """Stationary frequency (per shuffle event) of the k = f -> f+1 crossing.

    Conservative failure accounting: every boundary crossing counts as a
    committee compromise, whether or not an adversary exploits the interval.
    """
    f = f_of(n)
    return hyper_pmf(N, M, n, f) * p_up(N, M, n, f)


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


if __name__ == "__main__":
    main()
