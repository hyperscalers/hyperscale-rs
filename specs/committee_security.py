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
EPOCH_SECONDS = 30              # docs' production aspiration; dev sim uses 2s
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
    tau = 16000
    print("\nH. Shuffle-interval sweep at n=128 (one seat per I epochs; "
          f"tau={tau} epochs, beta=0.10 for r_max)")
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


if __name__ == "__main__":
    main()
