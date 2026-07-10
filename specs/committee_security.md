# Committee Security under Sampling and Shuffling (INV-SEC-1)

Every safety property verified in this directory is conditional on INV-SEC-1:
no committee ever seats ≥ f+1 corrupt members. That premise is statistical,
not logical — the right instrument is concentration bounds and Markov
analysis, not a model checker. This note prices the premise; the companion
script ([committee_security.py](committee_security.py)) generates all
analytic tables (exact hypergeometric arithmetic, no dependencies), and the
Monte Carlo harness driving the shipped fold
(`crates/beacon/tests/committee_security.rs`) regenerates every measured
number in §7 (`cargo nextest run --release -p hyperscale-beacon --test
committee_security --run-ignored=only --no-capture`; its seeded cells run in
CI as a regression net over the sampling code).

**Units are seats.** Voting is per seat; stake is only the admission gate
([docs/05 §1](../docs/05-byzantine-safety.md)). β denotes the corrupt fraction
of the validator pool, n the committee size, and the failure event is a
committee reaching k ≥ f+1 corrupt seats with f = ⌊(n−1)/3⌋ — the threshold
at which both the safety and liveness arguments lapse. Failure probabilities
compound across shards and years; a per-shard-year budget of 10⁻⁶ keeps a
100-shard network under 10⁻⁴/year.

**Candidate committee sizes are {32, 64, 96, 128, 256}**, capped by message
complexity — 256 is already questionable on that axis. The candidates are not
3f+1-aligned (tolerances f = 10, 21, 31, 42, 85); the one or two seats above
3f+1 slightly improve the draw statistics at no tolerance cost. Because n is
capped, the sizing question inverts: the budget converts into a *pool-hygiene
requirement* — the maximum β the network must maintain (§3).

## 1. Fresh draws (genesis, split cohorts, merge keepers)

A fresh committee is a hypergeometric draw from the pool. Exact tail
`P[k ≥ f+1]`, pool = 20n:

| n | β=0.05 | β=0.10 | β=0.15 | β=0.20 | β=0.25 |
|---|---|---|---|---|---|
| 4 *(dev)* | 0.011 | 0.048 | 0.105 | 0.177 | 0.259 |
| 32 | 5.1e-08 | 1.0e-04 | 4.1e-03 | 0.037 | 0.148 |
| 64 | 9.6e-15 | 4.0e-08 | 5.8e-05 | 4.1e-03 | 0.055 |
| 128 | 6.8e-27 | 4.5e-14 | 5.1e-08 | 1.5e-04 | 0.016 |
| 256 | 3.4e-52 | 1.4e-26 | 1.6e-14 | 1.1e-07 | 9.7e-04 |

The current `SHARD_CAPACITY = 4` is a dev value and provides no statistical
security at any β — every draw is a 1-in-90 to 1-in-4 failure. Production
sizing comes from §3.

**The beacon committee is a fresh draw every epoch.** `apply_epoch` fully
resamples it from the seated-ready eligible set each fold
(`resample_beacon_committee`, crates/beacon/src/state/committee.rs) — the
independent-redraw column of §2's table C made real, ~105k draws/year at
300s epochs, and there is exactly one of it network-wide. The redraw is
measured to be exactly hypergeometric within every corrupt-eligible bin
(§7). Script table I prices it: at the 10⁻⁶/year budget, n = 128 requires
β ≤ 0.111 — nominally the tightest β line in the system (the trickled
shard committee at the same budget tolerates 0.131). Severity differs,
though: epoch-commit safety rides the pool ratification quorum
(INV-BEACON-1), not this committee, so an over-threshold draw here prices
liveness degradation and randomness-bias exposure rather than a fork — its
budget can defensibly sit looser than the shard fork budget, but it is the
right line to watch if the beacon committee ever acquires safety-bearing
authority beyond content certification.

## 2. The trickle shuffle is a birth–death chain

One member rotates out per shard per `SHUFFLE_INTERVAL_EPOCHS` (16), replaced
from the pool. The committee's corrupt count k is then a Bernoulli–Laplace
birth–death chain whose stationary law is *exactly* the hypergeometric of §1
(detailed balance; asserted numerically in the script, measured against the
fold in §7). Failures are boundary crossings k = f → f+1; the stationary
crossing rate π(f)·p↑(f) per shuffle event, conservatively counting every
crossing as a compromise, gives expected compromises per shard-year (300s
epochs → 6,574 events/shard-year):

| n | β=0.05 | β=0.10 | β=0.15 | β=0.20 |
|---|---|---|---|---|
| 32 | 1.0e-04 | 0.18 | 5.9 | 41 |
| 64 | 1.9e-11 | 6.8e-05 | 0.081 | 4.4 |
| 96 | 5.8e-17 | 1.6e-07 | 3.9e-03 | 1.1 |
| 128 | 1.3e-23 | 7.4e-11 | 6.7e-05 | 0.14 |
| 256 | 6.7e-49 | 2.3e-23 | 2.1e-11 | 1.1e-04 |

Trickling beats independent per-event redraws by only 3–20× (script table C;
the beacon committee's per-epoch resample lives in the redraw column — §1):
correlation helps, but it is not a primary defense against a static
adversary. Its real value is operational (one syncing seat at a time) and
adaptivity-limiting (§4).

## 3. Sizing — and the inversion the size cap forces

Smallest candidate meeting a compromises-per-shard-year budget, and the
maximum pool corruption each candidate tolerates:

| budget | β=0.05 | β=0.10 | β=0.15 | β=0.20 |
|---|---|---|---|---|
| 10⁻³ | 32 | 64 | 128 | 256 |
| 10⁻⁶ | 64 | 96 | 256 | — |
| 10⁻⁹ | 64 | 128 | 256 | — |

| budget | n=32 | n=64 | n=96 | n=128 | n=256 |
|---|---|---|---|---|---|
| 10⁻³ | β≤0.059 | 0.115 | 0.141 | 0.164 | 0.210 |
| 10⁻⁶ | β≤0.034 | 0.080 | 0.107 | 0.131 | 0.182 |
| 10⁻⁹ | β≤0.022 | 0.059 | 0.083 | 0.107 | 0.160 |

Boundary note: 96 at β=0.10 clears the 10⁻⁶ budget by 6× — workable but
thin; 128 clears it by four orders.

**Finding 1 — β dominates n, and the cap makes that binding.** Going from
n=32 to n=256 (8× the seats, and the message-complexity price that implies)
only moves tolerable corruption from 3% to 18% at the 10⁻⁶ budget. With the
practical ceiling at 128, the pool must stay under ~13% corrupt seats — under
~11% if 96 is the operating point. Every mechanism that suppresses pool
corruption (the stake price, jailing, expulsion, the sybil floor) buys more
security per unit than seats do; committee size is the dial, pool hygiene is
the lever, and the ceiling on n turns "keep β low" from advice into a
requirement.

## 4. Adaptive corruption vs. rotation

Model: corrupting a specific seated validator takes τ epochs and lands only
if the target is still seated (survival `(1−1/n)^(τ/I)`; the L=1 lookahead
freeze hands the adversary one epoch of head start, folded into τ). Landed
corruption persists for the member's residual tenure (≈ n·I epochs). Little's
law gives the sustainable corruption rate the network tolerates:

```
r_max = (f − βn) / (survival(τ) · n · I)    corruptions per epoch, per shard
```

The survival term has a measured floor the formula rounds away: a fresh
seat cannot be rotated out before its second shuffle event (readiness is
sampled at shuffle boundaries, and an unready seat is victim-ineligible —
§7), so survival(τ) = 1 for τ up to two intervals. Little's law pins the
*mean* tenure at n·I regardless; only the shape moves.

**Finding 2 — at a fixed one-seat-per-interval rotation, larger committees
are *more* exposed to slow-adaptive adversaries.** Per-member tenure is n·I
epochs, so it grows with n — and at 300s epochs it is long in wall-clock
terms (n=128, I=16: 7.1 days). At β=0.10 and τ=1,600 epochs (≈5.6 days),
n=32 sustains ~0.3 targeted corruptions/epoch, n=128 only ~0.03, and n=256
~0.02 — a multi-day corruption pipeline *half-survives* n=128's rotation
(survival 0.49). Sampling luck (§1) pushes n up; adaptivity resistance
pushes per-member tenure down. The reconciliation is a design change
candidate for production sizing: **shrink the shuffle interval as n grows**
(one seat per event, smaller I) — §6 settles the mechanism and the rate.

## 5. Seats versus stake

A single-chain BFT system fails only at ≥⅓ of *stake*. Here the threshold is
denominated in seats, and the adversary always seats at exactly `min_stake`
while honest operators may overstake per seat. If the average honest seat
carries c × min_stake, the stake share the adversary needs for seat share
β_s is `β_s / (β_s + (1−β_s)·c)`:

| β_s target | c=1 | c=2 | c=5 |
|---|---|---|---|
| 0.10 | 0.100 | 0.053 | 0.022 |
| 0.33 | 0.333 | 0.200 | 0.091 |

**Finding 3 — honest overstaking is a security leak.** At c=5, an adversary
with 9% of total stake owns a third of the seats. The design's own answer is
the vnode: marginal seat cost approaches stake, so rational honest operators
split stake into many minimum-stake seats, driving c → 1 — vnodes are load-
bearing for the security model, not just for economics. The absolute cost
floor for f+1 seats in one committee is `(f+1) × MIN_STAKE_FLOOR` (10⁶ tokens
per seat) times the sampling odds of §1; the dynamic price (`t_admit`) raises
it further whenever supply is abundant.

## 6. Operating point: n = 128

The candidate the numbers favor. f = 42, quorum = 85; 128 = 3f+2, so the
spare seat buys slightly better sampling odds at no tolerance cost. The
failure rate around it moves four orders of magnitude per five points of β
(script table G) — 128's virtue is sitting on the good side of that cliff
*with margin*:

| β | per-shard-year | 100-shard network |
|---|---|---|
| 0.08 | 1.3e-14 | 1 per ~768B years |
| 0.10 | 7.4e-11 | 1 per ~136M years |
| 0.122 | 8.5e-08 | 1 per ~117,000 years |
| 0.13 | 7.5e-07 | 1 per ~13,000 years |
| 0.15 | 6.7e-05 | 1 per ~149 years |

At a working assumption of β = 0.10, 128 clears the 10⁻⁶ budget with four
orders of headroom — margin the §7 measurements leave intact — where 96
clears it by single digits and 256 buys five more points of β
tolerance at double the vote path, a ~65k-message view-change storm, and
worse slow-adaptive exposure. Fresh draws are never the binding term at 128
(4.5e-14 per split cohort at β = 0.10); reshape frequency is a security
non-factor.

Costs: 128 votes per round to the proposer, one pairing + O(n) key
aggregation per QC (wire size n-independent but for a 16-byte bitfield); the
n² term is the timeout path (~16k messages per full view change). Every
split needs a 128-member cohort free in the pool (`POOL_BUFFER_TARGET`
scales with it); the readiness gate is 85 ready per successor.

Attack economics: exceeding the 10⁻⁶ budget requires >13% of all seats — at
100 shards, ~1,680 seats ≥ 1.68B tokens at `MIN_STAKE_FLOOR` (more at the
dynamic price), all exposed to permanent jailing on first provable
equivocation. Per-committee arithmetic ("43 seats") is the wrong frame:
sampling decides where seats land, so the adversary buys the pool fraction.

Two riders, without which 128 is not this strong:

**Rider 1 — rotation must scale, by shortening the interval.** Rotation
speed trades static security for adaptive resistance, and the trade is
lopsided: the static cost is linear in the rate (more draws per year), while
the adaptive gain is exponential (survival of a corruption attempt is
`(1−1/n)^(τ/I)`). At 300s epochs the default interval leaves a seat parked
for a week — a multi-day corruption pipeline half-survives that rotation.
Script table H, at n=128, β=0.10, τ=1,600 epochs (≈5.6 days):

| I (epochs) | tenure | crossings/shard-yr | max β @10⁻⁶ | slow-adaptive r_max |
|---|---|---|---|---|
| 16 | 7.1d | 7.4e-11 | 0.131 | 0.03/epoch |
| 8 | 3.6d | 1.5e-10 | 0.128 | 0.14/epoch |
| 4 | 42.7h | 2.9e-10 | 0.126 | 1.3/epoch |
| 2 | 21.3h | 5.9e-10 | 0.123 | 61/epoch |
| 1 | 10.7h | 1.2e-09 | 0.121 | 6.4e4/epoch |

Sixteen-fold faster rotation costs less than one point of β headroom (the
§3 cliff is that steep), while at I=2 a ~5-day corruption pipeline survives
with probability 0.4% — sustaining pressure against that flush costs
thousands of targeted corruptions per day. Properly stated, fast rotation
does not make corruption impossible — it forces the adversary off cheap
slow corruption onto fast expensive corruption, a harder threat class.
**Recommendation: I=2 at n=128** (≈21h tenure; the 5-minute epoch puts the
old sub-5h tenure targets out of reach — even I=1 leaves 10.7h — so the
1-epoch floor genuinely binds: the I ∝ 1/n scaling puts n=256 exactly at
it).

The mechanism is the shorter interval, *not* rotating k seats per batch,
for three reasons: a k-batch guarantees a synchronized dip of k unready
seats (staggered singles keep concurrent syncing at the steady-state
average — a 30-minute catch-up at I=2 is ~3 syncing of 128, ready set
125 ≥ quorum 85, and the L=1 freeze pre-positions each incomer anyway);
INV-SEC-2 ("at most one seat per shard per interval") and the fold's
victim/draw logic survive as written; and the birth–death model stays exact
(±1 steps), so this note's tables remain valid under interval scaling
without re-derivation.

**Rider 2 — β ≲ 0.13 is load-bearing**: the 10⁻⁶ budget dies at β = 0.131,
five points of β cost four orders of magnitude, and nothing on the
candidate grid rescues β ≥ 0.2 — pool hygiene (pricing, jailing, expulsion)
is where the security actually lives. (The beacon committee's per-epoch
redraw sets its own 0.111 line at the same budget — §1's severity nuance
applies, but planning to β ≲ 0.10 covers both.)

## 7. Idealizations, measured

The math above idealizes the fold in five ways. The Monte Carlo harness
(header note) drives the shipped `apply_epoch` over synthetic epochs with a
marked corrupt set and tallies each committee's corrupt-seat transition at
every shuffle event. At production parameters the compromise tail
(~10⁻¹⁰/event) is unobservable by simulation, so the instrument validates
the *transition kernel* — measurable at every occupied corrupt count — and
§2's chain arithmetic extrapolates the tail from the validated kernel.

- **Victim selection** — assumed uniform over all n; the fold rotates among
  ready members only. Measured: the empirical kernel matches `p_up`/`p_down`
  within sampling error at every well-visited k across n ∈ {4, 16, 32},
  β ∈ {0.10, 0.25}, 200k events per cell (occupancy TV vs the hypergeometric
  ≤ 0.009). Ready-gating does not bend it: readiness is uncorrelated with
  corruption, so the corrupt-count kernel is invariant to the Ready lag —
  measured at lags of zero, one, and two intervals (two is
  `READY_TIMEOUT_EPOCHS`, the fold's ceiling with no witness at all; any lag
  collapses to whole intervals because eligibility is sampled at shuffle
  boundaries). What the lag moves is the flush floor: no seat rotates out
  before its second shuffle event (P[tenure ≥ 2 intervals] measured 0.94 at
  instant readiness, 1.00 at any real lag), while Little's law pins mean
  tenure at n·I. §4 carries the resulting survival floor.
- **Reshape pauses** — a pending split suspends its shard's rotation
  entirely; merge keepers are victim-exempt. Measured: the skip lasts
  exactly the pending window (neighbors rotate throughout) and is
  TTL-bounded — an unready split abandons at `RESHAPE_READY_TTL_EPOCHS` and
  rotation resumes, mechanically verified. Static accounting *improves*
  during a pause (crossings need events); the adaptive concession is a
  no-flush window of at most the TTL against a mean tenure of n·I —
  percent-level, low duty cycle, and not adversary-extensible (re-admission
  needs the consensus-checked reshape predicate to genuinely hold).
- **Mean-field pool** — the replacement probability (M−k)/(N−n) ignores
  depletion by concurrent committees. Measured to be exact, not
  approximate: under exchangeability the unseated fraction cancels from the
  replacement probability, and the cell built to break it — four committees
  seating *half* the population — still fits the single-committee formulas
  (occupancy TV ≤ 0.007).
- **Per-seat corruption unit** — a compromised operator yields all its
  seats at once. Conditional on M corrupt seats the fold treats validators
  exchangeably, so clustering is invisible to every table here: an M-subset
  is an M-subset, and the expected-compromises budget is
  correlation-invariant by linearity. What clustering changes is the *cost*
  of reaching M — operators compromise in lumps, so the corruption budget
  is denominated in operators, not seats — which is exactly the input §8's
  adversary model prices.
- **Crossing = compromise** stays conservative by choice, and **unbiased
  randomness** stays an assumption — the randomness pipeline's grinding
  surface is its own analysis, out of scope here.

## 8. Next phase

- **Phase 3 — adversary synthesis.** The corrupt-count chain plus an
  operator-denominated, lumpy corruption budget is a small finite MDP;
  exact value iteration (dependency-free, in the companion script) computes
  the optimal adaptive strategy, replacing §4's heuristic adversary with a
  worst case and pricing the seats-per-operator distribution §7 defers
  here. A probabilistic model checker was considered and rejected: a finite
  MDP solves exactly by value iteration, and the script stays
  dependency-free.

## 9. Composition with the models

The Quint models fix `BYZ = 1..F` — INV-SEC-1 as an axiom. This note bounds
the probability that axiom fails, so system-level claims compose as:
P[safety violation] ≤ P[some committee ever ≥ f+1 corrupt] (this note) +
P[violation | all committees honest-majority] (the models, = 0 for verified
properties within their bounds).
