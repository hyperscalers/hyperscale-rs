# Committee Security under Sampling and Shuffling (INV-SEC-1)

Every safety property verified in this directory is conditional on INV-SEC-1:
no committee ever seats ≥ f+1 corrupt members. That premise is statistical,
not logical — the right instrument is concentration bounds and Markov
analysis, not a model checker. This note prices the premise; the companion
script ([committee_security.py](committee_security.py)) generates all tables
(exact hypergeometric arithmetic, no dependencies).

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

## 2. The trickle shuffle is a birth–death chain

One member rotates out per shard per `SHUFFLE_INTERVAL_EPOCHS` (16), replaced
from the pool. The committee's corrupt count k is then a Bernoulli–Laplace
birth–death chain whose stationary law is *exactly* the hypergeometric of §1
(detailed balance; asserted numerically in the script). Failures are boundary
crossings k = f → f+1; the stationary crossing rate π(f)·p↑(f) per shuffle
event, conservatively counting every crossing as a compromise, gives expected
compromises per shard-year (30s epochs → 65,745 events/shard-year):

| n | β=0.05 | β=0.10 | β=0.15 | β=0.20 |
|---|---|---|---|---|
| 32 | 1.0e-03 | 1.8 | 59 | 415 |
| 64 | 1.9e-10 | 6.8e-04 | 0.81 | 44 |
| 96 | 5.8e-16 | 1.6e-06 | 0.039 | 11 |
| 128 | 1.3e-22 | 7.4e-10 | 6.7e-04 | 1.4 |
| 256 | 6.7e-48 | 2.3e-22 | 2.1e-10 | 1.1e-03 |

Trickling beats independent per-event redraws by only 3–20× (script table C):
correlation helps, but it is not a primary defense against a static
adversary. Its real value is operational (one syncing seat at a time) and
adaptivity-limiting (§4).

## 3. Sizing — and the inversion the size cap forces

Smallest candidate meeting a compromises-per-shard-year budget, and the
maximum pool corruption each candidate tolerates:

| budget | β=0.05 | β=0.10 | β=0.15 | β=0.20 |
|---|---|---|---|---|
| 10⁻³ | 64 | 64 | 128 | — |
| 10⁻⁶ | 64 | 128 | 256 | — |
| 10⁻⁹ | 64 | 128 | 256 | — |

| budget | n=32 | n=64 | n=96 | n=128 | n=256 |
|---|---|---|---|---|---|
| 10⁻³ | β≤0.048 | 0.102 | 0.128 | 0.152 | 0.200 |
| 10⁻⁶ | β≤0.030 | 0.072 | 0.098 | 0.122 | 0.174 |
| 10⁻⁹ | β≤0.019 | 0.053 | 0.077 | 0.101 | 0.154 |

Boundary note: 96 at β=0.10 misses the 10⁻⁶ budget by 1.6× — genuinely
borderline; 128 clears it with two orders of headroom.

**Finding 1 — β dominates n, and the cap makes that binding.** Going from
n=32 to n=256 (8× the seats, and the message-complexity price that implies)
only moves tolerable corruption from 3% to 17% at the 10⁻⁶ budget. With the
practical ceiling at 128, the pool must stay under ~12% corrupt seats — under
~10% if 96 is the operating point. Every mechanism that suppresses pool
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

**Finding 2 — at a fixed one-seat-per-interval rotation, larger committees
are *more* exposed to slow-adaptive adversaries.** Per-member tenure is n·I
epochs, so it grows with n: at β=0.10 and τ=16,000 epochs (≈5.5 days at 30s),
n=32 flushes corruption faster than it lands (r_max > 10³/epoch), n=128
tolerates ~36/epoch, and n=256 only ~0.7/epoch. Sampling luck (§1) pushes n
up; adaptivity resistance pushes per-member tenure down. The reconciliation
is a design change candidate for production sizing: **shrink the shuffle
interval as n grows** (I ∝ 1/n, one seat per event), keeping expected tenure
constant while n grows — §6 settles the mechanism and the rate.

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
| 0.08 | 1.3e-13 | 1 per ~77B years |
| 0.10 | 7.4e-10 | 1 per ~13.6M years |
| 0.122 | 8.5e-07 | 1 per ~11,700 years |
| 0.13 | 7.5e-06 | 1 per ~1,300 years |
| 0.15 | 6.7e-04 | 1 per ~15 years |

At a working assumption of β = 0.10, 128 clears the 10⁻⁶ budget with two
orders of headroom — margin that absorbs the §7 idealizations without a
resizing — where 96 sits on the line and 256 buys five more points of β
tolerance at double the vote path, a ~65k-message view-change storm, and 4×
worse slow-adaptive exposure. Fresh draws are never the binding term at 128
(4.5e-14 per split cohort at β = 0.10); reshape frequency is a security
non-factor.

Costs: 128 votes per round to the proposer, one pairing + O(n) key
aggregation per QC (wire size n-independent but for a 16-byte bitfield); the
n² term is the timeout path (~16k messages per full view change). Every
split needs a 128-member cohort free in the pool (`POOL_BUFFER_TARGET`
scales with it); the readiness gate is 85 ready per successor.

Attack economics: exceeding the 10⁻⁶ budget requires >12% of all seats — at
100 shards, ~1,560 seats ≥ 1.56B tokens at `MIN_STAKE_FLOOR` (more at the
dynamic price), all exposed to permanent jailing on first provable
equivocation. Per-committee arithmetic ("43 seats") is the wrong frame:
sampling decides where seats land, so the adversary buys the pool fraction.

Two riders, without which 128 is not this strong:

**Rider 1 — rotation must scale, by shortening the interval.** Rotation
speed trades static security for adaptive resistance, and the trade is
lopsided: the static cost is linear in the rate (more draws per year), while
the adaptive gain is exponential (survival of a corruption attempt is
`(1−1/n)^(τ/I)`). Script table H, at n=128, β=0.10, τ=16,000 epochs:

| I (epochs) | tenure | crossings/shard-yr | max β @10⁻⁶ | slow-adaptive r_max |
|---|---|---|---|---|
| 16 | 17.1h | 7.4e-10 | 0.122 | 36/epoch |
| 8 | 8.5h | 1.5e-09 | 0.120 | 1.9e5/epoch |
| 4 | 4.3h | 2.9e-09 | 0.118 | cannot land |
| 1 | 1.1h | 1.2e-08 | 0.113 | cannot land |

Sixteen-fold faster rotation costs less than one point of β headroom (the
§3 cliff is that steep), while at I=4 a multi-day corruption pipeline
cannot land before rotation flushes its target. Properly stated, fast
rotation does not make corruption impossible — it forces the adversary off
cheap slow corruption onto fast expensive corruption, a harder threat
class. **Recommendation: I=4 at n=128** (≈4.3h tenure, the 32-committee
baseline; the same tenure target gives I ∝ 1/n across the grid, and even
n=256 needs only I=2, so the 1-epoch floor never binds).

The mechanism is the shorter interval, *not* rotating k seats per batch,
for three reasons: a k-batch guarantees a synchronized dip of k unready
seats (staggered singles keep concurrent syncing at the steady-state
average — even a 30-minute catch-up at I=4 is ~15 unready of 128, ready set
113 ≥ quorum 85, and the L=1 freeze pre-positions each incomer anyway);
INV-SEC-2 ("at most one seat per shard per interval") and the fold's
victim/draw logic survive as written; and the birth–death model stays exact
(±1 steps), so this note's tables remain valid under interval scaling
without re-derivation.

**Rider 2 — β ≲ 0.12 is load-bearing**: at β = 0.15 even 128 fails yearly
at scale, and nothing on the candidate grid rescues that — pool hygiene
(pricing, jailing, expulsion) is where the security actually lives.

## 7. Stated idealizations

The math above assumes, and the code deviates in, the following — each is a
Phase-2 target, none is expected to flip a conclusion:

- **Uniform victim selection**: the fold rotates among *ready* members only,
  and skips mid-reshape shards; the analysis assumes uniform over all n.
- **Mean-field pool**: replacement corruption probability uses (M−k)/(N−n),
  ignoring depletion by concurrent committees and reshape cohort draws.
- **Independent per-seat corruption**: a compromised *operator* yields all
  co-hosted seats at once, and committee selection deliberately does not
  spread a host's identities. The corruption unit for a hacking adversary is
  operators; a heavy-tailed seats-per-operator distribution materially
  degrades §1–§3. Needs the operator-concentration distribution as an input.
- **Crossing = compromise**: conservative; an adversary must also exploit
  the window while it lasts.
- **Unbiased randomness**: committee draws use the beacon accumulator; VRF
  bias-resistance is assumed, not analyzed here.

## 8. Next phases

- **Phase 2 — Monte Carlo against the real fold.** Drive the actual
  `crates/beacon` sampling/shuffle code over synthetic epochs with a marked
  corrupt set; compare the empirical transition kernel against §2's chain.
  This closes the idealization gaps (ready-only victims, reshape skips,
  top-up) exactly the way trace validation closes the Quint model gap.
- **Phase 3 — adversary synthesis.** The corrupt-count chain plus a
  corruption budget is a small MDP; a probabilistic model checker (Storm)
  can compute the optimal adaptive strategy, replacing §4's heuristic
  adversary with a worst case.

## 9. Composition with the models

The Quint models fix `BYZ = 1..F` — INV-SEC-1 as an axiom. This note bounds
the probability that axiom fails, so system-level claims compose as:
P[safety violation] ≤ P[some committee ever ≥ f+1 corrupt] (this note) +
P[violation | all committees honest-majority] (the models, = 0 for verified
properties within their bounds).
