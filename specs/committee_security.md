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

`r_max` is a rate heuristic; the actual quantity is a compromise
*probability* over a campaign, which the corrupt-count chain computes
exactly. Script table J drives one shard committee (n=128, β=0.10) under
sustained pressure and reports P[k ever reaches f+1 within a 90-day
campaign], the transient the heuristic approximates:

- **Fast corruption (τ=160 epochs ≈ 13h) beats any interval on the grid**
  — the campaign compromises with probability 1 at every I from 16 down to
  2. Rotation cannot flush a target that turns in half a day.
- **Slow corruption (τ=1,600 epochs ≈ 5.6 days) is where the interval
  bites.** At the default I=16 the campaign still wins (0.63 even at
  pressure 16); at I=2 it is forced onto the graded tail (P = 0.016 at
  pressure 64, 0.25 at pressure 85 — and 85 concurrent attempts costs ~111
  targeted corruptions/day, sustained).

**Finding 2 — fast rotation converts slow cheap corruption into fast
expensive corruption; it does not stop a fast adversary.** This is the
heuristic's qualitative claim, now exact. Per-member tenure grows with n
(n=128, I=16: 7.1 days at 300s epochs), so larger committees are more
exposed to slow adaptation; shrinking I is the lever (§6). What the rate
heuristic misses entirely is the **budget-constrained** adversary.

**Finding 3 — a budget-limited adversary gains materially from adapting,
so the sustained-pressure table J is a lower bound, not the worst case.**
Exact value iteration over (corrupt seats, in-flight attempts, remaining
budget) on a tractable instance (script table K, n=32) finds the optimal
policy compromises at 2.3× the rate of blind launch-maximum (0.058 vs
0.025). The mechanism is a clean threshold: the optimal policy launches
*nothing* until a lucky rotation lifts the committee to within three seats
of the boundary, then spends its whole budget at once. Corruption budget is
best spent on luck, not sprayed uniformly — the intuition that constant
maximum pressure is optimal is wrong under a finite budget. The absolute
numbers stay tiny (both policies well under the per-shard budget at n=32's
weak sampling), and the finding does not move the sizing; it sharpens the
worst-case adversary §8 consolidates.

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

**Finding 4 — honest overstaking is a security leak.** At c=5, an adversary
with 9% of total stake owns a third of the seats. The design's own answer is
the vnode: marginal seat cost approaches stake, so rational honest operators
split stake into many minimum-stake seats, driving c → 1 — vnodes are load-
bearing for the security model, not just for economics. The absolute cost
floor for f+1 seats in one committee is `(f+1) × MIN_STAKE_FLOOR` (10⁶ tokens
per seat) times the sampling odds of §1; the dynamic price (`t_admit`) raises
it further whenever supply is abundant. Splitting into vnodes helps the
stake metric but concentrates control and often infrastructure under one
party; a hack corrupts the shared infrastructure and a bribe the party
behind it, neither priced by stake — §7 prices the concentration and shows
the protocol cannot bound it.

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
dynamic price). Any seat that equivocates is permanently key-revoked on the
self-proving evidence (INV-SEC-3) — its position forfeit, though the stake is
not slashed. Per-committee arithmetic ("43 seats") is the wrong frame:
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
**Recommendation: a genuine two-way trade, not a free choice of I=2.** Adaptive
corruption wants `I` small (I=2 flushes a ~5-day pipeline to 0.4% survival,
≈21h tenure, and the 5-minute epoch puts the old sub-5h targets out of reach —
even I=1 leaves 10.7h). But the randomness grind wants `I` *large*: the fork
march is linear in `I` (§10 table M), and a small beacon committee does **not**
cap the grind width — the coupled simulation of §10 Finding 11 shows the
resample boost survives jail-on-first, so the interval keeps its grind duty and
a small `I` is the grind's *worst* case. The two pull opposite ways and neither
dominates (the adaptive gain is exponential in `1/I`, the grind cost linear in
`I`), so `I` is not settled to a single number here: it balances the τ of the
realistic adaptive threat against the design-point march time, and the balance
eases as pool hygiene (§10 Disposition) shrinks the grind side.

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
  approximate *for unsteered draws*: under exchangeability the unseated
  fraction cancels from the replacement probability, and the cell built to
  break it — four committees seating *half* the population — still fits the
  single-committee formulas (occupancy TV ≤ 0.007). Exchangeability is what a
  *concentrating* grind breaks: an adversary steering corrupt seats onto one
  targeted shard depletes the shared pool the other shards draw from, so the
  fixed-β single-shard march (§10 Finding 5) *overstates* the grind on a real
  finite network — §10 Finding 8 prices the correction.
- **Corruption unit coarser than the seat.** Conditional on M corrupt seats
  the fold treats validators exchangeably, so clustering is invisible to
  every *seat-count* table here — an M-subset is an M-subset,
  correlation-invariant by linearity. What clustering changes is the *cost*
  of reaching M whenever the adversary's unit is coarser than one seat: a
  compromised machine (hacking) and a bribed controlling entity (bribery)
  each flip every seat they hold at once. Script table L prices it over one
  pool (N = 2,560 seats): under uniform 1-seat holders 336 must be subverted
  to reach the β = 0.131 boundary, but under a Zipf profile the largest
  holder already carries 16% of the pool — one machine, or one negotiation,
  clears it. **The protocol has no lever on the concentration.** It cannot
  attribute seats to a controlling entity: distinct stake-pool identities
  are indistinguishable from distinct entities — the same Sybil limit that
  makes stake, not identity, the admission gate — so a cap keyed on any
  observable identity is defeated by splitting it. Spread across independent
  operators and infrastructure is an operational premise the protocol cannot
  verify, the identity-only-selection fault-domain gap already noted at
  [06 §4](06-resource-economics.md). Accountability does not price this out:
  there is no slashing anywhere — a jailed validator's stake is preserved and
  withdrawable (INV-SEC-3 jails; it does not confiscate), so provable
  equivocation revokes the *key* (permanent jail, no unjail) but not the
  capital, which redeploys under a fresh identity. That is a re-registration
  tax, not a bribe floor. So the defense against a bribed or hacked committee
  is structural, not economic: a provable equivocation is self-proving
  evidence that halts the shard rather than forking it (INV-SHARD-1
  quorum intersection, INV-STATE-5 halt-loudly), degrading a safety attack to
  a liveness halt — and the residual, an external consumer acting on one
  branch before the evidence propagates, is a finality-latency question, not a
  slashing one. Bribery is also the fast-adaptive limit of §4 (a negotiation,
  not a multi-day intrusion), so it lands in table J's τ→small rows where
  rotation cannot help either. Only the *buying* adversary is
  concentration-neutral: `min_stake` is charged per seat regardless, so §1–3
  hold in seats.
- **Crossing = compromise** stays conservative by choice. **Unbiased
  randomness** does *not* hold: the epoch seed is grindable by a
  last-revealer, and §10 prices the resulting steered attack. Every table in
  §1–§8 assumes an unsteered draw and is a floor once §10's grind is
  available — the grind is what turns those tails into a directed march.

## 8. Adversary synthesis — the computed worst case

The rate heuristic of §4 is replaced by exact computation on the
corrupt-count chain (script tables J–L). Three
findings, in ascending threat sophistication:

- **Sustained pressure (table J).** P[compromise within a 90-day campaign]
  computed exactly over the event chain. Fast corruption (τ ≈ 13h) wins at
  every interval; slow corruption (τ ≈ 5.6 days) is forced onto a graded
  tail only once the interval shrinks to I=2 — the quantitative form of §4's
  "fast rotation buys nothing against a fast adversary, everything against a
  slow one."
- **Optimal adaptation (table K).** Exact value iteration over (corrupt
  seats, in-flight attempts, budget) shows a budget-constrained adversary
  beats blind maximum pressure by 2.3×, via a threshold policy: hold the
  budget until a lucky rotation lifts the committee near the boundary, then
  spend it all. The sustained-pressure table is therefore a lower bound on a
  fixed-budget adversary — the correction the heuristic could not have made.
- **Concentration cost (table L).** For an adversary whose unit is coarser
  than a seat — a hacked machine or a bribed entity — the corruption budget
  is denominated in those units, not seats; concentration collapses it, and
  the protocol cannot bound concentration (above).

Value iteration runs on the n=32 instance where the state space is
tractable; the argument is fraction-uniform, so the mechanism (spend on
luck) carries to n=128, where the absolute probabilities are the §6 tail.
A probabilistic model checker was considered and rejected: a finite MDP
solves exactly by value iteration, and the script stays dependency-free.

## 9. Composition with the models

The Quint models fix `BYZ = 1..F` — INV-SEC-1 as an axiom. This note bounds
the probability that axiom fails, so system-level claims compose as:
P[safety violation] ≤ P[some committee ever ≥ f+1 corrupt] (this note) +
P[violation | all committees honest-majority] (the models, = 0 for verified
properties within their bounds).

## 10. The randomness is grindable — a last-revealer steers the draw

Every table above assumes the draw is unsteered. It is not. The next-epoch
seed is `BLAKE3(prev_randomness ‖ VRF outputs of the committed
beacon-committee proposals)`, rolled immediately before the shuffle victim,
the shuffle entrant, the beacon resample, and pool draws all read it
(`filter_and_roll_randomness`, crates/beacon/src/state/vrf.rs). A Byzantine
beacon member cannot *choose* its VRF output — it is a fixed function of
`(key, epoch)` — but it can choose whether that output joins the fold:
reveal early and it is folded; withhold and its slot commits as `BOTTOM`,
unfolded. Because the PC input vector is dense and commits interior
`BOTTOM`s without truncating (`compute_view_input`, `qc1_certify`), the
include/omit toggle is **independent per member and does not shorten the
committed prefix**. With `t` such proposals held for late-but-included
release, the adversary observes the honest reveals, enumerates the `2^t`
candidate seeds, computes the committee each yields (ChaCha20 is a PRF, so
distinct seeds are independent uniform draws), and steers the commit to the
best one. **Grind width = 2^t**, one global best-of-`2^t` draw per epoch,
one-epoch lookahead.

Committee size does not dilute this. The seed is a hash: flipping one folded
input swaps the entire output for a fresh uniform value, and the honest
majority's reveals sit identically inside every candidate seed — a shared
constant that does not distinguish the adversary's options. The defect is
**move-order, not entropy quantity**: honest contributors reveal first, then
the adversary chooses which of its own contributions count, so it moves last.
The intuition "one honest unpredictable contribution randomizes the seed"
holds only for a beacon where contributors commit *before* any reveal; this
one reveals first.

`t` is bounded by the Byzantine beacon-committee count ≈ β·n (≈13 at n=128,
β=0.10; ceiling f=42). The realized value is how many of those proposals the
adversary can hold back and release late-but-included — a synchrony question
the code alone does not settle, and the one soft input here. Withholding is
not accountable today: an omitted proposal is indistinguishable from network
delay, and INV-SEC-3 catches only equivocation, not silence.

**Finding 5 — the trickle shuffle is the sharp target, and the grind marches
it to a fork.** On one targeted shard, a single seed gives
P[honest victim ∧ corrupt entrant] ≈ (1−β)·β ≈ 0.09 per event. Best-of-`2^t`
drives that to 0.78 at t=4 and ≈1 by t≥6, and the adversary simultaneously
grinds *away* from any corrupt-losing rotation, so the shard's corrupt count
climbs monotonically toward f+1 — an INV-SHARD-1 fork on that shard. Script
table M, at n=128, β=0.10:

| grind width t | candidate seeds 2^t | days to march β·n → f+1 |
|---|---|---|
| 2 | 4 | ~6.0 |
| 3 | 8 | ~3.5 |
| 4 | 16 | ~2.3 |
| ≥6 | ≥64 | ~1.7 (deterministic floor) |

Materiality threshold **t ≈ 3–4**, well under the ≈13 foothold ceiling at
baseline β. The corrupt pool (β·20n ≈ 256 seats) covers one shard's 43 seats;
the beacon foothold self-sustains via the resample grind below; and because
withholding is unaccountable, the march costs the adversary nothing it can be
jailed for.

**Finding 6 — the beacon resample amplifies but does not fork.** The
per-epoch resample tail is `P[≥f+1] ≈ 2.5e-13` (eligible ≈ shards·n =
12,800); best-of-`2^t` amplifies it, but even at t=13 it lands at
~2e-4/network-year (script table N). Epoch-commit safety rides pool
ratification (INV-BEACON-1) regardless, so this prices liveness degradation
and bias exposure — and the positive feedback that a grind-seated beacon
committee grinds the next epoch harder — not a fork.

**Severity is sharply β-sensitive.** Width is `2^t` and `t` tracks the
foothold ≈ β·n, so the grind is potent at β ≈ 0.05–0.10, marginal near
β ≈ 0.03, and largely defeated below ≈ 0.01. The system is *designed* to
tolerate β up to ≈0.10–0.13 (§6), so at the design point the grind bites. It
does not relax INV-SEC-1's honest-pool premise — it means the premise no
longer implies honest committees, because the draw an adversary sees is not
the draw the tables price.

**Finding 7 — the grind's lever is omission, so charge it, and the clean
charge is jail-on-first.** A member absent from the committed set is
attributable: the expected proposer set is the beacon committee the previous
fold seated, so absence is a strike against a consensus-known set
(`filter_and_roll_randomness`, crates/beacon/src/state/vrf.rs), riding beside the
fold with no wire field (the VRF output is already a commitment) and inert under
full participation. The subtlety is that absence is ambiguous — a withheld
proposal and one delayed past view formation are byte-identical — and the threat
model grants message-timing control. A naive reading concludes the penalty must
tolerate honest absence up to `f/n ≈ 1/3` (the SPC view forms on a `2f+1`
quorum, so the adversary can delay the slowest `f`), which would leave a
strike-aware grinder — rotating which single proposal it withholds — sitting
under any honest-safe threshold while still steering. That reading is wrong: it
reads a *leader-based* censorship model onto a *leaderless* protocol. The
committed value is the deepest prefix shared by `f+1` of the `2f+1` votes
([`qc1_certify`](../crates/types/src/beacon/prefix_ops.rs)), so an honest proposal
reaching a supermajority is committed whoever formed their input before it
arrived; to make an honest member absent the adversary must keep its proposal
from `f+1` members — a broad, sustained censorship possible only inside bounded
async windows (docs/05 partial synchrony), not the one-off delay the bound
assumes. A grinder, by contrast, is absent by *self-omission* — always. So the
penalty can be **jail-on-first for withholding**, which jails the self-omitting
grinder while sparing honest proposers (`sim_async_purge` confirms the residual
async-window purge is a rounding error, Finding 11). Whether jail-on-first
*closes* the grind or merely raises the bar is a quantitative question Finding 11
settles with a coupled simulation.

**Finding 8 — the single-shard march overstates the grind; the shared pool is
finite, and deterministic eviction caps the low-β band.** The march (Finding 5,
table M) prices one targeted shard drawing from an inexhaustible pool. Two facts
it omits both cut the adversary's way (script table R, on a conserved population
M = β·N shuffling through one shared finite pool). The pool is **finite and
contested** — forking one shard concentrates f+1 ≈ n/3 corrupt there, most of a
small network's total, fought over by every other shard's draws, so M ≤ f is a
structural floor plus a competition drag (the exchangeability §7 relied on,
broken by the concentration). And **deterministic-longest (FIFO) eviction**
removes the foothold's protection: where the current shuffle grinds the *victim*
too (steering honest seats out to keep corrupt ones, so the count marches
monotonically to f+1 whenever supply permits), FIFO gives every seat a fixed
n-event tenure, so freshly-seated corrupt age out on a clock the adversary can't
stop and the target settles at a stable equilibrium `c_T = n·(1−(1−x)^W)`
(x = pool corrupt fraction, W = grind width) instead of marching, forking only
if that equilibrium clears f+1. FIFO caps below f+1 for **β ≲ 0.025** alone, and
stacked with jail-on-first (which holds the effective foothold near its natural
distribution) the closed band reaches **β ≲ 0.05**, matching Finding 11. Neither
closes the design point: at β ≈ 0.10 the foothold makes the per-event
reliability `p = 1−(1−x)^W ≈ 1`, so `c_T ≈ n ≫ f+1` and the shard still forks
(validated against the conserved-population Monte Carlo `check_grind_network`).
FIFO's cost is a mild adaptive-corruption concession — deterministic tenure
makes the rotation schedule predictable, a bite a shorter interval blunts (the
same interval that speeds the grind, §6 Rider 1). So it is a **defense-in-depth**
layer that widens the closed band, not a design-point close.

**Finding 9 — liveness (f+1) and safety (2f+1) are different outcomes with
opposite defenses: f+1 is recoverable, 2f+1 is terminal — but f+1 carries a
bounded cross-shard exposure the recovery must fence, not a clean nuisance.**
Reaching f+1 corrupt on a shard is where BFT guarantees lapse, but the two
thresholds are not symmetric. The **liveness** attack — f+1 corrupt withhold,
leaving ≤ 2f honest, short of the 2f+1 quorum — halts the shard: other shards
keep committing, and the local chain simply stops. It is what
**detect-and-rotate** (Finding 10) recovers.

But "non-cascading" was too strong, and the correction is load-bearing (Model G,
`recovery_bridge` and `cross_shard_freeze`, finding G-1). Two facts. First, the
halted committee is beyond f *by construction* — that is why it halted — so with
one lagging honest member (an unfolded beacon, reachable under partition) the
corrupt f+1..2f can still form a quorum and extend the halted tip on an orphan
branch. Its QC weighted timestamp is the clamped **mean** of wall-clock vote
stamps ([`vote_set.rs`](../crates/shard/src/vote_set.rs)), and a beyond-f
committee is an honest *minority* in its own quorum, so the corrupt drag that
mean arbitrarily below wall-clock — past the one-window tolerance the recovery
bridge's certified re-bind is calibrated for (that tolerance assumes an
adversarial *minority*, the ≤ f case). The orphan resolves the *old* committee at
a folded replica and its signatures verify: a stale two-chain commit past the
tip. Second, and worse, that orphan **exports cross-shard**: a consuming shard
resolves the source committee for an execution certificate by its anchor window
([`lookup(ec.vote_anchor_ts())`](../crates/execution/src/coordinator.rs), the
plain lookup, no recovery bridge), so a stale-anchored forged EC resolves the old
committee and finalizes a wave — an INV-EXEC-1 break that **cascades**. So the
f+1 halt is not the clean, non-monetizable nuisance the first cut claimed; during
the recovery window it is a cross-shard cascade vector, the very thing this
finding reserved for 2f+1.

What bounds it is a **beacon-mandated freeze** (Finding 10, and the
[beacon-detected-shard-halt-recovery plan](../.plans/beacon-shard-halt-recovery.md)):
at the detection fold the beacon stamps a cutoff, folded network-wide, past which
no shard accepts a new old-committee cross-shard artifact from the halted shard
above the beacon-attested frontier. The beacon is the only actor honest-majority
(pool ratification), globally observed, and unforgeable by the halted committee,
so the cutoff is authenticated, not a per-consumer guess; structurally it is a
shard termination (the frozen committee is a cut, in-flight waves abort
— abort-dominant, so safe — attested finalizations carry, the fresh committee is
the successor), reusing the reshape/straddler machinery. `cross_shard_freeze`
checks it: with the fence, no new forgery crosses the cut and the residual is
bounded to the pre-fold detection-latency window; without it (the shipped state),
the leak is unbounded. The residual is genuinely irreducible — pre-freeze exports
are already finalized on honest shards and cannot be un-finalized, and the
attested frontier the fresh committee inherits is itself poisonable (a consumer
cannot distinguish a forged S-EC from a legitimate one). It is contained only in
that at f+1..2f the honest S co-signers recompute results (INV-DET), so what leaks
is *chain choice* between two internally-correct chains, not a forged execution
result: the stake-minting cascade still needs 2f+1 or tricked validators. So f+1
is a **recoverable liveness halt plus a bounded cross-shard exposure window the
freeze closes**, with the residual carried by prevention — which makes
`HALT_THRESHOLD` a safety parameter (a shorter window is a smaller exposure), not
only a liveness-latency knob, and makes the grind-hardening stack (b=16, FIFO,
jail-on-first, recency, pool hygiene) load-bearing for *safety* in this regime,
not merely defense-in-depth.

The **safety** threshold is a different animal. The equivocation route (f+1
double-signing two conflicting commits) is self-proving, so INV-SHARD-1's quorum
intersection catches the sibling commits and INV-SEC-3 revokes the keys — it
cannot produce a silent fork. But **2f+1** corrupt is *unilateral control*: it
commits a false state with a valid QC and **no** equivocation, so INV-SHARD-1
never fires, and no in-protocol verifier re-executes a committee it is supposed
to trust (INV-STATE-5 governs a node's own sync-vs-consensus consistency, not a
cross-committee check; a valid QC over a self-consistent false state passes every
soundness check downstream). It is an **unrecoverable** compromise: unilateral
control of one shard lets the adversary mint stake — the network-wide admission
gate — and cascade to every other shard. There is no recovery from 2f+1 and no
after-the-fact containment the design leans on; the entire defense is
**preventing the march from reaching it**. detect-and-rotate does not help — the
committee stays *live* while it lies (the corrupt vote for the false branch), so
a 2f+1 march never trips the halt detector.

So the two thresholds demand opposite defenses: f+1 a **recovery**
(detect-and-rotate), 2f+1 a **prevention** — keep the grind's sustained foothold
far below 2f+1 (Finding 11). And the prevention has to be real: the march to
2f+1 is reachable by grinding, ~4–6 days at β ≈ 0.10 with a large committee
(~2.5× the f+1 march), and with the input-side levers it is the *margin below
2f+1*, not any backstop, that stands between the design point and an
unrecoverable network compromise.

**Finding 10 — detect the halt and re-draw the whole committee: the recovery
for the f+1 liveness halt.** The f+1 liveness attack's outcome *is* a
*detectable* halt (Finding 9), so it can be defused at the outcome rather than
the input — the 2f+1 march is a different, terminal outcome this does not touch
(the committee stays live while it lies), which is prevention's job (Finding
11). The beacon already tracks each shard's
`last_live_epoch` — the epoch it last contributed a committed boundary
([`ShardBoundary`](../crates/beacon/src/state/reshape.rs)) — so a shard whose
watermark stalls for `HALT_THRESHOLD` epochs is, deterministically, halted. The
recovery is a **full re-draw** of that shard's committee: resample all n seats
fresh from the pool, not the one-seat trickle. That single move flushes the
concentrated f+1 foothold the grind spent days building.

The re-draw is grind-resistant exactly where the trickle is not. A fresh full
draw reaching f+1 is one hypergeometric event with a ~4.5e-14 tail at the
design point; best-of-`2^t` amplifies it only to ~3.7e-10 (t=13) — against the
trickle, where best-of-`2^t` drives each single-seat step to ~1 and the shard
marches. The grind's whole power is *incremental* accumulation across many
grind-certain steps; a full re-draw is a single event it cannot steer to f+1
(script table S). So the recovery restores an honest-majority committee with
overwhelming probability, even against a grinder timing the re-draw seed. It is
**outcome-triggered, not behavior-triggered**, which is why it succeeds where
the strike (Finding 7) fails: the strike must distinguish a grinder's
withholding from honest delay — the ambiguity that pins its crossover at ~1/3 —
while the rotation reacts only to the observable halt and asks nothing about
intent. The attacker economics collapse: ~1.7 days of grinding to reach f+1
buys a halt of at most `HALT_THRESHOLD` epochs plus a sync gap, then the
foothold flushes and the march restarts from ~β·n — a few-percent downtime on
*one* shard (the finite corrupt supply, Finding 8, bounds it to roughly one at
a time), for continuous grinding. No rational adversary runs it.

Design constraints, on the spec's terms:

- **Full re-draw, never a trickle** — the load-bearing choice. A trickle
  re-seed is grindable to a march; only a full fresh draw carries the ~1e-10
  resistance.
- **The trigger is deterministic and reshape-exempt** —
  `current_epoch − last_live_epoch > HALT_THRESHOLD`, with reshaping shards
  excluded (they are legitimately quiet). `HALT_THRESHOLD` sits above
  `RESHAPE_HANDOFF_TTL_EPOCHS` and the normal skip cadence — calibrated like
  the miss-counter thresholds, not guessed.
- **The recovery has a sync gap** — the fresh committee syncs the
  last-committed state (from the halted committee's honest 2f, or historical
  JMT), reusing the reshape make-before-break machinery. That gap is the
  residual outage.
- **The re-draw carries a cross-shard freeze** — the same detection fold that
  re-draws the committee revokes the old committee's cross-shard authority
  network-wide (Finding 9): past the freeze, no shard accepts a new
  old-committee execution certificate from the halted shard above the
  beacon-attested frontier. Without it the orphan a beyond-f committee can still
  certify (Finding 9) exports a forged wave finalization and cascades. The
  freeze is authenticated (a fold of the committed block, INV-BEACON-2) and
  structured as a shard termination — in-flight waves abort (abort-dominant, so
  safe), attested finalizations carry to the fresh committee — reusing the
  reshape/straddler machinery. It closes the leak *forward*; pre-freeze exports
  are irreversible, so the residual is the detection-latency window.
- **It rides beacon liveness** — the rotation is a fold of the committed beacon
  block (INV-BEACON-2), firing as long as the beacon commits (pool ratification,
  Finding 6). An adversary would have to halt the beacon itself, a separate,
  network-wide, far harder foothold.
- **No new authority** — trigger and re-draw are pure functions of
  `BeaconState`; rotation only reshuffles, never seats or grants, so it cannot
  become a grind lever. The re-draw is only as safe as a fresh draw at β (§1),
  so pool hygiene stays the underlying lever.

**Finding 11 — the grind width is set by tunable parameters, but a coupled
simulation shows they cap it only in the low-β band, not at the design point.**
Three knobs move the grind — beacon committee size `b` (which sets the width
`2^T`, `T ~ Binomial(b, β)`), the withholding penalty, and the shuffle interval
`I` — and it is tempting to read them as a parameter-choice *close*: shrink `b`
so most epochs the adversary holds 0–1 seats, jail-on-first for withholding to
hold the foothold at its natural (un-boosted) distribution, and free `I` for
adaptive corruption. The natural-foothold FIFO equilibrium
`c_T = n·E[1−(1−β)^{2^T}]` would then cap below f+1 (`grind_width_cap`:
`b=16 → 40 < 43`). But that reading assumes jail-on-first fully suppresses the
*resample boost* — the self-sustaining grind that steers the seed to
over-represent corrupt in the next epoch's committee draw, lifting `T` above its
Binomial mean. A coupled Monte Carlo (`sim_resample_boost`, script table T)
plays the boost out against the pool it actually draws from, and refutes the
close:

- **The boost survives jail-on-first at the design point.** The beacon committee
  redraws every epoch from `beacon_eligible()` — every `OnShard{ready}` validator
  network-wide, ~`shards·n` seats — so the corrupt supply is ~`β·shards·n` ≈ 1,300
  at the design point, and jail-on-first removes only the ~`T/2` members the
  winning grind pattern actually omits per epoch, for a cooldown. That drain
  cannot deplete a 1,300-seat supply: the eligible corrupt fraction stays near β,
  `best-of-2^T` still lifts `T` to ~3–4 even at `b=16`, and the realized `c_T` is
  **61 (b=16, liveness band) / 86 (b=20, safety band)** — far above the assumed
  40/49 (table T). Shrinking the *eligible pool* would restore the drain (at
  eligible ≈ 800 the boost collapses to `c_T` < f+1), but that is an
  architectural change with its own beacon-compromise cost, not the parameter
  tweak this finding tested.

- **Jail-on-first is clean but, for the same reason, weak.** The honest-purge
  fear is not realized: `sim_async_purge` (table T) holds the realized effective
  β at ~0.100 even at `p_async = 0.20`, against the `purge_beta_eff` worst-case
  ceiling of 0.10–0.11 — the `f+1`-shared commit
  ([`qc1_certify`](../crates/types/src/beacon/prefix_ops.rs)) makes an honest
  proposal un-excludable outside bounded async windows (Finding 7 correction).
  But the same large pool that makes jailing harmless to honest makes it too
  shallow a drain to catch enough grinders: it shaves the boosted foothold ~30%
  (`c_T` 88 → 61 at `b=16`) and closes the band **β ≲ 0.05**, but it is a
  bar-raise, not a design-point close.

- **The shuffle interval is not freed.** The "free `I`" argument rested on the
  width being capped; since the boost survives, `I` is a grind dial again — the
  march is linear in `I` (table M), so a small `I` is the grind's *worst* case
  and the §6 Rider 1 tension stands. Do not shrink `I` at the design point on
  grind grounds.

So the parameters do not *close* the grind at the design point — but what that
costs splits by threshold (Finding 9). For **f+1** (liveness) it is moot:
detect-and-rotate recovers the halt regardless. For **2f+1** (terminal,
unrecoverable) there is no recovery, so these input-side levers *are* the
defense, and their job is to hold the sustained foothold as far below 2f+1 = 85
as possible. That makes `b=16` **non-negotiable**, not merely preferable: at
`b=20` the sustained foothold reaches 86 ≥ 2f+1 — over the doom line — where
`b=16` holds it at 61. And the margin is thin: with the decided stack (b=16 +
FIFO + jail-on-first) the shard first crosses 2f+1 at β ≈ 0.12 (script table T),
*inside* the ≈0.13 the sampling budget tolerates, and at the design point β=0.10
the peak sits only ~3 seats under 85.

**Disposition.** The two thresholds are defended differently (Finding 9), with no
new cryptography. **f+1 (liveness)** is a recoverable halt: **detect-and-rotate**
re-draws the committee and flushes the foothold — the primary defense there, and
what makes the f+1 march a nuisance rather than a loss. **2f+1 (safety) is
terminal** — unilateral control of one shard is an unrecoverable network
compromise (mint stake, cascade) — so there is no recovery to lean on, and the
defense is entirely **prevention**: hold the grind's sustained foothold below
2f+1. The load-bearing levers are all input-side and stack additively: **`b=16`**
(non-negotiable — `b=20`'s sustained foothold reaches the 2f+1 line), **FIFO
eviction** (Finding 8, caps the shard equilibrium), **jail-on-first for
withholding** (Finding 7, clean under partial synchrony), a **recency-weighted
resample** (weight 0 right after serving, recovering additively over
`eligible/b` epochs — it caps the *sustained* foothold near natural `β·b` by
rate-limiting service, the single biggest margin-widener), and above all **pool
hygiene** (β low, §3, §6 Rider 2) — the deepest lever, since concentrating 2f+1
corrupt on one shard needs that many in play. Together they push the first 2f+1
crossing from β ≈ 0.12 (decided stack, without recency) to **β ≈ 0.14** (table
T) — outside the ≈0.13 the sampling budget tolerates — and leave a wide margin at
the design point where the decided stack had only ~3 seats. As implemented, the
recency ramp is **linear-additive** — a member's draw weight recovers by one step
per epoch over `eligible / committee_size` epochs, a full committee turnover —
chosen over a sharper cutoff because a sharper ramp makes the committee more
predictable (the §4 adaptive-corruption trade). Its jail-on-first synergy is
**realized by holding the withholding jail (`JailReason::Withholding`) for that
same recency period** rather than the short performance cooldown: the ramp alone
lands the first crossing at β ≈ 0.12, and the long jail — which removes the
omitting grinders from the eligible pool for a full turnover — is what depletes the
corrupt supply enough to reach β ≈ 0.14 (table T). Its cost is an aggressive
per-validator penalty (an honest member caught in a bounded async window is out for
a recency period), but the realized honest purge stays a rounding error (β_eff ≤
~0.11 even at `p_async = 0.20`, `sim_async_purge`). The shuffle interval is **not**
shrunk on grind grounds (the boost survives, so small `I` is grind-worst). Residuals: the beacon-committee
compromise rate (liveness/bias, rides pool ratification), the f+1
finality-latency window (consumer-side, bounded), and the thin design-point
margin below the terminal 2f+1 line.

**Both open items are resolved by the coupled simulations (Finding 11).** The
strike-limited resample boost was modelled directly (`sim_resample_boost`): it
survives jail-on-first at the true eligible-pool size, so `b` is not pinned by a
natural cap that does not hold — `b = 16` is chosen to keep the sustained
foothold below the terminal 2f+1 line, where `b = 20` reaches it. The
async-window purge was modelled against realized
synchrony (`sim_async_purge`): the realized honest purge is a rounding error for
any plausible `p_async`, well under the worst-case ceiling.
