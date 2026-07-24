# Committee Security under Sampling and Shuffling (INV-SEC-1)

Every safety property verified in this directory is conditional on INV-SEC-1:
no committee ever seats ≥ f+1 corrupt members. That premise is statistical,
not logical — the right instrument is concentration bounds and Markov
analysis, not a model checker. This note prices the premise; the companion
script ([committee_security.py](committee_security.py)) generates all
analytic tables (exact hypergeometric arithmetic, no dependencies), and the
Monte Carlo harness driving the production fold
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
100-shard network under 10⁻⁴/year. f+1 prices a *recoverable* event — a
degradation band, not a safety guarantee (above f the band is not safe:
withholding halts, and a fork through self-proving double-signing is
possible — §10.1); the unrecoverable boundary is 2f+1, priced separately in
§10.1.

**The quantity every table serves is a conversion rate**: from an
adversary's share of the pool to the single-shard control it can actually
achieve. Unsharded BFT is the 1:1 baseline — β of stake is β of the only
committee. Sampling holds every committee's *mean* at β while the adversary
attacks the max over shards; n concentrates each draw toward the mean (§1),
shard count compounds the tail (the per-shard-year × network accounting
above), and steering (§10) is what would collapse the rate toward one
shard's stake-cost. The resulting guarantee is probabilistic where
unsharded is a hard threshold: risk rises smoothly along the §3 cliff
rather than switching at ⅓. The system's claim is that the curve stays
security-competitive with the hard threshold while the network scales —
never that it beats it.

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
(§7). It is also deliberately *small* — b = 16 seats, sized in §10.5 —
which makes its per-draw compromise rate high (3.3e-3 at β = 0.10, table T)
and its severity low: epoch-commit safety rides the pool ratification
quorum (INV-BEACON-1), not this committee, and the epoch seed's grind
resistance is structural rather than a function of beacon honesty (§10.2),
so an over-threshold draw prices liveness degradation and fallback-path
bias exposure, never a fork. Table I shows what leaning on beacon honesty
would instead require — a shard-sized committee still needs β ≤ 0.111 at
the 10⁻⁶/year budget, nominally the tightest line in the system — which is
why nothing safety-bearing is routed through this committee beyond content
certification.

## 2. The trickle shuffle is a birth–death chain

One member rotates out per shard per shuffle interval, replaced from the
pool. The interval is derived, not stored:
`I(n) = max(1, ⌈SHUFFLE_SYNC_HEADROOM · ready_timeout_epochs / n⌉)`
(§6 Rider 1 — at the production sync budget, I(32)=8, I(128)=2, I(256)=1).
The committee's corrupt count k is then a Bernoulli–Laplace
birth–death chain whose stationary law is *exactly* the hypergeometric of §1
(detailed balance; asserted numerically in the script, measured against the
fold in §7). Failures are boundary crossings k = f → f+1; the stationary
crossing rate π(f)·p↑(f) per shuffle event, conservatively counting every
crossing as a compromise, gives expected compromises per shard-year (300s
epochs; the derived interval makes events/shard-year n-dependent — 13,149 at
n=32 up to 105,192 at n=256):

| n | β=0.05 | β=0.10 | β=0.15 | β=0.20 |
|---|---|---|---|---|
| 32 | 2.1e-04 | 0.36 | 12 | 83 |
| 64 | 7.8e-11 | 2.7e-04 | 0.32 | 17 |
| 96 | 3.1e-16 | 8.3e-07 | 0.021 | 5.9 |
| 128 | 1.1e-22 | 5.9e-10 | 5.4e-04 | 1.2 |
| 256 | 1.1e-47 | 3.8e-22 | 3.4e-10 | 1.7e-03 |

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
| 10⁻³ | 32 | 64 | 128 | — |
| 10⁻⁶ | 64 | 96 | 256 | — |
| 10⁻⁹ | 64 | 128 | 256 | — |

| budget | n=32 | n=64 | n=96 | n=128 | n=256 |
|---|---|---|---|---|---|
| 10⁻³ | β≤0.056 | 0.107 | 0.131 | 0.153 | 0.198 |
| 10⁻⁶ | β≤0.033 | 0.075 | 0.101 | 0.123 | 0.172 |
| 10⁻⁹ | β≤0.020 | 0.055 | 0.079 | 0.101 | 0.153 |

Boundary note: 96 at β=0.10 barely clears the 10⁻⁶ budget (1.2×); 128
clears it by three orders.

**β dominates n, and the cap makes that binding.** Going from
n=32 to n=256 (8× the seats, and the message-complexity price that implies)
only moves tolerable corruption from 3% to 17% at the 10⁻⁶ budget. With the
practical ceiling at 128, the pool must stay under ~12% corrupt seats — under
~10% if 96 is the operating point. Every mechanism that suppresses pool
corruption (the stake price, jailing, conviction, the sybil floor) buys more
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
  bites.** At a slow interval (I=16) the campaign still wins (0.63 even at
  pressure 16); at the derived operating interval (I(128)=2) it is forced
  onto the graded tail (P = 0.016 at pressure 64, 0.25 at pressure 85 — and
  85 concurrent attempts costs ~111 targeted corruptions/day, sustained).

**Fast rotation converts slow cheap corruption into fast expensive
corruption; it does not stop a fast adversary.** This is the
heuristic's qualitative claim, now exact. Under a fixed interval,
per-member tenure would grow with n, exposing larger committees more to
slow adaptation; the derived interval cancels exactly that — tenure is
pinned near `SHUFFLE_SYNC_HEADROOM · ready_timeout_epochs` (21.3h at the
production sync budget) whatever the committee size (§6). What the rate
heuristic misses entirely is the **budget-constrained** adversary.

**A budget-limited adversary gains materially from adapting, so the
sustained-pressure table J is a lower bound, not the worst case.**
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

**Honest overstaking is a security leak.** At c=5, an adversary
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
dynamic price). A seat that equivocates — a double-signed beacon ballot or a shard
double-vote — is permanently key-revoked on the self-proving evidence
(INV-SEC-3), its position forfeit though the stake is not slashed; the
shard-vote pair rides the beacon-witness channel to the fold (docs/05 §3).
Per-committee arithmetic ("43 seats") is the wrong frame:
sampling decides where seats land, so the adversary buys the pool fraction.

Two riders, without which 128 is not this strong:

**Rider 1 — rotation must scale, and the interval derives it.** Rotation
speed trades static security for adaptive resistance, and the trade is
lopsided: the static cost is linear in the rate (more draws per year), while
the adaptive gain is exponential (survival of a corruption attempt is
`(1−1/n)^(τ/I)`). A fixed interval cannot express the required `I ∝ 1/n`
coupling — at 300s epochs a 16-epoch interval parks a 128-seat shard's every
member for a week, and a multi-day corruption pipeline half-survives that
rotation. The fold therefore derives the interval from genesis config:
`I(n) = max(1, ⌈SHUFFLE_SYNC_HEADROOM · ready_timeout_epochs / n⌉)` —
rotation at the fastest cadence the ready margin allows (at most
`n / SHUFFLE_SYNC_HEADROOM` seats inside their sync budget concurrently,
the same bound on each seat's sync duty cycle) and no faster. Tenure
`n · I(n)` is thereby pinned at `≥ SHUFFLE_SYNC_HEADROOM ·
ready_timeout_epochs` for every n, and the production point lands at
I(128) = 2. Script table H sweeps the interval at n=128, β=0.10, τ=1,600
epochs (≈5.6 days) — the derived operating row is I=2:

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
**The interval remains a two-way trade, dominated by the adaptive side.**
Adaptive corruption wants `I` small: I=2 flushes a ~5-day pipeline to 0.4%
survival at ≈21h tenure (the 5-minute epoch puts sub-5h tenures out of
reach — even I=1 leaves 10.7h). The randomness grind wants `I` large — a
fork march is linear in `I` (§10 table M, priced at the derived interval) —
but that duty is confined to the fallback seed path, where sustaining a
march requires the self-announcing network-scale suppression of §10.4, and
to the window-edge residual, whose FIFO equilibrium is
interval-independent (§10.3). The derivation resolves the trade on the
adaptive side by construction; the fallback exposure is the residual §10
prices at I(n).

The handoff to accountability is computable. Rotation prices a campaign by
`survival ≈ e^(−τ/T)` with `T = n · I(n)` epochs of tenure (and survival
= 1 below two intervals — the readiness flush floor, §7). At the production
point T = 256 epochs: the half-line sits at τ½ ≈ 0.69·T ≈ 15h, and below
~T/10 (≈2h) rotation is inert (survival > 0.9). Faster-than-that
corruption is met by structure, not rotation: any fork must run through
self-proving double-signing, which the honest vote locks bias toward a halt
without precluding a double-commit across two consecutive equivocated
rounds (§10.1), and the halt is detected and re-drawn (§10.6). No
shard-level evidence pipeline exists — key revocation covers beacon
ballots only (docs/05 §3) — so the residual exposure is §10.1's bounded
window, and the accountability that does bind is jailing and
key-revocation, never slashing (§4 framing).

The mechanism is the shorter interval, *not* rotating k seats per batch,
for three reasons: a k-batch guarantees a synchronized dip of k unready
seats (staggered singles keep concurrent syncing at the steady-state
average — a 30-minute catch-up at I=2 is ~3 syncing of 128, ready set
125 ≥ quorum 85, and the L=1 freeze pre-positions each incomer anyway);
INV-SEC-2 ("at most one seat per shard per interval") and the fold's
victim/draw logic survive as written; and the birth–death model stays exact
(±1 steps), so this note's tables remain valid under interval scaling
without re-derivation.

**Rider 2 — β ≲ 0.12 is load-bearing**: at the derived operating interval
the 10⁻⁶ budget dies at β = 0.123, five points of β cost four orders of
magnitude, and nothing on the candidate grid rescues β ≥ 0.2 — pool hygiene
(pricing, jailing, conviction) is where the security actually lives. (The
beacon committee's own compromise rate is a severity question, not a fork
line — §1, §10.5.)

## 7. Idealizations, measured

The math above idealizes the fold in five ways. The Monte Carlo harness
(header note) drives the production `apply_epoch` over synthetic epochs with a
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
  measured at lags of zero, one, and two intervals (two is the cell's
  `ready_timeout_epochs`, the fold's ceiling with no witness at all; any lag
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
  fixed-β single-shard march (§10.4) *overstates* the grind on a real finite
  network — §10.5 prices the correction.
- **Corruption unit coarser than the seat.** Conditional on M corrupt seats
  the fold treats validators exchangeably, so clustering is invisible to
  every *seat-count* table here — an M-subset is an M-subset,
  correlation-invariant by linearity. What clustering changes is the *cost*
  of reaching M whenever the adversary's unit is coarser than one seat: a
  compromised machine (hacking) and a bribed controlling entity (bribery)
  each flip every seat they hold at once. Script table L prices it over one
  pool (N = 2,560 seats): under uniform 1-seat holders 315 must be subverted
  to reach the β = 0.123 boundary, but under a Zipf profile the largest
  holder already carries 16% of the pool — one machine, or one negotiation,
  clears it. **The protocol has no lever on the concentration.** It cannot
  attribute seats to a controlling entity: distinct stake-pool identities
  are indistinguishable from distinct entities — the same Sybil limit that
  makes stake, not identity, the admission gate — so a cap keyed on any
  observable identity is defeated by splitting it. Spread across independent
  operators and infrastructure is an operational premise the protocol cannot
  verify, the identity-only-selection fault-domain gap already noted at
  [06 §4](../docs/06-resource-economics.md). Accountability does not price this out:
  there is no slashing anywhere — principal is preserved (INV-SEC-3
  convicts; it does not confiscate), but provable equivocation — a beacon
  ballot or a shard double-vote — convicts the signer's whole *pool*: every
  key it operates permanently revoked, the pool retired, and its stake
  impounded for a governed span before it exits whole (docs/05 §3). That
  prices a floor of the capital's time-premium per caught pool — a bribe
  must cover it — though an adversary structured one seat per pool pays it
  per conviction and redeploys fresh capital freely, so it is a rental
  floor, not a burn; re-pricing this floor into the corruption march below
  is pending. So the defense against a bribed
  or hacked committee is structural, not economic: quorum intersection
  forces any fork through self-proving double-signed votes (INV-SHARD-1's
  mechanism, INV-STATE-5 halt-loudly), biasing a safety attack toward a loud
  liveness halt without precluding the fork (§10.1) — and the residual, an
  external consumer acting on one branch before the fork surfaces, is a
  bounded-exposure question, not a slashing one. Bribery is also the
  fast-adaptive limit of §4 (a negotiation,
  not a multi-day intrusion), so it lands in table J's τ→small rows where
  rotation cannot help either. Only the *buying* adversary is
  concentration-neutral: `min_stake` is charged per seat regardless, so §1–3
  hold in seats.
- **Crossing = compromise** stays conservative by choice. **Unbiased
  randomness** holds up to two priced residuals. On the primary path the
  epoch seed folds mandatory reveal leaves and the steering residual is a
  β-gated window-edge best-of-≈2 (§10.3) — on the §3 cliff that moves the
  crossing lines by well under half a point of β. An epoch where no chunk
  folds falls back to a grindable reveal ceremony (§10.4) — rare, and
  self-announcing when adversarially induced. The tables of §1–§8 price the
  unsteered draw; §10 prices both deviations.

## 8. Adversary synthesis — the computed worst case

The rate heuristic of §4 is replaced by exact computation on the
corrupt-count chain (script tables J–L). Three results, in ascending threat
sophistication:

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

## 10. Randomness: steering, the seed, and the two failure boundaries

Every table above prices an *unsteered* draw. A steerable seed voids those
prices wholesale: an adversary choosing among W candidate seeds converts a
per-event success p into 1−(1−p)^W, and against the trickle that converts the
stationary chain into a directed march — each single-seat step ground toward
"honest victim, corrupt entrant" and away from every corrupt-losing rotation.
Steering resistance, not entropy quantity, is therefore the load-bearing
property of the epoch seed. This section prices the two failure boundaries
steering aims at (§10.1), the seed and the residual steering it leaves
(§10.2–§10.3), the fallback seed path and the stack that bounds it
(§10.4–§10.5), and the recovery that defuses the lower boundary (§10.6).
§10.7 consolidates the defense.

### 10.1 The two failure boundaries: f+1 recovers, 2f+1 does not

Reaching f+1 corrupt on a shard is where the BFT guarantees lapse, but the
two boundaries could hardly differ more.

**f+1 opens a degradation band; withholding is a liveness halt with a
bounded cross-shard exposure window.** With f+1 corrupt withholding, the
remaining ≤ 2f honest seats are short of the
2f+1 quorum: other shards keep committing, the local chain stops. The halt is
the recoverable outcome — detect-and-rotate (§10.6) re-draws the committee —
but it is not cleanly contained while it lasts (Model G, `recovery_bridge`
and `cross_shard_freeze`). Two mechanisms leak. First, the halted committee
is beyond f *by construction*, so with one lagging honest member (an unfolded
beacon, reachable under partition) the corrupt f+1..2f can form a quorum and
extend the halted tip on an orphan branch. Its QC weighted timestamp is the
clamped **mean** of wall-clock vote stamps
([`vote_set.rs`](../crates/shard/src/vote_set.rs)), and a beyond-f committee
is an honest *minority* in its own quorum, so the corrupt drag that mean
arbitrarily below wall-clock — past the one-window tolerance the recovery
bridge's certified re-bind is calibrated for, a tolerance sized for an
adversarial *minority* (the ≤ f case). The orphan resolves the *old*
committee at a folded replica and its signatures verify: a stale two-chain
commit past the tip. Second, that orphan **exports cross-shard**: a consuming
shard resolves the source committee for an execution certificate by its
anchor window
([`lookup(ec.vote_anchor_ts())`](../crates/execution/src/coordinator.rs)), so
a stale-anchored forged EC resolves the old committee and finalizes a wave —
an INV-EXEC-1 break that cascades.

What bounds the leak is the **beacon-mandated freeze** (§10.6): at the
detection fold the beacon stamps a cutoff, folded network-wide, past which no
shard accepts a new old-committee cross-shard artifact from the halted shard
above the beacon-attested frontier. The beacon is the only actor that is
honest-majority (pool ratification), globally observed, and unforgeable by
the halted committee, so the cutoff is authenticated, not a per-consumer
guess; structurally it is a shard termination (the frozen committee is a cut,
in-flight waves abort — abort-dominant, so safe — attested finalizations
carry, the fresh committee is the successor), reusing the reshape/straddler
machinery. `cross_shard_freeze` checks both directions: with the fence the
residual is bounded to the pre-fold detection-latency window; the no-fence
twin leaks without bound. The residual is genuinely irreducible — pre-freeze
exports are already finalized on honest shards and cannot be un-finalized,
and the attested frontier the fresh committee inherits is itself poisonable
(a consumer cannot distinguish a forged source-EC from a legitimate one). It
is contained only in that at f+1..2f the honest co-signers recompute results
(INV-DET), so what leaks is *chain choice* between two internally-correct
chains, not a forged execution result: the stake-minting cascade still needs
2f+1 or tricked validators. So the withholding route is a recoverable
liveness halt plus a bounded exposure window — which makes
`HALT_THRESHOLD` a safety parameter (a
shorter window is a smaller exposure), not only a liveness-latency knob, and
makes the hardening stack of §10.5 load-bearing for *safety* in this regime,
not merely defense-in-depth.

**The middle band can also fork, and no beacon detector flags the fork
itself.** With f+1..2f corrupt, two conflicting commits require f+1
double-signed votes in each of two consecutive rounds: the honest locks
force the attack through self-proving equivocation — biasing it toward the
halt above — but do not preclude the double-commit. Those double-votes are
prosecuted: a replica holding both assembles self-proving evidence that
rides self-authenticating global gossip to the beacon's proposal lane and
permanently convicts the signer's pool (docs/05 §3) — best-effort, since an equivocator splitting
its votes across separate collectors leaves no single replica with the
pair. What nothing flags is the *fork itself*: the §10.6 trigger watches
for a *quiet* watermark an actively forking shard never shows, and the
boundary fold canonicalizes one crossing per shard per epoch
(INV-BEACON-5) without surfacing a conflicting sibling. The band's
containment is structural — honest co-signers recompute execution results,
so what forks is chain choice — plus the key-revocation accountability
above and the recovery once the fork collapses into the halt signature;
"safe between f+1 and 2f" is not a claim this note makes anywhere.

**2f+1 is unilateral control, and it is terminal.** The middle band's fork
is at least self-evidencing — quorum intersection forces it to leave
double-signed votes, so it cannot fork silently. But 2f+1 corrupt commits
a false state with a valid QC and **no** equivocation, so nothing
self-proving ever exists, and no in-protocol verifier re-executes a
committee it is supposed to trust (INV-STATE-5 governs a node's own
sync-vs-consensus consistency, not a
cross-committee check; a valid QC over a self-consistent false state passes
every soundness check downstream). Unilateral control of one shard mints
stake — the network-wide admission gate — and cascades to every other shard.
There is no recovery and no after-the-fact containment; the entire defense is
preventing the approach. Detect-and-rotate does not help — the committee
stays *live* while it lies (the corrupt vote for the false branch), so a 2f+1
march never trips the halt detector.

The two boundaries therefore get opposite defenses — f+1 a **recovery**
(§10.6), 2f+1 a **prevention** (§10.5, §10.7) — and different budgets. How
far the terminal boundary sits *without* steering fixes what prevention
actually defends (script table V, the k = 2f → 2f+1 crossing on the §2 chain
at n = 128):

| terminal budget (crossings/shard-yr) | max β |
|---|---|
| 10⁻³ | 0.436 |
| 10⁻⁶ | 0.386 |
| 10⁻⁹ | 0.346 |

Unsteered sampling essentially cannot produce the terminal event: the 10⁻⁶
budget tolerates β ≤ 0.386 — three times the f+1 line (0.123, §3). That is
a risk bound on the unsteered draw, not a comparative claim against an
unsharded chain: steering voids it, which is what the rest of this section
prices. The system has two β lines, not one. **Healthy, β ≲ 0.12**: the
f+1 budget holds and halts are negligible. **Sound, β ≲ 0.39**: in the
band between, the network
degrades without breaking — at β = 0.40 the f+1 boundary is crossed ~250 times
per shard-year and the stationary mean corrupt count β·n ≈ 51 exceeds f, so
shards halt, re-draw, and pay detection-latency exposure windows more or less
continuously — but unilateral control never assembles. The tables of §1–§6
price *availability*; survival is priced here. The corollary: steering is the
only route to 2f+1 at plausible β, so prevention's whole job is keeping the
*steered* dynamics below a boundary the unsteered draw cannot reach — and on
the cliff's slope (roughly 4× per point of β) even a residual best-of-2 per
event moves these lines by well under half a point.

### 10.2 The seed: reveal leaves in the beacon-witness accumulator

Every shard block carries a **mandatory reveal leaf**: the proposer's
deterministic hash-based VRF over `(shard, height)` — unforgeable and
unchooseable (fixed by key and slot before the epoch), verified by the shard
committee at block validation — appended to the per-shard beacon-witness
accumulator the chain already maintains. The epoch seed folds each crossing
shard's watermark-to-boundary leaf range `[prior, chunk_end)`, the exact
range the beacon already applies to mutate its own state, verified
leaf-by-leaf against the 2f+1-certified `beacon_witness_root`.

Two properties fall out with no new assumption. **There is no include/omit
lever:** the folded set is a consensus-derived range, not a per-member
choice, and a block without its valid reveal leaf is invalid — "propose or
forfeit the slot" replaces "append or quietly omit." **Interior leaves are
blind unconditionally:** a leaf at accumulator position p is chain-attested
to precede everything after it, so when a proposer commits an interior reveal
the later leaves that will join the fold *do not yet exist*. This is a fact
about certified accumulator position, not a network-timing assumption — the
property header- and aggregate-blinder designs lack (rejected: both need a
partial-synchrony race and a shard-count threshold to make dilution
load-bearing, where the accumulator needs neither).

Costs and edges. The randomness fold reads the *same* verified chunk stream
that already mutates `BeaconState`, so it introduces no new divergence
source — but it upgrades the blast radius of the witness window arithmetic
(base freeze, chunk bounds, terminal re-fold exemptions) from witness-state
corruption to a committee-selection fork. That arithmetic is model-checked
through window, reshape, and recovery churn (Model H,
[witness_fold.qnt](witness_fold.qnt)). Leaf-value uniqueness under
adversarial key generation reduces to chain-hash collision resistance
(already load-bearing across the PQ stack; seed-derived signature masks at
registration harden it further). Binding the reported boundary QC to the
committed child (`parent_qc` pinning) closes the sibling-certificate wiggle
the edge pricing below conservatively absorbs, and benefits witness
integrity generally.

### 10.3 The residual: the window edge

The steering that survives is confined to the **window edge**. The proposers
who close the last epoch windows still open when the rest of the fold has
settled can rush or sandbag the boundary within the ~32 s timestamp-validity
window — choosing among a handful of *known* candidate folds — or forfeit the
slot for a blind redraw by an unknown successor. Tables W1–W3 price that edge
(`witness_edge_p_event`) on the same march and FIFO-equilibrium machinery as
§10.4–§10.5, granting the adversary a zero-latency full-sight network (no
dilution credited — the structural worst case): the per-event grind is a
**β-gated best-of-≈2** held only when the adversary occupies a cut slot,
versus the ceremony's certain best-of-2^t every epoch. The width exponent
falls from β·b to β·m, with m (the number of cut-racing windows) small and
m ≪ b. The edge sits strictly below the ceremony at every shard count
(n = 128, β = 0.10: per-event 0.10–0.13 vs 0.31; march 15–19 d vs 6 d even at
full sight), its network FIFO equilibrium stays far below f+1 across the
tolerated band at every m (table W3: c_T ≤ ~26 through β = 0.13, where the
ceremony forks everywhere), and the terminal 2f+1 is never approached
anywhere on the grid. Because the residual is sub-baseline without any
dilution credited, the scheme is complete on its own — no shard-count
threshold and no separate header/aggregate blinder — and any real network's
cross-shard closing race only dilutes the edge further.

A variant tightens the edge (table W4). Anchoring the fold's upper cut to a
*fixed schedule line* `T_cut = boundary − Δ` (`Δ ≥ MAX_TIMESTAMP_DELAY`),
folding each reveal by its aggregated weighted timestamp rather than by the
boundary block's own leaf count, lets the timestamp-validity constants
(`MAX_TIMESTAMP_RUSH = 2 s`, `MAX_TIMESTAMP_DELAY = 30 s`) *prove* the bulk
of the fold un-contestable: ~99 % of the reveals fall outside the ≈ β·32 s
drag band and are sealed regardless of the adversary's sight. The residual
becomes a sight-independent β-gated best-of-2 ceiling (the boundary-anchored
edge grows with sight; this does not) and the single-proposer slide of
`chunk_end` disappears — contesting the line needs corrupt *weight* to drag
an aggregated WT, not one slot. The width gain at the design point is
marginal (best-of-2 either way); the value is robustness. The cost is a
WT→position cutoff in place of a count range — more fork-critical window
arithmetic — and a one-epoch lag on the last ≈ β·32 s of reveals (they fold
in the next epoch; no entropy is lost). The boundary-anchored cut is the
design here — already sub-baseline — with the WT anchor held as the
tightening if the edge ever needs it.

### 10.4 The fallback: a reveal ceremony, and what a grinder does to one

In an epoch where no witness chunk folds — genesis before the first crossing,
or every shard's crossing suppressed at once, which spikes every miss counter
and trips the halt detector (§10.6): loud, network-scale, never a quiet
per-epoch option — the seed falls back to the beacon ceremony's reveal mix:
`BLAKE3(prev_randomness ‖ VRF outputs of the committed beacon-committee
proposals)`, rolled immediately before the shuffle victim, the shuffle
entrant, the beacon resample, and pool draws read it
(`filter_and_roll_randomness`, crates/beacon/src/state/vrf.rs). A bare
`BLAKE3(prev)` would be a predictable seed, so the fallback keeps the mix —
and the mix is what a grinder can steer. This subsection prices that.

A Byzantine beacon member cannot *choose* its VRF output — it is a fixed
function of `(key, epoch)` — but it can choose whether that output joins the
fold: reveal early and it is folded; withhold and its slot commits as
`BOTTOM`, unfolded. Because the PC input vector is dense and commits interior
`BOTTOM`s without truncating (`compute_view_input`, `qc1_certify`), the
include/omit toggle is independent per member and does not shorten the
committed prefix. With t such proposals held for late-but-included release,
the adversary observes the honest reveals, enumerates the 2^t candidate
seeds, computes the committee each yields (ChaCha20 is a PRF, so distinct
seeds are independent uniform draws), and steers the commit to the best one.
**Grind width = 2^t**, one global best-of-2^t draw per epoch, one-epoch
lookahead.

Committee size does not dilute this. The seed is a hash: flipping one folded
input swaps the entire output for a fresh uniform value, and the honest
majority's reveals sit identically inside every candidate seed — a shared
constant that does not distinguish the adversary's options. The defect is
**move-order, not entropy quantity**: honest contributors reveal first, then
the adversary chooses which of its own contributions count, so it moves last.
"One honest unpredictable contribution randomizes the seed" holds only for a
beacon whose contributors commit *before* any reveal; a reveal-first ceremony
hands the last mover the menu. t is bounded by the Byzantine beacon-committee
count — natural mean β·b ≈ 1.6 at b = 16 (§10.5), lifted to ~3–4 by the
resample boost (table T) — and the realized value is how many proposals
synchrony lets the adversary hold back and release late-but-included.

**Sustained, the grind marches the trickle to a fork.** On one targeted
shard, a single seed gives P[honest victim ∧ corrupt entrant] ≈ (1−β)·β ≈
0.09 per event. Best-of-2^t drives that to 0.78 at t = 4 and ≈ 1 by t ≥ 6,
and the adversary simultaneously grinds *away* from any corrupt-losing
rotation, so the shard's corrupt count climbs monotonically toward f+1 — and,
at ~2.5× the time, toward the terminal 2f+1. Script table M, at n = 128,
β = 0.10:

| grind width t | candidate seeds 2^t | days to march β·n → f+1 |
|---|---|---|
| 2 | 4 | ~6.0 |
| 3 | 8 | ~3.5 |
| 4 | 16 | ~2.3 |
| ≥6 | ≥64 | ~1.7 (deterministic floor) |

The materiality threshold t ≈ 3–4 is exactly where the boosted foothold sits,
so a ceremony-seeded march runs at the ~2–3.5 day rows; the corrupt pool
(β·20n ≈ 256 seats) covers one shard's 43 seats. Severity is sharply
β-sensitive: width is 2^t and t tracks the foothold, so the grind is potent
at β ≈ 0.05–0.10, marginal near β ≈ 0.03, and largely defeated below ≈ 0.01 —
and the system tolerates β up to ≈ 0.10–0.13 (§6), so at the design point an
unconfined ceremony would bite. It does not relax INV-SEC-1's honest-pool
premise — it means the premise alone would not imply honest committees,
because the draw a grinder sees is not the draw the tables price. The beacon
resample itself amplifies but does not fork: even at a shard-sized beacon
committee (128 seats of eligible ≈ 12,800) and t = 13, best-of-2^t lifts the
per-epoch resample tail only to ~2e-4/network-year (table N), and
epoch-commit safety rides pool ratification (INV-BEACON-1) regardless — the
resample's real contribution to the threat is the positive feedback that a
grind-seated beacon committee grinds the next epoch harder (the boost,
§10.5).

### 10.5 Bounding the fallback: the input-side stack

Four levers bound the ceremony grind. Each is exact about what it does and
does not close.

**Withholding is charged: jail-on-first.** A member absent from the committed
set is attributable: the expected proposer set is the beacon committee the
previous fold seated, so absence is a strike against a consensus-known set
(`filter_and_roll_randomness`, crates/beacon/src/state/vrf.rs), riding beside
the fold with no wire field (the VRF output is already a commitment) and
inert under full participation. Absence is ambiguous in principle — a
withheld proposal and one delayed past view formation are byte-identical, and
the threat model grants message-timing control — but the ambiguity does not
force a lenient threshold, because the protocol is leaderless: the committed
value is the deepest prefix shared by f+1 of the 2f+1 votes
([`qc1_certify`](../crates/types/src/beacon/prefix_ops.rs)), so an honest
proposal reaching a supermajority is committed whoever formed their input
before it arrived. Making an honest member absent requires keeping its
proposal from f+1 members — broad, sustained censorship possible only inside
bounded async windows (docs/05 partial synchrony) — while a grinder is absent
by *self-omission*, always. Jail-on-first therefore jails the self-omitting
grinder while sparing honest proposers: the realized honest purge is a
rounding error (`sim_async_purge`, table T — effective β ≈ 0.100 even at
p_async = 0.20, against a worst-case ceiling of 0.10–0.11). The withholding
jail (`JailReason::Withholding`) is held for a full recency period (below)
rather than the short performance cooldown.

**The jail is clean but shallow.** The beacon committee redraws every epoch
from `beacon_eligible()` — every `OnShard{ready}` validator network-wide,
~shards·n seats — so the corrupt supply is ~β·shards·n ≈ 1,300 at the design
point, and jail-on-first removes only the ~t/2 members the winning grind
pattern actually omits per epoch. That drain cannot deplete the supply: the
**resample boost** — steering this epoch's seed to over-represent corrupt in
the next epoch's beacon draw, lifting t above its Binomial mean — survives it
(`sim_resample_boost`, the coupled Monte Carlo of table T). The natural
foothold t ~ Binomial(b, β) would cap the FIFO target equilibrium below f+1
at b = 16 (`grind_width_cap`: c_T = 40 < 43); the boosted foothold realizes
c_T = 61 at b = 16 and 86 at b = 20. Shrinking the *eligible pool* to ~800
would restore the drain and collapse the boost — rejected: an architectural
change with its own beacon-compromise cost, far beyond a parameter choice.

**FIFO eviction converts the march into an equilibrium.** The single-shard
march prices one targeted shard drawing from an inexhaustible pool; on a real
network the corrupt population is conserved (M = β·N seats) and the pool is
finite and shared, so forking one shard concentrates f+1 ≈ n/3 corrupt there
— most of a small network's total, fought over by every other shard's draws —
and M ≤ f is a structural floor plus a competition drag (the concentration
breaks the exchangeability §7's mean-field relies on). Deterministic-longest
(FIFO) eviction then removes the foothold's protection: where a victim-grind
scheme steers honest seats out to keep corrupt ones (marching monotonically
whenever supply permits), FIFO gives every seat a fixed n-event tenure, so
freshly-seated corrupt age out on a clock the adversary cannot stop and the
target settles at `c_T = n·(1−(1−x)^W)` (x = pool corrupt fraction, W = grind
width) instead of marching, forking only if that equilibrium clears f+1
(script table R, validated against the conserved-population Monte Carlo
`check_grind_network`). FIFO caps below f+1 for β ≲ 0.025 alone and β ≲ 0.05
stacked with jail-on-first; at β ≈ 0.10 the boosted width makes the per-event
seat rate ≈ 1, so c_T ≈ n and FIFO alone does not hold the design point. Its
cost is a mild adaptive-corruption concession — deterministic tenure makes
the rotation schedule predictable, a bite a shorter interval blunts.

**A small beacon committee and a recency-weighted resample set the width.**
b = 16 holds the boosted sustained foothold at c_T = 61 — below the terminal
2f+1 = 85 — where b = 20 realizes 86, over the line (table T); the price of
smallness is a higher per-draw beacon-compromise rate (3.3e-3 at β = 0.10),
which §1's severity split makes affordable — liveness and fallback-bias
exposure, never epoch-commit safety. The recency weight caps the *service
rate*: a member's draw weight is zero right after serving and recovers
additively over eligible/b epochs (a full committee turnover), so a corrupt
seat depletes its own weight and the *sustained* foothold pins near the
natural β·b — the single biggest margin-widener, and a rate limit the huge
eligible supply does not defeat. The ramp is linear-additive rather than a
sharp cutoff (a sharper ramp makes the committee more predictable — the §4
adaptive trade), and its synergy with jail-on-first comes from matching the
withholding jail to the recency period. At the derived interval the stack's
margin is thinner than the sustained line alone suggests: recency roughly
halves the sustained foothold at the design point (c_T = 34 at β = 0.10
under the full stack, against the no-recency 59) and trims the burst peaks
(73 against 81, with 2f+1 = 85), but the full stack's first 2f+1 *peak*
crossing sits at β ≈ 0.12 — level with the ≈ 0.12 the sampling budget
itself tolerates, not outside it (table T). The terminal margin therefore
rests on the sustained line, pool hygiene, and §10.4's suppression cost
rather than on peak headroom. The honest cost of the long jail stays the
rounding-error purge above.

**What the stack does not do** is close the ceremony grind outright: at the
design point the boosted width still lifts every trickle step, and any
ceremony-seeded epoch is a best-of-2^t draw. The stack's job is narrower and
sufficient. The ceremony seeds only zero-crossing epochs (§10.4), so a
*sustained* ceremony march requires suppressing every shard's crossings epoch
after epoch — a self-announcing, network-scale attack that trips the halt
detector — and within any such window the stack holds the *sustained*
foothold below the terminal line at the design point (peak margin is the
thinner line — table T commentary). On the primary path the
same stack is defense-in-depth behind a seed with no toggle to grind (§10.2).

### 10.6 The f+1 recovery: detect the halt, re-draw the committee

The f+1 liveness attack's outcome *is* a detectable halt (§10.1), so it is
defused at the outcome rather than the input — the 2f+1 march, whose
committee stays live while it lies, is prevention's job (§10.5, §10.7). The
beacon already tracks each shard's `last_live_epoch` — the epoch it last
contributed a committed boundary
([`ShardBoundary`](../crates/beacon/src/state/reshape.rs)) — so a shard whose
watermark stalls for `HALT_THRESHOLD` epochs is, deterministically, halted.
The recovery is a **full re-draw** of that shard's committee: resample all n
seats fresh from the pool, not the one-seat trickle. That single move flushes
the concentrated f+1 foothold a grind spends days building.

The re-draw is grind-resistant exactly where the trickle is not. A fresh full
draw reaching f+1 is one hypergeometric event with a ~4.5e-14 tail at the
design point; best-of-2^t amplifies it only to ~3.7e-10 at t = 13 — against
the trickle, where best-of-2^t drives each single-seat step to ~1 and the
shard marches. A grind's whole power is *incremental* accumulation across
many near-certain steps; a full re-draw is a single event it cannot steer to
f+1 (script table S). So the recovery restores an honest-majority committee
with overwhelming probability, even against a grinder timing the re-draw
seed. It is **outcome-triggered, not behavior-triggered**, which is why it
succeeds where the withholding charge alone cannot (§10.5 must distinguish a
grinder's withholding from honest delay; the rotation reacts only to the
observable halt and asks nothing about intent). The attacker economics
stay bounded rather than collapsing outright: at the derived interval the
march to f+1 takes ~0.2 days of grinding, buying a halt of at most
`HALT_THRESHOLD` epochs plus a sync gap before the foothold flushes and the
march restarts from ~β·n — sustained, roughly a quarter downtime on *one*
shard (the finite corrupt supply, §10.5, bounds it to roughly one at a
time). What keeps that unattractive is not the duty cycle alone: every
cycle requires re-suppressing the shard's crossings network-wide (§10.4 —
self-announcing), the yield is a recurring halt whose safety residual is
the bounded exposure window of §10.1, and each flushed foothold burns
withholding-jailed keys on the fallback path.

Design constraints:

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
- **The re-draw carries the cross-shard freeze** — the same detection fold
  that re-draws the committee revokes the old committee's cross-shard
  authority network-wide (§10.1): past the freeze, no shard accepts a new
  old-committee execution certificate from the halted shard above the
  beacon-attested frontier. Without it the orphan a beyond-f committee can
  still certify exports a forged wave finalization and cascades. The freeze
  is authenticated (a fold of the committed block, INV-BEACON-2) and
  structured as a shard termination — in-flight waves abort (abort-dominant,
  so safe), attested finalizations carry to the fresh committee — reusing the
  reshape/straddler machinery. It closes the leak *forward*; pre-freeze
  exports are irreversible, so the residual is the detection-latency window.
- **It rides beacon liveness** — the rotation is a fold of the committed
  beacon block (INV-BEACON-2), firing as long as the beacon commits (pool
  ratification). An adversary would have to halt the beacon itself, a
  separate, network-wide, far harder foothold.
- **No new authority** — trigger and re-draw are pure functions of
  `BeaconState`; rotation only reshuffles, never seats or grants, so it
  cannot become a grind lever. The re-draw is only as safe as a fresh draw at
  β (§1), so pool hygiene stays the underlying lever.

### 10.7 Disposition

The seed's primary path is structural. The range fold removes the
include/omit lever and blinds interior reveals with no network assumption
(§10.2); the residual is the window edge — a β-gated best-of-≈2, below the
ceremony baseline at every shard count, whose network FIFO equilibrium stays
far below f+1 across the tolerated band and never approaches the terminal
2f+1 (§10.3, tables W1–W3). No new cryptography anywhere in the defense.

The fallback ceremony is confined to zero-crossing epochs — rare, and
self-announcing when adversarially induced — and hardened by the input-side
stack (§10.5): b = 16 (b = 20's sustained foothold reaches the terminal
line), FIFO eviction, jail-on-first with the withholding jail held for a full
recency period, and the recency-weighted resample, under which the sustained
foothold pins near natural β·b and the first 2f+1 peak crossing sits at
β ≈ 0.12 — level with the 0.123 the sampling budget tolerates (table T).

The two failure boundaries are defended apart (§10.1). **f+1** opens the
recoverable band: withholding is a detected halt — detect-and-rotate
re-draws the committee and flushes the foothold (§10.6), the cross-shard
freeze bounding the exposure window to detection latency — while the band's
fork case has no beacon-fold detector and is contained structurally,
its double-signs key-revoked when caught (§10.1). **2f+1**
is terminal, so its defense is entirely
prevention: the seed, the stack, and above all **pool hygiene** (§3, §6
Rider 2) — the deepest lever, since concentrating 2f+1 corrupt on one shard
needs that many corrupt seats in play at all.

The shuffle interval's grind duty is confined to the fallback path (a march
is linear in I, but sustaining one requires the self-announcing suppression
above) and the window edge (whose FIFO equilibrium is interval-independent),
so the interval trades chiefly against adaptive corruption — §6 Rider 1
carries that trade.

Residuals, priced above: the window-edge lever (§10.3); fallback-epoch bias
exposure (one best-of-2^t draw per zero-crossing epoch); the
beacon-committee compromise rate (liveness/bias only — pool ratification
carries commits, and the seed's grind resistance no longer rides beacon
honesty); the f+1 detection-latency exposure window (§10.1, §10.6); and the
witness window arithmetic's upgraded blast radius (a fold divergence is a
committee-selection fork — Model H stands guard).
