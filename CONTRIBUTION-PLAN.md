# Hyperscale-RS — Contribution Plan
> bigdev (@bigdevxrd) | Updated: 2026-04-09

## The Opportunity

Hyperscale-rs is a 55,812-line Rust BFT consensus protocol with Radix Engine integration. 28 crates, 738 tests, active development (10 commits Apr 8, 5 PRs merged in 2 weeks). The maintainer tagged 21 open issues and explicitly asked for contributions ("try to break it").

We posted a detailed security audit on #22 (unbounded data structures) — first external contribution. No response yet but the team is clearly active. Hashlock (security firm) is also watching the repo.

## Codebase Profile

| Metric | Value |
|--------|-------|
| Total Rust LOC | 55,812 |
| Crates | 28 |
| Tests | 738 |
| Open Issues | 21 |
| Recent PRs | 5 merged in 2 weeks |
| CI | GitHub Actions (check, test, clippy, Docker, release) |
| Key Dependency | Radix Engine (forked radixdlt-scrypto) |

### Crate Complexity (where to focus)

| Crate | LOC | Risk | Our Skill Fit |
|-------|-----|------|---------------|
| **bft** | 11,925 | Highest — core consensus | Strong (Rust + protocol knowledge) |
| **types** | 7,157 | Foundation — changes ripple everywhere | Medium (careful, low risk) |
| **execution** | 2,776 | Cross-shard wave execution | Strong (we understand Radix execution) |
| **mempool** | 2,151 | Our audit target | Strong (we identified the bugs) |
| **engine** | 2,083 | Radix Engine integration | Very strong (Scrypto expertise) |
| **livelock** | 1,524 | Deadlock detection | Medium |
| **node** | 1,840 | I/O loop composition | Medium |

## Contribution Path (Ordered by Impact × Feasibility)

### Phase 1: Establish Credibility (Weeks 1-2)

#### PR #1: Bounded Mempool Pool (Issue #22)
**Target:** `crates/mempool/src/state.rs`
**Problem:** `pool: BTreeMap<Hash, PoolEntry>` has no size limit. `DEFAULT_IN_FLIGHT_LIMIT` (12,288) only throttles proposals, doesn't evict.
**Fix:**
1. Add `max_pool_size: usize` to `MempoolConfig` (default: 50,000)
2. Add `fn maybe_evict(&mut self)` called after every `pool.insert()`
3. Eviction strategy: FIFO by `PoolEntry.created_at` (simplest, least controversial)
4. Add metric: `mempool_pool_size` gauge
5. Add test: pool grows to limit, then evicts oldest on next insert

**What to read first:**
- `crates/mempool/src/state.rs` lines 1-50 (struct + config)
- `crates/mempool/src/state.rs` search for `.insert(` (insertion points)
- `crates/core/src/lib.rs` for `Action` enum (if we need new actions)

**Estimated effort:** 4-6 hours
**Risk:** Low — mempool is self-contained, doesn't affect consensus
**Why first:** Directly addresses our audit finding. Clean, testable, non-controversial.

#### PR #2: Livelock Tombstone Cleanup (Issue #22)
**Target:** `crates/livelock/src/state.rs`
**Problem:** `tombstones: HashMap<Hash, Duration>` has no cleanup loop despite `tombstone_ttl` config.
**Fix:**
1. Add `fn cleanup_tombstones(&mut self, committed_height: u64)` matching the pattern in `mempool::cleanup_old_tombstones()`
2. Call from node's commit path (in `crates/node/src/state.rs`)
3. Add metric: `livelock_tombstone_count` gauge
4. Add test: tombstones are cleaned after retention period

**Estimated effort:** 2-3 hours
**Risk:** Low — cleanup is additive, doesn't change livelock logic
**Why second:** Small, clean, directly from our audit. Builds trust.

### Phase 2: Deeper Contributions (Weeks 3-4)

#### PR #3: Execution Early State Cleanup (Issue #22)
**Target:** `crates/execution/src/state.rs`
**Problem:** `early_provisioning_complete`, `early_certificates`, `early_votes` leak entries when blocks are orphaned.
**Fix:**
1. In `prune_execution_state()`, add age-based cleanup for all `early_*` maps
2. Remove entries where block height < `committed_height - 100`
3. Add bounded capacity to inner `Vec` (cap at 1000 entries per key)
4. Add tests for orphaned block cleanup

**Estimated effort:** 4-6 hours
**Risk:** Medium — execution state is more delicate, needs careful testing
**Why third:** Completes the #22 audit triage. Three PRs = comprehensive fix.

#### PR #4: Benchmarks (Issue #15)
**Target:** New `benches/` directories in key crates
**Problem:** No benchmarks exist. Can't measure impact of changes.
**Fix:**
1. `crates/bft/benches/` — vote aggregation, QC formation (hot path)
2. `crates/mempool/benches/` — insert/evict/propose (with our bounded fix)
3. `crates/execution/benches/` — vote tracking, certificate formation
4. Use `criterion` crate for statistical benchmarks
5. Add to CI as optional step

**Estimated effort:** 6-8 hours
**Risk:** Low — additive, no logic changes
**Why fourth:** Demonstrates engineering maturity. Every future PR can show perf impact.

### Phase 3: Protocol-Level Contributions (Months 2-3)

#### PR #5: Transaction/Substate Test Suite (Issue #18)
**Target:** `crates/simulation/tests/`
**Problem:** No dedicated test suite for transaction lifecycle through the full stack.
**Fix:**
1. Single-shard transaction: submit → propose → execute → commit
2. Cross-shard transaction: submit → provision → execute → certify → commit
3. Conflicting transactions: two txns touching same substates
4. Byzantine proposer: invalid blocks, duplicate proposals
5. Network partition: shard isolated, then reconnected
6. Property-based tests with `proptest` for transaction ordering invariants

**Estimated effort:** 2-3 sessions
**Risk:** Medium — requires deep understanding of the full protocol
**Why fifth:** High value, establishes us as protocol experts

#### PR #6: Fee Model Design (Issue #17)
**Target:** New `crates/fees/` or integrated into execution
**Problem:** No fee mechanism in sharded RE. Who pays? How is it split across shards?
**Approach:**
1. Research: how Babylon node handles fees
2. Propose: fee split proportional to shard execution time
3. Implement: fee accumulator in execution state
4. Test: fee collection across single-shard and cross-shard transactions

**Estimated effort:** 3-4 sessions
**Risk:** High — design decisions, needs maintainer buy-in first
**Why sixth:** Big impact but needs discussion first. Open an issue with design proposal before coding.

## How We Work

### Before Each PR
1. **Read the relevant crate end-to-end** — understand the full context
2. **Run existing tests** — `cargo test -p hyperscale-<crate>`
3. **Check recent commits** — the codebase moves fast, don't work on stale code
4. **Open a discussion** on the issue first if the fix is non-obvious
5. **Pull latest main** — rebase before PR

### PR Standards (Match Their Style)
- Commit messages: imperative mood, concise ("Add bounded pool eviction to mempool")
- Code style: follow existing patterns (they use `rustfmt` + `clippy`)
- Tests: every behavior change has a test
- No unnecessary refactoring — fix the issue, nothing more
- Docs: inline comments for non-obvious logic

### Communication
- Comment on issues before starting work (avoid duplicated effort)
- Link PR to issue ("Fixes #22 — bounded mempool pool")
- Be concise in PR descriptions — what changed, why, how to test
- Respond to review comments promptly

## Don't Touch (Yet)

| Area | Why |
|------|-----|
| Consensus protocol changes (#10, #11, #12) | Design decisions still in flux |
| Gateway integration (#7, #8) | Operational, not our domain |
| TLA+ verification (#3) | Requires formal methods expertise |
| Topology changes (#10, #16) | Architectural decisions pending |
| radix-transactions fork (#4, #43) | Upstream dependency, maintainer territory |

## Tools & Setup

```bash
# Build
cargo build --release

# Test specific crate
cargo test -p hyperscale-mempool
cargo test -p hyperscale-bft
cargo test -p hyperscale-livelock

# Full test suite
cargo test

# Clippy (must pass for CI)
cargo clippy --all-targets

# Benchmark (after PR #4)
cargo bench -p hyperscale-mempool
```

## Timeline

| Week | PR | Status |
|------|----|--------|
| Week 1 | #1 Bounded mempool | Ready to start |
| Week 1-2 | #2 Livelock tombstone cleanup | After #1 merges |
| Week 2-3 | #3 Execution early state cleanup | After #2 |
| Week 3-4 | #4 Benchmarks | Can parallel with #3 |
| Month 2 | #5 Test suite | After learning from PRs 1-4 |
| Month 2-3 | #6 Fee model proposal | Needs discussion first |

## Success Metrics

- [ ] PR #1 merged (establishes contributor status)
- [ ] 3 PRs merged within first month
- [ ] Maintainer recognizes us as regular contributor
- [ ] Invited to discussions on protocol design
- [ ] Benchmarks become part of CI
