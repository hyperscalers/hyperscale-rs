# Hyperscale-RS Handoff — 2026-04-09

## What This Project Is
Rust BFT consensus protocol for Radix. 55K LOC, 28 crates, 738 tests. Built by hyperscalers team. We're contributing as external collaborators.

## Repo
- Upstream: https://github.com/hyperscalers/hyperscale-rs
- Our fork: https://github.com/bigdevxrd/hyperscale-rs
- Builds clean (`cargo check` passes)

## What We've Done So Far
1. **Forked + cloned** (Apr 8)
2. **Full security audit** — 17 unbounded data structures found across 5 crates, 3 critical
3. **Posted audit on issue #22** — https://github.com/hyperscalers/hyperscale-rs/issues/22#issuecomment-4205053762
4. **Researcher agent** triaged all 21 open issues and recommended contribution path
5. **CONTRIBUTION-PLAN.md** written — 6-PR phased approach

## No Response Yet From Maintainer
Our #22 comment is the only external contribution. No reply yet. But the maintainer made 10 commits on Apr 8 (same day), merged 5 PRs in 2 weeks. Very active, just hasn't responded to our audit yet.

Hashlock (security audit firm) also opened #52 introducing themselves — signals the project is getting attention.

## First PR: Bounded Mempool Pool

**Target:** `crates/mempool/src/state.rs`

**Problem:** `pool: BTreeMap<Hash, PoolEntry>` grows without bound. `DEFAULT_IN_FLIGHT_LIMIT` (12,288) throttles proposals but doesn't evict old transactions. Attacker can flood with cross-shard txns that never finalize.

**Fix:**
1. Add `max_pool_size: usize` to config (default 50,000)
2. Add `fn maybe_evict(&mut self)` after every insert
3. FIFO eviction by `created_at` (simplest, least controversial)
4. Add `mempool_pool_size` metric gauge
5. Test: pool reaches limit → oldest evicted on next insert

**Key files to read:**
- `crates/mempool/src/state.rs` — the full mempool state (2,151 LOC)
- `crates/mempool/src/config.rs` — where to add max_pool_size
- `crates/core/src/lib.rs` — Action enum, ProtocolEvent (understand the event model)
- `crates/simulation/tests/` — see how existing tests work

**Before starting:**
```bash
git pull origin main  # Codebase moves fast
cargo test -p hyperscale-mempool  # Run existing tests
```

## Second PR: Livelock Tombstone Cleanup

**Target:** `crates/livelock/src/state.rs`
**Problem:** `tombstones: HashMap<Hash, Duration>` — no cleanup despite `tombstone_ttl` config
**Fix:** Add `cleanup_tombstones(committed_height)` matching mempool's cleanup pattern
**Effort:** 2-3 hours, very low risk

## Third PR: Execution Early State Cleanup

**Target:** `crates/execution/src/state.rs`
**Problem:** `early_provisioning_complete`, `early_certificates`, `early_votes` leak on orphaned blocks
**Fix:** Age-based cleanup in `prune_execution_state()`, remove entries older than committed_height - 100
**Effort:** 4-6 hours, medium risk

## Architecture Quick Reference

```
NodeInput → IoLoop → ProtocolEvent → NodeStateMachine
  ├── BftState (11,925 LOC) — HotStuff-2 consensus
  ├── ExecutionState (2,776 LOC) — cross-shard wave execution
  ├── MempoolState (2,151 LOC) — tx pool ← OUR TARGET
  ├── ProvisionCoordinator — cross-shard state
  ├── RemoteHeaderCoordinator — remote block headers
  ├── LivelockState (1,524 LOC) — deadlock detection ← PR #2
  └── TopologyState — shard membership
```

All state machine logic is **synchronous, deterministic, pure** (no I/O). I/O deferred to runner layer.

## Key Crates By Size

| Crate | LOC | What |
|-------|-----|------|
| bft | 11,925 | Core consensus (don't touch yet) |
| types | 7,157 | Domain types (foundation) |
| storage-rocksdb | 4,956 | Production storage |
| execution | 2,776 | Cross-shard execution |
| mempool | 2,151 | Transaction pool (PR #1) |
| engine | 2,083 | Radix Engine integration |
| production | 1,890 | Async tokio runner |
| node | 1,840 | Composes all subsystems |
| livelock | 1,524 | Deadlock detection (PR #2) |

## PR Standards (Match Their Style)
- `rustfmt` + `clippy` must pass (CI enforces)
- Imperative commit messages ("Add bounded pool eviction")
- Every behavior change has a test
- Comment on the issue before starting work
- Keep PRs focused — one fix per PR

## Don't Touch
- Consensus protocol (#10, #11, #12) — design decisions pending
- Gateway integration (#7, #8) — operational
- TLA+ (#3) — formal methods
- radix-transactions fork (#4, #43) — upstream dep

## Files in This Repo
- `CLAUDE.md` — project context for Claude Code sessions
- `CONTRIBUTION-PLAN.md` — full 6-PR phased plan with timeline
- `HANDOFF.md` — this file

## Related References
- See `docs/IMPLEMENTATION.md` section 7 for the full unbounded data structure audit
- See `CONTRIBUTION-PLAN.md` for the phased contribution approach
