# hyperscale-rs — BFT Consensus Protocol

## What This Is
Rust implementation of the Hyperscale consensus protocol for Radix. Sharded BFT based on HotStuff-2 with deterministic simulation testing. Community project — "try to break it."

## Repo
- Upstream: https://github.com/hyperscalers/hyperscale-rs
- Fork: https://github.com/bigdevxrd/hyperscale-rs

## Stack
- Rust workspace monorepo
- 20+ crates in crates/
- Key crates: bft, core, execution, engine, simulation, node, production
- libp2p for networking, RocksDB for storage

## Key Architecture
- Two-chain commit (HotStuff-2 based)
- Optimistic pipelining — propose immediately after QC formation
- Wave-based cross-shard execution voting (not 2PC)
- Deterministic simulation as first-class testing
- Radix Engine integration for smart contract execution

## Contributing Focus
- Issue #22: Unbounded in-memory data structures (DoS vector) — HIGH PRIORITY
- Issue #18: Transaction/substate test suite (test gap)
- Issue #17: Fee model in sharded RE (design hole)
- See `CONTRIBUTION-PLAN.md` and `docs/IMPLEMENTATION.md` section 7 for full analysis

## Build
```bash
cargo check  # verify compiles
cargo test   # run test suite
```
