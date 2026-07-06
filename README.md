# hyperscale-rs

> **Warning**: Work in progress. Do not use.

Rust implementation of the Hyperscale protocol: a sharded smart-contract network that scales **linearly** — add shards, get proportional throughput — while keeping the properties sharding usually destroys: **atomic composability** (a transaction touching state on many shards commits everywhere or nowhere) and synchronous, single-chain semantics with BFT finality. No bridges, no optimistic rollback, no user-visible intermediate states.

**What makes it distinctive:**

- **Three consensus mechanisms, one clock.** Independent HotStuff-2 shard chains order transactions; execution certificates agree on their results; a slow beacon chain governs validators and topology. All three are harmonized by *weighted time* — a BFT-attested clock — which binds every artifact to exactly one governing committee.
- **Deterministic atomic commitment.** Cross-shard transactions run a provision–execute–certify pipeline: state moves between shards as merkle-proven facts about committed blocks, every shard executes deterministically on identical inputs, and quorum certificates attest outcomes rather than vote on them. No coordinator, no blocking, and locks that structurally cannot deadlock.
- **Dynamic sharding.** Shards split under load and merge when it recedes — live, without halting the network. State is one binary Jellyfish Merkle Tree and a shard is a prefix subtree, so resharding is a tree operation with a one-hash continuity proof; transactions straddling a reshape boundary settle atomically via attested settled sets.
- **A self-regulating validator economy.** The minimum activation stake is a market-clearing price recomputed every epoch from topology demand — rising when validator supply is abundant, falling when splits need staffing — while vnodes let one host run many validator identities, so a seat's marginal cost is its stake, not hardware.
- **Determinism as the spine.** The entire protocol stack is sans-io pure state machines. The same code runs under production I/O (tokio, libp2p, RocksDB) and under a deterministic simulator where whole multi-shard networks — fault injection included — replay byte-identically from a seed.

**[Architecture documentation → docs/](docs/)** — the whole story in a five-page overview, per-subsystem deep dives, and a consolidated invariant register intended as the starting point for formal verification.

**[Formal models → specs/](specs/)** — an in-progress track of machine-checked [Quint](https://quint-lang.org/) models (verified with Apalache) of the critical safety properties. Each is transcribed from the implementation it models and cross-checked against it by the deterministic scenario suite.

## Crates

| Crate | Purpose |
|-------|---------|
| [`beacon`](crates/beacon) | Beacon-chain coordinator (PC/SPC/MSC consensus, validator-set + topology source) |
| [`core`](crates/core) | The `StateMachine` and `SubStateMachine` traits that everything implements |
| [`dispatch`](crates/dispatch) | Abstract trait for scheduling CPU-intensive work across priority-isolated pools |
| [`dispatch-pooled`](crates/dispatch-pooled) | Production dispatch using rayon thread pools with core allocation and pinning |
| [`dispatch-sync`](crates/dispatch-sync) | Deterministic inline dispatch for simulation (runs closures on calling thread) |
| [`engine`](crates/engine) | Radix Engine integration for smart contract execution |
| [`execution`](crates/execution) | Transaction execution with cross-shard coordination |
| [`jmt`](crates/jmt) | Jellyfish Merkle Tree with generic hasher and batched multiproofs |
| [`mempool`](crates/mempool) | Transaction pool management |
| [`metrics`](crates/metrics) | Metrics facade with domain-specific trait and global singleton recorder |
| [`metrics-memory`](crates/metrics-memory) | In-memory metrics backend for tests and simulation assertions |
| [`metrics-prometheus`](crates/metrics-prometheus) | Prometheus metrics backend with counters, gauges, and histograms |
| [`network`](crates/network) | Shared network protocol logic: Network trait, handler registry, wire framing |
| [`network-libp2p`](crates/network-libp2p) | Production libp2p transport with gossipsub broadcast and QUIC/TCP streams |
| [`network-memory`](crates/network-memory) | Deterministic in-memory network for simulation with configurable latency and partitions |
| [`node`](crates/node) | Composes all sub-state machines into the main `NodeStateMachine` |
| [`production`](crates/production) | Production runner: async event loop, RPC server, telemetry |
| [`provisions`](crates/provisions) | Centralized provision coordination for cross-shard transactions |
| [`remote-headers`](crates/remote-headers) | Centralized remote block header coordination for cross-shard verification |
| [`scenarios`](crates/scenarios) | Portable node-behavioral scenarios run on both the simulation and production harnesses |
| [`shard`](crates/shard) | Shard consensus (HotStuff-2): block proposal, voting, QC formation, view changes |
| [`simulation`](crates/simulation) | Deterministic simulation runner with event queue and multi-node orchestration |
| [`simulator`](crates/simulator) | CLI tool for running simulations with metrics |
| [`spammer`](crates/spammer) | Transaction spammer CLI and library for load testing |
| [`storage`](crates/storage) | Storage trait abstractions (SubstateStore, CommitStore, ConsensusStore) and JMT integration |
| [`storage-memory`](crates/storage-memory) | In-memory storage using persistent data structures for deterministic simulation |
| [`storage-rocksdb`](crates/storage-rocksdb) | Production RocksDB storage with JMT state roots and snapshot isolation |
| [`types`](crates/types) | Core types: hashes, blocks, votes, QCs, keys, transactions, topology |

## Installation

### Binaries
Pre-built binaries for Linux (x86_64) and macOS (ARM64) are available on the [Releases page](https://github.com/flightofthefox/hyperscale-rs/releases).

### Docker Image
You can pull the latest Docker image from the GitHub Container Registry:

```bash
docker pull ghcr.io/flightofthefox/hyperscale-rs:latest
```

## Prerequisites

### 1. Install Rust
Install Rust using [rustup](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Install Build Dependencies

You will need `clang`, `lld`, `protobuf`, and `openssl`.

#### macOS
```bash
brew install llvm protobuf openssl pkg-config
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update && sudo apt-get install -y \
    clang \
    lld \
    pkg-config \
    protobuf-compiler \
    git \
    build-essential \
    libssl-dev \
    libc6-dev
```

#### Windows
1.  Install [Rust](https://rustup.rs/).
2.  Install [LLVM](https://releases.llvm.org/download.html).
3.  Install [Protoc](https://github.com/protocolbuffers/protobuf/releases).
4.  Ensure `clang` and `protoc` are in your `PATH`.

### 3. Install Docker (Optional)

Required only if you plan to run the `launch-docker-compose.sh` script or use the provided `Dockerfile`.

#### macOS & Windows
Recommended: [Docker Desktop](https://www.docker.com/products/docker-desktop/) or [Rancher Desktop](https://rancherdesktop.io/).

#### Linux
Install the Docker Engine and Docker Compose plugin:
[Install on Ubuntu](https://docs.docker.com/engine/install/ubuntu/) | [Install on Debian](https://docs.docker.com/engine/install/debian/) | [Install on Fedora](https://docs.docker.com/engine/install/fedora/)

Ensure your user is in the `docker` group to run commands without `sudo`:
```bash
sudo usermod -aG docker $USER
newgrp docker
```

## Cloning with Submodules

This repository uses git submodules for vendor dependencies. When cloning, use:

```bash
git clone --recurse-submodules https://github.com/flightofthefox/hyperscale-rs.git
```

If you've already cloned the repository without submodules, initialize them with:

```bash
git submodule update --init --recursive
```

## Building

```bash
cargo build --release
```

## Running the Simulator

```bash
cargo run --release --bin hyperscale-sim
```

## Running Tests

```bash
cargo test
```

## Running a Local Cluster

For development and testing, you can launch a local cluster using the provided scripts.

### Process-based Cluster

The `launch-cluster.sh` script launches a cluster of validator nodes as background processes on your host machine. This is faster and easier for quick iteration.

```bash
./scripts/launch-cluster.sh
```

**Options:**
- `--shards <N>`: Number of shards (default: 2)
- `--validators-per-shard <M>`: Validators per shard (default: 4)
- `--clean`: Clean data directories before starting
- `--monitoring`: Start Prometheus and Grafana for metrics

### Docker-based Cluster

The `launch-docker-compose.sh` script launches a full cluster inside Docker containers using Docker Compose. This more closely mimics a production environment.

> [!IMPORTANT]
> **Memory Requirement**: Please ensure your Docker VM/Desktop is configured with at least **8-10GB of RAM**. The validator nodes require significant memory for the high-throughput consensus simulation.

```bash
./scripts/launch-docker-compose.sh
```

**Options:**
- `--build <true|false>`: Whether to build the docker image (default: true). Set to false to use existing image for much faster startup.
- `--use-ghcr-image`: Use the latest pre-built image from GHCR instead of building locally.
- `--shards <N>`: Number of shards (default: 1)
- `--validators-per-shard <M>`: Validators per shard (default: 8)
- `--memory <limit>`: Memory limit per validator (e.g. `1g`, `512m`)
- `--cpus <limit>`: CPU limit per validator (e.g. `0.5`)
- `--latency <ms>`: Artificial network latency per validator
- `--latency-nodes <N>`: Number of nodes to apply latency to (default: 1)

### Stopping the Cluster

To stop the Docker cluster and remove volumes:

```bash
./scripts/stop-docker-compose.sh
```

### Running Load Tests (Spammer)

To run load tests against your local cluster, use the `hyperscale-spammer` binary.

> [!IMPORTANT]
> **Check Ports**: You **MUST** use the ports outputted by the launch script at the end of its execution. These ports may vary depending on the number of validators and sharding configuration.

Example command (adjust ports as needed):

```bash
./target/release/hyperscale-spammer run \
  --endpoints "http://localhost:8080,http://localhost:8081" \
  --num-shards 2 \
  --validators-per-shard 4 \
  --tps 100 \
  --duration 30s
```


## Troubleshooting

### Windows: "Path too long" Error

`hyperscale-rs` depends on the git monorepo `hyperscalers/radixdlt-scrypto`. Its
`radix-transaction-scenarios` crate contains generated fixture paths longer than
Windows `MAX_PATH` (~260). Cargo fetches via git but checks out with **libgit2**,
which fails unless long paths are enabled system-wide. Shorter `CARGO_HOME` does
not help — the in-repo suffix alone is ~268 characters.

**Enable Windows long paths:**

1. Open **PowerShell** as Administrator.
2. Run:
   ```powershell
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
   ```
3. Restart the machine (or sign out and back in).
4. Run:
   ```bash
   git config --global core.longpaths true
   ```

Long paths are the required fix. The repository `.cargo/config.toml` stays
platform-neutral (CMake policy only) so Linux and CI are unchanged.

Optional local Cargo settings for Windows belong in `.cargo/config.local.toml`
(gitignored). Cargo does not load that file automatically — copy its contents
into your working copy of `.cargo/config.toml`, then run
`git update-index --skip-worktree .cargo/config.toml` so local edits are not
committed:

```toml
# .cargo/config.local.toml (local only, not committed)
[net]
git-fetch-with-cli = true
```

`git-fetch-with-cli` alone does not replace enabling long paths; checkout still
uses libgit2 unless `LongPathsEnabled` is set.

### Windows: "Can't find clang.dll" or "libclang.dll"

RocksDB (`librocksdb-sys`) uses bindgen, which needs **LLVM/libclang** and **MSVC
headers** (`stdbool.h` from the Windows SDK). Both are required — LLVM alone is not
enough unless you run from a Developer Command Prompt.

1. Install LLVM (`choco install llvm`) and protobuf (`choco install protobuf`).
2. Install **Visual Studio Build Tools** with the **Desktop development with C++**
   workload (provides `vcvars64.bat` and SDK headers).
3. Set `LIBCLANG_PATH` permanently, e.g. `C:\Program Files\LLVM\bin`.

Run from **Developer PowerShell for VS** (loads `vcvars64.bat`) or set
`LIBCLANG_PATH` manually before `cargo build`:

```powershell
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
```

