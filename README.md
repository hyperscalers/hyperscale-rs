# hyperscale-rs

> **Warning**: Work in progress. Do not use.

Rust implementation of Hyperscale consensus protocol.

**What's different:**
- Pure consensus layer — no I/O, no locks, no async
- Created with deterministic simulation testing in mind
- Faster two-chain commit consensus based on HotStuff-2
- Optimistic pipelining — proposers propose immediately after QC formation
- Improved cross-shard livelock prevention
- Real Radix Engine integration

## Crates

| Crate | Purpose |
|-------|---------|
| `hyperscale-types` | Core types: hashes, blocks, votes, QCs, keys, transactions, topology |
| `hyperscale-core` | The `StateMachine` and `SubStateMachine` traits that everything implements |
| `hyperscale-messages` | Network message serialization (SBOR encoding) |
| `hyperscale-bft` | BFT consensus: block proposal, voting, QC formation, view changes |
| `hyperscale-execution` | Transaction execution with cross-shard 2PC coordination |
| `hyperscale-mempool` | Transaction pool management |
| `hyperscale-livelock` | Cross-shard deadlock detection and prevention |
| `hyperscale-sync` | Block synchronization for nodes catching up |
| `hyperscale-node` | Composes all sub-state machines into the main `NodeStateMachine` |
| `hyperscale-engine` | Radix Engine integration for smart contract execution |
| `hyperscale-simulation` | Deterministic simulator with configurable network conditions |
| `hyperscale-simulator` | CLI tool for running simulations with metrics |
| `hyperscale-production` | Production runner: libp2p networking, RocksDB storage, thread pools |
| `hyperscale-spammer` | Transaction spammer CLI and library for load testing |

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
