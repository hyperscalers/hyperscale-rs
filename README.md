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
- `--shards <N>`: Number of shards (default: 1)
- `--validators-per-shard <M>`: Validators per shard (default: 8)

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
