#!/bin/bash
#
# Launch a local hyperscale cluster for testing.
#
# Usage:
#   ./scripts/launch-cluster.sh [--shards N] [--validators-per-shard M] [--clean] [--log-level LEVEL]
#
# Examples:
#   ./scripts/launch-cluster.sh                    # 2 shards, 4 validators each (default)
#   ./scripts/launch-cluster.sh --shards 4         # 4 shards, 4 validators each
#   ./scripts/launch-cluster.sh --clean            # Clean data directories first
#   ./scripts/launch-cluster.sh --log-level debug  # Enable debug logging
#
# This script:
#   1. Builds the validator binary (if needed)
#   2. Generates keypairs for all validators
#   3. Creates TOML config files with proper genesis
#   4. Launches all validators as background processes
#   5. Writes PIDs to a file for cleanup

set -e

# Default configuration
NUM_SHARDS=2
VALIDATORS_PER_SHARD=4      # Minimum 4 required for BFT (3 validators can't tolerate any delays)
BASE_PORT=9000              # libp2p port
BASE_RPC_PORT=8080          # HTTP RPC port
DATA_DIR="./cluster-data"
CLEAN=false
ACCOUNTS_PER_SHARD=16000    # Spammer accounts per shard
INITIAL_BALANCE=1000000     # Initial XRD balance per account
MONITORING=false            # Start Prometheus + Grafana monitoring stack
LOG_LEVEL="info"            # Default log level (trace, debug, info, warn, error)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --shards)
            NUM_SHARDS="$2"
            shift 2
            ;;
        --validators-per-shard|--validators)
            VALIDATORS_PER_SHARD="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --accounts-per-shard)
            ACCOUNTS_PER_SHARD="$2"
            shift 2
            ;;
        --initial-balance)
            INITIAL_BALANCE="$2"
            shift 2
            ;;
        --monitoring)
            MONITORING=true
            shift
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--shards N] [--validators-per-shard M] [--clean] [--monitoring] [--log-level LEVEL]"
            echo ""
            echo "Options:"
            echo "  --shards N               Number of shards (default: 2)"
            echo "  --validators-per-shard M Validators per shard (default: 4, minimum: 4)"
            echo "  --accounts-per-shard N   Spammer accounts per shard (default: 100)"
            echo "  --initial-balance N      Initial XRD balance per account (default: 1000000)"
            echo "  --clean                  Remove existing data directories"
            echo "  --monitoring             Start Prometheus + Grafana monitoring stack"
            echo "  --log-level LEVEL        Log level: trace, debug, info, warn, error (default: info)"
            echo ""
            echo "Monitoring:"
            echo "  When --monitoring is enabled, Prometheus and Grafana are started via Docker."
            echo "  Prometheus: http://localhost:9090"
            echo "  Grafana:    http://localhost:3000 (admin/admin)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

TOTAL_VALIDATORS=$((NUM_SHARDS * VALIDATORS_PER_SHARD))

# Validate minimum validators per shard
if [ "$VALIDATORS_PER_SHARD" -lt 4 ]; then
    echo "ERROR: Minimum 4 validators per shard required for BFT consensus."
    echo "       With 3 validators, timing delays can cause permanent stalls."
    echo "       Use --validators-per-shard 4 or higher."
    exit 1
fi

echo "=== Hyperscale Local Cluster ==="
echo "Shards: $NUM_SHARDS"
echo "Validators per shard: $VALIDATORS_PER_SHARD"
echo "Total validators: $TOTAL_VALIDATORS"
echo "Accounts per shard: $ACCOUNTS_PER_SHARD"
echo "Initial balance: $INITIAL_BALANCE XRD"
echo "Log level: $LOG_LEVEL"
echo ""

# Clean up if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning data directories..."
    rm -rf "$DATA_DIR"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Build the validator, keygen, and spammer binaries
echo "Building binaries..."
cargo build --release --bin hyperscale-validator --bin hyperscale-keygen --bin hyperscale-spammer 2>&1 | tail -3

VALIDATOR_BIN="./target/release/hyperscale-validator"
KEYGEN_BIN="./target/release/hyperscale-keygen"
SPAMMER_BIN="./target/release/hyperscale-spammer"

if [ ! -f "$VALIDATOR_BIN" ]; then
    echo "ERROR: Validator binary not found at $VALIDATOR_BIN"
    exit 1
fi

if [ ! -f "$SPAMMER_BIN" ]; then
    echo "ERROR: Spammer binary not found at $SPAMMER_BIN"
    exit 1
fi

# Generate keypairs and collect public keys
echo "Generating validator keypairs..."
declare -a PUBLIC_KEYS
declare -a KEY_FILES

for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    KEY_DIR="$DATA_DIR/validator-$i"
    mkdir -p "$KEY_DIR"
    KEY_FILE="$KEY_DIR/signing.key"
    KEY_FILES[$i]="$KEY_FILE"

    # Generate a deterministic 32-byte seed from validator index
    # This makes the cluster reproducible
    SEED_HEX=$(printf '%064x' $((12345 + i)))
    echo "$SEED_HEX" | xxd -r -p > "$KEY_FILE"

    # Derive the actual public key from the seed using our keygen tool
    PUBLIC_KEYS[$i]=$("$KEYGEN_BIN" "$SEED_HEX")
    echo "  Validator $i: public_key=${PUBLIC_KEYS[$i]:0:16}..."
done

# Generate genesis balances for spammer accounts (per-shard)
# Each validator only needs balances for accounts on its shard to avoid
# memory issues with large account counts.
echo "Generating genesis balances for spammer accounts..."
declare -a SHARD_GENESIS_BALANCES
for shard in $(seq 0 $((NUM_SHARDS - 1))); do
    SHARD_GENESIS_BALANCES[$shard]=$("$SPAMMER_BIN" genesis \
        --num-shards "$NUM_SHARDS" \
        --accounts-per-shard "$ACCOUNTS_PER_SHARD" \
        --balance "$INITIAL_BALANCE" \
        --shard "$shard")
    echo "  Shard $shard: $ACCOUNTS_PER_SHARD accounts"
done
echo "  Generated balances for $((NUM_SHARDS * ACCOUNTS_PER_SHARD)) accounts total"

# Calculate bootstrap peer addresses
# First validator of each shard will be bootstrap peers
BOOTSTRAP_PEERS=""
for shard in $(seq 0 $((NUM_SHARDS - 1))); do
    first_validator=$((shard * VALIDATORS_PER_SHARD))
    port=$((BASE_PORT + first_validator))
    if [ -n "$BOOTSTRAP_PEERS" ]; then
        BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"
    fi
    # We'll use localhost multiaddr format
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/127.0.0.1/udp/$port/quic-v1\""
done

# Generate TOML configs for each validator
echo "Generating config files..."
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    p2p_port=$((BASE_PORT + i))
    rpc_port=$((BASE_RPC_PORT + i))

    CONFIG_FILE="$DATA_DIR/validator-$i/config.toml"
    KEY_FILE="$DATA_DIR/validator-$i/signing.key"
    NODE_DATA_DIR="$DATA_DIR/validator-$i/data"

    mkdir -p "$NODE_DATA_DIR"

    # Build genesis validators section - include ALL validators from ALL shards
    # This is required so validators can verify cross-shard messages
    GENESIS_VALIDATORS=""
    for j in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
        if [ -n "$GENESIS_VALIDATORS" ]; then
            GENESIS_VALIDATORS="$GENESIS_VALIDATORS
"
        fi
        # Calculate which shard this validator belongs to
        validator_shard=$((j / VALIDATORS_PER_SHARD))
        GENESIS_VALIDATORS="$GENESIS_VALIDATORS[[genesis.validators]]
id = $j
shard = $validator_shard
public_key = \"${PUBLIC_KEYS[$j]}\"
voting_power = 1"
    done

    cat > "$CONFIG_FILE" << EOF
# Hyperscale Validator Configuration
# Auto-generated for local cluster testing

[node]
validator_id = $i
shard = $shard
num_shards = $NUM_SHARDS
key_path = "$KEY_FILE"
data_dir = "$NODE_DATA_DIR"

[network]
listen_addr = "/ip4/0.0.0.0/udp/$p2p_port/quic-v1"
bootstrap_peers = [$BOOTSTRAP_PEERS]
request_timeout_ms = 500
max_message_size = 10485760
gossipsub_heartbeat_ms = 100

[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000
max_transactions_per_block = 4096
max_certificates_per_block = 4096

[threads]
crypto_threads = 0
execution_threads = 0
io_threads = 0
pin_cores = false

[storage]
max_background_jobs = 2
write_buffer_mb = 64
block_cache_mb = 256

[metrics]
enabled = true
listen_addr = "0.0.0.0:$rpc_port"

[telemetry]
enabled = false

$GENESIS_VALIDATORS

${SHARD_GENESIS_BALANCES[$shard]}
EOF

    echo "  Created config for validator $i (shard $shard, p2p port $p2p_port, rpc port $rpc_port)"
done

# Launch validators
echo ""
echo "Launching validators..."
PID_FILE="$DATA_DIR/pids.txt"
> "$PID_FILE"

for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    CONFIG_FILE="$DATA_DIR/validator-$i/config.toml"
    LOG_FILE="$DATA_DIR/validator-$i/output.log"

    echo "  Starting validator $i (shard $shard)..."

    # Build RUST_LOG based on log level
    # Always suppress noisy dependencies, but let hyperscale crates use the specified level
    RUST_LOG="warn,hyperscale=$LOG_LEVEL,hyperscale_production=$LOG_LEVEL,libp2p_gossipsub=warn" "$VALIDATOR_BIN" --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    PID=$!
    echo "$PID" >> "$PID_FILE"
    echo "    PID: $PID, logs: $LOG_FILE"

    # Small delay to stagger startup
    sleep 0.2
done

echo ""
echo "=== Cluster Started ==="
echo ""
echo "Validator endpoints:"
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    rpc_port=$((BASE_RPC_PORT + i))
    echo "  Validator $i (shard $shard): http://localhost:$rpc_port"
done

echo ""
echo "Useful commands:"
echo "  Check health:  curl http://localhost:$BASE_RPC_PORT/health"
echo "  Get status:    curl http://localhost:$BASE_RPC_PORT/api/v1/status"
echo "  View metrics:  curl http://localhost:$BASE_RPC_PORT/metrics"
echo "  View logs:     tail -f $DATA_DIR/validator-0/output.log"
echo "  Stop cluster:  ./scripts/stop-cluster.sh"
echo ""

# Build spammer endpoint list (all validators for load distribution)
SPAMMER_ENDPOINTS=""
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    rpc_port=$((BASE_RPC_PORT + i))
    if [ -n "$SPAMMER_ENDPOINTS" ]; then
        SPAMMER_ENDPOINTS="$SPAMMER_ENDPOINTS,"
    fi
    SPAMMER_ENDPOINTS="${SPAMMER_ENDPOINTS}http://localhost:$rpc_port"
done

echo "Run spammer:"
echo "  $SPAMMER_BIN run \\"
echo "    --endpoints $SPAMMER_ENDPOINTS \\"
echo "    --num-shards $NUM_SHARDS \\"
echo "    --validators-per-shard $VALIDATORS_PER_SHARD \\"
echo "    --tps 100 \\"
echo "    --duration 30s"
echo ""
echo "PIDs written to: $PID_FILE"

# Run smoke test to verify the cluster is working
echo ""
echo "=== Running Smoke Test ==="
echo "Waiting for cluster to stabilize..."
sleep 3

"$SPAMMER_BIN" smoke-test \
    --endpoints "$SPAMMER_ENDPOINTS" \
    --num-shards "$NUM_SHARDS" \
    --validators-per-shard "$VALIDATORS_PER_SHARD" \
    --accounts-per-shard "$ACCOUNTS_PER_SHARD" \
    --wait-ready \
    --timeout 60s \
    --poll-interval 100ms

SMOKE_TEST_EXIT=$?
if [ $SMOKE_TEST_EXIT -eq 0 ]; then
    echo ""
    echo "=== Cluster is ready for use ==="
else
    echo ""
    echo "WARNING: Smoke test failed with exit code $SMOKE_TEST_EXIT"
    echo "Check validator logs for details: tail -f $DATA_DIR/validator-*/output.log"
fi

# Start monitoring stack if requested
if [ "$MONITORING" = true ]; then
    echo ""
    echo "=== Starting Monitoring Stack ==="

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    MONITORING_DIR="$SCRIPT_DIR/monitoring"

    # Generate prometheus.yml with correct number of targets and shard labels
    echo "Generating Prometheus configuration for $TOTAL_VALIDATORS validators across $NUM_SHARDS shards..."

    # Build static configs grouped by shard
    PROM_STATIC_CONFIGS=""
    for shard in $(seq 0 $((NUM_SHARDS - 1))); do
        # Build targets for this shard
        SHARD_TARGETS=""
        for v in $(seq 0 $((VALIDATORS_PER_SHARD - 1))); do
            validator_idx=$((shard * VALIDATORS_PER_SHARD + v))
            rpc_port=$((BASE_RPC_PORT + validator_idx))
            if [ -n "$SHARD_TARGETS" ]; then
                SHARD_TARGETS="$SHARD_TARGETS
          - 'host.docker.internal:$rpc_port'"
            else
                SHARD_TARGETS="- 'host.docker.internal:$rpc_port'"
            fi
        done

        # Add this shard's config block
        PROM_STATIC_CONFIGS="$PROM_STATIC_CONFIGS
      # Shard $shard validators
      - targets:
          $SHARD_TARGETS
        labels:
          cluster: 'local'
          shard: '$shard'"
    done

    cat > "$MONITORING_DIR/prometheus.yml" << EOF
# Prometheus configuration for Hyperscale local cluster
# $NUM_SHARDS shards x $VALIDATORS_PER_SHARD validators = $TOTAL_VALIDATORS total
#
# Shard assignment (auto-generated):
$(for shard in $(seq 0 $((NUM_SHARDS - 1))); do
    first_port=$((BASE_RPC_PORT + shard * VALIDATORS_PER_SHARD))
    last_port=$((first_port + VALIDATORS_PER_SHARD - 1))
    echo "#   - Shard $shard: ports $first_port-$last_port"
done)

global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'hyperscale'
    static_configs:$PROM_STATIC_CONFIGS
    metrics_path: '/metrics'
    scrape_timeout: 5s
EOF

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo "WARNING: Docker not found. Cannot start monitoring stack."
        echo "Install Docker and run manually: cd $MONITORING_DIR && docker-compose up -d"
    else
        # Start the monitoring stack
        echo "Starting Prometheus and Grafana..."
        (cd "$MONITORING_DIR" && docker-compose up -d 2>&1) | tail -5

        echo ""
        echo "Monitoring URLs:"
        echo "  Prometheus: http://localhost:9090"
        echo "  Grafana:    http://localhost:3000/d/hyperscale-cluster/hyperscale-cluster"
        echo ""
        echo "Stop monitoring: cd $MONITORING_DIR && docker-compose down"
    fi
fi
