#!/bin/bash
#
# Launch a local hyperscale cluster for testing.
#
# Usage:
#   ./scripts/launch-cluster.sh [--shards N] [--validators-per-shard M] [--clean]
#
# Examples:
#   ./scripts/launch-cluster.sh                    # 2 shards, 3 validators each (default)
#   ./scripts/launch-cluster.sh --shards 4         # 4 shards, 3 validators each
#   ./scripts/launch-cluster.sh --clean            # Clean data directories first
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
VALIDATORS_PER_SHARD=3
BASE_PORT=9000          # libp2p port
BASE_RPC_PORT=8080      # HTTP RPC port
DATA_DIR="./cluster-data"
CLEAN=false

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
        --help|-h)
            echo "Usage: $0 [--shards N] [--validators-per-shard M] [--clean]"
            echo ""
            echo "Options:"
            echo "  --shards N              Number of shards (default: 2)"
            echo "  --validators-per-shard M  Validators per shard (default: 3)"
            echo "  --clean                 Remove existing data directories"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

TOTAL_VALIDATORS=$((NUM_SHARDS * VALIDATORS_PER_SHARD))

echo "=== Hyperscale Local Cluster ==="
echo "Shards: $NUM_SHARDS"
echo "Validators per shard: $VALIDATORS_PER_SHARD"
echo "Total validators: $TOTAL_VALIDATORS"
echo ""

# Clean up if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning data directories..."
    rm -rf "$DATA_DIR"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Build the validator and keygen binaries
echo "Building binaries..."
cargo build --release --bin hyperscale-validator --bin hyperscale-keygen 2>&1 | tail -3

VALIDATOR_BIN="./target/release/hyperscale-validator"
KEYGEN_BIN="./target/release/hyperscale-keygen"

if [ ! -f "$VALIDATOR_BIN" ]; then
    echo "ERROR: Validator binary not found at $VALIDATOR_BIN"
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

    # Build genesis validators section - only include validators for THIS shard
    GENESIS_VALIDATORS=""
    first_validator_in_shard=$((shard * VALIDATORS_PER_SHARD))
    last_validator_in_shard=$((first_validator_in_shard + VALIDATORS_PER_SHARD - 1))
    for j in $(seq $first_validator_in_shard $last_validator_in_shard); do
        if [ -n "$GENESIS_VALIDATORS" ]; then
            GENESIS_VALIDATORS="$GENESIS_VALIDATORS
"
        fi
        GENESIS_VALIDATORS="$GENESIS_VALIDATORS[[genesis.validators]]
id = $j
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
request_timeout_ms = 30000
max_message_size = 65536
gossipsub_heartbeat_ms = 1000

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

    RUST_LOG=warn,hyperscale=info,hyperscale_production=debug,libp2p_gossipsub=info "$VALIDATOR_BIN" --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
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
echo "PIDs written to: $PID_FILE"
