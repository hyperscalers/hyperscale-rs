#!/bin/bash
#
# Launch a single bootstrap node with UPnP enabled.
#
# Usage:
#   ./scripts/launch-bootstrap-node.sh [--clean] [--log-level LEVEL]
#
# This script:
#   1. Builds the validator binary
#   2. Generates a keypair for the node
#   3. Creates TOML config
#   4. Launches the validator
#

set -e

# Default configuration
BASE_PORT=9000
RPC_PORT=8080
DATA_DIR="./bootstrap-data"
CLEAN=false
LOG_LEVEL="info"
SKIP_BUILD="${SKIP_BUILD:-false}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--clean] [--log-level LEVEL]"
            echo ""
            echo "Options:"
            echo "  --clean                  Remove existing data directory"
            echo "  --log-level LEVEL        Log level: trace, debug, info, warn, error (default: info)"
            echo "  --skip-build             Skip building binaries (default: false)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "=== Hyperscale Bootstrap Node ==="
echo "Log level: $LOG_LEVEL"
echo "Clean data dir: $CLEAN"
echo "UPnP Enabled: true"
echo ""

# Clean up if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning data directory..."
    rm -rf "$DATA_DIR"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Build binaries
if [ "$SKIP_BUILD" != "true" ]; then
    echo "Building binaries..."
    cargo build --release --bin hyperscale-validator --bin hyperscale-keygen 2>&1 | tail -3
else
    echo "Skipping build (SKIP_BUILD=true)..."
fi

VALIDATOR_BIN="${VALIDATOR_BIN:-./target/release/hyperscale-validator}"
KEYGEN_BIN="${KEYGEN_BIN:-./target/release/hyperscale-keygen}"

if [ ! -f "$VALIDATOR_BIN" ]; then
    echo "ERROR: Validator binary not found at $VALIDATOR_BIN"
    exit 1
fi

# Generate keypair
echo "Generating validator keypair..."
KEY_DIR="$DATA_DIR/validator"
mkdir -p "$KEY_DIR"
KEY_FILE="$KEY_DIR/signing.key"

# Deterministic seed for bootstrap node (index 0 equivalent)
SEED_HEX=$(printf '%064x' 12345)
echo "$SEED_HEX" | xxd -r -p > "$KEY_FILE"
PUBLIC_KEY=$("$KEYGEN_BIN" "$SEED_HEX")
echo "  Public Key: ${PUBLIC_KEY:0:16}..."
NETWORK_KEY_FILE="$DATA_DIR/validator/network.key"
ENDPOINT_ID=$("$KEYGEN_BIN" --network-key "$NETWORK_KEY_FILE")
echo "  Endpoint: $ENDPOINT_ID"

# Generate Config
CONFIG_FILE="$DATA_DIR/validator/config.toml"
NODE_DATA_DIR="$DATA_DIR/validator/data"
mkdir -p "$NODE_DATA_DIR"

# The network this node starts: itself as its only validator, its epoch
# clock starting now.
NETWORK_FILE="$DATA_DIR/validator/network.toml"
GENESIS_TIMESTAMP_MS="${GENESIS_TIMESTAMP_MS:-$(( $(date +%s) * 1000 ))}"
cat > "$NETWORK_FILE" << EOF
# Hyperscale Network File

network = "simulator"
bootstrap_peers = []

[chain]
genesis_timestamp_ms = $GENESIS_TIMESTAMP_MS

[genesis]
[[genesis.validators]]
id = 0
public_key = "$PUBLIC_KEY"
EOF

cat > "$CONFIG_FILE" << EOF
# Hyperscale Bootstrap Node Configuration

[node]
network_file = "$NETWORK_FILE"
data_dir = "$NODE_DATA_DIR"

[[vnode]]
validator_id = 0
key_path = "$KEY_FILE"

[network]
listen_addr = "0.0.0.0:$BASE_PORT"
network_key_path = "$NETWORK_KEY_FILE"
version_interop_mode = "relaxed"
upnp_enabled = true

[threads]
consensus_threads = 0
throughput_threads = 0
io_threads = 0
pin_cores = false

[storage]
max_background_jobs = 2
write_buffer_mb = 64
block_cache_mb = 256

[metrics]
enabled = true
listen_addr = "0.0.0.0:$RPC_PORT"

[telemetry]
enabled = false
EOF

echo "Created config at $CONFIG_FILE and network file at $NETWORK_FILE"
echo ""
echo "Launching bootstrap node..."
echo "  RPC: http://localhost:$RPC_PORT"
echo "  P2P: UDP/$BASE_PORT (QUIC)"
echo "  Bootstrap entry: $ENDPOINT_ID@<this host's address>:$BASE_PORT"

# Run validator
RUST_LOG="warn,hyperscale=$LOG_LEVEL,hyperscale_production=$LOG_LEVEL" "$VALIDATOR_BIN" --config "$CONFIG_FILE"
