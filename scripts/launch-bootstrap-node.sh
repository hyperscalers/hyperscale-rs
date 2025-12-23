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
TCP_BASE_PORT=30500
RPC_PORT=8080
DATA_DIR="./bootstrap-data"
CLEAN=false
LOG_LEVEL="info"
SKIP_BUILD="${SKIP_BUILD:-false}"
TCP_FALLBACK_ENABLED="false"

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
        --no-tcp-fallback)
            TCP_FALLBACK_ENABLED="false"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--clean] [--log-level LEVEL] [--no-tcp-fallback]"
            echo ""
            echo "Options:"
            echo "  --clean                  Remove existing data directory"
            echo "  --log-level LEVEL        Log level: trace, debug, info, warn, error (default: info)"
            echo "  --skip-build             Skip building binaries (default: false)"
            echo "  --no-tcp-fallback        Disable TCP fallback transport"
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
echo "TCP fallback: $TCP_FALLBACK_ENABLED"
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

# Generate Config
CONFIG_FILE="$DATA_DIR/validator/config.toml"
NODE_DATA_DIR="$DATA_DIR/validator/data"
mkdir -p "$NODE_DATA_DIR"

cat > "$CONFIG_FILE" << EOF
# Hyperscale Bootstrap Node Configuration

[node]
validator_id = 0
shard = 0
num_shards = 1
key_path = "$KEY_FILE"
data_dir = "$NODE_DATA_DIR"

[network]
listen_addr = "/ip4/0.0.0.0/udp/$BASE_PORT/quic-v1"
tcp_fallback_enabled = $TCP_FALLBACK_ENABLED
tcp_fallback_port = $TCP_BASE_PORT
bootstrap_peers = []
upnp_enabled = true
request_timeout_ms = 10000
max_message_size = 10485760
gossipsub_heartbeat_ms = 100

[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000
max_transactions_per_block = 4096
max_certificates_per_block = 4096
rpc_mempool_limit = 16384

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
listen_addr = "0.0.0.0:$RPC_PORT"

[telemetry]
enabled = false

[[genesis.validators]]
id = 0
shard = 0
public_key = "$PUBLIC_KEY"
voting_power = 1

# No initial balances needed for bootstrap node specific logic yet
EOF

echo "Created config at $CONFIG_FILE"
echo ""
echo "Launching bootstrap node..."
echo "  RPC: http://localhost:$RPC_PORT"
echo "  P2P: UDP/$BASE_PORT (QUIC), TCP/$TCP_BASE_PORT"

# Run validator
# libp2p_gossipsub=error to suppress noise
RUST_LOG="warn,hyperscale=$LOG_LEVEL,hyperscale_production=$LOG_LEVEL,libp2p_gossipsub=error" "$VALIDATOR_BIN" --config "$CONFIG_FILE"
