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
NUM_SHARDS=2                                    # Number of shards
VALIDATORS_PER_SHARD=4                          # Minimum 4 required for BFT (3 validators can't tolerate any delays)
BASE_PORT=9000                                  # libp2p port
TCP_BASE_PORT=30500                             # Base TCP fallback port
BASE_RPC_PORT=8080                              # HTTP RPC port
DATA_DIR="./cluster-data"                       # Data directory
CLEAN=false                                     # Clean data directories first
ACCOUNTS_PER_SHARD=16000                        # Spammer accounts per shard
INITIAL_BALANCE=1000000                         # Initial XRD balance per account
MONITORING="${START_MONITORING:-false}"         # Start Prometheus + Grafana monitoring stack
TRACING="${TRACING:-false}"                     # Enable distributed tracing with Jaeger
LOG_LEVEL="info"                                # Default log level (trace, debug, info, warn, error)
SMOKE_TEST_TIMEOUT="${SMOKE_TEST_TIMEOUT:-60s}" # Smoke test timeout
SKIP_BUILD="${SKIP_BUILD:-false}"               # Skip building binaries
NODE_HOSTNAME="${NODE_HOSTNAME:-localhost}"     # Hostname for spammer endpoints
TCP_FALLBACK_ENABLED="${TCP_FALLBACK_ENABLED:-false}" # Enable TCP fallback transport (default: false)
NETWORK_LATENCY_MS=""                           # Network latency in milliseconds (empty = disabled)
PACKET_LOSS_PERCENT=""                          # Packet loss percentage (empty = disabled)

# Mempool configuration
MEMPOOL_MAX_IN_FLIGHT=512                       # Soft limit on in-flight transactions
MEMPOOL_MAX_IN_FLIGHT_HARD_LIMIT=1024           # Hard limit on in-flight transactions
MEMPOOL_MAX_PENDING=2048                        # Max pending before RPC backpressure

# Define explicit port ranges for Docker and firewall whitelisting
# let's give a range of 500 ports which should be ok for local testing
QUIC_PORT_RANGE="${BASE_PORT}-$((BASE_PORT + 500))"
TCP_PORT_RANGE="${TCP_BASE_PORT}-$((TCP_BASE_PORT + 500))"

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
        --smoke-timeout)
            SMOKE_TEST_TIMEOUT="$2"
            shift 2
            ;;
        --node-hostname)
            NODE_HOSTNAME="$2"
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
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --start-monitoring)
            MONITORING=true
            shift
            ;;
        --tcp-fallback)
            TCP_FALLBACK_ENABLED="true"
            shift
            ;;
        --tracing)
            TRACING=true
            shift
            ;;
        --latency)
            NETWORK_LATENCY_MS="$2"
            shift 2
            ;;
        --packet-loss)
            PACKET_LOSS_PERCENT="$2"
            shift 2
            ;;
        --mempool-max-in-flight)
            MEMPOOL_MAX_IN_FLIGHT="$2"
            shift 2
            ;;
        --mempool-max-in-flight-hard-limit)
            MEMPOOL_MAX_IN_FLIGHT_HARD_LIMIT="$2"
            shift 2
            ;;
        --mempool-max-pending)
            MEMPOOL_MAX_PENDING="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--shards N] [--validators-per-shard M] [--clean] [--monitoring] [--log-level LEVEL] [--smoke-timeout DURATION] [--node-hostname HOST] [--no-tcp-fallback]"
            echo ""
            echo "Options:"
            echo "  --shards N               Number of shards (default: 2)"
            echo "  --validators-per-shard M Validators per shard (default: 4, minimum: 4)"
            echo "  --accounts-per-shard N   Spammer accounts per shard (default: 100)"
            echo "  --initial-balance N      Initial XRD balance per account (default: 1000000)"
            echo "  --smoke-timeout DURATION Smoke test timeout (default: 60s)"
            echo "  --node-hostname HOST     Hostname for spammer endpoints (default: localhost)"
            echo "  --clean                  Remove existing data directories"
            echo "  --monitoring             Start Prometheus + Grafana monitoring stack"
            echo "  --tracing                Enable distributed tracing with Jaeger (exports to localhost:4317)"
            echo "  --log-level LEVEL        Log level: trace, debug, info, warn, error (default: info)"
            echo "  --skip-build             Skip building binaries (default: false)"
            echo "  --start-monitoring       Start Prometheus + Grafana monitoring stack (default: false)"
            echo "  --tcp-fallback           Enable TCP fallback transport (QUIC only)"
            echo "  --latency MS             Add network latency between validators (requires sudo)"
            echo "  --packet-loss PERCENT    Add packet loss between validators (requires sudo)"
            echo "  --mempool-max-in-flight N          Soft limit on in-flight transactions (default: 512)"
            echo "  --mempool-max-in-flight-hard-limit N  Hard limit on in-flight transactions (default: 1024)"
            echo "  --mempool-max-pending N  Max pending transactions before RPC backpressure (default: 2048)"
            echo ""
            echo "Environment Variables:"
            echo "  VALIDATOR_BIN            Path to validator binary (default: ./target/release/hyperscale-validator)"
            echo "  KEYGEN_BIN               Path to keygen binary (default: ./target/release/hyperscale-keygen)"
            echo "  SPAMMER_BIN              Path to spammer binary (default: ./target/release/hyperscale-spammer)"
            echo "  SMOKE_TEST_TIMEOUT       Smoke test timeout (default: 60s)"
            echo "  NODE_HOSTNAME            Hostname for spammer endpoints (default: localhost)"
            echo "  SKIP_BUILD               Skip building binaries (default: false)"
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

# Network simulation functions (cross-platform: Linux tc, macOS dnctl/pfctl)
apply_network_conditions() {
    if [ -z "$NETWORK_LATENCY_MS" ] && [ -z "$PACKET_LOSS_PERCENT" ]; then
        return 0
    fi

    local latency="${NETWORK_LATENCY_MS:-0}"
    local loss="${PACKET_LOSS_PERCENT:-0}"

    # Calculate port ranges for validators (P2P only, not RPC)
    local quic_port_start=$BASE_PORT
    local quic_port_end=$((BASE_PORT + TOTAL_VALIDATORS - 1))
    local tcp_port_start=$TCP_BASE_PORT
    local tcp_port_end=$((TCP_BASE_PORT + TOTAL_VALIDATORS - 1))

    echo "Applying network conditions (latency: ${latency}ms, packet loss: ${loss}%)..."
    echo "  Affecting P2P ports: QUIC ${quic_port_start}-${quic_port_end}, TCP ${tcp_port_start}-${tcp_port_end}"

    case "$(uname -s)" in
        Linux)
            # Use tc with iptables marking for port-based filtering
            # First, clean up any existing rules
            sudo tc qdisc del dev lo root 2>/dev/null || true
            sudo iptables -t mangle -F OUTPUT 2>/dev/null || true

            # Mark packets for validator P2P ports (not RPC)
            sudo iptables -t mangle -A OUTPUT -p udp --dport ${quic_port_start}:${quic_port_end} -j MARK --set-mark 1
            sudo iptables -t mangle -A OUTPUT -p tcp --dport ${tcp_port_start}:${tcp_port_end} -j MARK --set-mark 1

            # Create prio qdisc with netem for marked packets
            sudo tc qdisc add dev lo root handle 1: prio
            sudo tc qdisc add dev lo parent 1:3 handle 30: netem delay ${latency}ms loss ${loss}%
            sudo tc filter add dev lo parent 1:0 protocol ip prio 3 handle 1 fw flowid 1:3

            echo "  Applied via tc/iptables on Linux"
            ;;
        Darwin)
            # Use dnctl + pfctl for macOS
            # Clean up first
            sudo pfctl -d 2>/dev/null || true
            sudo dnctl -q flush 2>/dev/null || true

            # Convert loss percentage to probability (0.0 to 1.0)
            local plr=$(echo "scale=4; ${loss}/100" | bc)

            # Create dummynet pipe with delay and packet loss
            sudo dnctl pipe 1 config delay ${latency}ms plr ${plr}

            # Create pf rules for validator P2P ports only (not RPC)
            cat <<EOF | sudo pfctl -f -
# Hyperscale network simulation rules (P2P only)
dummynet in proto udp from any to any port ${quic_port_start}:${quic_port_end} pipe 1
dummynet out proto udp from any port ${quic_port_start}:${quic_port_end} to any pipe 1
dummynet in proto tcp from any to any port ${tcp_port_start}:${tcp_port_end} pipe 1
dummynet out proto tcp from any port ${tcp_port_start}:${tcp_port_end} to any pipe 1
EOF
            sudo pfctl -e 2>/dev/null || true

            echo "  Applied via dnctl/pfctl on macOS"
            ;;
        *)
            echo "WARNING: Network simulation not supported on $(uname -s)"
            return 1
            ;;
    esac
}

remove_network_conditions() {
    if [ -z "$NETWORK_LATENCY_MS" ] && [ -z "$PACKET_LOSS_PERCENT" ]; then
        return 0
    fi

    echo "Removing network conditions..."

    case "$(uname -s)" in
        Linux)
            sudo tc qdisc del dev lo root 2>/dev/null || true
            sudo iptables -t mangle -F OUTPUT 2>/dev/null || true
            ;;
        Darwin)
            sudo pfctl -d 2>/dev/null || true
            sudo dnctl -q flush 2>/dev/null || true
            ;;
    esac
}

# Validate minimum validators per shard
if [ "$VALIDATORS_PER_SHARD" -lt 4 ]; then
    echo "ERROR: Minimum 4 validators per shard required for BFT consensus."
    echo "       With 3 or less validators, the cluster will not work."
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
echo "Smoke test timeout: $SMOKE_TEST_TIMEOUT"
echo "Skip build: $SKIP_BUILD"
echo "Clean data dir: $CLEAN"
echo "TCP fallback: $TCP_FALLBACK_ENABLED"
echo "Tracing: $TRACING"
if [ -n "$NETWORK_LATENCY_MS" ] || [ -n "$PACKET_LOSS_PERCENT" ]; then
    echo "Network simulation: latency=${NETWORK_LATENCY_MS:-0}ms, loss=${PACKET_LOSS_PERCENT:-0}%"
fi
echo "Network Ports:"
echo "  QUIC Range: $QUIC_PORT_RANGE"
echo "  TCP Range:  $TCP_PORT_RANGE"
echo ""

# Clean up if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning data directories..."
    rm -rf "$DATA_DIR"
fi

# Create data directory
mkdir -p "$DATA_DIR"

# Build the validator, keygen, and spammer binaries
if [ "$SKIP_BUILD" != "true" ]; then
    echo "Building binaries..."
    cargo build --release --bin hyperscale-validator --bin hyperscale-keygen --bin hyperscale-spammer 2>&1 | tail -3
else
    echo "Skipping build (SKIP_BUILD=true)..."
fi

VALIDATOR_BIN="${VALIDATOR_BIN:-./target/release/hyperscale-validator}"
KEYGEN_BIN="${KEYGEN_BIN:-./target/release/hyperscale-keygen}"
SPAMMER_BIN="${SPAMMER_BIN:-./target/release/hyperscale-spammer}"

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
    # keygen outputs "public_key_hex peer_id" - we only need the public key
    PUBLIC_KEYS[$i]=$("$KEYGEN_BIN" "$SEED_HEX" | awk '{print $1}')
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
    quic_port=$((BASE_PORT + first_validator))
    tcp_port=$((TCP_BASE_PORT + first_validator))
    if [ -n "$BOOTSTRAP_PEERS" ]; then
        BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"
    fi
    # We'll use localhost multiaddr format
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/127.0.0.1/udp/$quic_port/quic-v1\",\"/ip4/127.0.0.1/tcp/$tcp_port\""
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

    # Calculate per-validator ports to avoid race conditions during startup
    validator_quic_port=$((BASE_PORT + i))
    validator_tcp_port=$((TCP_BASE_PORT + i))

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
# Use specific ports per validator to avoid race conditions during parallel startup
listen_addr = "/ip4/0.0.0.0/udp/$validator_quic_port/quic-v1"
tcp_fallback_enabled = $TCP_FALLBACK_ENABLED
tcp_fallback_port = $validator_tcp_port
version_interop_mode = "relaxed"
bootstrap_peers = [$BOOTSTRAP_PEERS]
upnp_enabled = false
max_message_size = 10485760
gossipsub_heartbeat_ms = 100

[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000
max_transactions_per_block = 1024
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

[mempool]
max_in_flight = $MEMPOOL_MAX_IN_FLIGHT
max_in_flight_hard_limit = $MEMPOOL_MAX_IN_FLIGHT_HARD_LIMIT
max_pending = $MEMPOOL_MAX_PENDING

[metrics]
enabled = true
listen_addr = "0.0.0.0:$rpc_port"

[telemetry]
enabled = $TRACING
otlp_endpoint = "http://localhost:4317"
service_name = "hyperscale-validator"

$GENESIS_VALIDATORS

${SHARD_GENESIS_BALANCES[$shard]}
EOF

    echo "  Created config for validator $i (shard $shard, rpc port $rpc_port)"
done

# Launch validators
echo ""
echo "Launching validators..."
PID_FILE="$DATA_DIR/pids.txt"
> "$PID_FILE"
declare -a VALIDATOR_PIDS

for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    CONFIG_FILE="$DATA_DIR/validator-$i/config.toml"
    LOG_FILE="$DATA_DIR/validator-$i/output.log"

    echo "  Starting validator $i (shard $shard)..."

    # Build RUST_LOG based on log level
    # Always suppress noisy dependencies, but let hyperscale crates use the specified level
    # libp2p_gossipsub=error to suppress "duplicate message" warnings which are normal in gossip
    RUST_LOG="warn,hyperscale=$LOG_LEVEL,hyperscale_production=$LOG_LEVEL,libp2p_gossipsub=error" "$VALIDATOR_BIN" --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    PID=$!
    VALIDATOR_PIDS[$i]=$PID
    echo "$PID" >> "$PID_FILE"
    echo "    PID: $PID, logs: $LOG_FILE"

    # Small delay to stagger startup
    sleep 0.2
done

# Wait a moment for validators to either start or fail
sleep 1

# Check if any validators died during startup
FAILED=false
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    PID=${VALIDATOR_PIDS[$i]}
    if ! kill -0 "$PID" 2>/dev/null; then
        echo ""
        echo "ERROR: Validator $i (PID $PID) failed to start!"
        echo "Log output:"
        cat "$DATA_DIR/validator-$i/output.log"
        echo ""
        FAILED=true
    fi
done

if [ "$FAILED" = true ]; then
    echo "One or more validators failed to start. Stopping cluster..."
    for pid in "${VALIDATOR_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 1
fi

# Apply network conditions after validators are running
apply_network_conditions

echo ""
echo "=== Cluster Started ==="
echo ""
echo "Validator endpoints:"
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    rpc_port=$((BASE_RPC_PORT + i))
    echo "  Validator $i (shard $shard): http://$NODE_HOSTNAME:$rpc_port"
done

echo ""
echo "Useful commands:"
echo "  Check health:  curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/health"
echo "  Get status:    curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/api/v1/status"
echo "  View metrics:  curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/metrics"
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
    SPAMMER_ENDPOINTS="${SPAMMER_ENDPOINTS}http://$NODE_HOSTNAME:$rpc_port"
done

echo "Run spammer:"
echo "  $SPAMMER_BIN run \\"
echo "    --endpoints $SPAMMER_ENDPOINTS \\"
echo "    --num-shards $NUM_SHARDS \\"
echo "    --validators-per-shard $VALIDATORS_PER_SHARD \\"
echo "    --tps 100 \\"
echo "    --duration 30s \\"
echo "    --measure-latency"
echo ""
echo "PIDs written to: $PID_FILE"

# Run smoke test to verify the cluster is working
echo ""
echo "=== Running Smoke Test ==="
echo "Waiting for cluster to stabilize..."
sleep 3

# Temporarily disable exit-on-error for smoke test
set +e
"$SPAMMER_BIN" smoke-test \
    --endpoints "$SPAMMER_ENDPOINTS" \
    --num-shards "$NUM_SHARDS" \
    --validators-per-shard "$VALIDATORS_PER_SHARD" \
    --accounts-per-shard "$ACCOUNTS_PER_SHARD" \
    --wait-ready \
    --timeout "$SMOKE_TEST_TIMEOUT" \
    --poll-interval 100ms

SMOKE_TEST_EXIT=$?
set -e
if [ $SMOKE_TEST_EXIT -eq 0 ]; then
    echo ""
    echo "=== Cluster is ready for use ==="
else
    echo ""
    echo "WARNING: Smoke test failed with exit code $SMOKE_TEST_EXIT"
    echo "Check validator logs for details: tail -f $DATA_DIR/validator-*/output.log"
fi

# Cleanup function to kill all child processes
cleanup() {
    echo ""
    echo "Stopping cluster..."

    # Remove network conditions first
    remove_network_conditions

    # Read PIDs from file if available, otherwise kill by pattern might be too aggressive
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
            fi
        done < "$PID_FILE"
    fi

    # Stop monitoring stack if it was started
    if [ "$MONITORING" = true ] || [ "$TRACING" = true ]; then
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        MONITORING_DIR="$SCRIPT_DIR/monitoring"

        if command -v docker &> /dev/null; then
            if docker ps --format '{{.Names}}' | grep -q "hyperscale-prometheus\|hyperscale-grafana\|hyperscale-jaeger"; then
                DC=$(command -v docker-compose >/dev/null 2>&1 && echo "docker-compose" || echo "docker compose")
                echo ""
                echo "Stopping monitoring stack and removing volumes..."
                (cd "$MONITORING_DIR" && $DC down -v 2>&1) | tail -2
                echo "Monitoring stopped."
            fi
        fi
    fi
    exit 0
}

# Trap signals for graceful shutdown
trap cleanup SIGINT SIGTERM

# Start monitoring stack if requested
if [ "$MONITORING" = true ] || [ "$TRACING" = true ]; then
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

global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'hyperscale'
    static_configs:$PROM_STATIC_CONFIGS
    metrics_path: '/metrics'
    scrape_timeout: 5s
EOF


    DC=$(command -v docker-compose >/dev/null 2>&1 && echo "docker-compose" || echo "docker compose")

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo "WARNING: Docker not found. Cannot start monitoring stack."
        echo "Install Docker and run manually: cd $MONITORING_DIR && $DC up -d"
    else
        # Start the monitoring stack
        if [ "$MONITORING" = true ]; then
            echo "Starting Prometheus, Grafana, and Jaeger..."
        else
            echo "Starting Jaeger for distributed tracing..."
        fi
        (cd "$MONITORING_DIR" && $DC up -d 2>&1) | tail -5

        echo ""
        echo "Monitoring URLs:"
        if [ "$MONITORING" = true ]; then
            echo "  Prometheus: http://localhost:9090"
            echo "  Grafana:    http://localhost:3000/d/hyperscale-cluster/hyperscale-cluster"
        fi
        if [ "$TRACING" = true ]; then
            echo "  Traces:     http://localhost:3000/explore (Grafana - better UI, select Jaeger datasource)"
            echo "  Jaeger:     http://localhost:16686 (legacy UI)"
        fi
        echo ""
        echo "Stop monitoring: cd $MONITORING_DIR && $DC down"
    fi
fi

# Keep script running to maintain container life and handle signals
echo "Cluster is running. Press Ctrl+C to stop."
wait
