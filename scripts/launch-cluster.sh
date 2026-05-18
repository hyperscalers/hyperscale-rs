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
VNODES_PER_HOST=1                               # Validators bundled into each host process. Must divide VALIDATORS_PER_SHARD.
CROSS_SHARD_PACK=false                          # Stripe one vnode from every shard into each host process.
BASE_PORT=9000                                  # libp2p port
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
NETWORK_LATENCY_MS="100"                        # Network latency in milliseconds (empty = disabled)
PACKET_LOSS_PERCENT=""                          # Packet loss percentage (empty = disabled)
JMT_HISTORY_LENGTH=256                          # Number of block heights of JMT history to retain (default: 256)

# Mempool configuration
MEMPOOL_MAX_PENDING=8192                        # Max pending before RPC backpressure

# Define explicit port ranges for Docker and firewall whitelisting
# let's give a range of 500 ports which should be ok for local testing
QUIC_PORT_RANGE="${BASE_PORT}-$((BASE_PORT + 500))"

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
        --vnodes-per-host)
            VNODES_PER_HOST="$2"
            shift 2
            ;;
        --cross-shard-pack)
            CROSS_SHARD_PACK=true
            shift
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
        --mempool-max-pending)
            MEMPOOL_MAX_PENDING="$2"
            shift 2
            ;;
        --state-history-length)
            JMT_HISTORY_LENGTH="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--shards N] [--validators-per-shard M] [--clean] [--monitoring] [--log-level LEVEL] [--smoke-timeout DURATION] [--node-hostname HOST]"
            echo ""
            echo "Options:"
            echo "  --shards N               Number of shards (default: 2)"
            echo "  --validators-per-shard M Validators per shard (default: 4, minimum: 4)"
            echo "  --vnodes-per-host K      Validators bundled into each host process (default: 1). Must divide validators-per-shard. Same-shard packing."
            echo "  --cross-shard-pack       Stripe one vnode from every shard into each host (requires shards >= 2; not combinable with --vnodes-per-host > 1)."
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
            echo "  --latency MS             Add network latency between validators (requires sudo)"
            echo "  --packet-loss PERCENT    Add packet loss between validators (requires sudo)"
            echo "  --mempool-max-pending N  Max pending transactions before RPC backpressure (default: 8192)"
            echo "  --state-history-length N Number of state versions to retain (default: 60000)"
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

    # Calculate port ranges for host processes (P2P only, not RPC)
    local quic_port_start=$BASE_PORT
    local quic_port_end=$((BASE_PORT + TOTAL_HOSTS - 1))

    echo "Applying network conditions (latency: ${latency}ms, packet loss: ${loss}%)..."
    echo "  Affecting P2P ports: QUIC ${quic_port_start}-${quic_port_end}"

    case "$(uname -s)" in
        Linux)
            # Use tc with iptables marking for port-based filtering
            # First, clean up any existing rules
            sudo tc qdisc del dev lo root 2>/dev/null || true
            sudo iptables -t mangle -F OUTPUT 2>/dev/null || true

            # Mark packets for validator P2P ports (not RPC)
            sudo iptables -t mangle -A OUTPUT -p udp --dport ${quic_port_start}:${quic_port_end} -j MARK --set-mark 1

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

            # Create pf rules for validator P2P ports only (not RPC).
            # Egress-only: on loopback, the same packet traverses pf at both the
            # sender's `out` hook and the receiver's `in` hook. Matching both
            # would feed the packet through pipe 1 twice, doubling the simulated
            # one-way delay (and compounding loss). Source-port match catches
            # every validator->validator packet since both endpoints are in range.
            cat <<EOF | sudo pfctl -f -
# Hyperscale network simulation rules (P2P only)
dummynet out proto udp from any port ${quic_port_start}:${quic_port_end} to any pipe 1
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

# Validate packing flags and derive host count.
#
# Two packing strategies:
#   - Same-shard (default): K consecutive same-shard validators per host. Each
#     host serves exactly one shard. HOSTS_PER_SHARD = VPS / K.
#   - Cross-shard: each host runs one vnode from every shard. Stripes the
#     validator-index "position" across shards. TOTAL_HOSTS = VPS, each host
#     holds NUM_SHARDS vnodes. Validator binary already handles cross-shard
#     hosting; the per-shard RocksDB instances open at data_dir/shard-{N}/db.
if [ "$VNODES_PER_HOST" -lt 1 ]; then
    echo "ERROR: --vnodes-per-host must be >= 1."
    exit 1
fi

if [ "$CROSS_SHARD_PACK" = true ]; then
    if [ "$NUM_SHARDS" -lt 2 ]; then
        echo "ERROR: --cross-shard-pack requires --shards >= 2."
        exit 1
    fi
    if [ "$VNODES_PER_HOST" -gt 1 ]; then
        echo "ERROR: --cross-shard-pack cannot be combined with --vnodes-per-host > 1."
        exit 1
    fi
    HOSTS_PER_SHARD=$VALIDATORS_PER_SHARD
    TOTAL_HOSTS=$VALIDATORS_PER_SHARD
    PACK_DESCRIPTION="cross-shard (one vnode from each shard per host)"
else
    if [ $((VALIDATORS_PER_SHARD % VNODES_PER_HOST)) -ne 0 ]; then
        echo "ERROR: --vnodes-per-host ($VNODES_PER_HOST) must divide --validators-per-shard ($VALIDATORS_PER_SHARD)."
        exit 1
    fi
    HOSTS_PER_SHARD=$((VALIDATORS_PER_SHARD / VNODES_PER_HOST))
    TOTAL_HOSTS=$((NUM_SHARDS * HOSTS_PER_SHARD))
    PACK_DESCRIPTION="same-shard ($VNODES_PER_HOST vnodes/host)"
fi

echo "=== Hyperscale Local Cluster ==="
echo "Shards: $NUM_SHARDS"
echo "Validators per shard: $VALIDATORS_PER_SHARD"
echo "Packing: $PACK_DESCRIPTION"
echo "Total hosts: $TOTAL_HOSTS"
echo "Total validators: $TOTAL_VALIDATORS"
echo "Accounts per shard: $ACCOUNTS_PER_SHARD"
echo "Initial balance: $INITIAL_BALANCE XRD"
echo "Log level: $LOG_LEVEL"
echo "Smoke test timeout: $SMOKE_TEST_TIMEOUT"
echo "Skip build: $SKIP_BUILD"
echo "Clean data dir: $CLEAN"
echo "Tracing: $TRACING"
if [ -n "$NETWORK_LATENCY_MS" ] || [ -n "$PACKET_LOSS_PERCENT" ]; then
    echo "Network simulation: latency=${NETWORK_LATENCY_MS:-0}ms, loss=${PACKET_LOSS_PERCENT:-0}%"
fi
echo "Network Ports:"
echo "  QUIC Range: $QUIC_PORT_RANGE"
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

# Generate keypairs and collect public keys. Keys live in a flat $DATA_DIR/keys
# dir; each host's TOML references the per-validator paths from there.
echo "Generating validator keypairs..."
declare -a PUBLIC_KEYS
declare -a KEY_FILES
mkdir -p "$DATA_DIR/keys"

for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    KEY_FILE="$DATA_DIR/keys/v-$i.key"
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

# Calculate bootstrap peer addresses. Pick NUM_SHARDS hosts for redundancy.
# - Same-shard: the first host of each shard (host_idx = shard * HOSTS_PER_SHARD).
# - Cross-shard: every host serves every shard, so the first NUM_SHARDS hosts.
BOOTSTRAP_PEERS=""
for shard in $(seq 0 $((NUM_SHARDS - 1))); do
    if [ "$CROSS_SHARD_PACK" = true ]; then
        bootstrap_host_idx=$shard
    else
        bootstrap_host_idx=$((shard * HOSTS_PER_SHARD))
    fi
    quic_port=$((BASE_PORT + bootstrap_host_idx))
    if [ -n "$BOOTSTRAP_PEERS" ]; then
        BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"
    fi
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/127.0.0.1/udp/$quic_port/quic-v1\""
done

# Build the [[genesis.validators]] section once — it's identical across hosts,
# listing every validator across every shard so each host can verify cross-
# shard messages.
GENESIS_VALIDATORS=""
for j in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    if [ -n "$GENESIS_VALIDATORS" ]; then
        GENESIS_VALIDATORS="$GENESIS_VALIDATORS
"
    fi
    validator_shard=$((j / VALIDATORS_PER_SHARD))
    GENESIS_VALIDATORS="$GENESIS_VALIDATORS[[genesis.validators]]
id = $j
shard = $validator_shard
public_key = \"${PUBLIC_KEYS[$j]}\"
voting_power = 1"
done

# Generate one TOML per host. Packing strategy:
#   - Same-shard: host h packs K consecutive same-shard validators starting at
#     index (shard * VPS + h_in_shard * K).
#   - Cross-shard: host h packs one validator from each shard at index
#     (shard * VPS + h), so host h holds validators [h, VPS+h, 2*VPS+h, ...].
echo "Generating config files..."
for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
    quic_port=$((BASE_PORT + host_idx))
    rpc_port=$((BASE_RPC_PORT + host_idx))

    HOST_DIR="$DATA_DIR/host-$host_idx"
    CONFIG_FILE="$HOST_DIR/config.toml"
    NODE_DATA_DIR="$HOST_DIR/data"
    mkdir -p "$NODE_DATA_DIR"

    # Build [[vnode]] blocks and accumulate the per-shard genesis balance
    # blocks this host needs (one block per distinct hosted shard). Shard
    # indices are small integers, so an indexed array doubles as a dedup
    # set without needing bash-4-only associative arrays.
    VNODE_BLOCKS=""
    HOSTED_LIST=""
    SHARD_SUMMARY=""
    HOST_GENESIS_BALANCES=""
    HOST_SHARDS_INCLUDED=()

    add_vnode_block() {
        local vid=$1
        local sh=$2
        if [ -n "$VNODE_BLOCKS" ]; then
            VNODE_BLOCKS="$VNODE_BLOCKS
"
        fi
        VNODE_BLOCKS="$VNODE_BLOCKS[[vnode]]
validator_id = $vid
shard = $sh
key_path = \"${KEY_FILES[$vid]}\""
        if [ -n "$HOSTED_LIST" ]; then
            HOSTED_LIST="$HOSTED_LIST, "
        fi
        HOSTED_LIST="$HOSTED_LIST$vid"
        if [ -z "${HOST_SHARDS_INCLUDED[$sh]:-}" ]; then
            HOST_SHARDS_INCLUDED[$sh]=1
            if [ -n "$HOST_GENESIS_BALANCES" ]; then
                HOST_GENESIS_BALANCES="$HOST_GENESIS_BALANCES

"
            fi
            HOST_GENESIS_BALANCES="$HOST_GENESIS_BALANCES${SHARD_GENESIS_BALANCES[$sh]}"
        fi
    }

    if [ "$CROSS_SHARD_PACK" = true ]; then
        # One vnode from each shard at validator index (shard * VPS + host_idx).
        for shard in $(seq 0 $((NUM_SHARDS - 1))); do
            vnode_id=$((shard * VALIDATORS_PER_SHARD + host_idx))
            add_vnode_block "$vnode_id" "$shard"
        done
        SHARD_SUMMARY="shards [0..$((NUM_SHARDS - 1))]"
    else
        shard=$((host_idx / HOSTS_PER_SHARD))
        h_in_shard=$((host_idx % HOSTS_PER_SHARD))
        first_vnode=$((shard * VALIDATORS_PER_SHARD + h_in_shard * VNODES_PER_HOST))
        for k in $(seq 0 $((VNODES_PER_HOST - 1))); do
            vnode_id=$((first_vnode + k))
            add_vnode_block "$vnode_id" "$shard"
        done
        SHARD_SUMMARY="shard $shard"
    fi

    cat > "$CONFIG_FILE" << EOF
# Hyperscale Validator Configuration
# Auto-generated for local cluster testing
# Host $host_idx: $SHARD_SUMMARY, vnodes [$HOSTED_LIST]

[node]
num_shards = $NUM_SHARDS
data_dir = "$NODE_DATA_DIR"

$VNODE_BLOCKS

[network]
listen_addr = "/ip4/0.0.0.0/udp/$quic_port/quic-v1"
version_interop_mode = "relaxed"
bootstrap_peers = [$BOOTSTRAP_PEERS]
upnp_enabled = false
max_message_size = 10485760

[threads]
consensus_crypto_threads = 0
crypto_threads = 0
tx_validation_threads = 0
execution_threads = 0
io_threads = 0
pin_cores = false

[storage]
max_background_jobs = 2
write_buffer_mb = 64
block_cache_mb = 256
jmt_history_length = $JMT_HISTORY_LENGTH

[mempool]
max_pending = $MEMPOOL_MAX_PENDING

[metrics]
enabled = true
listen_addr = "0.0.0.0:$rpc_port"

[telemetry]
enabled = $TRACING
otlp_endpoint = "http://localhost:4317"
service_name = "hyperscale-validator"
log_file = "$HOST_DIR/output.log"

$GENESIS_VALIDATORS

$HOST_GENESIS_BALANCES
EOF

    echo "  Created config for host $host_idx ($SHARD_SUMMARY, vnodes [$HOSTED_LIST], rpc port $rpc_port)"
    unset HOST_SHARDS_INCLUDED
done

# Apply network conditions before starting validators so they experience
# realistic conditions from the first message exchange
apply_network_conditions

# Launch hosts
echo ""
echo "Launching hosts..."
PID_FILE="$DATA_DIR/pids.txt"
> "$PID_FILE"
declare -a HOST_PIDS

for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
    HOST_DIR="$DATA_DIR/host-$host_idx"
    CONFIG_FILE="$HOST_DIR/config.toml"
    LOG_FILE="$HOST_DIR/output.log"

    if [ "$CROSS_SHARD_PACK" = true ]; then
        host_summary="cross-shard"
    else
        host_summary="shard $((host_idx / HOSTS_PER_SHARD))"
    fi
    echo "  Starting host $host_idx ($host_summary)..."

    # Tracing output goes to log_file (configured in TOML) with ANSI disabled.
    # Stderr redirect captures panics/crash output only.
    RUST_LOG="warn,hyperscale=$LOG_LEVEL,hyperscale_production=$LOG_LEVEL,libp2p_gossipsub=error" "$VALIDATOR_BIN" --config "$CONFIG_FILE" 2>> "$HOST_DIR/crash.log" &
    PID=$!
    HOST_PIDS[$host_idx]=$PID
    echo "$PID" >> "$PID_FILE"
    echo "    PID: $PID, logs: $LOG_FILE"

    # Small delay to stagger startup
    sleep 0.2
done

# Wait a moment for hosts to either start or fail
sleep 1

# Check if any hosts died during startup
FAILED=false
for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
    PID=${HOST_PIDS[$host_idx]}
    if ! kill -0 "$PID" 2>/dev/null; then
        echo ""
        echo "ERROR: Host $host_idx (PID $PID) failed to start!"
        echo "Log output:"
        cat "$DATA_DIR/host-$host_idx/output.log" 2>/dev/null || cat "$DATA_DIR/host-$host_idx/crash.log" 2>/dev/null
        echo ""
        FAILED=true
    fi
done

if [ "$FAILED" = true ]; then
    echo "One or more hosts failed to start. Stopping cluster..."
    for pid in "${HOST_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 1
fi

echo ""
echo "=== Cluster Started ==="
echo ""
echo "Host endpoints:"
for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
    rpc_port=$((BASE_RPC_PORT + host_idx))
    if [ "$CROSS_SHARD_PACK" = true ]; then
        # Cross-shard host runs one vnode from each shard at index (s * VPS + host_idx).
        vnodes_str=""
        for s in $(seq 0 $((NUM_SHARDS - 1))); do
            vid=$((s * VALIDATORS_PER_SHARD + host_idx))
            if [ -n "$vnodes_str" ]; then
                vnodes_str="$vnodes_str, "
            fi
            vnodes_str="$vnodes_str$vid"
        done
        echo "  Host $host_idx (cross-shard, vnodes [$vnodes_str]): http://$NODE_HOSTNAME:$rpc_port"
    else
        shard=$((host_idx / HOSTS_PER_SHARD))
        h_in_shard=$((host_idx % HOSTS_PER_SHARD))
        first_vnode=$((shard * VALIDATORS_PER_SHARD + h_in_shard * VNODES_PER_HOST))
        last_vnode=$((first_vnode + VNODES_PER_HOST - 1))
        echo "  Host $host_idx (shard $shard, vnodes $first_vnode..$last_vnode): http://$NODE_HOSTNAME:$rpc_port"
    fi
done

echo ""
echo "Useful commands:"
echo "  Check health:  curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/health"
echo "  Get status:    curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/api/v1/status"
echo "  View metrics:  curl http://$NODE_HOSTNAME:$BASE_RPC_PORT/metrics"
echo "  View logs:     tail -f $DATA_DIR/host-0/output.log"
echo "  Stop cluster:  ./scripts/stop-cluster.sh"
echo ""

# Build spammer endpoint list (one entry per host for load distribution)
SPAMMER_ENDPOINTS=""
for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
    rpc_port=$((BASE_RPC_PORT + host_idx))
    if [ -n "$SPAMMER_ENDPOINTS" ]; then
        SPAMMER_ENDPOINTS="$SPAMMER_ENDPOINTS,"
    fi
    SPAMMER_ENDPOINTS="${SPAMMER_ENDPOINTS}http://$NODE_HOSTNAME:$rpc_port"
done

SPAMMER_PACKING_FLAGS="--vnodes-per-host $VNODES_PER_HOST"
if [ "$CROSS_SHARD_PACK" = true ]; then
    SPAMMER_PACKING_FLAGS="$SPAMMER_PACKING_FLAGS --cross-shard-pack"
fi

echo "Run spammer:"
echo "  $SPAMMER_BIN run \\"
echo "    --endpoints $SPAMMER_ENDPOINTS \\"
echo "    --num-shards $NUM_SHARDS \\"
echo "    --validators-per-shard $VALIDATORS_PER_SHARD \\"
echo "    $SPAMMER_PACKING_FLAGS \\"
echo "    --tps 100 \\"
echo "    --duration 30s \\"
echo "    --measure-latency"
echo ""
echo "PIDs written to: $PID_FILE"

# Run smoke test to verify the cluster is working
echo ""
echo "=== Running Smoke Test ==="

# Temporarily disable exit-on-error for smoke test
set +e
SMOKE_TEST_PACKING_FLAGS=(--vnodes-per-host "$VNODES_PER_HOST")
if [ "$CROSS_SHARD_PACK" = true ]; then
    SMOKE_TEST_PACKING_FLAGS+=(--cross-shard-pack)
fi

"$SPAMMER_BIN" smoke-test \
    --endpoints "$SPAMMER_ENDPOINTS" \
    --num-shards "$NUM_SHARDS" \
    --validators-per-shard "$VALIDATORS_PER_SHARD" \
    "${SMOKE_TEST_PACKING_FLAGS[@]}" \
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
    echo "Check host logs for details: tail -f $DATA_DIR/host-*/output.log"
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

    # Generate prometheus.yml with one target per host. The `shard` and
    # `validator_id` labels are stamped by the application on per-shard /
    # per-vnode metrics, so the scrape config doesn't inject them — every
    # host is a single target.
    echo "Generating Prometheus configuration for $TOTAL_HOSTS hosts across $NUM_SHARDS shards..."

    ALL_TARGETS=""
    for host_idx in $(seq 0 $((TOTAL_HOSTS - 1))); do
        rpc_port=$((BASE_RPC_PORT + host_idx))
        if [ -n "$ALL_TARGETS" ]; then
            ALL_TARGETS="$ALL_TARGETS
          - 'host.docker.internal:$rpc_port'"
        else
            ALL_TARGETS="- 'host.docker.internal:$rpc_port'"
        fi
    done
    PROM_STATIC_CONFIGS="
      - targets:
          $ALL_TARGETS
        labels:
          cluster: 'local'"

    cat > "$MONITORING_DIR/prometheus.yml" << EOF
# Prometheus configuration for Hyperscale local cluster
# $NUM_SHARDS shards x $HOSTS_PER_SHARD hosts/shard = $TOTAL_HOSTS host processes
# ($VALIDATORS_PER_SHARD validators/shard, $VNODES_PER_HOST vnodes/host)

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
