#!/bin/bash
#
# Generate configuration for a distributed hyperscale cluster.
#
# Usage:
#   ./scripts/generate-distributed-config.sh --hosts "IP1,IP2..." [--nodes-per-host N] [--out-dir DIR]
#
# Examples:
#   ./scripts/generate-distributed-config.sh --hosts "192.168.1.10,192.168.1.11" --nodes-per-host 2
#

set -e

# Default configuration
HOSTS=""
OUT_DIR="./distributed-cluster-data"
BASE_PORT=9000
TCP_BASE_PORT=30500
RPC_BASE_PORT=8080
NUM_SHARDS=1 # Simplification for now: 1 shard for N nodes
CLEAN=false
NODES_PER_HOST=1
CRYPTO_THREADS=0
EXECUTION_THREADS=0
IO_THREADS=0
COPY_TO_REMOTE=false
REMOTE_PATH="~/git/hyperscale-rs/distributed-cluster-data/"
REMOTE_USER="$(whoami)"

while [[ $# -gt 0 ]]; do
    case $1 in
        --hosts)
            HOSTS="$2"
            shift 2
            ;;
        --nodes) # Deprecated alias for back-compat or user muscle memory, mapping to HOSTS
            HOSTS="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --nodes-per-host)
            NODES_PER_HOST="$2"
            shift 2
            ;;
        --validators-per-node) # Deprecated alias
            NODES_PER_HOST="$2"
            shift 2
            ;;
        --shards|--num-shards)
            NUM_SHARDS="$2"
            shift 2
            ;;
        --crypto-threads)
            CRYPTO_THREADS="$2"
            shift 2
            ;;
        --execution-threads)
            EXECUTION_THREADS="$2"
            shift 2
            ;;
        --io-threads)
            IO_THREADS="$2"
            shift 2
            ;;
        --copy-to-remote)
            COPY_TO_REMOTE=true
            shift
            ;;
        --remote-path)
            REMOTE_PATH="$2"
            shift 2
            ;;
        --remote-user)
            REMOTE_USER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 --hosts \"IP1,IP2...\" [--nodes-per-host N] [--shards N] [--out-dir DIR] [--clean]"
            echo "       [--crypto-threads N] [--execution-threads N] [--io-threads N]"
            echo "       [--copy-to-remote] [--remote-path DIR] [--remote-user USER]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$HOSTS" ]; then
    echo "ERROR: --hosts argument is required (comma-separated IPs)"
    exit 1
fi

# Split hosts into array
IFS=',' read -r -a HOST_IPS <<< "$HOSTS"
NUM_HOSTS=${#HOST_IPS[@]}
TOTAL_NODES=$((NUM_HOSTS * NODES_PER_HOST))

if (( TOTAL_NODES % NUM_SHARDS != 0 )); then
    echo "ERROR: Total nodes ($TOTAL_NODES) must be divisible by number of shards ($NUM_SHARDS)"
    exit 1
fi

NODES_PER_SHARD=$((TOTAL_NODES / NUM_SHARDS))

echo "=== Generating Distributed Cluster Config ==="
echo "Hosts: ${HOST_IPS[*]}"
echo "Nodes per Host: $NODES_PER_HOST"
echo "Shards: $NUM_SHARDS"
echo "Nodes per Shard: $NODES_PER_SHARD"
echo "Total Nodes (Validators): $TOTAL_NODES"
echo "Output Directory: $OUT_DIR"
echo "Clean: $CLEAN"
echo ""

# Build binaries if needed (keygen and spammer are essential)
KEYGEN_BIN="./target/release/hyperscale-keygen"
SPAMMER_BIN="./target/release/hyperscale-spammer"

if [ ! -f "$KEYGEN_BIN" ] || [ ! -f "$SPAMMER_BIN" ]; then
    echo "Building binaries..."
    cargo build --release --bin hyperscale-keygen --bin hyperscale-spammer 2>&1 | tail -3
fi

# Clean output dir if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning output directory..."
    rm -rf "$OUT_DIR"
fi
mkdir -p "$OUT_DIR"

# 1. Generate Keys
echo "Generating keys..."
declare -a PUBLIC_KEYS
declare -a PEER_IDS

# Flattened list of nodes for easier iterating later
# Structure: NODE_HOST_IPS[id] = IP, NODE_P2P_PORTS[id] = BASE_PORT + offset
declare -a NODE_HOST_IPS
declare -a NODE_P2P_PORTS

for i in "${!HOST_IPS[@]}"; do
    IP="${HOST_IPS[$i]}"
    HOST_DIR="$OUT_DIR/host-$i"
    mkdir -p "$HOST_DIR"
    
    for v in $(seq 0 $((NODES_PER_HOST - 1))); do
        # Global node ID
        NODE_ID=$((i * NODES_PER_HOST + v))
        NODE_DIR="$HOST_DIR/node-$v"
        mkdir -p "$NODE_DIR"
        
        KEY_FILE="$NODE_DIR/signing.key"
        
        # Deterministic seed for reproducibility (99999 + NODE_ID)
        SEED_HEX=$(printf '%064x' $((99999 + NODE_ID)))
        echo "$SEED_HEX" | xxd -r -p > "$KEY_FILE"
        
        # Keygen outputs: PUBKEY_HEX PEER_ID
        OUTPUT=$("$KEYGEN_BIN" "$SEED_HEX")
        PUBKEY=$(echo "$OUTPUT" | cut -d' ' -f1)
        PEER_ID=$(echo "$OUTPUT" | cut -d' ' -f2)
        
        PUBLIC_KEYS[$NODE_ID]=$PUBKEY
        PEER_IDS[$NODE_ID]=$PEER_ID
        
        NODE_HOST_IPS[$NODE_ID]=$IP
        
        # Calculate ports: offset by local index
        NODE_P2P_PORTS[$NODE_ID]=$((BASE_PORT + v))
        
        echo "  Host $i ($IP) Node $v (Global ID $NODE_ID): ${PUBKEY:0:16}... PeerID: $PEER_ID"
    done
done

# 2. Build Genesis Balances for Spammer (using spammer tool)
ACCOUNTS_PER_SHARD=16000
INITIAL_BALANCE=1000000

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

# 3. Build Genesis Validator Set
GENESIS_VALIDATORS=""
for id in $(seq 0 $((TOTAL_NODES - 1))); do
    if [ -n "$GENESIS_VALIDATORS" ]; then
        GENESIS_VALIDATORS="$GENESIS_VALIDATORS
"
    fi
    GENESIS_VALIDATORS="$GENESIS_VALIDATORS[[genesis.validators]]
id = $id
shard = $((id / NODES_PER_SHARD))
public_key = \"${PUBLIC_KEYS[$id]}\"
voting_power = 1"
done

# 4. Build Bootstrap Peer List
# 4. Build Bootstrap Peer List
BOOTSTRAP_PEERS=""
# Only use the first node as bootstrap peer to avoid a full mesh connection storm
# and ensure O(N) connections instead of O(N^2)
MAX_BOOTSTRAP_PEERS=1

for id in $(seq 0 $((TOTAL_NODES - 1))); do
    if [ "$id" -ge "$MAX_BOOTSTRAP_PEERS" ]; then
        break
    fi

    IP="${NODE_HOST_IPS[$id]}"
    PID="${PEER_IDS[$id]}"
    PORT="${NODE_P2P_PORTS[$id]}"
    
    if [ -n "$BOOTSTRAP_PEERS" ]; then BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"; fi
    
    # TCP fallback is disabled in this config, so only provide QUIC address
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/$IP/udp/$PORT/quic-v1/p2p/$PID\""
done

# 5. Generate Config Files
echo "Generating config files..."
# Generate Prometheus targets string
PROM_TARGETS=""

for i in "${!HOST_IPS[@]}"; do
    IP="${HOST_IPS[$i]}"
    HOST_DIR="$OUT_DIR/host-$i"
    
    for v in $(seq 0 $((NODES_PER_HOST - 1))); do
        NODE_ID=$((i * NODES_PER_HOST + v))
        NODE_DIR="$HOST_DIR/node-$v"
        CONFIG_FILE="$NODE_DIR/config.toml"
        
        P2P_PORT=$((BASE_PORT + v))
        TCP_PORT=$((TCP_BASE_PORT + v))
        RPC_PORT=$((RPC_BASE_PORT + v))
        
        # Add to prometheus targets
        if [ -n "$PROM_TARGETS" ]; then PROM_TARGETS="$PROM_TARGETS, "; fi
        PROM_TARGETS="$PROM_TARGETS'$IP:$RPC_PORT'"
        
        cat > "$CONFIG_FILE" << EOF
# Distributed Node Configuration
# Host ID: $i
# Local Node Index: $v
# Global Validator (Node) ID: $NODE_ID
# Public IP: $IP

[node]
validator_id = $NODE_ID
shard = $((NODE_ID / NODES_PER_SHARD))
num_shards = $NUM_SHARDS
key_path = "./distributed-cluster-data/host-$i/node-$v/signing.key"
data_dir = "./distributed-cluster-data/host-$i/node-$v/data"

[network]
# bind to all interfaces
listen_addr = "/ip4/0.0.0.0/udp/$P2P_PORT/quic-v1"
tcp_fallback_enabled = false
tcp_fallback_port = $TCP_PORT
version_interop_mode = "relaxed"
bootstrap_peers = [$BOOTSTRAP_PEERS]
upnp_enabled = false
request_timeout_ms = 30000
max_message_size = 10485760
gossipsub_heartbeat_ms = 100
direct_connection_limit = 50
direct_connection_timeout_ms = 10000
# Aggressive keep-alive for distributed deployments (WAN tolerant)
idle_connection_timeout_ms = 120000
keep_alive_interval_ms = 10000

[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000
max_transactions_per_block = 1024
max_certificates_per_block = 4096
rpc_mempool_limit = 16384

[threads]
crypto_threads = $CRYPTO_THREADS
execution_threads = $EXECUTION_THREADS
io_threads = $IO_THREADS
pin_cores = false

[metrics]
enabled = true
listen_addr = "0.0.0.0:$RPC_PORT"

[telemetry]
enabled = false

$GENESIS_VALIDATORS

${SHARD_GENESIS_BALANCES[0]}
EOF
        echo "  Generated config for Host $i ($IP) Node $v (Port $RPC_PORT)"
    done
done

# 6. Generate Prometheus Configuration
PROMETHEUS_CONFIG="$OUT_DIR/prometheus.yml"
echo "Generating monitoring config at $PROMETHEUS_CONFIG..."

cat > "$PROMETHEUS_CONFIG" << EOF
global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'hyperscale'
    scrape_interval: 5s
    static_configs:
      - targets: [$PROM_TARGETS]
        labels:
          cluster: 'distributed'
          shard: '$((NODE_ID / NODES_PER_SHARD))'
EOF

echo "=== Generation Complete ==="
echo "Artifacts are in '$OUT_DIR'."
echo ""
echo "Deployment Instructions:"
for i in "${!HOST_IPS[@]}"; do
    IP="${HOST_IPS[$i]}"
    echo "  Host $IP (ID $i):"
    echo "    1. Copy config dir:"
    echo "       scp -r $OUT_DIR/host-$i $IP:~/git/hyperscale-rs/distributed-cluster-data/"
    echo "    2. Copy binary:"
    echo "       scp target/release/hyperscale-validator $IP:~/git/hyperscale-rs/"
    echo "    3. Run nodes:"

    for v in $(seq 0 $((NODES_PER_HOST - 1))); do
        echo "       ./hyperscale-validator --config distributed-cluster-data/host-$i/node-$v/config.toml --clean &"
    done
done

# 7. Copy to Remote if requested
if [ "$COPY_TO_REMOTE" = true ]; then
    echo ""
    echo "=== Copying to Remote Hosts ==="
    
    # Detect local IPs to skip
    LOCAL_IPS=("127.0.0.1" "localhost" "::1")
    if command -v ifconfig >/dev/null 2>&1; then
        # BSD/macOS style
        current_ips=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}')
        for ip in $current_ips; do LOCAL_IPS+=("$ip"); done
    elif command -v hostname >/dev/null 2>&1; then
        # Linux style
        current_ips=$(hostname -I 2>/dev/null || hostname -i 2>/dev/null)
        for ip in $current_ips; do LOCAL_IPS+=("$ip"); done
    fi

    echo "Local IPs detected: ${LOCAL_IPS[*]}"

    for i in "${!HOST_IPS[@]}"; do
        IP="${HOST_IPS[$i]}"
        
        # Check if IP is local
        IS_LOCAL=false
        for local_ip in "${LOCAL_IPS[@]}"; do
            if [ "$IP" == "$local_ip" ]; then
                IS_LOCAL=true
                break
            fi
        done
        
        if [ "$IS_LOCAL" = true ]; then
            echo "  Skipping remote copy for local host $IP"
            continue
        fi
        
        echo "  Copying to $REMOTE_USER@$IP..."
        
        # Ensure parent directory exists
        ssh "$REMOTE_USER@$IP" "mkdir -p $REMOTE_PATH"
        
        # Copy config directory
        # Using rsync if available might be better, but scp is requested/standard
        scp -r "$OUT_DIR/host-$i" "$REMOTE_USER@$IP:$REMOTE_PATH/"
        
        # Copy binary (assuming it goes to parent of remote path or ~/git/hyperscale-rs based on printed instructions)
        # Printed: scp target/release/hyperscale-validator $IP:~/git/hyperscale-rs/
        # User default for REMOTE_PATH: ~/git/hyperscale-rs/distributed-cluster-data/
        # So binary likely goes to ~/git/hyperscale-rs/ (parent of default REMOTE_PATH's parent? no, just base dir)
        # Let's infer the binary path as the parent of the data directory if it ends in distributed-cluster-data, 
        # or just use a fixed path derived from REMOTE_PATH if possible.
        # Given the ambiguity, I will strictly follow the "one for the location on the remote host" for the DATA.
        # But for the binary, I will try to be smart or just copy to the directory *containing* the distributed-cluster-data if possible,
        # or just assume the user wants the binary in the same place?
        # Re-reading prompt: "copy the files to remote host". Files = config + binary.
        # Start instructions say: scp target/release/hyperscale-validator $IP:~/git/hyperscale-rs/
        # I will use $(dirname $REMOTE_PATH) if REMOTE_PATH ends in distributed-cluster-data, otherwise just $REMOTE_PATH.
        
        # Actually safer: just put binary in the same REMOTE_PATH to avoid permissions issues in parent folders?
        # No, the previous instructions were specific. 
        # "scp -r $OUT_DIR/host-$i $IP:~/git/hyperscale-rs/distributed-cluster-data/"
        # "scp target/release/hyperscale-validator $IP:~/git/hyperscale-rs/"
        # I will assume the binary target is the parent of REMOTE_PATH if it looks like the default structure, 
        # otherwise I'll put it IN REMOTE_PATH to be safe.
        
        REMOTE_BIN_DIR="$REMOTE_PATH"
        if [[ "$REMOTE_PATH" == *"distributed-cluster-data/" ]] || [[ "$REMOTE_PATH" == *"distributed-cluster-data" ]]; then
             # naive dirname
             REMOTE_BIN_DIR="${REMOTE_PATH%/distributed-cluster-data*}"
        fi
        
        echo "    - Configs to $REMOTE_PATH"
        echo "    - Binary to $REMOTE_BIN_DIR"

        scp -r "$OUT_DIR/host-$i" "$REMOTE_USER@$IP:$REMOTE_PATH/"
        scp "target/release/hyperscale-validator" "$REMOTE_USER@$IP:$REMOTE_BIN_DIR/"
    done
fi


# 7. Print Spammer Command
echo ""
echo "------------------------------------------------------------------"
echo "To run the spammer manually:"

# Construct endpoints string
ENDPOINTS=""
for i in "${!HOST_IPS[@]}"; do
    IP="${HOST_IPS[$i]}"
    for v in $(seq 0 $((NODES_PER_HOST - 1))); do
        RPC_PORT=$((RPC_BASE_PORT + v))
        if [ -n "$ENDPOINTS" ]; then ENDPOINTS="$ENDPOINTS,"; fi
        ENDPOINTS="${ENDPOINTS}http://$IP:$RPC_PORT"
    done
done

echo "./target/release/hyperscale-spammer run \\"
echo "    --endpoints \"$ENDPOINTS\" \\"
echo "    --num-shards \"$NUM_SHARDS\" \\"
echo "    --validators-per-shard \"$NODES_PER_SHARD\" \\"
echo "    --tps 150 \\"
echo "    --duration 60s --cross-shard-ratio 0 --measure-latency"
echo "------------------------------------------------------------------"
