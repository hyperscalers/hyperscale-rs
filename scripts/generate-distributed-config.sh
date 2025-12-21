#!/bin/bash
#
# Generate configuration for a distributed hyperscale cluster.
#
# Usage:
#   ./scripts/generate-distributed-config.sh --nodes "IP1,IP2,IP3..." [--out-dir DIR]
#
# Examples:
#   ./scripts/generate-distributed-config.sh --nodes "192.168.1.10,192.168.1.11"
#

set -e

# Default configuration
NODES=""
OUT_DIR="./distributed-cluster-data"
BASE_PORT=9000
TCP_BASE_PORT=30500
RPC_BASE_PORT=8080
NUM_SHARDS=1 # Simplification for now: 1 shard for N nodes
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes)
            NODES="$2"
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
        --help|-h)
            echo "Usage: $0 --nodes \"IP1,IP2...\" [--out-dir DIR] [--clean]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$NODES" ]; then
    echo "ERROR: --nodes argument is required (comma-separated IPs)"
    exit 1
fi

# Split nodes into array
IFS=',' read -r -a NODE_IPS <<< "$NODES"
TOTAL_VALIDATORS=${#NODE_IPS[@]}

echo "=== Generating Distributed Cluster Config ==="
echo "Nodes: ${NODE_IPS[*]}"
echo "Total Validators: $TOTAL_VALIDATORS"
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
declare -a KEY_FILES

for i in "${!NODE_IPS[@]}"; do
    NODE_DIR="$OUT_DIR/node-$i"
    mkdir -p "$NODE_DIR"
    KEY_FILE="$NODE_DIR/signing.key"
    
    # Deterministic seed for reproducibility
    SEED_HEX=$(printf '%064x' $((99999 + i)))
    echo "$SEED_HEX" | xxd -r -p > "$KEY_FILE"
    
    # Keygen now outputs: PUBKEY_HEX PEER_ID
    OUTPUT=$("$KEYGEN_BIN" "$SEED_HEX")
    PUBLIC_KEYS[$i]=$(echo "$OUTPUT" | cut -d' ' -f1)
    PEER_IDS[$i]=$(echo "$OUTPUT" | cut -d' ' -f2)
    
    echo "  Node $i (${NODE_IPS[$i]}): ${PUBLIC_KEYS[$i]:0:16}... PeerID: ${PEER_IDS[$i]}"
done

# 2. Build Genesis Balances for Spammer (using spammer tool)
# In distributed setup with 1 shard, we generate for shard 0.
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
for i in "${!NODE_IPS[@]}"; do
    if [ -n "$GENESIS_VALIDATORS" ]; then
        GENESIS_VALIDATORS="$GENESIS_VALIDATORS
"
    fi
    GENESIS_VALIDATORS="$GENESIS_VALIDATORS[[genesis.validators]]
id = $i
shard = 0
public_key = \"${PUBLIC_KEYS[$i]}\"
voting_power = 1"
done

# 4. Build Bootstrap Peer List (All nodes point to all other nodes ideally, or at least Node 0)
# Here we add ALL nodes as bootstrap peers for robustness, using their public IPs.
BOOTSTRAP_PEERS=""
for i in "${!NODE_IPS[@]}"; do
    IP="${NODE_IPS[$i]}"
    PID="${PEER_IDS[$i]}"
    # Each node listens on BASE_PORT (QUIC) and TCP_BASE_PORT (TCP)
    # Since these are distinct machines, they can all use the same port numbers locally!
    # But for the bootstrap list, we use their PUBLIC IPs.
    if [ -n "$BOOTSTRAP_PEERS" ]; then BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"; fi
    
    # IMPORTANT: Include Peer ID in the multiaddr to ensure connectivity
    # QUIC-only bootstrap peers as requested
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/$IP/udp/$BASE_PORT/quic-v1/p2p/$PID\""
done

# 5. Generate Config Files
echo "Generating config files..."
for i in "${!NODE_IPS[@]}"; do
    NODE_DIR="$OUT_DIR/node-$i"
    CONFIG_FILE="$NODE_DIR/config.toml"
    IP="${NODE_IPS[$i]}"
    
    # We use standard ports for the local bind since each is on a dedicated machine/VM
    
    cat > "$CONFIG_FILE" << EOF
# Distributed Node Configuration
# Node ID: $i
# Public IP: $IP

[node]
validator_id = $i
shard = 0
num_shards = 1
key_path = "./distributed-cluster-data/node-$i/signing.key"
data_dir = "./distributed-cluster-data/node-$i/data"

[network]
# bind to all interfaces
listen_addr = "/ip4/0.0.0.0/udp/$BASE_PORT/quic-v1"
tcp_fallback_enabled = false
tcp_fallback_port = $TCP_BASE_PORT
bootstrap_peers = [$BOOTSTRAP_PEERS]
upnp_enabled = false
request_timeout_ms = 500
max_message_size = 10485760
gossipsub_heartbeat_ms = 100

[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000

[metrics]
enabled = true
listen_addr = "0.0.0.0:$RPC_BASE_PORT"

[telemetry]
enabled = false

$GENESIS_VALIDATORS

${SHARD_GENESIS_BALANCES[0]}
EOF
    echo "  Generated config for Node $i"
done

# 5. Generate Prometheus Configuration
PROMETHEUS_CONFIG="$OUT_DIR/prometheus.yml"
echo "Generating monitoring config at $PROMETHEUS_CONFIG..."

# Build targets list
PROM_TARGETS=""
for i in "${!NODE_IPS[@]}"; do
    IP="${NODE_IPS[$i]}"
    if [ -n "$PROM_TARGETS" ]; then
        PROM_TARGETS="$PROM_TARGETS, "
    fi
    PROM_TARGETS="$PROM_TARGETS'$IP:8080'"
done

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
          shard: '0'
EOF
echo "=== Generation Complete ==="
echo "Artifacts are in '$OUT_DIR'."
echo ""
echo "Deployment Instructions:"
for i in "${!NODE_IPS[@]}"; do
    IP="${NODE_IPS[$i]}"
    echo "  Machine $IP:"
    echo "    1. Copy '$OUT_DIR/node-$i' to the machine."
    echo "    2. Copy 'target/release/hyperscale-validator' to the machine."
    echo "    3. Run: ./hyperscale-validator --config node-$i/config.toml"
done
