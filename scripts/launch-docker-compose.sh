#!/bin/bash
set -e

# --- 1. Defaults & Arguments ---
NUM_SHARDS=1
VALIDATORS_PER_SHARD=8
BASE_P2P_PORT=9000
BASE_RPC_PORT=18080
CLEAN=true
BUILD=true
USE_GHCR=false
ACCOUNTS_PER_SHARD=16000
INITIAL_BALANCE=1000000
LOG_LEVEL="info"
MEMORY_LIMIT=""
CPU_LIMIT=""
LATENCY=0
LATENCY_NODES=1

# Subnet for the cluster
SUBNET="172.99.0.0/16"
GATEWAY="172.99.0.1"

SCRIPT_PATH=$(realpath "$0")
SCRIPTS_DIR=$(dirname "$SCRIPT_PATH")
ROOT_DIR=$(dirname "$SCRIPTS_DIR")
DATA_DIR="$ROOT_DIR/cluster-data"
MONITORING_CONFIG_DIR="$SCRIPTS_DIR/monitoring"
COMPOSE_FILE="$SCRIPTS_DIR/docker-compose.generated.yml"
IMAGE_NAME="hyperscale-node:latest"

while [[ $# -gt 0 ]]; do
    case $1 in
        --shards) NUM_SHARDS="$2"; shift 2 ;;
        --validators-per-shard) VALIDATORS_PER_SHARD="$2"; shift 2 ;;
        --clean) CLEAN=true; shift ;;
        --build) BUILD="$2"; shift 2 ;;
        --use-ghcr-image) USE_GHCR=true; shift ;;
        --memory) MEMORY_LIMIT="$2"; shift 2 ;;
        --cpus) CPU_LIMIT="$2"; shift 2 ;;
        --latency) LATENCY="$2"; shift 2 ;;
        --latency) LATENCY="$2"; shift 2 ;;
        --latency-nodes) LATENCY_NODES="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --shards N               Number of shards (default: 1)"
            echo "  --validators-per-shard M Validators per shard (default: 8)"
            echo "  --accounts-per-shard N   Spammer accounts per shard (default: 16000)"
            echo "  --initial-balance N      Initial XRD balance per account (default: 1000000)"
            echo "  --clean                  Remove existing data directories"
            echo "  --build true|false       Build docker image (default: true)"
            echo "  --use-ghcr-image         Use pre-built image from GHCR"
            echo ""
            echo "Resource Limits & Network Simulation:"
            echo "  --memory LIMIT           Memory limit per validator (e.g. 512m, 1g)"
            echo "  --cpus LIMIT             CPU limit per validator (e.g. 0.5, 1.0)"
            echo "  --latency MS             Artificial network latency in ms (e.g. 100)"
            echo "  --latency-nodes N        Number of nodes to apply latency to, starting from 0 (default: 1)"
            echo ""
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TOTAL_VALIDATORS=$((NUM_SHARDS * VALIDATORS_PER_SHARD))
SPAM_BIN="$ROOT_DIR/target/release/hyperscale-spammer"
KEY_BIN="$ROOT_DIR/target/release/hyperscale-keygen"

# --- 2. Build & Cleanup ---
if [ "$CLEAN" = true ]; then
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    rm -rf "$DATA_DIR"
fi
mkdir -p "$DATA_DIR"

if [ "$USE_GHCR" = true ]; then
    IMAGE_NAME="ghcr.io/flightofthefox/hyperscale-rs:latest"
    BUILD=false
    echo "Using GHCR image: $IMAGE_NAME"
    docker pull "$IMAGE_NAME"
fi

if [ "$BUILD" = true ]; then
    cd "$ROOT_DIR" && docker build -t "$IMAGE_NAME" .
fi

# --- 3. Key & Genesis ---
declare -a PUBLIC_KEYS
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    NODE_DIR="$DATA_DIR/validator-$i"
    mkdir -p "$NODE_DIR"
    SEED_HEX=$(printf '%064x' $((12345 + i)))
    echo "$SEED_HEX" | xxd -r -p > "$NODE_DIR/signing.key"
    PUBLIC_KEYS[$i]=$("$KEY_BIN" "$SEED_HEX")
done

BOOTSTRAP_PEERS=""
for shard in $(seq 0 $((NUM_SHARDS - 1))); do
    first_v=$((shard * VALIDATORS_PER_SHARD))
    IP="172.99.0.$((10 + first_v))"
    if [ -n "$BOOTSTRAP_PEERS" ]; then BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS,"; fi
    BOOTSTRAP_PEERS="$BOOTSTRAP_PEERS\"/ip4/$IP/udp/9000/quic-v1\",\"/ip4/$IP/tcp/9000\""
done

GENESIS_VALIDATORS="[genesis]"
for j in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    v_shard=$((j / VALIDATORS_PER_SHARD))
    GENESIS_VALIDATORS="$GENESIS_VALIDATORS
[[genesis.validators]]
id = $j
shard = $v_shard
public_key = \"${PUBLIC_KEYS[$j]}\"
voting_power = 1"
done

# --- 4. Write Compose & Configs ---
cat > "$COMPOSE_FILE" <<EOF
networks:
  hyperscale-net:
    driver: bridge
    ipam:
      config:
        - subnet: $SUBNET
          gateway: $GATEWAY

services:
EOF

for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    shard=$((i / VALIDATORS_PER_SHARD))
    NODE_DIR="$DATA_DIR/validator-$i"
    IP="172.99.0.$((10 + i))"
    SHARD_BALANCES=$("$SPAM_BIN" genesis --num-shards "$NUM_SHARDS" --accounts-per-shard "$ACCOUNTS_PER_SHARD" --balance "$INITIAL_BALANCE" --shard "$shard")

    cat > "$NODE_DIR/config.toml" <<EOF
[node]
validator_id = $i
shard = $shard
num_shards = $NUM_SHARDS
key_path = "/home/hyperscalers/signing.key"
data_dir = "/home/hyperscalers/data"
[network]
listen_addr = "/ip4/0.0.0.0/udp/9000/quic-v1"
external_addr = "/ip4/$IP/udp/9000/quic-v1"
upnp_enabled = false
bootstrap_peers = [$BOOTSTRAP_PEERS]
tcp_fallback_port_range = "9000-9000"
[consensus]
proposal_interval_ms = 300
view_change_timeout_ms = 3000
[metrics]
enabled = true
listen_addr = "0.0.0.0:8080"
$GENESIS_VALIDATORS
$SHARD_BALANCES
EOF

    # Prepare optional configuration
    RESOURCE_OPTS=""
    if [ -n "$MEMORY_LIMIT" ] || [ -n "$CPU_LIMIT" ]; then
        RESOURCE_OPTS="    deploy:
      resources:
        limits:"
        if [ -n "$MEMORY_LIMIT" ]; then RESOURCE_OPTS="$RESOURCE_OPTS
          memory: $MEMORY_LIMIT"; fi
        if [ -n "$CPU_LIMIT" ]; then RESOURCE_OPTS="$RESOURCE_OPTS
          cpus: '$CPU_LIMIT'"; fi
    fi

    CAP_OPTS=""
    USER_OPTS=""
    if [ "$LATENCY" -gt 0 ] && [ "$i" -lt "$LATENCY_NODES" ]; then
        CAP_OPTS="    cap_add:
      - NET_ADMIN"
        USER_OPTS="    user: root"
        ENTRY_OPTS="    entrypoint: [\"/bin/bash\", \"-c\", \"tc qdisc add dev eth0 root netem delay ${LATENCY}ms && exec runuser -u hyperscalers -- /usr/local/bin/hyperscale-validator --config /home/hyperscalers/config.toml\"]"
    else
        ENTRY_OPTS="    entrypoint: [\"/usr/local/bin/hyperscale-validator\"]
    command: [\"--config\", \"/home/hyperscalers/config.toml\"]"
    fi

    cat >> "$COMPOSE_FILE" <<EOF
  validator-$i:
    image: $IMAGE_NAME
    container_name: validator-$i
    restart: unless-stopped
    networks:
      hyperscale-net:
        ipv4_address: $IP
    ports:
      - "$((BASE_RPC_PORT + i)):8080"
      - "$((BASE_P2P_PORT + i)):9000/udp"
      - "$((BASE_P2P_PORT + i)):9000"
    volumes:
      - $NODE_DIR:/home/hyperscalers
$RESOURCE_OPTS
$CAP_OPTS
$USER_OPTS
$ENTRY_OPTS
    environment:
      - RUST_LOG=warn,hyperscale=$LOG_LEVEL,libp2p_gossipsub=error
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/metrics"]
      interval: 5s
      timeout: 5s
      retries: 10
EOF
    if [ "$i" -ne 0 ]; then
        cat >> "$COMPOSE_FILE" <<EOF
    depends_on:
      validator-0:
        condition: service_healthy
EOF
    fi
done

# --- 5. Monitoring Stack ---
cat >> "$COMPOSE_FILE" <<EOF
  prometheus:
    image: prom/prometheus:latest
    container_name: hyperscale-prometheus
    networks:
      hyperscale-net:
        ipv4_address: 172.99.0.5
    ports:
      - "9090:9090"
    volumes:
      - $MONITORING_CONFIG_DIR/prometheus.yml:/etc/prometheus/prometheus.yml
  grafana:
    image: grafana/grafana:latest
    container_name: hyperscale-grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_AUTH_DISABLE_LOGIN_FORM=true
    networks:
      hyperscale-net:
        ipv4_address: 172.99.0.6
    ports:
      - "3000:3000"
    volumes:
      - $MONITORING_CONFIG_DIR/grafana/provisioning:/etc/grafana/provisioning
      - $MONITORING_CONFIG_DIR/grafana/dashboards:/var/lib/grafana/dashboards
EOF

# Prometheus Targets
cat > "$MONITORING_CONFIG_DIR/prometheus.yml" <<EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: 'hyperscale'
    static_configs:
EOF
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    IP="172.99.0.$((10 + i))"
    v_shard=$((i / VALIDATORS_PER_SHARD))
    cat >> "$MONITORING_CONFIG_DIR/prometheus.yml" <<EOF
      - targets: ['$IP:8080']
        labels:
          shard: '$v_shard'
          node: 'validator-$i'
          cluster: 'local'
EOF
done

# --- 6. Final Launch & Verification ---
echo "=== 4. Launching Cluster ==="
chmod -R 777 "$DATA_DIR"
docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting for all nodes to be healthy..."
while true; do
    STATUS=$(docker compose -f "$COMPOSE_FILE" ps --format json)
    UNHEALTHY=$(echo "$STATUS" | grep -v "healthy" | grep -v "running" || true)
    if [ -z "$UNHEALTHY" ]; then break; fi
    sleep 3
done

ENDPOINTS=""
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    [ -n "$ENDPOINTS" ] && ENDPOINTS="$ENDPOINTS,"
    ENDPOINTS="${ENDPOINTS}http://127.0.0.1:$((BASE_RPC_PORT + i))"
done

echo "=== 5. Running Consensus Smoke Test ==="
if $SPAM_BIN smoke-test \
    --endpoints "$ENDPOINTS" \
    --num-shards "$NUM_SHARDS" \
    --validators-per-shard "$VALIDATORS_PER_SHARD" \
    --wait-ready \
    --timeout 60s; then
    
    echo "------------------------------------------------------------------"
    echo "Success! Cluster is reaching consensus and producing blocks."
    echo "Grafana: http://localhost:3000"
    echo ""
    echo "To run the spammer manually:"
    echo "./target/release/hyperscale-spammer run \\"
    echo "    --endpoints \"$ENDPOINTS\" \\"
    echo "    --num-shards \"$NUM_SHARDS\" \\"
    echo "    --validators-per-shard \"$VALIDATORS_PER_SHARD\" \\"
    echo "    --tps 150 \\"
    echo "    --duration 60s --cross-shard-ratio 0 --measure-latency"
    echo "------------------------------------------------------------------"
else
    echo "------------------------------------------------------------------"
    echo "ERROR: Smoke test failed. Cluster left running for inspection."
    echo "Check logs: docker compose -f $COMPOSE_FILE logs -f"
    echo "------------------------------------------------------------------"
    exit 1
fi