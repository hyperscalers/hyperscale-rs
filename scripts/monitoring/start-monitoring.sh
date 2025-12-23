#!/bin/bash
#
# Start the Hyperscale monitoring stack (Prometheus + Grafana)
#
# Usage:
#   ./scripts/monitoring/start-monitoring.sh [--validators N]
#
# This script can be run independently of launch-cluster.sh if you want
# to start monitoring for an already-running cluster.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default configuration
NUM_SHARDS=2
VALIDATORS_PER_SHARD=4
BASE_RPC_PORT=8080

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --shards)
            NUM_SHARDS="$2"
            shift 2
            ;;
        --validators-per-shard|--validators)
            # Support both for compatibility, though --validators usually meant total before
            VALIDATORS_PER_SHARD="$2"
            shift 2
            ;;
        --base-port)
            BASE_RPC_PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--shards N] [--validators-per-shard M] [--base-port PORT]"
            echo ""
            echo "Options:"
            echo "  --shards N               Number of shards (default: 2)"
            echo "  --validators-per-shard M Validators per shard (default: 4)"
            echo "  --base-port PORT         Base RPC port (default: 8080)"
            echo ""
            echo "Access:"
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

echo "=== Starting Monitoring Stack ==="
echo "Shards: $NUM_SHARDS"
echo "Validators per shard: $VALIDATORS_PER_SHARD"
echo "Total Validators: $TOTAL_VALIDATORS"
echo "Base RPC port: $BASE_RPC_PORT"
echo ""

# Generate prometheus.yml
echo "Generating Prometheus configuration..."

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

cat > "$SCRIPT_DIR/prometheus.yml" << EOF
# Prometheus configuration for Hyperscale local cluster
# Auto-generated for $NUM_SHARDS shards x $VALIDATORS_PER_SHARD validators
# Job name 'hyperscale' matches Grafana dashboard expectations

global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'hyperscale'
    static_configs:$PROM_STATIC_CONFIGS
    metrics_path: '/metrics'
    scrape_timeout: 5s
EOF

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not found. Please install Docker first."
    exit 1
fi

# Start containers
echo "Starting Prometheus and Grafana..."

# MacOS and Linux need different settings
COMPOSE_FLAGS=""
if [[ "$(uname -s)" == "Linux" ]]; then
    echo "Detected Linux: Adding extra_hosts configuration..."
    COMPOSE_FLAGS="-f docker-compose.yml -f docker-compose.linux.yml"
fi

docker-compose $COMPOSE_FLAGS up -d

echo ""
echo "=== Monitoring Stack Started ==="
echo ""
echo "Access:"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana:    http://localhost:3000 (admin/admin)"
echo ""
echo "The Hyperscale dashboard is pre-loaded in Grafana."
echo ""
echo "Stop with: $0/../stop-monitoring.sh"
echo "Or:        cd $SCRIPT_DIR && docker-compose down"
