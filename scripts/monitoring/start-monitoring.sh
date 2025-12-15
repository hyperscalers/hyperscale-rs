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

# Default: 8 validators (2 shards x 4 validators)
TOTAL_VALIDATORS=8
BASE_RPC_PORT=8080

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --validators)
            TOTAL_VALIDATORS="$2"
            shift 2
            ;;
        --base-port)
            BASE_RPC_PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--validators N] [--base-port PORT]"
            echo ""
            echo "Options:"
            echo "  --validators N   Total number of validators (default: 8)"
            echo "  --base-port PORT Base RPC port (default: 8080)"
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

echo "=== Starting Monitoring Stack ==="
echo "Validators: $TOTAL_VALIDATORS"
echo "Base RPC port: $BASE_RPC_PORT"
echo ""

# Generate prometheus.yml
echo "Generating Prometheus configuration..."
PROM_TARGETS=""
for i in $(seq 0 $((TOTAL_VALIDATORS - 1))); do
    rpc_port=$((BASE_RPC_PORT + i))
    if [ -n "$PROM_TARGETS" ]; then
        PROM_TARGETS="$PROM_TARGETS
          - 'host.docker.internal:$rpc_port'"
    else
        PROM_TARGETS="- 'host.docker.internal:$rpc_port'"
    fi
done

cat > "$SCRIPT_DIR/prometheus.yml" << EOF
# Prometheus configuration for Hyperscale local cluster
# Auto-generated for $TOTAL_VALIDATORS validators

global:
  scrape_interval: 5s
  evaluation_interval: 5s

scrape_configs:
  - job_name: 'hyperscale'
    static_configs:
      - targets:
          $PROM_TARGETS
        labels:
          cluster: 'local'
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
docker-compose up -d

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
