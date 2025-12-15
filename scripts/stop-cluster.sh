#!/bin/bash
#
# Stop the local hyperscale cluster.
#
# Usage:
#   ./scripts/stop-cluster.sh [--keep-monitoring]
#
# Options:
#   --keep-monitoring  Don't stop the Prometheus/Grafana monitoring stack

DATA_DIR="./cluster-data"
PID_FILE="$DATA_DIR/pids.txt"
STOP_MONITORING=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-monitoring)
            STOP_MONITORING=false
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [ ! -f "$PID_FILE" ]; then
    echo "No cluster running (PID file not found: $PID_FILE)"
    exit 0
fi

echo "Stopping cluster..."

while read -r pid; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "  Stopping PID $pid..."
        kill "$pid" 2>/dev/null || true
    fi
done < "$PID_FILE"

# Wait a moment for graceful shutdown
sleep 1

# Force kill any remaining
while read -r pid; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "  Force killing PID $pid..."
        kill -9 "$pid" 2>/dev/null || true
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "Cluster stopped."

# Stop monitoring stack if running
if [ "$STOP_MONITORING" = true ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    MONITORING_DIR="$SCRIPT_DIR/monitoring"

    if command -v docker &> /dev/null; then
        # Check if monitoring containers are running
        if docker ps --format '{{.Names}}' | grep -q "hyperscale-prometheus\|hyperscale-grafana"; then
            echo ""
            echo "Stopping monitoring stack and removing volumes..."
            (cd "$MONITORING_DIR" && docker-compose down -v 2>&1) | tail -2
            echo "Monitoring stopped."
        fi
    fi
fi
