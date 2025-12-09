#!/bin/bash
#
# Stop the local hyperscale cluster.
#
# Usage:
#   ./scripts/stop-cluster.sh

DATA_DIR="./cluster-data"
PID_FILE="$DATA_DIR/pids.txt"

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
