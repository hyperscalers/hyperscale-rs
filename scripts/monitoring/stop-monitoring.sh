#!/bin/bash
#
# Stop the Hyperscale monitoring stack (Prometheus + Grafana)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Stopping monitoring stack..."

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not found."
    exit 1
fi

docker-compose down

echo "Monitoring stack stopped."
