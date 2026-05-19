#!/bin/bash
#
# Print per-vnode status from every reachable local validator.
#
# Probes RPC ports 8080..8087 (the launch-cluster.sh default range), pulls
# /api/v1/status from each, and emits one row per hosted vnode — sorted by
# shard, then validator_id. Unreachable ports are skipped silently.
#
# Usage:
#   ./scripts/print-status.sh
#
# Requires: curl, jq, column.

set -euo pipefail

{
    printf 'port\tvid\tshard\theight\tview\tpending\tin_flight\ttotal\tstate_root\n'
    for p in $(seq 8080 8087); do
        curl -fsS "http://localhost:$p/api/v1/status" 2>/dev/null \
            | jq -r --arg p "$p" \
                '.vnodes[] | [$p, .validator_id, .shard, .block_height, .view,
                              .mempool.pending_count, .mempool.in_flight_count,
                              .mempool.total_count, .state_root_hash] | @tsv' \
            || true
    done | sort -k3,3n -k2,2n
} | column -t
