#!/bin/bash
#
# Seat a fresh committee of hosts across a mix of NAT types in one
# privileged container, and time how long its pairs take to reach direct
# paths (G7 of the iroh spike). Needs a running Docker daemon on a Linux
# host or Docker Desktop with room for one process per host. Nothing leaves
# the container: the relay, every router and every host run inside it, port
# mapping is off, and no public relay or DNS is contacted.
#
# Usage:
#   ./scripts/iroh-seating.sh [OUT_DIR] [seating arguments...]
#
#   OUT_DIR defaults to target/iroh-seating. Seating arguments:
#     --mix "public:56 ipv6-only:8 port-restricted:30 double:16
#            full-cone:8 symmetric:6 udp-blocked:4"
#                         hosts of each type, in order
#     --secs 150          how long each seated host is watched
#     --rounds 3          seatings, each on fresh namespaces
#
# Results: OUT_DIR/round-<n>/summary.json, with the share of pairs that
# reached a direct path and how long they took (p50, p95, max), by pair of
# NAT types too.

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$WORKSPACE_ROOT/target/iroh-seating}"
shift || true
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

docker build --file "$WORKSPACE_ROOT/scripts/iroh-nat-testbed/Dockerfile" \
    --tag hyperscale-iroh-nat-testbed "$WORKSPACE_ROOT"

exec docker run --rm --privileged --network none --name hyperscale-iroh-seating \
    --volume "$OUT_DIR:/out" --entrypoint /usr/local/bin/seating.sh \
    hyperscale-iroh-nat-testbed --out /out "$@"
