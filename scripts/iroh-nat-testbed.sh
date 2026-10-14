#!/bin/bash
#
# Run the iroh path probe over a matrix of NAT types in one privileged
# container. Needs a running Docker daemon on a Linux host or Docker Desktop
# (the container's kernel provides network namespaces, nftables and netem).
# Nothing leaves the container: the relay, every router and every host run
# inside it, and no public relay or DNS is contacted.
#
# Usage:
#   ./scripts/iroh-nat-testbed.sh [OUT_DIR] [testbed arguments...]
#
#   OUT_DIR defaults to target/iroh-nat-testbed. Testbed arguments:
#     --rtt-ms "20 150"   round trips between the two hosts, one run each
#     --secs 75           how long each dial holds its connection
#     --types "..."       subset of: public full-cone port-restricted
#                         symmetric double udp-blocked ipv6-only
#
# Results: OUT_DIR/matrix.jsonl, one line per pair of NAT types and round
# trip, with the dialer's report: `selected_after_a_minute` is "direct" or
# "relay" (G1), `time_to_direct_ms` how long the hole punch took.

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$WORKSPACE_ROOT/target/iroh-nat-testbed}"
shift || true
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

docker build --file "$WORKSPACE_ROOT/scripts/iroh-nat-testbed/Dockerfile" \
    --tag hyperscale-iroh-nat-testbed "$WORKSPACE_ROOT"

exec docker run --rm --privileged --network none \
    --volume "$OUT_DIR:/out" \
    hyperscale-iroh-nat-testbed --out /out "$@"
