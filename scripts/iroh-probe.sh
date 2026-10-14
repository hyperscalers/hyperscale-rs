#!/bin/bash
#
# Path probe for the iroh transport: whether two hosts reach a direct path,
# how long it takes, and how the path behaves over time.
#
# Usage:
#   ./scripts/iroh-probe.sh loopback [--hold-secs N] [--path-idle-ms N] [--path-keep-alive-ms N]
#       Every measurement one machine can make, in one process. Exits
#       non-zero when a fall back to the relay is not visible through the
#       path events or a direct connection dies with its relay.
#
#   ./scripts/iroh-probe.sh blip --cut-ms N [--cut-ms N2] [--repeats N] [--repunch-ms N]
#                                [--path-idle-ms N] [--path-keep-alive-ms N]
#       Cut one loopback connection's direct path for each given time and
#       report how long traffic stalled and how long it stayed relayed.
#
#   ./scripts/iroh-probe.sh listen --relay URL [--relay URL2] --seed N
#   ./scripts/iroh-probe.sh dial   --relay URL [--relay URL2] --seed M --peer ID [--secs N]
#       Two machines on different networks. Both name the same relay, an
#       `iroh-relay` with a DNS name and a certificate that each can reach;
#       `listen` prints the id `dial` takes. Give the two a different seed.
#       Run `dial` for at least 600 seconds; for the relay outage rows, stop
#       the relay partway and leave both sides running.
#
# Each run prints one JSON line per path event and ends with a JSON report.
# Record with it the access type of each host: fixed line or mobile, the
# provider, and whether the router forwards a port.

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKSPACE_ROOT"

exec cargo run --release --package hyperscale-network-iroh --features test-utils \
    --example probe -- "$@"
