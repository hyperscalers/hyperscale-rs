#!/bin/bash
#
# Seat a fresh committee of hosts across a mix of NAT types, and time how
# long its pairs take to reach direct paths. Runs as root inside a
# privileged Linux container (see ../iroh-seating.sh).
#
# Usage: seating.sh [--mix "public:56 ..."] [--secs 150] [--rounds 3] [--out DIR]
#
# Each host runs the backend (`seat`) in its own namespace behind the
# router its type needs, with the NAT types of testbed.sh. Its site's
# uplink delays what it sends by 5 to 50 ms, varied by host, so a pair's
# round trip is 10 to 100 ms. Every host comes online through the one
# relay and writes its signed address record; once all have, every host
# reads all records, so the book is warm, and is seated at once. Each round
# builds the namespaces afresh, so no NAT mapping outlives it.
#
# Results, per round: DIR/round-<n>/out/<index>.json from every host, the
# relay's log, DIR/round-<n>/load.txt with the container's load, and
# DIR/round-<n>/summary.json with the pair times (seating-summary.jq).

set -euo pipefail

MIX="public:56 ipv6-only:8 port-restricted:30 double:16 full-cone:8 symmetric:6 udp-blocked:4"
SECS=150
ROUNDS=3
OUT=/out
while [ $# -gt 0 ]; do
    case "$1" in
        --mix) MIX="$2"; shift 2 ;;
        --secs) SECS="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=netns.sh
. /usr/local/bin/netns.sh

SEAT=/usr/local/bin/seat
PORT=7000
RELAY4=198.19.255.2
RELAY6=2001:db8:1::2

# One type per host, in the order of the mix.
TYPES=()
for entry in $MIX; do
    for _ in $(seq 1 "${entry#*:}"); do
        TYPES+=("${entry%%:*}")
    done
done
HOSTS=${#TYPES[@]}

# Outside addresses on the internet segment, a /15, and in 2001:db8:1::/64.
outer4() { echo "198.18.$(($1 / 250)).$(($1 % 250 + 2))/15"; }
outer6() { printf '2001:db8:1::1:%x/64' "$1"; }
inner_net() { echo "10.$(($1 / 256)).$(($1 % 256))"; }

# The site of host $1, of type $2, with $3 ms on its uplink. Sets BIND to
# the socket the host binds, or empty for every interface: a host with
# outside addresses binds them all, in both families.
make_site() {
    local n=$1 type=$2 delay=$3 host="h$1" router="r$1" carrier="c$1" net
    net=$(inner_net "$n")
    new_ns "$host"
    case "$type" in
        public)
            attach "$host" "$(outer4 "$n")" "$(outer6 "$n")"
            delay_uplink "$host" "$delay"
            BIND=""
            ;;
        ipv6-only)
            attach "$host" - "$(outer6 "$n")"
            reply_only_firewall "$host"
            delay_uplink "$host" "$delay"
            BIND=""
            ;;
        full-cone | port-restricted | symmetric | udp-blocked)
            new_ns "$router"
            attach "$router" "$(outer4 "$n")" -
            private_side "$router" "$net"
            join_private "$router" "$host" "$net.2" eth0 "$net.1"
            case "$type" in
                full-cone)
                    nat_router "$router" "" "ct status dnat accept"
                    ns "$router" nft add rule ip nat prerouting \
                        iifname wan udp dport "$PORT" dnat to "$net.2:$PORT"
                    ;;
                port-restricted) nat_router "$router" "" ;;
                symmetric) nat_router "$router" random ;;
                udp-blocked) nat_router "$router" "" "meta l4proto udp drop" ;;
            esac
            delay_uplink "$router" "$delay"
            BIND="$net.2:$PORT"
            ;;
        double)
            new_ns "$carrier"
            new_ns "$router"
            attach "$carrier" "$(outer4 "$n")" -
            private_side "$carrier" "100.64.$((n % 256))"
            join_private "$carrier" "$router" "100.64.$((n % 256)).2" wan "100.64.$((n % 256)).1"
            private_side "$router" "$net"
            join_private "$router" "$host" "$net.2" eth0 "$net.1"
            nat_router "$carrier" ""
            nat_router "$router" ""
            delay_uplink "$carrier" "$delay"
            BIND="$net.2:$PORT"
            ;;
        *) echo "unknown type: $type" >&2; exit 2 ;;
    esac
}

run_round() {
    local round=$1 dir="$OUT/round-$1" shared="$WORK/seating-$1"
    mkdir -p "$dir" "$shared"
    teardown_namespaces

    make_inet
    new_ns relay
    attach relay "$RELAY4/15" "$RELAY6/64"
    ns relay "$RELAY" --config-path "$WORK/relay.toml" >"$dir/relay.log" 2>&1 &
    sleep 2

    local n
    for n in $(seq 0 $((HOSTS - 1))); do
        make_site "$n" "${TYPES[$n]}" $((5 + (n * 37) % 46))
        # shellcheck disable=SC2046 # no --bind at all when BIND is empty
        ns "h$n" "$SEAT" --index "$n" --hosts "$HOSTS" --relay "$RELAY_URL" \
            --relay-ca "$WORK/relay.crt" $([ -n "$BIND" ] && echo --bind "$BIND") \
            --dir "$shared" --secs "$SECS" \
            --label "${TYPES[$n]}" >"$dir/seat-$n.log" 2>&1 &
    done
    echo "hosts started $(date +%s) load $(cat /proc/loadavg)" | tee "$dir/load.txt"

    local waited=0
    while [ "$(find "$shared/records" -name '*.hbor' 2>/dev/null | wc -l)" -lt "$HOSTS" ]; do
        if [ $waited -ge 180 ]; then
            echo "only $(find "$shared/records" -name '*.hbor' | wc -l) of $HOSTS hosts came online" \
                | tee -a "$dir/load.txt"
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    echo "seated $(date +%s) load $(cat /proc/loadavg)" | tee -a "$dir/load.txt"
    touch "$shared/go"

    local elapsed=0
    while [ $elapsed -lt $((SECS + 60)) ] && pgrep -f "$SEAT" >/dev/null; do
        sleep 10
        elapsed=$((elapsed + 10))
        echo "+${elapsed}s load $(cat /proc/loadavg)" >>"$dir/load.txt"
    done
    cp -r "$shared/out" "$dir/out" 2>/dev/null || true
    jq -s -f /usr/local/bin/seating-summary.jq "$dir"/out/*.json >"$dir/summary.json" || true
    echo "round $round: $(find "$dir/out" -name '*.json' 2>/dev/null | wc -l) of $HOSTS reports"
    jq -c '{direct, never_direct, direct_ms}' "$dir/summary.json" 2>/dev/null || true
}

prepare_relay "$RELAY4" "$RELAY6"
trap teardown_namespaces EXIT
for round in $(seq 1 "$ROUNDS"); do
    run_round "$round"
done
