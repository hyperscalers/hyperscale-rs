#!/bin/bash
#
# NAT matrix for the iroh path probe. Runs as root inside a privileged Linux
# container (see ../iroh-nat-testbed.sh); every host, router and the relay
# gets its own network namespace (netns.sh), and the routers translate with
# nftables.
#
# Usage: testbed.sh [--rtt-ms "20 150"] [--secs 75] [--types "..."]
#                   [--involving TYPE] [--out DIR]
#
# Each run joins two hosts of the given types through their routers to one
# shared segment, the "internet", where the relay and public hosts sit. Host
# one listens and host two dials. Both name the relay by a hostname that the
# container's hosts file maps to its IPv4 and its IPv6 address, so a host of
# either family reaches it (iroh 1.3.0 refuses a relay named by an IPv6
# literal), and trust its self-signed certificate, so the relay also serves
# QUIC address discovery. netem on each site's uplink makes the round
# trip between the two hosts the given value. Every ordered pair of types is
# run, or with --involving only the pairs one of whose hosts is of that
# type, plus two hosts behind one router (`lan`). One JSON line per run is
# appended to DIR/matrix.jsonl; each run's full output stays in
# DIR/rtt-<ms>/<listener>--<dialer>/.
#
# Types:
#   public      no NAT, both address families
#   full-cone   endpoint independent mapping and filtering
#   port-restricted
#               endpoint independent mapping, address and port dependent
#               filtering: a stock home router
#   symmetric   endpoint dependent mapping (a random port per destination),
#               address and port dependent filtering
#   double      a port restricted home router behind a port restricted
#               carrier grade NAT in 100.64.0.0/10
#   udp-blocked a port restricted router that forwards no UDP at all
#   ipv6-only   no IPv4; global IPv6 behind a stateful firewall that admits
#               only replies, as home routers do

set -euo pipefail

RTTS="20 150"
SECS=75
TYPES="public full-cone port-restricted symmetric double udp-blocked ipv6-only"
INVOLVING=""
OUT=/out
while [ $# -gt 0 ]; do
    case "$1" in
        --rtt-ms) RTTS="$2"; shift 2 ;;
        --secs) SECS="$2"; shift 2 ;;
        --types) TYPES="$2"; shift 2 ;;
        --involving) INVOLVING="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=netns.sh
. /usr/local/bin/netns.sh

PROBE=/usr/local/bin/probe
PORT=7000

RELAY4=198.51.100.2
RELAY6=2001:db8:1::2
RELAY_URLS="--relay $RELAY_URL"

mkdir -p "$OUT"
prepare_relay "$RELAY4" "$RELAY6"

# Bring up host $2 of type $1 in namespace h$2, behind whatever routers the
# type needs, with $3 milliseconds on the site's uplink. Sets BIND_<n> to
# the probe's bind flags.
make_site() {
    local type=$1 n=$2 delay=$3 host="h$2"
    new_ns "$host"
    case "$type" in
        public)
            attach "$host" "198.51.100.1$n/24" "2001:db8:1::1$n/64"
            delay_uplink "$host" "$delay"
            printf -v "BIND_$n" '%s' \
                "--bind 198.51.100.1$n:$PORT --bind [2001:db8:1::1$n]:$PORT"
            ;;
        ipv6-only)
            attach "$host" - "2001:db8:1::1$n/64"
            reply_only_firewall "$host"
            delay_uplink "$host" "$delay"
            printf -v "BIND_$n" '%s' "--bind [2001:db8:1::1$n]:$PORT"
            ;;
        full-cone | port-restricted | symmetric | udp-blocked)
            new_ns "r$n"
            attach "r$n" "198.51.100.2$n/24" -
            private_side "r$n" "10.$n.0"
            join_private "r$n" "$host" "10.$n.0.2" eth0 "10.$n.0.1"
            case "$type" in
                full-cone)
                    nat_router "r$n" "" "ct status dnat accept"
                    ns "r$n" nft add rule ip nat prerouting \
                        iifname wan udp dport "$PORT" dnat to "10.$n.0.2:$PORT"
                    ;;
                port-restricted) nat_router "r$n" "" ;;
                symmetric) nat_router "r$n" random ;;
                udp-blocked) nat_router "r$n" "" "meta l4proto udp drop" ;;
            esac
            delay_uplink "r$n" "$delay"
            printf -v "BIND_$n" '%s' "--bind 10.$n.0.2:$PORT"
            ;;
        double)
            new_ns "c$n"
            new_ns "r$n"
            attach "c$n" "198.51.100.3$n/24" -
            private_side "c$n" "100.64.$n"
            join_private "c$n" "r$n" "100.64.$n.2" wan "100.64.$n.1"
            private_side "r$n" "10.$n.0"
            join_private "r$n" "$host" "10.$n.0.2" eth0 "10.$n.0.1"
            nat_router "c$n" ""
            nat_router "r$n" ""
            delay_uplink "c$n" "$delay"
            printf -v "BIND_$n" '%s' "--bind 10.$n.0.2:$PORT"
            ;;
        *) echo "unknown type: $type" >&2; exit 2 ;;
    esac
}

# Two hosts behind one port restricted router, $1 milliseconds on its
# uplink.
make_lan() {
    new_ns r1
    attach r1 198.51.100.21/24 -
    private_side r1 10.1.0
    nat_router r1 ""
    delay_uplink r1 "$1"
    for n in 1 2; do
        new_ns "h$n"
        join_private r1 "h$n" "10.1.0.$((n + 1))" eth0 10.1.0.1
        printf -v "BIND_$n" '%s' "--bind 10.1.0.$((n + 1)):$PORT"
    done
}

run_pair() {
    local first=$1 second=$2 rtt=$3 dir
    dir="$OUT/rtt-$rtt/$first--$second"
    mkdir -p "$dir"
    teardown_namespaces

    make_inet
    new_ns relay
    attach relay "$RELAY4/24" "$RELAY6/64"
    ns relay "$RELAY" --config-path "$WORK/relay.toml" >"$dir/relay.log" 2>&1 &
    sleep 2

    # netem delays what a site sends, so a half on each site makes the
    # round trip between the two hosts; each host is half of it from the
    # relay.
    local half=$((rtt / 2))
    if [ "$first" = lan ]; then
        make_lan "$half"
    else
        make_site "$first" 1 "$half"
        make_site "$second" 2 "$half"
    fi

    # shellcheck disable=SC2086 # the flag strings split on purpose
    ns h1 "$PROBE" listen $RELAY_URLS --relay-ca "$WORK/relay.crt" --seed 1 $BIND_1 \
        >"$dir/listen.jsonl" 2>"$dir/listen.log" &
    local id="" addrs="" tries=0
    while [ -z "$id" ] && [ $tries -lt 60 ]; do
        sleep 1
        tries=$((tries + 1))
        id=$(head -1 "$dir/listen.jsonl" 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true)
    done
    if [ -z "$id" ]; then
        echo "{\"listener\":\"$first\",\"dialer\":\"$second\",\"rtt_ms\":$rtt,\"error\":\"listener never came online\"}" \
            | tee -a "$OUT/matrix.jsonl"
        return
    fi
    # What the listener announced stands in for its signed address record.
    addrs=$(head -1 "$dir/listen.jsonl" | jq -r '.addresses[] | "--addr " + .' | tr '\n' ' ')

    # shellcheck disable=SC2086
    ns h2 "$PROBE" dial $RELAY_URLS --relay-ca "$WORK/relay.crt" --seed 2 $BIND_2 \
        --peer "$id" $addrs --secs "$SECS" >"$dir/dial.jsonl" 2>"$dir/dial.log" || true

    # The report is the trailing pretty-printed object; the path events
    # before it are one per line.
    local report
    report=$(sed -n '/^{$/,$p' "$dir/dial.jsonl" | jq -c \
        '{time_to_direct_ms, selected_after_a_minute, fallbacks,
          rtt_p50_us: .overall.rtt_p50_us, on_relay: .overall.on_relay,
          on_direct: .overall.on_direct}' 2>/dev/null || echo '{"error":"no report"}')
    echo "{\"listener\":\"$first\",\"dialer\":\"$second\",\"rtt_ms\":$rtt,\"report\":$report}" \
        | tee -a "$OUT/matrix.jsonl"
}

trap teardown_namespaces EXIT
for rtt in $RTTS; do
    for first in $TYPES; do
        for second in $TYPES; do
            if [ -n "$INVOLVING" ] && [ "$first" != "$INVOLVING" ] && [ "$second" != "$INVOLVING" ]; then
                continue
            fi
            run_pair "$first" "$second" "$rtt"
        done
    done
    run_pair lan lan "$rtt"
done
