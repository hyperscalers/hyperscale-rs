#!/bin/bash
#
# NAT matrix for the iroh path probe. Runs as root inside a privileged Linux
# container (see ../iroh-nat-testbed.sh); every host, router and the relay
# gets its own network namespace, and the routers translate with nftables.
#
# Usage: testbed.sh [--rtt-ms "20 150"] [--secs 75] [--types "..."] [--out DIR]
#
# Each run joins two hosts of the given types through their routers to one
# shared segment, the "internet", where the relay and public hosts sit. Host
# one listens and host two dials. Both name the relay by its IPv4 and its
# IPv6 address and trust its self-signed certificate, so the relay also
# serves QUIC address discovery. netem on each site's uplink makes the round
# trip between the two hosts the given value. Every ordered pair of types is
# run, plus two hosts behind one router (`lan`). One JSON line per run is
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
OUT=/out
while [ $# -gt 0 ]; do
    case "$1" in
        --rtt-ms) RTTS="$2"; shift 2 ;;
        --secs) SECS="$2"; shift 2 ;;
        --types) TYPES="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

PROBE=/usr/local/bin/probe
RELAY=/usr/local/bin/iroh-relay
WORK=/tmp/testbed
PORT=7000

RELAY4=198.51.100.2
RELAY6=2001:db8:1::2
RELAY_URLS="--relay https://$RELAY4/ --relay https://[$RELAY6]/"

mkdir -p "$WORK" "$OUT"

# One certificate for the relay, trusted by every probe through --relay-ca.
# rustls refuses a certificate authority as a server certificate, so this
# self-signed one is marked as a leaf.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 30 -subj /CN=relay -addext "subjectAltName=IP:$RELAY4,IP:$RELAY6" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
    -keyout "$WORK/relay.key" -out "$WORK/relay.crt" 2>/dev/null

cat >"$WORK/relay.toml" <<CONFIG
enable_relay = true
http_bind_addr = "[::]:80"
enable_quic_addr_discovery = true
enable_metrics = false

[tls]
https_bind_addr = "[::]:443"
quic_bind_addr = "[::]:7842"
cert_mode = "Manual"
manual_cert_path = "$WORK/relay.crt"
manual_key_path = "$WORK/relay.key"
CONFIG

ns() { ip netns exec "$@"; }

new_ns() {
    ip netns add "$1"
    ns "$1" ip link set lo up
    ns "$1" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
}

# Attach namespace $1 to the internet segment as interface `wan`, with the
# given addresses ("-" for none).
attach() {
    local name=$1 v4=$2 v6=$3
    ip link add "w-$name" type veth peer name wan netns "$name"
    ip link set "w-$name" netns inet
    ns inet ip link set "w-$name" master br0 up
    ns "$name" ip link set wan up
    if [ "$v4" != - ]; then ns "$name" ip addr add "$v4/24" dev wan; fi
    if [ "$v6" != - ]; then ns "$name" ip addr add "$v6/64" dev wan nodad; fi
}

# Give router $1 a private side, bridge `lan`, at $2.1/24, so that more than
# one inner namespace can join it.
private_side() {
    local router=$1 net=$2
    ns "$router" ip link add lan type bridge
    ns "$router" ip addr add "$net.1/24" dev lan
    ns "$router" ip link set lan up
}

# Put namespace $2 on router $1's private side at $3, as interface $4,
# routing everything through the router at $5.
join_private() {
    local router=$1 inner=$2 addr=$3 ifname=$4 gateway=$5
    ip link add "l-$inner" type veth peer name "$ifname" netns "$inner"
    ip link set "l-$inner" netns "$router"
    ns "$router" ip link set "l-$inner" master lan up
    ns "$inner" ip addr add "$addr/24" dev "$ifname"
    ns "$inner" ip link set "$ifname" up
    ns "$inner" ip route add default via "$gateway"
}

# Translate everything leaving `wan` from `lan`. $2 is the masquerade flag
# set: empty keeps the source port where it can (endpoint independent
# mapping), `random` draws one per flow (endpoint dependent). $3 adds a rule
# to the forward chain ahead of the defaults.
nat_router() {
    local router=$1 flags=$2 extra_forward=${3:-}
    ns "$router" nft -f - <<RULES
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "wan" masquerade $flags
    }
}
table inet filter {
    chain forward {
        type filter hook forward priority filter; policy drop;
        $extra_forward
        ct state established,related accept
        iifname "lan" accept
    }
}
RULES
}

# Add $2 milliseconds to everything namespace $1 sends on `wan`.
delay_uplink() {
    if [ "$2" -gt 0 ]; then
        ns "$1" tc qdisc add dev wan root netem delay "${2}ms"
    fi
}

# Bring up host $2 of type $1 in namespace h$2, behind whatever routers the
# type needs, with $3 milliseconds on the site's uplink. Sets BIND_<n> to
# the probe's bind flags.
make_site() {
    local type=$1 n=$2 delay=$3 host="h$2"
    new_ns "$host"
    case "$type" in
        public)
            attach "$host" "198.51.100.1$n" "2001:db8:1::1$n"
            delay_uplink "$host" "$delay"
            printf -v "BIND_$n" '%s' \
                "--bind 198.51.100.1$n:$PORT --bind [2001:db8:1::1$n]:$PORT"
            ;;
        ipv6-only)
            attach "$host" - "2001:db8:1::1$n"
            ns "$host" nft -f - <<RULES
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname "lo" accept
        meta l4proto ipv6-icmp accept
    }
}
RULES
            delay_uplink "$host" "$delay"
            printf -v "BIND_$n" '%s' "--bind [2001:db8:1::1$n]:$PORT"
            ;;
        full-cone | port-restricted | symmetric | udp-blocked)
            new_ns "r$n"
            attach "r$n" "198.51.100.2$n" -
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
            attach "c$n" "198.51.100.3$n" -
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
    attach r1 198.51.100.21 -
    private_side r1 10.1.0
    nat_router r1 ""
    delay_uplink r1 "$1"
    for n in 1 2; do
        new_ns "h$n"
        join_private r1 "h$n" "10.1.0.$((n + 1))" eth0 10.1.0.1
        printf -v "BIND_$n" '%s' "--bind 10.1.0.$((n + 1)):$PORT"
    done
}

teardown() {
    pkill -f "$PROBE" 2>/dev/null || true
    pkill -f "$RELAY" 2>/dev/null || true
    sleep 1
    for name in $(ip netns list | awk '{print $1}'); do
        ip netns del "$name"
    done
}

run_pair() {
    local first=$1 second=$2 rtt=$3 dir
    dir="$OUT/rtt-$rtt/$first--$second"
    mkdir -p "$dir"
    teardown

    new_ns inet
    ns inet ip link add br0 type bridge
    ns inet ip link set br0 up
    new_ns relay
    attach relay "$RELAY4" "$RELAY6"
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

trap teardown EXIT
for rtt in $RTTS; do
    for first in $TYPES; do
        for second in $TYPES; do
            run_pair "$first" "$second" "$rtt"
        done
    done
    run_pair lan lan "$rtt"
done
