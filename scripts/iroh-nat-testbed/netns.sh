#!/bin/bash
#
# Network namespaces, NAT routers and the relay shared by the iroh testbeds
# (testbed.sh, seating.sh). Sourced, not run. Every host, router and the
# relay gets its own namespace; the "internet" is bridge br0 in namespace
# `inet`, where the relay and public hosts sit.

RELAY=/usr/local/bin/iroh-relay
WORK=/tmp/testbed

RELAY_NAME=relay.testbed
RELAY_URL="https://$RELAY_NAME/"

ns() { ip netns exec "$@"; }

new_ns() {
    ip netns add "$1"
    ns "$1" ip link set lo up
    ns "$1" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
}

# Make the internet segment.
make_inet() {
    new_ns inet
    ns inet ip link add br0 type bridge
    ns inet ip link set br0 up
}

# Attach namespace $1 to the internet segment as interface `wan`, with the
# given addresses in prefix notation ("-" for none).
attach() {
    local name=$1 v4=$2 v6=$3
    ip link add "w-$name" type veth peer name wan netns "$name"
    ip link set "w-$name" netns inet
    ns inet ip link set "w-$name" master br0 up
    ns "$name" ip link set wan up
    if [ "$v4" != - ]; then ns "$name" ip addr add "$v4" dev wan; fi
    if [ "$v6" != - ]; then ns "$name" ip addr add "$v6" dev wan nodad; fi
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
#
# Like a home router, the router drops what arrives on `wan` for itself
# unasked. Accepting it would let a hole punch probe that arrives before
# the inner host's own probe leaves claim the outside address and port in
# conntrack, and the inner host's probe would then be translated to another
# port.
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
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "wan" ct state new drop
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        $extra_forward
        ct state established,related accept
        iifname "lan" accept
    }
}
RULES
}

# Admit only replies to namespace $1, as an IPv6 home router's stateful
# firewall does for the global addresses behind it.
reply_only_firewall() {
    ns "$1" nft -f - <<RULES
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname "lo" accept
        meta l4proto ipv6-icmp accept
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

# Write the relay's certificate and configuration, and name it in the
# container's hosts file at IPv4 $1 and IPv6 $2. Every namespace shares
# that file, which iroh's resolver reads before any nameserver; iroh 1.3.0
# refuses a relay named by an IPv6 literal, so the relay is named by
# hostname for hosts of either family.
prepare_relay() {
    local v4=$1 v6=$2
    mkdir -p "$WORK"
    grep -q " $RELAY_NAME\$" /etc/hosts || printf '%s %s\n%s %s\n' \
        "$v4" "$RELAY_NAME" "$v6" "$RELAY_NAME" >>/etc/hosts

    # One certificate, trusted by every host. rustls refuses a certificate
    # authority as a server certificate, so this self-signed one is a leaf.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -days 30 -subj /CN=relay \
        -addext "subjectAltName=DNS:$RELAY_NAME,IP:$v4,IP:$v6" \
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
}

# Stop every process the testbed started in a namespace and remove the
# namespaces.
teardown_namespaces() {
    for name in $(ip netns list | awk '{print $1}'); do
        ip netns pids "$name" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 1
    for name in $(ip netns list | awk '{print $1}'); do
        ip netns del "$name"
    done
}
