# Running the iroh path probe between two real networks

The probe answers two questions no single machine can: do two hosts on
ordinary home connections reach each other directly, and once they do, how
often do they fall back to the relay. You need two computers on **different
networks** (for example your home broadband and a friend's, or home
broadband and a phone's hotspot) and one small server with a public address
to run a relay on. Everything runs on machines you control; the probe never
contacts a public relay or discovery service.

## 1. What you need

- Two computers, A and B, running macOS or Linux, on different networks.
  Write down for each: fixed line or mobile, the provider, the country, the
  router model if you know it, and whether you have set up port forwarding.
- One server with a public IPv4 address (a small cloud VM is enough) and a
  DNS name pointing at it, for example `relay.example.org`. It must accept
  TCP 80, TCP 443 and UDP 7842 from anywhere.
- On all three: a Rust toolchain (`rustup`) and a checkout of this
  repository on the `iroh-network-spike` branch. The first build takes a
  while and a few gigabytes of disk.

## 2. Run the relay on the server

```sh
cargo install --locked iroh-relay@1.3.0 --features server
```

Save this as `relay.toml`, with your DNS name and email:

```toml
enable_relay = true
enable_quic_addr_discovery = true
enable_metrics = false
http_bind_addr = "[::]:80"

[tls]
cert_mode = "LetsEncrypt"
hostname = "relay.example.org"
contact = "you@example.org"
cert_dir = "./certs"
```

Start it as root (it binds ports 80 and 443) and leave it running:

```sh
sudo ~/.cargo/bin/iroh-relay --config-path relay.toml
```

The relay obtains a certificate from Let's Encrypt on its first start. If
you cannot give the server a DNS name, use a self-signed certificate
instead: set `cert_mode = "Manual"` with `manual_cert_path` and
`manual_key_path`, name the relay by its IP address
(`https://203.0.113.5/`), and pass `--relay-ca cert.pem` to every probe
command below. The certificate must list that IP address as a subject
alternative name and must not be a certificate authority, or the probe
refuses it:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 30 -subj /CN=relay -addext "subjectAltName=IP:203.0.113.5" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
    -keyout key.pem -out cert.pem
```

## 3. Start the listener on computer A

From the repository root:

```sh
./scripts/iroh-probe.sh listen --relay https://relay.example.org --seed 1 | tee listen-A.jsonl
```

The first line printed is your listener's identity, for example:

```json
{"id":"8a88e3dd...","relays":["https://relay.example.org/"],"addresses":["192.168.1.20:51234","81.2.69.160:51234"]}
```

Copy the `id` value and send it to whoever runs computer B. Leave the
listener running; on a laptop keep it awake and plugged in (`caffeinate -i`
on macOS, `systemd-inhibit` on Linux). If macOS asks whether to accept
incoming connections, allow them.

## 4. Dial from computer B

```sh
./scripts/iroh-probe.sh dial --relay https://relay.example.org --seed 2 \
    --peer <the id from A> --secs 600 | tee dial-B.jsonl
```

This holds the connection for ten minutes, sending a small ping every 20
ms, then prints a report and exits. For the long run below, use
`--secs 86400` (24 hours) instead.

Run it once for ten minutes first. If you can, repeat it with the roles
swapped (B listens, A dials), and once more with one side on a phone
hotspot.

## 5. What to send back

- `dial-B.jsonl` and `listen-A.jsonl` from every run.
- For each computer, the notes from step 1, and the time and date of the
  run.

These files contain the public IP addresses of both computers. Share them
only with the people evaluating the spike.

## 6. How the files are read

Every line before the report is one path event: when (`at_ms` since the
probe started), which side saw it, and whether the path is `direct` or
`relay`. The report at the end of `dial-B.jsonl` holds:

| Field | Meaning |
|---|---|
| `time_to_direct_ms` | How long after dialing a direct path was first selected. Missing if it never was. |
| `selected_after_a_minute` | `direct` or `relay`: the path in use one minute after dialing. |
| `fallbacks` | How many times the connection moved from a direct path back to the relay. |
| `overall.pings`, `overall.on_direct`, `overall.on_relay` | Pings echoed in all, and how many came back over each kind of path. |
| `overall.rtt_p50_us`, `overall.rtt_p99_us` | Round trip time of the pings, median and 99th percentile, in microseconds. |
| `overall.longest_silence_ms` | The longest stretch with no ping answered: a stall. |

**G1, direct reachability.** A pair counts as direct when
`selected_after_a_minute` is `direct`. The go line needs at least 90% of
home pairs direct, and every pair direct where either side is public or
has a port forward.

**G8, time on the relay (24 hour runs).** The share of time a pair spent
relayed after first reaching a direct path is about `overall.on_relay`
divided by `overall.pings`, counting only pings after `time_to_direct_ms`;
the events list gives the exact intervals between each `selected relay`
and the next `selected direct`. The go line is under 1%; over 10% is a
kill. `fallbacks` above zero on a fixed line connection is worth a note
with the time of day.

## 7. When something goes wrong

- `the endpoint reached no relay`: the relay is not reachable from this
  computer. Check that `https://relay.example.org` answers in a browser and
  that the server's firewall allows TCP 443.
- The dial never prints `selected` `direct`: that is a result, not a
  failure. Send the files anyway; a relay only pair is what G1 counts.
- Nothing prints at all for a minute: the first build is still running.
