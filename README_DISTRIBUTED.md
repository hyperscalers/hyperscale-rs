# Running a Distributed Hyperscale Cluster

This guide explains how to run a `hyperscale` cluster across multiple physical machines or VMs using raw binaries (process-based).

## Prerequisites
- Rust and build tools installed on your local machine (to generate configs).
- SSH access to all target machines.
- **Port 9000 (UDP/TCP)** open between all machines (P2P).
- **Port 30500 (TCP)** open between all machines (TCP fallback).
- **Port 8080 (TCP)** open to query metrics/RPC remotely.

## Step 1: Generate Configuration

On your local machine (or one of the servers), use the helper script to generate the keys and configuration files for all nodes at once. You must provide the **Public/LAN IP addresses** that the nodes will use to communicate with each other.

```bash
# Example: 2 nodes at 192.168.1.10 and 192.168.1.11
./scripts/generate-distributed-config.sh --nodes "192.168.1.10,192.168.1.11"
```

This will create a `distributed-cluster-data/` directory containing:
- `node-0/`: Config and keys for the first IP.
- `node-1/`: Config and keys for the second IP.

## Step 2: Distribute Files

You need to copy the specific node folder and the validator binary to each machine.

### Build the binary first
```bash
cargo build --release --bin hyperscale-validator
```

### Copy to Machine 1 (192.168.1.10)
```bash
scp -r distributed-cluster-data/node-0 user@192.168.1.10:~/hyperscale-node
scp target/release/hyperscale-validator user@192.168.1.10:~/
```

### Copy to Machine 2 (192.168.1.11)
```bash
scp -r distributed-cluster-data/node-1 user@192.168.1.11:~/hyperscale-node
scp target/release/hyperscale-validator user@192.168.1.11:~/
```

## Step 3: Launch

SSH into each machine and start the validator using the uploaded config.

**Machine 1:**
```bash
./hyperscale-validator --config ~/hyperscale-node/config.toml
```

**Machine 2:**
```bash
./hyperscale-validator --config ~/hyperscale-node/config.toml
```

The nodes will automatically dial each other using the bootstrap peer list generated in Step 1.

## 4. Monitoring (Optional)

You can launch a Prometheus + Grafana stack to monitor your distributed cluster from your local machine.

Run the monitoring script with the list of node IPs:

```bash
./scripts/monitoring/start-distributed-monitoring.sh --nodes "192.168.178.106,192.168.178.119"
```

Access the dashboards:
- **Grafana**: [http://localhost:3000](http://localhost:3000) (User: `admin`, Password: `admin`)
- **Prometheus**: [http://localhost:9090](http://localhost:9090)

## Troubleshooting

- **Connection Refused**: Check your firewall rules (ufw/iptables) to ensure ports 9000/UDP, 9000/TCP, and 30500/TCP are open.
- **Logs**: Check output to see if they are connecting. You should see "New peer connected" or similar libp2p events.
