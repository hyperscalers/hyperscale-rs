# Running a Distributed Hyperscale Cluster

This guide explains how to run a `hyperscale` cluster across multiple physical machines or VMs using raw binaries (process-based). You can run multiple validators per host, but each validator must run on a different port. The configs will be generated for you locally, and you will need to copy them to the target machines. If one of your nodes is behind NAT, you can enable port mapping (UPnP, NAT-PMP or PCP) to forward the port automatically, or give the network relays to fall back on. Make sure that the ports are whitelisted in your firewall for UDP. Use the distributed monitoring script to set up a Prometheus / Grafana stack to monitor your distributed cluster. The monitoring host will have to scrape the target RPC ports (8080, 8081, 808x...) on your validator node hosts.

## Prerequisites
- Rust and build tools installed on your local machine (to generate configs).
- SSH access to all target machines.
- **Port 9000 (UDP)** open between all machines (P2P, QUIC).
- **Port 8080 (TCP)** open to query metrics/RPC remotely.

## Step 1: Generate Configuration

On your local machine (or one of the servers), use the helper script to generate the keys and configuration files for all Hosts and Nodes at once.

You must provide the **Public/LAN IP addresses** (Hosts) and the number of validator nodes to run on each host.

```bash
# Example: 2 physical hosts, running 2 validators each (4 validators total)
./scripts/generate-distributed-config.sh --hosts "192.168.1.10,192.168.1.11" --nodes-per-host 2
```

This will create a `distributed-cluster-data/` directory organized by host:
- `host-0/`: Contains configs for all nodes running on host 0.
  - `node-0/`: Validator 0 config (Port 8080).
  - `node-1/`: Validator 1 config (Port 8081).
- `host-1/`: Contains configs for all nodes running on host 1.
  - `node-0/`: Validator 0 config (Port 8080).
  - `node-1/`: Validator 1 config (Port 8081).

The script will also output convenient `scp` commands to copy the files to your target machines.

## Step 2: Distribute Files

Follow the instructions output by the generator script. Generally, you will:

1.  Copy the `host-N` directory to the respective machine.
2.  Copy the compiled `hyperscale-validator` binary.

## Step 3: Launch

SSH into each machine and start the validator nodes.

**Machine 1 (192.168.1.10):**
```bash
./hyperscale-validator --config ~/distributed-cluster-data/host-0/node-0/config.toml &
./hyperscale-validator --config ~/distributed-cluster-data/host-0/node-1/config.toml &
```

**Machine 2 (192.168.1.11):**
```bash
./hyperscale-validator --config ~/distributed-cluster-data/host-1/node-0/config.toml &
./hyperscale-validator --config ~/distributed-cluster-data/host-1/node-1/config.toml &
```

## 4. Monitoring (Optional)

You can launch a Prometheus + Grafana stack to monitor your distributed cluster from your local machine.

Run the monitoring script with the list of specific targets (IP:PORT):

```bash
./scripts/monitoring/start-distributed-monitoring.sh --targets "192.168.1.10:8080,192.168.1.10:8081,192.168.1.11:8080,192.168.1.11:8081"
```

Access the dashboards:
- **Grafana**: [http://localhost:3000](http://localhost:3000) (User: `admin`, Password: `admin`)
- **Prometheus**: [http://localhost:9090](http://localhost:9090)

## Troubleshooting

- **Connection Refused**: Check your firewall rules (ufw/iptables) to ensure the UDP ports 9000-9100 are open.
- **Logs**: Check output to see if they are connecting. You should see "iroh network adapter bound" and, once peers bind, no repeated "No bound peer" warnings.
