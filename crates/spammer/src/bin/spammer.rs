//! Hyperscale Transaction Spammer CLI
//!
//! A command-line tool for generating and submitting transactions to a Hyperscale network.

use clap::{Parser, Subcommand};
use hyperscale_spammer::accounts::{AccountPool, SelectionMode};
use hyperscale_spammer::client::RpcClient;
use hyperscale_spammer::config::SpammerConfig;
use hyperscale_spammer::genesis::generate_genesis_toml;
use hyperscale_spammer::runner::Spammer;
use hyperscale_spammer::workloads::{TransferWorkload, WorkloadGenerator};
use hyperscale_types::shard_for_node;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "hyperscale-spammer")]
#[command(about = "Transaction spammer for Hyperscale network")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate genesis configuration with funded accounts
    Genesis {
        /// Number of shards
        #[arg(long, default_value = "2")]
        num_shards: u64,

        /// Accounts per shard
        #[arg(long, default_value = "100")]
        accounts_per_shard: usize,

        /// Initial balance per account
        #[arg(long, default_value = "1000000")]
        balance: u64,
    },

    /// Run transaction spammer against network endpoints
    Run {
        /// RPC endpoints (comma-separated, one per shard minimum)
        #[arg(short, long, value_delimiter = ',', required = true)]
        endpoints: Vec<String>,

        /// Number of shards
        #[arg(long, default_value = "2")]
        num_shards: u64,

        /// Number of validators per shard (for load distribution)
        #[arg(long, default_value = "1")]
        validators_per_shard: usize,

        /// Target transactions per second
        #[arg(long, default_value = "1000")]
        tps: u64,

        /// Duration to run (e.g., "30s", "5m", "1h")
        #[arg(short, long, default_value = "60s")]
        duration: humantime::Duration,

        /// Cross-shard transaction ratio (0.0 to 1.0)
        #[arg(long, default_value = "0.3")]
        cross_shard_ratio: f64,

        /// Accounts per shard
        #[arg(long, default_value = "100")]
        accounts_per_shard: usize,

        /// Account selection mode (random, round-robin, no-contention, zipf, zipf:N)
        #[arg(long, default_value = "no-contention")]
        selection: String,

        /// Wait for nodes to be ready before starting
        #[arg(long)]
        wait_ready: bool,

        /// Batch size for transaction generation
        #[arg(long, default_value = "100")]
        batch_size: usize,

        /// Measure transaction latency by polling for completion
        ///
        /// When enabled, a sample of transactions will be tracked until they
        /// reach a terminal state. This adds overhead but provides latency metrics.
        #[arg(long)]
        measure_latency: bool,

        /// Sample rate for latency measurement (0.0 to 1.0)
        ///
        /// Controls what fraction of transactions are tracked for latency.
        /// Lower values reduce overhead. Only used if --measure-latency is set.
        #[arg(long, default_value = "0.01")]
        latency_sample_rate: f64,

        /// Poll interval for checking transaction status (e.g., "100ms")
        ///
        /// How frequently to poll for transaction completion.
        /// Only used if --measure-latency is set.
        #[arg(long, default_value = "100ms")]
        latency_poll_interval: humantime::Duration,
    },

    /// Submit a single transaction and wait for it to complete (smoke test)
    ///
    /// This command submits one transaction, polls for its status until it
    /// reaches a terminal state, and reports the end-to-end latency.
    /// Useful for verifying the cluster is healthy after startup.
    SmokeTest {
        /// RPC endpoints (comma-separated, one per shard minimum)
        #[arg(short, long, value_delimiter = ',', required = true)]
        endpoints: Vec<String>,

        /// Number of shards
        #[arg(long, default_value = "2")]
        num_shards: u64,

        /// Accounts per shard (must match genesis configuration)
        #[arg(long, default_value = "100")]
        accounts_per_shard: usize,

        /// Maximum time to wait for transaction completion
        #[arg(long, default_value = "60s")]
        timeout: humantime::Duration,

        /// Poll interval for checking transaction status
        #[arg(long, default_value = "100ms")]
        poll_interval: humantime::Duration,

        /// Wait for nodes to be ready before starting
        #[arg(long)]
        wait_ready: bool,
    },
}

fn parse_selection_mode(s: &str) -> Result<SelectionMode, String> {
    match s.to_lowercase().as_str() {
        "random" => Ok(SelectionMode::Random),
        "round-robin" | "roundrobin" => Ok(SelectionMode::RoundRobin),
        "no-contention" | "nocontention" => Ok(SelectionMode::NoContention),
        "zipf" => Ok(SelectionMode::Zipf { exponent: 1.5 }),
        s if s.starts_with("zipf:") => {
            let exp: f64 = s[5..]
                .parse()
                .map_err(|_| format!("Invalid zipf exponent: {}", &s[5..]))?;
            Ok(SelectionMode::Zipf { exponent: exp })
        }
        _ => Err(format!("Unknown selection mode: {}", s)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Genesis {
            num_shards,
            accounts_per_shard,
            balance,
        } => {
            // Don't initialize tracing for genesis - output goes to stdout
            let toml =
                generate_genesis_toml(num_shards, accounts_per_shard, Decimal::from(balance))?;
            print!("{}", toml);
        }

        Commands::Run {
            endpoints,
            num_shards,
            validators_per_shard,
            tps,
            duration,
            cross_shard_ratio,
            accounts_per_shard,
            selection,
            wait_ready,
            batch_size,
            measure_latency,
            latency_sample_rate,
            latency_poll_interval,
        } => {
            // Initialize tracing for the run command
            tracing_subscriber::fmt::init();

            let selection_mode = parse_selection_mode(&selection)?;

            // Clamp batch size to target TPS to avoid sending more txns than intended
            let effective_batch_size = batch_size.min(tps as usize).max(1);

            let mut config = SpammerConfig::new(endpoints)
                .with_num_shards(num_shards)
                .with_validators_per_shard(validators_per_shard)
                .with_target_tps(tps)
                .with_cross_shard_ratio(cross_shard_ratio)
                .with_accounts_per_shard(accounts_per_shard)
                .with_selection_mode(selection_mode)
                .with_batch_size(effective_batch_size)
                .with_network(NetworkDefinition::simulator());

            if measure_latency {
                config = config
                    .with_latency_tracking(true)
                    .with_latency_sample_rate(latency_sample_rate)
                    .with_latency_poll_interval(*latency_poll_interval);
            }

            let mut spammer = Spammer::new(config)?;

            if wait_ready {
                println!("Waiting for nodes to be ready...");
                spammer.wait_for_ready(Duration::from_secs(60)).await?;
                println!("All nodes ready.");
            }

            println!("Starting spammer for {:?}...", *duration);
            if measure_latency {
                println!(
                    "Latency tracking enabled (sample rate: {:.1}%, poll interval: {:?})",
                    latency_sample_rate * 100.0,
                    *latency_poll_interval
                );
            }
            let report = spammer.run_for(*duration).await;
            report.print();
        }

        Commands::SmokeTest {
            endpoints,
            num_shards,
            accounts_per_shard,
            timeout,
            poll_interval,
            wait_ready,
        } => {
            // Initialize tracing for smoke test
            tracing_subscriber::fmt::init();

            println!("=== Smoke Test ===");
            println!("Endpoints: {:?}", endpoints);
            println!("Shards: {}", num_shards);

            // Create RPC clients
            let clients: Vec<RpcClient> = endpoints
                .iter()
                .map(|e| RpcClient::new(e.clone()))
                .collect();

            // Wait for nodes to be ready if requested
            if wait_ready {
                println!("Waiting for nodes to be ready...");
                let start = Instant::now();
                let ready_timeout = Duration::from_secs(60);

                loop {
                    if start.elapsed() > ready_timeout {
                        eprintln!("ERROR: Nodes not ready within timeout");
                        std::process::exit(1);
                    }

                    let mut all_ready = true;
                    for client in &clients {
                        if !client.is_ready().await {
                            all_ready = false;
                            break;
                        }
                    }

                    if all_ready {
                        println!("All nodes ready.");
                        break;
                    }

                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }

            // Generate accounts (same as what's in genesis)
            let accounts = AccountPool::generate(num_shards, accounts_per_shard)
                .expect("Failed to generate account pool");

            // Load nonces from file to continue where previous runs left off
            match accounts.load_nonces_default() {
                Ok(n) if n > 0 => println!("Loaded {} account nonces from file", n),
                Ok(_) => {} // No file or empty, starting fresh
                Err(e) => eprintln!("Warning: failed to load nonces: {}", e),
            }

            // Create a simple same-shard transfer
            let workload =
                TransferWorkload::new(NetworkDefinition::simulator()).with_cross_shard_ratio(0.0); // Same-shard for simplicity

            // Use current time as seed to generate unique transactions each run
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let tx = workload
                .generate_one(&accounts, &mut rng)
                .expect("Failed to generate transaction");

            // Determine which shard to submit to
            let target_shard = if let Some(first_write) = tx.declared_writes.first() {
                shard_for_node(first_write, num_shards).0 as usize
            } else {
                0
            };

            let client_idx = target_shard % clients.len();
            let client = &clients[client_idx];

            // Submit the transaction
            println!("Submitting transaction to shard {}...", target_shard);
            let submit_start = Instant::now();

            let result = client
                .submit_transaction(&tx)
                .await
                .expect("Failed to submit transaction");

            if !result.accepted {
                eprintln!(
                    "ERROR: Transaction rejected: {}",
                    result.error.unwrap_or_default()
                );
                std::process::exit(1);
            }

            let tx_hash = &result.hash;
            println!("Transaction submitted: {}", tx_hash);
            println!("Polling for status...");

            // Poll for transaction status
            let timeout_duration: Duration = *timeout;
            let poll_duration: Duration = *poll_interval;
            let mut last_status = String::new();

            loop {
                if submit_start.elapsed() > timeout_duration {
                    eprintln!("ERROR: Transaction did not complete within timeout");
                    std::process::exit(1);
                }

                match client.get_transaction_status(tx_hash).await {
                    Ok(status) => {
                        if status.status != last_status {
                            println!(
                                "  [{:>6}ms] Status: {}",
                                submit_start.elapsed().as_millis(),
                                status.status
                            );
                            last_status = status.status.clone();
                        }

                        if status.is_terminal() {
                            let total_latency = submit_start.elapsed();
                            println!();
                            println!("=== Smoke Test Results ===");
                            println!("Final status: {}", status.status);

                            if let Some(decision) = &status.decision {
                                println!("Decision: {}", decision);
                            }

                            println!("Total latency: {:?}", total_latency);
                            println!("Latency (ms): {:.2}", total_latency.as_secs_f64() * 1000.0);

                            if status.is_success() {
                                println!("Result: SUCCESS");
                                // Save nonces for next run
                                if let Err(e) = accounts.save_nonces_default() {
                                    eprintln!("Warning: failed to save nonces: {}", e);
                                }
                            } else {
                                println!("Result: FAILED");
                                if let Some(error) = &status.error {
                                    eprintln!("Error: {}", error);
                                }
                                std::process::exit(1);
                            }

                            break;
                        }
                    }
                    Err(e) => {
                        // Transaction might not be in cache yet, continue polling
                        if submit_start.elapsed() > Duration::from_secs(5) {
                            eprintln!("Warning: Error polling status: {}", e);
                        }
                    }
                }

                tokio::time::sleep(poll_duration).await;
            }
        }
    }

    Ok(())
}
