//! Seed-drawn tuning a swarm run layers over a cluster's config.
//!
//! A fixed configuration explores one regime however many seeds it sees:
//! the same jitter, the same loss, the same fetch limits. A swarm run draws
//! them from the seed as well, each within the range a node may legally
//! run, so a sweep covers regimes as well as schedules. Every value drawn
//! here is one every node runs alike, so no draw splits consensus.

use std::env;
use std::time::Duration;

use hyperscale_network_memory::RegionPlan;
use hyperscale_node::{FetchConfig, NodeConfig};
use hyperscale_simulation::ProcessingTimes;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Environment variable that turns seed-drawn tuning on for every cluster.
pub const SWARM_VAR: &str = "HYPERSCALE_SIM_SWARM";

/// Whether [`SWARM_VAR`] asks every cluster for seed-drawn tuning.
#[must_use]
pub fn swarm_requested() -> bool {
    env::var(SWARM_VAR).is_ok_and(|value| value != "0")
}

/// Transport and node knobs drawn from a seed.
#[derive(Debug, Clone)]
pub struct SimTuning {
    /// Jitter as a fraction of base latency.
    pub jitter: f64,
    /// Probability a message is lost.
    pub loss: f64,
    /// Probability a delivered copy arrives twice.
    pub duplicate: f64,
    /// Probability a delivered copy brings an old payload of its type.
    pub replay: f64,
    /// Probability one delivery's latency spikes 10-50x.
    pub spike: f64,
    /// Regions the hosts are spread over, and the links between them.
    pub regions: RegionPlan,
    /// How long each pool's dispatched work takes on a host.
    pub processing: ProcessingTimes,
    /// The node configuration every host runs.
    pub node_config: NodeConfig,
    /// Largest offset any host's clock reads from simulated time.
    pub clock_skew: Duration,
    /// Largest drift, in parts per million, of any host's clock.
    pub clock_drift_ppm: u32,
}

impl SimTuning {
    /// The tuning `seed` draws.
    #[must_use]
    pub fn drawn(seed: u64) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x5357_4152_4D54_554E);
        let mut fetch = || {
            let per_request = rng.random_range(1..=50usize);
            FetchConfig::new(
                rng.random_range(per_request..=400),
                per_request,
                rng.random_range(1..=8usize),
            )
        };
        let node_config = NodeConfig {
            transaction_fetch: fetch(),
            provision_fetch: fetch(),
            exec_cert_fetch: fetch(),
            shard_witness_fetch: fetch(),
            beacon_proposal_fetch: fetch(),
            instance_record_fetch: fetch(),
            ..NodeConfig::default()
        };
        Self {
            jitter: rng.random_range(0.0..0.5),
            loss: rng.random_range(0.0..0.05),
            duplicate: rng.random_range(0.0..0.05),
            replay: rng.random_range(0.0..0.01),
            spike: rng.random_range(0.0..0.01),
            node_config,
            // Two hosts' clocks stay under the 2s rush a proposal's
            // timestamp may run ahead of a voter's: at most twice the skew
            // plus both drifts over the longest run.
            clock_skew: Duration::from_millis(rng.random_range(0..=700)),
            clock_drift_ppm: rng.random_range(0..=100),
            regions: RegionPlan {
                regions: rng.random_range(1..=4),
                seed: rng.random(),
            },
            // A node's pools take real time: a consensus step a few
            // milliseconds, a verification or execution batch tens, an I/O
            // post some in between, and a rare one stalls behind a hiccup.
            processing: ProcessingTimes {
                consensus: Duration::from_micros(rng.random_range(0..=5_000)),
                throughput: Duration::from_micros(rng.random_range(0..=50_000)),
                io: Duration::from_micros(rng.random_range(0..=20_000)),
                tail_per_million: rng.random_range(0..=1_000),
                tail: Duration::from_millis(500),
            },
        }
    }
}
