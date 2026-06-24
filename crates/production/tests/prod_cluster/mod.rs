//! `ProdCluster`: the production adaptor implementing [`Cluster`].
//!
//! Wraps the real QUIC + `RocksDB` [`Harness`] driven on wall-clock. The harness
//! observations are synchronous, so each [`Cluster`] method delegates directly;
//! only [`Cluster::run_until`] needs the async bridge — it `block_on`s a poll
//! loop on an owned multi-thread runtime, the same cadence the harness's own
//! `await_*` helpers use. The runtime never leaks into a scenario body.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_production::LocalValidator;
use hyperscale_scenarios::{Budget, Cluster, ScenarioConfig};
use hyperscale_test_helpers::fixtures::TestFixtures;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ReshapeThresholds, RoutableTransaction, ShardId,
    StateRoot, TransactionDecision, TransactionStatus, TxHash, ValidatorId, uniform_shard_for_node,
};
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};

use crate::cluster::{Cluster as Harness, ClusterSpec, HostSpec};

/// Seed for the production fixtures' deterministic key and topology derivation.
const FIXTURE_SEED: u64 = 7;

/// Poll cadence between predicate samples in `run_until`, matching the
/// harness's own `await_*` interval.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The production adaptor: a [`Cluster`] over the real QUIC + `RocksDB` harness.
pub struct ProdCluster {
    runtime: Runtime,
    inner: Harness,
    epoch_ms: u64,
}

impl ProdCluster {
    /// Build and start a genesis cluster from `config` at `epoch_ms`.
    #[must_use]
    pub fn start(config: &ScenarioConfig, epoch_ms: u64) -> Self {
        let runtime = Builder::new_multi_thread()
            .worker_threads(16)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let spec = Self::spec(config, epoch_ms);
        let inner = runtime.block_on(Harness::start(spec));
        Self {
            runtime,
            inner,
            epoch_ms,
        }
    }

    /// Drive the cluster to a clean shutdown, joining every host's runner task.
    pub fn shutdown(self) {
        let Self { runtime, inner, .. } = self;
        runtime.block_on(inner.shutdown());
    }

    /// Translate the portable config into a production `ClusterSpec`. Single
    /// shard, no surplus for now; multi-shard genesis and pool surplus arrive
    /// with the reshape scenarios.
    fn spec(config: &ScenarioConfig, epoch_ms: u64) -> ClusterSpec {
        let fixtures = TestFixtures::new(FIXTURE_SEED, config.validators_per_shard);
        let validators: Vec<LocalValidator> = (0..config.validators_per_shard)
            .map(|i| LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signing_key: fixtures.signing_key(i),
            })
            .collect();
        let hosts: Vec<HostSpec> = validators
            .chunks(config.vnodes_per_host.max(1) as usize)
            .map(|chunk| HostSpec::new(chunk.to_vec()))
            .collect();
        ClusterSpec {
            topology: fixtures.topology(),
            hosts,
            beacon_chain_config: BeaconChainConfig {
                epoch_duration_ms: epoch_ms,
                num_shards: u32::try_from(config.num_shards).unwrap_or(u32::MAX),
                shard_size: config.validators_per_shard,
                reshape_thresholds: ReshapeThresholds {
                    split_bytes: config.split_bytes,
                },
                ..BeaconChainConfig::default()
            },
            genesis_config: None,
            simulated_outbound_latency: config.latency,
        }
    }

    /// A host serving any shard `tx` touches, for submission routing. Single
    /// shard tests resolve to the one serving host; cross-shard source
    /// selection is refined when cross-shard scenarios land.
    fn host_for_tx(&self, tx: &RoutableTransaction) -> Option<usize> {
        let num_shards = u64::from(self.inner.beacon_state()?.chain_config.num_shards);
        tx.all_declared_nodes()
            .map(|node| uniform_shard_for_node(node, num_shards))
            .find_map(|shard| self.inner.host_serving(shard))
    }
}

/// Rank a status so the cluster-wide view takes the most advanced observation.
const fn status_rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::Completed(_) => 2,
    }
}

impl Cluster for ProdCluster {
    fn submit(&mut self, tx: Arc<RoutableTransaction>) {
        let host = self.host_for_tx(&tx).unwrap_or(0);
        self.inner.submit_transaction(host, tx);
    }

    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool {
        let within = Duration::from_millis(self.epoch_ms) * budget.0;
        self.runtime.block_on(async {
            timeout(within, async {
                while !cond(self) {
                    sleep(POLL_INTERVAL).await;
                }
            })
            .await
            .is_ok()
        })
    }

    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight> {
        self.inner.committed_height(shard).map(BlockHeight::new)
    }

    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        self.inner.committed_state_root_raw(shard)
    }

    fn serves_shard(&self, shard: ShardId) -> bool {
        self.inner.any_host_serves(shard)
    }

    fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        self.inner.beacon_state()
    }

    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus> {
        (0..self.inner.host_count())
            .filter_map(|idx| self.inner.tx_status(idx, &tx))
            .max_by_key(status_rank)
    }

    fn chain_fate(
        &self,
        shard: ShardId,
        tx: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    ) {
        self.inner.chain_fate(shard, tx)
    }
}
