//! `SimCluster`: the simulation adaptor implementing [`Cluster`].
//!
//! Wraps a [`SimulationRunner`] driven on its logical clock. Each [`Cluster`]
//! method maps onto an existing runner sampler; [`Cluster::run_until`] advances
//! the clock in one-second slices, checking the predicate between slices, up to
//! the budget. There is no reshape pump yet — that arrives with the
//! `ReshapeDriver`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::{Budget, Cluster, ScenarioConfig};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ReshapeThresholds, RoutableTransaction, ShardId,
    StateRoot, TransactionDecision, TransactionStatus, TxHash,
};

/// The clock slice `run_until` advances per poll, matching the runner's own
/// internal predicate loop.
const SLICE: Duration = Duration::from_secs(1);

/// The simulation adaptor: a [`Cluster`] over a [`SimulationRunner`].
pub struct SimCluster {
    runner: SimulationRunner,
}

impl SimCluster {
    /// Build a genesis cluster from `config`, seeded by `seed`.
    #[must_use]
    pub fn new(config: &ScenarioConfig, seed: u64) -> Self {
        let beacon_chain_config = BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: u32::try_from(config.num_shards).unwrap_or(u32::MAX),
            shard_size: config.validators_per_shard,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: config.split_bytes,
            },
            ..BeaconChainConfig::default()
        };
        let sim_config = SimConfig {
            validators_per_shard: config.validators_per_shard,
            vnodes_per_host: config.vnodes_per_host,
            pool_extra_validators: config.pool_surplus,
            dedicated_pool_hosts: config.dedicated_hosts,
            beacon_chain_config: Some(beacon_chain_config),
            intra_shard_latency: config.latency,
            cross_shard_latency: config.latency,
            ..SimConfig::default()
        };
        let mut runner = SimulationRunner::new(&sim_config, seed);
        runner.initialize_genesis();
        Self { runner }
    }

    /// The duration `budget` epochs span on this harness's clock.
    fn span(budget: Budget) -> Duration {
        Duration::from_millis(EPOCH_MS) * budget.0
    }

    /// A host serving any shard `tx` touches, for submission routing. Single
    /// shard tests resolve to the one serving host; cross-shard source
    /// selection is refined when cross-shard scenarios land.
    fn host_for_tx(&self, tx: &RoutableTransaction) -> Option<NodeIndex> {
        let topology = self.runner.host_topology(0)?;
        let shards: BTreeSet<ShardId> = tx
            .all_declared_nodes()
            .map(|node| topology.shard_for_node_id(node))
            .collect();
        (0..self.runner.num_hosts()).find(|&node| {
            self.runner
                .hosted_shards_of(node)
                .iter()
                .any(|shard| shards.contains(shard))
        })
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

impl Cluster for SimCluster {
    fn submit(&mut self, tx: Arc<RoutableTransaction>) {
        let host = self.host_for_tx(&tx).unwrap_or(0);
        self.runner.schedule_initial_event(
            host,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
    }

    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool {
        if cond(self) {
            return true;
        }
        let deadline = self.runner.now() + Self::span(budget);
        while self.runner.now() < deadline {
            let next = (self.runner.now() + SLICE).min(deadline);
            self.runner.run_until(next);
            if cond(self) {
                return true;
            }
        }
        cond(self)
    }

    fn now(&self) -> Duration {
        self.runner.now()
    }

    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight> {
        (0..self.runner.num_hosts())
            .filter_map(|node| self.runner.hosts_shard(node, shard))
            .map(ShardChainReader::committed_height)
            .max()
    }

    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        (0..self.runner.num_hosts())
            .find_map(|node| self.runner.hosts_shard(node, shard))
            .map(SubstateStore::state_root)
    }

    fn serves_shard(&self, shard: ShardId) -> bool {
        (0..self.runner.num_hosts()).any(|node| self.runner.hosted_shards_of(node).contains(&shard))
    }

    fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        (0..self.runner.num_hosts())
            .filter_map(|node| self.runner.beacon_storage(node))
            .filter_map(|storage| storage.latest_committed())
            .max_by_key(|(_, state)| state.current_epoch)
            .map(|(_, state)| state)
    }

    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus> {
        (0..self.runner.num_hosts())
            .filter_map(|node| self.runner.tx_status(node, &tx))
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
        let Some(store) =
            (0..self.runner.num_hosts()).find_map(|node| self.runner.hosts_shard(node, shard))
        else {
            return (None, None);
        };
        let mut committed = None;
        let mut finalized = None;
        let tip = store.committed_height();
        let mut height = BlockHeight::new(1);
        while height <= tip {
            if let Some(certified) = store.get_block(height) {
                let block = certified.block();
                if block.transactions().iter().any(|t| t.hash() == tx) {
                    committed = Some(height);
                }
                for fw in block.certificates().iter() {
                    if let Some((_, decision)) =
                        fw.tx_decisions().into_iter().find(|(h, _)| *h == tx)
                    {
                        finalized = Some((height, decision));
                    }
                }
            }
            height = height.next();
        }
        (committed, finalized)
    }
}
