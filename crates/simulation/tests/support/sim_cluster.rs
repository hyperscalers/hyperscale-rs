//! `SimCluster`: the simulation adaptor implementing [`Cluster`].
//!
//! Wraps a [`SimulationRunner`] driven on its logical clock. Each [`Cluster`]
//! method maps onto an existing runner sampler; [`Cluster::run_until`] advances
//! the clock in one-second slices, pumping every host's reshape orchestrator
//! before each slice and checking the predicate between slices, up to the
//! budget.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::tx::{merge_vote_payer, straddler_genesis_balances};
use hyperscale_scenarios::{Budget, Cluster, ScenarioConfig, grow_to, vote_reshape_threshold};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ReshapeThresholds, RoutableTransaction, ShardId,
    StateRoot, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;

/// The clock slice `run_until` advances per poll, matching the runner's own
/// internal predicate loop.
const SLICE: Duration = Duration::from_secs(1);

/// The simulation adaptor: a [`Cluster`] over a [`SimulationRunner`].
pub struct SimCluster {
    runner: SimulationRunner,
}

impl SimCluster {
    /// Build a genesis cluster from `config`, seeded by `seed`, funding the
    /// shared straddler accounts (seed `31` left, `30` right) the cross-shard
    /// scenarios spend.
    #[allow(dead_code)] // some test binaries fund their own balances (reshape_sibling), not every one
    #[must_use]
    pub fn new(config: &ScenarioConfig, seed: u64) -> Self {
        Self::with_balances(config, seed, &straddler_genesis_balances())
    }

    /// Build a genesis cluster funding `balances` instead of the default
    /// straddler accounts — for scenarios that seat their own genesis
    /// distribution (a byte-skewed split-straddler topology). Production
    /// installs the identical balances.
    #[must_use]
    pub fn with_balances(
        config: &ScenarioConfig,
        seed: u64,
        balances: &[(ComponentAddress, Decimal)],
    ) -> Self {
        Self::build(config, seed, balances, false)
    }

    /// Build a genesis cluster giving each pool extra its own shard-less
    /// follower host rather than riding a committee host. This is a sim-only
    /// layout the shuffle-relocation tests (`vnode_relocation`, `pool_reseat`)
    /// need: a rotated vnode must move onto a host not already serving the
    /// destination shard, so every committee host stays single-shard. Portable
    /// scenarios never need it — they express host packing through
    /// `vnodes_per_host` alone.
    #[allow(dead_code)] // only the relocation binaries build a dedicated-pool layout
    #[must_use]
    pub fn with_dedicated_pool_hosts(
        config: &ScenarioConfig,
        seed: u64,
        balances: &[(ComponentAddress, Decimal)],
    ) -> Self {
        Self::build(config, seed, balances, true)
    }

    fn build(
        config: &ScenarioConfig,
        seed: u64,
        balances: &[(ComponentAddress, Decimal)],
        dedicated_pool_hosts: bool,
    ) -> Self {
        let beacon_chain_config = BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: u32::try_from(config.num_shards).unwrap_or(u32::MAX),
            shard_size: config.shard_size,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: config.split_bytes,
            },
            ..BeaconChainConfig::default()
        };
        let sim_config = SimConfig {
            validators_per_shard: config.shard_size,
            vnodes_per_host: config.vnodes_per_host,
            pool_extra_validators: config.pool_surplus,
            dedicated_pool_hosts,
            beacon_chain_config: Some(beacon_chain_config),
            intra_shard_latency: config.latency,
            cross_shard_latency: config.latency,
            ..SimConfig::default()
        };
        let mut runner = SimulationRunner::new(&sim_config, seed);
        runner.initialize_genesis_with_balances(balances);

        Self { runner }
    }

    /// Build a cluster grown to `config.num_shards` with `config.split_bytes` as
    /// the live reshape threshold. Genesis is always a single ROOT shard, so a
    /// scenario that needs a deeper partition reaches it the only way the network
    /// does — by splitting into it, here via [`grow_to`]. Production grows to the
    /// same starting point the same way, so the scenario body is identical on
    /// both harnesses.
    ///
    /// # Panics
    ///
    /// Panics if the grow or the threshold activation misses its budget.
    #[allow(dead_code)] // only the merge-straddler binary pre-grows; others fund a flat genesis
    #[must_use]
    pub fn with_grown_balances(
        config: &ScenarioConfig,
        seed: u64,
        balances: &[(ComponentAddress, Decimal)],
    ) -> Self {
        let grow_config = ScenarioConfig {
            num_shards: 1,
            split_bytes: 0,
            ..*config
        };
        let mut cluster = Self::with_balances(&grow_config, seed, balances);
        let target = u32::try_from(config.num_shards).unwrap_or(u32::MAX);
        grow_to(&mut cluster, target);
        vote_reshape_threshold(&mut cluster, &merge_vote_payer(), config.split_bytes);
        cluster
    }

    /// The underlying runner, for bespoke sim tests that compose a portable
    /// scenario and then assert white-box internals the [`Cluster`] surface
    /// doesn't expose (raw stores, committed blocks, validator placement).
    #[allow(dead_code)] // consumed by some test binaries (reshape_grow), not every one
    #[must_use]
    pub const fn runner(&self) -> &SimulationRunner {
        &self.runner
    }

    /// The underlying runner for the white-box *mutations* the [`Cluster`]
    /// surface deliberately doesn't model — network faults, vnode lifecycle,
    /// system actions, host-targeted or delayed submission.
    #[allow(dead_code)] // consumed by some test binaries, not every one
    pub const fn runner_mut(&mut self) -> &mut SimulationRunner {
        &mut self.runner
    }

    /// The duration `budget` epochs span on this harness's clock.
    fn span(budget: Budget) -> Duration {
        Duration::from_millis(EPOCH_MS) * budget.0
    }

    /// Hosts whose `shard` vnode sits in the shard's current committee — the
    /// live copy. After a grow-then-merge the reformed shard's terminated
    /// pre-merge chain lingers under the same id on its old hosts; those carry
    /// no current committee seat, so this filters them out.
    fn live_committee_hosts(&self, shard: ShardId) -> Vec<NodeIndex> {
        let Some(topology_snapshot) = self.runner.host_topology(0) else {
            return Vec::new();
        };
        let committee: BTreeSet<ValidatorId> = topology_snapshot
            .committee_for_shard(shard)
            .iter()
            .copied()
            .collect();
        (0..self.runner.num_hosts())
            .filter(|&node| {
                self.runner
                    .vnode_state_in(node, shard)
                    .is_some_and(|vnode| committee.contains(&vnode.validator_id()))
            })
            .collect()
    }

    /// A host serving any shard `tx` touches, for submission routing. Single
    /// shard tests resolve to the one serving host; cross-shard source
    /// selection is refined when cross-shard scenarios land.
    fn host_for_tx(&self, tx: &RoutableTransaction) -> Option<NodeIndex> {
        let topology_snapshot = self.runner.host_topology(0)?;
        let shards: BTreeSet<ShardId> = tx
            .all_declared_nodes()
            .map(|node| topology_snapshot.shard_for_node_id(node))
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
            // Reshape first so its duties claim `is_seating`, then reconcile
            // ordinary committee membership (shuffles, relocations) against the
            // committed topology — the orchestrator and the placement path, the
            // two seaters production runs, coordinated the same way.
            self.runner.pump_reshape();
            self.runner.pump_placement();
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
        // Read the live committee's copy: a grow-then-merge leaves the reformed
        // shard's pre-merge chain hosted under the same id, and only the
        // reformed copy carries the beacon-composed root the scenarios assert.
        self.live_committee_hosts(shard)
            .into_iter()
            .find_map(|node| self.runner.hosts_shard(node, shard))
            .map(SubstateStore::state_root)
    }

    fn serves_shard(&self, shard: ShardId) -> bool {
        !self.live_committee_hosts(shard).is_empty()
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
