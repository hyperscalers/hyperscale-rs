//! `SimCluster`: the simulation adaptor implementing [`Cluster`].
//!
//! Wraps a [`SimulationRunner`] driven on its logical clock. Each [`Cluster`]
//! method maps onto an existing runner sampler; [`Cluster::run_until`] advances
//! the clock in one-second slices, stepping every host's reshape orchestrator
//! before each slice and checking the predicate between slices, up to the
//! budget.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_engine::{PreviewGrants, PreviewInputs, PreviewReport, TickEnvironment};
use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network::fault::{HostId, Rewrite, RuleHandle};
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::query::{
    RanAs, chain_fate, chain_membership, records_naming, status_rank,
};
use hyperscale_scenarios::tx::{staking_genesis_accounts, world_pools};
use hyperscale_scenarios::{
    Budget, Cluster, FaultHandle, FaultableCluster, ScenarioConfig, grow_to, submission_shards,
    vote_reshape_threshold,
};
use hyperscale_simulation::{EPOCH_MS, ExecutionMode, JoinKind, SimConfig, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    Address, BeaconChainConfig, BeaconState, BlockHeight, CertifiedBlock, ConsensusReceipt,
    Derivation, Event, LocalKey, PrincipalAddr, ReshapeThresholds, ShardId, Signer, StateRoot,
    SubstateKey, Transaction, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
    Verified, WeightedTimestamp, WorkInFlight,
};

/// The clock slice `run_until` advances per poll, matching the runner's own
/// internal predicate loop — and so the resolution of anything a scenario
/// reads off the clock between polls.
pub const SLICE: Duration = Duration::from_secs(1);

/// How many epochs the beacon tip may lag wall-clock before the harness
/// fails the scenario at the park itself, instead of at whatever distant
/// downstream assert first depends on a committed fold. Sized above the
/// longest deliberate beacon stall any scenario stages (the pool
/// partition holds roughly seven epochs, heal included); a genuine park
/// runs unbounded and crosses this within a few extra slices.
const MAX_BEACON_LAG_EPOCHS: u64 = 10;

/// The full constructor input, so the knobs don't fan out across every
/// constructor's signature.
struct BuildArgs<'a> {
    config: &'a ScenarioConfig,
    seed: u64,
    dedicated_pool_hosts: bool,
    accounts: &'a [(PrincipalAddr, u128)],
    execution_mode: ExecutionMode,
    packages: GenesisPackages,
}

/// The simulation adaptor: a [`Cluster`] over a [`SimulationRunner`].
pub struct SimCluster {
    runner: SimulationRunner,
    /// In-memory metrics, scoped over `run_until` so [`FaultableCluster::metric`]
    /// can read host-emitted counters. The sim is single-threaded, so the
    /// thread-local scoped recorder captures every emission.
    recorder: MemoryRecorder,
}

impl SimCluster {
    /// Build a genesis cluster from `config`, seeded by `seed`, funding no
    /// accounts of its own.
    #[must_use]
    pub fn new(config: &ScenarioConfig, seed: u64) -> Self {
        Self::build(config, seed, &[], false)
    }

    /// Build a genesis cluster with funded accounts, batch-scheduling
    /// ticks serially.
    #[must_use]
    pub fn with_accounts(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
    ) -> Self {
        Self::with_execution_mode(config, seed, accounts, ExecutionMode::Serial)
    }

    /// [`Self::with_accounts`] with an explicit batch scheduling mode —
    /// one side of the serial/parallel A/B.
    #[must_use]
    pub fn with_execution_mode(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        execution_mode: ExecutionMode,
    ) -> Self {
        Self::build_full(&BuildArgs {
            config,
            seed,
            dedicated_pool_hosts: false,
            accounts,
            execution_mode,
            packages: GenesisPackages::protocol(),
        })
    }

    /// [`Self::with_dedicated_pool_hosts`] with funded accounts — the
    /// straddler and halt-recovery scenarios, whose legs are transfers
    /// over a byte skew the genesis ballast shapes.
    /// [`Self::with_accounts`] over a network born running `packages`,
    /// with the config's reshape trigger armed from genesis — the shape a
    /// scenario that reaches a fixture and drives its own split wants.
    #[must_use]
    pub fn with_packages(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        packages: GenesisPackages,
    ) -> Self {
        Self::build_full(&BuildArgs {
            config,
            seed,
            dedicated_pool_hosts: false,
            accounts,
            execution_mode: ExecutionMode::Serial,
            packages,
        })
    }

    /// [`Self::with_packages`] with every pool extra on its own host, so
    /// the committees a split seats share no host — what a fault rule
    /// keyed on committee hosts needs to cut one shard's traffic and no
    /// other's.
    #[must_use]
    pub fn with_packages_on_dedicated_pool_hosts(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        packages: GenesisPackages,
    ) -> Self {
        Self::build_full(&BuildArgs {
            config,
            seed,
            dedicated_pool_hosts: true,
            accounts,
            execution_mode: ExecutionMode::Serial,
            packages,
        })
    }

    #[must_use]
    pub fn with_accounts_and_dedicated_pool_hosts(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
    ) -> Self {
        Self::build(config, seed, accounts, true)
    }

    /// Build a genesis cluster giving each pool extra its own shard-less
    /// follower host rather than riding a committee host. This is a sim-only
    /// layout the shuffle-relocation tests (`vnode_relocation`, `pool_reseat`)
    /// need: a rotated vnode must move onto a host not already serving the
    /// destination shard, so every committee host stays single-shard. Portable
    /// scenarios never need it — they express host packing through
    /// `vnodes_per_host` alone.
    #[must_use]
    pub fn with_dedicated_pool_hosts(config: &ScenarioConfig, seed: u64) -> Self {
        Self::build(config, seed, &[], true)
    }

    fn build(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        dedicated_pool_hosts: bool,
    ) -> Self {
        Self::build_full(&BuildArgs {
            config,
            seed,
            dedicated_pool_hosts,
            accounts,
            execution_mode: ExecutionMode::Serial,
            packages: GenesisPackages::protocol(),
        })
    }

    fn build_full(args: &BuildArgs<'_>) -> Self {
        let config = args.config;
        let beacon_chain_config = BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            shard_size: config.shard_size,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: config.split_bytes,
            },
            ..BeaconChainConfig::default()
        };
        let sim_config = SimConfig {
            shard_size: config.shard_size,
            vnodes_per_host: config.vnodes_per_host,
            pool_surplus: config.pool_surplus,
            dedicated_pool_hosts: args.dedicated_pool_hosts,
            beacon_chain_config: Some(beacon_chain_config),
            intra_shard_latency: config.latency,
            cross_shard_latency: config.latency,
            // Every cluster funds the pool operator and seats the pools,
            // because the founding pool's vote is how any cluster retunes
            // a network parameter — the same reason the statics register
            // every pool rather than only the ones a scenario delegates
            // to.
            accounts: args
                .accounts
                .iter()
                .copied()
                .chain(staking_genesis_accounts())
                .collect(),
            execution_mode: args.execution_mode,
            packages: args.packages.clone(),
            pools: world_pools(),
            ..SimConfig::default()
        };
        let mut runner = SimulationRunner::new(&sim_config, args.seed);
        runner.initialize_genesis();

        Self {
            runner,
            recorder: MemoryRecorder::new(),
        }
    }

    /// Build a cluster grown to `config.num_shards` with `config.split_bytes`
    /// as the live reshape threshold, with `accounts` funded at the
    /// single ROOT genesis so the grow splits their cells to their prefix
    /// shards.
    ///
    /// Genesis is always a single ROOT shard, so a scenario that needs a
    /// deeper partition reaches it the only way the network does — by
    /// splitting into it, here via [`grow_to`]. Production grows to the
    /// same starting point the same way, so the scenario body is identical
    /// on both harnesses.
    ///
    /// # Panics
    ///
    /// Panics if the grow or the threshold activation misses its budget.
    #[must_use]
    pub fn with_grown_accounts(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
    ) -> Self {
        Self::with_grown_packages(config, seed, accounts, GenesisPackages::protocol())
    }

    /// [`Self::with_grown_accounts`] over a network born running
    /// `packages` — how a scenario reaching a fixture asks for it.
    #[must_use]
    pub fn with_grown_packages(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        packages: GenesisPackages,
    ) -> Self {
        Self::grown(config, seed, accounts, packages, false)
    }

    /// [`Self::with_grown_packages`] with every pool extra on its own
    /// host, so the committees the grow seats share no host — what a
    /// fault rule keyed on committee hosts needs to cut one shard's
    /// traffic and no other's.
    #[must_use]
    pub fn with_grown_packages_on_dedicated_pool_hosts(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        packages: GenesisPackages,
    ) -> Self {
        Self::grown(config, seed, accounts, packages, true)
    }

    fn grown(
        config: &ScenarioConfig,
        seed: u64,
        accounts: &[(PrincipalAddr, u128)],
        packages: GenesisPackages,
        dedicated_pool_hosts: bool,
    ) -> Self {
        let grow_config = ScenarioConfig {
            split_bytes: 0,
            ..*config
        };
        let mut cluster = Self::build_full(&BuildArgs {
            config: &grow_config,
            seed,
            dedicated_pool_hosts,
            accounts,
            execution_mode: ExecutionMode::Serial,
            packages,
        });
        grow_to(&mut cluster, config.num_shards);
        vote_reshape_threshold(&mut cluster, config.split_bytes);
        cluster
    }

    /// Fail the scenario at a beacon park itself: if the committed tip
    /// lags wall-clock epochs beyond [`MAX_BEACON_LAG_EPOCHS`], panic now
    /// rather than letting a distant downstream assert report the symptom
    /// twenty virtual epochs later.
    fn assert_beacon_cadence(&self) {
        let expected = u64::try_from(self.runner.now().as_millis()).unwrap_or(u64::MAX) / EPOCH_MS;
        let actual = self
            .beacon_state()
            .map_or(0, |state| state.current_epoch.inner());
        assert!(
            expected.saturating_sub(actual) <= MAX_BEACON_LAG_EPOCHS,
            "beacon parked: committed epoch {actual} lags wall-clock epoch {expected} \
             beyond the {MAX_BEACON_LAG_EPOCHS}-epoch cadence bound",
        );
    }

    /// The underlying runner, for bespoke sim tests that compose a portable
    /// scenario and then assert white-box internals the [`Cluster`] surface
    /// doesn't expose (raw stores, committed blocks, validator placement).
    #[must_use]
    pub const fn runner(&self) -> &SimulationRunner {
        &self.runner
    }

    /// The underlying runner for the white-box *mutations* the [`Cluster`]
    /// surface deliberately doesn't model — network faults, vnode lifecycle,
    /// system actions, host-targeted or delayed submission.
    pub const fn runner_mut(&mut self) -> &mut SimulationRunner {
        &mut self.runner
    }

    /// Run a fault `scenario` with the in-memory recorder scoped, so
    /// [`FaultableCluster::metric`] reads host-emitted counters. The sim is
    /// single-threaded, so the thread-local scoped recorder captures every
    /// emission. Steady-state scenarios that read no metrics call the scenario
    /// directly instead.
    pub fn run_faultable<R>(&mut self, scenario: impl FnOnce(&mut Self) -> R) -> R {
        let recorder: Arc<dyn MetricsRecorder> = Arc::new(self.recorder.clone());
        with_scoped_recorder(recorder, || scenario(self))
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
            .filter(|&host| {
                self.runner
                    .vnode_state_in(host, shard)
                    .is_some_and(|vnode| committee.contains(&vnode.validator_id()))
            })
            .collect()
    }

    /// The block `host` committed at `height` on `shard`, if it holds
    /// one there.
    ///
    /// Per-host rather than per-shard: comparing two replicas is the
    /// point, and comparing them at one height is what makes the answer
    /// mean anything.
    #[must_use]
    pub fn host_block(
        &self,
        host: usize,
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<Verified<CertifiedBlock>> {
        self.runner
            .hosts_shard(host_index(host), shard)
            .and_then(|storage| storage.get_block(height))
    }

    /// Restart `host`'s replica of `shard`: tear the shard loop down and
    /// seat every member it carried again on the storage it kept.
    ///
    /// What a process restart leaves behind. The committed chain
    /// survives on disk; everything consensus and execution held in
    /// memory — tick assignments, tick outputs, absorbed provisions —
    /// does not, and has to come back out of committed content.
    ///
    /// Sim-only, and deliberately not on [`FaultableCluster`]: that trait
    /// is the intersection of what both harnesses can do, and bouncing a
    /// real node process is a larger commitment than this needs.
    ///
    /// # Panics
    ///
    /// Panics if `host` does not serve `shard`, or if the rejoin does not
    /// take the retained-storage path — a snap-sync there would be a
    /// different test entirely.
    /// Make `host` answer requests of `type_id` with what `rewrite`
    /// returns, given the request's bytes and the answer it was about to
    /// send.
    ///
    /// The byzantine seam, and sim-only for the same reason
    /// [`Self::restart_host`] is: the portable surface is the
    /// intersection of what both harnesses do, and a host that answers
    /// wrongly is a transport the libp2p gate has no hook for. A drop
    /// rule can only make a responder silent, which every fetch path has
    /// a fallback for; what an evidence check is exercised by is a
    /// well-formed answer that says the wrong thing.
    pub fn rewrite_responses(
        &mut self,
        host: usize,
        type_id: &'static str,
        rewrite: Rewrite,
    ) -> FaultHandle {
        let handle =
            self.runner
                .network_mut()
                .rewrite_responses(host_index(host), type_id, rewrite);
        FaultHandle::new(move || handle.fired())
    }

    pub fn restart_host(&mut self, host: usize, shard: ShardId) {
        let kind = self.runner.restart_shard(host_index(host), shard);
        assert!(
            matches!(kind, JoinKind::Retained { .. }),
            "a restart resumes the store it kept, not a fresh sync; got {kind:?}",
        );
    }

    /// The host a submission of `tx` enters at: a member of the payer
    /// shard's live committee, else of any touched shard's.
    ///
    /// The live committee rather than any host carrying the shard: a
    /// member a recovery or a rotation replaced keeps its loop until the
    /// placement scan retires it, and a submission queued at one runs
    /// after the teardown on a host that serves nothing — dropped, not
    /// delayed. A client routes to the committee the beacon names, and
    /// so does this.
    fn host_for_tx(&self, tx: &Transaction) -> Option<NodeIndex> {
        let topology_snapshot = self.runner.host_topology(0)?;
        // Built by the harness rather than by a node, so nothing has
        // derived it yet and routing is a derived fact.
        tx.try_derived(self.runner.host_derivation(0)?.as_ref())
            .ok()?;
        submission_shards(&topology_snapshot, tx)
            .into_iter()
            .find_map(|shard| self.live_committee_hosts(shard).first().copied())
    }
}

/// A portable `0..host_count` host index as the sim's [`NodeIndex`].
fn host_index(host: usize) -> NodeIndex {
    NodeIndex::try_from(host).expect("host index fits a NodeIndex")
}

impl Cluster for SimCluster {
    fn derivation(&self) -> Arc<dyn Derivation> {
        self.runner
            .host_derivation(0)
            .expect("a cluster runs at least one host")
    }

    fn signer_from_seed(&self, seed: &[u8; 32]) -> Arc<dyn Signer> {
        self.runner.signer_from_seed(seed)
    }

    fn submit(&mut self, tx: Arc<Transaction>) {
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
            self.runner.topology_step();
            let next = (self.runner.now() + SLICE).min(deadline);
            self.runner.run_until(next);
            self.assert_beacon_cadence();
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
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .map(ShardChainReader::committed_height)
            .max()
    }

    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        // Read the live committee's copy: a grow-then-merge leaves the reformed
        // shard's pre-merge chain hosted under the same id, and only the
        // reformed copy carries the beacon-composed root the scenarios assert.
        self.live_committee_hosts(shard)
            .into_iter()
            .find_map(|host| self.runner.hosts_shard(host, shard))
            .map(SubstateStore::state_root)
    }

    fn serves_shard(&self, shard: ShardId) -> bool {
        !self.live_committee_hosts(shard).is_empty()
    }

    fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.beacon_storage(host))
            .filter_map(|storage| storage.latest_committed())
            .max_by_key(|(_, state)| state.current_epoch)
            .map(|(_, state)| state)
    }

    fn substate(&self, shard: ShardId, owner: Address, local: [u8; 16]) -> Option<Vec<u8>> {
        // The furthest-along store among the live committee's hosts. A
        // shard id can be hosted twice on one host across a reshape — a
        // merged parent reclaims its predecessor's id, a recovered shard
        // reseats members that hold the frozen store — and only the live
        // one has committed past the cut.
        let store = self
            .live_committee_hosts(shard)
            .into_iter()
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .max_by_key(|store| store.jmt_height())?;
        let height = store.jmt_height();
        let key = SubstateKey {
            owner,
            local: LocalKey(local),
        };
        store.get_substate_at_height(key, height)?
    }

    fn preview(
        &self,
        shard: ShardId,
        tx: &Transaction,
        grants: PreviewGrants,
    ) -> Option<PreviewReport> {
        let store = self
            .live_committee_hosts(shard)
            .into_iter()
            .find_map(|host| self.runner.hosts_shard(host, shard))?;
        // The chain's own freshest attested values stand in for the
        // environment a committing block would fix. The epoch the grid
        // resolves is one sample, not a prediction: which block will
        // commit the transaction, and so which epoch a seal it writes
        // records, is not yet decided.
        let tip = store.get_certified_header(store.committed_height())?;
        let snapshot = store.snapshot();
        let topology = self.runner.host_topology(0)?;
        let windows = self.beacon_state()?.chain_config.epoch_windows();
        Some(self.runner.engine().preview(
            &snapshot,
            tx,
            &PreviewInputs {
                clock: tip.qc().weighted_timestamp(),
                env: TickEnvironment::governing(&topology, windows),
                grants,
            },
        ))
    }

    fn events(&self, shard: ShardId, tx: TxHash) -> Option<Vec<Event>> {
        let store =
            (0..self.runner.num_hosts()).find_map(|host| self.runner.hosts_shard(host, shard))?;
        match store.get_consensus_receipt(&tx)?.as_ref() {
            ConsensusReceipt::Succeeded { events, .. } => Some(events.clone()),
            ConsensusReceipt::Failed => Some(Vec::new()),
        }
    }

    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus> {
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.tx_status(host, &tx))
            .max_by_key(status_rank)
    }

    fn chain_origin_anchor(&self, shard: ShardId) -> Option<WeightedTimestamp> {
        // By tallest chain, not by first host: a terminated predecessor's
        // store can still answer for a shard id its successor has since
        // reclaimed, and that store's origin is the one the successor
        // replaced.
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .max_by_key(|store| ShardChainReader::committed_height(*store))
            .map(|store| store.load_recovered_state().chain_origin.anchor_wt)
    }

    fn committed_work_in_flight(&self, shard: ShardId) -> Option<WorkInFlight> {
        // Tallest chain, for the same reason the origin above reads it:
        // a terminated predecessor's store still answers for the shard id.
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .max_by_key(|store| ShardChainReader::committed_height(*store))
            .and_then(|store| store.get_certified_header(store.committed_height()))
            .map(|header| header.header().work_in_flight())
    }

    fn ran(&self, shard: ShardId, tx: TxHash) -> Vec<RanAs> {
        // Across every store of the shard, not the first: a member seated at
        // runtime snap-synced to an anchor and holds no block below it, so
        // its chain alone says nothing about what committed before it.
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .map(|store| chain_membership(store, tx))
            .find(|ran| !ran.is_empty())
            .unwrap_or_default()
    }

    fn named_unsettled(&self, shard: ShardId, tx: TxHash) -> Vec<(BlockHeight, ShardId)> {
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .map(|store| records_naming(store, tx))
            .find(|named| !named.is_empty())
            .unwrap_or_default()
    }

    fn chain_fate(
        &self,
        shard: ShardId,
        tx: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    ) {
        // Merged across every store of the shard, since a runtime seat's
        // chain starts at its snap-sync anchor; the chains agree wherever
        // they overlap.
        (0..self.runner.num_hosts())
            .filter_map(|host| self.runner.hosts_shard(host, shard))
            .map(|store| chain_fate(store, tx))
            .fold((None, None), |(committed, finalized), (c, f)| {
                (committed.or(c), finalized.or(f))
            })
    }
}

impl FaultableCluster for SimCluster {
    fn host_count(&self) -> usize {
        self.runner.num_hosts() as usize
    }

    fn drop_type(&mut self, type_id: &'static str) -> FaultHandle {
        // The sim's global engine consults every `(sender, recipient)` edge, so
        // one `Any`-sender rule covers every host.
        let handle = self
            .runner
            .network_mut()
            .fault()
            .drop_type(type_id)
            .install();
        FaultHandle::new(move || handle.fired())
    }

    fn drop_type_with_probability(
        &mut self,
        type_id: &'static str,
        probability: f64,
    ) -> FaultHandle {
        let handle = self
            .runner
            .network_mut()
            .fault()
            .drop_type_with_probability(type_id, probability)
            .install();
        FaultHandle::new(move || handle.fired())
    }

    fn partition(&mut self, group_a: &[usize], group_b: &[usize]) {
        let a: Vec<NodeIndex> = group_a.iter().map(|&h| host_index(h)).collect();
        let b: Vec<NodeIndex> = group_b.iter().map(|&h| host_index(h)).collect();
        self.runner.network_mut().partition_groups(&a, &b);
    }

    fn isolate(&mut self, host: usize) {
        self.runner.network_mut().isolate_node(host_index(host));
    }

    fn heal_between(&mut self, a: usize, b: usize) {
        self.runner
            .network_mut()
            .heal_bidirectional(host_index(a), host_index(b));
    }

    fn heal_all(&mut self) {
        self.runner.network_mut().heal_all();
    }

    fn clear_drops(&mut self) {
        self.runner.network_mut().fault().clear();
    }

    fn drop_type_between(
        &mut self,
        from: &[usize],
        to: &[usize],
        type_id: &'static str,
    ) -> FaultHandle {
        let mut handles = Vec::new();
        for &src in from {
            for &dst in to {
                if src == dst {
                    continue;
                }
                handles.push(
                    self.runner
                        .network_mut()
                        .fault()
                        .drop_type(type_id)
                        .from(HostId(host_index(src)))
                        .to(HostId(host_index(dst)))
                        .install(),
                );
            }
        }
        FaultHandle::new(move || handles.iter().map(RuleHandle::fired).sum())
    }

    fn committee_hosts(&self, shard: ShardId) -> Vec<usize> {
        self.live_committee_hosts(shard)
            .into_iter()
            .map(|host| host as usize)
            .collect()
    }

    fn host_committed_height(&self, host: usize, shard: ShardId) -> Option<BlockHeight> {
        self.runner
            .hosts_shard(host_index(host), shard)
            .map(ShardChainReader::committed_height)
    }

    fn host_committed_state_root(&self, host: usize, shard: ShardId) -> Option<StateRoot> {
        self.runner
            .hosts_shard(host_index(host), shard)
            .map(SubstateStore::state_root)
    }

    fn metric(&self, name: &'static str, label: Option<&str>) -> u64 {
        self.recorder.counter(name, label)
    }
}
