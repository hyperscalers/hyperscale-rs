//! Process crashes: a host dies whole and comes back on the disk it left.
//!
//! The runner holds a host's disk — every shard store it had open, the
//! ones its placement retired, the ones a reshape was preparing, and its
//! beacon store — so a crash loses exactly what the process held in
//! memory: its shard loops and pool, the jobs its pools had queued, its
//! timers, and what it was waiting on from the network. The restart
//! decides what to seat the way a production process starting on that
//! disk does, through [`plan_seats`] and [`departed_to_serve`]; a
//! validator whose store holds no chain of its own follows the beacon
//! until the placement scan joins it.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::Executor;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::reshape::orchestrator::ReshapeOrchestrator;
use hyperscale_node::startup::{ShardVnodes, boot_routing, departed_to_serve, plan_seats};
use hyperscale_node::{
    NodeHost, SeatConfig, SeatFollower, SeatVnodeGroup, VnodeInit, seat_follower, seat_vnode_group,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconState, LocalTimestamp, ShardId, TopologySnapshot, ValidatorId, shard_prefix_path,
};

use super::{SimulationRunner, WriteCrash};

/// What a crash takes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashKind {
    /// The process dies; every write it completed survives, since the
    /// operating system still holds what had not reached the disk.
    Process,
    /// The machine loses power; each store keeps only what its last
    /// synced write covered.
    Machine,
}
use crate::event_queue::SimEvent;

impl SimulationRunner {
    /// Crash `host` now, as `kind` says, and start its process again
    /// `downtime` later.
    ///
    /// Work its pools had queued and not yet run never happens. While it
    /// is down nothing reaches it and nothing it sent lands.
    ///
    /// # Panics
    ///
    /// Panics if `host` is already down.
    pub fn crash_host(&mut self, host: NodeIndex, kind: CrashKind, downtime: Duration) {
        self.take_down_host(host, kind);
        self.schedule(host, self.now + downtime, SimEvent::Restart);
    }

    /// Crash `host`, as `kind` says, at the storage write it makes after
    /// `writes_before` more, and start its process again `downtime` after
    /// that.
    ///
    /// The write it crashes at does not happen, nor does anything the
    /// work making it would have done after it.
    ///
    /// # Panics
    ///
    /// Panics if `host` is down.
    pub fn crash_at_write(
        &mut self,
        host: NodeIndex,
        writes_before: u64,
        kind: CrashKind,
        downtime: Duration,
    ) {
        assert!(
            self.hosts.is_up(host as usize),
            "only a running host crashes"
        );
        self.write_crashes[host as usize] = Some(WriteCrash {
            writes_before,
            kind,
            downtime,
        });
    }

    /// Lift a crash armed at one of `host`'s writes that has not yet
    /// fired.
    pub fn disarm_write_crash(&mut self, host: NodeIndex) {
        self.write_crashes[host as usize] = None;
    }

    /// Whether `host`'s process is running.
    #[must_use]
    pub fn is_up(&self, host: NodeIndex) -> bool {
        self.hosts.is_up(host as usize)
    }

    /// Crash `host`'s process and start it again at once, with its stores
    /// for `wiped` gone: the disk an operator leaves who deletes a shard's
    /// directory before bringing the process back.
    ///
    /// # Panics
    ///
    /// Panics if `host` is down.
    pub fn bounce_host(&mut self, host: NodeIndex, wiped: &[ShardId]) {
        self.take_down_host(host, CrashKind::Process);
        for &shard in wiped {
            self.retained_storages.remove(&(host, shard));
        }
        self.restart_host(host);
    }

    /// Take `host` down, keeping its disk as `kind` leaves it.
    pub(super) fn take_down_host(&mut self, host: NodeIndex, kind: CrashKind) {
        let i = host as usize;
        self.stats.crashes += 1;
        self.write_crashes[i] = None;
        let (_, shards, _) = self.hosts.take(i).into_parts();
        for (shard, shard_loop) in shards {
            self.retained_storages
                .insert((host, shard), (**shard_loop.io.storage()).clone());
        }
        let preparing: Vec<ShardId> = self
            .reshape_stores
            .keys()
            .filter(|(h, _)| *h == host)
            .map(|(_, shard)| *shard)
            .collect();
        for shard in preparing {
            let prepared = self
                .reshape_stores
                .remove(&(host, shard))
                .expect("listed above");
            self.retained_storages
                .entry((host, shard))
                .or_insert(prepared.storage);
        }
        if kind == CrashKind::Machine {
            // Each store rolls back on its own; the order they do it in
            // reads nothing.
            self.retained_storages
                .iter()
                .filter(|((h, _), _)| *h == host)
                .for_each(|(_, store)| store.lose_unsynced());
            self.beacon_stores[i].lose_unsynced();
        }
        self.event_queue.retain(|key, _| key.node_index != host);
        self.timers
            .retain(|(timer_host, ..), _| *timer_host != host);
        self.batch_wakes[i] = None;
        self.pool_tick_pending[i] = false;
        while self.event_rxs[i].try_recv().is_ok() {}
        if let Some(jobs) = &self.deferred[i] {
            drop(jobs.take());
        }
        self.pending_participation_changes
            .retain(|(changed, _)| *changed != host);
        self.pending_reseats.retain(|(asked, _)| *asked != host);
        self.network.take_down(host);

        self.reshape[i] = ReshapeOrchestrator::new(self.homed_validators(host));
        self.reshape_pending[i].clear();
        self.placement_epoch[i] = None;
    }

    /// Start `host`'s process on the disk its crash left.
    pub(super) fn restart_host(&mut self, host: NodeIndex) {
        let i = host as usize;
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::clone(&self.beacon_stores[i]) as _;
        let (_, beacon_state) = beacon_storage
            .latest_committed()
            .expect("a host's beacon store holds at least its genesis");
        let topology = Arc::new(beacon_state.derive_topology_snapshot(self.beacon_network.clone()));
        let executor = Arc::new(Executor::with_genesis(
            &self.pools,
            &self.packages,
            self.execution_mode,
        ));
        let config = SeatConfig {
            verifier: Arc::clone(&self.verifier),
            derivation: executor.derivation(),
            code: Arc::clone(&executor) as _,
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            shard_config: ShardConsensusConfig::default(),
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
        };
        let now = self.local_now(host);
        let seated = self.seat_from_disk(
            host,
            &beacon_state,
            beacon_storage.as_ref(),
            &topology,
            &config,
            now,
        );

        self.network
            .bring_up(host, seated.storages.keys().copied().collect());
        let dispatch = self.deferred[i]
            .clone()
            .map_or_else(SyncDispatch::new, SyncDispatch::deferred);
        let shard_event_senders = seated
            .storages
            .keys()
            .map(|&shard| (shard, self.event_txs[i].clone()))
            .collect();
        let restarted = NodeHost::new(
            seated.vnodes,
            seated.storages,
            beacon_storage,
            self.beacon_network.clone(),
            Arc::clone(&executor),
            self.network.create_adapter(host),
            dispatch,
            shard_event_senders,
            self.event_txs[i].clone(),
            Arc::new(ArcSwap::from(topology)),
            self.node_config.clone(),
        );
        self.hosts.put(i, restarted);
        if i == 0 {
            self.engine = executor;
        }
        self.hosts[i].set_time(now);
        let output = self.hosts[i].drain_pending_output();
        self.process_step_output(host, output);
        self.hosts[i].register_inbound_handlers();
        for (shard, recovered) in seated.resumed {
            let output = self.hosts[i].resume_shard_committed(shard, &recovered);
            self.process_step_output(host, output);
        }
        self.drain_host_io(host);
    }

    /// What `host` runs on the disk it left, as a production process
    /// starting on it decides: the groups it resumes or serves from a
    /// store, and a follower for every other validator it runs. Stores
    /// it does not open stay on disk.
    fn seat_from_disk(
        &mut self,
        host: NodeIndex,
        beacon_state: &BeaconState,
        beacon_storage: &dyn BeaconStorage,
        topology: &TopologySnapshot,
        config: &SeatConfig,
        now: LocalTimestamp,
    ) -> Seated {
        let mut disk: BTreeMap<ShardId, SimShardStorage> = BTreeMap::new();
        self.retained_storages.retain(|&(h, shard), store| {
            if h == host {
                disk.insert(shard, store.clone());
            }
            h != host
        });
        let local: ShardVnodes = self
            .homed_validators(host)
            .into_iter()
            .map(|validator| (validator, self.signer_of(validator)))
            .collect();
        let routing = boot_routing(beacon_storage, &self.beacon_network, now);
        let plan = plan_seats(
            beacon_state,
            &routing,
            &local,
            |shard| disk.contains_key(&shard),
            |shard| {
                Ok::<_, Infallible>(Arc::new(
                    disk.get(&shard)
                        .cloned()
                        .unwrap_or_else(|| SimShardStorage::new(shard_prefix_path(shard))),
                ))
            },
        )
        .unwrap_or_else(|never| match never {});
        let placed = plan.placed_shards();
        let followers = plan.followers();

        let mut seated = Seated::default();
        for (shard, (store, vnodes)) in plan.resumed {
            disk.remove(&shard);
            seated.restore(config, beacon_storage, now, shard, (*store).clone(), vnodes);
        }
        for (validator, signer) in followers {
            seated.vnodes.push(seat_follower(SeatFollower {
                verifier: Arc::clone(&self.verifier),
                beacon_storage,
                beacon_network: self.beacon_network.clone(),
                beacon_config_hash: self.beacon_config_hash,
                now,
                validator,
                signer,
            }));
        }
        let departed = departed_to_serve(
            &beacon_state.boundaries,
            &placed,
            |shard| disk.contains_key(&shard),
            topology,
            &routing,
            &local,
        );
        for (shard, vnodes) in departed {
            let store = disk.remove(&shard).expect("served only from disk");
            seated.restore(config, beacon_storage, now, shard, store, vnodes);
        }
        for (shard, store) in disk {
            self.retained_storages.insert((host, shard), store);
        }
        seated
    }

    /// The validators whose keys live on `host`.
    fn homed_validators(&self, host: NodeIndex) -> Vec<ValidatorId> {
        self.validator_home
            .iter()
            .enumerate()
            .filter(|&(_, &home)| home == host)
            .map(|(id, _)| ValidatorId::new(u64::try_from(id).expect("id fits u64")))
            .collect()
    }
}

/// What a restarting host runs.
#[derive(Default)]
struct Seated {
    vnodes: Vec<VnodeInit>,
    storages: BTreeMap<ShardId, SimShardStorage>,
    /// The state each store-backed shard resumes from.
    resumed: Vec<(ShardId, RecoveredState)>,
}

impl Seated {
    /// Seat `vnodes`' group on `shard` from what `store` recovers.
    fn restore(
        &mut self,
        config: &SeatConfig,
        beacon_storage: &dyn BeaconStorage,
        now: LocalTimestamp,
        shard: ShardId,
        store: SimShardStorage,
        vnodes: ShardVnodes,
    ) {
        let recovered = store.load_recovered_state(shard);
        self.vnodes.extend(seat_vnode_group(SeatVnodeGroup {
            config: config.clone(),
            beacon_storage,
            now,
            shard,
            recovered: &recovered,
            vnodes,
        }));
        self.storages.insert(shard, store);
        self.resumed.push((shard, recovered));
    }
}
