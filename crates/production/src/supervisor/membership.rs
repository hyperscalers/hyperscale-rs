//! The supervisor's membership half: bring shards up and tear them down
//! against the committed beacon placement.
//!
//! A join opens storage off the loop, snap-syncs a fresh store against the
//! beacon-attested anchor, and seats the shard's vnodes on a new pinned
//! thread; a leave refcounts memberships down and tears the thread, maps,
//! and storage down at zero. The reconcile pair is the committed-state
//! backstop: [`ShardSupervisor::reconcile_joins`] brings up any shard a
//! local validator is committed to that a lost delta never joined, and
//! [`ShardSupervisor::reconcile_teardown`] retires a shard once no local
//! validator holds a consensus or routing role in it.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::{SeatVnodeGroup, VnodeInit, seat_vnode_group};
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::{
    Block, BlockHeight, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
};
use tracing::{info, warn};

use super::{ShardSupervisor, ShardThread, SupervisorEvent};
use crate::bootstrap::bootstrap_shard_state;
use crate::runner::{ShardChannels, VnodeConfig, consensus_clock, spawn_shard_loop};

/// A finished snap-sync bootstrap, ready for the supervisor to seat:
/// the imported storage verified against the attested anchor, plus the
/// recovered state the shard's state machines boot from.
pub struct CompletedBootstrap {
    shard: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
}

impl ShardSupervisor {
    /// Bring up `shard`: open its storage off this loop, then continue
    /// in [`Self::on_opened`] — seat directly for a retained store or a
    /// genesis replay, or snap-sync against the beacon-attested anchor
    /// first. A join for a shard still tearing down queues and replays
    /// once the teardown finishes.
    pub(super) fn join(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.shards.contains_key(&shard) || self.bootstrapping.contains_key(&shard) {
            warn!(shard = ?shard, "Join rejected: shard already hosted or bootstrapping");
            return;
        }
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != shard) {
            warn!(shard = ?shard, "Join rejected: vnodes must be non-empty and target the shard");
            return;
        }
        if self.draining.contains(&shard) {
            info!(shard = ?shard, "Join queued behind the shard's in-flight teardown");
            if self.pending_joins.insert(shard, vnodes.to_vec()).is_some() {
                warn!(shard = ?shard, "Replaced an earlier queued join for the shard");
            }
            return;
        }

        // A reshape duty owns seating this shard — a merge's keepers
        // reforming the parent, or a split's children, surfaced as an ordinary
        // join when the reshape executes. The orchestrator seats them from the
        // prepared store (which carries the reshape's terminal/merged state),
        // so the placement-delta join is a no-op here. The four conditions span
        // the duty's whole lifetime so the join never opens a `RocksDB`
        // directory the duty is using — `RocksDB`'s exclusive lock fails the
        // second opener outright, so an overlap strands a co-hosted committee
        // member's seat. `is_seating` reads the orchestrator's post-discovery
        // state; `reshape_owns` reads the committed projection, covering the
        // window before discovery runs and while the cohort is still published;
        // `reshape_stores` covers the late window after the beacon marks the
        // successor live (clearing the cohort, so `reshape_owns` lapses) while
        // the duty still holds the opened store between its open and seat; and
        // `pending_reshape_prep` covers a prep parked behind an earlier open.
        if self.reshape.is_seating(shard)
            || self.reshape_owns(shard)
            || self.reshape_stores.contains_key(&shard)
            || self.pending_reshape_prep.contains_key(&shard)
        {
            info!(shard = ?shard, "Join superseded by an active reshape duty; the orchestrator seats it");
            return;
        }

        // The RocksDB open (and a previously-used store's recovery
        // read) can stall on disk; run it off the loop and continue in
        // `on_opened`. The `bootstrapping` entry blocks double joins
        // and lets a `Leave` during the open release memberships.
        self.bootstrapping.insert(shard, vnodes.len());
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = factory(shard).map(|storage| {
                let recovered = storage.load_recovered_state();
                // A brand-new store (no commits, no imported JMT) gets
                // the engine bootstrap before the snap-sync import or
                // the from-genesis replay populates it.
                if recovered.committed_height == BlockHeight::GENESIS {
                    engine_bootstrap.replicate_into(storage.as_ref());
                }
                (storage, recovered)
            });
            // Send failure means the runner is shutting down; the join
            // dies with it.
            let _ = events.send(SupervisorEvent::Opened {
                shard,
                vnodes,
                outcome,
            });
        });
    }

    /// Continue a join whose storage open finished.
    ///
    /// Three paths by what the store and the beacon offer:
    /// - **retained storage** (committed height > 0) — seat directly;
    ///   normal block sync covers the tail;
    /// - **fresh store, attested anchor** — snap-sync bootstrap off
    ///   this loop (a tokio task), seated via [`Self::finish_join`]
    ///   when the import verifies against the anchor;
    /// - **fresh store, no anchor** — seat directly and replay from
    ///   genesis through block sync.
    pub(super) fn on_opened(
        &mut self,
        shard: ShardId,
        mut vnodes: Vec<VnodeConfig>,
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    ) {
        let Some(pending) = self.bootstrapping.get(&shard).copied() else {
            info!(shard = ?shard, "Storage opened for an abandoned join; dropped");
            return;
        };
        let (storage, recovered) = match outcome {
            Ok(opened) => opened,
            Err(error) => {
                self.bootstrapping.remove(&shard);
                warn!(shard = ?shard, error, "Join rejected: storage open failed");
                return;
            }
        };
        // A reshape duty has since claimed this shard — the join slipped past
        // the `reshape_owns` suppression against a stale snapshot and opened the
        // store anyway. Drop it (releasing the `RocksDB` lock) and let the duty
        // seat the shard from its terminal/merged store; any prep held behind
        // this open can now run.
        if self.reshape_owns(shard) {
            self.bootstrapping.remove(&shard);
            drop(storage);
            info!(shard = ?shard, "Join abandoned to its reshape duty after the store opened");
            self.resume_pending_reshape_prep();
            return;
        }
        // Leaves during the open released memberships from the tail.
        vnodes.truncate(pending);

        let fresh_store = recovered.committed_height == BlockHeight::GENESIS;
        let anchor = self.process.topology_snapshot().load().boundary(shard);
        if fresh_store && anchor.is_some() {
            let process = Arc::clone(&self.process);
            let events = self.events_tx.clone();
            self.tokio_handle.spawn(async move {
                let done = match bootstrap_shard_state(
                    process.network(),
                    process.topology_snapshot(),
                    &storage,
                    shard,
                )
                .await
                {
                    Ok(recovered) => Ok(CompletedBootstrap {
                        shard,
                        vnodes,
                        storage,
                        recovered,
                    }),
                    Err(error) => {
                        warn!(shard = ?shard, error, "Shard bootstrap failed; join abandoned");
                        Err(shard)
                    }
                };
                // Send failure means the runner is shutting down; the
                // join dies with it.
                let _ = events.send(SupervisorEvent::Bootstrapped(done));
            });
            return;
        }
        self.bootstrapping.remove(&shard);
        self.seat_shard(shard, &vnodes, storage, &recovered);
    }

    /// Settle a finished bootstrap: seat the shard on success, clear
    /// the bootstrapping entry on failure (so a later placement delta
    /// can retry the join), drop the outcome when every pending vnode
    /// left during the bootstrap. Runs on the runner's loop via the
    /// completion channel — never on the bootstrap task.
    pub(super) fn finish_join(&mut self, done: Result<CompletedBootstrap, ShardId>) {
        let shard = match &done {
            Ok(done) => done.shard,
            Err(shard) => *shard,
        };
        let Some(pending) = self.bootstrapping.remove(&shard) else {
            info!(shard = ?shard, "Bootstrap finished for an abandoned join; dropped");
            return;
        };
        let Ok(done) = done else {
            // Failure already logged by the bootstrap task.
            return;
        };
        if self.shards.contains_key(&shard) {
            warn!(shard = ?shard, "Bootstrap completed for an already-hosted shard; dropped");
            return;
        }
        self.seat_shard(
            shard,
            &done.vnodes[..pending],
            done.storage,
            &done.recovered,
        );
    }

    /// Wire a shard's vnodes into the process maps and spawn its pinned
    /// thread, booting the state machines from `recovered`.
    fn seat_shard(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
    ) {
        self.seat_shard_with_genesis(shard, vnodes, storage, recovered, None);
    }

    /// [`Self::seat_shard`] with an optional pre-spawn genesis install —
    /// a split child's flip commits its derived genesis through the
    /// freshly attached loop before the thread spawns, exactly the
    /// startup runners' network-genesis sequence.
    pub(super) fn seat_shard_with_genesis(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
        genesis: Option<&Block>,
    ) {
        let inits = self.build_vnode_inits(shard, vnodes, recovered);
        let vnode_count = inits.len();
        let (channels, callback_tx) = ShardChannels::new();
        let mut shard_loop = attach_shard(
            &self.process,
            &self.node_config,
            inits,
            SharedStorage::new(Arc::clone(&storage)),
            callback_tx,
        );
        shard_loop.set_time(consensus_clock(self.genesis_offset_ms));
        // The genesis commit arms the pacemaker; capture its timer ops so the
        // spawned loop arms them as its initial ops rather than dropping them.
        let initial_timer_ops =
            genesis.map_or_else(Vec::new, |genesis| shard_loop.install_genesis(genesis));

        self.storages
            .lock()
            .expect("storages lock")
            .insert(shard, storage);

        let shutdown_tx = channels.shutdown_tx.clone();
        let validator_ids = vnodes.iter().map(|v| v.validator_id.inner()).collect();
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                vnode_count,
                validator_ids,
            },
        );
        // A seated validator now drives its beacon from this shard's thread,
        // so retire its pool follower if it had one (it drained here from a
        // prior shard, or started pooled and was just drawn into a committee).
        for cfg in vnodes {
            self.unfollow_in_pool(cfg.validator_id);
        }
        info!(shard = ?shard, vnodes = vnode_count, "Shard joined at runtime");
    }

    /// Release one vnode's membership; tear the shard down at zero. A
    /// leave that lands while the shard's join is still bootstrapping
    /// releases a pending membership instead, abandoning the join when
    /// the last one goes.
    pub(super) fn leave(&mut self, shard: ShardId) {
        if let Some(pending) = self.bootstrapping.get_mut(&shard) {
            *pending -= 1;
            let remaining = *pending;
            if remaining == 0 {
                self.bootstrapping.remove(&shard);
                info!(shard = ?shard, "Last pending vnode left during bootstrap; join abandoned");
            } else {
                info!(
                    shard = ?shard,
                    remaining,
                    "Vnode left during bootstrap; join continues for remaining vnodes"
                );
            }
            return;
        }
        let Some(entry) = self.shards.get_mut(&shard) else {
            warn!(shard = ?shard, "Leave rejected: shard not hosted");
            return;
        };
        entry.vnode_count = entry.vnode_count.saturating_sub(1);
        if entry.vnode_count > 0 {
            info!(
                shard = ?shard,
                remaining = entry.vnode_count,
                "Vnode left; shard stays up for remaining local vnodes"
            );
            return;
        }
        self.tear_down(shard);
    }

    /// Tear a hosted shard's thread down and unwire it off the loop:
    /// signal shutdown, drop the entry, and join the thread off-loop,
    /// finishing the unwire in [`Self::on_torn_down`]. Shared by the
    /// explicit per-vnode [`Self::leave`] at zero count and the
    /// reshape-tick routable-expiry reconcile.
    fn tear_down(&mut self, shard: ShardId) {
        let Some(entry) = self.shards.remove(&shard) else {
            return;
        };
        let _ = entry.shutdown_tx.send(());
        // The thread join waits out an in-flight shard step; run it off
        // the loop and finish the unwire in `on_torn_down`.
        self.draining.insert(shard);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            if entry.join.join().is_err() {
                warn!(shard = ?shard, "Shard thread panicked before teardown");
            }
            // Send failure means the runner is shutting down; the
            // teardown finishes with it.
            let _ = events.send(SupervisorEvent::TornDown {
                shard,
                validator_ids: entry.validator_ids,
            });
        });
    }

    /// Reconcile hosted shards against the committed routing window: tear
    /// down a shard once no local validator holds a consensus role in it
    /// (absent from the active committee) and none sits in its routing
    /// committee (no serve obligation — the shard aged out of the routable
    /// window, or the validator rotated off a still-live shard).
    ///
    /// The active-committee guard keeps a shard up through its current
    /// window even after a lookahead delta moved the validator on in
    /// routing; the routing guard keeps a dissolved shard served for as
    /// long as a fetch can still resolve this host among its peers, so a
    /// merge keeper that does not co-host a merging child can still
    /// snap-sync it. Run on the reshape tick, binding serving and routing
    /// to one committed lifetime in place of a fixed drain grace.
    pub(crate) fn reconcile_teardown(&mut self) {
        let topology_snapshot = self.process.topology_snapshot().load();
        let routing = self.process.network().routing_committees();
        let host_ids: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let expired: Vec<ShardId> = self
            .shards
            .keys()
            .copied()
            .filter(|&shard| shard_retired(shard, &topology_snapshot, &routing, &host_ids))
            .collect();
        for shard in expired {
            info!(
                shard = ?shard,
                "Shard aged out of the routable window; tearing down"
            );
            self.tear_down(shard);
        }
    }

    /// Reconcile hosted shards against the committed committee assignment: bring
    /// up any shard a local validator is a committed member of that this host is
    /// not already hosting, bootstrapping, draining, seating from a reshape
    /// duty, or holding queued behind a drain.
    ///
    /// The membership-up mirror of [`Self::reconcile_teardown`]. The placement
    /// delta still drives a join immediately (it arrives an epoch ahead, so the
    /// bootstrap completes before the window opens); this is the committed-state
    /// backstop for a delta that was never seen — a join that raced a teardown
    /// and lost its queued replay, or work missed across a restart — so a
    /// dropped delta cannot strand the host off a shard it must run. Idempotent:
    /// the guards skip every shard already accounted for, and [`Self::join`]
    /// rejects a double bring-up regardless. Run on the reshape tick.
    pub(crate) fn reconcile_joins(&mut self) {
        let topology_snapshot = self.process.topology_snapshot().load_full();
        let host_ids: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let needed: Vec<ShardId> = topology_snapshot
            .shard_trie()
            .leaves()
            .filter(|&shard| {
                host_assigned(shard, &topology_snapshot, &host_ids)
                    && !self.shards.contains_key(&shard)
                    && !self.bootstrapping.contains_key(&shard)
                    && !self.draining.contains(&shard)
                    && !self.pending_joins.contains_key(&shard)
                    && !self.reshape.is_seating(shard)
                    && !self.reshape_stores.contains_key(&shard)
            })
            .collect();
        for shard in needed {
            let vnodes = self.local_committee_vnodes(&topology_snapshot, shard);
            info!(shard = ?shard, "Reconciling a missed committee join from the committed view");
            self.join(shard, &vnodes);
        }
    }

    /// Finish a teardown whose thread joined: unwire the process maps,
    /// drop the storage handle, scrub the RPC slots, and replay any
    /// join that queued behind the drain.
    pub(super) fn on_torn_down(&mut self, shard: ShardId, validator_ids: &[u64]) {
        let departed: Vec<ValidatorId> = validator_ids
            .iter()
            .map(|&id| ValidatorId::new(id))
            .collect();
        detach_shard(&self.process, shard, &departed);
        self.storages.lock().expect("storages lock").remove(&shard);
        self.scrub_rpc_state(shard, validator_ids);
        self.draining.remove(&shard);
        info!(shard = ?shard, "Shard left and torn down");
        // A departed validator that runs no other shard would go dark — no
        // vnode to fold the beacon and raise its own re-seat trigger. Keep
        // it following in the pool instead; the host's beacon storage stays
        // warm for the eventual re-seat. A relocation that already seated
        // the destination leaves the validator on that shard, so it is not
        // pooled; a race that pools it is undone when the seat lands.
        for &validator in &departed {
            if !self.validator_on_any_shard(validator) {
                self.follow_in_pool(validator);
            }
        }
        if let Some(vnodes) = self.pending_joins.remove(&shard) {
            self.join(shard, &vnodes);
        }
    }

    /// Remove a departed shard's slots from the shared RPC state maps.
    /// Each slot is otherwise written only by the shard's own (now
    /// joined) thread, so a stale entry would persist forever — worst
    /// case a mempool slot frozen at `at_pending_limit: true` vetoing
    /// every RPC submission. A vnode still hosted elsewhere (relocation
    /// overlap) republishes its mempool slot on that shard's next tick.
    fn scrub_rpc_state(&self, shard: ShardId, validator_ids: &[u64]) {
        let shard_key = shard.inner();
        if let Some(ref rpc_status) = self.publishers.node_status {
            rpc_status.rcu(|current| {
                let mut updated = (**current).clone();
                updated.vnodes.retain(|v| v.shard != shard_key);
                Arc::new(updated)
            });
        }
        if let Some(ref sync_status) = self.publishers.sync_status {
            sync_status.rcu(|current| {
                let mut updated = (**current).clone();
                updated.shards.remove(&shard_key);
                Arc::new(updated)
            });
        }
        if let Some(ref mempool_snapshot) = self.publishers.mempool {
            mempool_snapshot.rcu(|current| {
                let mut updated = (**current).clone();
                for id in validator_ids {
                    updated.vnodes.remove(id);
                }
                Arc::new(updated)
            });
        }
    }

    /// One [`VnodeConfig`] per member of `shard`'s committee whose signing
    /// key this host holds — the local vnodes a seat or reconciled join
    /// brings up.
    pub(super) fn local_committee_vnodes(
        &self,
        topology_snapshot: &TopologySnapshot,
        shard: ShardId,
    ) -> Vec<VnodeConfig> {
        topology_snapshot
            .committee_for_shard(shard)
            .iter()
            .filter_map(|validator| {
                self.vnode_keys
                    .get(validator)
                    .map(|signing_key| VnodeConfig {
                        validator_id: *validator,
                        local_shard: shard,
                        signing_key: Arc::clone(signing_key),
                    })
            })
            .collect()
    }

    /// Build one `VnodeInit` per joining vnode via [`seat_vnode_group`],
    /// resuming from the host's committed beacon chain and booting from
    /// `recovered`.
    fn build_vnode_inits(
        &self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        recovered: &RecoveredState,
    ) -> Vec<VnodeInit> {
        seat_vnode_group(SeatVnodeGroup {
            beacon_storage: self.process.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: consensus_clock(self.genesis_offset_ms),
            shard,
            recovered,
            shard_config: &self.shard_config,
            mempool_config: self.mempool_config.clone(),
            provision_config: self.provision_config,
            vnodes: vnodes
                .iter()
                .map(|cfg| (cfg.validator_id, Arc::clone(&cfg.signing_key)))
                .collect(),
        })
    }
}

/// Whether a hosted shard has aged out of this host's serving duty: no
/// local validator holds a consensus role in it (absent from the active
/// committee) and none sits in its routing committee (no serve
/// obligation).
///
/// The active-committee guard keeps a shard up through its current window
/// even after a lookahead delta has moved the validator on in the routing
/// view; the routing guard keeps a dissolved shard served for as long as
/// a fetch can still resolve this host among its peers. Both false means
/// the shard is still wanted — it retires only when neither holds, so
/// serving and routing share the one committed lifetime.
fn shard_retired(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    routing: &RoutingCommittees,
    host_ids: &HashSet<ValidatorId>,
) -> bool {
    let in_routing = routing
        .get(&shard)
        .is_some_and(|committee| committee.iter().any(|v| host_ids.contains(v)));
    // A reshape predecessor mid-handoff stays up even once it ages out of the
    // routable window: under make-before-break its committee keeps coasting and
    // serving its terminal until the successors are live, so they can seed and
    // finalize against it.
    !host_assigned(shard, topology_snapshot, host_ids)
        && !in_routing
        && !topology_snapshot.reshape_handoff_pending(shard)
}

/// Whether `shard`'s committed committee includes a local validator — the host
/// holds a consensus role in it and must run it.
fn host_assigned(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    host_ids: &HashSet<ValidatorId>,
) -> bool {
    topology_snapshot
        .committee_for_shard(shard)
        .iter()
        .any(|v| host_ids.contains(v))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    use hyperscale_types::{
        NetworkDefinition, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
        ValidatorInfo, ValidatorSet, generate_bls_keypair,
    };

    use super::{host_assigned, shard_retired};

    const HOST: ValidatorId = ValidatorId::new(1);

    /// A head snapshot carrying `committees` as each shard's active
    /// membership — a complete sibling set so the trie is well-formed.
    fn head(committees: HashMap<ShardId, Vec<ValidatorId>>) -> TopologySnapshot {
        let ids: BTreeSet<ValidatorId> = committees.values().flatten().copied().collect();
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&validator_id| ValidatorInfo {
                validator_id,
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committees,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )
    }

    fn routing(entries: &[(ShardId, Vec<ValidatorId>)]) -> RoutingCommittees {
        entries.iter().cloned().collect()
    }

    /// A live shard the host rotated off — gone from both its active and
    /// its routing committee — retires.
    #[test]
    fn retires_a_shard_absent_from_active_and_routing() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let others = vec![ValidatorId::new(2), ValidatorId::new(3)];
        let topology_snapshot = head(HashMap::from([
            (shard, others.clone()),
            (sibling, vec![ValidatorId::new(4)]),
        ]));
        let routing = routing(&[(shard, others)]);
        assert!(shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A merge child gone from the head but retained in routing with the
    /// host among its terminal committee stays served — the keeper-fetch
    /// case the fix exists for.
    #[test]
    fn keeps_a_dissolved_shard_the_host_still_routes() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = routing(&[(child, vec![HOST, ValidatorId::new(2)])]);
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The host still sits in the active committee — kept even after the
    /// routing lookahead has moved it on, so the current window is served
    /// to its end.
    #[test]
    fn keeps_a_shard_with_an_active_consensus_role() {
        let shard = ShardId::leaf(1, 0);
        let topology_snapshot = head(HashMap::from([
            (shard, vec![HOST, ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![ValidatorId::new(4)]),
        ]));
        // The lookahead already moved the host off in routing.
        let routing = routing(&[(shard, vec![ValidatorId::new(2), ValidatorId::new(3)])]);
        assert!(!shard_retired(
            shard,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A dissolved shard aged out of routing entirely retires — once its
    /// reshape handoff has completed. Here `leaf(2, 2)` merged into `leaf(1, 1)`,
    /// which is now live (advanced past genesis), so the predecessor is free.
    #[test]
    fn retires_a_shard_evicted_from_routing() {
        let child = ShardId::leaf(2, 2);
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]))
        .with_advanced([ShardId::leaf(1, 1)].into());
        let routing = RoutingCommittees::new();
        assert!(shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A reshape predecessor mid-handoff is held up even once it has aged out of
    /// routing: its successors aren't live yet, so it keeps serving its terminal.
    #[test]
    fn holds_a_reshape_predecessor_until_its_successor_is_live() {
        let child = ShardId::leaf(2, 2);
        // `leaf(2, 2)` merged into `leaf(1, 1)`, which is seated but not yet live.
        let topology_snapshot = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = RoutingCommittees::new();
        assert!(!shard_retired(
            child,
            &topology_snapshot,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The join reconcile targets exactly the committed committees a local
    /// validator belongs to.
    #[test]
    fn host_assigned_tracks_committed_committee_membership() {
        let mine = ShardId::leaf(1, 0);
        let theirs = ShardId::leaf(1, 1);
        let topology_snapshot = head(HashMap::from([
            (mine, vec![HOST, ValidatorId::new(2)]),
            (theirs, vec![ValidatorId::new(3)]),
        ]));
        let host_ids = HashSet::from([HOST]);
        assert!(host_assigned(mine, &topology_snapshot, &host_ids));
        assert!(!host_assigned(theirs, &topology_snapshot, &host_ids));
    }
}
