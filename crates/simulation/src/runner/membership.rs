//! The harness's membership half: bring shards up and tear them down
//! against the committed beacon placement.
//!
//! Hosted vnodes surface [`ParticipationChange`]s through `StepOutput`;
//! the committed projection drives the actual joins and leaves — a join
//! runs the same sans-io [`ShardBootstrap`] sequencer production drives
//! (state assembly → import + anchor verification → witness history →
//! recovered state), served straight from the target committee's hosts'
//! storages, then seats the vnode via `NodeHost::add_shard`; a leave
//! tears the shard down via `NodeHost::remove_shard`, handing back a
//! shared storage handle so a later rejoin exercises the
//! retained-storage fast path.
//!
//! The join half reads the seatable committee view (split-observer riders
//! excluded); the teardown half reads full membership — the same
//! asymmetry as the production supervisor's reconcile pair.
//!
//! Nothing here runs unless a test calls it, so simulations that never
//! reconcile membership are byte-identical to before.

use std::sync::Arc;

use hyperscale_core::ParticipationChange;
use hyperscale_engine::GenesisConfig;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::bootstrap::{BootstrapRequest, ShardBootstrap, replicate_engine_bootstrap};
use hyperscale_node::{
    SeatFollower, SeatVnodeGroup, VnodeInit, seat_follower, seat_vnode_group,
    serve_state_range_request, serve_witness_history_request,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BoundaryStore, RecoveredState};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{BlockHeight, ShardAnchor, ShardId, ValidatorId, shard_prefix_path};

use super::SimulationRunner;

/// Drive cap for the snap-sync pump — generous over the dozens of
/// rounds a small-state bootstrap takes, so exhaustion means a wedge.
pub(super) const MAX_BOOTSTRAP_ROUNDS: usize = 100_000;

/// Which join path [`SimulationRunner::join_shard`] took. Mirrors the
/// production supervisor's branching on the store's recovered state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    /// Fresh store, bootstrapped via snap-sync against the attested
    /// anchor; tail block sync continues from `anchor_height + 1`.
    SnapSync {
        /// The beacon-attested boundary the import verified against.
        anchor_height: BlockHeight,
    },
    /// Retained store resumed in place — no snap-sync; tail block sync
    /// continues from the retained tip.
    Retained {
        /// The retained store's committed tip at rejoin.
        committed_height: BlockHeight,
    },
}

impl SimulationRunner {
    /// Drain the placement deltas hosted vnodes emitted since the last
    /// call, in deterministic event order.
    pub fn take_participation_changes(&mut self) -> Vec<(NodeIndex, ParticipationChange)> {
        std::mem::take(&mut self.pending_participation_changes)
    }

    /// Begin hosting `shard` for `validator` on `host` at runtime,
    /// bootstrapping `storage` exactly the way the production
    /// supervisor would: a retained store (committed past genesis)
    /// seats directly, a fresh store snap-syncs against the
    /// beacon-attested anchor through the [`ShardBootstrap`] sequencer,
    /// served from the shard's current committee hosts.
    ///
    /// # Panics
    ///
    /// Panics if the shard has no attested anchor or no serving host
    /// (the simulation models neither genesis replay nor a fully dark
    /// committee), or if the imported root diverges from the anchor.
    pub fn join_shard(
        &mut self,
        host: NodeIndex,
        validator: ValidatorId,
        shard: ShardId,
        storage: SimShardStorage,
    ) -> JoinKind {
        self.seat_joined_group(host, shard, &[validator], storage)
    }

    /// Seat a group of this host's committee members onto `shard` from one
    /// `storage`: a retained store (committed past genesis) resumes in place, a
    /// fresh store snap-syncs against the beacon-attested anchor through the
    /// [`ShardBootstrap`] sequencer, served from the shard's current committee.
    /// Every member shares the one store and one bootstrap, mirroring the
    /// production supervisor seating a whole committee group at once. A snap-sync
    /// whose attested anchor has gone stale leaves the group unseated; the
    /// placement scan retries it next slice.
    ///
    /// # Panics
    ///
    /// Panics if a fresh store has no attested anchor or no serving host, or if
    /// the imported root diverges from the anchor.
    fn seat_joined_group(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        validators: &[ValidatorId],
        storage: SimShardStorage,
    ) -> JoinKind {
        let recovered = storage.load_recovered_state();
        let (recovered, kind) = if recovered.committed_height > BlockHeight::GENESIS {
            let committed_height = recovered.committed_height;
            (recovered, JoinKind::Retained { committed_height })
        } else {
            let snapshot = self.hosts[host as usize]
                .process()
                .topology_snapshot()
                .load_full();
            let anchor = snapshot
                .boundary(shard)
                .expect("runtime join requires an attested anchor");
            // A fresh store needs the engine bootstrap (system packages, the
            // intent-hash tracker) before the snap-sync import, exactly as the
            // reshape duty and the production supervisor seed a fresh store —
            // the authenticated span import overwrites only the prefix subtree.
            replicate_engine_bootstrap(
                &storage,
                &self.beacon_network,
                &GenesisConfig::test_default(),
            );
            let Some(recovered) = self.bootstrap_from_committee(host, shard, anchor, &storage)
            else {
                // The attested anchor's state has aged out of the serving
                // committee — a transient fold freeze. Defer the seat; the
                // placement scan retries next slice against the advanced anchor.
                return JoinKind::SnapSync {
                    anchor_height: anchor.height,
                };
            };
            (
                recovered,
                JoinKind::SnapSync {
                    anchor_height: anchor.height,
                },
            )
        };

        let inits: Vec<VnodeInit> = validators
            .iter()
            .map(|&validator| self.runtime_vnode_init(host, validator, shard, &recovered))
            .collect();
        self.hosts[host as usize].add_shard(inits, storage, self.event_txs[host as usize].clone());
        // Parity with the production supervisor's `unfollow_in_pool`: each
        // seated validator now drives its beacon from this shard, so retire any
        // pool follower it carried (it drained here earlier).
        for &validator in validators {
            self.hosts[host as usize].drop_pooled_vnode(validator);
        }
        // Resume consensus from the recovered committed state, as the
        // production supervisor does pre-spawn: this arms the pacemaker and
        // cleanup timers, so a committee seated onto a quiet chain (a halt
        // recovery's fresh committee) still enters consensus.
        let output = self.hosts[host as usize].resume_shard_committed(shard, &recovered);
        self.process_step_output(host, output);
        self.drain_host_io(host);
        kind
    }

    /// Reconcile this host's physical shard membership against the committed
    /// beacon placement — the deterministic counterpart of the production
    /// supervisor's reconcile pair (`reconcile_joins` /
    /// `reconcile_teardown`). Seats every live leaf the host holds a committed
    /// `OnShard` placement on but isn't running, and tears down every leaf it
    /// runs but no longer holds a placement on (a committee rotation moved its
    /// members off). A shard a reshape duty owns (`is_seating`) is left to the
    /// orchestrator. Idempotent; safe to call every slice.
    ///
    /// Placement is read from the seatable committee view — full membership
    /// minus split-observer riders — the same view the production supervisor's
    /// join half reads. An observer rides the networking committee for
    /// serving, gossip, and ready-signal admission but must not be seated as
    /// a consensus member. A terminated parent is an internal
    /// trie host, not a leaf, so it is never torn down here — it stays retained
    /// for serving. The placement deltas the hosted vnodes emit are drained for
    /// parity with production's delta-driven path, but the committed projection
    /// drives the actual join/leave: the snap-sync usually completes within the
    /// slice, and a join whose attested anchor has gone stale (a transient fold
    /// freeze evicted its state) simply defers to a later slice, the same way
    /// production's async bootstrap retries against the advanced anchor.
    pub fn reconcile_placement(&mut self) {
        let _ = self.take_participation_changes();
        for host in 0..self.num_hosts() {
            // Committee membership only changes at an epoch boundary, so skip the
            // reconciliation scan until this host's committed epoch advances.
            let Some(epoch) = self
                .beacon_storage(host)
                .and_then(|storage| storage.latest_committed_epoch())
            else {
                continue;
            };
            if self.placement_epoch[host as usize] == Some(epoch) {
                continue;
            }
            self.placement_epoch[host as usize] = Some(epoch);

            let Some(snapshot) = self.host_topology(host) else {
                continue;
            };
            let routing = self.hosts[host as usize]
                .process()
                .network()
                .routing_committees();
            let leaves: Vec<ShardId> = snapshot.shard_trie().leaves().collect();
            let hosted: Vec<ShardId> = self.hosted_shards_of(host);

            for &shard in &leaves {
                if hosted.contains(&shard) || self.reshape[host as usize].is_seating(shard) {
                    continue;
                }
                let placed: Vec<ValidatorId> = snapshot
                    .seatable_committee_for_shard(shard)
                    .filter(|&validator| self.homes_validator(host, validator))
                    .collect();
                if !placed.is_empty() {
                    let storage = self
                        .retained_storages
                        .remove(&(host, shard))
                        .unwrap_or_else(|| SimShardStorage::new(shard_prefix_path(shard)));
                    self.seat_joined_group(host, shard, &placed, storage);
                }
            }

            for &shard in &hosted {
                if self.reshape[host as usize].is_seating(shard) {
                    continue;
                }
                let committee = snapshot.committee_for_shard(shard);
                // A stalled ex-member: the host runs a live shard but the rotated
                // committee no longer carries any of its validators. An empty
                // committee is a terminated chain the host retains for serving,
                // not an ex-member, so it stays. Teardown reads full membership
                // rather than the seatable view: any window role — an observer
                // ride included — keeps the shard up, mirroring the production
                // supervisor's `host_in_committee` rule.
                let ex_member = !committee.is_empty()
                    && !committee
                        .iter()
                        .any(|&validator| self.homes_validator(host, validator));
                // A host the routing view still resolves keeps serving: a
                // halt recovery retains the replaced committee in the
                // shard's routing entry until the shard commits under its
                // fresh one — the members it replaced hold the halted tip
                // the incomers sync from. This is the same projection the
                // production supervisor's retired check reads, so a change
                // to routing retention lands on both harnesses.
                let in_routing = routing.get(&shard).is_some_and(|entry| {
                    entry
                        .iter()
                        .any(|&validator| self.homes_validator(host, validator))
                });
                if ex_member && !in_routing {
                    let storage = self.leave_shard(host, shard);
                    self.retained_storages.insert((host, shard), storage);
                }
            }
        }
    }

    /// Stop hosting `shard` on `host`, returning a shared handle onto
    /// its storage so a later [`Self::join_shard`] can exercise the
    /// retained-storage fast path.
    ///
    /// # Panics
    ///
    /// Panics if `shard` isn't hosted on `host`.
    pub fn leave_shard(&mut self, host: NodeIndex, shard: ShardId) -> SimShardStorage {
        let shard_loop = self.hosts[host as usize]
            .remove_shard(shard)
            .expect("leave of an unhosted shard");
        let departed: Vec<ValidatorId> = shard_loop.vnodes.iter().map(|v| v.validator_id).collect();
        let storage = (**shard_loop.io.storage()).clone();

        // Parity with the production supervisor's `on_torn_down`: a validator
        // that drains off its last shard keeps following the beacon in the
        // pool (its storage stays warm and it raises its own re-seat trigger)
        // rather than going dark. One still on another shard keeps that
        // coordinator and needs no follower.
        let now = self.local_now();
        for validator in departed {
            if self.hosts[host as usize].hosts_validator(validator) {
                continue;
            }
            let signing_key = Arc::clone(
                &self.signing_keys[usize::try_from(validator.inner()).expect("id fits usize")],
            );
            let init = seat_follower(SeatFollower {
                beacon_storage: self.hosts[host as usize].beacon_storage().as_ref(),
                beacon_network: self.beacon_network.clone(),
                beacon_config_hash: self.beacon_config_hash,
                now,
                validator,
                signing_key,
            });
            self.hosts[host as usize].add_pooled_vnode(init);
        }
        storage
    }

    /// Drive the [`ShardBootstrap`] sequencer to completion against the
    /// shard's serving hosts, importing into `storage`, and return the
    /// recovered state the joining vnode boots from. Requests rotate
    /// across the serving hosts; a rejected chunk simply re-arms and
    /// the rotation retries it elsewhere.
    ///
    /// Returns `None` when no serving host still pins the attested
    /// boundary's state — a transient beacon-fold freeze at a reshape
    /// boundary can leave a shard's attested anchor stale while its tip
    /// runs on, so every serving member evicts the anchor's state from its
    /// pin ring before the snap-sync can read it. The caller defers the
    /// seat and retries next slice, when the fold has recovered and the
    /// anchor advanced — the deterministic counterpart of production's
    /// async `bootstrap_shard_state`, which restarts against the advanced
    /// anchor the moment it observes the boundary move.
    fn bootstrap_from_committee(
        &self,
        host: NodeIndex,
        shard: ShardId,
        anchor: ShardAnchor,
        storage: &SimShardStorage,
    ) -> Option<RecoveredState> {
        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| i != host as usize && self.hosts[i].hosted_shards().any(|s| s == shard))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for shard {shard:?} — snap-sync needs a live committee",
        );

        // Defer if the attested anchor's state has aged out of every serving
        // member's pin ring; the join retries against the advanced anchor.
        if !serving.iter().any(|&i| {
            self.hosts[i]
                .shard_io(shard)
                .storage()
                .open_boundary(anchor.height)
                .is_some()
        }) {
            return None;
        }

        let mut bootstrap = ShardBootstrap::new(shard, anchor);
        let mut peer = 0usize;
        for _ in 0..MAX_BOOTSTRAP_ROUNDS {
            if bootstrap.is_complete() {
                break;
            }
            if let Some((height, leaves)) = bootstrap.take_import() {
                let root = storage
                    .import_boundary_state(height, leaves)
                    .expect("boundary import into a fresh store");
                bootstrap
                    .on_imported(root)
                    .expect("imported root matches the attested anchor");
                continue;
            }
            for request in bootstrap.next_requests() {
                let server = &self.hosts[serving[peer % serving.len()]];
                peer += 1;
                match request {
                    BootstrapRequest::StateRange(id, request) => {
                        let response =
                            serve_state_range_request(server.shard_io(shard).storage(), &request);
                        bootstrap.on_state_range(id, &response);
                    }
                    BootstrapRequest::WitnessHistory(request) => {
                        let response = serve_witness_history_request(
                            server.shard_io(shard).pending_chain(),
                            &request,
                        );
                        bootstrap.on_witness_history(&response);
                    }
                }
            }
        }
        assert!(
            bootstrap.is_complete(),
            "snap-sync bootstrap for shard {shard:?} did not complete against a pinned anchor",
        );
        Some(bootstrap.into_recovered_state())
    }

    /// Build a runtime joiner's `VnodeInit` via [`seat_vnode_group`] —
    /// the same construction the production supervisor runs at seat
    /// time.
    pub(super) fn runtime_vnode_init(
        &self,
        host: NodeIndex,
        validator: ValidatorId,
        shard: ShardId,
        recovered: &RecoveredState,
    ) -> VnodeInit {
        let host = &self.hosts[host as usize];
        let now = self.local_now();
        let signing_key = Arc::clone(
            &self.signing_keys[usize::try_from(validator.inner()).expect("id fits usize")],
        );
        seat_vnode_group(SeatVnodeGroup {
            beacon_storage: host.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now,
            shard,
            recovered,
            shard_config: &ShardConsensusConfig::default(),
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
            vnodes: vec![(validator, signing_key)],
        })
        .pop()
        .expect("one vnode in, one init out")
    }
}
