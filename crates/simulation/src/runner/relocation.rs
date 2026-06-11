//! Runtime vnode relocation for the simulation harness.
//!
//! The deterministic counterpart of the production runner's
//! reconfiguration loop: hosted vnodes surface
//! [`ParticipationChange`]s through `StepOutput`, and the harness
//! applies them — a join runs the same sans-io
//! [`ShardBootstrap`] sequencer production pumps (state assembly →
//! import + anchor verification → witness history → recovered state),
//! served straight from the target committee's hosts' storages, then
//! seats the vnode via `NodeHost::add_shard`; a leave tears the shard
//! down via `NodeHost::remove_shard`, handing back a shared storage
//! handle so a later rejoin exercises the retained-storage fast path.
//!
//! Nothing here runs unless a test calls it, so simulations that never
//! relocate are byte-identical to before.

use hyperscale_node::bootstrap::{BootstrapRequest, ShardBootstrap};
use hyperscale_node::{
    SeatVnodeGroup, seat_vnode_group, serve_state_range_request, serve_witness_history_request,
};
use hyperscale_storage::BoundaryStore;
use hyperscale_types::ShardAnchor;

#[allow(clippy::wildcard_imports)] // parent-module split; shares runner.rs's imports
use super::*;

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
    pub fn take_reconfigurations(&mut self) -> Vec<(NodeIndex, ParticipationChange)> {
        std::mem::take(&mut self.pending_reconfigurations)
    }

    /// Begin hosting `shard` for `validator` on `node` at runtime,
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
    /// committee), if the bootstrap cannot complete, or if the imported
    /// root diverges from the anchor.
    pub fn join_shard(
        &mut self,
        node: NodeIndex,
        validator: ValidatorId,
        shard: ShardId,
        storage: SimShardStorage,
    ) -> JoinKind {
        let recovered = storage.load_recovered_state();
        let (recovered, kind) = if recovered.committed_height > BlockHeight::GENESIS {
            let committed_height = recovered.committed_height;
            (recovered, JoinKind::Retained { committed_height })
        } else {
            let snapshot = self.hosts[node as usize].process().topology().load_full();
            let anchor = snapshot
                .boundary(shard)
                .expect("runtime join requires an attested anchor");
            let recovered = self.bootstrap_from_committee(node, shard, anchor, &storage);
            (
                recovered,
                JoinKind::SnapSync {
                    anchor_height: anchor.height,
                },
            )
        };

        let init = self.runtime_vnode_init(node, validator, shard, &recovered);
        self.hosts[node as usize].add_shard(
            vec![init],
            storage,
            self.event_txs[node as usize].clone(),
        );
        kind
    }

    /// The state machine of `node`'s vnode in `shard`, or `None` when
    /// the host doesn't carry that shard. Relocation puts two vnodes
    /// with one validator id on a host (the draining shard's and the
    /// joined shard's), so lookups here are shard-scoped where
    /// `Self::vnode_state`'s validator-id walk would be ambiguous.
    #[must_use]
    pub fn vnode_state_in(&self, node: NodeIndex, shard: ShardId) -> Option<&NodeStateMachine> {
        let host = self.hosts.get(node as usize)?;
        host.hosted_shards()
            .any(|s| s == shard)
            .then(|| host.vnode_state(shard, 0))
    }

    /// Stop hosting `shard` on `node`, returning a shared handle onto
    /// its storage so a later [`Self::join_shard`] can exercise the
    /// retained-storage fast path.
    ///
    /// # Panics
    ///
    /// Panics if `shard` isn't hosted on `node`.
    pub fn leave_shard(&mut self, node: NodeIndex, shard: ShardId) -> SimShardStorage {
        let shard_loop = self.hosts[node as usize]
            .remove_shard(shard)
            .expect("leave of an unhosted shard");
        (*shard_loop.io.storage).clone()
    }

    /// Drive the [`ShardBootstrap`] sequencer to completion against the
    /// shard's serving hosts, importing into `storage`, and return the
    /// recovered state the joining vnode boots from. Requests rotate
    /// across the serving hosts; a rejected chunk simply re-arms and
    /// the rotation retries it elsewhere.
    fn bootstrap_from_committee(
        &self,
        node: NodeIndex,
        shard: ShardId,
        anchor: ShardAnchor,
        storage: &SimShardStorage,
    ) -> RecoveredState {
        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| i != node as usize && self.hosts[i].hosted_shards().any(|s| s == shard))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for shard {shard:?} — snap-sync needs a live committee",
        );

        let mut bootstrap = ShardBootstrap::new(shard, anchor);
        let mut peer = 0usize;
        for _ in 0..100_000 {
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
                            serve_state_range_request(&server.shard_io(shard).storage, &request);
                        bootstrap.on_state_range(id, &response);
                    }
                    BootstrapRequest::WitnessHistory(request) => {
                        let response = serve_witness_history_request(
                            &server.shard_io(shard).pending_chain,
                            &request,
                        );
                        bootstrap.on_witness_history(&response);
                    }
                }
            }
        }
        assert!(
            bootstrap.is_complete(),
            "snap-sync bootstrap for shard {shard:?} did not complete",
        );
        bootstrap.into_recovered_state()
    }

    /// Build a runtime joiner's `VnodeInit` via [`seat_vnode_group`] —
    /// the same construction the production supervisor runs at seat
    /// time.
    fn runtime_vnode_init(
        &self,
        node: NodeIndex,
        validator: ValidatorId,
        shard: ShardId,
        recovered: &RecoveredState,
    ) -> VnodeInit {
        let host = &self.hosts[node as usize];
        let now = LocalTimestamp::from_millis(u64::try_from(self.now.as_millis()).unwrap_or(0));
        let signing_key = Arc::clone(
            &self.signing_keys[usize::try_from(validator.inner()).expect("id fits usize")],
        );
        seat_vnode_group(SeatVnodeGroup {
            beacon_storage: host.beacon_storage().as_ref(),
            proposal_pool: Arc::clone(host.process().beacon_proposal_pool()),
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
