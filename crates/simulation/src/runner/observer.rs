//! Runtime reshape-observer duty for the simulation harness.
//!
//! The deterministic counterpart of the production runner's observer
//! pipeline: a pooled validator drawn into a pending split's cohort
//! syncs its assigned child's key span out of the splitting shard's
//! attested anchor through the sans-io [`ObserverBootstrap`], served
//! straight from the splitting shard's hosts' storages, then
//! broadcasts its self-signed ready signal to that committee — where
//! it BLS-verifies, pools, drains into a block, classifies as a
//! `ReshapeReady` witness leaf, and folds into the split's readiness
//! gate. Nothing here runs unless a test calls it.

use hyperscale_network::Network;
use hyperscale_node::bootstrap::BootstrapRequest;
use hyperscale_node::bootstrap::observer::{
    ObserverBootstrap, ObserverTail, TailOutcome, observer_ready_signal,
};
use hyperscale_node::{serve_block_request, serve_state_range_request};
use hyperscale_storage::BoundaryStore;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::{ShardAnchor, ShardId, StateRoot, ValidatorId, shard_prefix_path};

use super::SimulationRunner;
use super::relocation::MAX_BOOTSTRAP_ROUNDS;

impl SimulationRunner {
    /// Run `validator`'s observer duty for `child`, the pending child
    /// of splitting shard `via`: bootstrap the child's span from
    /// `via`'s committee hosts into a fresh child-rooted store, then
    /// broadcast the self-signed ready signal to that committee.
    /// Returns the synced store, its imported root — the splitting
    /// shard's subtree node at the child's prefix as of the anchor —
    /// and the anchor the sync verified against, which the follow
    /// resumes from.
    ///
    /// # Panics
    ///
    /// Panics if `via` has no serving host or no attested anchor, or
    /// if the bootstrap cannot complete.
    pub fn observe_child(
        &mut self,
        validator: ValidatorId,
        via: ShardId,
        child: ShardId,
    ) -> (SimShardStorage, StateRoot, ShardAnchor) {
        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| self.hosts[i].hosted_shards().any(|s| s == via))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for shard {via:?} — observer duty needs a live committee",
        );
        let snapshot = self.hosts[serving[0]].process().topology().load_full();
        let anchor = snapshot
            .boundary(via)
            .expect("observer duty requires an attested anchor");

        let storage = SimShardStorage::new(shard_prefix_path(child));
        let mut bootstrap = ObserverBootstrap::new(via, anchor, child);
        let mut peer = 0usize;
        for _ in 0..MAX_BOOTSTRAP_ROUNDS {
            if bootstrap.is_complete() {
                break;
            }
            if let Some((height, leaves)) = bootstrap.take_import() {
                let root = storage
                    .import_boundary_state(height, leaves)
                    .expect("child-span import into a fresh store");
                bootstrap.on_imported(root);
                continue;
            }
            for request in bootstrap.next_requests() {
                let server = &self.hosts[serving[peer % serving.len()]];
                peer += 1;
                let BootstrapRequest::StateRange(id, request) = request else {
                    unreachable!("observer bootstrap emits only state ranges");
                };
                let response = serve_state_range_request(&server.shard_io(via).storage, &request);
                bootstrap.on_state_range(id, &response);
            }
        }
        assert!(
            bootstrap.is_complete(),
            "observer bootstrap for child {child:?} of {via:?} did not complete",
        );
        let root = bootstrap.imported_root().expect("complete bootstrap");

        // Broadcast the ready signal through a committee host's
        // adapter: BLS verification, pool admission, the manifest
        // drain, and the ReshapeReady classification all run the real
        // receive path.
        let signal = observer_ready_signal(
            &self.beacon_network,
            validator,
            &self.signing_keys[usize::try_from(validator.inner()).expect("id fits usize")],
            anchor,
        );
        let recipients: Vec<ValidatorId> = snapshot
            .committee_for_shard(via)
            .iter()
            .copied()
            .filter(|&v| v != validator)
            .collect();
        self.hosts[serving[0]]
            .network()
            .notify(&recipients, &ReadySignalNotification::new(signal));

        (storage, root, anchor)
    }

    /// Run an observer's stay-current duty: follow `via`'s committed
    /// chain above the `anchor` the store synced at, applying each
    /// block's child-prefix writes, until the serving hosts run out of
    /// blocks (the parent terminated, or its tip is reached). Returns
    /// the followed root — the splitting shard's subtree node at the
    /// child's prefix as of the last followed block.
    ///
    /// # Panics
    ///
    /// Panics if `via` has no serving host, or when a served block
    /// fails the follower's chain or self checks — protocol regressions
    /// the calling test should surface loudly.
    pub fn follow_child(
        &mut self,
        storage: &SimShardStorage,
        via: ShardId,
        child: ShardId,
        anchor: ShardAnchor,
        imported_root: StateRoot,
    ) -> StateRoot {
        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| self.hosts[i].hosted_shards().any(|s| s == via))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for shard {via:?} — observer duty needs a live committee",
        );
        let mut tail = ObserverTail::new(anchor, child, imported_root);
        let mut peer = 0usize;
        for _ in 0..MAX_BOOTSTRAP_ROUNDS {
            if let Some((height, receipts)) = tail.take_apply() {
                let root = storage
                    .follow_block_writes(height, &receipts)
                    .expect("follow application onto the synced child store");
                tail.on_applied(root)
                    .expect("followed root matches the carried split child roots");
                continue;
            }
            let Some(request) = tail.next_request() else {
                unreachable!("tail with no pending application always wants a fetch");
            };
            let io = self.hosts[serving[peer % serving.len()]].shard_io(via);
            peer += 1;
            let response =
                serve_block_request(&io.pending_chain, &io.caches.provision_store, &request);
            match tail.on_response(&response) {
                TailOutcome::Accepted => {}
                // The serving hosts hold no block at the next height:
                // the parent chain stopped (or its tip is reached) and
                // the follow is current.
                TailOutcome::NotYetAvailable => return tail.root(),
                TailOutcome::Rejected(reason) => {
                    panic!("follow of {via:?} for {child:?} rejected a served block: {reason}")
                }
            }
        }
        panic!("follow of {via:?} for {child:?} did not reach the parent's tip");
    }
}
