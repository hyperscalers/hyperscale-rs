//! Runtime reshape-keeper duty and the merged-parent genesis flip,
//! simulation side.
//!
//! The deterministic counterpart of the production supervisor's keeper
//! pipeline. During the grow a keeper proves the sibling-half sync from
//! the sibling's committee and broadcasts its ready signal to its own
//! child's committee, where it BLS-verifies, pools, drains into a block,
//! classifies as a `ReshapeReady` witness leaf, and folds into the merge
//! readiness gate. At the boundary the keeper builds a `parent`-rooted
//! store from both terminated children's halves, derives the
//! deterministic merged genesis from their terminal pair via
//! [`merge_genesis_from_terminals`], verifies it against the beacon's
//! composed parent anchor, seats the vnode, and commits the genesis
//! through the normal pipeline. Nothing here runs unless a test calls
//! it.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_engine::GenesisConfig;
use hyperscale_network::Network;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::bootstrap::merge_flip::merge_genesis_from_terminals;
use hyperscale_node::bootstrap::observer::observer_ready_signal;
use hyperscale_node::bootstrap::{BootstrapRequest, ShardBootstrap, replicate_engine_bootstrap};
use hyperscale_node::shard_loop::ShardEvent;
use hyperscale_node::{serve_state_range_request, serve_witness_history_request};
use hyperscale_storage::{BoundaryStore, ImportLeaf, RecoveredState, ShardChainReader};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::{
    CertifiedBlock, ShardId, StateRoot, ValidatorId, Verified, shard_prefix_path,
};

use super::SimulationRunner;
use super::relocation::MAX_BOOTSTRAP_ROUNDS;

impl SimulationRunner {
    /// Run `validator`'s keeper duty for the pending merge of
    /// `own_child` and its `sibling` under their parent: snap-sync the
    /// sibling half it doesn't run (proving the cross-committee sync),
    /// then broadcast its self-signed ready signal to its own child's
    /// committee.
    ///
    /// # Panics
    ///
    /// Panics if `own_child` or `sibling` has no serving host or attested
    /// anchor, or if the sibling sync cannot complete.
    pub fn merge_keeper(&mut self, validator: ValidatorId, own_child: ShardId, sibling: ShardId) {
        // The grow-phase work: pull the sibling half from its committee.
        let _ = self.collect_shard_leaves(sibling);

        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| self.hosts[i].hosted_shards().any(|s| s == own_child))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for {own_child:?} — keeper duty needs a live committee",
        );
        let snapshot = self.hosts[serving[0]].process().topology().load_full();
        let anchor = snapshot
            .boundary(own_child)
            .expect("keeper duty requires its own child's attested anchor");

        let signal = observer_ready_signal(
            &self.beacon_network,
            validator,
            &self.signing_keys[usize::try_from(validator.inner()).expect("id fits usize")],
            anchor,
        );
        let recipients: Vec<ValidatorId> = snapshot
            .committee_for_shard(own_child)
            .iter()
            .copied()
            .filter(|&v| v != validator)
            .collect();
        self.hosts[serving[0]]
            .network()
            .notify(&recipients, &ReadySignalNotification::new(signal));
    }

    /// Flip a keeper onto the reformed `parent` at the boundary, seating
    /// the vnode on `node`'s host: build a `parent`-rooted store from
    /// both terminated children's halves, derive the deterministic merged
    /// genesis from their terminal pair, adopt it against the beacon's
    /// composed anchor, and commit the genesis through the normal
    /// pipeline. Returns the adopted merged state root.
    ///
    /// # Panics
    ///
    /// Panics if the beacon's parent anchor hasn't composed yet, if a
    /// child's terminal block is missing, or if the adoption doesn't
    /// reconstruct the beacon-composed genesis — each a protocol
    /// regression the calling test should surface loudly.
    pub fn flip_merge_parent(
        &mut self,
        node: NodeIndex,
        validator: ValidatorId,
        parent: ShardId,
    ) -> StateRoot {
        let snapshot = self.hosts[node as usize].process().topology().load_full();
        let anchor = snapshot
            .boundary(parent)
            .expect("flip requires the beacon-composed parent anchor");
        let (left, right) = parent.children();

        let (left_terminal, left_leaves) = self.child_terminal(left);
        let (right_terminal, right_leaves) = self.child_terminal(right);
        let (genesis, origin) = merge_genesis_from_terminals(
            parent,
            (left_terminal.block().header(), left_terminal.qc_verified()),
            (
                right_terminal.block().header(),
                right_terminal.qc_verified(),
            ),
            self.epoch_duration_ms,
            &anchor,
        )
        .expect("certified terminals derive the beacon-composed genesis");

        // Build the merged store: the union of both halves, imported at
        // the genesis version, gives a tree whose root is the stitched
        // `r_p` by construction.
        let storage = SimShardStorage::new(shard_prefix_path(parent));
        replicate_engine_bootstrap(&storage, snapshot.network(), &GenesisConfig::test_default());
        let mut leaves = left_leaves;
        leaves.extend(right_leaves);
        storage
            .import_boundary_state(origin.genesis_height, leaves)
            .expect("merged-half import into a fresh parent store");
        let adopted = storage
            .adopt_merge_parent(origin, &genesis)
            .expect("merged parent store adoption");
        assert_eq!(
            adopted, anchor.state_root,
            "adopted merged root must match the beacon-composed anchor",
        );

        let recovered = RecoveredState {
            substate_count: storage
                .substate_count_at_version(origin.genesis_height.inner())
                .unwrap_or(0),
            chain_origin: origin,
            ..RecoveredState::default()
        };
        let init = self.runtime_vnode_init(node, validator, parent, &recovered);
        self.network.bind_validator(validator, node);
        self.hosts[node as usize].add_shard(
            vec![init],
            storage,
            self.event_txs[node as usize].clone(),
        );

        self.hosts[node as usize].initialize_shard_genesis(&genesis);
        self.hosts[node as usize].flush_all_batches();
        let output = self.hosts[node as usize].drain_pending_output();
        self.drain_node_io(node);
        self.process_step_output(node, output);
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(genesis));
        self.schedule_event(
            node,
            self.now,
            ShardEvent::protocol(parent, ProtocolEvent::BlockCommitted { certified }),
        );
        adopted
    }

    /// The certified terminal block of a terminated `child` — the
    /// crossing block `B` the beacon composed from, which sits one below
    /// the chain's committed tip (the empty coast block that certified it
    /// and stopped the chain) — and the full leaf set of its subtree.
    fn child_terminal(&self, child: ShardId) -> (Verified<CertifiedBlock>, Vec<ImportLeaf>) {
        let host = (0..self.hosts.len())
            .find(|&i| self.hosts[i].hosted_shards().any(|s| s == child))
            .expect("a host still carries the terminated child");
        let storage = &self.hosts[host].shard_io(child).storage;
        let crossing = storage
            .committed_height()
            .prev()
            .expect("a terminated child sits above its genesis");
        let terminal = storage
            .get_block(crossing)
            .expect("the terminated child holds its crossing block");
        let leaves = self.collect_shard_leaves(child);
        (terminal, leaves)
    }

    /// Collect the full leaf set of `shard`'s subtree by snap-syncing its
    /// attested anchor from its committee — the half a keeper folds into
    /// the merged store.
    fn collect_shard_leaves(&self, shard: ShardId) -> Vec<ImportLeaf> {
        let serving: Vec<usize> = (0..self.hosts.len())
            .filter(|&i| self.hosts[i].hosted_shards().any(|s| s == shard))
            .collect();
        assert!(
            !serving.is_empty(),
            "no serving host for {shard:?} — leaf collection needs a live committee",
        );
        let snapshot = self.hosts[serving[0]].process().topology().load_full();
        let anchor = snapshot
            .boundary(shard)
            .expect("leaf collection requires an attested anchor");
        let mut bootstrap = ShardBootstrap::new(shard, anchor);
        let mut peer = 0usize;
        for _ in 0..MAX_BOOTSTRAP_ROUNDS {
            if let Some((_, leaves)) = bootstrap.take_import() {
                return leaves;
            }
            if bootstrap.is_complete() {
                return Vec::new();
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
        panic!("leaf collection for {shard:?} did not complete");
    }
}
