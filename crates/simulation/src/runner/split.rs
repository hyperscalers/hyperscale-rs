//! The split-child genesis flip, simulation side.
//!
//! Mirrors the production supervisor's adoption paths over the memory
//! backend: a parent-half member deep-clones its parent store
//! ([`SimShardStorage::clone_for_split_child`]); an observer reuses the
//! store its duty synced. Both adopt the child subtree, derive the
//! deterministic genesis from the parent chain's terminal pair via
//! [`split_genesis_from_terminal`], verify it against the beacon's
//! child anchor, seat the vnode, and commit the genesis through the
//! normal pipeline — the startup runners' network-genesis sequence.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::bootstrap::split_flip::split_genesis_from_terminal;
use hyperscale_node::shard_loop::ShardEvent;
use hyperscale_storage::{RecoveredState, ShardChainReader};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    CertifiedBlock, ShardId, StateRoot, ValidatorId, Verified, shard_prefix_path,
};

use super::SimulationRunner;

impl SimulationRunner {
    /// Flip a pre-staffed member onto the freshly split `child` of
    /// `parent`, seating the vnode on `node`'s host.
    ///
    /// `observer_store` carries an observer's synced child store; `None`
    /// takes the parent-half path, deep-cloning the parent store hosted
    /// on `node`. Returns the adopted child state root.
    ///
    /// # Panics
    ///
    /// Panics when the beacon's child anchor hasn't seeded yet, when no
    /// host carries the parent's terminated chain, or when the adoption
    /// doesn't reconstruct the beacon-anchored genesis — each a protocol
    /// regression the calling test should surface loudly.
    pub fn flip_split_child(
        &mut self,
        node: NodeIndex,
        validator: ValidatorId,
        parent: ShardId,
        child: ShardId,
        observer_store: Option<SimShardStorage>,
    ) -> StateRoot {
        let snapshot = self.hosts[node as usize].process().topology().load_full();
        let anchor = snapshot
            .boundary(child)
            .expect("flip requires the beacon-seeded child anchor");

        // The parent chain's terminal pair, read from any host still
        // carrying the terminated parent.
        let parent_host = (0..self.hosts.len())
            .find(|&i| self.hosts[i].hosted_shards().any(|s| s == parent))
            .expect("a host still carries the terminated parent");
        let parent_storage = &self.hosts[parent_host].shard_io(parent).storage;
        let coast = parent_storage
            .get_block(anchor.height)
            .expect("parent chain committed its coast block");
        let terminal_height = anchor
            .height
            .prev()
            .expect("child anchor sits above the height floor");
        let terminal = parent_storage
            .get_block(terminal_height)
            .expect("parent chain holds its terminal block");
        let (genesis, origin) = split_genesis_from_terminal(
            child,
            terminal.block().header(),
            coast.block().header(),
            &anchor,
        )
        .expect("terminal pair derives the beacon-anchored genesis");

        let (storage, adopted) = observer_store.map_or_else(
            || {
                let storage = parent_storage.clone_for_split_child(shard_prefix_path(child));
                let adopted = storage
                    .adopt_split_child(origin)
                    .expect("child subtree adoption");
                (storage, adopted)
            },
            |storage| {
                let adopted = storage
                    .adopt_followed_child(origin)
                    .expect("followed child store adoption");
                (storage, adopted)
            },
        );
        assert_eq!(
            adopted, anchor.state_root,
            "adopted subtree root must match the beacon anchor",
        );

        let recovered = RecoveredState {
            substate_count: storage
                .substate_count_at_version(origin.genesis_height.inner())
                .unwrap_or(0),
            chain_origin: origin,
            ..RecoveredState::default()
        };
        let init = self.runtime_vnode_init(node, validator, child, &recovered);
        // The hosting-mode formula doesn't cover runtime seating —
        // observers land on hosts of the harness's choosing — so the
        // network learns the validator's host explicitly.
        self.network.bind_validator(validator, node);
        self.hosts[node as usize].add_shard(
            vec![init],
            storage,
            self.event_txs[node as usize].clone(),
        );

        // Commit the genesis through the normal pipeline, exactly the
        // startup runners' sequence.
        self.hosts[node as usize].initialize_shard_genesis(&genesis);
        self.hosts[node as usize].flush_all_batches();
        let output = self.hosts[node as usize].drain_pending_output();
        self.drain_node_io(node);
        self.process_step_output(node, output);
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(genesis));
        self.schedule_event(
            node,
            self.now,
            ShardEvent::protocol(child, ProtocolEvent::BlockCommitted { certified }),
        );
        adopted
    }
}
