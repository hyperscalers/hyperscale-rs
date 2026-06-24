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
use hyperscale_node::shard::HostEvent;
use hyperscale_storage::{RecoveredState, ShardChainReader};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconState, CertifiedBlock, ShardAnchor, ShardId, StateRoot, ValidatorId, ValidatorStatus,
    Verified, shard_prefix_path,
};

use super::SimulationRunner;

/// One cohort member's synced child store, its imported root, and the anchor
/// the sync verified against.
type SyncedMember = (
    ValidatorId,
    ShardId,
    SimShardStorage,
    ShardAnchor,
    StateRoot,
);

impl SimulationRunner {
    /// Flip every member of one split onto its assigned child: follow each
    /// synced store to the parent's terminal root, seat each parent half
    /// (clone-and-adopt on its own host), then seat each observer on its synced
    /// store. The post-gate `state` says where each pre-split `member` landed.
    ///
    /// With [`NetworkConfig::dedicated_pool_hosts`] every observer seats on its
    /// own dedicated host — kept current by the beacon follower that ran there
    /// since construction — and that follower is dropped once the shard vnode is
    /// seated, so every committee member ends on a single shard. Otherwise an
    /// observer co-hosts on a host whose own vnode flipped to the sibling child.
    ///
    /// # Panics
    ///
    /// Panics if a member did not land `OnShard`, or if no free sibling host is
    /// available for a co-hosted observer.
    ///
    /// [`NetworkConfig::dedicated_pool_hosts`]: hyperscale_network_memory::NetworkConfig::dedicated_pool_hosts
    pub fn flip_all_for(
        &mut self,
        parent: ShardId,
        members: &[ValidatorId],
        synced: Vec<SyncedMember>,
        state: &BeaconState,
    ) {
        let parent_halves: Vec<(ValidatorId, ShardId)> = members
            .iter()
            .map(|member| {
                let ValidatorStatus::OnShard { shard, .. } = state.validators[member].status else {
                    panic!(
                        "parent member {member:?} must land on a child of {parent:?}; got {:?}",
                        state.validators[member].status,
                    )
                };
                (*member, shard)
            })
            .collect();
        for (_, child, store, anchor, imported_root) in &synced {
            self.follow_child(store, parent, *child, *anchor, *imported_root);
        }
        for (member, child) in &parent_halves {
            let node = self.network.validator_to_node(*member);
            self.flip_split_child(node, *member, parent, *child, None);
        }
        let dedicated = self.config.dedicated_pool_hosts;
        let mut sibling_hosts: Vec<NodeIndex> = Vec::new();
        for (validator, child, store, _, _) in synced {
            let node = if dedicated {
                self.network.validator_to_node(validator)
            } else {
                let node = parent_halves
                    .iter()
                    .map(|(member, member_child)| {
                        (self.network.validator_to_node(*member), *member_child)
                    })
                    .find(|(node, member_child)| {
                        *member_child != child && !sibling_hosts.contains(node)
                    })
                    .map(|(node, _)| node)
                    .expect("a free host whose own vnode flipped to the sibling");
                sibling_hosts.push(node);
                node
            };
            self.flip_split_child(node, validator, parent, child, Some(store));
            if dedicated {
                // The seat rebuilt the validator's coordinator from the host's
                // warm beacon storage; retire the now-redundant follower.
                self.hosts[node as usize].drop_pooled_vnode(validator);
            }
        }
    }

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
            terminal.qc_verified(),
            &anchor,
        )
        .expect("certified terminal derives the beacon-anchored genesis");

        let (storage, adopted) = observer_store.map_or_else(
            || {
                let storage = parent_storage.clone_for_split_child(shard_prefix_path(child));
                let adopted = storage
                    .adopt_split_child(origin, &genesis)
                    .expect("child subtree adoption");
                (storage, adopted)
            },
            |storage| {
                let adopted = storage
                    .adopt_followed_child(origin, &genesis)
                    .expect("followed child store adoption");
                (storage, adopted)
            },
        );
        assert_eq!(
            adopted, anchor.state_root,
            "adopted subtree root must match the beacon anchor",
        );

        let recovered = RecoveredState {
            substate_bytes: storage
                .substate_bytes_at_version(origin.genesis_height.inner())
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
            HostEvent::protocol(child, ProtocolEvent::BlockCommitted { certified }),
        );
        adopted
    }
}
