//! Protocol-event passthrough step handlers.
//!
//! `ShardScopedInput::Protocol(_)` is the channel for state-machine events that
//! re-enter `ShardLoop` via `dispatch_event` (continuation-style). Most are pure
//! passthrough — feed the variant straight into the state machine. The
//! exceptions are `BlockPersisted`, which carries `ShardLoop`-side commit
//! pipeline state (`block_commit`, `pending_chain`) that needs updating
//! before the state machine sees the event, and `CommittedStateRestored`,
//! after which the loop derives the chain floor of the store it resumed
//! on.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::{FloorInputs, ShardStorage, chain_floor};
use hyperscale_types::BlockHeight;

use crate::shard::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Update the commit pipeline before forwarding `BlockPersisted` to the
    /// state machine: the persisted height advances `block_commit`'s gate
    /// and `pending_chain`'s pruning watermark, and the event picks up
    /// the authoritative substate byte total from storage so the state
    /// machine's count frontier reconciles even across sync commits.
    pub(in crate::shard) fn handle_block_persisted(&mut self, height: BlockHeight) {
        self.io.block_commit.mark_persisted(height);
        // Drop pending state for blocks now persisted to RocksDB.
        self.io.pending_chain.prune(height);
        self.io.consensus.proposals.prune(height);
        // Evict ticks whose folds the persisted base now fully covers.
        self.hold_execution_baselines(height);
        self.advance_chain_floor();
        // The byte total is written in the same crash-consistent batch as
        // the block's JMT, and `height` is the tip we just persisted, so it
        // is always present. A zero fallback here would silently corrupt the
        // reshape count frontier the state machine reconciles from, so fail
        // loud instead.
        let substate_bytes = self
            .io
            .storage
            .substate_bytes_at(height)
            .expect("the just-persisted height must carry its committed byte total");
        self.dispatch_event(ProtocolEvent::BlockPersisted {
            height,
            substate_bytes,
        });
    }

    /// Hold the tick chain and the store's history at the lowest baseline
    /// any seated vnode's execution still reads, with the base known to
    /// carry `persisted`.
    ///
    /// Every vnode runs each tick itself, so one seated behind its
    /// siblings — a seat admitted mid-chain replaying from where its
    /// restore resumes — needs history they no longer do, and a hold that
    /// followed the furthest of them would retire it.
    pub(in crate::shard) fn hold_execution_baselines(&self, persisted: BlockHeight) {
        let executed = self
            .vnodes
            .iter()
            .map(|vnode| vnode.state.execution_coordinator().baseline_floor())
            .min()
            .unwrap_or(persisted);
        self.io.tick_chain.prune_persisted(persisted, executed);
    }

    /// Feed `CommittedStateRestored` to the state machine, then derive
    /// the chain floor of the store the loop resumed on.
    ///
    /// The floor is the store's record of a derivation only the loop can
    /// make, written after the commit that moved it and synced by none.
    /// A store resumed after a power loss may hold a chain that begins
    /// above the floor it states — one that began at an imported anchor
    /// holds nothing beneath its first block — and every reader of the
    /// floor takes it as where the store's blocks begin. So the loop
    /// derives it as it takes the store, and never leaves a store stating
    /// a prefix it does not hold until its next block persists.
    pub(in crate::shard) fn handle_committed_state_restored(&mut self, event: ProtocolEvent) {
        self.handle_protocol_passthrough(event);
        self.derive_chain_floor();
    }

    /// Move the store's chain floor to what its readers still reach,
    /// once the oldest pin or the attested anchor has moved since it last
    /// did — the binding term moves with them, once an epoch.
    pub(in crate::shard) fn advance_chain_floor(&mut self) {
        let pins = self.floor_pins();
        if self.io.floor_pins == Some(pins) {
            return;
        }
        self.io.floor_pins = Some(pins);
        self.derive_chain_floor();
    }

    /// The oldest pin the store keeps, the attested one included, and
    /// the attested anchor: what the floor's binding term moves with.
    fn floor_pins(&self) -> (Option<BlockHeight>, Option<BlockHeight>) {
        let topology = self.process.topology_snapshot().load();
        let attested = topology.boundary(self.shard).map(|anchor| anchor.height);
        let oldest_pin = [self.io.storage.oldest_pin(), attested]
            .into_iter()
            .flatten()
            .min();
        (oldest_pin, attested)
    }

    /// Derive the store's chain floor from what it holds and move it
    /// there, whatever pins it was last derived at. The floor never moves
    /// down, so deriving it over a store that has gained nothing since
    /// the last derivation changes nothing.
    fn derive_chain_floor(&self) {
        let topology = self.process.topology_snapshot().load();
        let (oldest_pin, attested) = self.floor_pins();
        let Some(vnode) = self.vnodes.first() else {
            return;
        };
        let floor = chain_floor(
            &*self.io.storage,
            FloorInputs {
                origin: vnode.state.shard_coordinator().chain_origin(),
                oldest_pin: attested.and(oldest_pin),
                settled_window_floor: topology.settled_window_floor(self.shard),
            },
        );
        self.io.storage.advance_chain_floor(self.shard, floor);
    }

    /// Default `Protocol(_)` passthrough — fan the event across fetch-binding
    /// drain hooks (so e.g. `TransactionsReceived` clears in-flight tracking)
    /// and feed the variant into the state machine.
    pub(in crate::shard) fn handle_protocol_passthrough(&mut self, event: ProtocolEvent) {
        self.drive_fetch_admission(&event);
        self.dispatch_event(event);
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::{RecoveredState, ShardChainReader, ShardChainWriter};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHash, BlockHeight, ShardAnchor,
        StateRoot, WeightedTimestamp, shard_prefix_path,
    };

    use crate::shard::seated_host::{Fixture, SHARD, loop_of};

    /// A store that began at an imported anchor holds no block beneath
    /// its first, and says so only once its floor is derived. The floor
    /// rides a write no commit syncs, so a machine that loses power
    /// before the next synced commit comes back holding the blocks and
    /// stating no floor. The loop resuming on that store derives the
    /// floor as it takes the store, and does not serve a prefix the
    /// store never held until its next block lands.
    #[test]
    fn a_resumed_loop_derives_the_floor_its_store_lost() {
        let storage = SimShardStorage::new(shard_prefix_path(SHARD));
        for height in 5..=8u64 {
            commit_settled_at(
                &storage,
                &make_test_certified(make_test_block(BlockHeight::new(height))),
                &[],
                &[],
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        let (first, tip) = (BlockHeight::new(5), BlockHeight::new(8));
        storage.advance_chain_floor(SHARD, first);
        assert_eq!(storage.chain_floor(), first);
        storage.lose_unsynced();
        assert_eq!(storage.committed_height(), tip, "every commit was synced");
        assert_eq!(
            storage.chain_floor(),
            BlockHeight::GENESIS,
            "the floor was not, and the store states none",
        );

        let recovered = RecoveredState {
            committed_height: tip,
            ..RecoveredState::default()
        };
        let boundary = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: tip,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        let mut host = Fixture::new().host_over(storage.clone(), tip, boundary);
        let _timers = loop_of(&mut host).resume_committed(&recovered);

        assert_eq!(
            storage.chain_floor(),
            first,
            "the floor sits on the lowest block the store holds",
        );
    }
}
