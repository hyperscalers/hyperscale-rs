//! Protocol-event passthrough step handlers.
//!
//! `ShardScopedInput::Protocol(_)` is the channel for state-machine events that
//! re-enter `ShardLoop` via `dispatch_event` (continuation-style). Most are pure
//! passthrough — feed the variant straight into the state machine. The
//! exceptions are `CommittedStateRestored`, after which the loop derives
//! the chain floor of the store it resumed on, and the
//! `ShardScopedInput::BlockFlushed` step, which updates `ShardLoop`-side
//! commit pipeline state (`block_commit`, `pending_chain`) before the
//! state machine sees the `BlockPersisted` it builds.

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::{AnswerFollow, FloorInputs, ShardStorage, chain_floor};
use hyperscale_types::{BlockHash, BlockHeight, StandingAnswers, shard_prefix_path};

use crate::shard::ShardLoop;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Update the commit pipeline for a flush that wrote through
    /// `height`, then tell the state machine with `BlockPersisted`: the
    /// persisted height advances `block_commit`'s gate and
    /// `pending_chain`'s pruning watermark, and the event carries the
    /// authoritative substate byte total from storage so the state
    /// machine's count frontier reconciles even across sync commits.
    pub(in crate::shard) fn handle_block_flushed(&mut self, height: BlockHeight) {
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
        let standing_answers = self.follow_answers();
        self.dispatch_event(ProtocolEvent::BlockPersisted {
            height,
            substate_bytes,
            standing_answers,
        });
    }

    /// The answers under this shard's prefix at the store's persisted
    /// head, tagged with the height and block they were read at. The
    /// replica follows them whatever its signers, so a signer attached
    /// later votes under the cap at once. The head can stand above the
    /// persist that asks: a flush the drain tail started can land before
    /// its event is handled.
    pub(in crate::shard) fn follow_answers(
        &mut self,
    ) -> Option<(BlockHeight, BlockHash, StandingAnswers)> {
        AnswerFollow::step(
            &mut self.answer_follow,
            &self.io.pending_chain,
            &shard_prefix_path(self.shard),
        )
    }

    /// Hold the tick chain and the store's history at the lowest baseline
    /// the replica's execution still reads, with the base known to carry
    /// `persisted`.
    pub(in crate::shard) fn hold_execution_baselines(&self, persisted: BlockHeight) {
        let executed = self.replica.execution_coordinator().baseline_floor();
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
        let oldest_pin = [self.io.boundary_pins.oldest(), attested]
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
        let floor = chain_floor(
            &*self.io.storage,
            FloorInputs {
                origin: self.replica.shard_coordinator().chain_origin(),
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
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::{
        answer_leaf, commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::{
        AnswerFollow, PendingChain, RecoveredState, ShardChainReader, ShardChainWriter,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        Address, AddressClass, BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHash, BlockHeight,
        ShardAnchor, StandingAnswers, StateRoot, SubstateKey, WeightedTimestamp, shard_prefix_path,
    };
    use hyperscale_vm_effects::Answered;

    use crate::shard::test_host::{Fixture, SHARD, loop_of};

    /// `count` answers under [`SHARD`]'s prefix out of one producer, the
    /// `from`th onward.
    fn answers_from(from: u32, count: u32) -> Vec<(SubstateKey, Vec<u8>)> {
        let producer = Address::new([0x10; 31], AddressClass::Component);
        let consumer = Address::new([0x20; 31], AddressClass::Component);
        (from..from + count)
            .map(|output| answer_leaf(producer, consumer, output, Answered::Taken, 1))
            .collect()
    }

    /// Persist the next block on `storage`, writing `creations`, and
    /// say which block it was.
    fn persist(storage: &SimShardStorage, creations: &[(SubstateKey, Vec<u8>)]) -> BlockHash {
        let block = make_test_block(storage.committed_height().next());
        let hash = block.hash();
        commit_settled_at(
            storage,
            &make_test_certified(block),
            creations,
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        hash
    }

    /// The follow a loop over `storage` keeps.
    struct Following {
        chain: Arc<PendingChain<SimShardStorage>>,
        follow: Option<AnswerFollow>,
    }

    impl Following {
        fn over(storage: &SimShardStorage) -> Self {
            Self {
                chain: Arc::new(PendingChain::new(
                    Arc::new(storage.clone()),
                    BlockHeight::GENESIS,
                )),
                follow: None,
            }
        }

        fn step(&mut self) -> Option<(BlockHeight, BlockHash, StandingAnswers)> {
            AnswerFollow::step(&mut self.follow, &self.chain, &shard_prefix_path(SHARD))
        }
    }

    /// A flush the drain tail started can land before the event of the
    /// one before it is handled. The count the loop carries then is the
    /// one its view read, tagged with that view's height and block, not
    /// with the height of the persist that asked.
    #[test]
    fn a_count_is_tagged_with_the_height_its_view_read() {
        let storage = SimShardStorage::new(shard_prefix_path(SHARD));
        persist(&storage, &answers_from(0, 1));
        let mut follow = Following::over(&storage);
        assert_eq!(follow.step(), None, "the first persist reads whole");

        persist(&storage, &answers_from(1, 2));
        let landed = persist(&storage, &answers_from(3, 4));
        let (height, block, count) = follow.step().expect("the persist of block 2 catches up");
        assert_eq!((height, block), (BlockHeight::new(3), landed));
        assert_eq!(count.total(), 7);
    }

    /// Where the store's journal cannot say what moved since the follow's
    /// cursor, the loop reads whole again and carries no count, and
    /// catches up exactly at the next persist: past the journal's keys,
    /// and on a store restored from an image, whose journal is another
    /// line.
    #[test]
    fn the_follow_reads_whole_again_where_the_journal_cannot_say() {
        let storage = SimShardStorage::new(shard_prefix_path(SHARD));
        persist(&storage, &answers_from(0, 3));
        let image = storage.image();
        let mut follow = Following::over(&storage);
        assert_eq!(follow.step(), None);

        let past = u32::try_from(1usize << 16).expect("fits") + 1;
        persist(&storage, &answers_from(3, past));
        assert_eq!(follow.step(), None, "past the journal's keys");
        persist(&storage, &answers_from(3 + past, 1));
        let (_, _, count) = follow.step().expect("caught up");
        assert_eq!(count.total(), u64::from(3 + past + 1));

        storage.restore(&image);
        persist(&storage, &answers_from(10, 2));
        assert_eq!(follow.step(), None, "another line");
        persist(&storage, &answers_from(20, 1));
        let (height, _, count) = follow.step().expect("caught up");
        assert_eq!((height, count.total()), (BlockHeight::new(3), 6));
    }

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
