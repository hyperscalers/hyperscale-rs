//! The crossing index a shard's execution asks its questions from, read
//! at the chain's persisted tip.

use std::sync::Arc;

use hyperscale_execution::CrossingIndex;
use hyperscale_storage::{PendingChain, ShardStorage, SubstateStore, Substates};
use hyperscale_types::{ShardId, SubstateKey, shard_prefix_path};

/// The persisted index's rows, each point-read at the persisted tip and
/// dropped where it reads absent there.
///
/// A block committed but not yet persisted is not seen: a cell it writes
/// is missed and a cell it removes still reads present until it
/// persists. That costs latency only: nothing an asker returns reaches a
/// block without the voter re-proving it.
pub struct ChainCrossings<S: ShardStorage>(pub Arc<PendingChain<S>>);

impl<S: ShardStorage> CrossingIndex for ChainCrossings<S> {
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        let view = self.0.view_at_persisted_tip();
        let tip = view.snapshot();
        view.base()
            .crossing_rows(&shard_prefix_path(shard))
            .into_iter()
            .filter_map(|key| tip.cell(key).map(|value| (key, value)))
            .collect()
    }

    fn present(&self, key: SubstateKey) -> bool {
        self.0
            .view_at_persisted_tip()
            .snapshot()
            .cell(key)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::{
        ChainEntry, ChainWrites, MemberInputs, ParentAnchor, ShardChainWriter, SubstateStore,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        Address, AddressClass, BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHeight,
        ChainOrigin, FrontierInputs, ResourceAddr, SyncHint,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher, Terms, TxHash};

    use super::*;

    fn record(seed: u8) -> (SubstateKey, Vec<u8>) {
        let id = CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed + 1; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        };
        let cell = id.cell(
            TxHash(Hash32([seed; 32])),
            ResourceAddr::new([0xE0; 31]),
            5,
            9_000,
            Terms::Owed,
        );
        (id.record_key(&ProtocolHasher), cell.to_bytes())
    }

    /// The index reads at the persisted tip: a block committed to the
    /// chain but not yet persisted is not seen, neither the record it
    /// writes nor the one it removes, and both are seen once it
    /// persists.
    #[test]
    fn the_index_sees_a_block_once_it_persists() {
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        let store = SimShardStorage::default();
        let (a, a_bytes) = record(0x41);
        let (b, b_bytes) = record(0x51);
        commit_settled_at(
            &store,
            &make_test_certified(make_test_block(BlockHeight::new(1))),
            &[(a, a_bytes)],
            &[],
            &witness,
        );
        let chain = Arc::new(PendingChain::new(
            Arc::new(store.clone()),
            ChainOrigin::ROOT,
        ));
        let index = ChainCrossings(Arc::clone(&chain));
        let rows = |index: &ChainCrossings<SimShardStorage>| {
            index
                .crossing_rows(ShardId::ROOT)
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>()
        };
        assert!(index.present(a));
        assert_eq!(rows(&index), vec![a]);

        let second = make_test_certified(make_test_block(BlockHeight::new(2)));
        let base = Arc::new(store);
        let (_, jmt_snapshot, commit) = base.prepare_block_commit(
            ParentAnchor {
                state_root: base.state_root(),
                height: BlockHeight::new(1),
                state: &base.snapshot(),
                pending: &[],
                base_reads: None,
            },
            &[],
            ChainWrites {
                creations: &[(b, b_bytes)],
                removals: &[a],
                frontier: &FrontierInputs::still(ShardId::ROOT),
                state_claims: &[],
                members: &MemberInputs::still(ShardId::ROOT),
            },
            BlockHeight::new(2),
        );
        chain.insert(
            second.block().hash(),
            ChainEntry {
                parent_block_hash: second.block().header().parent_block_hash(),
                height: BlockHeight::new(2),
                settled_txs: Vec::new(),
                jmt_snapshot,
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        assert!(
            index.present(a),
            "the removal is not seen before it persists"
        );
        assert!(!index.present(b), "nor the write");
        assert_eq!(rows(&index), vec![a]);

        commit(SyncHint::FlushNow, &second, &witness);
        assert!(!index.present(a));
        assert!(index.present(b));
        assert_eq!(rows(&index), vec![b]);
    }
}
