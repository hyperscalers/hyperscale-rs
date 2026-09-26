//! `ShardChainWriter` implementation for `SimShardStorage`.

use std::sync::Arc;

use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    ChainWrites, JmtSnapshot, ParentAnchor, ShardChainWriter, SubstateStore, crossing_settlements,
    holds_this_block_at, member_writes, read_frontier_writes, settled_writes_at,
};
use hyperscale_types::{
    BeaconWitnessCommit, BlockHeight, CertifiedBlock, Finalization, PreparedCommit, SettledWrites,
    StateRoot, StoredReceipt, SyncHint, Verifiable, Verified,
};

use super::core::SimShardStorage;
use super::state::apply_writes;

impl ShardChainWriter for SimShardStorage {
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent: ParentAnchor<'_>,
        finalizations: &[Arc<Verifiable<Finalization>>],
        chain: ChainWrites<'_>,
        block_height: BlockHeight,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit) {
        let ChainWrites {
            creations,
            removals,
            frontier,
            state_claims,
            members,
        } = chain;
        // Everything the ticks carried, for storage; only what they
        // decided reaches state.
        let receipts: Vec<StoredReceipt> = finalizations
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        // The chain's own protocol families: the read frontier and tick
        // membership, each read off the parent state it advances.
        let mut frontier = read_frontier_writes(parent.state, frontier);
        frontier.extend(member_writes(parent.state, members));
        // What the claims settle against the parent state, read once
        // for the no-op test below; the fold reads it again beside the
        // receipts, whose writes it defers to.
        let settled = crossing_settlements(state_claims, &SettledWrites::default(), parent.state);
        // Nothing to write → state root is unchanged. Build a no-op
        // JmtSnapshot directly, avoiding put_at_version which would fail
        // if the parent's tree nodes aren't in the store yet. A block's
        // sweep, its committed cells and its read frontier are writes
        // like any other, so a block that removes, creates or raises
        // something is not one of these however few receipts it carries.
        if receipts.is_empty()
            && creations.is_empty()
            && removals.is_empty()
            && frontier.is_empty()
            && settled.is_empty()
        {
            let s = read_or_recover(&self.state);
            let snapshot = Arc::new(noop_jmt_snapshot(
                &s.tree_store,
                parent.pending,
                parent.state_root,
                parent.height,
                block_height,
            ));
            drop(s);
            let prepared = build_prepared_commit(
                Arc::clone(self),
                Arc::clone(&snapshot),
                SettledWrites::default(),
                Vec::new(),
            );
            return (parent.state_root, snapshot, prepared);
        }

        // Read lock: compute speculative JMT root.
        let s = read_or_recover(&self.state);

        let parent_version =
            jmt_parent_height(parent.height, parent.state_root).map(BlockHeight::inner);

        // One resolution, feeding both the tree and the substate store —
        // they commit the same values or they disagree about state. It
        // happens here rather than per receipt because a receipt says
        // what it moved, and two receipts moving one cell compose only
        // once something has said what they moved from.
        // The type says the baseline was fixed when it was made; which
        // block it was fixed at is this caller's to check, and a movement
        // resolved against any other is as wrong as one resolved live.
        let settled = settled_writes_at(
            finalizations,
            parent.state,
            parent.height,
            creations,
            removals,
            frontier,
            state_claims,
        );

        let (result_root, collected) = if parent.pending.is_empty() {
            put_at_version(
                &s.tree_store,
                parent_version,
                block_height.inner(),
                &settled,
            )
        } else {
            let overlay = OverlayTreeReader::new(&s.tree_store, parent.pending);
            put_at_version(&overlay, parent_version, block_height.inner(), &settled)
        };

        let snapshot = Arc::new(JmtSnapshot::from_collected_writes(
            collected,
            settled.clone(),
            parent.state_root,
            parent.height,
            result_root,
            block_height,
        ));

        drop(s); // Release read lock

        let prepared =
            build_prepared_commit(Arc::clone(self), Arc::clone(&snapshot), settled, receipts);

        (result_root, snapshot, prepared)
    }
}

/// Build the closure that performs the in-memory atomic block commit.
///
/// Captures the storage handle, the JMT snapshot, the merged updates,
/// and the receipts. At invocation time the closure receives the
/// `Verified<CertifiedBlock>` and witness, applies the snapshot/state/
/// consensus changes, and returns the resulting state root.
#[allow(clippy::significant_drop_tightening)] // state write held across snapshot + substate apply by design
fn build_prepared_commit(
    storage: Arc<SimShardStorage>,
    snapshot: Arc<JmtSnapshot>,
    merged_writes: SettledWrites,
    receipts: Vec<StoredReceipt>,
) -> PreparedCommit {
    Box::new(
        move |_sync_hint: SyncHint,
              certified: &Arc<Verified<CertifiedBlock>>,
              witness: &BeaconWitnessCommit|
              -> StateRoot {
            let result_root = snapshot.result_root;
            // A block already committed — by a sync commit that landed
            // it between prepare and flush, or by a second vnode on this
            // store — is in, and applying it again would write its
            // history twice at one version. The tree's own version says
            // so, as it does on the persistent backend: a chain adopted
            // from a checkpoint carries a committed height above its
            // first blocks, and the tree starts where the chain does.
            if storage.jmt_height() >= snapshot.new_height {
                assert!(
                    holds_this_block_at(
                        storage.as_ref(),
                        certified.block().height(),
                        certified.block().hash(),
                    ),
                    "BFT CRITICAL: prepared commit for height {} meets a different block already there",
                    certified.block().height().inner(),
                );
                return result_root;
            }
            storage.append_beacon_witnesses(witness);

            let block_height_u64 = snapshot.new_height.inner();

            let block = certified.block();
            let qc = certified.qc_verified();

            let floor = {
                let mut s = write_or_recover(&storage.state);
                s.apply_jmt_snapshot(&snapshot);
                apply_writes(
                    &mut s,
                    &merged_writes,
                    block_height_u64,
                    /* write_history */ true,
                );
                s.advance_retention_floor(block_height_u64, qc.weighted_timestamp())
            };

            // SAFETY: synthetic in-memory commit wrapper; the certified
            // value is already verified upstream and we're just copying
            // its inner shape into the consensus map.
            let unwrapped = CertifiedBlock::new_unchecked(block.clone().into_sealed(), qc.clone());

            let mut c = write_or_recover(&storage.consensus);
            for tx in block.transactions().iter() {
                c.transactions.insert(tx.hash(), (***tx).clone());
            }
            c.blocks.insert(block.height(), unwrapped);
            let local_shard = block.header().shard_id();
            for fw in block.certificates().iter() {
                let hash = fw.receipt_hash();
                c.certificates.insert(hash, fw.attestation());
                // Only a finalization of this shard's own tick is indexed,
                // and only for its local certificate: a counterpart's
                // certificate riding inside it answers a question nobody
                // asks this shard, and an asker served its own
                // certificate back refuses it as unsolicited and asks
                // again.
                if fw.tick_id().shard_id() != local_shard {
                    continue;
                }
                c.tx_finalizations.extend(
                    fw.local_ec()
                        .tx_outcomes()
                        .iter()
                        .map(|outcome| (outcome.tx_hash(), hash)),
                );
            }
            c.record_provisions(block, floor);
            c.insert_receipts(&receipts);
            c.committed_height = block.height();
            c.committed_hash = Some(block.hash());
            c.committed_qc = Some(qc.as_ref().clone());
            c.prune_receipts(block.height());
            c.drop_voted_blocks_through(block.height());

            result_root
        },
    )
}

impl SimShardStorage {
    /// Fold a block's beacon-witness commit into the in-memory map:
    /// append `witness.leaves` and drop entries below a carried
    /// retention floor.
    fn append_beacon_witnesses(&self, witness: &BeaconWitnessCommit) {
        if witness.leaves.is_empty() && witness.prune_persisted_below.is_none() {
            return;
        }
        let mut c = write_or_recover(&self.consensus);
        if let Some(floor) = witness.prune_persisted_below {
            c.beacon_witnesses = c.beacon_witnesses.split_off(&floor.inner());
        }
        let start = witness.starting_leaf_index.inner();
        for (offset, payload) in witness.leaves.iter().enumerate() {
            c.beacon_witnesses
                .insert(start + offset as u64, payload.clone());
        }
    }
}
