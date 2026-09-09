//! `ShardChainWriter` implementation for `RocksDbShardStorage`.

use std::sync::Arc;

use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    JmtSnapshot, ParentAnchor, ShardChainWriter, SweepRows, settled_writes_at,
};
use hyperscale_types::{
    BeaconWitnessCommit, BlockHeight, CertifiedBlock, Finalization, PreparedCommit, StateRoot,
    StoredReceipt, SubstateKey, SyncHint, Verifiable, Verified,
};
use rocksdb::WriteBatch;

use super::column_families::{ConsensusReceiptsCf, ExecutionMetadataCf};
use super::core::RocksDbShardStorage;
use super::jmt_snapshot_store::SnapshotTreeStore;
use super::receipts::add_receipt_to_batch;
use crate::typed_cf::TypedCf;

impl ShardChainWriter for RocksDbShardStorage {
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent: ParentAnchor<'_>,
        finalizations: &[Arc<Verifiable<Finalization>>],
        creations: &[(SubstateKey, Vec<u8>)],
        removals: &[SubstateKey],
        block_height: BlockHeight,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit) {
        // Everything the ticks carried, for storage; only what they
        // decided reaches state.
        let receipts: Vec<&StoredReceipt> = finalizations
            .iter()
            .flat_map(|fw| fw.receipts().iter())
            .collect();
        // Nothing to write → state root is unchanged. Build a no-op
        // JmtSnapshot directly, avoiding put_at_version which would fail
        // if the parent's tree nodes aren't in the store yet (e.g.,
        // proposer just exited sync and BlockPersisted hasn't fired).
        // A block's sweep and its committed cells are writes like any
        // other, so a block that removes or creates something is not one
        // of these however few receipts it carries.
        if receipts.is_empty() && creations.is_empty() && removals.is_empty() {
            let jmt_snapshot = Arc::new(noop_jmt_snapshot(
                &SnapshotTreeStore::new(&self.db, self.root_path.clone()),
                parent.pending,
                parent.state_root,
                parent.height,
                block_height,
            ));
            let prepared = build_prepared_commit(
                Arc::clone(self),
                WriteBatch::default(),
                SweepRows::default(),
                Arc::clone(&jmt_snapshot),
            );
            return (parent.state_root, jmt_snapshot, prepared);
        }

        let snapshot_store = SnapshotTreeStore::new(&self.db, self.root_path.clone());
        let parent_version =
            jmt_parent_height(parent.height, parent.state_root).map(BlockHeight::inner);

        // Collect per-receipt writes references — no merge needed.
        // State locking guarantees no key conflicts between receipts, so
        // put_at_version can flatten them directly into JMT work items.
        // One resolution, feeding both the tree and the substate batch —
        // they commit the same values or they disagree about state. A
        // receipt says what it moved, and two receipts moving one cell
        // compose only once something has said what they moved from.
        // The type says the baseline was fixed when it was made; which
        // block it was fixed at is this caller's to check, and a movement
        // resolved against any other is as wrong as one resolved live.
        let settled = settled_writes_at(
            finalizations,
            parent.state,
            parent.height,
            creations,
            removals,
        );

        let (computed_root, collected) = if parent.pending.is_empty() {
            put_at_version(
                &snapshot_store,
                parent_version,
                block_height.inner(),
                &settled,
            )
        } else {
            let overlay = OverlayTreeReader::new(&snapshot_store, parent.pending);
            put_at_version(&overlay, parent_version, block_height.inner(), &settled)
        };

        let jmt_snapshot = Arc::new(JmtSnapshot::from_collected_writes(
            collected,
            settled.clone(),
            parent.state_root,
            parent.height,
            computed_root,
            block_height,
        ));

        // Merge writes for the substate WriteBatch (off the state_root critical path).
        // Pre-build substate + receipt writes into a WriteBatch for efficient commit.
        let (mut write_batch, sweep_rows) = self.build_substate_write_batch(
            &settled,
            block_height.inner(),
            /* write_history */ true,
            parent.base_reads,
            parent.pending,
        );

        let cf = self.cf();
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);
        let metadata_cf = ExecutionMetadataCf::handle(&cf);
        for receipt in &receipts {
            add_receipt_to_batch(&mut write_batch, consensus_cf, metadata_cf, receipt);
        }

        let prepared = build_prepared_commit(
            Arc::clone(self),
            write_batch,
            sweep_rows,
            Arc::clone(&jmt_snapshot),
        );

        (computed_root, jmt_snapshot, prepared)
    }
}

/// Build the closure that performs the atomic block commit.
///
/// Captures the storage handle, the pre-built `WriteBatch`, and the JMT
/// snapshot. At invocation time the closure receives the
/// `Verified<CertifiedBlock>` and beacon-witness commit, folds them into
/// the batch, and writes. A store that has already landed this block
/// refuses the batch and the closure answers the root it prepared; a
/// store anywhere else is a divergence and halts.
fn build_prepared_commit(
    storage: Arc<RocksDbShardStorage>,
    write_batch: WriteBatch,
    sweep_rows: SweepRows,
    jmt_snapshot: Arc<JmtSnapshot>,
) -> PreparedCommit {
    Box::new(
        move |sync_hint: SyncHint,
              certified: &Arc<Verified<CertifiedBlock>>,
              witness: &BeaconWitnessCommit|
              -> StateRoot {
            let result_root = jmt_snapshot.result_root;
            let mut write_batch = write_batch;

            let block = certified.block();
            let qc = certified.qc_verified();

            let floor = storage.advance_retention_floor(
                &mut write_batch,
                block.height().inner(),
                qc.weighted_timestamp(),
            );
            storage.append_block_to_batch(
                &mut write_batch,
                block,
                qc,
                witness.leaf_count_at_block_end,
                floor,
            );
            storage.append_beacon_witnesses_to_batch(&mut write_batch, witness);

            // The block's execution certificates and its sweep-index
            // delta append inside `try_apply_prepared_commit`, which
            // holds `commit_lock` across the reads their writes depend
            // on.
            let applied = storage.try_apply_prepared_commit(
                write_batch,
                &sweep_rows,
                &jmt_snapshot,
                block,
                qc,
                sync_hint.is_flush_now(),
            );
            if applied {
                return result_root;
            }

            // The fast path refused: the store advanced since the commit
            // was prepared. A second commit of this very block — a synced
            // copy, or a co-hosted vnode's — is the one benign cause, and
            // the block is then already in.
            // Anything else — the store at a height below this block
            // with a base the prepared batch was not built on — is a
            // divergence between what the chain committed and what this
            // node prepared, and a fresh fold here would commit a root
            // no verifier compared with the header's.
            let _guard = storage.commit_lock.lock().unwrap();
            let (current_version, _) =
                SnapshotTreeStore::new(&storage.db, storage.root_path.clone()).read_jmt_metadata();
            assert!(
                block.height().inner() <= current_version,
                "BFT CRITICAL: prepared commit for height {} refused with the store at {}",
                block.height().inner(),
                current_version,
            );
            tracing::debug!(
                height = block.height().inner(),
                current_version,
                "PreparedCommit stale — block already committed, skipping"
            );
            result_root
        },
    )
}
