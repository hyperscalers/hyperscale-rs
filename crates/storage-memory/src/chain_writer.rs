//! `ChainWriter` implementation for `SimStorage`.

use std::sync::Arc;

use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    BaseReadCache, ChainWriter, DatabaseUpdates, JmtSnapshot, merge_updates_from_receipts,
};
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, FinalizedWave, QuorumCertificate, StateRoot, StoredReceipt,
};

use crate::core::SimStorage;
use crate::state::apply_updates;

/// Precomputed commit work for a `SimStorage` block commit.
///
/// Contains a `JmtSnapshot` (precomputed merkle tree nodes) plus the
/// merged updates and receipts for substate application at commit time.
pub struct SimPreparedCommit {
    snapshot: JmtSnapshot,
    merged_updates: DatabaseUpdates,
    receipts: Vec<StoredReceipt>,
}

impl ChainWriter for SimStorage {
    type PreparedCommit = SimPreparedCommit;

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot {
        &prepared.snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        // Memory backend already keeps state in-memory — the priors
        // hint is irrelevant to its perf and is ignored.
        _base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Self::PreparedCommit) {
        let receipts: Vec<StoredReceipt> = finalized_waves
            .iter()
            .flat_map(|fw| fw.receipts.iter().cloned())
            .collect();

        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JmtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet.
        if receipts.is_empty() {
            let s = read_or_recover(&self.state);
            let snapshot = noop_jmt_snapshot(
                &s.tree_store,
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            );
            drop(s);
            let prepared = SimPreparedCommit {
                snapshot,
                merged_updates: DatabaseUpdates::default(),
                receipts: vec![],
            };
            return (parent_state_root, prepared);
        }

        // Read lock: compute speculative JMT root.
        let s = read_or_recover(&self.state);

        let parent_version =
            jmt_parent_height(parent_block_height, parent_state_root).map(BlockHeight::inner);

        // Collect per-receipt DatabaseUpdates references — no merge needed.
        let per_receipt_updates: Vec<&DatabaseUpdates> = receipts
            .iter()
            .filter_map(|r| r.consensus.database_updates())
            .collect();

        let (result_root, collected) = if pending_snapshots.is_empty() {
            put_at_version(
                &s.tree_store,
                parent_version,
                block_height.inner(),
                &per_receipt_updates,
                &std::collections::HashMap::new(),
            )
        } else {
            let overlay = OverlayTreeReader::new(&s.tree_store, pending_snapshots);
            put_at_version(
                &overlay,
                parent_version,
                block_height.inner(),
                &per_receipt_updates,
                &std::collections::HashMap::new(),
            )
        };

        let snapshot = JmtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            result_root,
            block_height,
        );

        drop(s); // Release read lock

        // Merge for commit-time substate writes (off the state_root critical path).
        let merged_updates = merge_updates_from_receipts(&receipts);

        let prepared = SimPreparedCommit {
            snapshot,
            merged_updates,
            receipts,
        };

        (result_root, prepared)
    }

    #[allow(clippy::significant_drop_tightening)] // every locked op needs the lock
    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(Self::PreparedCommit, Arc<Block>, Arc<QuorumCertificate>)>,
    ) -> Vec<StateRoot> {
        blocks
            .into_iter()
            .map(|(prepared, block, qc)| {
                let block_height_u64 = prepared.snapshot.new_height.inner();
                let result_root = prepared.snapshot.result_root;

                {
                    let mut s = write_or_recover(&self.state);

                    s.apply_jmt_snapshot(prepared.snapshot);

                    apply_updates(
                        &mut s,
                        &prepared.merged_updates,
                        block_height_u64,
                        /* write_history */ true,
                    );
                }

                let mut c = write_or_recover(&self.consensus);
                for tx in block.transactions().iter() {
                    c.transactions.insert(tx.hash(), tx.as_ref().clone());
                }
                c.blocks.insert(
                    block.height(),
                    CertifiedBlock::new_unchecked((*block).clone().into_sealed(), (*qc).clone()),
                );
                for fw in block.certificates().iter() {
                    let cert = &fw.certificate;
                    let wave_id = cert.wave_id.clone();
                    c.certificates.insert(wave_id.clone(), (**cert).clone());
                    c.wave_certs_by_height
                        .entry(wave_id.block_height)
                        .or_default()
                        .push(wave_id);
                }
                c.insert_receipts(&prepared.receipts);
                for fw in block.certificates().iter() {
                    for ec in &fw.certificate.execution_certificates {
                        let canonical_hash = ec.canonical_hash();
                        c.execution_certs.insert(canonical_hash, (**ec).clone());
                        c.execution_certs_by_height
                            .entry(ec.block_height())
                            .or_default()
                            .push(canonical_hash);
                    }
                }
                c.committed_height = block.height();
                c.committed_hash = Some(block.hash());
                c.committed_qc = Some((*qc).clone());
                c.prune_receipts(block.height());

                result_root
            })
            .collect()
    }

    fn commit_block(&self, block: &Arc<Block>, qc: &Arc<QuorumCertificate>) -> StateRoot {
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts.iter().cloned())
            .collect();
        let merged_updates = merge_updates_from_receipts(&receipts);
        self.commit_block_inner(&merged_updates, block, qc, &receipts)
    }
}

impl SimStorage {
    /// Internal commit path used by `commit_block` (sync blocks without a `PreparedCommit`).
    fn commit_block_inner(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Arc<Block>,
        qc: &Arc<QuorumCertificate>,
        receipts: &[StoredReceipt],
    ) -> StateRoot {
        let block_height = block.height();
        let mut s = write_or_recover(&self.state);

        assert!(
            block_height == s.current_block_height + 1
                || (block_height == BlockHeight::GENESIS
                    && s.current_block_height == BlockHeight::GENESIS),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            s.current_block_height
        );

        // Apply substate writes at this block height.
        apply_updates(
            &mut s,
            merged_updates,
            block_height.inner(),
            /* write_history */ true,
        );

        let parent_version =
            jmt_parent_height(s.current_block_height, s.current_root_hash).map(BlockHeight::inner);

        let (new_root, collected) = put_at_version(
            &s.tree_store,
            parent_version,
            block_height.inner(),
            &[merged_updates],
            &std::collections::HashMap::new(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        // Stale JMT nodes are intentionally NOT deleted here: historical
        // roots must be retained for provision proof generation at past
        // block heights. RocksDB GC handles pruning in production. See
        // also `apply_jmt_snapshot`.

        s.current_block_height = block_height;
        s.current_root_hash = new_root;

        drop(s);

        // Store block + certificate + consensus state atomically.
        {
            let mut c = write_or_recover(&self.consensus);
            for tx in block.transactions().iter() {
                c.transactions.insert(tx.hash(), tx.as_ref().clone());
            }
            c.blocks.insert(
                block.height(),
                CertifiedBlock::new_unchecked((**block).clone().into_sealed(), (**qc).clone()),
            );
            for fw in block.certificates().iter() {
                let cert = &fw.certificate;
                let wave_id = cert.wave_id.clone();
                c.certificates.insert(wave_id.clone(), (**cert).clone());
                c.wave_certs_by_height
                    .entry(wave_id.block_height)
                    .or_default()
                    .push(wave_id);
            }
            // Store receipts atomically with block commit.
            c.insert_receipts(receipts);
            // Store execution certificates (extracted from wave certs) atomically.
            for fw in block.certificates().iter() {
                for ec in &fw.certificate.execution_certificates {
                    let canonical_hash = ec.canonical_hash();
                    c.execution_certs.insert(canonical_hash, (**ec).clone());
                    c.execution_certs_by_height
                        .entry(ec.block_height())
                        .or_default()
                        .push(canonical_hash);
                }
            }
            c.committed_height = block.height();
            c.committed_hash = Some(block.hash());
            c.committed_qc = Some((**qc).clone());
            c.prune_receipts(block.height());
        }

        new_root
    }
}
