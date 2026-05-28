//! `ShardChainWriter` implementation for `SimShardStorage`.

use std::sync::Arc;

use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    BaseReadCache, DatabaseUpdates, JmtSnapshot, ShardChainWriter, merge_updates_from_receipts,
};
use hyperscale_types::{
    BeaconWitnessCommit, Block, BlockHeight, CertifiedBlock, FinalizedWave, PreparedCommit,
    QuorumCertificate, StateRoot, StoredReceipt, SyncHint, Verifiable, Verified,
};

use super::core::SimShardStorage;
use super::state::apply_updates;

impl ShardChainWriter for SimShardStorage {
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<Verifiable<FinalizedWave>>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<JmtSnapshot>],
        // Memory backend already keeps state in-memory — the priors
        // hint is irrelevant to its perf and is ignored.
        _base_reads: Option<&BaseReadCache>,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit) {
        let receipts: Vec<StoredReceipt> = finalized_waves
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();

        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JmtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet.
        if receipts.is_empty() {
            let s = read_or_recover(&self.state);
            let snapshot = Arc::new(noop_jmt_snapshot(
                &s.tree_store,
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            ));
            drop(s);
            let prepared = build_prepared_commit(
                Arc::clone(self),
                Arc::clone(&snapshot),
                DatabaseUpdates::default(),
                Vec::new(),
            );
            return (parent_state_root, snapshot, prepared);
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

        let snapshot = Arc::new(JmtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            result_root,
            block_height,
        ));

        drop(s); // Release read lock

        // Merge for commit-time substate writes (off the state_root critical path).
        let merged_updates = merge_updates_from_receipts(&receipts);

        let prepared = build_prepared_commit(
            Arc::clone(self),
            Arc::clone(&snapshot),
            merged_updates,
            receipts,
        );

        (result_root, snapshot, prepared)
    }

    fn commit_block(
        &self,
        certified: &Arc<Verified<CertifiedBlock>>,
        witness: &BeaconWitnessCommit,
    ) -> StateRoot {
        let block = certified.block();
        let qc = certified.qc_verified();
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        let merged_updates = merge_updates_from_receipts(&receipts);
        self.append_beacon_witnesses(witness);
        self.commit_block_inner(&merged_updates, block, qc, &receipts)
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
    merged_updates: DatabaseUpdates,
    receipts: Vec<StoredReceipt>,
) -> PreparedCommit {
    Box::new(
        move |_sync_hint: SyncHint,
              certified: &Arc<Verified<CertifiedBlock>>,
              witness: &BeaconWitnessCommit|
              -> StateRoot {
            storage.append_beacon_witnesses(witness);

            let block_height_u64 = snapshot.new_height.inner();
            let result_root = snapshot.result_root;
            let snapshot = match Arc::try_unwrap(snapshot) {
                Ok(s) => s,
                Err(arc) => (*arc).clone(),
            };

            {
                let mut s = write_or_recover(&storage.state);
                s.apply_jmt_snapshot(snapshot);
                apply_updates(
                    &mut s,
                    &merged_updates,
                    block_height_u64,
                    /* write_history */ true,
                );
            }

            let block = certified.block();
            let qc = certified.qc_verified();

            // SAFETY: synthetic in-memory commit wrapper; the certified
            // value is already verified upstream and we're just copying
            // its inner shape into the consensus map.
            let unwrapped = CertifiedBlock::new_unchecked(block.clone().into_sealed(), qc.clone());

            let mut c = write_or_recover(&storage.consensus);
            for tx in block.transactions().iter() {
                c.transactions.insert(tx.hash(), (***tx).clone());
            }
            c.blocks.insert(block.height(), unwrapped);
            for fw in block.certificates().iter() {
                let cert = fw.certificate();
                let wave_id = cert.wave_id().clone();
                c.certificates.insert(wave_id.clone(), (**cert).clone());
                c.wave_certs_by_height
                    .entry(wave_id.block_height())
                    .or_default()
                    .push(wave_id);
            }
            c.insert_receipts(&receipts);
            for fw in block.certificates().iter() {
                for ec in fw.certificate().execution_certificates() {
                    c.execution_certs
                        .insert(ec.wave_id().clone(), (**ec).clone());
                }
            }
            c.committed_height = block.height();
            c.committed_hash = Some(block.hash());
            c.committed_qc = Some(qc.as_ref().clone());
            c.prune_receipts(block.height());

            result_root
        },
    )
}

impl SimShardStorage {
    /// Append `witness.leaves` into the in-memory beacon-witness map.
    /// Lives next to the commit paths so both prepared-commit and
    /// from-scratch commits share one entry point.
    fn append_beacon_witnesses(&self, witness: &BeaconWitnessCommit) {
        if witness.leaves.is_empty() {
            return;
        }
        let mut c = write_or_recover(&self.consensus);
        let start = witness.starting_leaf_index.inner();
        for (offset, payload) in witness.leaves.iter().enumerate() {
            c.beacon_witnesses
                .insert(start + offset as u64, payload.clone());
        }
    }
}

impl SimShardStorage {
    /// Internal commit path used by `commit_block` (sync blocks without a `PreparedCommit`).
    fn commit_block_inner(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
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
                c.transactions.insert(tx.hash(), (***tx).clone());
            }
            // SAFETY: sync-path commit; certified value is already
            // verified upstream.
            c.blocks.insert(
                block.height(),
                CertifiedBlock::new_unchecked(block.clone().into_sealed(), qc.clone()),
            );
            for fw in block.certificates().iter() {
                let cert = fw.certificate();
                let wave_id = cert.wave_id().clone();
                c.certificates.insert(wave_id.clone(), (**cert).clone());
                c.wave_certs_by_height
                    .entry(wave_id.block_height())
                    .or_default()
                    .push(wave_id);
            }
            // Store receipts atomically with block commit.
            c.insert_receipts(receipts);
            // Store execution certificates (extracted from wave certs) atomically.
            for fw in block.certificates().iter() {
                for ec in fw.certificate().execution_certificates() {
                    c.execution_certs
                        .insert(ec.wave_id().clone(), (**ec).clone());
                }
            }
            c.committed_height = block.height();
            c.committed_hash = Some(block.hash());
            c.committed_qc = Some(qc.as_ref().clone());
            c.prune_receipts(block.height());
        }

        new_root
    }
}
