//! `ChainWriter` implementation for `SimStorage`.

use crate::core::SimStorage;
use crate::state::apply_updates;

use hyperscale_storage::{ChainWriter, DatabaseUpdates, JmtSnapshot};
use hyperscale_types::{BlockHeight, CertifiedBlock, Hash, ReceiptBundle};
use std::sync::Arc;

/// Precomputed commit work for a SimStorage block commit.
///
/// Contains a `JmtSnapshot` (precomputed merkle tree nodes) plus the
/// merged updates and receipts for substate application at commit time.
pub struct SimPreparedCommit {
    snapshot: JmtSnapshot,
    merged_updates: DatabaseUpdates,
    receipts: Vec<ReceiptBundle>,
}

impl ChainWriter for SimStorage {
    type PreparedCommit = SimPreparedCommit;

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &hyperscale_storage::JmtSnapshot {
        &prepared.snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        parent_block_height: BlockHeight,
        finalized_waves: &[Arc<hyperscale_types::FinalizedWave>],
        block_height: BlockHeight,
        pending_snapshots: &[Arc<hyperscale_storage::JmtSnapshot>],
        // Memory backend already keeps state in-memory — the priors
        // hint is irrelevant to its perf and is ignored.
        _base_reads: Option<&hyperscale_storage::BaseReadCache>,
    ) -> (Hash, Self::PreparedCommit) {
        let receipts: Vec<ReceiptBundle> = finalized_waves
            .iter()
            .flat_map(|fw| fw.receipts.iter().cloned())
            .collect();

        // No receipts → no state changes → state root is unchanged.
        // Build a no-op JmtSnapshot directly, avoiding put_at_version which
        // would fail if the parent's tree nodes aren't in the store yet.
        if receipts.is_empty() {
            let s = self.state.read().unwrap();
            let snapshot = hyperscale_storage::tree::noop_jmt_snapshot(
                &s.tree_store,
                pending_snapshots,
                parent_state_root,
                parent_block_height,
                block_height,
            );
            drop(s);
            let prepared = SimPreparedCommit {
                snapshot,
                merged_updates: Default::default(),
                receipts: vec![],
            };
            return (parent_state_root, prepared);
        }

        // Read lock: compute speculative JMT root.
        let s = self.state.read().unwrap();

        let parent_version =
            hyperscale_storage::tree::jmt_parent_height(parent_block_height, parent_state_root)
                .map(|h| h.0);

        // Collect per-receipt DatabaseUpdates references — no merge needed.
        let per_receipt_updates: Vec<&hyperscale_storage::DatabaseUpdates> = receipts
            .iter()
            .map(|b| &b.local_receipt.database_updates)
            .collect();

        let (result_root, collected) = if pending_snapshots.is_empty() {
            hyperscale_storage::tree::put_at_version(
                &s.tree_store,
                parent_version,
                block_height.0,
                &per_receipt_updates,
                &Default::default(),
            )
        } else {
            let overlay =
                hyperscale_storage::tree::OverlayTreeReader::new(&s.tree_store, pending_snapshots);
            hyperscale_storage::tree::put_at_version(
                &overlay,
                parent_version,
                block_height.0,
                &per_receipt_updates,
                &Default::default(),
            )
        };

        let snapshot = JmtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height.0,
            result_root,
            block_height.0,
        );

        drop(s); // Release read lock

        // Merge for commit-time substate writes (off the state_root critical path).
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(&receipts);

        let prepared = SimPreparedCommit {
            snapshot,
            merged_updates,
            receipts,
        };

        (result_root, prepared)
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(
            Self::PreparedCommit,
            Arc<hyperscale_types::Block>,
            Arc<hyperscale_types::QuorumCertificate>,
        )>,
    ) -> Vec<Hash> {
        blocks
            .into_iter()
            .map(|(prepared, block, qc)| {
                let block_height_u64 = prepared.snapshot.new_version;
                let result_root = prepared.snapshot.result_root;

                {
                    let mut s = self.state.write().unwrap();

                    s.apply_jmt_snapshot(prepared.snapshot);

                    apply_updates(
                        &mut s,
                        &prepared.merged_updates,
                        block_height_u64,
                        /* write_history */ true,
                    );
                }

                let mut c = self.consensus.write().unwrap();
                for tx in block.transactions().iter() {
                    c.transactions.insert(tx.hash(), tx.as_ref().clone());
                }
                c.blocks.insert(
                    block.height(),
                    CertifiedBlock::new_unchecked((*block).clone().into_sealed(), (*qc).clone()),
                );
                for fw in block.certificates() {
                    let cert = &fw.certificate;
                    let wave_id_hash = cert.wave_id.hash();
                    c.certificates.insert(wave_id_hash, (**cert).clone());
                    c.wave_certs_by_height
                        .entry(cert.wave_id.block_height)
                        .or_default()
                        .push(wave_id_hash);
                }
                for bundle in &prepared.receipts {
                    c.local_receipts
                        .insert(bundle.tx_hash, bundle.local_receipt.clone());
                    if let Some(ref exec_output) = bundle.execution_output {
                        c.execution_outputs
                            .insert(bundle.tx_hash, exec_output.clone());
                    }
                }
                for fw in block.certificates() {
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

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
    ) -> Hash {
        let receipts: Vec<ReceiptBundle> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts.iter().cloned())
            .collect();
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(&receipts);
        self.commit_block_inner(&merged_updates, block, qc, &receipts)
    }
}

impl SimStorage {
    /// Internal commit path used by `commit_block` (sync blocks without a PreparedCommit).
    fn commit_block_inner(
        &self,
        merged_updates: &DatabaseUpdates,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
        receipts: &[ReceiptBundle],
    ) -> Hash {
        let block_height = block.height().0;
        let mut s = self.state.write().unwrap();

        assert!(
            block_height == s.current_block_height + 1
                || (block_height == 0 && s.current_block_height == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            s.current_block_height
        );

        // Apply substate writes at this block height.
        apply_updates(
            &mut s,
            merged_updates,
            block_height,
            /* write_history */ true,
        );

        let parent_version = hyperscale_storage::tree::jmt_parent_height(
            BlockHeight(s.current_block_height),
            s.current_root_hash,
        )
        .map(|h| h.0);

        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            &[merged_updates],
            &Default::default(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store
                .insert(key.clone(), std::sync::Arc::clone(node));
        }
        // NOTE: stale JMT nodes are NOT deleted — see apply_jmt_snapshot comment.
        // Historical roots must be retained for provision proof generation at
        // past block heights. RocksDB GC handles pruning in production.

        s.current_block_height = block_height;
        s.current_root_hash = new_root;

        drop(s);

        // Store block + certificate + consensus state atomically.
        {
            let mut c = self.consensus.write().unwrap();
            for tx in block.transactions().iter() {
                c.transactions.insert(tx.hash(), tx.as_ref().clone());
            }
            c.blocks.insert(
                block.height(),
                CertifiedBlock::new_unchecked((**block).clone().into_sealed(), (**qc).clone()),
            );
            for fw in block.certificates() {
                let cert = &fw.certificate;
                let wave_id_hash = cert.wave_id.hash();
                c.certificates.insert(wave_id_hash, (**cert).clone());
                c.wave_certs_by_height
                    .entry(cert.wave_id.block_height)
                    .or_default()
                    .push(wave_id_hash);
            }
            // Store receipts atomically with block commit.
            for bundle in receipts {
                c.local_receipts
                    .insert(bundle.tx_hash, bundle.local_receipt.clone());
                if let Some(ref exec_output) = bundle.execution_output {
                    c.execution_outputs
                        .insert(bundle.tx_hash, exec_output.clone());
                }
            }
            // Store execution certificates (extracted from wave certs) atomically.
            for fw in block.certificates() {
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
