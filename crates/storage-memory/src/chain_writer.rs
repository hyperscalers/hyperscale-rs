//! `ChainWriter` implementation for `SimStorage`.

use crate::core::SimStorage;
use crate::state::apply_updates_to_ordmap;

use hyperscale_storage::{ChainWriter, DatabaseUpdates, JvtSnapshot};
use hyperscale_types::{Hash, ReceiptBundle};
use std::sync::Arc;

/// Precomputed commit work for a SimStorage block commit.
///
/// Contains a `JvtSnapshot` (precomputed verkle tree nodes) plus the
/// merged updates and receipts for substate application at commit time.
pub struct SimPreparedCommit {
    snapshot: JvtSnapshot,
    merged_updates: DatabaseUpdates,
    receipts: Vec<ReceiptBundle>,
}

impl ChainWriter for SimStorage {
    type PreparedCommit = SimPreparedCommit;

    fn jvt_snapshot(prepared: &Self::PreparedCommit) -> &hyperscale_storage::JvtSnapshot {
        &prepared.snapshot
    }

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        parent_block_height: u64,
        receipts: &[ReceiptBundle],
        block_height: u64,
        pending_snapshots: &[Arc<hyperscale_storage::JvtSnapshot>],
    ) -> (Hash, Self::PreparedCommit) {
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(receipts);

        // Read lock: compute speculative JVT root.
        let s = self.state.read().unwrap();

        let parent_version =
            hyperscale_storage::tree::jvt_parent_height(parent_block_height, parent_state_root);

        // Use a layered reader if there are pending snapshots from prior
        // uncommitted verifications. This avoids mutating the shared tree
        // store — orphaned nodes from abandoned blocks (view changes) would
        // corrupt subsequent computations if written directly.
        let (result_root, collected) = if pending_snapshots.is_empty() {
            hyperscale_storage::tree::put_at_version(
                &s.tree_store,
                parent_version,
                block_height,
                &merged_updates,
                &Default::default(),
            )
        } else {
            let overlay =
                hyperscale_storage::tree::OverlayTreeReader::new(&s.tree_store, pending_snapshots);
            hyperscale_storage::tree::put_at_version(
                &overlay,
                parent_version,
                block_height,
                &merged_updates,
                &Default::default(),
            )
        };

        let snapshot = JvtSnapshot::from_collected_writes(
            collected,
            parent_state_root,
            parent_block_height,
            result_root,
            block_height,
        );

        drop(s); // Release read lock

        let prepared = SimPreparedCommit {
            snapshot,
            merged_updates,
            receipts: receipts.to_vec(),
        };

        (result_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
    ) -> Hash {
        let block_height = prepared.snapshot.new_version;
        let result_root = prepared.snapshot.result_root;

        {
            let mut s = self.state.write().unwrap();

            // Always apply the precomputed JVT snapshot — its tree nodes are
            // consensus-verified and correct regardless of tree store state.
            // The overlay may have computed ahead of the tree store.
            s.apply_jvt_snapshot(prepared.snapshot);

            // Apply substate updates to current data + MVCC versioned store.
            {
                let crate::state::SharedState {
                    ref mut data,
                    ref mut versioned_substates,
                    ..
                } = *s;
                apply_updates_to_ordmap(
                    data,
                    &prepared.merged_updates,
                    Some((block_height, versioned_substates)),
                );
            }
        }

        // Store certificates + consensus metadata atomically in consensus lock.
        let mut c = self.consensus.write().unwrap();
        for tx in block.transactions.iter() {
            c.transactions.insert(tx.hash(), tx.as_ref().clone());
        }
        c.blocks
            .insert(block.header.height, ((**block).clone(), (**qc).clone()));
        for cert in &block.certificates {
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
        for wc in &block.certificates {
            for ec in &wc.execution_certificates {
                let canonical_hash = ec.canonical_hash();
                c.execution_certs.insert(canonical_hash, (**ec).clone());
                c.execution_certs_by_height
                    .entry(ec.block_height())
                    .or_default()
                    .push(canonical_hash);
            }
        }
        c.committed_height = block.header.height;
        c.committed_hash = Some(block.hash());
        c.committed_qc = Some((**qc).clone());
        c.prune_receipts(block.header.height.0);

        result_root
    }

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
        receipts: &[ReceiptBundle],
    ) -> Hash {
        let merged_updates = hyperscale_storage::merge_updates_from_receipts(receipts);
        self.commit_block_inner(&merged_updates, block, qc, receipts)
    }

    fn node_cache_len(&self) -> usize {
        0
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
        let block_height = block.header.height.0;
        let mut s = self.state.write().unwrap();

        assert!(
            block_height == s.current_block_height + 1
                || (block_height == 0 && s.current_block_height == 0),
            "commit_block: block_height ({block_height}) must be exactly current_version + 1 ({})",
            s.current_block_height
        );

        // Apply substate writes to OrdMap + MVCC versioned store.
        {
            let crate::state::SharedState {
                ref mut data,
                ref mut versioned_substates,
                ..
            } = *s;
            apply_updates_to_ordmap(
                data,
                merged_updates,
                Some((block_height, versioned_substates)),
            );
        }

        let parent_version = hyperscale_storage::tree::jvt_parent_height(
            s.current_block_height,
            s.current_root_hash,
        );

        let (new_root, collected) = hyperscale_storage::tree::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            merged_updates,
            &Default::default(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store
                .insert(key.clone(), std::sync::Arc::clone(node));
        }
        // NOTE: stale JVT nodes are NOT deleted — see apply_jvt_snapshot comment.
        // Historical roots must be retained for provision proof generation at
        // past block heights. RocksDB GC handles pruning in production.

        s.current_block_height = block_height;
        s.current_root_hash = new_root;

        drop(s);

        // Store block + certificate + consensus state atomically.
        {
            let mut c = self.consensus.write().unwrap();
            for tx in block.transactions.iter() {
                c.transactions.insert(tx.hash(), tx.as_ref().clone());
            }
            c.blocks
                .insert(block.header.height, ((**block).clone(), (**qc).clone()));
            for cert in &block.certificates {
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
            for wc in &block.certificates {
                for ec in &wc.execution_certificates {
                    let canonical_hash = ec.canonical_hash();
                    c.execution_certs.insert(canonical_hash, (**ec).clone());
                    c.execution_certs_by_height
                        .entry(ec.block_height())
                        .or_default()
                        .push(canonical_hash);
                }
            }
            c.committed_height = block.header.height;
            c.committed_hash = Some(block.hash());
            c.committed_qc = Some((**qc).clone());
            c.prune_receipts(block.header.height.0);
        }

        new_root
    }
}
