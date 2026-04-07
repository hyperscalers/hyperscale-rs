//! `CommitStore` implementation for `SimStorage`.

use crate::core::SimStorage;
use crate::state::apply_updates_to_ordmap;

use hyperscale_storage::{CommitStore, DatabaseUpdates, JvtSnapshot};
use hyperscale_types::{Hash, TransactionCertificate};
use im::OrdMap;
use std::sync::Arc;

/// Precomputed commit work for a SimStorage block commit.
///
/// Contains a `JvtSnapshot` (precomputed verkle tree nodes), a pre-built
/// `OrdMap` with all certificate substate writes already applied (for O(1)
/// swap at commit time), plus the certificates and shard needed for
/// `store_certificate` calls and fallback recompute.
pub struct SimPreparedCommit {
    snapshot: JvtSnapshot,
    /// Pre-built OrdMap with all certificate substate writes already applied.
    /// O(1) clone from base at prepare time; O(1) swap at commit time.
    resulting_data: OrdMap<Vec<u8>, Vec<u8>>,
    merged_updates: DatabaseUpdates,
}

impl CommitStore for SimStorage {
    type PreparedCommit = SimPreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        merged_updates: &DatabaseUpdates,
        block_height: u64,
    ) -> (Hash, Self::PreparedCommit) {
        // Read lock: clone data + compute speculative JVT root concurrently.
        let s = self.state.read().unwrap();
        let base_data = s.data.clone();
        let base_root = s.current_root_hash;
        let base_version = s.current_block_height;

        if base_root != parent_state_root {
            tracing::warn!(
                ?base_root,
                ?parent_state_root,
                "JVT root mismatch - verification will likely fail"
            );
        }

        let parent_version = hyperscale_storage::jvt_parent_height(base_version, base_root);
        let (result_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            merged_updates,
            &Default::default(),
            &self.node_cache,
        );

        let snapshot = JvtSnapshot::from_collected_writes(
            collected,
            base_root,
            base_version,
            result_root,
            block_height,
        );

        drop(s); // Release read lock

        // Pre-apply all substate writes to a cloned OrdMap (O(1) clone).
        // No MVCC writes here — those happen at commit time.
        let mut resulting_data = base_data;
        apply_updates_to_ordmap(&mut resulting_data, merged_updates, None);

        let prepared = SimPreparedCommit {
            snapshot,
            resulting_data,
            merged_updates: merged_updates.clone(),
        };

        (result_root, prepared)
    }

    fn commit_prepared_block(
        &self,
        prepared: Self::PreparedCommit,
        certificates: &[Arc<TransactionCertificate>],
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
        _execution_certificates: &[hyperscale_types::ExecutionCertificate],
    ) -> Hash {
        let block_height = prepared.snapshot.new_version;
        let result_root = prepared.snapshot.result_root;

        {
            let mut s = self.state.write().unwrap();
            let use_fast_path = s.current_root_hash == prepared.snapshot.base_root;

            if use_fast_path {
                // Fast path: apply precomputed JVT snapshot + swap OrdMap.
                // Write MVCC entries from the merged updates.
                s.apply_jvt_snapshot(prepared.snapshot);
                s.data = prepared.resulting_data;
                // The OrdMap was pre-built, but we still need MVCC entries.
                // Use a throwaway OrdMap since data is already applied.
                let mut throwaway = OrdMap::new();
                {
                    let vs = &mut s.versioned_substates;
                    apply_updates_to_ordmap(
                        &mut throwaway,
                        &prepared.merged_updates,
                        Some((block_height, vs)),
                    );
                }
                drop(s);

                // Store certificates + consensus metadata atomically in consensus lock.
                let mut c = self.consensus.write().unwrap();
                for cert in certificates {
                    c.certificates
                        .insert(cert.transaction_hash, (**cert).clone());
                }
                if let Some(consensus) = consensus {
                    c.committed_height = consensus.height;
                    c.committed_hash = Some(consensus.hash);
                    c.committed_qc = Some(consensus.qc);
                    c.prune_receipts(consensus.height.0);
                }

                return result_root;
            }
        }

        // Stale cache: fall back to full block commit which recomputes JVT.
        // Use the stored merged_updates to ensure substate writes aren't lost.
        self.commit_block(
            &prepared.merged_updates,
            certificates,
            block_height,
            consensus,
            &[],
        )
    }

    fn commit_block(
        &self,
        merged_updates: &DatabaseUpdates,
        certificates: &[Arc<TransactionCertificate>],
        block_height: u64,
        consensus: Option<hyperscale_storage::ConsensusCommitData>,
        _execution_certificates: &[hyperscale_types::ExecutionCertificate],
    ) -> Hash {
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

        let parent_version =
            hyperscale_storage::jvt_parent_height(s.current_block_height, s.current_root_hash);

        let (new_root, collected) = hyperscale_storage::jmt::put_at_version(
            &s.tree_store,
            parent_version,
            block_height,
            merged_updates,
            &Default::default(),
            &self.node_cache,
        );

        collected.apply_to(&s.tree_store);

        s.current_block_height = block_height;
        s.current_root_hash = new_root;

        drop(s);

        // Store certificate metadata + consensus state atomically in consensus lock.
        {
            let mut c = self.consensus.write().unwrap();
            for cert in certificates {
                c.certificates
                    .insert(cert.transaction_hash, (**cert).clone());
            }
            if let Some(consensus) = consensus {
                c.committed_height = consensus.height;
                c.committed_hash = Some(consensus.hash);
                c.committed_qc = Some(consensus.qc);
                c.prune_receipts(consensus.height.0);
            }
        }

        new_root
    }

    fn node_cache_len(&self) -> usize {
        self.node_cache.len()
    }
}
