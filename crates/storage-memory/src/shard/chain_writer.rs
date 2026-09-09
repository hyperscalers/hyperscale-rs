//! `ShardChainWriter` implementation for `SimShardStorage`.

use std::collections::hash_map::Entry;
use std::sync::Arc;

use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::{
    OverlayTreeReader, jmt_parent_height, noop_jmt_snapshot, put_at_version,
};
use hyperscale_storage::{
    JmtSnapshot, ParentAnchor, ShardChainWriter, SubstateStore, covers_strictly_more,
    holds_this_block_at, settled_writes_at, widest_tick_copies,
};
use hyperscale_types::{
    BeaconWitnessCommit, Block, BlockHeight, CertifiedBlock, Finalization, PreparedCommit,
    SettledWrites, StateRoot, StoredReceipt, SubstateKey, SyncHint, Verifiable, Verified,
};

use super::core::SimShardStorage;
use super::state::{ConsensusState, apply_writes};

impl ShardChainWriter for SimShardStorage {
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
        let receipts: Vec<StoredReceipt> = finalizations
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        // Nothing to write → state root is unchanged. Build a no-op
        // JmtSnapshot directly, avoiding put_at_version which would fail
        // if the parent's tree nodes aren't in the store yet. A block's
        // sweep and its committed cells are writes like any other, so a
        // block that removes or creates something is not one of these
        // however few receipts it carries.
        if receipts.is_empty() && creations.is_empty() && removals.is_empty() {
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
            for fw in block.certificates().iter() {
                let tick_id = *fw.tick_id();
                c.certificates.insert(fw.receipt_hash(), fw.attestation());
                c.finalizations_by_height
                    .entry(tick_id.block_height())
                    .or_default()
                    .push(tick_id);
            }
            c.record_provisions(block, floor);
            c.insert_receipts(&receipts);
            record_execution_certs(&mut c, block);
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

/// Fold a block's execution certificates into the consensus map, keeping
/// the widest copy of each tick and indexing the transactions that copy
/// attests.
///
/// Only an accepted copy of this shard's own certificate is indexed. A
/// settled cross-shard transaction lands here under both sides'
/// certificates, and the index answers "what did THIS shard attest for
/// the transaction" — the question a counterpart's fallback fetch asks
/// this shard. A remote copy in there serves the requester its own
/// certificate back, which it rightly refuses as unsolicited, and the
/// fetch loops forever.
///
/// Every one of this shard's is indexed, not the newest: the verdict and
/// whatever settles what it left both name the transaction, and only the
/// asker can tell which answers the question its tick waits on.
fn record_execution_certs(consensus: &mut ConsensusState, block: &Block) {
    let local_shard = block
        .certificates()
        .first()
        .map(|finalization| finalization.tick_id().shard_id());
    for cert in widest_tick_copies(block).into_values() {
        match consensus.execution_certs.entry(*cert.tick_id()) {
            Entry::Occupied(mut held) => {
                if !covers_strictly_more(cert, held.get()) {
                    continue;
                }
                held.insert(cert.clone());
            }
            Entry::Vacant(slot) => {
                slot.insert(cert.clone());
            }
        }
        if Some(cert.tick_id().shard_id()) != local_shard {
            continue;
        }
        for outcome in cert.tx_outcomes() {
            consensus
                .tx_cert_index
                .entry(outcome.tx_hash())
                .or_default()
                .insert(*cert.tick_id());
        }
    }
}
