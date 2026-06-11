//! Crash recovery for `RocksDB` storage.

use hyperscale_metrics::record_storage_operation;
use hyperscale_storage::{RecoveredState, SubstateStore};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockMetadata, Hash, ShardWitnessPayload,
    WeightedTimestamp,
};

use super::column_families::{BeaconWitnessesCf, BlocksCf};
use super::core::RocksDbShardStorage;
use crate::typed_cf::{TypedCf, get, iter_from};

impl RocksDbShardStorage {
    /// Load recovered state from storage for crash recovery.
    ///
    /// This should be called on startup before creating the state machine.
    /// Returns `RecoveredState::default()` for a fresh database.
    pub fn load_recovered_state(&self) -> RecoveredState {
        let start = std::time::Instant::now();
        let (committed_height, committed_hash, latest_qc) = self.get_chain_metadata();

        // Get current JMT state from storage - critical for correct state root computation.
        // Without this, the state machine would start with Hash::ZERO which causes
        // state root verification failures if the JMT has already advanced.
        //
        // Note: We always include JMT state, even at height 0, because genesis bootstrap
        // populates the JMT with initial Radix state at height 0 but with a non-zero root.
        // The height 0 case is handled correctly by the state machine.
        let jmt_block_height = self.jmt_height();
        let jmt_root = self.state_root();
        let jmt_root_opt = Some(jmt_root);

        // Recovery invariant: JMT version (= block height) must match committed_height.
        // Consensus metadata and the JMT commit share a single WriteBatch, so a
        // mismatch indicates storage corruption.
        if committed_height > BlockHeight::GENESIS && jmt_block_height != committed_height {
            tracing::error!(
                committed_height = committed_height.inner(),
                jmt_block_height = jmt_block_height.inner(),
                "RECOVERY: JMT version does not match committed height — \
                 this should not happen with atomic commits. Possible storage corruption."
            );
        }

        let beacon_witness_start = self.committed_witness_base(committed_height);
        let beacon_witness_leaf_hashes = self.load_beacon_witness_leaf_hashes(beacon_witness_start);

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.inner(),
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            jmt_block_height = jmt_block_height.inner(),
            jmt_root = ?jmt_root,
            beacon_witness_start = beacon_witness_start.inner(),
            beacon_witness_leaf_count = beacon_witness_leaf_hashes.len(),
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        RecoveredState {
            committed_height,
            committed_hash: committed_hash.map(BlockHash::from_raw),
            latest_qc,
            committed_anchor_ts: self.committed_anchor_ts(committed_height),
            jmt_root: jmt_root_opt,
            beacon_witness_start,
            beacon_witness_leaf_hashes,
            substate_count: self
                .substate_count_at_version(committed_height.inner())
                .unwrap_or(0),
            genesis_anchor_wt: WeightedTimestamp::ZERO,
        }
    }

    /// Weighted timestamp of the committed tip's parent QC — the anchor its
    /// committee was keyed on (`committee = at(committed_anchor_ts)`). Read
    /// from the committed block's stored header. `None` when no block is
    /// stored at `committed_height` (fresh start / genesis tip), where the
    /// coordinator falls back to the tip's own weighted timestamp.
    fn committed_anchor_ts(&self, committed_height: BlockHeight) -> Option<WeightedTimestamp> {
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let metadata: BlockMetadata =
            get::<BlocksCf>(&*self.db, blocks_cf, &committed_height.inner())?;
        Some(metadata.header().parent_qc().weighted_timestamp())
    }

    /// The committed tip's witness window base, read from its stored
    /// header. `ZERO` when no block is stored at `committed_height`
    /// (fresh start / genesis tip).
    fn committed_witness_base(&self, committed_height: BlockHeight) -> BeaconWitnessLeafCount {
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        get::<BlocksCf>(&*self.db, blocks_cf, &committed_height.inner())
            .map_or(BeaconWitnessLeafCount::ZERO, |metadata: BlockMetadata| {
                metadata.header().beacon_witness_base()
            })
    }

    /// Read the retained beacon-witness leaves at or above `start` from
    /// the [`BeaconWitnessesCf`](crate::column_families::BeaconWitnessesCf)
    /// in key order and hash each payload through
    /// [`ShardWitnessPayload::leaf_hash`]. The result feeds
    /// [`BeaconWitnessAccumulator::from_leaves`](../../crates/shard/src/beacon_witnesses.rs)
    /// at coordinator startup. Entries below `start` are the
    /// persistence layer's hysteresis stock — serving data, not
    /// accumulator state.
    fn load_beacon_witness_leaf_hashes(&self, start: BeaconWitnessLeafCount) -> Vec<Hash> {
        let cf = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cf);
        iter_from::<BeaconWitnessesCf>(&self.db, beacon_witnesses_cf, &start.inner())
            .map(|(_leaf_index, payload): (_, ShardWitnessPayload)| payload.leaf_hash())
            .collect()
    }
}
