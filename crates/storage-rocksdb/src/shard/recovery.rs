//! Crash recovery for `RocksDB` storage.

use hyperscale_metrics::record_storage_operation;
use hyperscale_storage::{RecoveredState, SubstateStore};
use hyperscale_types::{
    BlockHash, BlockHeight, Hash, QuorumCertificate, ShardWitnessPayload, Verified,
};

use super::column_families::BeaconWitnessesCf;
use super::core::RocksDbShardStorage;
use crate::typed_cf::{TypedCf, iter_all};

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

        let beacon_witness_leaf_hashes = self.load_beacon_witness_leaf_hashes();

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.inner(),
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            jmt_block_height = jmt_block_height.inner(),
            jmt_root = ?jmt_root,
            beacon_witness_leaf_count = beacon_witness_leaf_hashes.len(),
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        // SAFETY: QCs only land in storage after verification at the
        // shard-consensus admission boundary, so recovery can rewrap
        // with `new_unchecked` without re-verifying.
        let latest_qc = latest_qc.map(Verified::<QuorumCertificate>::new_unchecked);

        RecoveredState {
            committed_height,
            committed_hash: committed_hash.map(BlockHash::from_raw),
            latest_qc,
            jmt_root: jmt_root_opt,
            beacon_witness_leaf_hashes,
        }
    }

    /// Read all retained beacon-witness leaves from the
    /// [`BeaconWitnessesCf`](crate::column_families::BeaconWitnessesCf)
    /// in key order and hash each payload through
    /// [`ShardWitnessPayload::leaf_hash`]. The result feeds
    /// [`BeaconWitnessAccumulator::from_leaves`](../../crates/shard/src/beacon_witnesses.rs)
    /// at coordinator startup. Storage is scoped per-shard, so the
    /// full-scan order is the accumulator's monotonic leaf order.
    fn load_beacon_witness_leaf_hashes(&self) -> Vec<Hash> {
        let cf = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cf);
        iter_all::<BeaconWitnessesCf>(&self.db, beacon_witnesses_cf)
            .map(|(_leaf_index, payload): (_, ShardWitnessPayload)| payload.leaf_hash())
            .collect()
    }
}
