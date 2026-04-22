//! Crash recovery for RocksDB storage.

use crate::core::RocksDbStorage;

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHash, BlockHeight};

impl RocksDbStorage {
    /// Load recovered state from storage for crash recovery.
    ///
    /// This should be called on startup before creating the state machine.
    /// Returns `RecoveredState::default()` for a fresh database.
    pub fn load_recovered_state(&self) -> hyperscale_bft::RecoveredState {
        let start = std::time::Instant::now();
        let (committed_height, committed_hash, latest_qc) = self.get_chain_metadata();

        // Get current JMT state from storage - critical for correct state root computation.
        // Without this, the state machine would start with Hash::ZERO which causes
        // state root verification failures if the JMT has already advanced.
        //
        // Note: We always include JMT state, even at height 0, because genesis bootstrap
        // populates the JMT with initial Radix state at height 0 but with a non-zero root.
        // The height 0 case is handled correctly by the state machine.
        use hyperscale_storage::SubstateStore;
        let jmt_block_height = self.jmt_height();
        let jmt_root = self.state_root_hash();
        let jmt_root_opt = Some(jmt_root);

        // Recovery invariant: JMT version (= block height) must match committed_height.
        // Since consensus metadata is now written atomically in the same WriteBatch
        // as the JMT commit, a mismatch should never occur. If it does, something
        // is seriously wrong (e.g., storage corruption).
        if committed_height > BlockHeight::GENESIS && jmt_block_height != committed_height {
            tracing::error!(
                committed_height = committed_height.0,
                jmt_block_height = jmt_block_height.0,
                "RECOVERY: JMT version does not match committed height — \
                 this should not happen with atomic commits. Possible storage corruption."
            );
        }

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.0,
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            jmt_block_height = jmt_block_height.0,
            jmt_root = ?jmt_root,
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        hyperscale_bft::RecoveredState {
            committed_height,
            committed_hash: committed_hash.map(BlockHash::from_raw),
            latest_qc,
            jmt_root: jmt_root_opt,
        }
    }
}
