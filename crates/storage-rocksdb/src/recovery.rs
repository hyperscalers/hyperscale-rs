//! Crash recovery for RocksDB storage.

use crate::core::RocksDbStorage;

use hyperscale_metrics as metrics;

impl RocksDbStorage {
    /// Load recovered state from storage for crash recovery.
    ///
    /// This should be called on startup before creating the state machine.
    /// Returns `RecoveredState::default()` for a fresh database.
    pub fn load_recovered_state(&self) -> hyperscale_bft::RecoveredState {
        let start = std::time::Instant::now();
        let (committed_height, committed_hash, latest_qc) = self.get_chain_metadata();

        // Get current JVT state from storage - critical for correct state root computation.
        // Without this, the state machine would start with Hash::ZERO which causes
        // state root verification failures if the JVT has already advanced.
        //
        // Note: We always include JVT state, even at height 0, because genesis bootstrap
        // populates the JVT with initial Radix state at height 0 but with a non-zero root.
        // The height 0 case is handled correctly by the state machine.
        use hyperscale_storage::SubstateStore;
        let jvt_block_height = self.jmt_version();
        let jvt_root = self.state_root_hash();
        let jvt_root_opt = Some(jvt_root);

        // Recovery invariant: JVT version (= block height) must match committed_height.
        // Since consensus metadata is now written atomically in the same WriteBatch
        // as the JVT commit, a mismatch should never occur. If it does, something
        // is seriously wrong (e.g., storage corruption).
        if committed_height.0 > 0 && jvt_block_height != committed_height.0 {
            tracing::error!(
                committed_height = committed_height.0,
                jvt_block_height,
                "RECOVERY: JVT version does not match committed height — \
                 this should not happen with atomic commits. Possible storage corruption."
            );
        }

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.0,
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            jvt_block_height,
            jvt_root = ?jvt_root,
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        hyperscale_bft::RecoveredState {
            committed_height: committed_height.0,
            committed_hash,
            latest_qc,
            jvt_root: jvt_root_opt,
        }
    }
}
