//! State recovered from storage on startup, used to restore the consensus
//! state machine after a crash or restart.

use hyperscale_types::{BlockHash, BlockHeight, QuorumCertificate, StateRoot};

/// State recovered from storage on startup.
///
/// Constructed by storage backends (e.g. `RocksDbStorage::load_recovered_state`)
/// and passed to `ShardCoordinator::new()` to restore consensus state after a
/// crash/restart. For a fresh start, use `RecoveredState::default()`.
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Last committed height; the resume point for proposal/voting after restart.
    pub committed_height: BlockHeight,

    /// Last committed block hash (None for fresh start).
    pub committed_hash: Option<BlockHash>,

    /// Latest QC (certifies the highest certified block).
    pub latest_qc: Option<QuorumCertificate>,

    /// Last committed JMT root hash.
    ///
    /// Restored from storage at startup so proposals use the correct parent
    /// state root instead of the default `StateRoot::ZERO`.
    ///
    /// If not provided (None), defaults to `StateRoot::ZERO` for fresh start.
    pub jmt_root: Option<StateRoot>,
}
