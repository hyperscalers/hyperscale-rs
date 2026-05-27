//! State recovered from storage on startup, used to restore the consensus
//! state machine after a crash or restart.

use hyperscale_types::{BlockHash, BlockHeight, Hash, StateRoot, VerifiedQuorumCertificate};

/// State recovered from storage on startup.
///
/// Constructed by storage backends (e.g. `RocksDbShardStorage::load_recovered_state`)
/// and passed to `ShardCoordinator::new()` to restore consensus state after a
/// crash/restart. For a fresh start, use `RecoveredState::default()`.
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Last committed height; the resume point for proposal/voting after restart.
    pub committed_height: BlockHeight,

    /// Last committed block hash (None for fresh start).
    pub committed_hash: Option<BlockHash>,

    /// Latest QC (certifies the highest certified block). Wrapped as
    /// [`VerifiedQuorumCertificate`] via `new_unchecked` inside the
    /// storage adapter; the trust source is the persistence invariant
    /// that QCs only land in storage after verification at admission.
    pub latest_qc: Option<VerifiedQuorumCertificate>,

    /// Last committed JMT root hash.
    ///
    /// Restored from storage at startup so proposals use the correct parent
    /// state root instead of the default `StateRoot::ZERO`.
    ///
    /// If not provided (None), defaults to `StateRoot::ZERO` for fresh start.
    pub jmt_root: Option<StateRoot>,

    /// Beacon-witness accumulator leaf hashes for the recovery shard, in
    /// monotonic leaf-index order. Storage backends derive these from
    /// the `beacon_witnesses` CF by hashing each retained payload, so
    /// the shard coordinator can rebuild
    /// [`BeaconWitnessAccumulator`](../../crates/shard/src/beacon_witnesses.rs)
    /// to the on-disk count without re-deriving from receipts +
    /// historical topology. Empty on a fresh start.
    pub beacon_witness_leaf_hashes: Vec<Hash>,
}
