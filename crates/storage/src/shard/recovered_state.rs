//! State recovered from storage on startup, used to restore the consensus
//! state machine after a crash or restart.

use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeader, BlockHeight, Hash, QuorumCertificate,
    ShardAnchor, StateRoot, Verified, WeightedTimestamp,
};

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
    /// `Verified<QuorumCertificate>` via `new_unchecked` inside the
    /// storage adapter; the trust source is the persistence invariant
    /// that QCs only land in storage after verification at admission.
    pub latest_qc: Option<Verified<QuorumCertificate>>,

    /// Weighted timestamp of the committed tip's *parent* QC — the anchor
    /// its committee was keyed on (`committee = at(committed_anchor_ts)`).
    /// Distinct from `latest_qc`'s timestamp (the tip's own WT) when the tip
    /// is an epoch's first block. `None` for a fresh start or genesis tip; the
    /// coordinator then falls back to the tip's own WT, exact except across
    /// that one boundary case.
    pub committed_anchor_ts: Option<WeightedTimestamp>,

    /// Last committed JMT root hash.
    ///
    /// Restored from storage at startup so proposals use the correct parent
    /// state root instead of the default `StateRoot::ZERO`.
    ///
    /// If not provided (None), defaults to `StateRoot::ZERO` for fresh start.
    pub jmt_root: Option<StateRoot>,

    /// Absolute leaf index of `beacon_witness_leaf_hashes[0]` — the
    /// committed tip's witness window base. Stored payloads below it
    /// (the persistence layer's one-window hysteresis stock) are
    /// serving data, not accumulator state, and are excluded from the
    /// recovered window. `ZERO` on a fresh start.
    pub beacon_witness_start: BeaconWitnessLeafCount,

    /// Beacon-witness accumulator leaf hashes for the recovery shard
    /// from `beacon_witness_start`, in monotonic leaf-index order.
    /// Storage backends derive these from the `beacon_witnesses` CF by
    /// hashing each retained payload at or above the tip's window base,
    /// so the shard coordinator can rebuild
    /// [`BeaconWitnessAccumulator`](../../crates/shard/src/beacon_witnesses.rs)
    /// to the on-disk count without re-deriving from receipts +
    /// historical topology. Empty on a fresh start.
    pub beacon_witness_leaf_hashes: Vec<Hash>,
}

impl RecoveredState {
    /// The recovered state of a snap-synced bootstrap: the store was
    /// imported at the beacon-attested boundary `anchor`, so the
    /// committed tip is the boundary block itself.
    ///
    /// `boundary_header` is the anchor block's header, hash-verified
    /// against `anchor.block_hash` by the fetch path; its `parent_qc`
    /// weighted timestamp is the tip's committee anchor, and
    /// `witness_leaf_hashes` is its verified accumulator window —
    /// starting at the header's `beacon_witness_base`. `latest_qc`
    /// stays `None` — the store holds no QC for the boundary block,
    /// and the first tail-synced block's QC adopts through the normal
    /// round-monotonic path.
    #[must_use]
    pub fn from_snap_synced_boundary(
        anchor: &ShardAnchor,
        boundary_header: &BlockHeader,
        witness_leaf_hashes: Vec<Hash>,
    ) -> Self {
        Self {
            committed_height: anchor.height,
            committed_hash: Some(anchor.block_hash),
            latest_qc: None,
            committed_anchor_ts: Some(boundary_header.parent_qc().weighted_timestamp()),
            jmt_root: Some(anchor.state_root),
            beacon_witness_start: boundary_header.beacon_witness_base(),
            beacon_witness_leaf_hashes: witness_leaf_hashes,
        }
    }

    /// Committee anchor of the recovered tip — [`committed_anchor_ts`](Self::committed_anchor_ts)
    /// when storage recovered it, else the tip QC's own weighted timestamp
    /// (identical except when the tip is an epoch's first block), else `ZERO`
    /// on a fresh start. The oldest weighted timestamp the recovered chain
    /// can still key a topology lookup on.
    #[must_use]
    pub fn committee_anchor_ts(&self) -> WeightedTimestamp {
        self.committed_anchor_ts.unwrap_or_else(|| {
            self.latest_qc.as_deref().map_or(
                WeightedTimestamp::ZERO,
                QuorumCertificate::weighted_timestamp,
            )
        })
    }
}
