//! Where a shard chain starts: genesis height plus start-time anchor.

use crate::{BlockHeight, WeightedTimestamp};

/// Where a shard chain starts: the height of its genesis block and the
/// weighted-time anchor its genesis QC carries.
///
/// Chains born at network genesis start at height 0 with a `ZERO` anchor
/// ([`Self::ROOT`]). A child chain created by a shard split continues its
/// parent's lines instead of restarting them: its genesis sits at the
/// parent's terminal height + 1 (so JMT versions stay equal to block
/// heights over the hard-linked parent data) and anchors at the parent's
/// final committed canonical weighted timestamp (so the child's BFT clock
/// is continuous with the parent it inherits).
///
/// The origin is a per-chain constant. Consensus components reconstruct
/// the chain's canonical genesis QC from it, so a value that doesn't
/// byte-match the chain's real genesis QC breaks verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainOrigin {
    /// Height of the chain's genesis block.
    pub genesis_height: BlockHeight,
    /// Start-time anchor, carried as the genesis QC's weighted timestamp.
    pub anchor_wt: WeightedTimestamp,
}

impl ChainOrigin {
    /// Origin of a chain born at network genesis: height 0, `ZERO` anchor.
    pub const ROOT: Self = Self {
        genesis_height: BlockHeight::GENESIS,
        anchor_wt: WeightedTimestamp::ZERO,
    };
}

impl Default for ChainOrigin {
    fn default() -> Self {
        Self::ROOT
    }
}
