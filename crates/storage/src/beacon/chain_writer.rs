//! Write interface for committed beacon blocks.

use std::sync::Arc;

use hyperscale_types::{BeaconState, CertifiedBeaconBlock, Verified};

/// Write access to the process-level beacon chain.
///
/// Beacon blocks are paired with their authenticating
/// [`BeaconCert`](hyperscale_types::BeaconCert) on the
/// [`CertifiedBeaconBlock`] wrapper — the cert (Genesis / Normal / Skip)
/// is the committee QC. No separate certificate parameter is threaded
/// through.
pub trait BeaconChainWriter: Send + Sync {
    /// Persist `block` together with the `BeaconState` it advances to.
    ///
    /// Both writes go inside one atomic batch keyed by
    /// `block.epoch()`, so the (block, state) pair on disk can never
    /// diverge for a given epoch. Idempotent on
    /// `(epoch, block_hash, state_root)` — committing the same pair
    /// twice is a no-op.
    ///
    /// Behavior under epoch-collision with a *different* block or
    /// state is implementation-defined: a well-behaved consensus
    /// never produces two distinct blocks at the same epoch, so a
    /// collision indicates either a programming bug or Byzantine
    /// activity. Implementations may panic, log, or overwrite — none
    /// of these is safety-critical because the BFT layer's dedup
    /// catches it first.
    fn commit_beacon_block(&self, block: &Arc<Verified<CertifiedBeaconBlock>>, state: &BeaconState);
}
