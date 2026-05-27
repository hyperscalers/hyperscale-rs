//! QC deferred while its certifying block header isn't yet in memory.
//!
//! When a QC forms before the corresponding block header has been received,
//! the coordinator can't safely adopt it: proposal building reads the parent
//! header for `parent_state_root` / `parent_in_flight`. The QC is parked
//! here keyed by its block hash and adopted as soon as the matching header
//! arrives via `on_block_header`.
//!
//! Holding at most one deferred QC matches the lifecycle: each `latest_qc`
//! advance is monotone in height, so an earlier deferred entry would be
//! superseded before any second QC could arrive without its header.

use hyperscale_types::{BlockHash, QuorumCertificate, Verified};

/// Single-slot stash for a QC awaiting its block header.
#[derive(Default)]
pub struct DeferredQc(Option<(BlockHash, Verified<QuorumCertificate>)>);

impl DeferredQc {
    pub const fn new() -> Self {
        Self(None)
    }

    /// Park `qc` until the header for `block_hash` arrives. Overwrites any
    /// previously deferred entry — only the latest deferral can still be
    /// load-bearing, since `latest_qc` advances monotonically.
    pub fn defer(&mut self, block_hash: BlockHash, qc: Verified<QuorumCertificate>) {
        self.0 = Some((block_hash, qc));
    }

    /// Take the deferred QC if it's the one waiting on `block_hash`. Leaves
    /// any non-matching deferred entry in place so it can still be adopted
    /// when its own header arrives.
    pub fn take_for(&mut self, block_hash: BlockHash) -> Option<Verified<QuorumCertificate>> {
        let (deferred_hash, _) = self.0.as_ref()?;
        if *deferred_hash != block_hash {
            return None;
        }
        self.0.take().map(|(_, qc)| qc)
    }
}
