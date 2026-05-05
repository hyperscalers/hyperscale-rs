//! Block content limits.
//!
//! Hard caps on per-block payload sizes. Wire decoders enforce them at
//! decode time, admission paths enforce them at header ingress, and
//! proposers respect them when building blocks.
//!
//! These are protocol invariants, not operator-tunable config: every
//! validator must be able to handle a peak-sized block, so dialing
//! limits down on a single node only degrades that node's responsiveness
//! without reducing the protocol-wide load it has to keep up with.

/// Hard cap on the number of transactions any single block can carry.
///
/// Bounds the `tx_hashes` array in [`BlockManifest`](crate::BlockManifest),
/// the `transactions` array inside [`Block`](crate::Block), the
/// `tx_outcomes` array inside any one
/// [`ExecutionCertificate`](crate::ExecutionCertificate) for a wave from
/// this block, and the `transactions` (per-tx state-entry sets) inside
/// any one [`Provisions`](crate::Provisions) batch sourced from this
/// block.
pub const MAX_TX_HASHES_PER_BLOCK: usize = 12_288;

/// Hard cap on the number of finalized-wave certificates any single
/// block can carry.
///
/// Bounds the `cert_ids` array in [`BlockManifest`](crate::BlockManifest)
/// and the `certificates` array inside [`Block`](crate::Block).
pub const MAX_CERT_IDS_PER_BLOCK: usize = 4_096;

/// Hard cap on the number of provision batches any single block can carry.
///
/// Bounds the `provision_hashes` array in
/// [`BlockManifest`](crate::BlockManifest) and the `provisions` array
/// inside [`Block`](crate::Block).
pub const MAX_PROVISION_HASHES_PER_BLOCK: usize = 12_288;

/// Cap on the number of finalized transactions a proposer includes in a
/// single block, summed across all wave certificates.
///
/// Older waves (by kickoff `block_height`) are prioritized over newer
/// ones. Structurally a block could carry far more
/// (`MAX_CERT_IDS_PER_BLOCK × MAX_TX_HASHES_PER_BLOCK`); this cap keeps
/// build/verify work and block size on a tight budget.
pub const MAX_FINALIZED_TX_PER_BLOCK: usize = 8_192;
