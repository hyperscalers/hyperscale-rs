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

/// Hard cap on the number of live transactions any single block can carry.
///
/// Bounds the `tx_hashes` array in [`BlockManifest`](crate::BlockManifest),
/// the `transactions` array inside [`Block`](crate::Block), the
/// `tx_outcomes` array inside any one
/// [`ExecutionCertificate`](crate::ExecutionCertificate) for a wave from
/// this block, and the `transactions` (per-tx state-entry sets) inside
/// any one [`Provisions`](crate::Provisions) batch sourced from this
/// block.
pub const MAX_TXS_PER_BLOCK: usize = 4_096;

/// Cap on the number of finalized transactions a proposer includes in a
/// single block, summed across all wave certificates.
///
/// Older waves (by kickoff `block_height`) are prioritized over newer
/// ones. Also serves as the outer-`Vec<FinalizedWave>` decode bound:
/// every wave's local EC carries at least one outcome in practice, so
/// the count of wave certificates a block can carry is implicitly
/// bounded by this same cap.
pub const MAX_FINALIZED_TX_PER_BLOCK: usize = 8_192;

/// Hard cap on the number of provision batches any single block can carry.
///
/// A [`Provisions`](crate::Provisions) batch is keyed on `(source_shard,
/// target_shard, source_block_height)`. The count per local block scales
/// with the number of remote shards we depend on for cross-shard work
/// and the recent source-block-heights we still need state from. Sized
/// for small-to-mid-shard topologies; widening the topology may require
/// revisiting.
pub const MAX_PROVISIONS_PER_BLOCK: usize = 256;

/// Cap on the number of in-flight transactions the mempool tracks
/// simultaneously (transactions holding state locks).
///
/// Sized at `MAX_TXS_PER_BLOCK * 3` to keep a full pipeline of blocks
/// (commit → execute → certify) without stalling proposal of new
/// transactions. Not operator-tunable: the right value is fully
/// determined by block size and pipeline depth.
pub const MAX_TX_IN_FLIGHT: usize = MAX_TXS_PER_BLOCK * 3;
