//! Per-validator [`ExecutionVote`] over an entire wave's transactions.

use crate::{
    BlockHash, BlockHeight, Bls12381G2Signature, GlobalReceiptRoot, ShardGroupId, TxOutcome,
    ValidatorId, WaveId, WeightedTimestamp,
};
use sbor::prelude::*;

/// A validator's vote on all transactions in an execution wave.
///
/// One vote covers all transactions sharing the same provision dependency set,
/// with `global_receipt_root` being a padded merkle root over per-tx leaf hashes
/// where each leaf = `H(tx_hash` || `receipt_hash` || `success_byte`).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVote {
    /// Block this wave belongs to.
    pub block_hash: BlockHash,
    /// Block height (the block containing the wave's transactions).
    pub block_height: BlockHeight,
    /// BFT-authenticated anchor at which this vote was cast.
    ///
    /// Validators vote at each block commit where the wave is complete.
    /// Including `vote_anchor_ts` in the BLS-signed message prevents
    /// cross-height aggregation, ensuring that if an abort intent changes
    /// the `global_receipt_root` between heights, stale votes cannot combine.
    pub vote_anchor_ts: WeightedTimestamp,
    /// Which wave within the block.
    pub wave_id: WaveId,
    /// Which shard produced this vote.
    pub shard_group_id: ShardGroupId,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: GlobalReceiptRoot,
    /// Number of transactions in this wave.
    pub tx_count: u32,
    /// Per-tx execution outcomes in wave order.
    ///
    /// Carried alongside the vote so any aggregator can extract `tx_outcomes`
    /// directly from quorum votes when building the EC. Not included in the
    /// BLS-signed message (`global_receipt_root` already commits to the content).
    /// This avoids relying on each aggregator's local accumulator, which may
    /// have diverged due to different abort timing.
    pub tx_outcomes: Vec<TxOutcome>,
    /// Validator who cast this vote.
    pub validator: ValidatorId,
    /// BLS signature over the vote signing message.
    pub signature: Bls12381G2Signature,
}
