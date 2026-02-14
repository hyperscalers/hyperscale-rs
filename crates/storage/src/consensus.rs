//! Consensus storage trait.
//!
//! Abstracts block, certificate, vote, and metadata storage.
//! All methods take `&self` — implementations use interior mutability.

use hyperscale_types::{Block, BlockHeight, Hash, QuorumCertificate, TransactionCertificate};
use std::collections::HashMap;

/// Abstracts consensus-related storage for both simulation and production.
///
/// Provides a uniform interface for storing blocks, certificates, votes,
/// and chain metadata across different storage backends.
pub trait ConsensusStore: Send + Sync {
    /// Store a committed block with its quorum certificate.
    fn put_block(&self, height: BlockHeight, block: &Block, qc: &QuorumCertificate);

    /// Get a committed block by height.
    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)>;

    /// Set the highest committed block height.
    fn set_committed_height(&self, height: BlockHeight);

    /// Get the highest committed block height.
    fn committed_height(&self) -> BlockHeight;

    /// Set committed state (height + hash + QC) atomically.
    fn set_committed_state(&self, height: BlockHeight, hash: Hash, qc: &QuorumCertificate);

    /// Get the latest committed block hash.
    fn committed_hash(&self) -> Option<Hash>;

    /// Get the latest quorum certificate.
    fn latest_qc(&self) -> Option<QuorumCertificate>;

    /// Store a transaction certificate (extracts hash internally).
    fn store_certificate(&self, certificate: &TransactionCertificate);

    /// Get a transaction certificate by transaction hash.
    fn get_certificate(&self, hash: &Hash) -> Option<TransactionCertificate>;

    /// Store our own vote for a height.
    ///
    /// **BFT Safety Critical**: Must be called before broadcasting the vote.
    fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash);

    /// Get our own vote for a height (if any).
    ///
    /// Returns `Some((block_hash, round))` if we previously voted at this height.
    fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)>;

    /// Get all our own votes (for recovery on startup).
    ///
    /// Returns a map of height → (block_hash, round).
    fn get_all_own_votes(&self) -> HashMap<u64, (Hash, u64)>;

    /// Remove votes at or below a committed height (cleanup).
    fn prune_own_votes(&self, committed_height: u64);
}
