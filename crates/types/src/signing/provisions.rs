//! Signing message for cross-shard state provisions gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{BlockHeight, Hash, Provisions, ShardId};

/// What a state-provisions gossip signature covers: the route, the source
/// height, and a digest of the transaction hashes in the bundle.
///
/// Cheap to reconstruct at verification while binding the signature to the
/// specific bundle contents, so unauthenticated provision spam is rejected
/// before expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-provisions-sender-v1", signing_context = NetworkId)]
pub struct ProvisionsSenderMessage {
    /// Shard the bundle was produced on.
    pub(crate) source_shard: ShardId,
    /// Shard the bundle serves.
    pub(crate) target_shard: ShardId,
    /// Source block height the bundle belongs to.
    pub(crate) block_height: BlockHeight,
    /// Digest over the bundle's transaction hashes, in bundle order.
    pub(crate) tx_digest: Hash,
}

impl ProvisionsSenderMessage {
    /// Assemble the message a provisions broadcast signs.
    #[must_use]
    pub fn new(provisions: &Provisions) -> Self {
        let mut hasher = Hasher::new();
        for tx in provisions.transactions() {
            hasher.update(tx.tx_hash.as_bytes());
        }
        Self {
            source_shard: provisions.source_shard(),
            target_shard: provisions.target_shard(),
            block_height: provisions.block_height(),
            tx_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}
