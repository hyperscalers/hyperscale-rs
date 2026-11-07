//! Signing message for cross-shard state provisions gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{BlockHeight, Hash, Provision, ShardId};

/// What a state-provisions gossip signature covers: the route, the source
/// height, and a digest of the hashes of the parts one notification
/// packs.
///
/// Cheap to reconstruct at verification while binding the signature to the
/// specific parts it carries, so unauthenticated provision spam is rejected
/// before expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-provisions-sender-v2", signing_context = NetworkId)]
pub struct ProvisionsSenderMessage {
    /// Shard the parts were produced on.
    pub(crate) source_shard: ShardId,
    /// Shard the parts serve.
    pub(crate) target_shard: ShardId,
    /// Source block height the parts belong to.
    pub(crate) block_height: BlockHeight,
    /// Digest over the packed parts' hashes, in notification order.
    pub(crate) parts_digest: Hash,
}

impl ProvisionsSenderMessage {
    /// Assemble the message a provisions notification over `parts` of
    /// `(source_shard, target_shard, block_height)` signs.
    #[must_use]
    pub fn new<'a>(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        parts: impl IntoIterator<Item = &'a Provision>,
    ) -> Self {
        let mut hasher = Hasher::new();
        for part in parts {
            hasher.update(part.hash().as_bytes());
        }
        Self {
            source_shard,
            target_shard,
            block_height,
            parts_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}
