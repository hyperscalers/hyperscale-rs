//! `BlockHeader` notification message.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{
    BlockHeader, BlockManifest, BlockProposalMessage, ConsensusSignature, MessageClass,
    NetworkDefinition, NetworkMessage, Signed, ValidatorId, signed_bytes,
};

/// Notifies committee members of a block proposal (header + manifest, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
///
/// The `proposer_signature` is a signature by the proposer over a domain-separated
/// message, ensuring that block proposals cannot be forged by non-proposers.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BlockHeaderNotification {
    /// The block header being proposed.
    pub header: Arc<BlockHeader>,

    /// Block contents manifest (transaction hashes, certificates, deferrals, etc.)
    pub(crate) manifest: BlockManifest,

    /// signature by the proposer over the domain-separated block header message.
    /// Verifies that the claimed proposer actually created this proposal.
    pub(crate) proposer_signature: ConsensusSignature,
}

impl BlockHeaderNotification {
    /// Create a block header notification message.
    #[must_use]
    pub fn new(
        header: impl Into<Arc<BlockHeader>>,
        manifest: BlockManifest,
        proposer_signature: ConsensusSignature,
    ) -> Self {
        Self {
            header: header.into(),
            manifest,
            proposer_signature,
        }
    }

    /// Consume and return header (as `Arc`), manifest, and proposer signature.
    #[must_use]
    pub fn into_parts(self) -> (Arc<BlockHeader>, BlockManifest, ConsensusSignature) {
        (self.header, self.manifest, self.proposer_signature)
    }
}

// Network message implementation
impl Signed for BlockHeaderNotification {
    /// The proposer is the implicit signer — no separate `sender` field
    /// rides on this notification.
    fn signer(&self) -> ValidatorId {
        self.header.proposer()
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.proposer_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &BlockProposalMessage {
                shard_group: self.header.shard_id(),
                height: self.header.height(),
                round: self.header.round(),
                block_hash: self.header.hash(),
            },
            network,
        )
    }
}

impl NetworkMessage for BlockHeaderNotification {
    fn message_type_id() -> &'static str {
        "block.header"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        BlockHash, BlockHeaderParts, BlockHeight, ChainOrigin, Hash, ProposerTimestamp,
        QuorumCertificate, ShardId, TxHash, WitnessSources,
    };

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            ..Default::default()
        })
    }

    fn zero_sig() -> ConsensusSignature {
        ConsensusSignature::ZERO
    }

    #[test]
    fn test_block_header_gossip_creation() {
        let header = make_header(BlockHeight::new(1));
        let manifest = BlockManifest::new(
            vec![
                TxHash::from(Hash::from_bytes(b"tx1")),
                TxHash::from(Hash::from_bytes(b"tx2")),
                TxHash::from(Hash::from_bytes(b"tx3")),
                TxHash::from(Hash::from_bytes(b"tx4")),
            ],
            vec![],
            vec![],
            vec![],
            vec![],
            WitnessSources::empty(),
        );

        let gossip = BlockHeaderNotification::new(header.clone(), manifest.clone(), zero_sig());
        assert_eq!(*gossip.header, header);
        assert_eq!(gossip.manifest, manifest);
        assert_eq!(gossip.manifest.transaction_count(), 4);
    }

    #[test]
    fn test_block_header_gossip_into_parts() {
        let header = make_header(BlockHeight::new(5));
        let manifest = BlockManifest::new(
            vec![TxHash::from(Hash::from_bytes(b"tx1"))],
            vec![],
            vec![],
            vec![],
            vec![],
            WitnessSources::empty(),
        );

        let gossip = BlockHeaderNotification::new(header.clone(), manifest.clone(), zero_sig());
        let (h, m, _sig) = gossip.into_parts();
        assert_eq!(*h, header);
        assert_eq!(m, manifest);
    }

    #[test]
    fn test_block_header_gossip_all_transaction_hashes() {
        let tx1 = TxHash::from(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from(Hash::from_bytes(b"tx2"));
        let tx3 = TxHash::from(Hash::from_bytes(b"tx3"));

        let gossip = BlockHeaderNotification::new(
            make_header(BlockHeight::new(1)),
            BlockManifest::new(
                vec![tx1, tx2, tx3],
                vec![],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            zero_sig(),
        );

        let all: Vec<TxHash> = gossip.manifest.tx_hashes().clone();
        assert_eq!(all, vec![tx1, tx2, tx3]);
    }
}
