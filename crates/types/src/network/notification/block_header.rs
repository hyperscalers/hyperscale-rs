//! `BlockHeader` notification message.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{
    BlockHeader, BlockManifest, Bls12381G2Signature, MessageClass, NetworkDefinition,
    NetworkMessage, Signed, ValidatorId, block_header_message,
};

/// Notifies committee members of a block proposal (header + manifest, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
///
/// The `proposer_signature` is a BLS signature by the proposer over a domain-separated
/// message, ensuring that block proposals cannot be forged by non-proposers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeaderNotification {
    /// The block header being proposed.
    pub header: Arc<BlockHeader>,

    /// Block contents manifest (transaction hashes, certificates, deferrals, etc.)
    pub manifest: BlockManifest,

    /// BLS signature by the proposer over the domain-separated block header message.
    /// Verifies that the claimed proposer actually created this proposal.
    pub proposer_signature: Bls12381G2Signature,
}

impl BlockHeaderNotification {
    /// Create a block header notification message.
    #[must_use]
    pub fn new(
        header: impl Into<Arc<BlockHeader>>,
        manifest: BlockManifest,
        proposer_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            header: header.into(),
            manifest,
            proposer_signature,
        }
    }

    /// Consume and return header (as `Arc`), manifest, and proposer signature.
    #[must_use]
    pub fn into_parts(self) -> (Arc<BlockHeader>, BlockManifest, Bls12381G2Signature) {
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

    fn signature(&self) -> &Bls12381G2Signature {
        &self.proposer_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        block_header_message(
            network,
            self.header.shard_id(),
            self.header.height(),
            self.header.round(),
            &self.header.hash(),
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeight, CertificateRoot, Hash,
        InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate,
        Round, ShardId, StateRoot, TransactionRoot, TxHash, ValidatorId,
    };

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn zero_sig() -> Bls12381G2Signature {
        Bls12381G2Signature([0u8; Bls12381G2Signature::LENGTH])
    }

    #[test]
    fn test_block_header_gossip_creation() {
        let header = make_header(BlockHeight::new(1));
        let manifest = BlockManifest::new(
            vec![
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                TxHash::from_raw(Hash::from_bytes(b"tx2")),
                TxHash::from_raw(Hash::from_bytes(b"tx3")),
                TxHash::from_raw(Hash::from_bytes(b"tx4")),
            ],
            vec![],
            vec![],
            vec![],
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
            vec![TxHash::from_raw(Hash::from_bytes(b"tx1"))],
            vec![],
            vec![],
            vec![],
        );

        let gossip = BlockHeaderNotification::new(header.clone(), manifest.clone(), zero_sig());
        let (h, m, _sig) = gossip.into_parts();
        assert_eq!(*h, header);
        assert_eq!(m, manifest);
    }

    #[test]
    fn test_block_header_gossip_all_transaction_hashes() {
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from_raw(Hash::from_bytes(b"tx2"));
        let tx3 = TxHash::from_raw(Hash::from_bytes(b"tx3"));

        let gossip = BlockHeaderNotification::new(
            make_header(BlockHeight::new(1)),
            BlockManifest::new(vec![tx1, tx2, tx3], vec![], vec![], vec![]),
            zero_sig(),
        );

        let all: Vec<TxHash> = gossip.manifest.tx_hashes().clone().into_inner();
        assert_eq!(all, vec![tx1, tx2, tx3]);
    }
}
