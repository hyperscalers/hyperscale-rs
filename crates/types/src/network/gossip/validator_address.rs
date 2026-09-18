//! Validator address announcement for by-identity dialing.

use hyperscale_hbor::{Bytes, Capped, Hbor};

use crate::network::{GossipMessage, TopicScope};
use crate::{
    ConsensusSignature, MessageClass, NetworkDefinition, NetworkMessage, ShardId, Signed,
    ValidatorAddressMessage, ValidatorId, signed_bytes,
};

/// Maximum addresses one announcement may carry. A validator announces its
/// listen and externally observed addresses — a handful; the cap bounds
/// decode and signature-verify work on unauthenticated input.
pub const MAX_ANNOUNCED_ADDRESSES: usize = 16;

/// Maximum encoded length of one announced multiaddr.
pub const MAX_ANNOUNCED_ADDRESS_BYTES: usize = 256;

/// Maximum encoded length of the announced libp2p peer id.
pub const MAX_ANNOUNCED_PEER_ID_BYTES: usize = 64;

/// The addresses one announcement carries: each a dialable multiaddr no
/// longer than a receiver admits, and no more of them than one record
/// names.
pub type AnnouncedAddresses =
    Capped<Vec<Bytes<MAX_ANNOUNCED_ADDRESS_BYTES>>, MAX_ANNOUNCED_ADDRESSES>;

/// Gossips a validator's own libp2p peer id and network addresses globally.
///
/// Every node caches these records in a `ValidatorId → (PeerId, addresses)`
/// book, which is what lets it dial a committee-relevant validator it has
/// never connected to — a halt-recovery committee drawn cold from the pool
/// being the canonical consumer. Unicast delivery (provisions, execution
/// certificates) resolves peers only through live validator-bind entries;
/// without this book there is no path from a `ValidatorId` to a dialable
/// address for a never-connected peer.
///
/// The peer id and addresses travel as raw bytes: this crate carries no
/// libp2p types, and the network adapter parses them at ingest. Their
/// caps are the types', so a record past one is a record that does not
/// decode.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ValidatorAddressGossip {
    /// The validator this record names — also its signer: address records
    /// are only ever self-announced.
    pub validator: ValidatorId,
    /// libp2p peer id bytes the validator currently binds as.
    pub peer_id: Bytes<MAX_ANNOUNCED_PEER_ID_BYTES>,
    /// Encoded multiaddrs the peer can be dialed at.
    pub addresses: AnnouncedAddresses,
    /// Announce ordering: consumers keep the record with the highest
    /// sequence per validator, so a re-announce after a peer-id or address
    /// change supersedes older records everywhere.
    pub sequence: u64,
    /// Signature over the domain-separated signing message, by
    /// `validator`.
    pub signature: ConsensusSignature,
}

impl Signed for ValidatorAddressGossip {
    fn signer(&self) -> ValidatorId {
        self.validator
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &ValidatorAddressMessage::new(&self.peer_id, &self.addresses, self.sequence),
            network,
        )
    }
}

impl NetworkMessage for ValidatorAddressGossip {
    fn message_type_id() -> &'static str {
        "validator.address"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl GossipMessage for ValidatorAddressGossip {
    const SCOPE: TopicScope = TopicScope::Global;

    fn source_shard(&self) -> Option<ShardId> {
        None
    }

    fn dedup_key(&self) -> Option<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // One dispatch per (validator, sequence): mesh copies of the same
        // announce collapse regardless of propagation path.
        let mut hasher = DefaultHasher::new();
        self.validator.hash(&mut hasher);
        self.sequence.hash(&mut hasher);
        Some(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::{ConsensusPublicKey, SignedContext};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signed_record(sequence: u64) -> (ValidatorAddressGossip, ConsensusPublicKey) {
        let key = BlsSigner::from_seed(&[7u8; 32]);
        let peer_id = Bytes::new(b"peer-id".to_vec()).expect("under the peer id cap");
        let addresses = Capped::from_array([Bytes::from_array(*b"addr")]);
        let message = signed_bytes(
            &ValidatorAddressMessage::new(&peer_id, &addresses, sequence),
            &net(),
        );
        let gossip = ValidatorAddressGossip {
            validator: ValidatorId::new(3),
            peer_id,
            addresses,
            sequence,
            signature: key.sign(&message).expect("sign"),
        };
        (gossip, key.public_key())
    }

    #[test]
    fn signature_roundtrip_verifies() {
        let (gossip, public_key) = signed_record(9);
        let network = net();
        let ctx = SignedContext {
            verifier: &BlsVerifier,
            network: &network,
            public_key: &public_key,
        };
        assert!(gossip.verify_signature(&ctx).is_ok());
    }

    #[test]
    fn tampered_addresses_fail_verification() {
        let (mut gossip, public_key) = signed_record(9);
        gossip
            .addresses
            .push(Bytes::from_array(*b"injected"))
            .expect("under the address cap");
        let network = net();
        let ctx = SignedContext {
            verifier: &BlsVerifier,
            network: &network,
            public_key: &public_key,
        };
        assert!(gossip.verify_signature(&ctx).is_err());
    }

    #[test]
    fn dedup_key_tracks_validator_and_sequence() {
        let (a, _) = signed_record(9);
        let (same, _) = signed_record(9);
        let (newer, _) = signed_record(10);
        assert_eq!(a.dedup_key(), same.dedup_key());
        assert_ne!(a.dedup_key(), newer.dedup_key());
    }
}
