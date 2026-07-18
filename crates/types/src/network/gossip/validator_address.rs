//! Validator address announcement for by-identity dialing.

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{
    Bls12381G2Signature, MessageClass, NetworkDefinition, NetworkMessage, ShardId, Signed,
    ValidatorId, validator_address_message,
};

/// Maximum addresses one announcement may carry. A validator announces its
/// listen and externally observed addresses — a handful; the cap bounds
/// decode and signature-verify work on unauthenticated input.
pub const MAX_ANNOUNCED_ADDRESSES: usize = 16;

/// Maximum encoded length of one announced multiaddr.
pub const MAX_ANNOUNCED_ADDRESS_BYTES: usize = 256;

/// Maximum encoded length of the announced libp2p peer id.
pub const MAX_ANNOUNCED_PEER_ID_BYTES: usize = 64;

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
/// libp2p types, and the network adapter parses and validates them at
/// ingest against the `MAX_ANNOUNCED_*` caps.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ValidatorAddressGossip {
    /// The validator this record names — also its signer: address records
    /// are only ever self-announced.
    pub validator: ValidatorId,
    /// libp2p peer id bytes the validator currently binds as.
    pub peer_id: Vec<u8>,
    /// Encoded multiaddrs the peer can be dialed at.
    pub addresses: Vec<Vec<u8>>,
    /// Announce ordering: consumers keep the record with the highest
    /// sequence per validator, so a re-announce after a peer-id or address
    /// change supersedes older records everywhere.
    pub sequence: u64,
    /// BLS signature over the domain-separated signing message, by
    /// `validator`.
    pub signature: Bls12381G2Signature,
}

impl Signed for ValidatorAddressGossip {
    fn signer(&self) -> ValidatorId {
        self.validator
    }

    fn signature(&self) -> &Bls12381G2Signature {
        &self.signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        validator_address_message(network, &self.peer_id, &self.addresses, self.sequence)
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
    use super::*;
    use crate::{Bls12381G1PublicKey, SignedContext, bls_keypair_from_seed};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signed_record(sequence: u64) -> (ValidatorAddressGossip, Bls12381G1PublicKey) {
        let key = bls_keypair_from_seed(&[7u8; 32]);
        let peer_id = b"peer-id".to_vec();
        let addresses = vec![b"addr".to_vec()];
        let message = validator_address_message(&net(), &peer_id, &addresses, sequence);
        let gossip = ValidatorAddressGossip {
            validator: ValidatorId::new(3),
            peer_id,
            addresses,
            sequence,
            signature: key.sign_v1(&message),
        };
        (gossip, key.public_key())
    }

    #[test]
    fn signature_roundtrip_verifies() {
        let (gossip, public_key) = signed_record(9);
        let network = net();
        let ctx = SignedContext {
            network: &network,
            public_key: &public_key,
        };
        assert!(gossip.verify_signature(&ctx).is_ok());
    }

    #[test]
    fn tampered_addresses_fail_verification() {
        let (mut gossip, public_key) = signed_record(9);
        gossip.addresses.push(b"injected".to_vec());
        let network = net();
        let ctx = SignedContext {
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
