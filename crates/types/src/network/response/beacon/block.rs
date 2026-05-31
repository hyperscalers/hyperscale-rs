//! Beacon block gap-fill sync response.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{CertifiedBeaconBlock, MessageClass, NetworkMessage, Verifiable};

/// Response to a
/// [`GetBeaconBlockRequest`](crate::network::request::beacon::GetBeaconBlockRequest).
///
/// Carries the committed block if the responder has it, otherwise
/// `None` — the requester treats `None` as "this peer doesn't have it;
/// try another." Wire decode lands the wrapper as
/// [`Verifiable::Unverified`]; the requester verifies the cert before
/// applying.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBeaconBlockResponse {
    /// The committed block, if the responder had it.
    pub block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
}

impl GetBeaconBlockResponse {
    /// Build a response from an optional block.
    #[must_use]
    pub const fn new(block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>) -> Self {
        Self { block }
    }

    /// Found response — the responder had the block.
    #[must_use]
    pub const fn found(block: Arc<Verifiable<CertifiedBeaconBlock>>) -> Self {
        Self { block: Some(block) }
    }

    /// Empty response — the responder didn't have the block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { block: None }
    }
}

impl NetworkMessage for GetBeaconBlockResponse {
    fn message_type_id() -> &'static str {
        "beacon.block.response"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{
        BeaconBlock, BeaconBlockHash, BeaconCert, Bls12381G2Signature, Epoch, Hash, SignerBitfield,
        SkipEpochCert,
    };

    fn sample_block() -> Arc<Verifiable<CertifiedBeaconBlock>> {
        let block = BeaconBlock::skip(
            Epoch::new(5),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
        );
        let cert = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(5),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        );
        Arc::new(Verifiable::from(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Skip(cert),
        )))
    }

    #[test]
    fn sbor_round_trip_found() {
        let resp = GetBeaconBlockResponse::found(sample_block());
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetBeaconBlockResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn sbor_round_trip_not_found() {
        let resp = GetBeaconBlockResponse::not_found();
        let bytes = basic_encode(&resp).unwrap();
        let decoded: GetBeaconBlockResponse = basic_decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn class_is_recovery() {
        assert_eq!(GetBeaconBlockResponse::class(), MessageClass::Recovery);
    }
}
