//! Standalone skip-cert gossip — helps late-joining nodes.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, SkipEpochCert};

/// Broadcasts an assembled [`SkipEpochCert`] across the active pool.
///
/// The cert is independently useful for late-joining or syncing nodes
/// that didn't observe the underlying [`SkipRequest`](crate::SkipRequest)s.
/// Multiple valid certs (different signer subsets) at the same
/// `(anchor_hash, epoch_to_skip)` all authenticate the same block
/// hash — adoption converges via the wrapper's
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock).
///
/// `MessageClass::Consensus` — skip cert delivery unblocks adoption.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipCertGossip {
    /// The assembled skip cert.
    pub cert: Arc<SkipEpochCert>,
}

impl SkipCertGossip {
    /// Wrap a [`SkipEpochCert`] for gossip broadcast.
    #[must_use]
    pub fn new(cert: impl Into<Arc<SkipEpochCert>>) -> Self {
        Self { cert: cert.into() }
    }

    /// Get the inner cert.
    #[must_use]
    pub fn cert(&self) -> &SkipEpochCert {
        &self.cert
    }

    /// Consume and return the inner cert.
    #[must_use]
    pub fn into_cert(self) -> Arc<SkipEpochCert> {
        self.cert
    }
}

impl NetworkMessage for SkipCertGossip {
    fn message_type_id() -> &'static str {
        "beacon.skip_cert"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for SkipCertGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use sbor::prelude::*;

    use super::*;
    use crate::{BeaconBlockHash, Bls12381G2Signature, Epoch, Hash, SignerBitfield, SkipEpochCert};

    fn sample_cert() -> SkipEpochCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let g = SkipCertGossip::new(sample_cert());
        let bytes = basic_encode(&g).unwrap();
        let decoded: SkipCertGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(SkipCertGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(SkipCertGossip::SCOPE, TopicScope::Global));
    }
}
