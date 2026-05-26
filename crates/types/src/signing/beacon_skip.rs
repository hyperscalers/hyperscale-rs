//! Domain-separated signing for beacon-chain skip requests.
//!
//! Each active validator signs the pair `(anchor_hash, epoch_to_skip)`
//! under [`DOMAIN_SKIP_REQUEST`] to vote that the chain should abandon
//! `epoch_to_skip`. Aggregating ⌈2M/3⌉ + 1 active-pool signers over the
//! same pair produces a [`SkipEpochCert`](crate::SkipEpochCert)
//! authenticating the skip block.
//!
//! Domain separation here keeps a skip sig from being confused with a
//! PC vote, a VRF reveal, or any other BLS message reusing the same
//! key material.

use crate::{BeaconBlockHash, Epoch, NetworkDefinition};

/// Domain tag for individual skip-request signatures and for the
/// aggregate signature on the assembled
/// [`SkipEpochCert`](crate::SkipEpochCert).
pub const DOMAIN_SKIP_REQUEST: &[u8] = b"HYPERSCALE_SKIP_REQUEST_v1";

/// Build the canonical signing bytes for a skip request at
/// `(anchor_hash, epoch_to_skip)` under `network`.
///
/// Layout: `domain || network.id || anchor_hash (32) || epoch_to_skip_le (8)`.
/// All fields are fixed-width — no length prefixes needed.
#[must_use]
pub fn skip_request_message(
    network: &NetworkDefinition,
    anchor_hash: &BeaconBlockHash,
    epoch_to_skip: Epoch,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_SKIP_REQUEST.len() + 1 + 32 + 8);
    out.extend_from_slice(DOMAIN_SKIP_REQUEST);
    out.push(network.id);
    out.extend_from_slice(anchor_hash.as_bytes());
    out.extend_from_slice(&epoch_to_skip.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use crate::signing::DOMAIN_PC_VRF;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    /// Pins the byte layout. Any change to the encoder — field order,
    /// width, domain tag — fails this test. Cross-arch determinism
    /// rides on this layout being identical regardless of host
    /// `usize` width.
    #[test]
    fn skip_request_message_byte_layout_is_pinned() {
        let bytes = skip_request_message(&net(), &anchor(), Epoch::new(5));

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_SKIP_REQUEST);
        expected.push(net().id);
        expected.extend_from_slice(anchor().as_bytes());
        expected.extend_from_slice(&5u64.to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_SKIP_REQUEST.len() + 1 + 32 + 8);
    }

    #[test]
    fn skip_request_message_differs_across_epochs() {
        let a = skip_request_message(&net(), &anchor(), Epoch::new(5));
        let b = skip_request_message(&net(), &anchor(), Epoch::new(6));
        assert_ne!(a, b);
    }

    #[test]
    fn skip_request_message_differs_across_anchors() {
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"other"));
        let a = skip_request_message(&net(), &anchor(), Epoch::new(5));
        let b = skip_request_message(&net(), &other, Epoch::new(5));
        assert_ne!(a, b);
    }

    #[test]
    fn skip_request_message_differs_across_networks() {
        let mainnet = skip_request_message(&NetworkDefinition::mainnet(), &anchor(), Epoch::new(5));
        let stokenet =
            skip_request_message(&NetworkDefinition::stokenet(), &anchor(), Epoch::new(5));
        assert_ne!(mainnet, stokenet);
    }

    /// Domain separation: a skip sig must not collide with a VRF reveal
    /// (or any other beacon BLS message reusing the same key material) —
    /// distinct domain tags guarantee the prefixes diverge.
    #[test]
    fn skip_request_message_differs_from_other_beacon_domains() {
        let bytes = skip_request_message(&net(), &anchor(), Epoch::new(5));
        assert_ne!(&bytes[..DOMAIN_PC_VRF.len()], DOMAIN_PC_VRF);
    }
}
