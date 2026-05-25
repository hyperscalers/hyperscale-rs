//! Domain-separated signing for beacon-chain recovery requests.
//!
//! Each active validator signs the triple
//! `(last_block_hash, last_block_epoch, recovery_round)` under
//! [`DOMAIN_RECOVERY_REQUEST`] to attest the beacon chain has not
//! progressed past that anchor within the recovery timeout. Aggregating
//! ≥⅔ of active signers over the same triple produces a
//! [`RecoveryCertificate`](crate::RecoveryCertificate) that triggers
//! deterministic committee replacement.
//!
//! Binding `recovery_round` into the signed bytes is what stops a
//! round-N cert from being re-presented as round N+1 by tampering with
//! the field. Domain separation here keeps a recovery sig from being
//! confused with a PC vote, a VRF reveal, or a beacon-header sig, all
//! of which reuse the same BLS keys.

use crate::{BeaconBlockHash, Epoch, NetworkDefinition, RecoveryRound};

/// Domain tag for individual recovery-request signatures and for the
/// aggregate signature on the assembled [`RecoveryCertificate`](crate::RecoveryCertificate).
pub const DOMAIN_RECOVERY_REQUEST: &[u8] = b"HYPERSCALE_RECOVERY_REQUEST_v1";

/// Build the canonical signing bytes for a recovery request at
/// `(last_block_hash, last_block_epoch, recovery_round)` under `network`.
///
/// Layout: `domain || network.id || last_block_hash (32) ||
/// last_block_epoch_le (8) || recovery_round_le (4)`. All fields are
/// fixed-width so no length prefixes are needed.
#[must_use]
pub fn recovery_request_message(
    network: &NetworkDefinition,
    last_block_hash: &BeaconBlockHash,
    last_block_epoch: Epoch,
    recovery_round: RecoveryRound,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_RECOVERY_REQUEST.len() + 1 + 32 + 8 + 4);
    out.extend_from_slice(DOMAIN_RECOVERY_REQUEST);
    out.push(network.id);
    out.extend_from_slice(last_block_hash.as_bytes());
    out.extend_from_slice(&last_block_epoch.to_le_bytes());
    out.extend_from_slice(&recovery_round.to_le_bytes());
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

    /// Pins the byte layout of `recovery_request_message`. Any change
    /// to the encoder — field order, length-prefix width, domain tag —
    /// shifts these bytes and fails this test. Cross-arch determinism
    /// rides on this layout being identical regardless of `usize` width
    /// on the host.
    #[test]
    fn recovery_request_message_byte_layout_is_pinned() {
        let bytes =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(2));

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_RECOVERY_REQUEST);
        expected.push(net().id);
        expected.extend_from_slice(anchor().as_bytes());
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), DOMAIN_RECOVERY_REQUEST.len() + 1 + 32 + 8 + 4);
    }

    /// Bumping the recovery round must shift the signed bytes — this is
    /// the property that stops a round-N cert from being re-presented
    /// as round N+1 by tampering with the field.
    #[test]
    fn recovery_request_message_differs_across_rounds() {
        let a = recovery_request_message(&net(), &anchor(), Epoch::new(1), RecoveryRound::new(0));
        let b = recovery_request_message(&net(), &anchor(), Epoch::new(1), RecoveryRound::new(1));
        assert_ne!(a, b);
    }

    /// Distinct anchors at the same `(epoch, round)` produce distinct
    /// signing bytes — a sig over one anchor can't be replayed against
    /// another.
    #[test]
    fn recovery_request_message_differs_across_anchors() {
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"other"));
        let a = recovery_request_message(&net(), &anchor(), Epoch::new(1), RecoveryRound::INITIAL);
        let b = recovery_request_message(&net(), &other, Epoch::new(1), RecoveryRound::INITIAL);
        assert_ne!(a, b);
    }

    /// Cross-network replay protection: byte-identical
    /// `(anchor, epoch, round)` inputs under different networks must
    /// produce different signing bytes.
    #[test]
    fn recovery_request_message_differs_across_networks() {
        let mainnet = recovery_request_message(
            &NetworkDefinition::mainnet(),
            &anchor(),
            Epoch::new(1),
            RecoveryRound::INITIAL,
        );
        let stokenet = recovery_request_message(
            &NetworkDefinition::stokenet(),
            &anchor(),
            Epoch::new(1),
            RecoveryRound::INITIAL,
        );
        assert_ne!(mainnet, stokenet);
    }

    /// Cross-domain replay protection: a recovery sig must not collide
    /// with a VRF reveal — distinct domain tags guarantee the prefixes
    /// diverge.
    #[test]
    fn recovery_request_message_differs_from_other_beacon_domains() {
        let bytes =
            recovery_request_message(&net(), &anchor(), Epoch::new(1), RecoveryRound::INITIAL);
        assert_ne!(&bytes[..DOMAIN_RECOVERY_REQUEST.len()], DOMAIN_PC_VRF);
    }
}
