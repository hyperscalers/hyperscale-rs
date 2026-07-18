//! Domain-separated signing for validator address announcements.

use blake3::Hasher;

use crate::NetworkDefinition;

/// Domain tag for validator address announcements.
///
/// Format: `VALIDATOR_ADDRESS` || `network.id` || `sequence` (8 bytes LE) ||
/// `H(peer_id, addresses)` (32 bytes)
///
/// Signed by a validator's BLS key over the libp2p peer id and listen
/// addresses it gossips for itself, so any node can authenticate a
/// `ValidatorId → (PeerId, addresses)` record — and dial the validator —
/// without a prior connection. The sequence orders announcements from the
/// same validator; consumers keep the highest.
pub const DOMAIN_VALIDATOR_ADDRESS: &[u8] = b"VALIDATOR_ADDRESS";

/// Build the signing message for a validator address announcement.
///
/// The variable-length peer id and address list fold into a blake3 digest,
/// each field length-framed so distinct `(peer_id, addresses)` splits can
/// never collide. The digest keeps the signed message fixed-size and safe
/// to reconstruct from unvalidated wire input.
#[must_use]
pub fn validator_address_message(
    network: &NetworkDefinition,
    peer_id_bytes: &[u8],
    addresses: &[Vec<u8>],
    sequence: u64,
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(&frame_len(peer_id_bytes.len()));
    hasher.update(peer_id_bytes);
    for addr in addresses {
        hasher.update(&frame_len(addr.len()));
        hasher.update(addr);
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(DOMAIN_VALIDATOR_ADDRESS.len() + 1 + 8 + 32);
    message.extend_from_slice(DOMAIN_VALIDATOR_ADDRESS);
    message.push(network.id);
    message.extend_from_slice(&sequence.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

/// Length-framing word for the digest input.
fn frame_len(len: usize) -> [u8; 8] {
    u64::try_from(len).expect("length fits u64").to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn deterministic_for_fixed_inputs() {
        let peer = b"peer-id-bytes";
        let addrs = vec![b"addr-one".to_vec(), b"addr-two".to_vec()];
        let msg1 = validator_address_message(&net(), peer, &addrs, 42);
        let msg2 = validator_address_message(&net(), peer, &addrs, 42);
        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_VALIDATOR_ADDRESS));
    }

    #[test]
    fn differs_per_sequence_and_content() {
        let peer = b"peer-id-bytes";
        let addrs = vec![b"addr-one".to_vec()];
        let base = validator_address_message(&net(), peer, &addrs, 1);
        assert_ne!(base, validator_address_message(&net(), peer, &addrs, 2));
        assert_ne!(
            base,
            validator_address_message(&net(), b"other-peer", &addrs, 1)
        );
        assert_ne!(
            base,
            validator_address_message(&net(), peer, &[b"addr-two".to_vec()], 1)
        );
    }

    #[test]
    fn length_framing_prevents_field_shifting() {
        // The same concatenated bytes split differently across fields must
        // not produce the same message.
        let a = validator_address_message(&net(), b"ab", &[b"cd".to_vec()], 1);
        let b = validator_address_message(&net(), b"abc", &[b"d".to_vec()], 1);
        let c = validator_address_message(&net(), b"a", &[b"b".to_vec(), b"cd".to_vec()], 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }
}
