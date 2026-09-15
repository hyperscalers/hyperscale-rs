//! Signing message for validator address announcement gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::Hash;
use crate::signing::NetworkId;

/// What a validator address announcement's signature covers: the
/// announcement sequence number plus a digest of the peer id and
/// addresses.
///
/// The digest keeps the signed message fixed-width while binding the
/// signature to the specific announcement contents.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-validator-address-v1", signing_context = NetworkId)]
pub struct ValidatorAddressMessage {
    /// Monotonic announcement sequence — receivers keep the highest.
    pub(crate) sequence: u64,
    /// Digest over the length-framed peer id and addresses.
    pub(crate) content_digest: Hash,
}

impl ValidatorAddressMessage {
    /// Assemble the message an address announcement signs.
    #[must_use]
    pub fn new(peer_id_bytes: &[u8], addresses: &[Vec<u8>], sequence: u64) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&frame_len(peer_id_bytes.len()));
        hasher.update(peer_id_bytes);
        for addr in addresses {
            hasher.update(&frame_len(addr.len()));
            hasher.update(addr);
        }
        Self {
            sequence,
            content_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

fn frame_len(len: usize) -> [u8; 8] {
    u64::try_from(len).expect("length fits u64").to_le_bytes()
}
