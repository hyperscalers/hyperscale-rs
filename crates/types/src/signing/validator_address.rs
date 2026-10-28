//! Signing message for validator address announcement gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::Hash;
use crate::network::gossip::ENDPOINT_ID_LEN;
use crate::signing::NetworkId;

/// What a validator address announcement's signature covers: the
/// announcement sequence number plus a digest of the endpoint id and
/// addresses.
///
/// The digest keeps the signed message fixed-width while binding the
/// signature to the specific announcement contents.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-validator-address-v1", signing_context = NetworkId)]
pub struct ValidatorAddressMessage {
    /// Monotonic announcement sequence — receivers keep the highest.
    pub(crate) sequence: u64,
    /// Digest over the endpoint id and the length-framed addresses.
    pub(crate) content_digest: Hash,
}

impl ValidatorAddressMessage {
    /// Assemble the message an address announcement signs.
    #[must_use]
    pub fn new(
        endpoint_id: &[u8; ENDPOINT_ID_LEN],
        addresses: &[impl AsRef<[u8]>],
        sequence: u64,
    ) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(endpoint_id);
        for addr in addresses {
            let addr = addr.as_ref();
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
