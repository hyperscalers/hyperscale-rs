//! Substate pairs shipped between shards: provision entries and
//! snap-sync leaves, both keyed for direct lookup at the receiver.

use hyperscale_hbor::{Bytes, Hbor};
use hyperscale_vm_types::MAX_CELL_VALUE_LEN;

#[cfg(any(test, feature = "test-utils"))]
use crate::Address;
use crate::{Hash, SubstateKey};

/// One live substate as a proven pair: the key — its JMT leaf key by
/// identity — and the raw value behind it.
///
/// The snap-sync unit, on the wire and through staging: a verifier
/// trusts none of it bare — the key's own 48 bytes must prove into the
/// shard's attested `state_root` via a range proof whose claimed value
/// hash must equal the hash of `value`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SubstateLeaf {
    /// The substate's key — its JMT leaf key by identity.
    pub key: SubstateKey,
    /// The raw substate value, bounded like a provisioned entry's.
    pub value: Bytes<MAX_CELL_VALUE_LEN>,
}

/// A state entry shipped by key for direct lookup at the receiving shard.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SubstateEntry {
    /// The substate's key — its JMT leaf and storage key in one.
    pub key: SubstateKey,

    /// The raw substate value (`None` if deleted/doesn't exist).
    pub value: Option<Bytes<MAX_CELL_VALUE_LEN>>,
}

impl SubstateEntry {
    /// Create a new substate entry.
    #[must_use]
    pub const fn new(key: SubstateKey, value: Option<Bytes<MAX_CELL_VALUE_LEN>>) -> Self {
        Self { key, value }
    }

    /// Compute hash of this entry for signing/verification.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.key.to_bytes());

        match &self.value {
            Some(value_bytes) => {
                let value_hash = Hash::from_bytes(value_bytes);
                data.extend_from_slice(value_hash.as_bytes());
            }
            None => {
                data.extend_from_slice(&[0u8; 32]); // ZERO hash for deletion
            }
        }

        Hash::from_bytes(&data)
    }

    /// Create a test entry from an owner prefix and a local half
    /// zero-padded from `local`, so a fixture names a cell by a short
    /// seed.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_entry(
        owner: Address,
        local: &[u8],
        value: Option<Bytes<MAX_CELL_VALUE_LEN>>,
    ) -> Self {
        use hyperscale_vm_types::LocalKey;
        let mut half = [0u8; 16];
        let n = local.len().min(16);
        half[..n].copy_from_slice(&local[..n]);
        Self::new(
            SubstateKey {
                owner,
                local: LocalKey(half),
            },
            value,
        )
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::test_utils::{test_key, test_prefix};

    #[test]
    fn test_substate_entry_hash() {
        let entry = SubstateEntry::test_entry(
            test_prefix(1),
            b"key",
            Some(Bytes::new(b"value".to_vec()).expect("a list written out in a test")),
        );

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hbor_roundtrip_some_value() {
        let entry =
            SubstateEntry::test_entry(test_prefix(7), b"sort", Some(Bytes::from_array([9u8; 128])));
        let bytes = hbor_to_vec(&entry).unwrap();
        let decoded: SubstateEntry = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn hbor_roundtrip_none_value() {
        let entry = SubstateEntry::test_entry(test_prefix(7), b"sort", None);
        let bytes = hbor_to_vec(&entry).unwrap();
        let decoded: SubstateEntry = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// The value cap reaches through the `Option`: an oversized value
    /// rejects at decode before allocation.
    #[test]
    fn decode_rejects_oversized_value() {
        let mut buf = test_key(3).to_bytes().to_vec(); // the fixed-width key
        buf.push(1); // Some
        varint::write(&mut buf, MAX_CELL_VALUE_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_CELL_VALUE_LEN + 1));
        let err = hbor_from_slice::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_CELL_VALUE_LEN && actual == MAX_CELL_VALUE_LEN + 1
        ));
    }
}
