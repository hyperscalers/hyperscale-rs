//! Composite key type for the `state_history` column family.
//!
//! Layout: `[storage_key_bytes...][write_version_BE_8B]`
//!
//! The big-endian version suffix ensures that for a given storage key
//! prefix, entries sort in ascending lexicographic order on version —
//! enabling the forward seek used by historical reads to find the
//! smallest `write_version > V` for a key.

use crate::substate_key::SubstateKeyCodec;
use crate::typed_cf::DbCodec;

use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

const VERSION_LEN: usize = 8;

/// Key type for the versioned substates CF.
type VersionedKey = ((DbPartitionKey, DbSortKey), u64);

/// Codec for versioned substate keys: `substate_key_bytes ++ version_BE_8B`.
///
/// Composes [`SubstateKeyCodec`] (for the substate key portion) with a
/// big-endian u64 suffix (for the version). The version suffix preserves
/// lexicographic ordering so that for a given substate key prefix, versions
/// sort ascending — enabling efficient "find latest version <= N" scans.
#[derive(Default)]
pub(crate) struct VersionedSubstateKeyCodec;

impl DbCodec<VersionedKey> for VersionedSubstateKeyCodec {
    fn encode_to(&self, value: &VersionedKey, buf: &mut Vec<u8>) {
        let ((pk, sk), version) = value;
        SubstateKeyCodec.encode_to(&(pk.clone(), sk.clone()), buf);
        buf.extend_from_slice(&version.to_be_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> VersionedKey {
        assert!(
            bytes.len() >= VERSION_LEN,
            "versioned key must be at least {VERSION_LEN} bytes, got {}",
            bytes.len()
        );
        let key_len = bytes.len() - VERSION_LEN;
        let substate_key = SubstateKeyCodec.decode(&bytes[..key_len]);
        let version = u64::from_be_bytes(bytes[key_len..].try_into().unwrap());
        (substate_key, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key(partition_num: u8, sort_key: &[u8]) -> (DbPartitionKey, DbSortKey) {
        (
            DbPartitionKey {
                node_key: vec![0u8; 50], // 50-byte entity key
                partition_num,
            },
            DbSortKey(sort_key.to_vec()),
        )
    }

    #[test]
    fn round_trip() {
        let substate_key = make_test_key(1, b"sort_key");
        let version = 42u64;

        let encoded = VersionedSubstateKeyCodec.encode(&(substate_key.clone(), version));
        let ((decoded_pk, decoded_sk), decoded_version) =
            VersionedSubstateKeyCodec.decode(&encoded);

        assert_eq!(decoded_pk.partition_num, 1);
        assert_eq!(decoded_sk.0, b"sort_key");
        assert_eq!(decoded_version, version);
    }

    #[test]
    fn lexicographic_version_ordering() {
        let key = make_test_key(0, b"same_key");

        let buf1 = VersionedSubstateKeyCodec.encode(&(key.clone(), 1));
        let buf2 = VersionedSubstateKeyCodec.encode(&(key, 2));

        // Version 1 sorts before version 2 for the same storage key.
        assert!(buf1 < buf2);
    }

    #[test]
    #[should_panic(expected = "versioned key must be at least 8 bytes")]
    fn decode_too_short() {
        VersionedSubstateKeyCodec.decode(&[0; 7]);
    }
}
