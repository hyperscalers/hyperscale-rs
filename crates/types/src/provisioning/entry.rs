//! Per-transaction state entries within a provision.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MAX_STATE_ENTRIES_PER_TX, SubstateEntry, TxHash};

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction and what state it touched on the source
/// shard. Nothing names what the receiver needs: the receiver derives
/// that from the envelope, so a bundle carries values and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ProvisionEntry {
    /// Hash of the transaction.
    pub tx_hash: TxHash,

    /// The state entries this transaction touched on the source shard.
    /// Empty for an engagement echo — a counterpart with nothing to serve
    /// still owes the payer its commitment of the transaction.
    pub entries: Capped<Vec<SubstateEntry>, MAX_STATE_ENTRIES_PER_TX>,
}

impl ProvisionEntry {
    /// Build a `ProvisionEntry`, canonicalising `entries` by storage key.
    ///
    /// Both transports (gossip emit and fetch serve) construct entries
    /// from the same logical inputs but through different iteration
    /// paths; canonicalising here rather than at each call site means a
    /// future ordering leak can't slip past one caller.
    #[must_use]
    pub fn new(
        tx_hash: TxHash,
        mut entries: Capped<Vec<SubstateEntry>, MAX_STATE_ENTRIES_PER_TX>,
    ) -> Self {
        entries.sort_by_key(|entry| entry.key);
        Self { tx_hash, entries }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        Bytes, DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::test_utils::test_prefix;
    use crate::{Hash, LEAF_KEY_BYTES};

    fn sample_entry(seed: u8) -> SubstateEntry {
        SubstateEntry::test_entry(test_prefix(seed), b"sort", Some(Bytes::from_array([seed])))
    }

    #[test]
    fn hbor_roundtrip() {
        let entry = ProvisionEntry::new(
            TxHash::from(Hash::from_bytes(b"tx")),
            Capped::from_array([sample_entry(1), sample_entry(2)]),
        );
        let bytes = hbor_to_vec(&entry).unwrap();
        let decoded: ProvisionEntry = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// Both transports build an entry from the same logical read set but
    /// walk it in different orders; a bundle is only comparable across
    /// them if construction canonicalises.
    #[test]
    fn construction_canonicalises_entry_order() {
        let tx_hash = TxHash::from(Hash::from_bytes(b"tx"));
        let forward = ProvisionEntry::new(
            tx_hash,
            Capped::from_array([sample_entry(1), sample_entry(2)]),
        );
        let reverse = ProvisionEntry::new(
            tx_hash,
            Capped::from_array([sample_entry(2), sample_entry(1)]),
        );
        assert_eq!(forward, reverse);
        assert_eq!(
            hbor_to_vec(&forward).unwrap(),
            hbor_to_vec(&reverse).unwrap()
        );
    }

    #[test]
    fn decode_rejects_oversized_entries() {
        let mut buf = hbor_to_vec(&TxHash::from(Hash::from_bytes(b"tx"))).unwrap();
        varint::write(&mut buf, MAX_STATE_ENTRIES_PER_TX + 1).unwrap();
        // Enough input to pay for the claimed count at an entry's minimum
        // width (the leaf key plus the value's None tag), so the entry cap
        // is the check that refuses.
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_STATE_ENTRIES_PER_TX + 1) * (LEAF_KEY_BYTES + 1),
        ));
        let err = hbor_from_slice::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_STATE_ENTRIES_PER_TX && actual == MAX_STATE_ENTRIES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_the_node_set_shape() {
        // Hand-roll a wire layout carrying entries plus target and owned
        // node lists, to confirm a peer can't ship node sets the receiver
        // derives for itself.
        let entry = ProvisionEntry::new(
            TxHash::from(Hash::from_bytes(b"tx")),
            Capped::from_array([]),
        );
        let mut buf = hbor_to_vec(&entry).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&Vec::<[u8; 16]>::new()).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&Vec::<[u8; 16]>::new()).unwrap());
        let err = hbor_from_slice::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::TrailingBytes { .. }));
    }
}
