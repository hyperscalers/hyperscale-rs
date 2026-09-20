//! What a block offers again of a crossing its consumer never claimed.
//!
//! A crossing an outbound leg consumes is the consumer's from the moment
//! the core commits it, and the record standing for it is claimed by the
//! shard holding the consumer's prefix. That shard learns the record
//! exists only from a bundle, and a bundle is admitted against the
//! `provision_tx_roots` of the block it names — so a crossing whose one
//! offer went missing can only be offered again by a block whose own
//! header promises it.
//!
//! This is what such a block carries: the consumer owed the claim, the
//! transaction the crossing belongs to, and the record cells the bundle
//! is built from. Everything else the offer needs — the height to build
//! at, the root to prove against — is the offering block's own.

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_types::MAX_CROSSINGS_PER_TX;

use crate::{ShardId, SubstateKey, TxHash};

/// One consumer's outstanding crossings in one transaction, offered
/// again off the block that carries this.
///
/// The cells are the producer's own record cells, sorted and without
/// repeats, so the bundle built from an offer has one form whoever
/// builds it — the proposer broadcasting it and a peer answering a
/// fetch for it alike.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct CrossingReoffer {
    /// The shard holding the prefix of the claim these records are owed
    /// to, resolved when the offer was composed.
    pub target: ShardId,
    /// The transaction whose crossings these are.
    pub tx_hash: TxHash,
    /// The record cells the target's delivery consumes.
    pub records: Capped<Vec<SubstateKey>, MAX_CROSSINGS_PER_TX>,
}

impl CrossingReoffer {
    /// An offer of `records` to `target`, in the one order it may carry
    /// them.
    #[must_use]
    pub fn new(
        target: ShardId,
        tx_hash: TxHash,
        records: impl IntoIterator<Item = SubstateKey>,
    ) -> Self {
        let mut records: Vec<SubstateKey> = records.into_iter().collect();
        records.sort_unstable();
        records.dedup();
        // A record list past the cap is one no offer may carry, and an
        // empty offer is one `is_well_formed` refuses — so an over-cap
        // input lands where it landed before, refused rather than
        // trimmed into a different offer.
        let records = Capped::new(records).unwrap_or_default();
        Self {
            target,
            tx_hash,
            records,
        }
    }

    /// Whether the offer is in the one form it may take: sorted records,
    /// one entry per cell, naming something, and no more than the cap.
    ///
    /// An offer naming no cell promises a bundle with nothing in it,
    /// which a consumer would admit and learn nothing from, so it is not
    /// well-formed rather than merely pointless.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.records.is_empty() && self.records.windows(2).all(|pair| pair[0] < pair[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, AddressClass, Hash, LocalKey};

    fn key(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 8]))
    }

    #[test]
    fn an_offer_carries_its_records_in_one_order() {
        let jumbled =
            CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), [key(9), key(2), key(9), key(5)]);
        assert!(jumbled.is_well_formed());
        assert_eq!(jumbled.records.as_slice(), &[key(2), key(5), key(9)]);
        assert_eq!(
            jumbled,
            CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), [key(5), key(9), key(2)]),
        );
    }

    #[test]
    fn an_offer_naming_nothing_is_refused() {
        assert!(!CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), []).is_well_formed());
    }

    #[test]
    fn an_offer_past_the_cap_is_refused_rather_than_trimmed() {
        let over = CrossingReoffer::new(
            ShardId::leaf(1, 1),
            tx(1),
            (0..=MAX_CROSSINGS_PER_TX).map(|at| {
                let mut owner = [0u8; 31];
                owner[..8].copy_from_slice(&(at as u64).to_be_bytes());
                SubstateKey {
                    owner: Address::new(owner, AddressClass::Component),
                    local: LocalKey([0u8; 16]),
                }
            }),
        );
        assert!(!over.is_well_formed(), "an over-cap offer names nothing");
    }
}
