//! What a block offers again of a crossing its consumer never claimed.
//!
//! A crossing an outbound leg consumes is the consumer's from the moment
//! the core commits it, and the record standing for it reaches that
//! consumer in a bundle.
//!
//! The consumer is not in the dark about what it waits for: its member
//! files a crossing requirement naming the source shard and the record
//! cell, so it could name the bundle it is missing. Naming it is not
//! enough to ask for it. A bundle is admitted only against the
//! `provision_tx_roots` of the block it names — the entry there is what
//! says the source promised this target that exact set, and it is what
//! the completeness check reads — so one served off a block promising
//! nothing is refused whoever asked for it. A crossing whose one offer
//! went missing can therefore only be offered again by a block whose own
//! header promises it, which is what this is.
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
    /// them, or `None` where `records` is not a set an offer may carry.
    ///
    /// Nothing and more than the cap are both refused rather than
    /// trimmed: an offer promises a bundle built from exactly these
    /// cells, so one built from some of them is a different offer and
    /// one built from none promises a bundle with nothing in it.
    #[must_use]
    pub fn new(
        target: ShardId,
        tx_hash: TxHash,
        records: impl IntoIterator<Item = SubstateKey>,
    ) -> Option<Self> {
        let mut records: Vec<SubstateKey> = records.into_iter().collect();
        records.sort_unstable();
        records.dedup();
        if records.is_empty() {
            return None;
        }
        Some(Self {
            target,
            tx_hash,
            records: Capped::new(records).ok()?,
        })
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
            CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), [key(9), key(2), key(9), key(5)])
                .expect("a set inside the cap");
        assert!(jumbled.is_well_formed());
        assert_eq!(jumbled.records.as_slice(), &[key(2), key(5), key(9)]);
        assert_eq!(
            Some(jumbled),
            CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), [key(5), key(9), key(2)]),
        );
    }

    /// Neither end of the range an offer may carry is trimmed into a
    /// different offer: an offer promises a bundle built from exactly
    /// the cells it names.
    #[test]
    fn an_offer_naming_nothing_or_more_than_the_cap_is_refused() {
        assert_eq!(CrossingReoffer::new(ShardId::leaf(1, 1), tx(1), []), None);
        assert_eq!(
            CrossingReoffer::new(
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
            ),
            None,
        );
    }
}
