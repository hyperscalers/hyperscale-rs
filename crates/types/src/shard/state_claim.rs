//! What a block says about a counterpart's cells.
//!
//! A leg's ledger asks a silent counterpart whether it took what the leg
//! issued: a core's committed cell, a delivery's claim, a core
//! consumer's claim. What is done with the answer — a record offered, a
//! reclaim or a retirement composed — is composed from the ledger, so
//! the answer has to be the chain's rather than a replica's, or the
//! composition splits. That is what a block carries: the claim, one
//! reading per cell against a commit-proven header.
//!
//! The proof for it does not travel here. Every validator probes, not
//! only the proposer, so the multiproof a voter checks a claim against
//! is one it fetched itself, and a voter with none defers until its own
//! fetch lands. Carrying the bytes to a committee that mostly holds
//! them already costs a block megabytes to save a fetch nobody makes.

use hyperscale_hbor::{Capped, Hbor};

use crate::{Anchor, Inclusion, MAX_PROOFS_PER_QUERY, SubstateKey};

/// One anchor's answers: what a commit-proven header says about each
/// cell asked of it.
///
/// The anchor names the shard, the height, the root the reading was
/// taken against and the block's clock, every term of which a voter
/// holds to the commit-proven header it has for the height. The cells
/// are sorted and without repeats, so the claim has one form and a
/// validator checking it walks the order it would build.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct StateClaim {
    /// The commit-proven state the readings were taken against.
    pub anchor: Anchor,
    /// Each cell asked about, with what the anchor's root says of it.
    pub cells: Capped<Vec<(SubstateKey, Inclusion)>, MAX_PROOFS_PER_QUERY>,
}

impl StateClaim {
    /// A claim over `cells`, in the one order it may carry them.
    #[must_use]
    pub fn new(anchor: Anchor, cells: impl IntoIterator<Item = (SubstateKey, Inclusion)>) -> Self {
        let mut cells: Vec<(SubstateKey, Inclusion)> = cells.into_iter().collect();
        cells.sort_unstable();
        cells.dedup_by_key(|(key, _)| *key);
        // A reading list past the cap is one no claim may carry, and an
        // empty claim is one `is_well_formed` refuses — so an over-cap
        // input lands where it landed before, refused rather than
        // trimmed into a different claim.
        let cells = Capped::new(cells).unwrap_or_default();
        Self { anchor, cells }
    }

    /// Whether the claim is in the one form it may take: sorted cells,
    /// one reading per key, naming something, and no more than the cap.
    ///
    /// A claim naming no cell answers nothing and would cost a block a
    /// leaf for it, so it is not well-formed rather than merely
    /// pointless.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        !self.cells.is_empty() && self.cells.windows(2).all(|pair| pair[0].0 < pair[1].0)
    }

    /// The cells this claim answers for.
    #[must_use]
    pub fn keys(&self) -> Vec<SubstateKey> {
        self.cells.iter().map(|(key, _)| *key).collect()
    }

    /// What the claim says of `key`, if it says anything.
    #[must_use]
    pub fn reading(&self, key: SubstateKey) -> Option<Inclusion> {
        self.cells
            .iter()
            .find(|(asked, _)| *asked == key)
            .map(|(_, inclusion)| *inclusion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Address, AddressClass, BlockHeight, Hash, LocalKey, ShardId, StateRoot, WeightedTimestamp,
    };

    fn key(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    fn anchor() -> Anchor {
        Anchor {
            shard: ShardId::ROOT,
            height: BlockHeight::new(3),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
            ts: WeightedTimestamp::ZERO,
        }
    }

    /// One form: whatever order a caller offers, the claim it builds is
    /// the claim every other builder would have produced.
    #[test]
    fn a_claim_is_built_in_its_canonical_order() {
        let present = Inclusion::Present([7u8; 32]);
        let jumbled = StateClaim::new(
            anchor(),
            [
                (key(3), Inclusion::Absent),
                (key(1), present),
                (key(3), Inclusion::Absent),
                (key(2), present),
            ],
        );
        let ordered = StateClaim::new(
            anchor(),
            [
                (key(1), present),
                (key(2), present),
                (key(3), Inclusion::Absent),
            ],
        );
        assert_eq!(jumbled, ordered);
        assert!(jumbled.is_well_formed());
        assert_eq!(jumbled.reading(key(1)), Some(present));
        assert_eq!(jumbled.reading(key(3)), Some(Inclusion::Absent));
        assert_eq!(jumbled.reading(key(4)), None);
    }

    /// Empty, repeating, or out of order is a second form of the same
    /// claim, or no claim at all.
    #[test]
    fn a_claim_out_of_its_form_is_refused() {
        let over = |cells: Vec<(SubstateKey, Inclusion)>| StateClaim {
            anchor: anchor(),
            cells: Capped::new(cells).expect("a list written out in a test"),
        };
        assert!(!over(Vec::new()).is_well_formed());
        assert!(
            !over(vec![
                (key(2), Inclusion::Absent),
                (key(1), Inclusion::Absent)
            ])
            .is_well_formed()
        );
        assert!(
            !over(vec![
                (key(1), Inclusion::Absent),
                (key(1), Inclusion::Absent)
            ])
            .is_well_formed()
        );
    }
}
