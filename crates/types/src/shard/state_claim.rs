//! What a block says about a counterpart's cells, and the proof of it.
//!
//! A leg's ledger asks a silent counterpart whether it took what the leg
//! issued: a core's committed cell, a delivery's claim, a core
//! consumer's claim. What is done with the answer — a record offered, a
//! reclaim or a retirement composed — is composed from the ledger, so
//! the answer has to be the chain's rather than a replica's, or the
//! composition splits. That is what a block carries: the claim, one
//! reading per cell against a commit-proven header, and the multiproof
//! the readings were taken from.
//!
//! The proof travels with the claim so that the claim is checkable from
//! the block alone. Every replica walks it at admission under the
//! anchor's root, so a bad proof refuses the block on every replica
//! alike, and a voter never holds a reading to a fetch of its own. What
//! a voter still holds for itself is the anchor: whether the header the
//! claim names is one it commit-proved is the vote fence's question.
//! The proof is over exactly the keys the claim reads, and the section
//! that carries claims is spent by the byte, proof and values included.
//!
//! A reading may carry the cell's value. A crossing record reaches its
//! consumer this way: the bytes ride beside the key, and `verify` holds
//! them to the presence the proof reconstructs, so no hash travels with
//! them and none is trusted.

use hyperscale_hbor::{Bytes, Capped, Hbor};

use crate::state_key::jmt_value_hash;
use crate::{
    Anchor, Inclusion, MAX_HELD_VALUE_BYTES, MAX_PROOFS_PER_QUERY, MerkleInclusionProof,
    STATE_CLAIM_BYTES, STATE_CLAIM_CELL_BYTES, StateProofError, SubstateKey,
};

/// What a claim states of one cell: whether the anchor's root holds it,
/// or the value it holds there.
///
/// [`Inclusion`] stays the proof's vocabulary: no proof yields a held
/// value, so the arm belongs to the claim. A held value is what a
/// consumer reads a crossing record's terms off; every other reader
/// sees it through [`StateClaim::reading`] as the presence it proves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Stated {
    /// Whether the key has a leaf, and its value hash if so.
    Inclusion(Inclusion),
    /// The bytes the key holds under the anchor's root.
    Held(Bytes<MAX_HELD_VALUE_BYTES>),
}

impl From<Inclusion> for Stated {
    fn from(inclusion: Inclusion) -> Self {
        Self::Inclusion(inclusion)
    }
}

impl Stated {
    /// What the proof would say of the cell: a held value is a presence
    /// hashing to it.
    #[must_use]
    pub fn inclusion(&self) -> Inclusion {
        match self {
            Self::Inclusion(inclusion) => *inclusion,
            Self::Held(bytes) => Inclusion::Present(jmt_value_hash(bytes)),
        }
    }

    /// The bytes it holds, if it carries them.
    #[must_use]
    pub fn held(&self) -> Option<&[u8]> {
        match self {
            Self::Inclusion(_) => None,
            Self::Held(bytes) => Some(bytes),
        }
    }

    /// The bytes this reading costs a block beyond the key and the
    /// reading itself: a held value and its length prefix.
    fn value_weight(&self) -> usize {
        self.held().map_or(0, |bytes| bytes.len() + 4)
    }
}

/// One anchor's answers: what a commit-proven header says about each
/// cell asked of it, and the proof that it does.
///
/// The anchor names the shard, the height, the root the reading was
/// taken against and the block's clock, every term of which a voter
/// holds to the commit-proven header it has for the height. The cells
/// are sorted and without repeats, so the claim has one form and a
/// validator checking it walks the order it would build. The proof
/// claims exactly the cells' keys under the anchor's root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct StateClaim {
    /// The commit-proven state the readings were taken against.
    pub anchor: Anchor,
    /// Each cell asked about, with what the anchor's root says of it.
    pub cells: Capped<Vec<(SubstateKey, Stated)>, MAX_PROOFS_PER_QUERY>,
    /// The multiproof the readings were taken from, over exactly the
    /// cells' keys.
    pub proof: MerkleInclusionProof,
}

impl StateClaim {
    /// A claim over `cells`, in the one order it may carry them, proven
    /// by `proof`.
    #[must_use]
    pub fn new<S: Into<Stated>>(
        anchor: Anchor,
        cells: impl IntoIterator<Item = (SubstateKey, S)>,
        proof: MerkleInclusionProof,
    ) -> Self {
        let mut cells: Vec<(SubstateKey, Stated)> = cells
            .into_iter()
            .map(|(key, stated)| (key, stated.into()))
            .collect();
        cells.sort_unstable();
        cells.dedup_by_key(|(key, _)| *key);
        // A reading list past the cap is one no claim may carry, and an
        // empty claim is one `is_well_formed` refuses — so an over-cap
        // input lands where it landed before, refused rather than
        // trimmed into a different claim.
        let cells = Capped::new(cells).unwrap_or_default();
        Self {
            anchor,
            cells,
            proof,
        }
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

    /// Whether the proof says of every cell what the claim says, under
    /// the anchor's root, and of nothing else.
    ///
    /// The one check a block's claim gets, run by every replica at
    /// admission: the proof is walked over exactly the claim's keys,
    /// and each reading is held to what the walk reconstructed. A
    /// presence must match the proof's presence, hash and all, an
    /// absence its absence, and a held value must hash to the presence
    /// the proof reconstructs for its key.
    ///
    /// # Errors
    ///
    /// As [`StateProofError`] lists them: a proof that does not decode,
    /// misses or exceeds the claim's keys, or reconstructs another root,
    /// and [`StateProofError::ReadingMismatch`] for a reading the proof
    /// does not bear out.
    pub fn verify(&self) -> Result<(), StateProofError> {
        let proven =
            self.proof
                .exact_inclusions(self.anchor.state_root, self.anchor.shard, &self.keys())?;
        if proven
            .iter()
            .zip(self.cells.iter())
            .all(|((_, proved), (_, stated))| *proved == stated.inclusion())
        {
            Ok(())
        } else {
            Err(StateProofError::ReadingMismatch)
        }
    }

    /// The cells this claim answers for.
    #[must_use]
    pub fn keys(&self) -> Vec<SubstateKey> {
        self.cells.iter().map(|(key, _)| *key).collect()
    }

    /// What the claim says of `key`, if it says anything, as the
    /// presence or absence the proof reconstructs: a held value reads
    /// as the presence it hashes to.
    #[must_use]
    pub fn reading(&self, key: SubstateKey) -> Option<Inclusion> {
        self.stated(key).map(Stated::inclusion)
    }

    /// The value the claim carries for `key`, if it carries one.
    #[must_use]
    pub fn held(&self, key: SubstateKey) -> Option<&[u8]> {
        self.stated(key).and_then(Stated::held)
    }

    /// Whether any cell of the claim carries its value.
    #[must_use]
    pub fn holds_a_value(&self) -> bool {
        self.cells.iter().any(|(_, stated)| stated.held().is_some())
    }

    fn stated(&self, key: SubstateKey) -> Option<&Stated> {
        self.cells
            .iter()
            .find(|(asked, _)| *asked == key)
            .map(|(_, stated)| stated)
    }

    /// This claim cut down to the cells `keep` admits, its proof cut
    /// with them, or `None` when nothing is left or the proof cannot be
    /// cut.
    ///
    /// The cut proof is the one a fresh fetch over the kept keys would
    /// bring, so the piece is a claim in its own right: what a proposer
    /// carries when the whole does not fit, and what a composer holds
    /// once a block has carried the rest.
    #[must_use]
    pub fn restrict(&self, keep: impl Fn(SubstateKey) -> bool) -> Option<Self> {
        let cells: Vec<(SubstateKey, Stated)> = self
            .cells
            .iter()
            .filter(|(key, _)| keep(*key))
            .cloned()
            .collect();
        if cells.is_empty() {
            return None;
        }
        if cells.len() == self.cells.len() {
            return Some(self.clone());
        }
        let keys: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
        let proof = self.proof.restrict(&keys).ok()?;
        Some(Self::new(self.anchor, cells, proof))
    }

    /// The bytes this claim costs a block: the figures the wire budget
    /// prices its terms and each cell at, every value a cell holds, and
    /// the proof as it encodes.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        let values: usize = self
            .cells
            .iter()
            .map(|(_, stated)| stated.value_weight())
            .sum();
        STATE_CLAIM_BYTES
            + self.cells.len() * STATE_CLAIM_CELL_BYTES
            + values
            + self.proof.as_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{proven_claim, test_key};
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
            MerkleInclusionProof::dummy(),
        );
        let ordered = StateClaim::new(
            anchor(),
            [
                (key(1), present),
                (key(2), present),
                (key(3), Inclusion::Absent),
            ],
            MerkleInclusionProof::dummy(),
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
            cells: Capped::new(cells.into_iter().map(|(key, i)| (key, i.into())).collect())
                .expect("a list written out in a test"),
            proof: MerkleInclusionProof::dummy(),
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

    /// A claim whose proof bears out every reading verifies; one whose
    /// reading disagrees with its proof, whose proof answers for a key
    /// the claim does not read, or whose anchor names another root does
    /// not.
    #[test]
    fn a_claim_is_held_to_its_proof() {
        let (held, missing) = (test_key(1), test_key(2));
        let claim = proven_claim(ShardId::ROOT, 3, &[held], &[held, missing]);
        assert_eq!(claim.verify(), Ok(()));
        assert!(claim.reading(held).is_some_and(Inclusion::is_present));
        assert_eq!(claim.reading(missing), Some(Inclusion::Absent));

        let mut flipped = claim.clone();
        flipped.cells = Capped::new(vec![
            (held, Inclusion::Absent.into()),
            (missing, Inclusion::Absent.into()),
        ])
        .expect("two cells");
        assert_eq!(flipped.verify(), Err(StateProofError::ReadingMismatch));

        let narrower = StateClaim::new(
            claim.anchor,
            [(held, claim.reading(held).unwrap())],
            claim.proof.clone(),
        );
        assert_eq!(narrower.verify(), Err(StateProofError::ExtraClaim));

        let mut other_root = claim.clone();
        other_root.anchor.state_root = StateRoot::from_raw(Hash::from_bytes(b"another"));
        assert_eq!(other_root.verify(), Err(StateProofError::RootMismatch));

        let mut bit_flipped = claim;
        let mut bytes = bit_flipped.proof.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        bit_flipped.proof = MerkleInclusionProof::new(bytes);
        assert!(bit_flipped.verify().is_err());
    }

    /// A claim may carry a cell's value. It keeps one canonical form,
    /// round-trips, reads as the presence it hashes to, weighs its
    /// bytes, and verifies only where the proof's presence is that hash:
    /// one byte changed refuses, and so does a value where the proof
    /// says absent.
    #[test]
    fn a_held_value_is_held_to_the_proof() {
        use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

        let (held, missing) = (test_key(1), test_key(2));
        let bare = proven_claim(ShardId::ROOT, 3, &[held], &[held, missing]);
        // The fixture tree's leaf value is the key's own bytes.
        let value = held.to_bytes().to_vec();
        let carrying = StateClaim::new(
            bare.anchor,
            [
                (held, Stated::Held(Bytes::new(value.clone()).unwrap())),
                (missing, Inclusion::Absent.into()),
            ],
            bare.proof.clone(),
        );
        assert_eq!(carrying.verify(), Ok(()));
        assert_eq!(carrying.held(held), Some(value.as_slice()));
        assert_eq!(carrying.held(missing), None);
        assert_eq!(carrying.reading(held), bare.reading(held));
        assert!(carrying.holds_a_value() && !bare.holds_a_value());
        assert_eq!(
            carrying.wire_weight(),
            bare.wire_weight() + value.len() + 4,
            "a held value costs its bytes and a length prefix",
        );
        let encoded = hbor_to_vec(&carrying).unwrap();
        assert!(encoded.len() <= carrying.wire_weight());
        assert_eq!(hbor_from_slice::<StateClaim>(&encoded).unwrap(), carrying);

        let mut altered = value.clone();
        altered[0] ^= 0x01;
        let forged = StateClaim::new(
            bare.anchor,
            [
                (held, Stated::Held(Bytes::new(altered).unwrap())),
                (missing, Inclusion::Absent.into()),
            ],
            bare.proof.clone(),
        );
        assert_eq!(forged.verify(), Err(StateProofError::ReadingMismatch));

        let absent_held = StateClaim::new(
            bare.anchor,
            [
                (held, bare.reading(held).unwrap().into()),
                (missing, Stated::Held(Bytes::new(value).unwrap())),
            ],
            bare.proof,
        );
        assert_eq!(absent_held.verify(), Err(StateProofError::ReadingMismatch));
    }

    /// A claim cut by key is a claim in its own right: the piece
    /// verifies on its own, and the cut proof is what a fetch over the
    /// kept keys alone would bring.
    #[test]
    fn a_claim_cut_by_key_still_proves_its_piece() {
        let (a, b, c) = (test_key(1), test_key(2), test_key(3));
        let whole = proven_claim(ShardId::ROOT, 3, &[a, c], &[a, b, c]);
        let piece = whole.restrict(|key| key != b).expect("two cells kept");
        assert_eq!(piece.keys(), vec![a, c]);
        assert_eq!(piece.verify(), Ok(()));
        assert_eq!(
            piece,
            proven_claim(ShardId::ROOT, 3, &[a, c], &[a, c]),
            "the piece is the claim a narrower fetch would have built",
        );
        assert!(whole.restrict(|_| false).is_none());
        assert_eq!(whole.restrict(|_| true), Some(whole.clone()));
        assert!(piece.wire_weight() < whole.wire_weight());
    }
}
