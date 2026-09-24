//! [`StateClaimsRoot`]: the root over a block's state claims, one leaf
//! per claim.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{Hash, LeafRoot, StateClaim, StateClaimsRoot};

/// Domain tag separating a state claim's merkle leaf from every other
/// leaf preimage the codebase hashes.
const STATE_CLAIM_LEAF_TAG: &[u8] = b"hyperscale.state_claim_leaf.v1";

impl LeafRoot for StateClaimsRoot {
    type Leaf = StateClaim;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One claim's leaf: the tag and its canonical encoding — the
    /// anchor it was read against and what it read of every cell — so
    /// two blocks claiming the same root carry the same answers.
    ///
    /// # Panics
    ///
    /// If the claim does not encode, which a value built through
    /// [`StateClaim::new`] under its caps always does.
    fn leaf(claim: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(claim).expect("a state claim encodes");
        Hash::from_parts(&[STATE_CLAIM_LEAF_TAG, &bytes])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Address, AddressClass, Anchor, BlockHeight, Inclusion, LocalKey, MerkleInclusionProof,
        RootMismatch, ShardId, StateRoot, SubstateKey, Verified, Verify, WeightedTimestamp,
    };

    fn key(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    fn claim(height: u64, keys: &[u8], reading: &[u8]) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::ROOT,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
                ts: WeightedTimestamp::from_millis(height * 1_000),
            },
            keys.iter().map(|seed| {
                let mut value = [0u8; 32];
                value[..reading.len().min(32)].copy_from_slice(reading);
                (key(*seed), Inclusion::Present(value))
            }),
            MerkleInclusionProof::new(reading.to_vec()),
        )
    }

    #[test]
    fn an_empty_section_has_the_zero_root() {
        assert_eq!(StateClaimsRoot::over(&[]), StateClaimsRoot::ZERO);
    }

    /// Every term of a claim is under its leaf: the anchor, the clock,
    /// the cells, what each was read as and the proof move the root.
    #[test]
    fn every_term_of_a_claim_moves_the_root() {
        let base = StateClaimsRoot::over(&[claim(3, &[1, 2], b"p")]);
        assert_ne!(base, StateClaimsRoot::over(&[claim(4, &[1, 2], b"p")]));
        assert_ne!(base, StateClaimsRoot::over(&[claim(3, &[1], b"p")]));
        assert_ne!(base, StateClaimsRoot::over(&[claim(3, &[1, 2], b"q")]));
        let mut other_clock = claim(3, &[1, 2], b"p");
        other_clock.anchor.ts = WeightedTimestamp::from_millis(1);
        assert_ne!(base, StateClaimsRoot::over(&[other_clock]));
        let mut other_proof = claim(3, &[1, 2], b"p");
        other_proof.proof = MerkleInclusionProof::new(b"pq".to_vec());
        assert_ne!(
            base,
            StateClaimsRoot::over(&[other_proof]),
            "a proof bit flipped fails the root, so a peer serving the block cannot alter it",
        );
    }

    #[test]
    fn a_claimed_root_verifies_against_its_claims_and_no_others() {
        let claims = [claim(3, &[1], b"p"), claim(4, &[2], b"q")];
        let claimed = StateClaimsRoot::over(&claims);
        assert_eq!(
            claimed.verify(&claims[..]).map(Verified::into_inner),
            Ok(claimed)
        );
        assert_eq!(
            StateClaimsRoot::ZERO.verify(&claims[..]),
            Err(RootMismatch {
                expected: StateClaimsRoot::ZERO,
                computed: claimed,
            })
        );
    }
}
