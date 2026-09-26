//! Signing message for a producer's pushed crossing readings.

use blake3::Hasher;
use hyperscale_hbor::{Hbor, to_vec};

use crate::signing::NetworkId;
use crate::{Hash, ShardId, StateClaim};

/// What a producer committee member signs over a push of readings.
///
/// The shard the push is for and a digest of every claim it carries, in
/// order, each in its canonical bytes. A claim's bytes hold its anchor,
/// so the digest binds the anchor as well as the cells.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-crossing-readings-sender-v1", signing_context = NetworkId)]
pub struct CrossingReadingsSenderMessage {
    pub(crate) target_shard: ShardId,
    pub(crate) claims_digest: Hash,
}

impl CrossingReadingsSenderMessage {
    /// The message over `claims`, in the order they are sent.
    ///
    /// # Panics
    ///
    /// Panics if a claim does not encode, which a claim built from its
    /// own capped parts cannot fail to.
    #[must_use]
    pub fn new(target_shard: ShardId, claims: &[StateClaim]) -> Self {
        let mut hasher = Hasher::new();
        for claim in claims {
            let bytes = to_vec(claim).expect("a state claim encodes");
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
        Self {
            target_shard,
            claims_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_key;
    use crate::{
        Anchor, BlockHeight, Inclusion, MerkleInclusionProof, StateRoot, WeightedTimestamp,
    };

    fn claim(height: u64, key: u8) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 0),
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(1_000),
            },
            [(test_key(key), Inclusion::Absent)],
            MerkleInclusionProof::dummy(),
        )
    }

    #[test]
    fn the_digest_binds_every_claim_in_order() {
        let target = ShardId::leaf(1, 1);
        let a = claim(7, 1);
        let b = claim(7, 2);
        let ab = CrossingReadingsSenderMessage::new(target, &[a.clone(), b.clone()]);
        assert_eq!(
            ab,
            CrossingReadingsSenderMessage::new(target, &[a.clone(), b.clone()])
        );
        assert_ne!(
            ab,
            CrossingReadingsSenderMessage::new(target, &[b.clone(), a.clone()])
        );
        assert_ne!(
            ab,
            CrossingReadingsSenderMessage::new(target, std::slice::from_ref(&a))
        );
        assert_ne!(
            ab,
            CrossingReadingsSenderMessage::new(target, &[a, claim(8, 2)])
        );
        assert_ne!(
            ab,
            CrossingReadingsSenderMessage::new(ShardId::leaf(1, 0), &[claim(7, 1), b])
        );
    }
}
