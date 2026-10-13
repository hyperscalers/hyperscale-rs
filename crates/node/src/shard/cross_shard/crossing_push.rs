//! Ingress checks on a producer's pushed crossing readings, before any
//! trust is placed in them.
//!
//! The order is the cost order: the cheap shape checks, then the sender
//! against the committee that proposed the anchor's block, then each
//! claim's own proof. What passes is offered to the execution
//! coordinator; what fails is dropped whole and counted by reason.

use hyperscale_types::network::notification::CrossingReadingsNotification;
use hyperscale_types::{Anchor, MAX_STATE_CLAIMS_BYTES, StateClaim};

/// The one anchor a well-shaped push sits at: routed to `target_shard`,
/// non-empty, every claim at one anchor on another shard, and weighing
/// no more than one block's section.
pub fn shaped(notification: &CrossingReadingsNotification) -> Result<Anchor, &'static str> {
    if notification.claims.is_empty() {
        return Err("empty");
    }
    let Some(anchor) = notification.anchor() else {
        return Err("mixed_anchors");
    };
    if anchor.shard == notification.target_shard {
        return Err("own_shard");
    }
    if notification.wire_weight() > MAX_STATE_CLAIMS_BYTES {
        return Err("over_budget");
    }
    Ok(anchor)
}

/// Every claim well formed and proving its readings at its anchor's
/// root, each held value hashing to the presence its proof shows.
///
/// A claim naming members is carried among the verdict readings, which
/// ride last and raise no read frontier. One that also held a value or
/// named a crossing is not well formed, so a producer sends the two
/// kinds apart and a push mixing them is refused whole.
pub fn proven(claims: &[StateClaim]) -> Result<(), &'static str> {
    for claim in claims {
        if !claim.is_well_formed() {
            return Err("malformed");
        }
        if claim.verify().is_err() {
            return Err("unproven");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::test_utils::{proven_claim, test_key};
    use hyperscale_types::{
        BlockHeight, ConsensusSignature, Hash, Inclusion, MerkleInclusionProof, ShardId, StateRoot,
        Stated, TxHash, ValidatorId, WeightedTimestamp, verdict_leaf,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher};

    use super::*;

    const PRODUCER: ShardId = ShardId::leaf(1, 0);
    const CONSUMER: ShardId = ShardId::leaf(1, 1);

    fn anchor_at(shard: ShardId, height: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(1_000),
        }
    }

    fn claim_at(anchor: Anchor, key: u8) -> StateClaim {
        StateClaim::new(
            anchor,
            [(test_key(key), Inclusion::Absent)],
            MerkleInclusionProof::dummy(),
        )
    }

    fn push(claims: Vec<StateClaim>, target: ShardId) -> CrossingReadingsNotification {
        CrossingReadingsNotification::new(
            Capped::new(claims).unwrap(),
            target,
            ValidatorId::new(0),
            ConsensusSignature::ZERO,
        )
    }

    #[test]
    fn a_push_is_shaped_by_its_one_anchor() {
        let anchor = anchor_at(PRODUCER, 7);
        assert_eq!(shaped(&push(Vec::new(), CONSUMER)), Err("empty"));
        assert_eq!(
            shaped(&push(
                vec![claim_at(anchor, 1), claim_at(anchor_at(PRODUCER, 8), 2)],
                CONSUMER
            )),
            Err("mixed_anchors"),
        );
        assert_eq!(
            shaped(&push(vec![claim_at(anchor, 1)], PRODUCER)),
            Err("own_shard"),
        );
        assert_eq!(
            shaped(&push(vec![claim_at(anchor, 1)], CONSUMER)),
            Ok(anchor)
        );
    }

    /// A claim naming a member is refused as ill-formed where it also
    /// holds a value or names a crossing, whatever its proof says;
    /// either kind alone goes on to its proof.
    #[test]
    fn a_claim_naming_a_member_beside_a_value_or_a_crossing_is_refused() {
        let shard = ShardId::leaf(1, 0);
        let tx = TxHash::from(Hash::from_bytes(b"member"));
        let leaf = verdict_leaf(shard, tx);
        let record = CrossingId {
            producer: leaf.owner,
            consumer: leaf.owner,
            intent: IntentHash(Hash32([7; 32])),
            local: 0,
            output: 0,
        };
        let record_key = record.record_key(&ProtocolHasher);
        let named = proven_claim(shard, 7, &[leaf], &[leaf]).hearing([tx]);
        assert_eq!(proven(std::slice::from_ref(&named)), Ok(()));

        let crossed = proven_claim(shard, 7, &[leaf], &[leaf, record_key])
            .hearing([tx])
            .naming([(record_key, record)]);
        assert_eq!(crossed.verify(), Ok(()));
        assert_eq!(proven(&[crossed]), Err("malformed"));
        let crossing = StateClaim {
            verdicts: Capped::empty(),
            ..proven_claim(shard, 7, &[leaf], &[leaf, record_key]).naming([(record_key, record)])
        };
        assert_eq!(proven(&[crossing]), Ok(()));

        let held = StateClaim {
            cells: Capped::new(vec![(
                leaf,
                Stated::Held(Bytes::new(leaf.to_bytes().to_vec()).expect("a short value")),
            )])
            .expect("one cell"),
            ..named
        };
        assert_eq!(held.verify(), Ok(()));
        assert_eq!(proven(std::slice::from_ref(&held)), Err("malformed"));
        let valued = StateClaim {
            verdicts: Capped::empty(),
            ..held
        };
        assert_eq!(proven(&[valued]), Ok(()));
    }

    #[test]
    fn a_claim_that_does_not_prove_its_readings_is_refused() {
        let anchor = anchor_at(PRODUCER, 7);
        assert_eq!(proven(&[claim_at(anchor, 1)]), Err("unproven"));
        let empty = StateClaim::new(
            anchor,
            Vec::<(_, Inclusion)>::new(),
            MerkleInclusionProof::dummy(),
        );
        assert_eq!(proven(&[empty]), Err("malformed"));
    }
}
