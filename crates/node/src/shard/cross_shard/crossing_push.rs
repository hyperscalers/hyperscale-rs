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
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        BlockHeight, ConsensusSignature, Inclusion, MerkleInclusionProof, ShardId, StateRoot,
        ValidatorId, WeightedTimestamp,
    };

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
