//! Pushed claims held until this replica commit-proves their anchor.
//!
//! A push arrives with the producer's next certified header, and the
//! two race: the header proves the anchor, the push carries readings at
//! it, and either may land first. What lands first is held here, keyed
//! by the anchor it waits on, and released when the header proves it.
//! Only a claim that passed ingress can enter — routed, signed by a
//! member of the producer's committee at the anchor's clock, well
//! formed and proving its own readings — so what fills this is a
//! committee member's readings at a root this replica has yet to prove,
//! never an unauthenticated byte.
//!
//! A push can also land before its key is wanted here: before the
//! consumer's transaction commits, or before any body reports its
//! record. Such a claim, at a proven anchor, is held the same way until
//! a key of its is wanted, so a producer that runs ahead of its consumer
//! costs the consumer no fallback read.
//!
//! Bounded on two axes for each kind, and a bound that trips leaves the
//! reading to the fallback read: per anchor the claims weigh at most one
//! block's section, and per shard at most [`MAX_PARKED_CLAIM_HEIGHTS`]
//! heights are held, the highest going first, since it is the one
//! furthest from proving and a flood ahead of the frontier evicts
//! itself.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_metrics::record_crossing_push_dropped;
use hyperscale_types::{
    BlockHeight, MAX_STATE_CLAIMS_BYTES, RETENTION_HORIZON, ShardId, StateClaim, SubstateKey,
    WeightedTimestamp,
};

/// How many unproven heights of one shard are held at once.
pub const MAX_PARKED_CLAIM_HEIGHTS: usize = 8;

/// The verified claims waiting on their anchor's proof, and the ones at
/// a proven anchor waiting on a want.
#[derive(Debug, Default)]
pub struct ParkedClaims {
    unproven: BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>,
    /// Claims at a proven anchor that nothing here wants yet: a push
    /// that landed before its consumer's transaction committed here, or
    /// before any body reported its record, held the same bounded way
    /// until a key of theirs is wanted.
    early: BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>,
}

/// Hold `claim` in `held` under the bounds, or say why not: a claim
/// whose keys a held claim at the same anchor already covers adds
/// nothing; one that would take the anchor's claims past a block's
/// section cannot be carried whole; and one at a height past the
/// shard's held heights, or one that pushes the shard's highest height
/// out, is left to the fallback read.
fn hold(
    held: &mut BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>,
    claim: StateClaim,
) -> Result<(), &'static str> {
    let anchor = claim.anchor;
    let key = (anchor.shard, anchor.height);
    let at = held.entry(key).or_default();
    let keys = claim.keys();
    if at
        .iter()
        .any(|held| held.anchor == anchor && keys.iter().all(|key| held.reading(*key).is_some()))
    {
        if at.is_empty() {
            held.remove(&key);
        }
        return Err("held");
    }
    let weight: usize = at.iter().map(StateClaim::wire_weight).sum();
    if weight.saturating_add(claim.wire_weight()) > MAX_STATE_CLAIMS_BYTES {
        if at.is_empty() {
            held.remove(&key);
        }
        return Err("over_budget");
    }
    at.push(claim);
    let heights: Vec<BlockHeight> = held
        .range((anchor.shard, BlockHeight::GENESIS)..=(anchor.shard, BlockHeight::new(u64::MAX)))
        .map(|((_, height), _)| *height)
        .collect();
    if heights.len() > MAX_PARKED_CLAIM_HEIGHTS {
        let highest = *heights.last().expect("over the cap, so not empty");
        let evicted = held.remove(&(anchor.shard, highest)).unwrap_or_default();
        if highest == anchor.height {
            for _ in evicted.iter().take(evicted.len().saturating_sub(1)) {
                record_crossing_push_dropped("evicted");
            }
            return Err("beyond_frontier");
        }
        for _ in evicted {
            record_crossing_push_dropped("evicted");
        }
    }
    Ok(())
}

fn drop_shard_from(held: &mut BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>, shard: ShardId) {
    let gone: Vec<(ShardId, BlockHeight)> = held
        .range((shard, BlockHeight::GENESIS)..=(shard, BlockHeight::new(u64::MAX)))
        .map(|(key, _)| *key)
        .collect();
    for key in gone {
        for _ in held.remove(&key).unwrap_or_default() {
            record_crossing_push_dropped("departed");
        }
    }
}

fn retire_from(
    held: &mut BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>,
    floor: WeightedTimestamp,
) {
    let retired: Vec<(ShardId, BlockHeight)> = held
        .iter()
        .filter(|(_, claims)| claims.iter().any(|claim| claim.anchor.ts < floor))
        .map(|(key, _)| *key)
        .collect();
    for key in retired {
        for _ in held.remove(&key).unwrap_or_default() {
            record_crossing_push_dropped("retired");
        }
    }
}

impl ParkedClaims {
    /// Nothing parked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `claim` until its anchor is proven, or say why it was not
    /// held.
    pub fn park(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        hold(&mut self.unproven, claim)
    }

    /// The claims held on exactly this anchor, now that it is proven.
    pub fn release(&mut self, shard: ShardId, height: BlockHeight) -> Vec<StateClaim> {
        self.unproven.remove(&(shard, height)).unwrap_or_default()
    }

    /// Hold `claim`, at a proven anchor, until a key of its is wanted, or
    /// say why it was not held.
    pub fn hold_early(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        hold(&mut self.early, claim)
    }

    /// The early claims carrying any of `wanted`, now that it is.
    pub fn release_early(&mut self, wanted: &BTreeSet<SubstateKey>) -> Vec<StateClaim> {
        let mut released = Vec::new();
        self.early.retain(|_, claims| {
            let (out, kept): (Vec<StateClaim>, Vec<StateClaim>) = claims
                .drain(..)
                .partition(|claim| claim.keys().iter().any(|key| wanted.contains(key)));
            released.extend(out);
            *claims = kept;
            !claims.is_empty()
        });
        released
    }

    /// Drop everything held on `shard`: a departed shard's anchors are
    /// never proven again, and its records never wanted.
    pub fn drop_shard(&mut self, shard: ShardId) {
        drop_shard_from(&mut self.unproven, shard);
        drop_shard_from(&mut self.early, shard);
    }

    /// Drop the claims at anchors older than one horizon before `now`:
    /// a proof or a want that has not come in that long is not coming,
    /// and the reading would be past every window a block admits it in.
    pub fn retire_below(&mut self, now: WeightedTimestamp) {
        let floor = now.minus(RETENTION_HORIZON);
        retire_from(&mut self.unproven, floor);
        retire_from(&mut self.early, floor);
    }

    /// How many claims are held, proven or not.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.unproven
            .values()
            .chain(self.early.values())
            .map(Vec::len)
            .sum()
    }

    /// Whether nothing is held.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.unproven.is_empty() && self.early.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{Anchor, Inclusion, MerkleInclusionProof, StateRoot};

    use super::*;

    const SHARD: ShardId = ShardId::leaf(1, 0);

    fn claim_at(height: u64, ts_ms: u64, key: u8) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: SHARD,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            [(test_key(key), Inclusion::Absent)],
            MerkleInclusionProof::dummy(),
        )
    }

    #[test]
    fn a_parked_claim_is_released_on_exactly_its_anchor() {
        let mut parked = ParkedClaims::new();
        parked.park(claim_at(5, 1_000, 1)).unwrap();
        assert!(parked.release(SHARD, BlockHeight::new(6)).is_empty());
        assert_eq!(parked.release(SHARD, BlockHeight::new(5)).len(), 1);
        assert!(parked.is_empty());
    }

    #[test]
    fn a_claim_already_covered_at_its_anchor_adds_nothing() {
        let mut parked = ParkedClaims::new();
        parked.park(claim_at(5, 1_000, 1)).unwrap();
        assert_eq!(parked.park(claim_at(5, 1_000, 1)), Err("held"));
        assert_eq!(parked.len(), 1);
    }

    #[test]
    fn a_ninth_height_evicts_the_highest() {
        let mut parked = ParkedClaims::new();
        for height in 1..=8 {
            parked.park(claim_at(height, 1_000, 1)).unwrap();
        }
        assert_eq!(
            parked.park(claim_at(9, 1_000, 1)),
            Err("beyond_frontier"),
            "the newest height is the one furthest from proving",
        );
        assert_eq!(parked.len(), 8);
        parked.park(claim_at(0, 1_000, 1)).unwrap();
        assert_eq!(parked.len(), 8, "a lower height evicts the highest held");
        assert!(parked.release(SHARD, BlockHeight::new(8)).is_empty());
        assert_eq!(parked.release(SHARD, BlockHeight::new(0)).len(), 1);
    }

    #[test]
    fn a_claim_past_the_horizon_is_retired() {
        let mut parked = ParkedClaims::new();
        parked.park(claim_at(5, 1_000, 1)).unwrap();
        parked.park(claim_at(6, 2_000, 2)).unwrap();
        let just_inside = WeightedTimestamp::from_millis(1_000).plus(RETENTION_HORIZON);
        parked.retire_below(just_inside);
        assert_eq!(parked.len(), 2);
        parked.retire_below(just_inside.plus(Duration::from_millis(1)));
        assert_eq!(parked.len(), 1);
        assert_eq!(parked.release(SHARD, BlockHeight::new(6)).len(), 1);
    }

    #[test]
    fn an_early_claim_is_released_once_a_key_of_its_is_wanted() {
        let mut parked = ParkedClaims::new();
        parked.hold_early(claim_at(5, 1_000, 1)).unwrap();
        parked.hold_early(claim_at(6, 1_000, 2)).unwrap();
        assert!(
            parked
                .release_early(&BTreeSet::from([test_key(3)]))
                .is_empty()
        );
        let released = parked.release_early(&BTreeSet::from([test_key(2)]));
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].keys(), vec![test_key(2)]);
        assert_eq!(parked.len(), 1);
    }

    #[test]
    fn a_departed_shard_takes_its_claims_with_it() {
        let mut parked = ParkedClaims::new();
        parked.park(claim_at(5, 1_000, 1)).unwrap();
        parked.drop_shard(SHARD);
        assert!(parked.is_empty());
    }
}
