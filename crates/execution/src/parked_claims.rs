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
//! Bounded on three axes for each kind, and a bound that trips leaves the
//! reading to the fallback read: per anchor the claims weigh at most one
//! block's section, per shard at most [`MAX_PARKED_CLAIM_HEIGHTS`]
//! heights are held, [`MAX_EARLY_CLAIM_HEIGHTS`] for a record waiting on
//! a want, and across shards the kind weighs at most its byte budget. An
//! unproven height gives way highest first, since it is the one furthest
//! from proving and a flood ahead of the frontier evicts itself. A proven
//! one gives way lowest first: the height pushed longest ago is the one
//! least likely still wanted, so heights that nothing comes to want leave
//! a newer push its place.
//!
//! Over the budget, the shard holding the most bytes gives up a height in
//! its own order, the arriving shard first where it ties the most. A
//! shard holding no more bytes than its share of the budget, two
//! single-cell claims' worth, is then never the one to give way, whatever
//! every other shard pushes: one shard's members can crowd only their own
//! shard's account. The share is in bytes, not claims, so a shard pushing
//! heavier claims keeps fewer of them.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_metrics::record_crossing_push_dropped;
use hyperscale_types::{
    BlockHeight, MAX_SHARDS, MAX_STATE_CLAIMS_BYTES, RETENTION_HORIZON,
    SINGLE_CELL_CLAIM_P99_BYTES, ShardId, StateClaim, SubstateKey, WeightedTimestamp,
};

/// How many unproven heights of one shard are held at once.
pub const MAX_PARKED_CLAIM_HEIGHTS: usize = 8;

/// How many proven heights of one shard are held waiting on a want.
///
/// A proven height's stay is this many of the holder's heights when each
/// parks something, so this is how far a consumer's filing can run behind
/// a holder's pushes and still find them: about 11 s of its blocks, the
/// window a holder's grace is derived over. Short of the lag, every early
/// push goes just before its want files, and each costs a read.
const MAX_EARLY_CLAIM_HEIGHTS: usize = 32;

/// The wire bytes one kind holds across every shard, for a kind holding
/// `max_heights` of each: one shard's heights at a full section each, or
/// two single-cell claims for every shard, whichever is more.
///
/// So a lone shard at its caps fits whole, and under a flood across every
/// shard each keeps two single-cell claims' worth of bytes, since only the
/// shard holding the most gives way.
const fn budget(max_heights: usize) -> usize {
    let sections = max_heights * MAX_STATE_CLAIMS_BYTES;
    let shares = MAX_SHARDS * 2 * SINGLE_CELL_CLAIM_P99_BYTES;
    if sections > shares { sections } else { shares }
}

/// The verified claims waiting on their anchor's proof, and the ones at
/// a proven anchor waiting on a want.
#[derive(Debug)]
pub struct ParkedClaims {
    unproven: Held,
    /// Claims naming verdicts that wait on their anchor's proof, apart
    /// from `unproven` and bounded the same way: a block that states or
    /// settles a core member pushes its leaves at a height of its own,
    /// and none of those heights takes one a record's push would park
    /// at.
    unproven_heard: Held,
    /// Claims at a proven anchor that nothing here wants yet: a push
    /// that landed before its consumer's transaction committed here, or
    /// before any body reported its record, held the same bounded way
    /// until a key of theirs is wanted.
    early: Held,
    /// Verdict leaves pushed at a proven anchor for members no row here
    /// asks about yet: a sibling that states first pushes its yes before
    /// this shard's row hears, and the leaf is held until the row's
    /// question names it. Kept apart from `early`, so a leaf nobody
    /// comes to ask about never holds a place a record's push needs,
    /// and bounded the same way with the lowest height going first: the
    /// leaf pushed longest ago is the one least likely still wanted.
    unasked: Held,
}

/// Which height of a shard gives way when it holds too many.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GivesWay {
    /// The one furthest from proving.
    Highest,
    /// The one pushed longest ago.
    Lowest,
}

/// Count `count` claims dropped for `reason`.
fn dropped(reason: &'static str, count: usize) {
    for _ in 0..count {
        record_crossing_push_dropped(reason);
    }
}

/// One kind's claims by the anchor they wait on, with the bytes each
/// shard holds in them and the bounds they are held under.
///
/// `total` is the sum of `by_shard`, which is each shard's sum of
/// [`StateClaim::wire_weight`] over its claims in `by_anchor`, and
/// `heaviest` holds one `(bytes, shard)` for each shard holding any. A
/// shard holding nothing has no entry in either, and no key of
/// `by_anchor` holds an empty list. `total` never stays past `budget`.
#[derive(Debug)]
struct Held {
    by_anchor: BTreeMap<(ShardId, BlockHeight), Vec<StateClaim>>,
    by_shard: BTreeMap<ShardId, usize>,
    heaviest: BTreeSet<(usize, ShardId)>,
    total: usize,
    gives_way: GivesWay,
    max_heights: usize,
    budget: usize,
}

impl Held {
    /// Claims waiting on their anchor's proof.
    const fn unproven() -> Self {
        Self::new(GivesWay::Highest, MAX_PARKED_CLAIM_HEIGHTS)
    }

    /// Claims at a proven anchor waiting on a want, `max_heights` of a
    /// shard at once.
    const fn proven(max_heights: usize) -> Self {
        Self::new(GivesWay::Lowest, max_heights)
    }

    const fn new(gives_way: GivesWay, max_heights: usize) -> Self {
        Self {
            by_anchor: BTreeMap::new(),
            by_shard: BTreeMap::new(),
            heaviest: BTreeSet::new(),
            total: 0,
            gives_way,
            max_heights,
            budget: budget(max_heights),
        }
    }

    /// The bytes `shard` holds here.
    fn bytes(&self, shard: ShardId) -> usize {
        self.by_shard.get(&shard).copied().unwrap_or(0)
    }

    /// The keys `shard` holds claims at, lowest height first.
    fn keys_of(
        &self,
        shard: ShardId,
    ) -> impl DoubleEndedIterator<Item = (ShardId, BlockHeight)> + '_ {
        self.by_anchor
            .range((shard, BlockHeight::GENESIS)..=(shard, BlockHeight::new(u64::MAX)))
            .map(|(key, _)| *key)
    }

    /// Move `shard` from holding `from` bytes to holding `to`.
    fn reweigh(&mut self, shard: ShardId, from: usize, to: usize) {
        if from > 0 {
            self.heaviest.remove(&(from, shard));
        }
        if to > 0 {
            self.heaviest.insert((to, shard));
            self.by_shard.insert(shard, to);
        } else {
            self.by_shard.remove(&shard);
        }
        self.total = self.total + to - from;
    }

    /// Every claim held at `key`, no longer held.
    fn take(&mut self, key: (ShardId, BlockHeight)) -> Vec<StateClaim> {
        let taken = self.by_anchor.remove(&key).unwrap_or_default();
        if !taken.is_empty() {
            let weight: usize = taken.iter().map(StateClaim::wire_weight).sum();
            let from = self.bytes(key.0);
            self.reweigh(key.0, from, from - weight);
        }
        taken
    }

    /// Every claim `matches` holds of, no longer held, the rest of each
    /// key's claims kept.
    fn drain_matching(&mut self, mut matches: impl FnMut(&StateClaim) -> bool) -> Vec<StateClaim> {
        let mut drained = Vec::new();
        let mut lighter: BTreeMap<ShardId, usize> = BTreeMap::new();
        self.by_anchor.retain(|(shard, _), claims| {
            if !claims.iter().any(&mut matches) {
                return true;
            }
            let (out, kept): (Vec<StateClaim>, Vec<StateClaim>) =
                claims.drain(..).partition(|claim| matches(claim));
            if !out.is_empty() {
                *lighter.entry(*shard).or_default() +=
                    out.iter().map(StateClaim::wire_weight).sum::<usize>();
                drained.extend(out);
            }
            *claims = kept;
            !claims.is_empty()
        });
        for (shard, weight) in lighter {
            let from = self.bytes(shard);
            self.reweigh(shard, from, from - weight);
        }
        drained
    }

    /// The key `shard` gives up when it gives way.
    fn giving_way(&self, shard: ShardId) -> (ShardId, BlockHeight) {
        let mut keys = self.keys_of(shard);
        match self.gives_way {
            GivesWay::Highest => keys.next_back(),
            GivesWay::Lowest => keys.next(),
        }
        .expect("a shard giving way holds a height")
    }

    /// Hold `claim` under the bounds, or say why not: a claim whose keys
    /// a held claim at the same anchor already covers adds nothing; one
    /// that would take the anchor's claims past a block's section cannot
    /// be carried whole; past `max_heights` of the shard one height gives
    /// way as `gives_way` says; and while the kind is over its budget,
    /// the shard holding the most gives way the same, the claim's own
    /// shard first where it ties. Left to the fallback read is the claim
    /// itself where the height going is its own.
    fn hold(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        let anchor = claim.anchor;
        let key = (anchor.shard, anchor.height);
        let at = self.by_anchor.get(&key).map_or(&[][..], Vec::as_slice);
        let keys = claim.keys();
        if at.iter().any(|held| {
            held.anchor == anchor && keys.iter().all(|key| held.reading(*key).is_some())
        }) {
            return Err("held");
        }
        let weight: usize = at.iter().map(StateClaim::wire_weight).sum();
        if weight.saturating_add(claim.wire_weight()) > MAX_STATE_CLAIMS_BYTES {
            return Err("over_budget");
        }
        let from = self.bytes(anchor.shard);
        let to = from + claim.wire_weight();
        self.by_anchor.entry(key).or_default().push(claim);
        self.reweigh(anchor.shard, from, to);
        if self.keys_of(anchor.shard).count() > self.max_heights {
            let gone = self.giving_way(anchor.shard);
            let evicted = self.take(gone);
            if gone == key {
                dropped("evicted", evicted.len() - 1);
                return Err(match self.gives_way {
                    GivesWay::Highest => "beyond_frontier",
                    GivesWay::Lowest => "outlasted",
                });
            }
            dropped("evicted", evicted.len());
        }
        while self.total > self.budget {
            let &(most, heaviest) = self.heaviest.last().expect("over budget, so not empty");
            let shard = if self.bytes(anchor.shard) == most {
                anchor.shard
            } else {
                heaviest
            };
            let gone = self.giving_way(shard);
            let evicted = self.take(gone);
            if gone == key {
                dropped("crowded", evicted.len() - 1);
                return Err("crowded");
            }
            dropped("crowded", evicted.len());
        }
        Ok(())
    }

    /// Drop everything held on `shard`.
    fn drop_shard(&mut self, shard: ShardId) {
        let gone: Vec<(ShardId, BlockHeight)> = self.keys_of(shard).collect();
        for key in gone {
            dropped("departed", self.take(key).len());
        }
    }

    /// Drop every key holding a claim at an anchor older than `floor`.
    fn retire_below(&mut self, floor: WeightedTimestamp) {
        let retired: Vec<(ShardId, BlockHeight)> = self
            .by_anchor
            .iter()
            .filter(|(_, claims)| claims.iter().any(|claim| claim.anchor.ts < floor))
            .map(|(key, _)| *key)
            .collect();
        for key in retired {
            dropped("retired", self.take(key).len());
        }
    }
}

impl ParkedClaims {
    /// Nothing parked.
    pub const fn new() -> Self {
        Self {
            unproven: Held::unproven(),
            unproven_heard: Held::unproven(),
            early: Held::proven(MAX_EARLY_CLAIM_HEIGHTS),
            unasked: Held::proven(MAX_PARKED_CLAIM_HEIGHTS),
        }
    }

    /// Hold `claim` until its anchor is proven, or say why it was not
    /// held.
    pub fn park(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        if claim.verdicts.is_empty() {
            self.unproven.hold(claim)
        } else {
            self.unproven_heard.hold(claim)
        }
    }

    /// The claims held on exactly this anchor, now that it is proven.
    pub fn release(&mut self, shard: ShardId, height: BlockHeight) -> Vec<StateClaim> {
        let mut released = self.unproven.take((shard, height));
        released.extend(self.unproven_heard.take((shard, height)));
        released
    }

    /// Hold `claim`, at a proven anchor, until a key of its is wanted, or
    /// say why it was not held.
    pub fn hold_early(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        self.early.hold(claim)
    }

    /// Hold `claim`, verdict leaves at a proven anchor, until a question
    /// names one of them, or say why it was not held.
    pub fn hold_unasked(&mut self, claim: StateClaim) -> Result<(), &'static str> {
        self.unasked.hold(claim)
    }

    /// The early claims carrying any of `wanted`, now that it is.
    pub fn release_early(&mut self, wanted: &BTreeSet<SubstateKey>) -> Vec<StateClaim> {
        let carries = |claim: &StateClaim| claim.cells.iter().any(|(key, _)| wanted.contains(key));
        let mut released = self.early.drain_matching(carries);
        released.extend(self.unasked.drain_matching(carries));
        released
    }

    /// Drop everything held on `shard`: a departed shard's anchors are
    /// never proven again, and its records never wanted.
    pub fn drop_shard(&mut self, shard: ShardId) {
        self.unproven.drop_shard(shard);
        self.early.drop_shard(shard);
        self.unasked.drop_shard(shard);
        self.unproven_heard.drop_shard(shard);
    }

    /// Drop the claims at anchors older than one horizon before `now`:
    /// a proof or a want that has not come in that long is not coming,
    /// and the reading would be past every window a block admits it in.
    pub fn retire_below(&mut self, now: WeightedTimestamp) {
        let floor = now.minus(RETENTION_HORIZON);
        self.unproven.retire_below(floor);
        self.early.retire_below(floor);
        self.unasked.retire_below(floor);
        self.unproven_heard.retire_below(floor);
    }

    /// The wire bytes held, proven or not.
    pub const fn weight(&self) -> usize {
        self.unproven.total + self.unproven_heard.total + self.early.total + self.unasked.total
    }

    /// How many claims are held, proven or not.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        [
            &self.unproven,
            &self.early,
            &self.unasked,
            &self.unproven_heard,
        ]
        .into_iter()
        .flat_map(|held| held.by_anchor.values())
        .map(Vec::len)
        .sum()
    }

    /// Whether nothing is held.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.unproven.by_anchor.is_empty()
            && self.early.by_anchor.is_empty()
            && self.unasked.by_anchor.is_empty()
            && self.unproven_heard.by_anchor.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
    use hyperscale_metrics_memory::MemoryRecorder;
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Anchor, Hash, Inclusion, MAX_HELD_VALUE_BYTES, MerkleInclusionProof,
        STATE_CLAIM_CROSSING_BYTES, StateRoot, TxHash, verdict_leaf,
    };

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

    /// A claim at `height` naming a member whose verdict leaf it reads.
    fn heard_at(height: u64, seed: u8) -> StateClaim {
        let tx = TxHash::from(Hash::from_bytes(&[seed; 32]));
        StateClaim::new(
            Anchor {
                shard: SHARD,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(1_000),
            },
            [(verdict_leaf(SHARD, tx), Inclusion::Absent)],
            MerkleInclusionProof::dummy(),
        )
        .hearing([tx])
    }

    /// Verdict pushes waiting on their anchors hold heights of their
    /// own: a shard's worth of them leaves a record's push its place,
    /// and each kind is released with its anchor.
    #[test]
    fn verdict_pushes_take_no_height_a_record_push_parks_at() {
        let mut parked = ParkedClaims::new();
        for height in 1..=8 {
            parked.park(heard_at(height, 1)).unwrap();
        }
        assert_eq!(parked.park(heard_at(9, 1)), Err("beyond_frontier"));
        for height in 9..=16 {
            assert_eq!(parked.park(claim_at(height, 1_000, 1)), Ok(()));
        }
        assert_eq!(parked.len(), 16);
        assert_eq!(parked.release(SHARD, BlockHeight::new(3)).len(), 1);
        assert_eq!(parked.release(SHARD, BlockHeight::new(9)).len(), 1);
    }

    /// Verdict leaves held for a question not yet standing give way
    /// lowest height first, and one that arrives lower than all held is
    /// the one let go.
    #[test]
    fn unasked_verdict_leaves_give_way_oldest_first() {
        let mut parked = ParkedClaims::new();
        for height in 2..=9 {
            parked.hold_unasked(heard_at(height, 1)).unwrap();
        }
        assert_eq!(parked.hold_unasked(heard_at(1, 1)), Err("outlasted"));
        assert_eq!(parked.hold_unasked(heard_at(10, 1)), Ok(()));
        assert_eq!(parked.len(), 8);
        let leaf = verdict_leaf(SHARD, TxHash::from(Hash::from_bytes(&[1; 32])));
        let released = parked.release_early(&BTreeSet::from([leaf]));
        assert_eq!(
            released
                .iter()
                .map(|claim| claim.anchor.height.inner())
                .collect::<Vec<_>>(),
            (3..=10).collect::<Vec<_>>(),
            "the lowest height went",
        );
    }

    /// Early claims give way lowest height first, so heights nothing
    /// comes to want never keep a newer push out, and one lower than
    /// every height held is the one let go.
    #[test]
    fn early_claims_give_way_oldest_first() {
        let mut parked = ParkedClaims::new();
        let top = 1 + u64::try_from(MAX_EARLY_CLAIM_HEIGHTS).expect("a small bound");
        for height in 2..=top {
            parked.hold_early(claim_at(height, 1_000, 1)).unwrap();
        }
        assert_eq!(parked.hold_early(claim_at(1, 1_000, 2)), Err("outlasted"));
        assert_eq!(parked.hold_early(claim_at(top + 1, 1_000, 3)), Ok(()));
        assert_eq!(parked.len(), MAX_EARLY_CLAIM_HEIGHTS);
        assert!(
            parked
                .release_early(&BTreeSet::from([test_key(2)]))
                .is_empty(),
            "the lower push went",
        );
        assert_eq!(
            parked.release_early(&BTreeSet::from([test_key(3)])).len(),
            1,
            "the newest stayed",
        );
    }

    /// A filing running a steady lag behind a holder's pushes still finds
    /// them: a push stays 31 parked heights, past the 3 s a venue's filing
    /// can trail, with every height between parking something.
    #[test]
    fn a_push_outlasts_a_steady_lag_of_its_want() {
        let mut parked = ParkedClaims::new();
        parked.hold_early(claim_at(1, 1_000, 1)).unwrap();
        for height in 2..=32 {
            parked.hold_early(claim_at(height, 1_000, 2)).unwrap();
        }
        assert_eq!(
            parked.release_early(&BTreeSet::from([test_key(1)])).len(),
            1,
        );
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

    /// The four kinds, each with the claims it holds and how they leave.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Unproven,
        Heard,
        Early,
        Unasked,
    }

    const KINDS: [Kind; 4] = [Kind::Unproven, Kind::Heard, Kind::Early, Kind::Unasked];

    /// The `index`th shard of the most a network can hold.
    fn nth_shard(index: usize) -> ShardId {
        ShardId::leaf(
            MAX_SHARDS.trailing_zeros(),
            u64::try_from(index).expect("under the shard cap"),
        )
    }

    impl Kind {
        /// A claim of this kind from `shard` at `height`, reading a key
        /// `seed` names and weighing `weight` wire bytes.
        fn claim(self, shard: ShardId, height: usize, seed: u8, weight: usize) -> StateClaim {
            let anchor = Anchor {
                shard,
                height: BlockHeight::new(u64::try_from(height).expect("a small height")),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(1_000),
            };
            let bare = match self {
                Self::Unproven | Self::Early => StateClaim::new(
                    anchor,
                    [(test_key(seed), Inclusion::Absent)],
                    MerkleInclusionProof::dummy(),
                ),
                Self::Heard | Self::Unasked => {
                    let tx = TxHash::from(Hash::from_bytes(&[seed; 32]));
                    StateClaim::new(
                        anchor,
                        [(verdict_leaf(shard, tx), Inclusion::Absent)],
                        MerkleInclusionProof::dummy(),
                    )
                    .hearing([tx])
                }
            };
            let padding = weight - bare.wire_weight();
            let claim = StateClaim {
                proof: MerkleInclusionProof::new(vec![0; padding]),
                ..bare
            };
            assert_eq!(claim.wire_weight(), weight);
            claim
        }

        fn hold(self, parked: &mut ParkedClaims, claim: StateClaim) -> Result<(), &'static str> {
            match self {
                Self::Unproven | Self::Heard => parked.park(claim),
                Self::Early => parked.hold_early(claim),
                Self::Unasked => parked.hold_unasked(claim),
            }
        }

        fn held(self, parked: &ParkedClaims) -> &Held {
            match self {
                Self::Unproven => &parked.unproven,
                Self::Heard => &parked.unproven_heard,
                Self::Early => &parked.early,
                Self::Unasked => &parked.unasked,
            }
        }

        /// The claims held at `claim`'s anchor, or carrying its keys,
        /// released the way this kind is.
        fn release(self, parked: &mut ParkedClaims, claim: &StateClaim) -> Vec<StateClaim> {
            match self {
                Self::Unproven | Self::Heard => {
                    parked.release(claim.anchor.shard, claim.anchor.height)
                }
                Self::Early | Self::Unasked => {
                    parked.release_early(&claim.keys().into_iter().collect())
                }
            }
        }
    }

    /// `held`'s counts agree with a recount of its claims, and it is
    /// within its budget.
    fn assert_accounted(held: &Held) {
        let mut by_shard: BTreeMap<ShardId, usize> = BTreeMap::new();
        for ((shard, _), claims) in &held.by_anchor {
            assert!(!claims.is_empty(), "no key holds an empty list");
            *by_shard.entry(*shard).or_default() +=
                claims.iter().map(StateClaim::wire_weight).sum::<usize>();
        }
        assert_eq!(held.by_shard, by_shard);
        assert_eq!(held.total, by_shard.values().sum::<usize>());
        assert_eq!(
            held.heaviest,
            by_shard
                .iter()
                .map(|(shard, bytes)| (*bytes, *shard))
                .collect::<BTreeSet<_>>(),
        );
        assert!(held.total <= held.budget);
    }

    /// Fill `kind` from shards after the first `from` with claims of at
    /// most a section each, at height 1, until it holds `left` more bytes.
    ///
    /// Where the last claim would weigh under half a section, the one
    /// before it gives up the difference, so no claim weighs less than
    /// half a section and every one outweighs its bare terms.
    fn fill(kind: Kind, parked: &mut ParkedClaims, from: usize, mut left: usize) {
        const HALF: usize = MAX_STATE_CLAIMS_BYTES / 2;
        assert!(left == 0 || left >= HALF, "{left} B is less than one claim");
        let mut index = from;
        while left > 0 {
            let weight = if left <= MAX_STATE_CLAIMS_BYTES {
                left
            } else {
                MAX_STATE_CLAIMS_BYTES.min(left - HALF)
            };
            kind.hold(parked, kind.claim(nth_shard(index), 1, 3, weight))
                .expect("within the budget");
            left -= weight;
            index += 1;
        }
    }

    /// What a flooding shard pushes at each height, and how many shards
    /// flood: a full section from eight shards, which pushes every kind
    /// past twice its budget, or a single cell from every other shard,
    /// which leaves each flooder as light as it can be.
    const FLOODS: [(usize, usize); 2] = [
        (MAX_STATE_CLAIMS_BYTES, 8),
        (SINGLE_CELL_CLAIM_P99_BYTES, MAX_SHARDS - 1),
    ];

    /// A one-cell record claim at the measured size that carries the
    /// widest record value and names one crossing.
    const RECORD_CLAIM_BYTES: usize =
        SINGLE_CELL_CLAIM_P99_BYTES + MAX_HELD_VALUE_BYTES + STATE_CLAIM_CROSSING_BYTES;

    /// The honest shard's two claims of `honest` bytes in every kind, the
    /// lower height first, then `flooders` other shards each pushing a
    /// claim of `weight` at each height it may hold, in every kind.
    fn flooded(
        honest: usize,
        weight: usize,
        flooders: usize,
    ) -> (ParkedClaims, Vec<(Kind, [StateClaim; 2])>) {
        let mut parked = ParkedClaims::new();
        let mut pushed = Vec::new();
        for kind in KINDS {
            // A release takes both unproven kinds at its anchor, so the
            // heard claims sit at heights of their own.
            let below = if matches!(kind, Kind::Heard) { 2 } else { 0 };
            let claims = [(below + 1, 1), (below + 2, 2)]
                .map(|(height, seed)| kind.claim(nth_shard(0), height, seed, honest));
            for claim in &claims {
                kind.hold(&mut parked, claim.clone())
                    .expect("room for an honest push");
            }
            pushed.push((kind, claims));
        }
        for index in 1..=flooders {
            for kind in KINDS {
                for height in 1..=kind.held(&parked).max_heights {
                    let claim = kind.claim(nth_shard(index), height, 200, weight);
                    let _ = kind.hold(&mut parked, claim);
                }
            }
        }
        (parked, pushed)
    }

    /// Every other shard pushing all it may leaves the honest shard's
    /// share of bytes, two single-cell claims, held in every kind, and
    /// they are released as ever.
    #[test]
    fn a_flood_leaves_an_honest_shard_its_share_of_bytes() {
        for (weight, flooders) in FLOODS {
            let (mut parked, honest) = flooded(SINGLE_CELL_CLAIM_P99_BYTES, weight, flooders);
            for (kind, claims) in honest {
                for claim in claims {
                    assert_eq!(
                        kind.release(&mut parked, &claim),
                        vec![claim],
                        "{kind:?} kept the honest push under a flood of {weight} B claims",
                    );
                }
            }
        }
    }

    /// The share is in bytes: under a flood of single-cell claims, an
    /// honest shard pushing two record claims holds more than its share
    /// and gives one up in its own order, and the one that fits its share
    /// stays.
    #[test]
    fn an_honest_shard_keeps_the_record_claims_its_share_of_bytes_fits() {
        let share = 2 * SINGLE_CELL_CLAIM_P99_BYTES;
        assert!(
            (RECORD_CLAIM_BYTES..2 * RECORD_CLAIM_BYTES).contains(&share),
            "the share fits one record claim and not two",
        );
        let (mut parked, honest) = flooded(
            RECORD_CLAIM_BYTES,
            SINGLE_CELL_CLAIM_P99_BYTES,
            MAX_SHARDS - 1,
        );
        for (kind, [lower, higher]) in honest {
            let (kept, gone) = match kind.held(&parked).gives_way {
                GivesWay::Lowest => (higher, lower),
                GivesWay::Highest => (lower, higher),
            };
            assert_eq!(
                kind.release(&mut parked, &gone),
                vec![],
                "{kind:?} gave one up"
            );
            assert_eq!(
                kind.release(&mut parked, &kept),
                vec![kept],
                "{kind:?} kept the record claim its share fits",
            );
        }
    }

    /// Under the flood each kind holds no more than its budget, its
    /// counts are the claims' own weights, and the flooders hold within
    /// one claim of each other: a full kind makes room by taking from the
    /// most, never by refusing whoever arrives last.
    #[test]
    fn the_budget_holds_under_a_flood() {
        for (weight, flooders) in FLOODS {
            let (parked, _) = flooded(SINGLE_CELL_CLAIM_P99_BYTES, weight, flooders);
            for kind in KINDS {
                let held = kind.held(&parked);
                assert_accounted(held);
                assert!(
                    held.total > held.budget - weight,
                    "{kind:?} was filled to its budget by {weight} B claims",
                );
                let bytes: Vec<usize> = (1..=flooders)
                    .map(|index| held.bytes(nth_shard(index)))
                    .collect();
                let most = bytes.iter().max().expect("flooders");
                let least = bytes.iter().min().expect("flooders");
                assert!(
                    most - least <= weight,
                    "{kind:?} flooders hold {least} B to {most} B of {weight} B claims",
                );
            }
            assert_eq!(
                parked.weight(),
                KINDS
                    .iter()
                    .map(|kind| kind.held(&parked).total)
                    .sum::<usize>()
            );
        }
    }

    /// A lone shard at its caps fits each kind whole, and every shard at
    /// two single-cell claims fits beside the others: neither evicts.
    #[test]
    fn honest_load_evicts_nothing() {
        let mut lone = ParkedClaims::new();
        for kind in KINDS {
            let heights = kind.held(&lone).max_heights;
            for height in 1..=heights {
                let claim = kind.claim(nth_shard(1), height, 1, MAX_STATE_CLAIMS_BYTES);
                assert_eq!(kind.hold(&mut lone, claim), Ok(()), "{kind:?}");
            }
            assert_eq!(kind.held(&lone).total, heights * MAX_STATE_CLAIMS_BYTES);
            assert_accounted(kind.held(&lone));
        }

        let mut shared = ParkedClaims::new();
        for index in 0..MAX_SHARDS {
            for kind in KINDS {
                for (height, seed) in [(1, 1), (2, 2)] {
                    let claim =
                        kind.claim(nth_shard(index), height, seed, SINGLE_CELL_CLAIM_P99_BYTES);
                    assert_eq!(kind.hold(&mut shared, claim), Ok(()), "{kind:?}");
                }
            }
        }
        assert_eq!(shared.len(), MAX_SHARDS * 2 * KINDS.len());
    }

    /// Releasing one of two claims at a key leaves the other held, and
    /// the counts match what is left.
    #[test]
    fn a_partial_release_keeps_the_accounting() {
        let mut parked = ParkedClaims::new();
        let other = nth_shard(1);
        parked.hold_early(claim_at(5, 1_000, 1)).unwrap();
        parked.hold_early(claim_at(5, 1_000, 2)).unwrap();
        parked
            .hold_early(Kind::Early.claim(other, 5, 3, 1_000))
            .unwrap();
        let released = parked.release_early(&BTreeSet::from([test_key(1)]));
        assert_eq!(released, vec![claim_at(5, 1_000, 1)]);
        assert_accounted(&parked.early);
        assert_eq!(
            parked.early.bytes(SHARD),
            claim_at(5, 1_000, 2).wire_weight()
        );
        assert_eq!(
            parked.release_early(&BTreeSet::from([test_key(2)])),
            vec![claim_at(5, 1_000, 2)],
        );
        assert_accounted(&parked.early);
        assert_eq!(parked.early.total, 1_000);
    }

    fn with_recorder<R>(recorder: &MemoryRecorder, f: impl FnOnce() -> R) -> R {
        let scoped: std::sync::Arc<dyn MetricsRecorder> = std::sync::Arc::new(recorder.clone());
        with_scoped_recorder(scoped, f)
    }

    /// Over the budget, the shard holding the most gives up one height,
    /// the lowest of a proven kind and the highest of an unproven one,
    /// and the lighter arrival and every other holder keep everything.
    #[test]
    fn the_heaviest_shard_gives_way_in_its_own_order() {
        for kind in KINDS {
            let mut parked = ParkedClaims::new();
            let heaviest = nth_shard(1);
            // Short of the whole budget, so other shards hold the rest.
            let heights = kind.held(&parked).max_heights.min(24);
            for height in 1..=heights {
                kind.hold(
                    &mut parked,
                    kind.claim(heaviest, height, 1, MAX_STATE_CLAIMS_BYTES),
                )
                .expect("within the shard's caps");
            }
            let budget = kind.held(&parked).budget;
            fill(
                kind,
                &mut parked,
                2,
                budget - heights * MAX_STATE_CLAIMS_BYTES,
            );
            assert_eq!(kind.held(&parked).total, budget);
            let others = kind.held(&parked).by_shard.len() - 1;
            assert!(others > 0, "{kind:?} has other holders");

            let recorder = MemoryRecorder::new();
            let lighter = kind.claim(nth_shard(0), 1, 2, SINGLE_CELL_CLAIM_P99_BYTES);
            let held = with_recorder(&recorder, || kind.hold(&mut parked, lighter.clone()));
            assert_eq!(held, Ok(()), "{kind:?}");
            assert_eq!(
                recorder.counter("crossing_pushes_dropped", Some("crowded")),
                1
            );
            let gone = match kind.held(&parked).gives_way {
                GivesWay::Lowest => 1,
                GivesWay::Highest => heights,
            };
            let left: Vec<usize> = kind
                .held(&parked)
                .keys_of(heaviest)
                .map(|(_, height)| usize::try_from(height.inner()).expect("small"))
                .collect();
            assert_eq!(
                left,
                (1..=heights)
                    .filter(|height| *height != gone)
                    .collect::<Vec<_>>(),
                "{kind:?} gave up its own height",
            );
            assert_eq!(
                kind.held(&parked).total,
                budget - MAX_STATE_CLAIMS_BYTES + SINGLE_CELL_CLAIM_P99_BYTES,
                "{kind:?}: nothing else went",
            );
            assert_eq!(
                kind.held(&parked).by_shard.len(),
                others + 2,
                "{kind:?}: every other holder stayed",
            );
            assert_accounted(kind.held(&parked));
            assert_eq!(kind.release(&mut parked, &lighter), vec![lighter]);
        }
    }

    /// Over the budget with the arrival's shard tied for the most, the
    /// arrival is the one refused, counted only by its refusal, and the
    /// other holders keep everything.
    #[test]
    fn a_tie_evicts_the_arrival() {
        for kind in KINDS {
            let mut parked = ParkedClaims::new();
            let budget = kind.held(&parked).budget;
            fill(kind, &mut parked, 1, budget);
            let before = parked.len();

            let recorder = MemoryRecorder::new();
            let arrival = kind.claim(nth_shard(0), 1, 2, MAX_STATE_CLAIMS_BYTES);
            let held = with_recorder(&recorder, || kind.hold(&mut parked, arrival));
            assert_eq!(held, Err("crowded"), "{kind:?}");
            assert_eq!(
                recorder.counter("crossing_pushes_dropped", Some("crowded")),
                0
            );
            assert_eq!(parked.len(), before, "{kind:?}: the others kept all");
            assert_eq!(kind.held(&parked).total, budget);
            assert_accounted(kind.held(&parked));
        }
    }

    /// Over the budget with the arrival's shard tied for the most in a
    /// proven kind, that shard gives up its own older height and the
    /// arrival is held, while the shard it ties keeps everything.
    #[test]
    fn a_tied_arrival_in_a_proven_kind_gives_up_its_older_height() {
        for kind in [Kind::Early, Kind::Unasked] {
            let mut parked = ParkedClaims::new();
            let arriving = nth_shard(0);
            let tied = nth_shard(1);
            let older = kind.claim(arriving, 1, 1, MAX_STATE_CLAIMS_BYTES);
            kind.hold(&mut parked, older.clone()).expect("room");
            for height in 1..=2 {
                kind.hold(
                    &mut parked,
                    kind.claim(tied, height, 3, MAX_STATE_CLAIMS_BYTES),
                )
                .expect("room");
            }
            let budget = kind.held(&parked).budget;
            fill(kind, &mut parked, 2, budget - 3 * MAX_STATE_CLAIMS_BYTES);

            let recorder = MemoryRecorder::new();
            let arrival = kind.claim(arriving, 2, 2, MAX_STATE_CLAIMS_BYTES);
            let held = with_recorder(&recorder, || kind.hold(&mut parked, arrival.clone()));
            assert_eq!(held, Ok(()), "{kind:?}");
            assert_eq!(
                recorder.counter("crossing_pushes_dropped", Some("crowded")),
                1
            );
            assert_eq!(kind.held(&parked).bytes(tied), 2 * MAX_STATE_CLAIMS_BYTES);
            assert_eq!(kind.held(&parked).total, budget);
            assert_accounted(kind.held(&parked));
            assert_eq!(kind.release(&mut parked, &older), vec![], "{kind:?}");
            assert_eq!(kind.release(&mut parked, &arrival), vec![arrival]);
        }
    }
}
