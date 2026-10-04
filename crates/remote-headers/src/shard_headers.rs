//! One remote shard's held headers, indexed for incremental retention.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, ValidatorId, Verified, WeightedTimestamp,
};

use crate::coordinator::RemoteHeaderMemoryStats;

/// The weighted timestamp a held header's retention is measured on: its
/// parent QC's, the moment the remote committee certified the block it
/// extends.
fn retention_ts(header: &CertifiedBlockHeader) -> WeightedTimestamp {
    header.header().parent_qc().weighted_timestamp()
}

/// What [`ShardHeaders::add_candidate`] did with a sender's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// The sender already holds a candidate at the height; nothing changed.
    Duplicate,
    /// The first candidate at the height: it is the one to verify.
    First,
    /// Held behind an earlier candidate still being verified.
    Queued,
}

/// Everything held from one remote shard's chain, keyed by height.
///
/// Each header map carries an index ordered by [`retention_ts`], so the
/// retention pass visits only the entries it drops rather than the whole
/// store. An index holds exactly one `(timestamp, height)` per occupied
/// height of its map; the maps change only through the methods here,
/// which keep that true.
#[derive(Default)]
pub struct ShardHeaders {
    /// Highest seen `(block_height, weighted_timestamp)`. The timestamp is
    /// the pruning anchor — retention is measured against how long ago (in
    /// remote wall-clock) each stored header was produced, so pruning stays
    /// meaningful when remote block cadence varies.
    tip: (BlockHeight, WeightedTimestamp),

    /// Headers received but not yet QC-verified, one candidate per sender.
    /// Multiple senders may gossip the same header; all candidates are kept
    /// until QC verification picks the valid one. A height holds at least
    /// one candidate.
    pending: BTreeMap<BlockHeight, BTreeMap<ValidatorId, Arc<CertifiedBlockHeader>>>,
    /// `pending` by its newest candidate's timestamp: a height is retained
    /// while any of its candidates is.
    pending_by_age: BTreeSet<(WeightedTimestamp, BlockHeight)>,

    /// Verified committed block headers — one per height. Holds the
    /// BFT-transitive trust composite produced by
    /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`].
    verified: BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>,
    /// The sync frontier `verified` is indexed against: heights at or
    /// below it are walked, heights above it are not. `None` walks every
    /// height. The two sides age out under different bounds, so each has
    /// an index of its own and a pass reads only the entries it drops.
    walked_through: Option<BlockHeight>,
    /// `verified` at or below `walked_through`, by each canonical
    /// header's timestamp.
    walked_by_age: BTreeSet<(WeightedTimestamp, BlockHeight)>,
    /// `verified` above `walked_through`, by each canonical header's
    /// timestamp.
    unwalked_by_age: BTreeSet<(WeightedTimestamp, BlockHeight)>,

    /// Heights in `verified` whose header is commit-proven: we also hold
    /// its committing structure — a round-contiguous certified child, or a
    /// parent-hash link under an already-proven descendant (a block that
    /// commits as the prefix of a later two-chain, INV-SHARD-4). A bare QC
    /// certifies availability, not canonicality: an f+1..2f corrupt
    /// committee can certify two blocks at one height without violating
    /// the safe-vote rule, but committing both is impossible below f+1
    /// corrupt seats (INV-SHARD-1). Cross-shard consumers therefore gate
    /// provision and execution-certificate consumption on the
    /// `RemoteHeaderCommitted` continuation this set drives, never on
    /// `RemoteHeaderAdmitted` alone. Always a subset of `verified`'s
    /// heights; evicted with them.
    proven: BTreeSet<BlockHeight>,

    /// Heights in `proven` whose `RemoteHeaderCommitted` continuation has
    /// been emitted. A fork fence withholds the promotion of a proven
    /// height without forgetting the proof, so the fence-clear sweep reads
    /// the difference between the two sets to release exactly the withheld
    /// heights — each proven height promotes exactly once across fence
    /// transitions. Always a subset of `proven`; evicted with it.
    promoted: BTreeSet<BlockHeight>,

    /// Verified headers that lost the canonical `verified` slot to a
    /// first-seen different-hash header at their height — the off-branch
    /// siblings of a committee fork. A QC certifies availability, not
    /// canonicality, so a sibling here is a genuine committee-signed block
    /// on a losing branch; held only to assemble a
    /// [`ShardForkProof`](hyperscale_types::ShardForkProof) once both
    /// branches are commit-proven. Empty under honest operation (an honest
    /// committee produces one chain). A height holds at least one sibling.
    fork_siblings: BTreeMap<BlockHeight, Vec<Arc<Verified<CertifiedBlockHeader>>>>,
    /// `fork_siblings` by each height's oldest sibling: the first to age
    /// out is the one a prune has to visit the height for.
    siblings_by_age: BTreeSet<(WeightedTimestamp, BlockHeight)>,
}

impl ShardHeaders {
    pub const fn tip(&self) -> (BlockHeight, WeightedTimestamp) {
        self.tip
    }

    pub fn pending(
        &self,
        height: BlockHeight,
    ) -> Option<&BTreeMap<ValidatorId, Arc<CertifiedBlockHeader>>> {
        self.pending.get(&height)
    }

    pub fn verified(&self, height: BlockHeight) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.verified.get(&height)
    }

    pub fn siblings(&self, height: BlockHeight) -> &[Arc<Verified<CertifiedBlockHeader>>] {
        self.fork_siblings.get(&height).map_or(&[], Vec::as_slice)
    }

    pub fn is_proven(&self, height: BlockHeight) -> bool {
        self.proven.contains(&height)
    }

    pub fn is_promoted(&self, height: BlockHeight) -> bool {
        self.promoted.contains(&height)
    }

    /// The proven heights whose promotion a fork fence withheld, ascending.
    pub fn withheld(&self) -> impl Iterator<Item = BlockHeight> + '_ {
        self.proven.difference(&self.promoted).copied()
    }

    /// Raise the tip to `(height, ts)` if `height` is above it, returning
    /// the tip's timestamp.
    pub fn raise_tip(&mut self, height: BlockHeight, ts: WeightedTimestamp) -> WeightedTimestamp {
        if height > self.tip.0 {
            self.tip = (height, ts);
        }
        self.tip.1
    }

    /// The timestamp `pending_by_age` holds `height` at.
    fn pending_age(&self, height: BlockHeight) -> Option<WeightedTimestamp> {
        self.pending
            .get(&height)?
            .values()
            .map(|header| retention_ts(header))
            .max()
    }

    /// The timestamp `siblings_by_age` holds `height` at.
    fn siblings_age(&self, height: BlockHeight) -> Option<WeightedTimestamp> {
        self.fork_siblings
            .get(&height)?
            .iter()
            .map(|header| retention_ts(header))
            .min()
    }

    /// Hold `header` as `sender`'s candidate at `height`.
    pub fn add_candidate(
        &mut self,
        height: BlockHeight,
        sender: ValidatorId,
        header: Arc<CertifiedBlockHeader>,
    ) -> Candidate {
        let before = self.pending_age(height);
        let candidates = self.pending.entry(height).or_default();
        if candidates.contains_key(&sender) {
            return Candidate::Duplicate;
        }
        let first = candidates.is_empty();
        candidates.insert(sender, header);
        self.reindex_pending(height, before);
        if first {
            Candidate::First
        } else {
            Candidate::Queued
        }
    }

    /// Drop `sender`'s candidate at `height`, and the height with it once
    /// no candidate is left.
    pub fn remove_candidate(
        &mut self,
        height: BlockHeight,
        sender: ValidatorId,
    ) -> Option<Arc<CertifiedBlockHeader>> {
        let before = self.pending_age(height);
        let candidates = self.pending.get_mut(&height)?;
        let removed = candidates.remove(&sender);
        if candidates.is_empty() {
            self.pending.remove(&height);
        }
        self.reindex_pending(height, before);
        removed
    }

    /// The lowest-sender candidate at `height`: the next to verify.
    pub fn first_candidate(
        &self,
        height: BlockHeight,
    ) -> Option<(ValidatorId, Arc<CertifiedBlockHeader>)> {
        self.pending
            .get(&height)?
            .iter()
            .next()
            .map(|(sender, header)| (*sender, Arc::clone(header)))
    }

    /// Drop every candidate at `height`.
    pub fn clear_pending(&mut self, height: BlockHeight) {
        if let Some(age) = self.pending_age(height) {
            self.pending_by_age.remove(&(age, height));
            self.pending.remove(&height);
        }
    }

    fn reindex_pending(&mut self, height: BlockHeight, before: Option<WeightedTimestamp>) {
        if let Some(age) = before {
            self.pending_by_age.remove(&(age, height));
        }
        if let Some(age) = self.pending_age(height) {
            self.pending_by_age.insert((age, height));
        }
    }

    fn reindex_siblings(&mut self, height: BlockHeight, before: Option<WeightedTimestamp>) {
        if let Some(age) = before {
            self.siblings_by_age.remove(&(age, height));
        }
        if let Some(age) = self.siblings_age(height) {
            self.siblings_by_age.insert((age, height));
        }
    }

    /// Seat `header` in the canonical slot at its height, returning the
    /// header it displaces.
    pub fn set_verified(
        &mut self,
        header: Arc<Verified<CertifiedBlockHeader>>,
    ) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        let height = header.height();
        let age = retention_ts(&header);
        let displaced = self.verified.insert(height, header);
        if let Some(displaced) = &displaced {
            self.verified_index_mut(height)
                .remove(&(retention_ts(displaced), height));
        }
        self.verified_index_mut(height).insert((age, height));
        displaced
    }

    /// Hold `sibling` off the canonical slot at its height. False if a
    /// copy of it is already held.
    pub fn add_sibling(&mut self, sibling: Arc<Verified<CertifiedBlockHeader>>) -> bool {
        let height = sibling.height();
        if self
            .siblings(height)
            .iter()
            .any(|held| held.block_hash() == sibling.block_hash())
        {
            return false;
        }
        let before = self.siblings_age(height);
        self.fork_siblings.entry(height).or_default().push(sibling);
        self.reindex_siblings(height, before);
        true
    }

    /// Swap the sibling at `position` of `height` into the canonical slot,
    /// holding the occupant it displaces as a sibling in its place.
    /// Returns the newly canonical header.
    pub fn seat_sibling(
        &mut self,
        height: BlockHeight,
        position: usize,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let before = self.siblings_age(height);
        let siblings = self
            .fork_siblings
            .get_mut(&height)
            .expect("seated sibling is held");
        let seated = siblings.swap_remove(position);
        let squatter = self
            .set_verified(Arc::clone(&seated))
            .expect("a sibling is held only beside a canonical occupant");
        self.fork_siblings.entry(height).or_default().push(squatter);
        self.reindex_siblings(height, before);
        seated
    }

    pub fn mark_proven(&mut self, height: BlockHeight) {
        self.proven.insert(height);
    }

    pub fn mark_promoted(&mut self, height: BlockHeight) {
        self.promoted.insert(height);
    }

    /// The age index `height` belongs in under the current frontier.
    fn verified_index_mut(
        &mut self,
        height: BlockHeight,
    ) -> &mut BTreeSet<(WeightedTimestamp, BlockHeight)> {
        if self
            .walked_through
            .is_some_and(|frontier| height > frontier)
        {
            &mut self.unwalked_by_age
        } else {
            &mut self.walked_by_age
        }
    }

    /// Re-index `verified` against `frontier`, moving only the heights
    /// that cross from one side to the other.
    fn walk_to(&mut self, frontier: Option<BlockHeight>) {
        if frontier == self.walked_through {
            return;
        }
        let (from, to) = (self.walked_through, frontier);
        // Heights in `(low, high]` change side; `None` stands above every
        // height, as every height is walked under it.
        let bound = |f: Option<BlockHeight>| f.map_or(Bound::Unbounded, Bound::Included);
        let (low, high, walking) = match (from, to) {
            (Some(a), Some(b)) if a < b => (a, bound(to), true),
            (Some(a), Some(b)) => (b, bound(Some(a)), false),
            (Some(a), None) => (a, Bound::Unbounded, true),
            (None, Some(b)) => (b, Bound::Unbounded, false),
            (None, None) => unreachable!("an unchanged frontier returned above"),
        };
        let moved: Vec<(WeightedTimestamp, BlockHeight)> = self
            .verified
            .range((Bound::Excluded(low), high))
            .map(|(&height, header)| (retention_ts(header), height))
            .collect();
        let (out, into) = if walking {
            (&mut self.unwalked_by_age, &mut self.walked_by_age)
        } else {
            (&mut self.walked_by_age, &mut self.unwalked_by_age)
        };
        for entry in moved {
            out.remove(&entry);
            into.insert(entry);
        }
        self.walked_through = frontier;
    }

    /// Drop the canonical header at `height`, with its proof and promotion.
    fn evict_verified(&mut self, height: BlockHeight) {
        if let Some(header) = self.verified.remove(&height) {
            self.verified_index_mut(height)
                .remove(&(retention_ts(&header), height));
        }
        self.proven.remove(&height);
        self.promoted.remove(&height);
    }

    /// Drop what has aged past `cutoff`, visiting only the entries it
    /// drops and the frontier.
    ///
    /// A pending height goes once its newest candidate is older than
    /// `cutoff`, and a fork sibling once it is. A verified header older
    /// than `cutoff` goes unless it is the walked `frontier`, or lies above
    /// the frontier with a timestamp at or past `horizon`; one held for
    /// either reason stays in the index and is weighed again on the next
    /// pass.
    pub fn prune(
        &mut self,
        cutoff: WeightedTimestamp,
        horizon: WeightedTimestamp,
        frontier: Option<BlockHeight>,
    ) {
        while let Some(&(age, height)) = self.pending_by_age.first()
            && age < cutoff
        {
            self.pending_by_age.pop_first();
            self.pending.remove(&height);
        }

        self.walk_to(frontier);
        let expired: Vec<BlockHeight> = self
            .walked_by_age
            .range(..(cutoff, BlockHeight::GENESIS))
            .map(|&(_, height)| height)
            .filter(|&height| frontier != Some(height))
            .chain(
                self.unwalked_by_age
                    .range(..(horizon.min(cutoff), BlockHeight::GENESIS))
                    .map(|&(_, height)| height),
            )
            .collect();
        for height in expired {
            self.evict_verified(height);
        }

        while let Some(&(age, height)) = self.siblings_by_age.first()
            && age < cutoff
        {
            self.siblings_by_age.pop_first();
            let Some(siblings) = self.fork_siblings.get_mut(&height) else {
                continue;
            };
            siblings.retain(|sibling| retention_ts(sibling) >= cutoff);
            if siblings.is_empty() {
                self.fork_siblings.remove(&height);
            } else {
                self.reindex_siblings(height, None);
            }
        }
    }

    /// Drop everything held strictly above `frontier`.
    pub fn evict_above(&mut self, frontier: BlockHeight) {
        let above = frontier.next();
        for (height, candidates) in self.pending.split_off(&above) {
            if let Some(age) = candidates.values().map(|header| retention_ts(header)).max() {
                self.pending_by_age.remove(&(age, height));
            }
        }
        for (height, header) in self.verified.split_off(&above) {
            self.verified_index_mut(height)
                .remove(&(retention_ts(&header), height));
        }
        self.proven.split_off(&above);
        self.promoted.split_off(&above);
        for (height, siblings) in self.fork_siblings.split_off(&above) {
            if let Some(age) = siblings.iter().map(|header| retention_ts(header)).min() {
                self.siblings_by_age.remove(&(age, height));
            }
        }
    }

    /// Add this shard's holdings to the coordinator-wide counts.
    pub fn count_into(&self, stats: &mut RemoteHeaderMemoryStats) {
        stats.pending_headers += self.pending.values().map(BTreeMap::len).sum::<usize>();
        stats.verified_headers += self.verified.len();
        stats.proven_headers += self.proven.len();
        stats.fork_siblings += self.fork_siblings.values().map(Vec::len).sum::<usize>();
    }
}

#[cfg(test)]
impl ShardHeaders {
    /// Panic unless every age index holds exactly the `(timestamp, height)`
    /// its map implies, and `promoted ⊆ proven ⊆ verified`.
    pub fn assert_indexed(&self) {
        let pending: BTreeSet<_> = self
            .pending
            .keys()
            .map(|&height| (self.pending_age(height).expect("no empty height"), height))
            .collect();
        assert_eq!(self.pending_by_age, pending, "pending index");
        let (unwalked, walked): (BTreeSet<_>, BTreeSet<_>) = self
            .verified
            .iter()
            .map(|(&height, header)| (retention_ts(header), height))
            .partition(|&(_, height)| self.walked_through.is_some_and(|f| height > f));
        assert_eq!(self.walked_by_age, walked, "walked index");
        assert_eq!(self.unwalked_by_age, unwalked, "unwalked index");
        let siblings: BTreeSet<_> = self
            .fork_siblings
            .keys()
            .map(|&height| (self.siblings_age(height).expect("no empty height"), height))
            .collect();
        assert_eq!(self.siblings_by_age, siblings, "sibling index");
        assert!(
            self.proven
                .iter()
                .all(|height| self.verified.contains_key(height))
        );
        assert!(self.promoted.is_subset(&self.proven));
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, ProposerTimestamp,
        QuorumCertificate, Round, ShardId, SignerBitfield,
    };

    use super::*;

    /// A header at `height` whose parent QC stamps `parent_qc_wt`.
    fn header_at(height: BlockHeight, parent_qc_wt: u64) -> Arc<CertifiedBlockHeader> {
        let shard = ShardId::leaf(2, 1);
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            shard,
            BlockHeight::new(height.inner().saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_qc_wt),
        );
        Arc::new(CertifiedBlockHeader::new(header, qc))
    }

    /// A pending height is held while any of its candidates is inside the
    /// retention, so it is indexed at its newest candidate's timestamp and
    /// re-indexed as candidates come and go.
    #[test]
    fn a_pending_height_ages_with_its_newest_candidate() {
        let height = BlockHeight::new(5);
        let old = header_at(height, 5_000);
        let new = header_at(height, 50_000);
        let cutoff = WeightedTimestamp::from_millis(40_000);
        let mut store = ShardHeaders::default();

        assert_eq!(
            store.add_candidate(height, ValidatorId::new(1), Arc::clone(&old)),
            Candidate::First
        );
        assert_eq!(
            store.add_candidate(height, ValidatorId::new(2), Arc::clone(&new)),
            Candidate::Queued
        );
        assert_eq!(
            store.add_candidate(height, ValidatorId::new(2), Arc::clone(&old)),
            Candidate::Duplicate
        );
        store.assert_indexed();

        store.prune(cutoff, WeightedTimestamp::ZERO, None);
        assert_eq!(
            store.pending(height).map(BTreeMap::len),
            Some(2),
            "one candidate inside the retention holds the height",
        );
        store.assert_indexed();

        store.remove_candidate(height, ValidatorId::new(2));
        store.assert_indexed();
        store.prune(cutoff, WeightedTimestamp::ZERO, None);
        assert!(
            store.pending(height).is_none(),
            "with only the stale candidate left the height goes",
        );
        store.assert_indexed();
    }

    fn verified_at(height: u64, parent_qc_wt: u64) -> Arc<Verified<CertifiedBlockHeader>> {
        let header = header_at(BlockHeight::new(height), parent_qc_wt);
        Arc::new(Verified::new_unchecked_for_test(Arc::unwrap_or_clone(
            header,
        )))
    }

    fn held(store: &ShardHeaders) -> Vec<u64> {
        store.verified.keys().map(|h| h.inner()).collect()
    }

    /// A verified header past the cutoff goes when walked, stays above the
    /// frontier until the horizon, and the frontier itself always stays —
    /// however the frontier moves between passes.
    #[test]
    fn a_verified_header_ages_on_its_side_of_the_frontier() {
        let mut store = ShardHeaders::default();
        for height in 1..=10 {
            store.set_verified(verified_at(height, height * 1_000));
        }
        store.assert_indexed();
        let cutoff = WeightedTimestamp::from_millis(9_000);
        let horizon = WeightedTimestamp::from_millis(3_000);

        store.prune(cutoff, horizon, Some(BlockHeight::new(5)));
        store.assert_indexed();
        assert_eq!(
            held(&store),
            vec![5, 6, 7, 8, 9, 10],
            "walked heights past the cutoff go; the frontier, and unwalked heights inside the horizon, stay",
        );

        store.prune(cutoff, horizon, Some(BlockHeight::new(7)));
        store.assert_indexed();
        assert_eq!(
            held(&store),
            vec![7, 8, 9, 10],
            "a walk forward releases what it crosses"
        );

        store.prune(cutoff, horizon, Some(BlockHeight::new(4)));
        store.assert_indexed();
        assert_eq!(
            held(&store),
            vec![7, 8, 9, 10],
            "a frontier walked back holds again"
        );
        store.set_verified(verified_at(5, 5_000));
        store.assert_indexed();

        store.prune(cutoff, WeightedTimestamp::from_millis(8_000), None);
        store.assert_indexed();
        assert_eq!(held(&store), vec![9, 10], "no frontier walks every height");
    }
}
