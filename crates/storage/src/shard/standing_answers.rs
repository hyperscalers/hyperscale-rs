//! The answers a consumer's chain holds, counted per producer route: what
//! a block's writes do to them, and a follow of the persisted chain that
//! keeps the count at the store's head.
//!
//! An answer is a leaf [`CrossingLeaf::read`] reads as one, so a cell
//! shaped like an answer at a key its derivation does not reach is not
//! counted.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt::NibblePath;
use hyperscale_types::{
    AnswerDelta, BlockHash, BlockHeight, RoutePrefix, StandingAnswers, SubstateKey,
};
use hyperscale_vm_effects::{CrossingLeaf, ProtocolHasher};

use crate::{
    CrossingCursor, PendingChain, ShardStorage, SubstateStore, Substates, key_under_prefix,
};

/// The producer route of the answer `value` at `key` is, or `None`
/// where the leaf is no answer.
#[must_use]
pub fn answer_route(key: SubstateKey, value: &[u8]) -> Option<RoutePrefix> {
    match CrossingLeaf::read(&ProtocolHasher, key, value)? {
        CrossingLeaf::Answer { id, .. } => Some(RoutePrefix::of(id.producer)),
        CrossingLeaf::Record { .. } => None,
    }
}

/// What a block's written `cells` do to the answers under `under`.
///
/// A cell written over an answer `parent` holds takes one off that
/// answer's route, and a cell written as an answer puts one on its own.
/// An overwrite does both.
pub fn answer_delta<'a>(
    cells: impl IntoIterator<Item = (&'a SubstateKey, &'a Option<Vec<u8>>)>,
    parent: &(impl Substates + ?Sized),
    under: &NibblePath,
) -> AnswerDelta {
    let mut delta = AnswerDelta::default();
    for (&key, written) in cells {
        if !key_under_prefix(&key.to_bytes(), under) {
            continue;
        }
        if let Some(route) = parent.cell(key).and_then(|prior| answer_route(key, &prior)) {
            delta.take(route);
        }
        if let Some(route) = written
            .as_deref()
            .and_then(|value| answer_route(key, value))
        {
            delta.put(route);
        }
    }
    delta
}

/// The persisted chain a follow reads its count off.
pub trait AnswerSource {
    /// The newest persisted block, `None` while nothing is persisted.
    fn head(&self) -> Option<(BlockHeight, BlockHash)>;

    /// The crossing rows under `under` the store lists.
    fn rows(&self, under: &NibblePath) -> Vec<SubstateKey>;

    /// The rows under `under` put or removed above `since` and at or
    /// below `through`, or `None` where the store cannot say, with where
    /// a reader stands once it has read them at `through`.
    fn changes(
        &self,
        under: &NibblePath,
        since: Option<CrossingCursor>,
        through: BlockHeight,
    ) -> (Option<Vec<SubstateKey>>, CrossingCursor);

    /// Each of `keys` as the persisted block `at` left it.
    fn read_at(&self, at: (BlockHeight, BlockHash), keys: &[SubstateKey]) -> Vec<Option<Vec<u8>>>;
}

impl<S: ShardStorage> AnswerSource for Arc<PendingChain<S>> {
    fn head(&self) -> Option<(BlockHeight, BlockHash)> {
        let (height, hash) = self.base().committed_head();
        Some((height, hash?))
    }

    fn rows(&self, under: &NibblePath) -> Vec<SubstateKey> {
        self.base().crossing_rows(under)
    }

    fn changes(
        &self,
        under: &NibblePath,
        since: Option<CrossingCursor>,
        through: BlockHeight,
    ) -> (Option<Vec<SubstateKey>>, CrossingCursor) {
        self.base().crossing_changes(under, since, through)
    }

    fn read_at(&self, at: (BlockHeight, BlockHash), keys: &[SubstateKey]) -> Vec<Option<Vec<u8>>> {
        let view = self.view_at(at.1, at.0);
        let pinned = view.snapshot();
        keys.iter().map(|key| pinned.cell(*key)).collect()
    }
}

/// A count of the answers under one prefix, kept at the persisted
/// chain's head: every answer's key with its route, and where in the
/// store's crossing journal the count stands.
#[derive(Debug, Clone)]
pub struct AnswerFollow {
    routes: HashMap<SubstateKey, RoutePrefix>,
    count: StandingAnswers,
    cursor: CrossingCursor,
}

impl AnswerFollow {
    /// The count under `under` as `source`'s persisted block `at` left
    /// it, read whole: every row the store lists, each read at `at`.
    ///
    /// The listing is not pinned, so a block persisted while it runs can
    /// add a key `at` does not hold, which reads absent, or drop one it
    /// does. The catch-up from the cursor at `at` names both, so the
    /// count is exact once the follow next catches up.
    pub fn whole(
        source: &impl AnswerSource,
        at: (BlockHeight, BlockHash),
        under: &NibblePath,
    ) -> Self {
        let (_, cursor) = source.changes(under, None, at.0);
        let keys = source.rows(under);
        let mut follow = Self {
            routes: HashMap::new(),
            count: StandingAnswers::default(),
            cursor,
        };
        follow.read(source, at, &keys);
        follow
    }

    /// Advance to `source`'s persisted head and say the count there,
    /// tagged with the height and block it was read at.
    ///
    /// `None` where nothing is persisted, and where the follow read
    /// whole: on its first step, and where the store's journal cannot
    /// say what moved since the cursor.
    pub fn step(
        follow: &mut Option<Self>,
        source: &impl AnswerSource,
        under: &NibblePath,
    ) -> Option<(BlockHeight, BlockHash, StandingAnswers)> {
        let at = source.head()?;
        if let Some(held) = follow.as_mut() {
            let (changed, cursor) = source.changes(under, Some(held.cursor), at.0);
            if let Some(keys) = changed {
                held.read(source, at, &keys);
                held.cursor = cursor;
                return Some((at.0, at.1, held.count.clone()));
            }
        }
        *follow = Some(Self::whole(source, at, under));
        None
    }

    /// The count held.
    #[must_use]
    pub const fn count(&self) -> &StandingAnswers {
        &self.count
    }

    /// Re-read each of `keys` at `at`, taking off the route it held and
    /// putting on the one it reads.
    fn read(
        &mut self,
        source: &impl AnswerSource,
        at: (BlockHeight, BlockHash),
        keys: &[SubstateKey],
    ) {
        for (key, value) in keys.iter().zip(source.read_at(at, keys)) {
            if let Some(route) = self.routes.remove(key) {
                self.count.remove(route);
            }
            if let Some(route) = value.and_then(|value| answer_route(*key, &value)) {
                self.routes.insert(*key, route);
                self.count.add(route);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{Address, AddressClass, CollectionId, Hash};
    use hyperscale_vm_effects::Answered;

    use super::*;
    use crate::CrossingJournal;
    use crate::test_helpers::answer_leaf;

    fn owner(seed: u8) -> Address {
        Address::new([seed; 31], AddressClass::Component)
    }

    /// Cells as a parent holds them.
    struct Cells(BTreeMap<SubstateKey, Vec<u8>>);

    impl Substates for Cells {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            _: Address,
            _: CollectionId,
            _: u128,
            _: u128,
            _: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    /// One persisted block's cells, every key its own row, whose journal
    /// cannot say what moved.
    struct Persisted(Cells);

    impl AnswerSource for Persisted {
        fn head(&self) -> Option<(BlockHeight, BlockHash)> {
            Some((
                BlockHeight::new(1),
                BlockHash::from_raw(Hash::from_bytes(b"one")),
            ))
        }

        fn rows(&self, _: &NibblePath) -> Vec<SubstateKey> {
            self.0.0.keys().copied().collect()
        }

        fn changes(
            &self,
            _: &NibblePath,
            _: Option<CrossingCursor>,
            _: BlockHeight,
        ) -> (Option<Vec<SubstateKey>>, CrossingCursor) {
            CrossingJournal::new().since(&NibblePath::empty(), None, 1)
        }

        fn read_at(
            &self,
            _: (BlockHeight, BlockHash),
            keys: &[SubstateKey],
        ) -> Vec<Option<Vec<u8>>> {
            keys.iter().map(|key| self.0.cell(*key)).collect()
        }
    }

    /// A cell holding an answer's bytes at a key its derivation does not
    /// reach is no answer: the delta of a block writing one and a whole
    /// read of a store holding one count nothing for it, where they count
    /// the answer at its own key.
    #[test]
    fn a_user_cell_shaped_as_an_answer_is_not_counted() {
        let (key, bytes) = answer_leaf(owner(0x10), owner(0x20), 0, Answered::Taken, 1);
        let (elsewhere, _) = answer_leaf(owner(0x10), owner(0x20), 1, Answered::Taken, 1);
        let route = RoutePrefix::of(owner(0x10));
        assert_eq!(answer_route(key, &bytes), Some(route));
        assert_eq!(answer_route(elsewhere, &bytes), None);

        let empty = Cells(BTreeMap::new());
        let under = NibblePath::empty();
        let shaped = BTreeMap::from([(elsewhere, Some(bytes.clone()))]);
        assert!(answer_delta(&shaped, &empty, &under).is_empty());
        let real = BTreeMap::from([(key, Some(bytes.clone()))]);
        assert_eq!(answer_delta(&real, &empty, &under).of(route), 1);

        let store = Persisted(Cells(BTreeMap::from([
            (elsewhere, bytes.clone()),
            (key, bytes),
        ])));
        let mut follow = None;
        assert_eq!(
            AnswerFollow::step(&mut follow, &store, &under),
            None,
            "a first step reads whole"
        );
        let follow = follow.expect("read whole");
        assert_eq!(
            (follow.count().total(), follow.count().from_route(route)),
            (1, 1)
        );
    }

    /// A block's delta takes an answer it removes or writes over off its
    /// route and puts an answer it writes on its own: an overwrite by
    /// another producer's answer at the same key moves one between
    /// routes, an overwrite by the same answer nets nothing, and a cell
    /// outside the prefix is not read.
    #[test]
    fn a_delta_counts_each_answer_in_and_out_by_its_route() {
        let (key, first) = answer_leaf(owner(0x10), owner(0x20), 0, Answered::Never, 1);
        let (same_key, second) = answer_leaf(owner(0x30), owner(0x20), 0, Answered::Never, 2);
        assert_eq!(key, same_key, "the producer is not in an answer's key");
        let (gone, removed) = answer_leaf(owner(0x10), owner(0x20), 5, Answered::Taken, 1);
        let parent = Cells(BTreeMap::from([(key, first.clone()), (gone, removed)]));
        let (a, b) = (RoutePrefix::of(owner(0x10)), RoutePrefix::of(owner(0x30)));
        let under = NibblePath::empty();

        let writes = BTreeMap::from([(key, Some(second)), (gone, None)]);
        let delta = answer_delta(&writes, &parent, &under);
        assert_eq!((delta.of(a), delta.of(b)), (-2, 1));
        let again = BTreeMap::from([(key, Some(first))]);
        assert!(answer_delta(&again, &parent, &under).is_empty());

        let mut other_half = NibblePath::empty();
        other_half.push_bits(!(key.to_bytes()[0] >> 7) & 1, 1);
        assert!(answer_delta(&writes, &parent, &other_half).is_empty());
    }
}
