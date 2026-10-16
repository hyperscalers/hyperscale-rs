//! What a shard's intake of core transactions is held to: the member
//! rows standing toward each sibling, against
//! [`MAX_STANDING_TOWARD_SHARD`], and the answers a consumer's chain
//! holds per producer route.

use std::collections::{BTreeMap, HashSet};
#[cfg(any(test, feature = "test-utils"))]
use std::sync::LazyLock;

use crate::{
    MAX_STANDING_TOWARD_SHARD, RoutePrefix, ShardId, ShardTrie, Terminating, TxHash, TxsInFlight,
};

/// The member rows standing toward each shard: for a shard, the rows
/// whose settlement awaits it.
///
/// A row counts for as long as it stands with the shard among its
/// `awaits`, whatever state it stands in, since a sibling that stops
/// answering pins every one of them. It holds an entry only for a shard
/// a counted row names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StandingToward(BTreeMap<ShardId, usize>);

impl StandingToward {
    /// The count over rows, each given as the shards it awaits.
    #[must_use]
    pub fn over<'a>(rows: impl IntoIterator<Item = &'a [ShardId]>) -> Self {
        let mut standing = Self::default();
        for awaits in rows {
            standing.add(awaits);
        }
        standing
    }

    /// The rows standing toward `shard`.
    #[must_use]
    pub fn toward(&self, shard: ShardId) -> usize {
        self.0.get(&shard).copied().unwrap_or(0)
    }

    /// The most rows standing toward any one shard.
    #[must_use]
    pub fn most(&self) -> usize {
        self.0.values().copied().max().unwrap_or(0)
    }

    /// The first of `awaited` already holding
    /// [`MAX_STANDING_TOWARD_SHARD`] rows, which refuses one more row
    /// awaiting it. `None` admits the row.
    #[must_use]
    pub fn capped(&self, awaited: &[ShardId]) -> Option<ShardId> {
        awaited
            .iter()
            .copied()
            .find(|&shard| self.toward(shard) >= MAX_STANDING_TOWARD_SHARD)
    }

    /// Count one more row awaiting `awaited`.
    pub fn add(&mut self, awaited: &[ShardId]) {
        for &shard in awaited {
            let count = self.0.entry(shard).or_default();
            *count = count.saturating_add(1);
        }
    }
}

/// The answers a consumer's chain holds, per producer route: for each
/// route, how many answer leaves under the chain's prefix answer a
/// crossing whose producer it places.
///
/// It holds an entry only for a route some answer names, so it holds no
/// more entries than answers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StandingAnswers(BTreeMap<RoutePrefix, u64>);

impl StandingAnswers {
    /// The answers standing for crossings out of `route`.
    #[must_use]
    pub fn from_route(&self, route: RoutePrefix) -> u64 {
        self.0.get(&route).copied().unwrap_or(0)
    }

    /// Every answer standing.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.0.values().sum()
    }

    /// Count one more answer out of `route`.
    pub fn add(&mut self, route: RoutePrefix) {
        *self.0.entry(route).or_default() += 1;
    }

    /// Count one answer out of `route` fewer, where one stands.
    pub fn remove(&mut self, route: RoutePrefix) {
        if let Some(count) = self.0.get_mut(&route) {
            *count -= 1;
            if *count == 0 {
                self.0.remove(&route);
            }
        }
    }

    /// Advance by `delta`, or leave the count as it was and name the
    /// first route `delta` would take below zero.
    ///
    /// # Errors
    ///
    /// The route `delta` takes more answers off than stand.
    pub fn advance(&mut self, delta: &AnswerDelta) -> Result<(), RoutePrefix> {
        let mut advanced = self.0.clone();
        for (&route, &change) in &delta.0 {
            let held = advanced.get(&route).copied().unwrap_or(0);
            let count = held.checked_add_signed(change).ok_or(route)?;
            if count == 0 {
                advanced.remove(&route);
            } else {
                advanced.insert(route, count);
            }
        }
        self.0 = advanced;
        Ok(())
    }
}

/// What a block does to the answers its chain holds, per producer
/// route: an answer it writes counts one up, an answer it removes or
/// writes over one down. It holds no route whose change nets to zero.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerDelta(BTreeMap<RoutePrefix, i64>);

impl AnswerDelta {
    /// One answer out of `route` written.
    pub fn put(&mut self, route: RoutePrefix) {
        self.change(route, 1);
    }

    /// One answer out of `route` removed or written over.
    pub fn take(&mut self, route: RoutePrefix) {
        self.change(route, -1);
    }

    /// The net change out of `route`.
    #[must_use]
    pub fn of(&self, route: RoutePrefix) -> i64 {
        self.0.get(&route).copied().unwrap_or(0)
    }

    /// Whether the block changes no route's count.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn change(&mut self, route: RoutePrefix, by: i64) {
        let net = self.0.entry(route).or_default();
        *net += by;
        if *net == 0 {
            self.0.remove(&route);
        }
    }
}

/// What a proposer's ready set is filled against, so it offers what
/// admission will take: the readings of the one block the proposal
/// extends, and the placement the proposal is classified under.
#[derive(Debug, Clone)]
pub struct IntakeView<'t> {
    /// The trie the block's committee places owners by.
    pub trie: &'t ShardTrie,
    /// The shards leaving the trie at the end of the window the block's
    /// anchor resolves, across which no core member is admitted.
    pub terminating: Terminating<'t>,
    /// The rows standing toward each shard at the block's parent.
    pub standing: StandingToward,
    /// The drain the parent's header records, which the block's places
    /// are what is left of.
    pub in_flight: TxsInFlight,
    /// The transactions the uncommitted chain up to the parent carries,
    /// none of which the block may carry again.
    pub carried: &'t HashSet<TxHash>,
}

/// The carried set of a parent with no uncommitted chain behind it.
#[cfg(any(test, feature = "test-utils"))]
static NOTHING_CARRIED: LazyLock<HashSet<TxHash>> = LazyLock::new(HashSet::new);

#[cfg(any(test, feature = "test-utils"))]
impl<'t> IntakeView<'t> {
    /// Intake under `trie` on a parent with no row standing, nothing in
    /// flight, no shard terminating and no uncommitted chain behind it.
    #[must_use]
    pub fn idle(trie: &'t ShardTrie) -> Self {
        Self {
            trie,
            terminating: Terminating::NONE,
            standing: StandingToward::default(),
            in_flight: TxsInFlight::ZERO,
            carried: &NOTHING_CARRIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StandingToward;
    use crate::{MAX_STANDING_TOWARD_SHARD, ShardId};

    /// The most rows toward one shard is the largest count held, and
    /// nothing where no row stands.
    #[test]
    fn the_most_standing_toward_one_shard_is_the_largest_count() {
        let (near, far) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        assert_eq!(StandingToward::default().most(), 0);
        let standing = StandingToward::over([&[near][..], &[near, far], &[near]]);
        assert_eq!((standing.toward(near), standing.toward(far)), (3, 1));
        assert_eq!(standing.most(), 3);
    }

    /// A shard holds the cap and no more, and a row awaiting two shards
    /// is refused by either one at the cap.
    #[test]
    fn a_shard_at_the_cap_refuses_every_row_awaiting_it() {
        let (near, far) = ShardId::ROOT.children();
        let mut standing = StandingToward::default();
        for _ in 0..MAX_STANDING_TOWARD_SHARD - 1 {
            standing.add(&[near]);
        }
        assert_eq!(standing.capped(&[near, far]), None);
        standing.add(&[near]);
        assert_eq!(standing.toward(near), MAX_STANDING_TOWARD_SHARD);
        assert_eq!(standing.capped(&[far, near]), Some(near));
        assert_eq!(standing.capped(&[far]), None);
        assert_eq!(standing.capped(&[]), None, "a row awaiting nobody");
    }
}
