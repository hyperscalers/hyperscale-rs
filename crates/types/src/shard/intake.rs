//! What a shard's intake of core transactions is held to: the member
//! rows standing toward each sibling, against
//! [`MAX_STANDING_TOWARD_SHARD`].

use std::collections::{BTreeMap, HashSet};
#[cfg(any(test, feature = "test-utils"))]
use std::sync::LazyLock;

use crate::{MAX_STANDING_TOWARD_SHARD, ShardId, ShardTrie, TxHash, TxsInFlight};

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

/// What a proposer's ready set is filled against, so it offers what
/// admission will take: the readings of the one block the proposal
/// extends, and the placement the proposal is classified under.
#[derive(Debug, Clone)]
pub struct IntakeView<'t> {
    /// The trie the block's committee places owners by.
    pub trie: &'t ShardTrie,
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
    /// flight and no uncommitted chain behind it.
    #[must_use]
    pub fn idle(trie: &'t ShardTrie) -> Self {
        Self {
            trie,
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
