//! What a shard's intake of core transactions is held to: the member
//! rows standing toward each sibling and the crossings they owe, against
//! [`MAX_STANDING_TOWARD_SHARD`] and [`MAX_OWED_TOWARD_SHARD`], and the
//! answers and owed crossings a consumer's chain holds per producer
//! route, against [`MAX_STANDING_ANSWERS_FROM_SHARD`] per lineage and
//! [`MAX_STANDING_ANSWERS`] in all.

use std::collections::{BTreeMap, HashSet};
#[cfg(any(test, feature = "test-utils"))]
use std::sync::LazyLock;

use hyperscale_vm_types::MAX_CROSSINGS_PER_TX;

use crate::{
    MAX_OWED_TOWARD_SHARD, MAX_STANDING_ANSWERS, MAX_STANDING_ANSWERS_FROM_SHARD,
    MAX_STANDING_TOWARD_SHARD, Owes, RoutePrefix, ShardId, ShardTrie, Terminating, TxHash,
    TxsInFlight,
};

/// The member rows standing toward each shard, and the escrowed
/// crossings those rows owe: for a shard, the rows whose settlement
/// awaits it.
///
/// A row counts for as long as it stands with the shard among its
/// `awaits`, whatever state it stands in, since a sibling that stops
/// answering pins every one of them. It holds an entry only for a shard
/// a counted row names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StandingToward(BTreeMap<ShardId, Toward>);

/// What stands toward one shard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Toward {
    rows: usize,
    owed: u64,
}

impl StandingToward {
    /// The count over rows, each given as the shards it awaits and the
    /// escrowed crossings it owes.
    #[must_use]
    pub fn over<'a>(rows: impl IntoIterator<Item = (&'a [ShardId], u64)>) -> Self {
        let mut standing = Self::default();
        for (awaits, owed) in rows {
            standing.add(awaits, owed);
        }
        standing
    }

    /// The rows standing toward `shard`.
    #[must_use]
    pub fn toward(&self, shard: ShardId) -> usize {
        self.0.get(&shard).map_or(0, |toward| toward.rows)
    }

    /// The escrowed crossings the rows standing toward `shard` owe.
    #[must_use]
    pub fn owed_toward(&self, shard: ShardId) -> u64 {
        self.0.get(&shard).map_or(0, |toward| toward.owed)
    }

    /// The most rows standing toward any one shard.
    #[must_use]
    pub fn most(&self) -> usize {
        self.0.values().map(|toward| toward.rows).max().unwrap_or(0)
    }

    /// The first of `awaited` already holding
    /// [`MAX_STANDING_TOWARD_SHARD`] rows, or rows owing
    /// [`MAX_OWED_TOWARD_SHARD`] crossings, which refuses one more row
    /// awaiting it. `None` admits the row.
    #[must_use]
    pub fn capped(&self, awaited: &[ShardId]) -> Option<ShardId> {
        awaited.iter().copied().find(|&shard| {
            self.toward(shard) >= MAX_STANDING_TOWARD_SHARD
                || self.owed_toward(shard) >= MAX_OWED_TOWARD_SHARD
        })
    }

    /// Count one more row awaiting `awaited`, owing `owed` crossings.
    pub fn add(&mut self, awaited: &[ShardId], owed: u64) {
        for &shard in awaited {
            let toward = self.0.entry(shard).or_default();
            toward.rows = toward.rows.saturating_add(1);
            toward.owed = toward.owed.saturating_add(owed);
        }
    }
}

/// The answers a consumer's chain holds, per producer route.
///
/// For each route, how many answer leaves under the chain's prefix answer
/// a crossing whose producer it places. Where the cap judges a block, the
/// crossings the chain's rows owe are counted beside them ([`Self::owe`]).
///
/// It holds an entry only for a route something counted names, so it
/// holds no more entries than it counts.
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

    /// Count the crossings `owes` names as standing too.
    pub fn owe(&mut self, owes: &Owes) {
        for (route, count) in owes.iter() {
            *self.0.entry(route).or_default() += u64::from(count);
        }
    }

    /// Whether `additions`, a block's, keep this count, the answers and
    /// owed crossings at the block's parent, within the cap: no lineage
    /// of `trie` the block adds to past
    /// [`MAX_STANDING_ANSWERS_FROM_SHARD`], and where it adds anything,
    /// the total no further than [`MAX_STANDING_ANSWERS`]. A block
    /// adding nothing is admitted whatever stands, so a lineage over its
    /// cap drains.
    ///
    /// # Errors
    ///
    /// The first lineage the block adds to past its cap, or, with every
    /// lineage within its own, the first lineage it adds to while the
    /// total is passed.
    pub fn admits(&self, additions: &AnswerAdditions, trie: &ShardTrie) -> Result<(), ShardId> {
        if additions.is_empty() {
            return Ok(());
        }
        let standing = lineages(&self.0, trie);
        let added = lineages(&additions.0, trie);
        for (&lineage, &adds) in &added {
            let stands = standing.get(&lineage).copied().unwrap_or(0);
            if stands.saturating_add(adds) > MAX_STANDING_ANSWERS_FROM_SHARD {
                return Err(lineage);
            }
        }
        match added.keys().next() {
            Some(&lineage)
                if self.total().saturating_add(additions.total()) > MAX_STANDING_ANSWERS =>
            {
                Err(lineage)
            }
            _ => Ok(()),
        }
    }

    /// What stands toward each lineage of `trie`: the counts of every
    /// route it places there, summed.
    #[must_use]
    pub fn per_lineage(&self, trie: &ShardTrie) -> BTreeMap<ShardId, u64> {
        lineages(&self.0, trie)
    }

    /// The lineages of `trie` whose deletions a proposal spends the
    /// claims section's reserve on first: each standing within one
    /// transaction's crossings of [`MAX_STANDING_ANSWERS_FROM_SHARD`],
    /// which refuses the widest transaction consuming from it, and,
    /// where the total stands that close to [`MAX_STANDING_ANSWERS`],
    /// every lineage anything stands toward, since a deletion out of any
    /// of them makes room under the total.
    #[must_use]
    pub fn draining(&self, trie: &ShardTrie) -> Vec<ShardId> {
        let widest = MAX_CROSSINGS_PER_TX as u64;
        let near = |count: u64, cap: u64| count.saturating_add(widest) > cap;
        let total_binds = near(self.total(), MAX_STANDING_ANSWERS);
        self.per_lineage(trie)
            .into_iter()
            .filter(|&(_, count)| total_binds || near(count, MAX_STANDING_ANSWERS_FROM_SHARD))
            .map(|(lineage, _)| lineage)
            .collect()
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

/// `routes` summed per lineage of `trie`.
fn lineages(routes: &BTreeMap<RoutePrefix, u64>, trie: &ShardTrie) -> BTreeMap<ShardId, u64> {
    let mut summed: BTreeMap<ShardId, u64> = BTreeMap::new();
    for (&route, &count) in routes {
        let lineage = summed.entry(trie.shard_for_route(route)).or_default();
        *lineage = lineage.saturating_add(count);
    }
    summed
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

/// What a block adds to what its consumer chain stands holding, per
/// producer route: the crossings its terms entries owe, and the answers
/// its owed credits and declines write.
///
/// Only these raise a chain's answers and owed crossings together: a
/// landing answers at most what its row owed, and a deletion or a row
/// that goes unlanded only takes away.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerAdditions(BTreeMap<RoutePrefix, u64>);

impl AnswerAdditions {
    /// `count` more out of `route`.
    pub fn add(&mut self, route: RoutePrefix, count: u64) {
        if count != 0 {
            let added = self.0.entry(route).or_default();
            *added = added.saturating_add(count);
        }
    }

    /// The crossings `owes` names.
    pub fn owe(&mut self, owes: &Owes) {
        for (route, count) in owes.iter() {
            self.add(route, u64::from(count));
        }
    }

    /// What `other` adds as well.
    pub fn extend(&mut self, other: &Self) {
        for (&route, &count) in &other.0 {
            self.add(route, count);
        }
    }

    /// What is added out of `route`.
    #[must_use]
    pub fn of(&self, route: RoutePrefix) -> u64 {
        self.0.get(&route).copied().unwrap_or(0)
    }

    /// Everything added.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.0
            .values()
            .fold(0, |sum, count| sum.saturating_add(*count))
    }

    /// Whether the block adds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    /// The answers and owed crossings the chain stands holding at the
    /// block's parent, `None` where the proposer cannot rebuild them, in
    /// which case it carries no transaction owing a crossing.
    pub answers: Option<StandingAnswers>,
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
            answers: Some(StandingAnswers::default()),
            in_flight: TxsInFlight::ZERO,
            carried: &NOTHING_CARRIED,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Capped, Hash32};
    use hyperscale_vm_effects::{CrossingId, IntentHash};
    use hyperscale_vm_types::MAX_CROSSINGS_PER_TX;

    use super::{AnswerAdditions, AnswerDelta, StandingAnswers, StandingToward};
    use crate::{
        Address, AddressClass, MAX_OWED_TOWARD_SHARD, MAX_STANDING_ANSWERS,
        MAX_STANDING_ANSWERS_FROM_SHARD, MAX_STANDING_TOWARD_SHARD, Owes, RoutePrefix, ShardId,
        ShardTrie,
    };

    /// A producer route the trie places under `shard`.
    fn route(shard: ShardId) -> RoutePrefix {
        RoutePrefix::of(ShardTrie::shard_owner(shard))
    }

    /// The answers standing out of each route.
    fn standing(at: &[(RoutePrefix, u64)]) -> StandingAnswers {
        let mut count = StandingAnswers::default();
        for &(route, answers) in at {
            let mut delta = AnswerDelta::default();
            for _ in 0..answers {
                delta.put(route);
            }
            count.advance(&delta).expect("only adds");
        }
        count
    }

    fn added(at: &[(RoutePrefix, u64)]) -> AnswerAdditions {
        let mut additions = AnswerAdditions::default();
        for &(route, count) in at {
            additions.add(route, count);
        }
        additions
    }

    /// What a member consuming `count` crossings out of `shard` owes.
    fn owes(shard: ShardId, count: u8) -> Owes {
        let crossings: Vec<CrossingId> = (0..count)
            .map(|local| CrossingId {
                producer: ShardTrie::shard_owner(shard),
                consumer: Address::new([0xc0; 31], AddressClass::Component),
                intent: IntentHash(Hash32([0x5a; 32])),
                local: local.into(),
                output: 0,
            })
            .collect();
        Owes::of(&Capped::new(crossings).expect("within the cap"))
    }

    /// The most rows toward one shard is the largest count held, and
    /// nothing where no row stands.
    #[test]
    fn the_most_standing_toward_one_shard_is_the_largest_count() {
        let (near, far) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        assert_eq!(StandingToward::default().most(), 0);
        let standing = StandingToward::over([(&[near][..], 0), (&[near, far], 0), (&[near], 0)]);
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
            standing.add(&[near], 0);
        }
        assert_eq!(standing.capped(&[near, far]), None);
        standing.add(&[near], 0);
        assert_eq!(standing.toward(near), MAX_STANDING_TOWARD_SHARD);
        assert_eq!(standing.capped(&[far, near]), Some(near));
        assert_eq!(standing.capped(&[far]), None);
        assert_eq!(standing.capped(&[]), None, "a row awaiting nobody");
    }

    /// The rows toward a shard owing the crossings cap refuse one more
    /// row awaiting it, however few rows stand: a silent sibling holds
    /// no more than a quarter of what a consumer may stand holding.
    #[test]
    fn a_transaction_awaiting_a_shard_past_its_owed_crossings_is_refused() {
        let (near, far) = ShardId::ROOT.children();
        let mut standing = StandingToward::default();
        let rows = MAX_OWED_TOWARD_SHARD / 128;
        for _ in 0..rows - 1 {
            standing.add(&[near], 128);
        }
        standing.add(&[near], 127);
        assert_eq!(standing.owed_toward(near), MAX_OWED_TOWARD_SHARD - 1);
        assert!(standing.toward(near) < MAX_STANDING_TOWARD_SHARD);
        assert_eq!(standing.capped(&[near]), None);
        standing.add(&[near, far], 1);
        assert_eq!(standing.capped(&[near]), Some(near));
        assert_eq!(
            standing.capped(&[far]),
            None,
            "one row owes far one crossing"
        );
        assert_eq!(
            StandingToward::over([(&[far][..], MAX_OWED_TOWARD_SHARD)]).capped(&[far]),
            Some(far),
            "one row owing the cap"
        );
    }

    /// A member consuming from a lineage standing within its owes of the
    /// cap is refused; one owing a crossing less, or consuming from
    /// another lineage, is admitted. Answers and owed crossings count
    /// alike, and every producer route the trie places in one lineage
    /// counts toward it.
    #[test]
    fn a_transaction_consuming_from_a_capped_lineage_is_refused() {
        let trie = ShardTrie::uniform(1);
        let (near, far) = ShardId::ROOT.children();
        let (deep, _) = near.children();
        let mut count = standing(&[
            (route(near), MAX_STANDING_ANSWERS_FROM_SHARD / 2),
            (route(deep), MAX_STANDING_ANSWERS_FROM_SHARD / 2 - 130),
        ]);
        count.owe(&owes(near, 2));
        let mut member = AnswerAdditions::default();
        member.owe(&owes(deep, 128));
        assert_eq!(count.admits(&member, &trie), Ok(()), "at the cap exactly");
        member.owe(&owes(near, 1));
        assert_eq!(count.admits(&member, &trie), Err(near));
        let mut elsewhere = AnswerAdditions::default();
        elsewhere.owe(&owes(far, 128));
        assert_eq!(count.admits(&elsewhere, &trie), Ok(()));
    }

    /// The reserve drains a lineage within one transaction's crossings
    /// of its cap and no other, and every lineage anything stands toward
    /// once the total stands within one transaction's crossings of its
    /// own, each lineage under its cap.
    #[test]
    fn the_reserve_drains_what_one_transaction_could_carry_past_a_cap() {
        let widest = MAX_CROSSINGS_PER_TX as u64;
        let trie = ShardTrie::uniform(1);
        let (near, far) = ShardId::ROOT.children();
        let count = standing(&[
            (route(near), MAX_STANDING_ANSWERS_FROM_SHARD - widest + 1),
            (route(far), MAX_STANDING_ANSWERS_FROM_SHARD - widest),
        ]);
        assert_eq!(count.draining(&trie), vec![near]);

        let trie = ShardTrie::uniform(3);
        let lineages: Vec<ShardId> = trie.leaves().collect();
        let under = MAX_STANDING_ANSWERS_FROM_SHARD - widest;
        let mut held: Vec<(RoutePrefix, u64)> = Vec::new();
        let mut total = 0;
        for &lineage in &lineages {
            let take = under.min(MAX_STANDING_ANSWERS - widest - total);
            held.push((route(lineage), take));
            total += take;
        }
        assert!(
            standing(&held).draining(&trie).is_empty(),
            "the total has a transaction's room"
        );
        let last = held.len() - 1;
        held[last].1 += 1;
        let count = standing(&held);
        assert!(
            count
                .per_lineage(&trie)
                .values()
                .all(|&count| count <= under)
        );
        assert_eq!(
            count.draining(&trie),
            count.per_lineage(&trie).into_keys().collect::<Vec<_>>(),
        );
    }

    /// An owed credit or a decline writes an answer whatever row stands,
    /// so one out of a lineage at its cap is refused.
    #[test]
    fn an_owed_record_from_a_capped_lineage_is_refused() {
        let trie = ShardTrie::uniform(1);
        let (near, far) = ShardId::ROOT.children();
        let count = standing(&[(route(near), MAX_STANDING_ANSWERS_FROM_SHARD)]);
        assert_eq!(count.admits(&added(&[(route(near), 1)]), &trie), Err(near));
        assert_eq!(count.admits(&added(&[(route(far), 1)]), &trie), Ok(()));
    }

    /// The swap shape: a leg row standing for the transaction owes
    /// nothing, and the owed credit beside it writes a `Taken`, which the
    /// block's additions count whatever row stands.
    #[test]
    fn an_owed_credit_beside_a_standing_row_is_counted() {
        let trie = ShardTrie::uniform(1);
        let (near, _) = ShardId::ROOT.children();
        let mut count = standing(&[(route(near), MAX_STANDING_ANSWERS_FROM_SHARD - 1)]);
        count.owe(&Owes::default());
        let mut credit = AnswerAdditions::default();
        credit.owe(&Owes::default());
        credit.add(route(near), 1);
        assert_eq!(count.admits(&credit, &trie), Ok(()));
        count.add(route(near));
        assert_eq!(count.admits(&credit, &trie), Err(near));
    }

    /// An escrowed arrival for a standing row writes no answer, so a
    /// block of them adds nothing and is admitted at the cap.
    #[test]
    fn an_escrowed_arrival_is_admitted_at_the_cap() {
        let trie = ShardTrie::uniform(1);
        let (near, _) = ShardId::ROOT.children();
        let mut count = standing(&[(route(near), MAX_STANDING_ANSWERS_FROM_SHARD - 4)]);
        count.owe(&owes(near, 4));
        assert_eq!(count.admits(&AnswerAdditions::default(), &trie), Ok(()));
    }

    /// Past the cap in a lineage and in total, a block adding nothing is
    /// admitted, so the deletions that drain the chain always land.
    #[test]
    fn a_block_of_deletions_alone_is_admitted_over_the_cap() {
        let trie = ShardTrie::uniform(3);
        let lineages: Vec<ShardId> = trie.leaves().collect();
        let over: Vec<(RoutePrefix, u64)> = lineages
            .iter()
            .map(|&lineage| (route(lineage), MAX_STANDING_ANSWERS_FROM_SHARD + 1))
            .collect();
        let count = standing(&over);
        assert!(count.total() > MAX_STANDING_ANSWERS);
        assert_eq!(count.admits(&AnswerAdditions::default(), &trie), Ok(()));
        assert!(
            count
                .admits(&added(&[(route(lineages[0]), 1)]), &trie)
                .is_err()
        );
    }

    /// A consumer merge's successor inherits both parents' answers, over
    /// a lineage's cap and over the total: every addition is refused,
    /// to any lineage while the total stands passed, until the drain
    /// brings the count back under.
    #[test]
    fn a_merged_successor_over_the_cap_refuses_additions_until_it_drains() {
        let trie = ShardTrie::uniform(3);
        let lineages: Vec<ShardId> = trie.leaves().collect();
        let mut held: Vec<(RoutePrefix, u64)> = lineages[..4]
            .iter()
            .map(|&lineage| (route(lineage), MAX_STANDING_ANSWERS_FROM_SHARD))
            .collect();
        held[0].1 *= 2;
        let mut count = standing(&held);
        let one = |lineage: ShardId| added(&[(route(lineage), 1)]);
        assert_eq!(count.admits(&one(lineages[0]), &trie), Err(lineages[0]));
        assert_eq!(
            count.admits(&one(lineages[5]), &trie),
            Err(lineages[5]),
            "a lineage under its own cap while the total stands passed"
        );
        let mut drained = AnswerDelta::default();
        for _ in 0..MAX_STANDING_ANSWERS_FROM_SHARD {
            drained.take(route(lineages[0]));
        }
        count.advance(&drained).expect("drains what stands");
        assert_eq!(
            count.admits(&one(lineages[5]), &trie),
            Err(lineages[5]),
            "at the total"
        );
        drained = AnswerDelta::default();
        drained.take(route(lineages[0]));
        count.advance(&drained).expect("drains what stands");
        assert_eq!(count.admits(&one(lineages[5]), &trie), Ok(()));
        assert_eq!(count.admits(&one(lineages[0]), &trie), Ok(()));
        assert_eq!(count.admits(&one(lineages[1]), &trie), Err(lineages[1]));
    }
}
