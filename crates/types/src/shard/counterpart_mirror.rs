//! What this node holds of departed counterparts, as one mirror: their
//! settled sets, the transactions their terminals ended, and which
//! transactions a committed record has established no counterpart can
//! settle.
//!
//! Each fact is asked about twice — once by the execution coordinator,
//! composing the record to offer, and once by the vote fence, checking a
//! record a block carries against what this validator itself holds. Two
//! mirrors of one fact would let a record pass the fence that its own
//! composer would never have offered, and the difference between them
//! would be nobody's to notice. So the fact has one home and both
//! consumers read it, exactly as
//! [`ProvenAnchors`](crate::ProvenAnchors) holds the anchors those same
//! two ask about.
//!
//! # Node-local, and shared
//!
//! Which sets a validator has acquired is its own view — it is why the
//! fence defers rather than refusing — so nothing here is consensus
//! content and there is no determinism to preserve. One instance per
//! host, shared by handle.
//!
//! # Retention
//!
//! Two rules, both stated by the caller rather than here. A covered
//! transaction is one this shard still owes an outcome for and means
//! nothing once it does not, which the execution coordinator's ledger
//! answers through [`CounterpartMirror::retain`]; a departed shard's
//! settled set and ended names mean nothing once the schedule stops
//! reading its evidence, which [`CounterpartMirror::retain_departures`]
//! asks of a predicate the coordinator closes over its own clock. No clock is held
//! in this file, and neither rule is written here: one stated against a
//! clock of its own would be a second answer to when a fact stops being
//! true.
//!
//! # Generation
//!
//! Every write of a fact a vote is judged on advances a generation
//! counter. A vote deferred for want of a fact here is re-driven
//! whenever the generation has moved since the last drain, so no writer
//! has to know which votes were waiting on it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{BlockHash, SettledTxSet, ShardId, TxHash};

/// The transactions one terminal block ended.
#[derive(Debug)]
struct EndedNames {
    /// The terminal block the names were verified against.
    terminal: BlockHash,
    names: BTreeSet<TxHash>,
}

/// The facts, under one lock: they are written together at a commit and
/// read together at a vote, so splitting them would buy contention
/// nobody is waiting on.
#[derive(Debug, Default)]
struct Mirrored {
    /// Complete settled-transaction sets of shards that have terminated,
    /// each verified against its beacon-attested terminal root. Absence
    /// from a set is proof, not ignorance.
    settled: HashMap<ShardId, SettledTxSet>,
    /// The transactions each terminated shard's terminal block ended,
    /// taken off the manifest its header binds: every row the shard had
    /// accepted and still held when its chain ended. One terminal's
    /// manifest a shard at most.
    ended: HashMap<ShardId, EndedNames>,
    /// Transactions a committed record has established no counterpart
    /// can settle. An abort of one makes no claim on any settled set:
    /// the record answered in a form that outlives the set.
    covered: HashSet<TxHash>,
}

/// Every departed counterpart's remainder this node holds.
#[derive(Debug, Default)]
pub struct CounterpartMirror {
    inner: RwLock<Mirrored>,
    /// Advanced by every write that adds a fact a vote is judged on.
    generation: AtomicU64,
}

impl CounterpartMirror {
    /// An empty mirror.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many facts have been added, ever. A reader that remembers the
    /// value it last drained at knows whether anything is new.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Advanced after the write's guard is released, so a reader that
    /// sees the new generation reads the fact it counts.
    fn advance(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Record a terminated shard's settled set.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn record_settled(&self, shard: ShardId, settled: SettledTxSet) {
        self.write().settled.insert(shard, settled);
        self.advance();
    }

    /// Record the transactions `shard`'s terminal block `terminal`
    /// ended, in place of any names held for another terminal of that
    /// shard.
    ///
    /// A vote on a block ending a row that awaits `shard` is deferred
    /// while these are not held, so their arrival advances the
    /// generation.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn record_ended(&self, shard: ShardId, terminal: BlockHash, names: BTreeSet<TxHash>) {
        self.write()
            .ended
            .insert(shard, EndedNames { terminal, names });
        self.advance();
    }

    /// Whether `shard`'s terminal block `terminal` ended `tx_hash`, or
    /// `None` where that terminal's ended names are not held. Held names
    /// that do not include a transaction are proof the shard had not
    /// accepted it when it left.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    #[must_use]
    pub fn ended(&self, shard: ShardId, terminal: BlockHash, tx_hash: TxHash) -> Option<bool> {
        self.read()
            .ended
            .get(&shard)
            .filter(|held| held.terminal == terminal)
            .map(|held| held.names.contains(&tx_hash))
    }

    /// Whether the names `shard`'s terminal block `terminal` ended are
    /// held, an empty list included. Names held for another terminal of
    /// the shard are not this one's.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    #[must_use]
    pub fn holds_ended(&self, shard: ShardId, terminal: BlockHash) -> bool {
        self.read()
            .ended
            .get(&shard)
            .is_some_and(|held| held.terminal == terminal)
    }

    /// Record that a committed record covers `tx_hash`: no counterpart
    /// can settle it, whatever its set says.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn cover(&self, tx_hash: TxHash) {
        let inserted = self.write().covered.insert(tx_hash);
        if inserted {
            self.advance();
        }
    }

    /// Whether a committed record covers `tx_hash`.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    #[must_use]
    pub fn covers(&self, tx_hash: TxHash) -> bool {
        self.read().covered.contains(&tx_hash)
    }

    /// Read the settled sets in place, without copying them.
    ///
    /// The sets are whole transaction sets of a departed chain, so every
    /// consumer reads them behind the guard rather than taking one.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn with_settled<R>(&self, read: impl FnOnce(&HashMap<ShardId, SettledTxSet>) -> R) -> R {
        read(&self.read().settled)
    }

    /// Drop the settled sets and ended names of shards `readable` no
    /// longer attests.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn retain_departures(&self, readable: &dyn Fn(ShardId) -> bool) {
        let mut inner = self.write();
        inner.settled.retain(|&shard, _| readable(shard));
        inner.ended.retain(|&shard, _| readable(shard));
    }

    /// Drop the coverage of every transaction `held` does not name.
    ///
    /// Called by the execution coordinator with its own ledger's answer,
    /// since that ledger is what an entry here speaks for.
    /// [`retain_departures`](Self::retain_departures) is the other rule,
    /// over what departed shards left rather than the coverage.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn retain(&self, held: &dyn Fn(TxHash) -> bool) {
        self.write().covered.retain(|&tx_hash| held(tx_hash));
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Mirrored> {
        self.inner.read().expect("counterpart mirror lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Mirrored> {
        self.inner
            .write()
            .expect("counterpart mirror lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, WeightedTimestamp};

    const DEPARTED: ShardId = ShardId::leaf(1, 0);
    const OTHER: ShardId = ShardId::leaf(1, 1);

    fn tx(seed: &[u8]) -> TxHash {
        TxHash::from(Hash::from_bytes(seed))
    }

    fn terminal(seed: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(seed))
    }

    fn settled() -> SettledTxSet {
        SettledTxSet {
            txs: BTreeSet::new(),
            terminal_wt: WeightedTimestamp::from_millis(1_000),
        }
    }

    /// Held names answer for every transaction, absent ones included,
    /// and names not held answer for none.
    #[test]
    fn ended_names_answer_only_where_held() {
        let mirror = CounterpartMirror::new();
        let at = terminal(b"terminal");
        assert_eq!(mirror.ended(DEPARTED, at, tx(b"accepted")), None);

        mirror.record_ended(DEPARTED, at, BTreeSet::from([tx(b"accepted")]));
        assert_eq!(mirror.ended(DEPARTED, at, tx(b"accepted")), Some(true));
        assert_eq!(mirror.ended(DEPARTED, at, tx(b"left")), Some(false));
        assert_eq!(mirror.ended(OTHER, at, tx(b"accepted")), None);
    }

    /// A terminal that ended nothing is held as an empty list, which is
    /// an answer and not a gap.
    #[test]
    fn an_empty_ended_list_is_held() {
        let mirror = CounterpartMirror::new();
        let at = terminal(b"terminal");
        assert!(!mirror.holds_ended(DEPARTED, at));
        mirror.record_ended(DEPARTED, at, BTreeSet::new());
        assert_eq!(mirror.ended(DEPARTED, at, tx(b"any")), Some(false));
        assert!(mirror.holds_ended(DEPARTED, at));
    }

    /// Names verified under one terminal answer nothing about another
    /// of the same shard, and the later record replaces the earlier.
    #[test]
    fn ended_names_are_held_for_one_terminal() {
        let mirror = CounterpartMirror::new();
        let (older, newer) = (terminal(b"older"), terminal(b"newer"));

        mirror.record_ended(DEPARTED, older, BTreeSet::from([tx(b"accepted")]));
        assert!(!mirror.holds_ended(DEPARTED, newer));
        assert_eq!(mirror.ended(DEPARTED, newer, tx(b"accepted")), None);

        mirror.record_ended(DEPARTED, newer, BTreeSet::new());
        assert!(mirror.holds_ended(DEPARTED, newer));
        assert!(!mirror.holds_ended(DEPARTED, older));
        assert_eq!(mirror.ended(DEPARTED, older, tx(b"accepted")), None);
    }

    /// The names retire with the set, under the one predicate.
    #[test]
    fn the_mirror_holds_and_retires_ended_names_with_the_sets() {
        let mirror = CounterpartMirror::new();
        let at = terminal(b"terminal");
        for shard in [DEPARTED, OTHER] {
            mirror.record_settled(shard, settled());
            mirror.record_ended(shard, at, BTreeSet::from([tx(b"accepted")]));
        }

        mirror.retain_departures(&|shard| shard == OTHER);

        assert_eq!(mirror.ended(DEPARTED, at, tx(b"accepted")), None);
        assert!(mirror.with_settled(|sets| !sets.contains_key(&DEPARTED)));
        assert_eq!(mirror.ended(OTHER, at, tx(b"accepted")), Some(true));
        assert!(mirror.with_settled(|sets| sets.contains_key(&OTHER)));
    }

    /// A vote on a block ending a row that awaits a departed shard is
    /// deferred for want of that shard's ended names, so recording them,
    /// an empty list included, advances the generation held votes are
    /// re-driven on.
    #[test]
    fn recording_ended_names_advances_the_generation() {
        let mirror = CounterpartMirror::new();
        let generation = mirror.generation();
        mirror.record_ended(
            DEPARTED,
            terminal(b"older"),
            BTreeSet::from([tx(b"accepted")]),
        );
        assert!(mirror.generation() > generation);
        let generation = mirror.generation();
        mirror.record_ended(DEPARTED, terminal(b"newer"), BTreeSet::new());
        assert!(mirror.generation() > generation);
    }
}
