//! What this node holds of departed counterparts, as one mirror: their
//! settled sets, and which transactions a committed record has
//! established no counterpart can settle.
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
//! A covered transaction is one this shard still owes an outcome for,
//! and means nothing once it does not. The execution coordinator owns
//! that ledger and is the only writer here, so it is the one that says
//! what to drop, through [`CounterpartMirror::retain`]. There is no
//! clock in this file: a second retention rule stated against one would
//! be a second answer to when a fact stops being true.
//!
//! # Generation
//!
//! Every write advances a generation counter. A vote the fence deferred
//! for want of a fact here is re-driven whenever the generation has
//! moved since the last drain, so no writer has to know which votes
//! were waiting on it.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{SettledTxSet, ShardId, TxHash};

/// The facts, under one lock: they are written together at a commit and
/// read together at a vote, so splitting them would buy contention
/// nobody is waiting on.
#[derive(Debug, Default)]
struct Mirrored {
    /// Complete settled-transaction sets of shards that have terminated,
    /// each verified against its beacon-attested terminal root. Absence
    /// from a set is proof, not ignorance.
    settled: HashMap<ShardId, SettledTxSet>,
    /// Transactions a committed record has established no counterpart
    /// can settle. An abandonment of one makes no claim on any settled
    /// set: the record answered in a form that outlives the set.
    covered: HashSet<TxHash>,
}

/// Every departed counterpart's remainder this node holds.
#[derive(Debug, Default)]
pub struct CounterpartMirror {
    inner: RwLock<Mirrored>,
    /// Advanced by every write that adds a fact.
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

    /// Drop the settled sets of shards `readable` no longer attests.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned.
    pub fn retain_departures(&self, readable: &dyn Fn(ShardId) -> bool) {
        self.write().settled.retain(|&shard, _| readable(shard));
    }

    /// Drop the coverage of every transaction `held` does not name.
    ///
    /// The one retention rule. Called by the execution coordinator with
    /// its own ledger's answer, since that ledger is what an entry here
    /// speaks for.
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
