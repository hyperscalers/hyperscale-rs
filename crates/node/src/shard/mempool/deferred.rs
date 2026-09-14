//! Envelopes held back for records this node has not seen.
//!
//! A derivation that names a component whose seal committed on a shard
//! this node does not serve is not a verdict — the same envelope derives
//! wherever that seal landed. Dropping it would be, and the drop is
//! self-defeating: every node that touches the transaction has the same
//! gap, so nothing would ever propose it and the fetch it triggered
//! would arrive with nothing left to admit.
//!
//! So the envelope waits here while the fetch runs, indexed by what it
//! is waiting for, and is offered to validation again when that lands.
//! A record and a package are indexed alike: each is named by an
//! address, so one arrival path releases both. Re-admission needs nothing undone: a derivation memoizes only
//! its successes, so the second attempt reads the registry the fetch just
//! grew.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use hyperscale_engine::Executor;
use hyperscale_types::{Address, MAX_TXS_PER_BLOCK, Transaction, TxHash, Unresolved};

/// How many envelopes one shard holds back at once.
///
/// Anyone can gossip an envelope naming a component that does not exist,
/// and each one costs a fetch that will never be answered — so the wait
/// is a bounded queue and the oldest entry goes when a new one arrives.
/// Sized at one block's worth: a shard that has more than that waiting on
/// records is not going to include them all in the block the fetch lands
/// for either.
pub const MAX_DEFERRED_FOR_RECORDS: usize = MAX_TXS_PER_BLOCK;

/// Which door an envelope came in by, and so which one it goes back
/// through once its records land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredOrigin {
    /// Offered to this shard's validation pipeline — gossip, or a body
    /// fetched to vote on a block.
    Validation,
    /// Submitted to this node, its cross-shard fan-out never computed.
    /// Re-entering by validation would admit it on one shard and gossip
    /// it to none, so it goes back through the fan-out instead.
    Submission,
}

/// An envelope this node cannot yet derive, and what it needs.
#[derive(Debug, Clone)]
pub struct DeferredTransaction {
    /// The envelope, unverified — nothing about it has been judged.
    pub tx: Arc<Transaction>,
    /// What its derivation could not resolve, in the forms a fetch asks
    /// for.
    pub wanted: Unresolved,
    /// Every name above as an address, which is what the wait is indexed
    /// by: a component by its own, a package by the one its content
    /// address derives.
    pub awaited: Vec<Address>,
    /// Where it came from.
    pub origin: DeferredOrigin,
}

impl DeferredTransaction {
    /// Hold `tx` for `wanted`, indexing the wait by the addresses that
    /// name it.
    #[must_use]
    pub fn new(tx: Arc<Transaction>, wanted: Unresolved, origin: DeferredOrigin) -> Self {
        let awaited = wanted.awaited(|package| Executor::package_artifact_key(package).owner);
        Self {
            tx,
            wanted,
            awaited,
            origin,
        }
    }
}

/// Envelopes waiting on records, indexed by the records they wait on.
///
/// The index names only envelopes the queue is still holding, so the
/// bound over the queue is a bound over the whole structure. Nothing
/// awaited has to arrive — an envelope naming a component that does not
/// exist is one anyone can gossip — so a key that outlived its envelopes
/// would never be reached by an arrival, and the index would grow with
/// what was asked for rather than with what is waiting.
pub struct DeferredForRecords {
    held: HashMap<TxHash, (Arc<Transaction>, DeferredOrigin)>,
    /// Which envelopes each awaited record would release.
    waiting: HashMap<Address, Vec<TxHash>>,
    order: VecDeque<TxHash>,
    capacity: usize,
}

impl DeferredForRecords {
    /// An empty wait at the default bound.
    #[must_use]
    pub fn new() -> Self {
        Self {
            held: HashMap::new(),
            waiting: HashMap::new(),
            order: VecDeque::new(),
            capacity: MAX_DEFERRED_FOR_RECORDS,
        }
    }

    /// Hold `deferred` until its records land, evicting the oldest
    /// entries the bound leaves no room for and returning their hashes
    /// so the caller can release their pipeline bookkeeping.
    pub fn defer(&mut self, deferred: DeferredTransaction) -> Vec<TxHash> {
        let hash = deferred.tx.hash();
        if self
            .held
            .insert(hash, (deferred.tx, deferred.origin))
            .is_none()
        {
            self.order.push_back(hash);
        }
        for awaited in deferred.awaited {
            let queue = self.waiting.entry(awaited).or_default();
            if !queue.contains(&hash) {
                queue.push(hash);
            }
        }
        let mut evicted = Vec::new();
        while self.order.len() > self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if self.held.remove(&oldest).is_some() {
                evicted.push(oldest);
            }
        }
        if !evicted.is_empty() {
            self.forget_dropped();
        }
        evicted
    }

    /// Drop from the order and the index every envelope the queue has
    /// stopped holding.
    ///
    /// Where the bound is made to cover the index too: an evicted
    /// envelope leaves a key behind that only its own arrival would ever
    /// read, and the arrival is exactly what may never come.
    fn forget_dropped(&mut self) {
        let held = &self.held;
        self.order.retain(|hash| held.contains_key(hash));
        self.waiting.retain(|_, hashes| {
            hashes.retain(|hash| held.contains_key(hash));
            !hashes.is_empty()
        });
    }

    /// Take the envelopes `arrived` releases.
    ///
    /// An envelope waiting on several names is released by the first of
    /// them: re-admission is what discovers whether the rest are there,
    /// and it holds itself back again naming what is still missing —
    /// including the packages a record it just learned points at.
    pub fn release(&mut self, arrived: &[Address]) -> Vec<(Arc<Transaction>, DeferredOrigin)> {
        let mut released = Vec::new();
        for name in arrived {
            let Some(hashes) = self.waiting.remove(name) else {
                continue;
            };
            for hash in hashes {
                if let Some(tx) = self.held.remove(&hash) {
                    released.push(tx);
                }
            }
        }
        self.forget_dropped();
        released
    }

    /// Drop the envelopes whose validity window has closed by
    /// `now_ms`, returning their hashes.
    ///
    /// The window is signed content, so this reads it without deriving
    /// anything. Nothing will include a transaction past it, and the
    /// record it waits on may never arrive at all.
    pub fn sweep_expired(&mut self, now_ms: u64) -> Vec<TxHash> {
        let expired: Vec<TxHash> = self
            .held
            .iter()
            .filter(|(_, (tx, _))| tx.body().validity_end_ms <= now_ms)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.held.remove(hash);
        }
        if !expired.is_empty() {
            self.forget_dropped();
        }
        expired
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

impl Default for DeferredForRecords {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{stub_transaction, test_prefix};
    use hyperscale_types::{PrincipalAddr, TimestampRange, WeightedTimestamp};

    use super::*;

    /// An envelope valid until `end_ms`, distinguished by `seed`.
    fn envelope(seed: u8, end_ms: u64) -> Arc<Transaction> {
        Arc::new(stub_transaction(
            PrincipalAddr::new([seed; 31]),
            &[test_prefix(seed)],
            1_000,
            TimestampRange::new(
                WeightedTimestamp::from_millis(0),
                WeightedTimestamp::from_millis(end_ms),
            ),
        ))
    }

    fn instance(byte: u8) -> Address {
        test_prefix(byte)
    }

    fn deferred(tx: Arc<Transaction>, instances: Vec<Address>) -> DeferredTransaction {
        DeferredTransaction::new(
            tx,
            Unresolved {
                instances,
                packages: Vec::new(),
            },
            DeferredOrigin::Validation,
        )
    }

    /// The bound covers the index, not just the queue.
    ///
    /// Anyone can gossip an envelope naming a component that does not
    /// exist, and each one asks for a record nothing will ever deliver.
    /// If eviction left the index alone, what a node held would grow
    /// with every distinct address ever asked for — and the sweep that
    /// would have caught it stands down once the queue is empty.
    #[test]
    fn an_evicted_envelope_leaves_nothing_behind_in_the_index() {
        let mut wait = DeferredForRecords {
            held: HashMap::new(),
            waiting: HashMap::new(),
            order: VecDeque::new(),
            capacity: 2,
        };
        for seed in 1..=8u8 {
            wait.defer(deferred(envelope(seed, u64::MAX), vec![instance(seed)]));
        }
        assert_eq!(wait.held.len(), 2, "the queue holds its bound");
        assert_eq!(
            wait.waiting.len(),
            2,
            "and the index names those two alone, not every address asked for"
        );
    }

    #[test]
    fn a_record_releases_only_what_waited_on_it() {
        let mut wait = DeferredForRecords::new();
        let first = envelope(1, u64::MAX);
        let second = envelope(2, u64::MAX);
        wait.defer(deferred(Arc::clone(&first), vec![instance(0xA1)]));
        wait.defer(deferred(Arc::clone(&second), vec![instance(0xB2)]));

        let released = wait.release(&[instance(0xA1)]);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0.hash(), first.hash());
        assert_eq!(wait.held.len(), 1, "the other envelope is still waiting");
    }

    /// One record is enough to offer an envelope again. Whether the rest
    /// have landed is re-admission's question, and it holds itself back
    /// again naming what is still missing.
    #[test]
    fn one_of_several_records_releases_the_envelope() {
        let mut wait = DeferredForRecords::new();
        let tx = envelope(3, u64::MAX);
        wait.defer(deferred(
            Arc::clone(&tx),
            vec![instance(0xA1), instance(0xB2)],
        ));

        assert_eq!(wait.release(&[instance(0xB2)]).len(), 1);
        assert!(wait.is_empty());
        assert!(
            wait.release(&[instance(0xA1)]).is_empty(),
            "the record it no longer waits on releases nothing"
        );
    }

    #[test]
    fn the_bound_evicts_the_oldest_and_names_it() {
        let mut wait = DeferredForRecords {
            capacity: 2,
            ..DeferredForRecords::new()
        };
        let first = envelope(1, u64::MAX);
        wait.defer(deferred(Arc::clone(&first), vec![instance(0xA1)]));
        wait.defer(deferred(envelope(2, u64::MAX), vec![instance(0xA1)]));
        let evicted = wait.defer(deferred(envelope(3, u64::MAX), vec![instance(0xA1)]));

        assert_eq!(evicted, vec![first.hash()]);
        assert_eq!(wait.held.len(), 2);
        assert_eq!(
            wait.release(&[instance(0xA1)]).len(),
            2,
            "an evicted hash left behind in the index releases nothing"
        );
    }

    #[test]
    fn a_closed_validity_window_drops_the_envelope() {
        let mut wait = DeferredForRecords::new();
        let expiring = envelope(1, 5_000);
        let lasting = envelope(2, 50_000);
        wait.defer(deferred(Arc::clone(&expiring), vec![instance(0xA1)]));
        wait.defer(deferred(Arc::clone(&lasting), vec![instance(0xA1)]));

        assert_eq!(wait.sweep_expired(10_000), vec![expiring.hash()]);
        let released = wait.release(&[instance(0xA1)]);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0.hash(), lasting.hash());
    }
}
