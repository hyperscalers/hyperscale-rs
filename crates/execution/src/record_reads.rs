//! The one pacing for a consumer's reads of the crossing records it
//! waits on.
//!
//! A record reaches its consumer as a pushed claim, and when no push
//! lands the consumer reads it through the ordinary state-proof fetch of
//! the producer's chain. This is what decides when that read is put:
//! a key arms on the first evidence that the producer's leg has run or
//! never will, and once armed is asked at a proven anchor of the
//! record's holder, backing off in the holder's heights and never
//! waiting longer than one finalization delay of the holder's clock
//! between asks.
//!
//! Node-local, like the asking itself: what a validator asks for is its
//! own business, and what the answer licenses is a claim riding into a
//! block where every replica folds the same bytes. A restarted,
//! snap-synced or re-seated replica starts empty and re-derives the
//! wanted set and its arming instants from committed state, so a key
//! whose arming evidence is already in hand is asked at once.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_metrics::record_record_ask;
use hyperscale_types::{
    Anchor, MAX_FINALIZATION_DELAY, RETENTION_HORIZON, ShardId, SubstateKey, TxHash,
    WeightedTimestamp,
};

use crate::provisioning::WantedRecord;

/// What arms a read: the evidence that the producer's leg has finalized
/// or never will.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// One finalization delay of committed clock has passed since the
    /// want was filed, or the body it serves is past its validity end.
    Clock,
    /// A verified execution certificate from the record's holder named
    /// the transaction.
    Certificate,
}

/// One record's read: whether it is armed and by what, how many asks
/// have gone out since it was armed, and the holder anchor the last one
/// was put at.
#[derive(Debug, Default)]
struct Read {
    armed: Option<Evidence>,
    step: u32,
    last: Option<Anchor>,
}

/// The record reads this node has put, and what decides whether to put
/// one again.
#[derive(Debug, Default)]
pub struct RecordReads {
    reads: BTreeMap<SubstateKey, Read>,
    /// The transactions a holder's certificate has named, by transaction,
    /// with the committed clock each was heard at: a certificate folded
    /// before the key it arms is wanted is remembered until the key
    /// enters, and swept one horizon past the clock.
    certified: BTreeMap<TxHash, (BTreeSet<ShardId>, WeightedTimestamp)>,
}

impl RecordReads {
    /// Nothing asked yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A verified certificate from `shard` naming `txs`, heard at `now`.
    pub fn certified(
        &mut self,
        shard: ShardId,
        txs: impl IntoIterator<Item = TxHash>,
        now: WeightedTimestamp,
    ) {
        for tx in txs {
            let entry = self
                .certified
                .entry(tx)
                .or_insert_with(|| (BTreeSet::new(), now));
            entry.0.insert(shard);
            entry.1 = now;
        }
    }

    /// Drop the reads of keys `wanted` no longer names, which have been
    /// answered or are nobody's to ask about, and the certificates
    /// remembered past one horizon of `now`.
    pub fn sweep(&mut self, now: WeightedTimestamp, wanted: &[WantedRecord]) {
        let live: BTreeSet<SubstateKey> = wanted.iter().map(|wanted| wanted.key).collect();
        self.reads.retain(|key, _| live.contains(key));
        let floor = now.minus(RETENTION_HORIZON);
        self.certified.retain(|_, (_, heard)| *heard >= floor);
    }

    /// Arm the read of `wanted` where its evidence is in: the clock it
    /// names has passed, or `holder` has certified its transaction.
    /// Fresh evidence resets the backoff, so a key the clock armed is
    /// asked again at once when the holder's certificate lands.
    pub fn arm(&mut self, wanted: &WantedRecord, holder: ShardId, now: WeightedTimestamp) {
        let by_certificate = self
            .certified
            .get(&wanted.tx)
            .is_some_and(|(shards, _)| shards.contains(&holder));
        let evidence = if by_certificate {
            Some(Evidence::Certificate)
        } else if wanted.arms_at.is_some_and(|at| now >= at) {
            Some(Evidence::Clock)
        } else {
            None
        };
        let read = self.reads.entry(wanted.key).or_default();
        if let Some(evidence) = evidence
            && read.armed != Some(evidence)
        {
            read.armed = Some(evidence);
            read.step = 0;
        }
    }

    /// Whether `key` is asked at `anchor`, a proven anchor of its holder,
    /// and if so the ask is counted as put there.
    ///
    /// The k-th ask after arming waits for a holder anchor `2^k` heights
    /// above the last, and no longer than one finalization delay of the
    /// holder's clock past it, so a record a producer is slow to write
    /// is asked less and less often while one the consumer is about to
    /// need is asked at least once per finality delay.
    pub fn due(&mut self, key: SubstateKey, anchor: Anchor) -> bool {
        let Some(read) = self.reads.get_mut(&key) else {
            return false;
        };
        if read.armed.is_none() {
            return false;
        }
        let due = match read.last {
            None => true,
            Some(last) => {
                let gap = 1u64 << read.step.min(32);
                anchor.height.inner() >= last.height.inner().saturating_add(gap)
                    || anchor.ts.elapsed_since(last.ts) >= MAX_FINALIZATION_DELAY
            }
        };
        if due {
            read.last = Some(anchor);
            read.step = read.step.saturating_add(1);
            record_record_ask();
        }
        due
    }

    /// Whether `key` is armed, for the tests that watch the arming.
    #[cfg(test)]
    pub fn is_armed(&self, key: SubstateKey) -> bool {
        self.reads
            .get(&key)
            .is_some_and(|read| read.armed.is_some())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{BlockHeight, Hash, StateRoot};

    use super::*;

    const HOLDER: ShardId = ShardId::leaf(1, 0);

    fn anchor(height: u64, ts_ms: u64) -> Anchor {
        Anchor {
            shard: HOLDER,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(ts_ms),
        }
    }

    fn wanted(arms_at: Option<u64>) -> WantedRecord {
        WantedRecord {
            key: test_key(1),
            tx: TxHash::from(Hash::from_bytes(b"tx")),
            arms_at: arms_at.map(WeightedTimestamp::from_millis),
        }
    }

    /// Nothing is asked before the arming evidence; once armed the
    /// asks double in holder heights, and no gap between them exceeds
    /// one finalization delay of the holder's clock.
    #[test]
    fn a_read_arms_on_its_evidence_and_backs_off_in_holder_heights() {
        let mut reads = RecordReads::new();
        let want = wanted(Some(10_000));
        let key = want.key;

        reads.arm(&want, HOLDER, WeightedTimestamp::from_millis(9_999));
        assert!(!reads.is_armed(key));
        assert!(!reads.due(key, anchor(1, 9_999)), "not before the evidence");

        reads.arm(&want, HOLDER, WeightedTimestamp::from_millis(10_000));
        assert!(reads.is_armed(key));
        assert!(reads.due(key, anchor(1, 10_000)), "the first ask goes out");
        assert!(
            !reads.due(key, anchor(1, 10_001)),
            "and not again at the same anchor"
        );
        assert!(
            !reads.due(key, anchor(2, 10_002)),
            "the second waits two heights"
        );
        assert!(reads.due(key, anchor(3, 10_003)));
        assert!(!reads.due(key, anchor(6, 10_004)), "the third waits four");
        assert!(reads.due(key, anchor(7, 10_005)));
        assert!(
            !reads.due(key, anchor(14, 10_006)),
            "the fourth waits eight"
        );

        let much_later = 10_005 + u64::try_from(MAX_FINALIZATION_DELAY.as_millis()).unwrap();
        assert!(
            reads.due(key, anchor(9, much_later)),
            "but never longer than one finalization delay of the holder's clock",
        );
    }

    /// A holder's certificate arms a read the clock has not, resets the
    /// backoff of one the clock had, and is remembered for a key that
    /// is not yet wanted until the horizon sweeps it.
    #[test]
    fn a_holders_certificate_arms_and_resets() {
        let mut reads = RecordReads::new();
        let want = wanted(None);
        let key = want.key;
        let now = WeightedTimestamp::from_millis(5_000);

        reads.arm(&want, HOLDER, now);
        assert!(
            !reads.is_armed(key),
            "nothing but a certificate arms this one"
        );
        reads.certified(ShardId::leaf(1, 1), [want.tx], now);
        reads.arm(&want, HOLDER, now);
        assert!(
            !reads.is_armed(key),
            "another shard's certificate is not the holder's"
        );
        reads.certified(HOLDER, [want.tx], now);
        reads.arm(&want, HOLDER, now);
        assert!(reads.is_armed(key));
        assert!(reads.due(key, anchor(1, 5_000)));
        assert!(reads.due(key, anchor(3, 5_001)));
        assert!(
            !reads.due(key, anchor(5, 5_002)),
            "the third ask waits four heights"
        );

        // Fresh evidence resets the backoff.
        let clocked = wanted(Some(0));
        let mut by_clock = RecordReads::new();
        by_clock.arm(&clocked, HOLDER, now);
        assert!(by_clock.due(key, anchor(1, 5_000)));
        assert!(by_clock.due(key, anchor(3, 5_001)));
        assert!(!by_clock.due(key, anchor(5, 5_002)));
        by_clock.certified(HOLDER, [clocked.tx], now);
        by_clock.arm(&clocked, HOLDER, now);
        assert!(
            by_clock.due(key, anchor(5, 5_003)),
            "the certificate resets the step"
        );

        // A certificate heard before its key is wanted is kept one
        // horizon and no longer.
        let mut early = RecordReads::new();
        early.certified(HOLDER, [want.tx], now);
        early.sweep(now.plus(RETENTION_HORIZON), &[]);
        early.arm(&want, HOLDER, now.plus(RETENTION_HORIZON));
        assert!(early.is_armed(key), "still remembered at the horizon");
        let mut late = RecordReads::new();
        late.certified(HOLDER, [want.tx], now);
        late.sweep(
            now.plus(RETENTION_HORIZON)
                .plus(std::time::Duration::from_millis(1)),
            &[],
        );
        late.arm(&want, HOLDER, now);
        assert!(!late.is_armed(key), "and forgotten past it");
    }

    /// A key the wanted set stops naming is forgotten: an arrival
    /// committed, or nothing here waits on it any more.
    #[test]
    fn a_read_ends_with_its_want() {
        let mut reads = RecordReads::new();
        let want = wanted(Some(0));
        let now = WeightedTimestamp::from_millis(1);
        reads.arm(&want, HOLDER, now);
        assert!(reads.due(want.key, anchor(1, 1)));
        reads.sweep(now, &[]);
        assert!(!reads.is_armed(want.key));
        assert!(!reads.due(want.key, anchor(9, 9)));
    }
}
