//! The one pacing for a consumer's reads of the crossing records it
//! waits on.
//!
//! A record reaches its consumer as a pushed claim, and when no push
//! lands the consumer reads it through a state-proof fetch of the
//! producer's chain, one that is the record reads' alone. This is what
//! decides when that read is put: a key arms on the first evidence that
//! the producer's leg has run or never will, and once armed is asked at
//! a proven anchor of the record's holder, backing off in the holder's
//! heights and never waiting longer than one finalization delay of the
//! holder's clock between asks. One ask stands for a key at a time: a
//! later one takes the earlier's place, so no key queues twice.
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

/// One read as the fetch holds it: the clock its want was filed at, the
/// holder anchor it asks at, and the record's key.
pub type RecordAsk = (WeightedTimestamp, Anchor, SubstateKey);

/// What arms a read: the evidence that the producer's leg has finalized
/// or never will.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// One finalization delay of committed clock has passed since the
    /// want was filed.
    Clock,
    /// A verified execution certificate from the record's holder named
    /// the transaction. Only a producer whose member is not a leg sends
    /// one: a pure leg's certificate stays home, so its consumer arms on
    /// the clock, which is when the leg has finalized or never will. The
    /// push carries the happy path, so this delays only the fallback.
    Certificate,
}

/// One record's read: whether it is armed and by what, how many asks
/// have gone out since it was armed, the holder anchor the last one was
/// put at, and the ask still out for the key, if one is.
#[derive(Debug, Default)]
struct Read {
    armed: Option<Evidence>,
    step: u32,
    last: Option<Anchor>,
    out: Option<(WeightedTimestamp, Anchor)>,
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

    /// Whether `shard`'s certificate naming `tx` is remembered.
    #[cfg(test)]
    pub fn heard(&self, shard: ShardId, tx: TxHash) -> bool {
        self.certified
            .get(&tx)
            .is_some_and(|(shards, _)| shards.contains(&shard))
    }

    /// Drop the reads of keys `live` no longer names, which have been
    /// answered or are nobody's to ask about, and the certificates
    /// remembered past one horizon of `now`. Hands back the asks still
    /// out for the keys dropped.
    pub fn sweep(
        &mut self,
        now: WeightedTimestamp,
        live: &BTreeSet<SubstateKey>,
    ) -> Vec<RecordAsk> {
        let ended = self
            .reads
            .extract_if(.., |key, _| !live.contains(key))
            .filter_map(|(key, read)| read.out.map(|(filed_at, at)| (filed_at, at, key)))
            .collect();
        let floor = now.minus(RETENTION_HORIZON);
        self.certified.retain(|_, (_, heard)| *heard >= floor);
        ended
    }

    /// Start `key`'s backoff over with no last anchor, so the next
    /// proven anchor of its holder is asked at once: what a held
    /// reading dropped below the read frontier's floor is read again
    /// as.
    pub fn reset(&mut self, key: SubstateKey) {
        if let Some(read) = self.reads.get_mut(&key) {
            read.step = 0;
            read.last = None;
        }
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
        } else if now >= wanted.filed_at.plus(MAX_FINALIZATION_DELAY) {
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

    /// A pushed reading of `key` at `anchor` was kept: it stands where an
    /// answered ask would, so the next ask waits one more doubling past
    /// this anchor, and nothing here disarms — only a committed arrival
    /// ends the want.
    pub fn pushed(&mut self, key: SubstateKey, anchor: Anchor) {
        let read = self.reads.entry(key).or_default();
        read.last = Some(anchor);
        read.step = read.step.saturating_add(1);
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
        }
        due
    }

    /// Stand `ask` as the one out for its key, and hand back the one it
    /// replaces. The two are the same where a reset read is asked again
    /// at an anchor that has not moved: that ask is still out, and
    /// nothing is put.
    pub fn put(&mut self, ask: RecordAsk) -> Option<RecordAsk> {
        let (filed_at, anchor, key) = ask;
        let read = self.reads.entry(key).or_default();
        let replaced = read
            .out
            .replace((filed_at, anchor))
            .map(|(filed_at, at)| (filed_at, at, key));
        if replaced != Some(ask) {
            record_record_ask();
        }
        replaced
    }

    /// A proof at `anchor` read `key`: where that is the ask out, it has
    /// come back. An answer at another anchor is a replaced ask's, and
    /// the one out still stands.
    pub fn answered(&mut self, key: SubstateKey, anchor: Anchor) {
        if let Some(read) = self.reads.get_mut(&key)
            && read.out.is_some_and(|(_, at)| at == anchor)
        {
            read.out = None;
        }
    }

    /// Hand back the ask out for `key`, which nothing waits on any more.
    pub fn take_out(&mut self, key: SubstateKey) -> Option<RecordAsk> {
        let (filed_at, anchor) = self.reads.get_mut(&key)?.out.take()?;
        Some((filed_at, anchor, key))
    }

    /// The ask out for `key`, if one is.
    pub fn out(&self, key: SubstateKey) -> Option<Anchor> {
        self.reads.get(&key)?.out.map(|(_, anchor)| anchor)
    }

    /// How many asks are out toward `holder`.
    pub fn live(&self, holder: ShardId) -> usize {
        self.reads
            .values()
            .filter(|read| read.out.is_some_and(|(_, at)| at.shard == holder))
            .count()
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

    fn wanted(filed_ms: u64) -> WantedRecord {
        WantedRecord {
            key: test_key(1),
            tx: TxHash::from(Hash::from_bytes(b"tx")),
            filed_at: WeightedTimestamp::from_millis(filed_ms),
        }
    }

    /// The clock one finalization delay past a filing at `filed_ms`.
    fn delay_past(filed_ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(filed_ms).plus(MAX_FINALIZATION_DELAY)
    }

    /// A filing so far ahead of a test's clock that the clock never arms
    /// it.
    const FAR_AHEAD: u64 = 1 << 40;

    /// Nothing is asked before the arming evidence; once armed the
    /// asks double in holder heights, and no gap between them exceeds
    /// one finalization delay of the holder's clock.
    #[test]
    fn a_read_arms_on_its_evidence_and_backs_off_in_holder_heights() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let key = want.key;
        let armed = delay_past(0);

        reads.arm(
            &want,
            HOLDER,
            armed.minus(std::time::Duration::from_millis(1)),
        );
        assert!(!reads.is_armed(key));
        assert!(!reads.due(key, anchor(1, 9_999)), "not before the evidence");

        reads.arm(&want, HOLDER, armed);
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

    /// A pure leg's consumer hears no certificate from its producer and
    /// no push, and still reads: the want filed at commit arms one
    /// finalization delay later on the clock alone.
    #[test]
    fn a_pure_legs_consumer_arms_on_the_finalization_delay() {
        use hyperscale_engine::tick_select::Requirement;

        use crate::provisioning::ProvisioningTracker;

        let filed = WeightedTimestamp::from_millis(7_000);
        let mut provisioning = ProvisioningTracker::new();
        provisioning.advance_clock(filed);
        provisioning.record_required(
            TxHash::from(Hash::from_bytes(b"tx")),
            BTreeSet::from([Requirement::Crossing { key: test_key(1) }]),
        );
        let [want] = provisioning.wanted_records().try_into().expect("one want");

        let mut reads = RecordReads::new();
        let armed = filed.plus(MAX_FINALIZATION_DELAY);
        reads.arm(
            &want,
            HOLDER,
            armed.minus(std::time::Duration::from_millis(1)),
        );
        assert!(!reads.is_armed(want.key), "not before the delay");
        reads.arm(&want, HOLDER, armed);
        assert!(reads.is_armed(want.key));
        assert!(reads.due(want.key, anchor(1, armed.as_millis())));
    }

    /// A holder's certificate arms a read the clock has not, resets the
    /// backoff of one the clock had, and is remembered for a key that
    /// is not yet wanted until the horizon sweeps it.
    #[test]
    fn a_holders_certificate_arms_and_resets() {
        let mut reads = RecordReads::new();
        let want = wanted(FAR_AHEAD);
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
        let clocked = wanted(0);
        let now = delay_past(0);
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
        early.sweep(now.plus(RETENTION_HORIZON), &BTreeSet::new());
        early.arm(&want, HOLDER, now.plus(RETENTION_HORIZON));
        assert!(early.is_armed(key), "still remembered at the horizon");
        let mut late = RecordReads::new();
        late.certified(HOLDER, [want.tx], now);
        late.sweep(
            now.plus(RETENTION_HORIZON)
                .plus(std::time::Duration::from_millis(1)),
            &BTreeSet::new(),
        );
        late.arm(&want, HOLDER, now);
        assert!(!late.is_armed(key), "and forgotten past it");
    }

    /// A key the wanted set stops naming is forgotten: an arrival
    /// committed, or nothing here waits on it any more.
    #[test]
    fn a_read_ends_with_its_want() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let now = delay_past(0);
        reads.arm(&want, HOLDER, now);
        assert!(reads.due(want.key, anchor(1, 1)));
        let _ = reads.sweep(now, &BTreeSet::new());
        assert!(!reads.is_armed(want.key));
        assert!(!reads.due(want.key, anchor(9, 9)));
    }

    /// Put the ask `key` is due at `at`, as the asker does, and hand
    /// back the one it replaces.
    fn ask(reads: &mut RecordReads, want: &WantedRecord, at: Anchor) -> Option<RecordAsk> {
        assert!(reads.due(want.key, at), "due at {at:?}");
        reads.put((want.filed_at, at, want.key))
    }

    /// A re-ask takes the place of the ask out, and one out stands no
    /// matter how often the ladder calls.
    #[test]
    fn a_re_ask_replaces_the_ask_out() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        reads.arm(&want, HOLDER, delay_past(0));
        let (first, second) = (anchor(1, 1), anchor(3, 2));
        assert_eq!(ask(&mut reads, &want, first), None);
        assert_eq!(reads.live(HOLDER), 1);
        assert_eq!(
            ask(&mut reads, &want, second),
            Some((want.filed_at, first, want.key)),
        );
        assert_eq!(reads.live(HOLDER), 1, "replacing leaves the count alone");
        assert_eq!(reads.out(want.key), Some(second));
    }

    /// The ask out comes back to whoever ends it: an arrival takes it,
    /// and a want's end sweeps it.
    #[test]
    fn an_arrival_and_a_wants_end_hand_the_ask_back() {
        let want = wanted(0);
        let at = anchor(1, 1);
        let id = (want.filed_at, at, want.key);

        let mut reads = RecordReads::new();
        reads.arm(&want, HOLDER, delay_past(0));
        let _ = ask(&mut reads, &want, at);
        assert_eq!(reads.take_out(want.key), Some(id));
        assert_eq!(reads.take_out(want.key), None, "handed back once");
        assert_eq!(reads.live(HOLDER), 0);

        let mut reads = RecordReads::new();
        reads.arm(&want, HOLDER, delay_past(0));
        let _ = ask(&mut reads, &want, at);
        assert_eq!(
            reads.sweep(delay_past(0), &BTreeSet::from([want.key])),
            vec![],
            "a want that stands keeps its ask",
        );
        assert_eq!(reads.sweep(delay_past(0), &BTreeSet::new()), vec![id]);
    }

    /// An answer at the anchor out clears it. One at any other anchor is
    /// a replaced ask's, and leaves the one out standing.
    #[test]
    fn only_the_ask_out_is_answered() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        reads.arm(&want, HOLDER, delay_past(0));
        let (first, second) = (anchor(1, 1), anchor(3, 2));
        let _ = ask(&mut reads, &want, first);
        let _ = ask(&mut reads, &want, second);
        reads.answered(want.key, first);
        assert_eq!(reads.out(want.key), Some(second));
        reads.answered(want.key, second);
        assert_eq!(reads.out(want.key), None);
    }

    /// A reset read asked at a newer anchor replaces the ask out. Asked
    /// at the anchor out it is that same ask, still standing: the caller
    /// sees its own id come back, and puts and abandons nothing.
    #[test]
    fn a_reset_replaces_the_ask_out_and_keeps_one_at_the_same_anchor() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        reads.arm(&want, HOLDER, delay_past(0));
        let at = anchor(1, 1);
        let id = (want.filed_at, at, want.key);
        let _ = ask(&mut reads, &want, at);

        reads.reset(want.key);
        assert_eq!(ask(&mut reads, &want, at), Some(id));
        assert_eq!(reads.out(want.key), Some(at));
        assert_eq!(reads.live(HOLDER), 1);

        reads.reset(want.key);
        assert_eq!(ask(&mut reads, &want, anchor(2, 2)), Some(id));
        assert_eq!(reads.out(want.key), Some(anchor(2, 2)));
    }

    /// A read the frontier reset asks at the very next holder anchor
    /// and backs off from there.
    #[test]
    fn a_reset_read_asks_at_the_next_anchor() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let key = want.key;
        reads.arm(&want, HOLDER, delay_past(0));
        assert!(reads.due(key, anchor(1, 1)));
        assert!(reads.due(key, anchor(3, 2)));
        assert!(!reads.due(key, anchor(5, 3)), "the third waits four");
        reads.reset(key);
        assert!(
            reads.due(key, anchor(5, 3)),
            "reset, the next anchor is asked at once"
        );
        assert!(!reads.due(key, anchor(6, 4)), "and the backoff starts over");
    }

    #[test]
    fn a_kept_push_stands_in_for_an_ask_and_does_not_disarm() {
        let mut reads = RecordReads::new();
        let key = test_key(1);
        let wanted = wanted(0);
        reads.arm(&wanted, HOLDER, delay_past(0));
        reads.pushed(key, anchor(9, 10_000));
        assert!(reads.is_armed(key), "a push never disarms");
        assert!(
            !reads.due(key, anchor(9, 10_000)),
            "not asked where the push answered"
        );
        assert!(
            !reads.due(key, anchor(10, 10_000)),
            "the next ask waits two heights"
        );
        assert!(reads.due(key, anchor(11, 10_000)));
    }
}
