//! The one pacing for a consumer's reads of the crossing records it
//! waits on.
//!
//! A record reaches its consumer as a pushed claim, and when no push
//! lands the consumer reads it through a state-proof fetch of the
//! producer's chain, one that is the record reads' alone. This is what
//! decides when that read is put: a key arms on the first evidence that
//! the producer's leg has run or never will, and once armed is asked at
//! a proven anchor of the record's holder, backing off in the holder's
//! heights and never waiting longer than one finalization delay between
//! asks, of the holder's clock or of this chain's where the holder's
//! has stopped. One ask stands for a key at a time: a
//! later one takes the earlier's place, so no key queues twice.
//!
//! Two clocks arm a read. The holder's own, read off its newest proven
//! anchor, arms a key once that anchor stands a grace past the want's
//! filing, where the grace is derived from how long the holder's pushes
//! have been taking: nothing committed says when a leg ran, so the read
//! itself is the only verifiable answer, and a read that lands before
//! the push it stands in for is a wasted one. This node's committed
//! clock arms it one finalization delay past the filing whatever the
//! holder's headers do, which catches a holder whose headers stopped
//! with the record already written.
//!
//! Node-local, like the asking itself: what a validator asks for is its
//! own business, and what the answer licenses is a claim riding into a
//! block where every replica folds the same bytes. A restarted,
//! snap-synced or re-seated replica starts empty and re-derives the
//! wanted set and its arming instants from committed state, so a key
//! whose arming evidence is already in hand is asked at once.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use hyperscale_metrics::{record_record_ask, record_record_push_span, set_record_push_grace};
use hyperscale_types::{
    Anchor, BlockHeight, MAX_FINALIZATION_DELAY, RETENTION_HORIZON, ShardId, SubstateKey, TxHash,
    WeightedTimestamp,
};

use crate::provisioning::WantedRecord;

/// The least grace a holder's records get, and all of it before any push
/// has been heard: a quiet window must not arm into a normal leg.
pub const RECORD_PUSH_GRACE_FLOOR: Duration = Duration::from_secs(5);

/// The most grace a holder's records get, which keeps a lost record
/// inside a route's naming window on any network.
pub const RECORD_PUSH_GRACE_CEILING: Duration = Duration::from_secs(15);

/// How many of a holder's heights the grace is derived over, about 11 s
/// of its blocks.
const PUSH_SPAN_HEIGHTS: usize = 32;

/// The grace over a holder's height samples: 3/2 of their median, which
/// sits above nearly all of its spans and well under the 10 s a lost
/// record should take. A small tail outruns it, each a read that holds
/// nothing.
///
/// The median, since one late push or one contended leg moves it nowhere,
/// where a maximum would hand that lever to one member. A member is not
/// held off by it: it picks the anchor height of each claim it withholds
/// and can take any share of the window its keys buy, and past half the
/// median follows it. [`RECORD_PUSH_GRACE_CEILING`] is what bounds that.
fn grace_over(samples: &[Duration]) -> Duration {
    median_of(samples).map_or(RECORD_PUSH_GRACE_FLOOR, |median| {
        (median * 3 / 2).clamp(RECORD_PUSH_GRACE_FLOOR, RECORD_PUSH_GRACE_CEILING)
    })
}

/// The lower median of `spans`, `None` where there are none: a tie goes
/// low, so one late span beside an honest one does not win a height, and
/// holding half the heights does not win the window.
fn median_of(spans: &[Duration]) -> Option<Duration> {
    let mut spans = spans.to_vec();
    spans.sort_unstable();
    spans.get(spans.len().saturating_sub(1) / 2).copied()
}

/// How long one holder's pushes have been taking, by the holder height
/// each was read at.
///
/// One sample a height, the median of the spans of the keys kept at that
/// anchor. Not one a key, or one claim of 32 keys replaces the window;
/// not one a claim, or any member can split a batch into many proven
/// claims with `restrict`. The grace is derived only as a new height
/// enters, from the heights before it, so a commit walks no list and one
/// batch moves it by at most one sample.
#[derive(Debug)]
struct Spans {
    heights: BTreeMap<BlockHeight, Vec<Duration>>,
    grace: Duration,
    /// The clock of the last span heard, which sweeps a holder gone
    /// quiet.
    heard: WeightedTimestamp,
}

impl Spans {
    const fn new(now: WeightedTimestamp) -> Self {
        Self {
            heights: BTreeMap::new(),
            grace: RECORD_PUSH_GRACE_FLOOR,
            heard: now,
        }
    }

    /// Take `span`, kept at `height`. Past a full window, a span below
    /// the lowest height held is dropped.
    fn sample(&mut self, height: BlockHeight, span: Duration, now: WeightedTimestamp) {
        self.heard = now;
        let full = self.heights.len() >= PUSH_SPAN_HEIGHTS;
        if let Some(spans) = self.heights.get_mut(&height) {
            spans.push(span);
            return;
        }
        if full
            && self
                .heights
                .first_key_value()
                .is_some_and(|(lowest, _)| height < *lowest)
        {
            return;
        }
        let samples: Vec<Duration> = self
            .heights
            .values()
            .filter_map(|spans| median_of(spans))
            .collect();
        self.grace = grace_over(&samples);
        set_record_push_grace(u64::try_from(self.grace.as_millis()).unwrap_or(u64::MAX));
        self.heights.insert(height, vec![span]);
        if self.heights.len() > PUSH_SPAN_HEIGHTS {
            self.heights.pop_first();
        }
    }
}

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
    /// The holder's newest proven anchor stands a grace past the want's
    /// filing, on the holder's clock. A push held before then means no
    /// ask goes out.
    Grace,
    /// A verified execution certificate from the record's holder named
    /// the transaction. Only a producer whose member is not a leg sends
    /// one: a pure leg's certificate stays home, so its consumer arms on
    /// the clocks. The push carries the happy path, so this delays only
    /// the fallback.
    Certificate,
}

/// One record's read: whether it is armed and by what, how many asks
/// have gone out since it was armed, the holder anchor the last one was
/// put at with this chain's clock as it was, and the ask still out for
/// the key, if one is.
#[derive(Debug, Default)]
struct Read {
    armed: Option<Evidence>,
    step: u32,
    last: Option<(Anchor, WeightedTimestamp)>,
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
    /// How long each holder's pushes have been taking. A restarted
    /// replica or a new holder after a reshape starts at the floor.
    spans: BTreeMap<ShardId, Spans>,
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
    /// remembered past one horizon of `now`, and the holders no push has
    /// been heard from for as long. Hands back the asks still out for
    /// the keys dropped.
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
        self.spans.retain(|_, spans| spans.heard >= floor);
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

    /// The grace past a want's filing that `holder`'s records get.
    fn grace(&self, holder: ShardId) -> Duration {
        self.spans
            .get(&holder)
            .map_or(RECORD_PUSH_GRACE_FLOOR, |spans| spans.grace)
    }

    /// Arm the read of `wanted` where its evidence is in: `holder` has
    /// certified its transaction, this chain's clock `now` is one
    /// finalization delay past its filing, or `anchor`, the holder's
    /// newest proven, stands the holder's grace past it. Arming is
    /// sticky, so a grace that falls arms what it has passed.
    ///
    /// The one ladder runs across the clocks, so a key the grace armed
    /// keeps its step when the clock catches it up. Only a certificate
    /// resets it: a key the clocks armed is asked again at once when the
    /// holder's certificate lands.
    pub fn arm(
        &mut self,
        wanted: &WantedRecord,
        holder: ShardId,
        now: WeightedTimestamp,
        anchor: Option<Anchor>,
    ) {
        let by_certificate = self
            .certified
            .get(&wanted.tx)
            .is_some_and(|(shards, _)| shards.contains(&holder));
        let past_grace = wanted.filed_at.plus(self.grace(holder));
        let evidence = if by_certificate {
            Some(Evidence::Certificate)
        } else if now >= wanted.filed_at.plus(MAX_FINALIZATION_DELAY) {
            Some(Evidence::Clock)
        } else if anchor.is_some_and(|anchor| anchor.ts >= past_grace) {
            Some(Evidence::Grace)
        } else {
            None
        };
        let read = self.reads.entry(wanted.key).or_default();
        if let Some(evidence) = evidence
            && read.armed != Some(evidence)
        {
            read.armed = Some(evidence);
            if evidence == Evidence::Certificate {
                read.step = 0;
            }
        }
    }

    /// A pushed arrival of `key` at `anchor` was kept: it stands where an
    /// answered ask would, so the next ask waits one more doubling past
    /// this anchor, and nothing here disarms — only a committed arrival
    /// ends the want. `span` is how long it took, heard at `now`, which
    /// goes into the grace of the anchor's shard.
    pub fn pushed(
        &mut self,
        key: SubstateKey,
        anchor: Anchor,
        span: Duration,
        now: WeightedTimestamp,
    ) {
        let read = self.reads.entry(key).or_default();
        read.last = Some((anchor, now));
        read.step = read.step.saturating_add(1);
        record_record_push_span(u64::try_from(span.as_millis()).unwrap_or(u64::MAX));
        self.spans
            .entry(anchor.shard)
            .or_insert_with(|| Spans::new(now))
            .sample(anchor.height, span, now);
    }

    /// Whether `key` is asked at `anchor`, a proven anchor of its holder,
    /// and if so the ask is counted as put there.
    ///
    /// The k-th ask after arming waits for a holder anchor `2^k` heights
    /// above the last, and no longer than one finalization delay of the
    /// holder's clock past it, so a record a producer is slow to write
    /// is asked less and less often while one the consumer is about to
    /// need is asked at least once per finality delay.
    ///
    /// A holder whose headers froze runs neither of those out, so one
    /// finalization delay of this chain's clock `now` past the last ask
    /// also calls one, at any anchor above the last: the record may
    /// stand in the last block it wrote. At the anchor of the last ask
    /// there is nothing new to read, so a frozen holder draws one such
    /// ask and no more.
    pub fn due_at(&mut self, key: SubstateKey, anchor: Anchor, now: WeightedTimestamp) -> bool {
        let Some(read) = self.reads.get_mut(&key) else {
            return false;
        };
        if read.armed.is_none() {
            return false;
        }
        let due = match read.last {
            None => true,
            Some((last, asked_at)) => {
                let gap = 1u64 << read.step.min(32);
                anchor.height.inner() >= last.height.inner().saturating_add(gap)
                    || anchor.ts.elapsed_since(last.ts) >= MAX_FINALIZATION_DELAY
                    || (anchor.height > last.height
                        && now.elapsed_since(asked_at) >= MAX_FINALIZATION_DELAY)
            }
        };
        if due {
            read.last = Some((anchor, now));
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

    /// [`Self::due_at`] with this chain's clock level with the holder's,
    /// for the tests that watch the ladder.
    #[cfg(test)]
    pub fn due(&mut self, key: SubstateKey, anchor: Anchor) -> bool {
        self.due_at(key, anchor, anchor.ts)
    }

    /// How many of `holder`'s heights have given a sample, for the tests
    /// that watch the window.
    #[cfg(test)]
    pub fn sampled_heights(&self, holder: ShardId) -> usize {
        self.spans
            .get(&holder)
            .map_or(0, |spans| spans.heights.len())
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

        reads.arm(&want, HOLDER, armed.minus(Duration::from_millis(1)), None);
        assert!(!reads.is_armed(key));
        assert!(!reads.due(key, anchor(1, 9_999)), "not before the evidence");

        reads.arm(&want, HOLDER, armed, None);
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
    /// no push, and still reads: the want filed at commit arms a grace
    /// later, on the holder's clock.
    #[test]
    fn a_pure_legs_consumer_arms_on_the_holders_clock() {
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
        let armed = filed.plus(RECORD_PUSH_GRACE_FLOOR).as_millis();
        reads.arm(&want, HOLDER, filed, Some(anchor(1, armed - 1)));
        assert!(
            !reads.is_armed(want.key),
            "a millisecond short of the grace"
        );
        reads.arm(&want, HOLDER, filed, Some(anchor(1, armed)));
        assert!(reads.is_armed(want.key), "on the holder's clock alone");
        assert!(reads.due(want.key, anchor(1, armed)));
    }

    /// The local clock past the grace arms nothing while the holder's
    /// anchors stand below it: what the grace reads is the holder's own
    /// clock, or no anchor at all.
    #[test]
    fn a_local_clock_past_the_grace_does_not_arm() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let past = WeightedTimestamp::from_millis(0).plus(RECORD_PUSH_GRACE_CEILING);
        reads.arm(&want, HOLDER, past, Some(anchor(1, 4_999)));
        assert!(!reads.is_armed(want.key));
        reads.arm(&want, HOLDER, past, None);
        assert!(!reads.is_armed(want.key));
    }

    /// The clock arms a key with no fresh holder anchor, and keeps the
    /// grace's step: one key's asks stay on one ladder.
    #[test]
    fn the_clock_arms_with_no_anchor_and_keeps_the_ladder() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let key = want.key;
        reads.arm(&want, HOLDER, delay_past(0), None);
        assert!(reads.is_armed(key), "no anchor stands past the grace");

        let mut laddered = RecordReads::new();
        let at = anchor(1, 5_000);
        laddered.arm(&want, HOLDER, at.ts, Some(at));
        assert!(laddered.due(key, at));
        assert!(laddered.due(key, anchor(3, 5_001)));
        laddered.arm(&want, HOLDER, delay_past(0), None);
        assert!(
            !laddered.due(key, anchor(5, 5_002)),
            "the third ask still waits four heights",
        );
        assert!(laddered.due(key, anchor(7, 5_003)));
    }

    /// A key the grace armed and walked up the ladder, whose holder then
    /// froze short of the next rung, still asks: one finalization delay
    /// of this chain's clock past the last ask, at the newest anchor
    /// held. Its holder's clock has stopped, and the record may stand in
    /// the last block it wrote. A frozen holder draws that one ask and
    /// no more, and the ask at an anchor the last one stood at draws none.
    #[test]
    fn a_frozen_holder_is_asked_on_this_chains_clock() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let key = want.key;
        let first = anchor(1, 5_000);
        reads.arm(&want, HOLDER, first.ts, Some(first));
        assert!(reads.due(key, first));
        assert!(reads.due(key, anchor(3, 6_000)));
        assert!(reads.due(key, anchor(7, 7_000)));
        assert!(reads.due(key, anchor(15, 10_000)));
        let last = anchor(31, 16_000);
        assert!(reads.due(key, last));

        let frozen = anchor(37, 18_000);
        let asked_at = last.ts;
        let reach = asked_at.plus(MAX_FINALIZATION_DELAY);
        let short = reach.minus(Duration::from_millis(1));
        assert!(!reads.due_at(key, frozen, short), "a millisecond short");
        reads.arm(&want, HOLDER, reach, Some(frozen));
        assert!(
            !reads.due_at(key, last, reach),
            "nothing new at that anchor"
        );
        assert!(reads.due_at(key, frozen, reach), "the clock's reach asks");

        let much_later = reach.plus(MAX_FINALIZATION_DELAY * 4);
        assert!(!reads.due_at(key, frozen, much_later), "and only once");
    }

    /// `spans`, one height each, from `HOLDER`'s height `from`.
    fn heard(reads: &mut RecordReads, from: u64, spans: &[Duration]) {
        for (height, span) in (from..).zip(spans) {
            reads.pushed(
                test_key(1),
                anchor(height, 0),
                *span,
                WeightedTimestamp::ZERO,
            );
        }
    }

    /// The floor before any sample. Then 3/2 of the median of the
    /// heights before the newest, held at both clamps, and unmoved by a
    /// quarter of the heights running late.
    #[test]
    fn the_grace_is_three_halves_of_the_median_within_its_clamps() {
        let secs = Duration::from_secs;
        let mut reads = RecordReads::new();
        assert_eq!(reads.grace(HOLDER), RECORD_PUSH_GRACE_FLOOR, "cold");
        heard(&mut reads, 1, &[secs(6)]);
        assert_eq!(
            reads.grace(HOLDER),
            RECORD_PUSH_GRACE_FLOOR,
            "a height counts once the next one enters",
        );
        heard(&mut reads, 2, &[secs(6), secs(6), secs(6)]);
        assert_eq!(reads.grace(HOLDER), secs(9));

        let mut quiet = RecordReads::new();
        heard(&mut quiet, 1, &[Duration::from_secs(1); 8]);
        assert_eq!(quiet.grace(HOLDER), RECORD_PUSH_GRACE_FLOOR, "the floor");
        let mut slow = RecordReads::new();
        heard(&mut slow, 1, &[Duration::from_secs(60); 8]);
        assert_eq!(slow.grace(HOLDER), RECORD_PUSH_GRACE_CEILING, "the ceiling");

        let mut late = RecordReads::new();
        let window = [secs(6), secs(6), secs(6), secs(30)].repeat(8);
        heard(&mut late, 1, &window);
        assert_eq!(late.grace(HOLDER), secs(9), "a quarter of the heights late");
    }

    /// One height, one sample, however its keys reach here: a claim of
    /// 64 keys or the same batch split across 64 claims moves the window
    /// by the one height they were read at. The window then evicts its
    /// lowest height, and a span below it is dropped.
    #[test]
    fn a_batch_moves_the_window_by_one_height() {
        let secs = Duration::from_secs;
        let mut reads = RecordReads::new();
        heard(&mut reads, 1, &[secs(6); 32]);
        for _ in 0..64 {
            reads.pushed(
                test_key(2),
                anchor(33, 0),
                secs(40),
                WeightedTimestamp::ZERO,
            );
        }
        let spans = &reads.spans[&HOLDER];
        assert_eq!(spans.heights.len(), PUSH_SPAN_HEIGHTS);
        assert_eq!(spans.heights.keys().next(), Some(&BlockHeight::new(2)));
        heard(&mut reads, 34, &[secs(6)]);
        assert_eq!(reads.grace(HOLDER), secs(9), "the batch is one sample");

        heard(&mut reads, 1, &[secs(40)]);
        assert!(
            !reads.spans[&HOLDER]
                .heights
                .contains_key(&BlockHeight::new(1)),
            "below the window",
        );
    }

    /// Feed a full window, honest at 6 s, then `windows` more in which
    /// `late_of_32` heights of every 32 are a member's, each span as long
    /// as the grace it reads, so the member spends all the grace gives it.
    fn ratcheted(windows: u64, late_of_32: u64) -> Duration {
        let secs = Duration::from_secs;
        let mut reads = RecordReads::new();
        heard(&mut reads, 1, &[secs(6); 32]);
        for height in 33..33 + windows * 32 {
            let span = if (height - 33) % 32 < late_of_32 {
                reads.grace(HOLDER)
            } else {
                secs(6)
            };
            heard(&mut reads, height, &[span]);
        }
        reads.grace(HOLDER)
    }

    /// A member holding half a holder's heights, each span as late as the
    /// grace lets it, leaves the grace at the honest figure however long
    /// it keeps at it. One height past half and the median is its own,
    /// which climbs by 3/2 a window to the ceiling: that is what the
    /// ceiling is for.
    #[test]
    fn half_the_heights_do_not_ratchet_the_grace() {
        let secs = Duration::from_secs;
        assert_eq!(ratcheted(8, 16), secs(9), "half is not enough");
        assert_eq!(ratcheted(8, 17), RECORD_PUSH_GRACE_CEILING, "past half is");
    }

    /// A late span beside an honest one at the same height does not win
    /// it, and a late height has to outnumber its honest spans.
    #[test]
    fn a_tie_at_a_height_goes_to_the_earlier_span() {
        let secs = Duration::from_secs;
        assert_eq!(median_of(&[secs(6), secs(15)]), Some(secs(6)));
        assert_eq!(median_of(&[secs(15), secs(6), secs(15)]), Some(secs(15)));
        assert_eq!(median_of(&[]), None);

        let mut reads = RecordReads::new();
        for height in 1..=33 {
            for span in [secs(6), secs(15)] {
                reads.pushed(
                    test_key(1),
                    anchor(height, 0),
                    span,
                    WeightedTimestamp::ZERO,
                );
            }
        }
        assert_eq!(reads.grace(HOLDER), secs(9));
    }

    /// A holder's spans go a horizon after its last sample, which leaves
    /// a new holder at the floor.
    #[test]
    fn a_quiet_holders_spans_are_swept() {
        let mut reads = RecordReads::new();
        heard(&mut reads, 1, &[Duration::from_secs(8); 4]);
        let at_the_horizon = WeightedTimestamp::ZERO.plus(RETENTION_HORIZON);
        let _ = reads.sweep(at_the_horizon, &BTreeSet::new());
        assert_eq!(reads.grace(HOLDER), Duration::from_secs(12));
        let past_it = at_the_horizon.plus(Duration::from_millis(1));
        let _ = reads.sweep(past_it, &BTreeSet::new());
        assert_eq!(reads.grace(HOLDER), RECORD_PUSH_GRACE_FLOOR);
    }

    /// A replayed commit whose clock is past the grace puts one ask,
    /// however often it passes the key, and the arrival folded next
    /// stands it down.
    #[test]
    fn a_replayed_commit_puts_at_most_one_ask() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let at = anchor(1, 5_000);
        for _ in 0..3 {
            reads.arm(&want, HOLDER, at.ts, Some(at));
            if reads.due(want.key, at) {
                assert_eq!(reads.put((want.filed_at, at, want.key)), None);
            }
        }
        assert_eq!(reads.live(HOLDER), 1);
        assert_eq!(
            reads.take_out(want.key),
            Some((want.filed_at, at, want.key))
        );
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

        reads.arm(&want, HOLDER, now, None);
        assert!(
            !reads.is_armed(key),
            "nothing but a certificate arms this one"
        );
        reads.certified(ShardId::leaf(1, 1), [want.tx], now);
        reads.arm(&want, HOLDER, now, None);
        assert!(
            !reads.is_armed(key),
            "another shard's certificate is not the holder's"
        );
        reads.certified(HOLDER, [want.tx], now);
        reads.arm(&want, HOLDER, now, None);
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
        by_clock.arm(&clocked, HOLDER, now, None);
        assert!(by_clock.due(key, anchor(1, 5_000)));
        assert!(by_clock.due(key, anchor(3, 5_001)));
        assert!(!by_clock.due(key, anchor(5, 5_002)));
        by_clock.certified(HOLDER, [clocked.tx], now);
        by_clock.arm(&clocked, HOLDER, now, None);
        assert!(
            by_clock.due(key, anchor(5, 5_003)),
            "the certificate resets the step"
        );

        // A certificate heard before its key is wanted is kept one
        // horizon and no longer.
        let mut early = RecordReads::new();
        early.certified(HOLDER, [want.tx], now);
        early.sweep(now.plus(RETENTION_HORIZON), &BTreeSet::new());
        early.arm(&want, HOLDER, now.plus(RETENTION_HORIZON), None);
        assert!(early.is_armed(key), "still remembered at the horizon");
        let mut late = RecordReads::new();
        late.certified(HOLDER, [want.tx], now);
        late.sweep(
            now.plus(RETENTION_HORIZON).plus(Duration::from_millis(1)),
            &BTreeSet::new(),
        );
        late.arm(&want, HOLDER, now, None);
        assert!(!late.is_armed(key), "and forgotten past it");
    }

    /// A key the wanted set stops naming is forgotten: an arrival
    /// committed, or nothing here waits on it any more.
    #[test]
    fn a_read_ends_with_its_want() {
        let mut reads = RecordReads::new();
        let want = wanted(0);
        let now = delay_past(0);
        reads.arm(&want, HOLDER, now, None);
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
        reads.arm(&want, HOLDER, delay_past(0), None);
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
        reads.arm(&want, HOLDER, delay_past(0), None);
        let _ = ask(&mut reads, &want, at);
        assert_eq!(reads.take_out(want.key), Some(id));
        assert_eq!(reads.take_out(want.key), None, "handed back once");
        assert_eq!(reads.live(HOLDER), 0);

        let mut reads = RecordReads::new();
        reads.arm(&want, HOLDER, delay_past(0), None);
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
        reads.arm(&want, HOLDER, delay_past(0), None);
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
        reads.arm(&want, HOLDER, delay_past(0), None);
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
        reads.arm(&want, HOLDER, delay_past(0), None);
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
        reads.arm(&wanted, HOLDER, delay_past(0), None);
        reads.pushed(
            key,
            anchor(9, 10_000),
            Duration::ZERO,
            WeightedTimestamp::ZERO,
        );
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
