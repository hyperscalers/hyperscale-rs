//! Buffer for execution votes and cross-shard execution certificates that
//! arrive before their local tick is tracked.
//!
//! Two distinct arrival races need buffering:
//!
//! ## Votes that arrive before the block commits
//!
//! A validator may receive an execution vote for a tick whose originating
//! block hasn't been committed locally yet — either because we're a few
//! blocks behind, or because we're the rotated leader for a retry and the
//! original leader's block reached us before ours did. These votes are
//! buffered per-`TickId` and replayed into the [`VoteTracker`] when a
//! leader tracker is eventually created.
//!
//! ## ECs that arrive before the tx's tick assignment exists
//!
//! A cross-shard [`ExecutionCertificate`] covers `tx_hashes` from the remote
//! shard's tick composition. Some of those txs may land in local blocks
//! that haven't committed yet, so we can't route the EC immediately. The
//! buffer holds the EC by its `tick_id` with a pending-tx set; as `tx_hashes`
//! land locally, we drain the EC back into the routing pipeline.
//!
//! The EC buffer has a two-level invariant: `pending_routing[tick_id]`
//! holds one bookkeeping entry per EC with the set of still-unrouted
//! `tx_hashes`; `tx_index[tx_hash]` holds the reverse index from `tx_hash` to
//! the ECs that mention it. Both sides must stay consistent — inserts
//! record into both, routed-clears decrement both, and stale-prunes remove
//! from both.
//!
//! ## Retention
//!
//! The two halves are bounded differently, and the asymmetry is the rule
//! rather than an oversight: a vote here is committee-gated at ingress and
//! not signature-verified until a tracker exists, where a certificate is
//! quorum-signed — see the holding classes in
//! [`hyperscale_types::verifiable`].
//!
//! - [`EARLY_VOTE_RETENTION`]: how long to hold votes whose block has never
//!   committed locally. Cleanup at commit time drops older entries since
//!   failure to commit past this window signals shard consensus is broken.
//! - [`MAX_BUFFERED_EARLY_VOTES`]: the count cap a single-signer class
//!   takes. Without it a Byzantine committee member floods votes for
//!   fabricated `TickId`s up to the time-based sweep. Past the ceiling new
//!   early votes are dropped; the voter's own vote-retry retransmits once
//!   the block commits, so a drop costs at most one retry interval of
//!   latency.
//! - Buffered ECs take no count cap and evict at the EC's own
//!   [`ExecutionCertificate::deadline`] — `vote_anchor_ts +
//!   RETENTION_HORIZON`. Past that point every tx the EC could mention
//!   has expired its `validity_range` and either terminated or aborted,
//!   so no local tick can still consume it. The anchor is BFT-attested,
//!   matching the sender-side deadline used by
//!   [`OutboundExecutionCertificateTracker`](crate::outbound_certs::OutboundExecutionCertificateTracker).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    ExecutionCertificate, ExecutionVote, MAX_FINALIZATION_DELAY, TickId, TxHash, Verifiable,
    Verified, WeightedTimestamp,
};

/// How long to retain unmatched early votes whose block never committed
/// locally. Past `MAX_FINALIZATION_DELAY` from the vote's `vote_anchor_ts`, the tick
/// the vote belonged to has aborted (success or all-abort), so the vote can
/// no longer contribute to a useful tick. Anchored on the committing QC's
/// `weighted_timestamp_ms` so the bound is BFT-authenticated.
pub const EARLY_VOTE_RETENTION: Duration = MAX_FINALIZATION_DELAY;

/// Hard ceiling on early votes buffered across all ticks.
///
/// Early votes are committee-gated at ingress but their per-vote
/// signatures aren't checked until a vote tracker spins up, so a Byzantine
/// committee member could otherwise grow the buffer without bound by
/// flooding votes for fabricated `TickId`s until the [`EARLY_VOTE_RETENTION`]
/// sweep. The ceiling is a global vote count, not a per-tick or per-shard
/// limit: legitimate buffering only spans a handful of in-flight ticks at a
/// time, so the sum stays far below this bound unless flooded. Past it, new
/// early votes are dropped — recoverable via the voter's vote-retry once the
/// block commits.
pub const MAX_BUFFERED_EARLY_VOTES: usize = 65_536;

/// Bookkeeping for an EC awaiting local routing.
///
/// Holds a single owning reference to the EC plus the set of `tx_hashes` from
/// `tx_outcomes` that haven't yet been matched to a local tick. As each
/// unrouted tx eventually commits locally, the `tx_hash` is removed from
/// `pending_txs`; when the set drains to empty the EC has been fully routed
/// and the entry is dropped.
#[derive(Debug)]
struct BufferedEc {
    ec: Arc<Verified<ExecutionCertificate>>,
    pending_txs: HashSet<TxHash>,
}

pub struct EarlyArrivalBuffer {
    /// Execution votes that arrived before tracking started, keyed by tick.
    votes: HashMap<TickId, Vec<Verifiable<ExecutionVote>>>,

    /// Reverse index from `tx_hash` to any buffered ECs mentioning it.
    /// Multiple `tx_hash` entries may reference the same handle (one EC
    /// covers many txs).
    tx_index: HashMap<TxHash, Vec<Arc<Verified<ExecutionCertificate>>>>,

    /// Per-EC bookkeeping. `tx_index` and `pending_routing` must stay
    /// consistent: an EC present in `tx_index[tx_hash]` for some `tx_hash`
    /// MUST have a `BufferedEc` entry in `pending_routing[ec.tick_id()]` with
    /// that `tx_hash` in its `pending_txs` set. Enforced by `buffer_ec`,
    /// `clear_routed`, `drain_ecs_for_txs`, and `gc_stale_ecs`.
    pending_routing: HashMap<TickId, BufferedEc>,

    /// Running total of votes across every `votes` entry, kept in step with
    /// `votes` so the [`MAX_BUFFERED_EARLY_VOTES`] cap is an O(1) check.
    buffered: usize,
}

impl EarlyArrivalBuffer {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            tx_index: HashMap::new(),
            pending_routing: HashMap::new(),
            buffered: 0,
        }
    }

    // ─── Votes ──────────────────────────────────────────────────────────

    /// Buffer a vote whose tick isn't yet tracked. Called from the
    /// non-leader ingress path. Returns `false` if the vote was dropped
    /// because the buffer is at [`MAX_BUFFERED_EARLY_VOTES`] capacity.
    pub fn buffer_vote(&mut self, tick_id: TickId, vote: Verifiable<ExecutionVote>) -> bool {
        if self.buffered >= MAX_BUFFERED_EARLY_VOTES {
            tracing::debug!(
                tick = %tick_id,
                buffered = self.buffered,
                "Early-vote buffer at capacity — dropping vote"
            );
            return false;
        }
        self.votes.entry(tick_id).or_default().push(vote);
        self.buffered += 1;
        true
    }

    /// Remove and return all buffered votes for `tick_id`. Called when the
    /// coordinator creates a leader or fallback-leader `VoteTracker` and
    /// needs to replay the backlog.
    pub fn drain_votes_for_tick(&mut self, tick_id: &TickId) -> Vec<Verifiable<ExecutionVote>> {
        let drained = self.votes.remove(tick_id).unwrap_or_default();
        self.buffered -= drained.len();
        drained
    }

    /// Predicate-driven retention for vote entries. The caller owns the
    /// policy (is the tick still tracked? does it already have an EC?); the
    /// buffer just exposes the retention cutoff and the retain loop.
    pub fn retain_votes<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&TickId, &[Verifiable<ExecutionVote>]) -> bool,
    {
        let buffered = &mut self.buffered;
        self.votes.retain(|tick_id, votes| {
            let keep = predicate(tick_id, votes);
            if !keep {
                *buffered -= votes.len();
            }
            keep
        });
    }

    // ─── ECs ────────────────────────────────────────────────────────────

    /// Buffer an EC under `tx_hashes` that don't yet have a local tick
    /// assignment. Idempotent: `tx_hashes` already tracked for this EC's
    /// `tick_id` are skipped, so replaying a previously-buffered EC won't
    /// create duplicate entries in the reverse index.
    pub fn buffer_ec(&mut self, ec: &Arc<Verified<ExecutionCertificate>>, tx_hashes: &[TxHash]) {
        if tx_hashes.is_empty() {
            return;
        }
        let entry = self
            .pending_routing
            .entry(*ec.tick_id())
            .or_insert_with(|| BufferedEc {
                ec: Arc::clone(ec),
                pending_txs: HashSet::new(),
            });
        for tx_hash in tx_hashes {
            if entry.pending_txs.insert(*tx_hash) {
                self.tx_index
                    .entry(*tx_hash)
                    .or_default()
                    .push(Arc::clone(ec));
            }
        }
    }

    /// Mark `tx_hashes` as routed for `ec`. When the pending set drains to
    /// empty the EC has been fully delivered and the entry is dropped.
    /// The reverse index is NOT touched here — the EC's `tx_hashes` are
    /// drained explicitly by [`drain_ecs_for_txs`] when those txs commit.
    pub fn clear_routed(&mut self, ec: &Arc<Verified<ExecutionCertificate>>, tx_hashes: &[TxHash]) {
        let Some(entry) = self.pending_routing.get_mut(ec.tick_id()) else {
            return;
        };
        for tx_hash in tx_hashes {
            entry.pending_txs.remove(tx_hash);
        }
        if entry.pending_txs.is_empty() {
            self.pending_routing.remove(ec.tick_id());
        }
    }

    /// Drain any buffered ECs that mention any hash in `tx_hashes`. The
    /// returned vec is deduplicated by `Arc` identity — a single EC that
    /// covers multiple newly-committed txs appears once.
    ///
    /// The reverse index is cleared for each drained `tx_hash`; the
    /// `pending_routing` entry is left alone (the caller will typically
    /// feed the EC into `handle_attestation`, which then calls
    /// `clear_routed` to drop the entry).
    pub fn drain_ecs_for_txs(
        &mut self,
        tx_hashes: &[TxHash],
    ) -> Vec<Arc<Verified<ExecutionCertificate>>> {
        let mut ecs: Vec<Arc<Verified<ExecutionCertificate>>> = Vec::new();
        let mut seen_ptrs: HashSet<usize> = HashSet::new();
        for tx_hash in tx_hashes {
            if let Some(entries) = self.tx_index.remove(tx_hash) {
                for ec in entries {
                    let ptr = Arc::as_ptr(&ec) as usize;
                    if seen_ptrs.insert(ptr) {
                        ecs.push(ec);
                    }
                }
            }
        }
        ecs
    }

    /// Drop buffered ECs whose own deadline has elapsed. The deadline is
    /// `ec.vote_anchor_ts() + RETENTION_HORIZON`, BFT-attested by the
    /// remote committee — the same bound the sender uses on the outbound
    /// side. Past it, every tx the EC mentions has expired its
    /// `validity_range` and either terminated or aborted, so no local
    /// tick can still consume it. Returns the number of ECs evicted.
    pub fn gc_stale_ecs(&mut self, now_ts: WeightedTimestamp) -> usize {
        let stale: Vec<TickId> = self
            .pending_routing
            .iter()
            .filter(|(_, entry)| entry.ec.deadline() <= now_ts)
            .map(|(wid, _)| *wid)
            .collect();
        if stale.is_empty() {
            return 0;
        }
        let count = stale.len();
        for wid in stale {
            let Some(entry) = self.pending_routing.remove(&wid) else {
                continue;
            };
            for tx_hash in &entry.pending_txs {
                if let Some(vec) = self.tx_index.get_mut(tx_hash) {
                    vec.retain(|e| !Arc::ptr_eq(e, &entry.ec));
                    if vec.is_empty() {
                        self.tx_index.remove(tx_hash);
                    }
                }
            }
        }
        count
    }

    // ─── Query ──────────────────────────────────────────────────────────

    pub fn vote_len(&self) -> usize {
        self.votes.len()
    }

    pub fn tx_index_len(&self) -> usize {
        self.tx_index.len()
    }

    pub fn pending_routing_len(&self) -> usize {
        self.pending_routing.len()
    }

    /// How many buffered ECs mention `tx_hash` — the count surfaced by the
    /// coordinator's `certificate_tracking_debug` output.
    pub fn attestation_count_for_tx(&self, tx_hash: TxHash) -> usize {
        self.tx_index.get(&tx_hash).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeight, ConsensusSignature, ExecutionOutcome,
        ExecutionVoteMessage, GlobalReceiptHash, GlobalReceiptRoot, Hash, NetworkDefinition,
        RETENTION_HORIZON, ShardId, Signer, SignerBitfield, TxHash, TxOutcome, ValidatorId,
        signed_bytes,
    };
    use proptest::collection::vec as prop_vec;

    use super::*;

    fn shard() -> ShardId {
        ShardId::ROOT
    }

    fn tick(height: u64) -> TickId {
        TickId::new(shard(), BlockHeight::new(height))
    }

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
    }

    fn make_tx_outcome(tx: TxHash) -> TxOutcome {
        TxOutcome::new(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
    }

    fn make_ec(tick_id: TickId, tx_hashes: &[TxHash]) -> Arc<Verified<ExecutionCertificate>> {
        make_ec_with_anchor(tick_id, tx_hashes, WeightedTimestamp::ZERO)
    }

    fn make_ec_with_anchor(
        tick_id: TickId,
        tx_hashes: &[TxHash],
        vote_anchor_ts: WeightedTimestamp,
    ) -> Arc<Verified<ExecutionCertificate>> {
        let outcomes: Vec<TxOutcome> = tx_hashes.iter().map(|h| make_tx_outcome(*h)).collect();
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            vote_anchor_ts,
            GlobalReceiptRoot::ZERO,
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )))
    }

    fn make_vote(tick_id: TickId, anchor_ts: WeightedTimestamp) -> ExecutionVote {
        let tx_outcomes = vec![make_tx_outcome(TxHash::from(Hash::from_bytes(b"tx")))];
        let global_receipt_root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let msg = signed_bytes(
            &ExecutionVoteMessage {
                vote_anchor_ts: anchor_ts,
                tick_id,
                shard_group: tick_id.shard_id(),
                global_receipt_root,
                tx_count: u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
            },
            &NetworkDefinition::simulator(),
        );
        let kp = BlsSigner::from_seed(&[7u8; 32]);
        let signature = kp.sign(&msg).expect("sign");
        ExecutionVote::new(
            BlockHash::ZERO,
            BlockHeight::new(1),
            anchor_ts,
            tick_id,
            shard(),
            global_receipt_root,
            u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
            tx_outcomes,
            ValidatorId::new(0),
            signature,
        )
    }

    /// A vote with a zero signature — cheap to build (no signing), for
    /// exercising the buffer's size cap at scale.
    fn cheap_vote(tick_id: TickId) -> Verifiable<ExecutionVote> {
        ExecutionVote::new(
            BlockHash::ZERO,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            tick_id,
            shard(),
            GlobalReceiptRoot::ZERO,
            0,
            vec![],
            ValidatorId::new(0),
            ConsensusSignature::ZERO,
        )
        .into()
    }

    // ─── Votes ──────────────────────────────────────────────────────────

    #[test]
    fn drain_votes_returns_buffered_and_leaves_buffer_empty() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        b.buffer_vote(w, make_vote(w, ms(100)).into());
        b.buffer_vote(w, make_vote(w, ms(200)).into());

        let drained = b.drain_votes_for_tick(&w);
        assert_eq!(drained.len(), 2);
        assert_eq!(b.vote_len(), 0);

        // Idempotent: second drain returns empty.
        assert!(b.drain_votes_for_tick(&w).is_empty());
    }

    #[test]
    fn drain_votes_is_per_tick() {
        let mut b = EarlyArrivalBuffer::new();
        let w1 = tick(1);
        let w2 = tick(2);
        b.buffer_vote(w1, make_vote(w1, ms(100)).into());
        b.buffer_vote(w2, make_vote(w2, ms(100)).into());

        let drained = b.drain_votes_for_tick(&w1);
        assert_eq!(drained.len(), 1);
        assert_eq!(b.vote_len(), 1);
    }

    #[test]
    fn retain_votes_drops_entries_matching_predicate() {
        let mut b = EarlyArrivalBuffer::new();
        let w1 = tick(1);
        let w2 = tick(2);
        b.buffer_vote(w1, make_vote(w1, ms(100)).into());
        b.buffer_vote(w2, make_vote(w2, ms(100)).into());

        b.retain_votes(|tick_id, _| tick_id == &w1);

        assert_eq!(b.vote_len(), 1);
        assert_eq!(b.drain_votes_for_tick(&w1).len(), 1);
        assert!(b.drain_votes_for_tick(&w2).is_empty());
    }

    #[test]
    fn buffer_vote_enforces_global_cap() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        for _ in 0..MAX_BUFFERED_EARLY_VOTES {
            assert!(b.buffer_vote(w, cheap_vote(w)));
        }
        // At capacity, further votes are dropped — including for a tick the
        // buffer has never seen, so a fabricated-`TickId` flood can't grow it.
        assert!(!b.buffer_vote(w, cheap_vote(tick(1))));
        assert!(!b.buffer_vote(tick(2), cheap_vote(tick(2))));
        assert!(!b.votes.contains_key(&tick(2)));
    }

    #[test]
    fn draining_a_tick_frees_buffer_capacity() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        for _ in 0..MAX_BUFFERED_EARLY_VOTES {
            b.buffer_vote(w, cheap_vote(w));
        }
        assert!(!b.buffer_vote(tick(2), cheap_vote(tick(2))));

        let drained = b.drain_votes_for_tick(&w);
        assert_eq!(drained.len(), MAX_BUFFERED_EARLY_VOTES);
        // The reclaimed budget lets fresh votes buffer again.
        assert!(b.buffer_vote(tick(2), cheap_vote(tick(2))));
    }

    #[test]
    fn retaining_frees_buffer_capacity_for_dropped_ticks() {
        let mut b = EarlyArrivalBuffer::new();
        let w1 = tick(1);
        let w2 = tick(2);
        let half = MAX_BUFFERED_EARLY_VOTES / 2;
        for _ in 0..half {
            b.buffer_vote(w1, cheap_vote(w1));
        }
        for _ in 0..(MAX_BUFFERED_EARLY_VOTES - half) {
            b.buffer_vote(w2, cheap_vote(w2));
        }
        assert!(!b.buffer_vote(tick(3), cheap_vote(tick(3))));

        // Dropping `w1` returns exactly its share of the budget.
        b.retain_votes(|tick_id, _| tick_id != &w1);
        for _ in 0..half {
            assert!(b.buffer_vote(tick(3), cheap_vote(tick(3))));
        }
        assert!(!b.buffer_vote(tick(3), cheap_vote(tick(3))));
    }

    // ─── ECs ────────────────────────────────────────────────────────────

    #[test]
    fn buffer_ec_records_pending_set_and_reverse_index() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"b"));
        let ec = make_ec(w, &[tx_a, tx_b]);

        b.buffer_ec(&ec, &[tx_a, tx_b]);

        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(b.attestation_count_for_tx(tx_a), 1);
        assert_eq!(b.attestation_count_for_tx(tx_b), 1);
    }

    #[test]
    fn buffer_ec_idempotent_for_same_tx_hashes() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx = TxHash::from(Hash::from_bytes(b"a"));
        let ec = make_ec(w, &[tx]);

        b.buffer_ec(&ec, &[tx]);
        b.buffer_ec(&ec, &[tx]);

        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(
            b.attestation_count_for_tx(tx),
            1,
            "duplicate buffer must not stack Arcs in the reverse index"
        );
    }

    #[test]
    fn clear_routed_drops_entry_once_pending_set_drains() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"b"));
        let ec = make_ec(w, &[tx_a, tx_b]);

        b.buffer_ec(&ec, &[tx_a, tx_b]);

        // Partial clear: entry survives.
        b.clear_routed(&ec, &[tx_a]);
        assert_eq!(b.pending_routing_len(), 1);

        // Final clear: entry dropped.
        b.clear_routed(&ec, &[tx_b]);
        assert_eq!(b.pending_routing_len(), 0);
    }

    #[test]
    fn drain_ecs_for_txs_returns_ecs_and_clears_reverse_index() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"b"));
        let ec = make_ec(w, &[tx_a, tx_b]);
        b.buffer_ec(&ec, &[tx_a, tx_b]);

        let drained = b.drain_ecs_for_txs(&[tx_a]);
        assert_eq!(drained.len(), 1);
        assert_eq!(b.attestation_count_for_tx(tx_a), 0);
        // tx_b still indexed — this drain only targeted tx_a.
        assert_eq!(b.attestation_count_for_tx(tx_b), 1);
    }

    #[test]
    fn drain_ecs_for_txs_dedups_arc_identity() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx_a = TxHash::from(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from(Hash::from_bytes(b"b"));
        // Single EC covers both txs; draining both hashes should yield one EC.
        let ec = make_ec(w, &[tx_a, tx_b]);
        b.buffer_ec(&ec, &[tx_a, tx_b]);

        let drained = b.drain_ecs_for_txs(&[tx_a, tx_b]);
        assert_eq!(drained.len(), 1, "identity-dedup on Arc pointer");
    }

    #[test]
    fn gc_stale_ecs_evicts_past_certificate_deadline() {
        // Each EC's deadline is `vote_anchor_ts + RETENTION_HORIZON`.
        // Old EC: anchor at ms(1_000) → deadline at 1_000 + horizon_ms.
        // Fresh EC: anchor at ms(60_000) → deadline at 60_000 + horizon_ms.
        let mut b = EarlyArrivalBuffer::new();
        let w_old = tick(1);
        let w_fresh = tick(2);
        let tx_old = TxHash::from(Hash::from_bytes(b"old"));
        let tx_fresh = TxHash::from(Hash::from_bytes(b"fresh"));

        let old_anchor = ms(1_000);
        let fresh_anchor = ms(60_000);
        b.buffer_ec(
            &make_ec_with_anchor(w_old, &[tx_old], old_anchor),
            &[tx_old],
        );
        b.buffer_ec(
            &make_ec_with_anchor(w_fresh, &[tx_fresh], fresh_anchor),
            &[tx_fresh],
        );

        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX);
        // now sits past the old EC's deadline but before the fresh one's.
        let now = ms(old_anchor.as_millis() + horizon_ms + 1);
        assert!(now.as_millis() < fresh_anchor.as_millis() + horizon_ms);
        let evicted = b.gc_stale_ecs(now);
        assert_eq!(evicted, 1);
        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(b.attestation_count_for_tx(tx_old), 0);
        assert_eq!(b.attestation_count_for_tx(tx_fresh), 1);
    }

    #[test]
    fn gc_stale_ecs_preserves_entries_within_horizon() {
        let mut b = EarlyArrivalBuffer::new();
        let w = tick(1);
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let anchor = ms(100_000);
        b.buffer_ec(&make_ec_with_anchor(w, &[tx], anchor), &[tx]);

        // now_ts equal to the anchor — well inside the EC's deadline.
        assert_eq!(b.gc_stale_ecs(anchor), 0);
        assert_eq!(b.pending_routing_len(), 1);
    }

    // ─── Property tests ─────────────────────────────────────────────────

    use proptest::prelude::*;

    // drain_votes_for_tick is idempotent: draining returns all buffered
    // votes and a subsequent drain returns empty.
    proptest! {
        #[test]
        fn drain_votes_is_idempotent(
            heights in prop_vec(0u64..20, 1..20),
            anchors in prop_vec(0u64..10_000, 1..20),
        ) {
            let mut b = EarlyArrivalBuffer::new();
            for (i, h) in heights.iter().enumerate() {
                let w = tick(*h);
                let anchor = ms(anchors[i % anchors.len()]);
                b.buffer_vote(w, make_vote(w, anchor).into());
            }

            // Drain every tick once; collect counts. A second drain of each
            // must return zero.
            let tick_ids: Vec<TickId> = heights.iter().map(|h| tick(*h)).collect();
            let mut first_counts = Vec::new();
            for w in &tick_ids {
                first_counts.push(b.drain_votes_for_tick(w).len());
            }
            for w in &tick_ids {
                prop_assert!(b.drain_votes_for_tick(w).is_empty());
            }
            // Total drained = total buffered.
            prop_assert_eq!(first_counts.iter().sum::<usize>(), heights.len());
        }
    }

    // GC never drops an EC whose deadline (vote_anchor_ts +
    // RETENTION_HORIZON) is strictly greater than now_ts.
    proptest! {
        #[test]
        fn gc_preserves_fresh_entries(
            heights in prop_vec(0u64..20, 1..10),
            anchor_ms in prop_vec(0u64..1_000_000, 1..10),
            now_ms in 0u64..2_000_000,
        ) {
            let mut b = EarlyArrivalBuffer::new();
            for (i, h) in heights.iter().enumerate() {
                let w = tick(*h);
                let tx = TxHash::from(Hash::from_bytes(&[u8::try_from(i).unwrap_or(u8::MAX); 32]));
                let anchor = ms(anchor_ms[i % anchor_ms.len()]);
                b.buffer_ec(&make_ec_with_anchor(w, &[tx], anchor), &[tx]);
            }
            let before = b.pending_routing_len();

            b.gc_stale_ecs(ms(now_ms));

            // Every surviving entry must have a deadline strictly past now.
            for entry in b.pending_routing.values() {
                prop_assert!(
                    entry.ec.deadline() > ms(now_ms),
                    "GC left a stale entry: deadline={:?}, now={}",
                    entry.ec.deadline(),
                    now_ms,
                );
            }
            // Invariant: we never GAIN entries from a GC call.
            prop_assert!(b.pending_routing_len() <= before);
        }
    }
}
