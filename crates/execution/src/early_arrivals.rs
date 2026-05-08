//! Buffer for execution votes and cross-shard execution certificates that
//! arrive before their local wave is tracked.
//!
//! Two distinct arrival races need buffering:
//!
//! ## Votes that arrive before the block commits
//!
//! A validator may receive an execution vote for a wave whose originating
//! block hasn't been committed locally yet — either because we're a few
//! blocks behind, or because we're the rotated leader for a retry and the
//! original leader's block reached us before ours did. These votes are
//! buffered per-`WaveId` and replayed into the [`VoteTracker`] when a
//! leader tracker is eventually created.
//!
//! ## ECs that arrive before the tx's wave assignment exists
//!
//! A cross-shard [`ExecutionCertificate`] covers `tx_hashes` from the remote
//! shard's wave decomposition. Some of those txs may land in local blocks
//! that haven't committed yet, so we can't route the EC immediately. The
//! buffer holds the EC by its `wave_id` with a pending-tx set; as `tx_hashes`
//! land locally, we drain the EC back into the routing pipeline.
//!
//! The EC buffer has a two-level invariant: `pending_routing[wave_id]`
//! holds one bookkeeping entry per EC with the set of still-unrouted
//! `tx_hashes`; `tx_index[tx_hash]` holds the reverse index from `tx_hash` to
//! the ECs that mention it. Both sides must stay consistent — inserts
//! record into both, routed-clears decrement both, and stale-prunes remove
//! from both.
//!
//! ## Retention
//!
//! - [`EARLY_VOTE_RETENTION`]: how long to hold votes whose block has never
//!   committed locally. Cleanup at commit time drops older entries since
//!   failure to commit past this window signals BFT is broken.
//! - Buffered ECs evict at the EC's own
//!   [`ExecutionCertificate::deadline`] — `vote_anchor_ts +
//!   RETENTION_HORIZON`. Past that point every tx the EC could mention
//!   has expired its `validity_range` and either terminated or aborted,
//!   so no local wave can still consume it. The anchor is BFT-attested,
//!   matching the sender-side deadline used by
//!   [`OutboundExecutionCertificateTracker`](crate::outbound_certs::OutboundExecutionCertificateTracker).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    ExecutionCertificate, ExecutionVote, TxHash, WAVE_TIMEOUT, WaveId, WeightedTimestamp,
};

/// How long to retain unmatched early votes whose block never committed
/// locally. Past `WAVE_TIMEOUT` from the vote's `vote_anchor_ts`, the wave
/// the vote belonged to has aborted (success or all-abort), so the vote can
/// no longer contribute to a useful wave. Anchored on the committing QC's
/// `weighted_timestamp_ms` so the bound is BFT-authenticated.
pub const EARLY_VOTE_RETENTION: Duration = WAVE_TIMEOUT;

/// Bookkeeping for an EC awaiting local routing.
///
/// Holds a single owning reference to the EC plus the set of `tx_hashes` from
/// `tx_outcomes` that haven't yet been matched to a local wave. As each
/// unrouted tx eventually commits locally, the `tx_hash` is removed from
/// `pending_txs`; when the set drains to empty the EC has been fully routed
/// and the entry is dropped.
#[derive(Debug)]
struct BufferedEc {
    ec: Arc<ExecutionCertificate>,
    pending_txs: HashSet<TxHash>,
}

pub struct EarlyArrivalBuffer {
    /// Execution votes that arrived before tracking started, keyed by wave.
    votes: HashMap<WaveId, Vec<ExecutionVote>>,

    /// Reverse index from `tx_hash` to any buffered ECs mentioning it.
    /// Multiple `tx_hash` entries may reference the same `Arc<EC>` (one EC
    /// covers many txs).
    tx_index: HashMap<TxHash, Vec<Arc<ExecutionCertificate>>>,

    /// Per-EC bookkeeping. `tx_index` and `pending_routing` must stay
    /// consistent: an EC present in `tx_index[tx_hash]` for some `tx_hash`
    /// MUST have a `BufferedEc` entry in `pending_routing[ec.wave_id]` with
    /// that `tx_hash` in its `pending_txs` set. Enforced by `buffer_ec`,
    /// `clear_routed`, `drain_ecs_for_txs`, and `gc_stale_ecs`.
    pending_routing: HashMap<WaveId, BufferedEc>,
}

impl EarlyArrivalBuffer {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            tx_index: HashMap::new(),
            pending_routing: HashMap::new(),
        }
    }

    // ─── Votes ──────────────────────────────────────────────────────────

    /// Buffer a vote whose wave isn't yet tracked. Called from the
    /// non-leader ingress path.
    pub fn buffer_vote(&mut self, wave_id: WaveId, vote: ExecutionVote) {
        self.votes.entry(wave_id).or_default().push(vote);
    }

    /// Remove and return all buffered votes for `wave_id`. Called when the
    /// coordinator creates a leader or fallback-leader `VoteTracker` and
    /// needs to replay the backlog.
    pub fn drain_votes_for_wave(&mut self, wave_id: &WaveId) -> Vec<ExecutionVote> {
        self.votes.remove(wave_id).unwrap_or_default()
    }

    /// Predicate-driven retention for vote entries. The caller owns the
    /// policy (is the wave still tracked? does it already have an EC?); the
    /// buffer just exposes the retention cutoff and the retain loop.
    pub fn retain_votes<F>(&mut self, mut predicate: F)
    where
        F: FnMut(&WaveId, &[ExecutionVote]) -> bool,
    {
        self.votes
            .retain(|wave_id, votes| predicate(wave_id, votes));
    }

    // ─── ECs ────────────────────────────────────────────────────────────

    /// Buffer an EC under `tx_hashes` that don't yet have a local wave
    /// assignment. Idempotent: `tx_hashes` already tracked for this EC's
    /// `wave_id` are skipped, so replaying a previously-buffered EC won't
    /// create duplicate entries in the reverse index.
    pub fn buffer_ec(&mut self, ec: &Arc<ExecutionCertificate>, tx_hashes: &[TxHash]) {
        if tx_hashes.is_empty() {
            return;
        }
        let entry = self
            .pending_routing
            .entry(ec.wave_id.clone())
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
    pub fn clear_routed(&mut self, ec: &Arc<ExecutionCertificate>, tx_hashes: &[TxHash]) {
        let Some(entry) = self.pending_routing.get_mut(&ec.wave_id) else {
            return;
        };
        for tx_hash in tx_hashes {
            entry.pending_txs.remove(tx_hash);
        }
        if entry.pending_txs.is_empty() {
            self.pending_routing.remove(&ec.wave_id);
        }
    }

    /// Drain any buffered ECs that mention any hash in `tx_hashes`. The
    /// returned vec is deduplicated by `Arc` identity — a single EC that
    /// covers multiple newly-committed txs appears once.
    ///
    /// The reverse index is cleared for each drained `tx_hash`; the
    /// `pending_routing` entry is left alone (the caller will typically
    /// feed the EC into `handle_wave_attestation`, which then calls
    /// `clear_routed` to drop the entry).
    pub fn drain_ecs_for_txs(&mut self, tx_hashes: &[TxHash]) -> Vec<Arc<ExecutionCertificate>> {
        let mut ecs: Vec<Arc<ExecutionCertificate>> = Vec::new();
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
    /// `ec.vote_anchor_ts + RETENTION_HORIZON`, BFT-attested by the
    /// remote committee — the same bound the sender uses on the outbound
    /// side. Past it, every tx the EC mentions has expired its
    /// `validity_range` and either terminated or aborted, so no local
    /// wave can still consume it. Returns the number of ECs evicted.
    pub fn gc_stale_ecs(&mut self, now_ts: WeightedTimestamp) -> usize {
        let stale: Vec<WaveId> = self
            .pending_routing
            .iter()
            .filter(|(_, entry)| entry.ec.deadline() <= now_ts)
            .map(|(wid, _)| wid.clone())
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
    pub fn attestation_count_for_tx(&self, tx_hash: &TxHash) -> usize {
        self.tx_index.get(tx_hash).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BlockHash, BlockHeight, ExecutionOutcome, GlobalReceiptHash, GlobalReceiptRoot, Hash,
        RETENTION_HORIZON, ShardGroupId, SignerBitfield, TxHash, TxOutcome, ValidatorId,
        bls_keypair_from_seed, exec_vote_message, zero_bls_signature,
    };
    use proptest::collection::vec as prop_vec;

    use super::*;

    fn shard() -> ShardGroupId {
        ShardGroupId::new(0)
    }

    fn wave(height: u64) -> WaveId {
        WaveId::new(shard(), BlockHeight::new(height), BTreeSet::new())
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

    fn make_ec(wave_id: WaveId, tx_hashes: &[TxHash]) -> Arc<ExecutionCertificate> {
        make_ec_with_anchor(wave_id, tx_hashes, WeightedTimestamp::ZERO)
    }

    fn make_ec_with_anchor(
        wave_id: WaveId,
        tx_hashes: &[TxHash],
        vote_anchor_ts: WeightedTimestamp,
    ) -> Arc<ExecutionCertificate> {
        let outcomes: Vec<TxOutcome> = tx_hashes.iter().map(|h| make_tx_outcome(*h)).collect();
        Arc::new(ExecutionCertificate::new(
            wave_id,
            vote_anchor_ts,
            GlobalReceiptRoot::ZERO,
            outcomes,
            zero_bls_signature(),
            SignerBitfield::new(4),
        ))
    }

    fn make_vote(wave_id: WaveId, anchor_ts: WeightedTimestamp) -> ExecutionVote {
        let tx_outcomes = vec![make_tx_outcome(TxHash::from_raw(Hash::from_bytes(b"tx")))];
        let global_receipt_root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let msg = exec_vote_message(
            anchor_ts,
            &wave_id,
            wave_id.shard_group_id(),
            &global_receipt_root,
            u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
        );
        let kp = bls_keypair_from_seed(&[7u8; 32]);
        let signature = kp.sign_v1(&msg);
        ExecutionVote {
            block_hash: BlockHash::ZERO,
            block_height: BlockHeight::new(1),
            vote_anchor_ts: anchor_ts,
            wave_id,
            shard_group_id: shard(),
            global_receipt_root,
            tx_count: u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
            tx_outcomes,
            validator: ValidatorId::new(0),
            signature,
        }
    }

    // ─── Votes ──────────────────────────────────────────────────────────

    #[test]
    fn drain_votes_returns_buffered_and_leaves_buffer_empty() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        b.buffer_vote(w.clone(), make_vote(w.clone(), ms(100)));
        b.buffer_vote(w.clone(), make_vote(w.clone(), ms(200)));

        let drained = b.drain_votes_for_wave(&w);
        assert_eq!(drained.len(), 2);
        assert_eq!(b.vote_len(), 0);

        // Idempotent: second drain returns empty.
        assert!(b.drain_votes_for_wave(&w).is_empty());
    }

    #[test]
    fn drain_votes_is_per_wave() {
        let mut b = EarlyArrivalBuffer::new();
        let w1 = wave(1);
        let w2 = wave(2);
        b.buffer_vote(w1.clone(), make_vote(w1.clone(), ms(100)));
        b.buffer_vote(w2.clone(), make_vote(w2, ms(100)));

        let drained = b.drain_votes_for_wave(&w1);
        assert_eq!(drained.len(), 1);
        assert_eq!(b.vote_len(), 1);
    }

    #[test]
    fn retain_votes_drops_entries_matching_predicate() {
        let mut b = EarlyArrivalBuffer::new();
        let w1 = wave(1);
        let w2 = wave(2);
        b.buffer_vote(w1.clone(), make_vote(w1.clone(), ms(100)));
        b.buffer_vote(w2.clone(), make_vote(w2.clone(), ms(100)));

        b.retain_votes(|wave_id, _| wave_id == &w1);

        assert_eq!(b.vote_len(), 1);
        assert_eq!(b.drain_votes_for_wave(&w1).len(), 1);
        assert!(b.drain_votes_for_wave(&w2).is_empty());
    }

    // ─── ECs ────────────────────────────────────────────────────────────

    #[test]
    fn buffer_ec_records_pending_set_and_reverse_index() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
        let ec = make_ec(w, &[tx_a, tx_b]);

        b.buffer_ec(&ec, &[tx_a, tx_b]);

        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(b.attestation_count_for_tx(&tx_a), 1);
        assert_eq!(b.attestation_count_for_tx(&tx_b), 1);
    }

    #[test]
    fn buffer_ec_idempotent_for_same_tx_hashes() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx = TxHash::from_raw(Hash::from_bytes(b"a"));
        let ec = make_ec(w, &[tx]);

        b.buffer_ec(&ec, &[tx]);
        b.buffer_ec(&ec, &[tx]);

        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(
            b.attestation_count_for_tx(&tx),
            1,
            "duplicate buffer must not stack Arcs in the reverse index"
        );
    }

    #[test]
    fn clear_routed_drops_entry_once_pending_set_drains() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
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
        let w = wave(1);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
        let ec = make_ec(w, &[tx_a, tx_b]);
        b.buffer_ec(&ec, &[tx_a, tx_b]);

        let drained = b.drain_ecs_for_txs(&[tx_a]);
        assert_eq!(drained.len(), 1);
        assert_eq!(b.attestation_count_for_tx(&tx_a), 0);
        // tx_b still indexed — this drain only targeted tx_a.
        assert_eq!(b.attestation_count_for_tx(&tx_b), 1);
    }

    #[test]
    fn drain_ecs_for_txs_dedups_arc_identity() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
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
        let w_old = wave(1);
        let w_fresh = wave(2);
        let tx_old = TxHash::from_raw(Hash::from_bytes(b"old"));
        let tx_fresh = TxHash::from_raw(Hash::from_bytes(b"fresh"));

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
        assert_eq!(b.attestation_count_for_tx(&tx_old), 0);
        assert_eq!(b.attestation_count_for_tx(&tx_fresh), 1);
    }

    #[test]
    fn gc_stale_ecs_preserves_entries_within_horizon() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let anchor = ms(100_000);
        b.buffer_ec(&make_ec_with_anchor(w, &[tx], anchor), &[tx]);

        // now_ts equal to the anchor — well inside the EC's deadline.
        assert_eq!(b.gc_stale_ecs(anchor), 0);
        assert_eq!(b.pending_routing_len(), 1);
    }

    // ─── Property tests ─────────────────────────────────────────────────

    use proptest::prelude::*;

    // drain_votes_for_wave is idempotent: draining returns all buffered
    // votes and a subsequent drain returns empty.
    proptest! {
        #[test]
        fn drain_votes_is_idempotent(
            heights in prop_vec(0u64..20, 1..20),
            anchors in prop_vec(0u64..10_000, 1..20),
        ) {
            let mut b = EarlyArrivalBuffer::new();
            for (i, h) in heights.iter().enumerate() {
                let w = wave(*h);
                let anchor = ms(anchors[i % anchors.len()]);
                b.buffer_vote(w.clone(), make_vote(w, anchor));
            }

            // Drain every wave once; collect counts. A second drain of each
            // must return zero.
            let wave_ids: Vec<WaveId> = heights.iter().map(|h| wave(*h)).collect();
            let mut first_counts = Vec::new();
            for w in &wave_ids {
                first_counts.push(b.drain_votes_for_wave(w).len());
            }
            for w in &wave_ids {
                prop_assert!(b.drain_votes_for_wave(w).is_empty());
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
                let w = wave(*h);
                let tx = TxHash::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap_or(u8::MAX); 32]));
                let anchor = ms(anchor_ms[i % anchor_ms.len()]);
                b.buffer_ec(&make_ec_with_anchor(w.clone(), &[tx], anchor), &[tx]);
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
