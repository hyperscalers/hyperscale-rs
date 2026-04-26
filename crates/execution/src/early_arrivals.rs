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
//! - [`EC_BUFFER_RETENTION`]: how long to hold ECs referencing `tx_hashes`
//!   that never land locally (orphaned txs or malicious remotes). Sized
//!   well above plausible cross-shard inclusion lag.

use hyperscale_types::{
    ExecutionCertificate, ExecutionVote, TxHash, WAVE_TIMEOUT, WaveId, WeightedTimestamp,
};
#[cfg(test)]
use hyperscale_types::{GlobalReceiptRoot, Hash};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// How long to retain unmatched early votes whose block never committed
/// locally. Past `WAVE_TIMEOUT` from the vote's `vote_anchor_ts`, the wave
/// the vote belonged to has aborted (success or all-abort), so the vote can
/// no longer contribute to a useful wave. Anchored on the committing QC's
/// `weighted_timestamp_ms` so the bound is BFT-authenticated.
pub const EARLY_VOTE_RETENTION: Duration = WAVE_TIMEOUT;

/// Maximum age before a buffered EC is considered stale and evicted. Bounds
/// the leak from ECs whose `tx_hashes` never land in a local block (orphaned
/// txs, malicious or buggy remotes referencing `tx_hashes` our shard will
/// never see). Sized at `WAVE_TIMEOUT * 2` — twice the cross-shard execution
/// window covers a slow remote committing locally well past its source
/// commit, while still bounding the leak.
const EC_BUFFER_RETENTION: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() * 2);

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
    /// Local weighted timestamp when this EC was first buffered. Used by
    /// [`EarlyArrivalBuffer::gc_stale_ecs`] to evict entries past the
    /// retention window.
    buffered_at: WeightedTimestamp,
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
    pub fn buffer_ec(
        &mut self,
        ec: &Arc<ExecutionCertificate>,
        tx_hashes: &[TxHash],
        now_ts: WeightedTimestamp,
    ) {
        if tx_hashes.is_empty() {
            return;
        }
        let entry = self
            .pending_routing
            .entry(ec.wave_id.clone())
            .or_insert_with(|| BufferedEc {
                ec: Arc::clone(ec),
                pending_txs: HashSet::new(),
                buffered_at: now_ts,
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

    /// Drop buffered ECs older than [`EC_BUFFER_RETENTION`]. Covers the
    /// leak from `tx_hashes` that never land locally (orphaned txs or
    /// malicious remotes referencing unknown txs). Returns the number of
    /// ECs evicted.
    ///
    /// No-op before the first commit (when `now_ts` is still below the
    /// retention window), so pre-first-commit buffered entries aren't
    /// wiped on the very first timeout check.
    pub fn gc_stale_ecs(&mut self, now_ts: WeightedTimestamp) -> usize {
        if now_ts.as_millis() < u64::try_from(EC_BUFFER_RETENTION.as_millis()).unwrap_or(u64::MAX) {
            return 0;
        }
        let cutoff = now_ts.minus(EC_BUFFER_RETENTION);
        let stale: Vec<WaveId> = self
            .pending_routing
            .iter()
            .filter(|(_, entry)| entry.buffered_at <= cutoff)
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

    /// Retro-stamp `buffered_at == ZERO` entries with `now_ts`.
    /// Remote ECs can arrive before our first local commit; without this,
    /// every such entry would report a ~57-year age on the next commit
    /// and be evicted immediately.
    pub fn retro_stamp_zero_timestamps(&mut self, now_ts: WeightedTimestamp) {
        for entry in self.pending_routing.values_mut() {
            if entry.buffered_at == WeightedTimestamp::ZERO {
                entry.buffered_at = now_ts;
            }
        }
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
    use super::*;
    use hyperscale_types::{
        BlockHash, BlockHeight, ExecutionOutcome, GlobalReceiptHash, ShardGroupId, SignerBitfield,
        TxHash, TxOutcome, ValidatorId, bls_keypair_from_seed, exec_vote_message,
        zero_bls_signature,
    };
    use std::collections::BTreeSet;

    fn shard() -> ShardGroupId {
        ShardGroupId(0)
    }

    fn wave(height: u64) -> WaveId {
        WaveId {
            shard_group_id: shard(),
            block_height: BlockHeight(height),
            remote_shards: BTreeSet::new(),
        }
    }

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp(value)
    }

    fn make_tx_outcome(tx: TxHash) -> TxOutcome {
        TxOutcome {
            tx_hash: tx,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }
    }

    fn make_ec(wave_id: WaveId, tx_hashes: &[TxHash]) -> Arc<ExecutionCertificate> {
        let outcomes: Vec<TxOutcome> = tx_hashes.iter().map(|h| make_tx_outcome(*h)).collect();
        Arc::new(ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
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
            wave_id.shard_group_id,
            &global_receipt_root,
            u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
        );
        let kp = bls_keypair_from_seed(&[7u8; 32]);
        let signature = kp.sign_v1(&msg);
        ExecutionVote {
            block_hash: BlockHash::ZERO,
            block_height: BlockHeight(1),
            vote_anchor_ts: anchor_ts,
            wave_id,
            shard_group_id: shard(),
            global_receipt_root,
            tx_count: u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX),
            tx_outcomes,
            validator: ValidatorId(0),
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

        b.buffer_ec(&ec, &[tx_a, tx_b], ms(1_000));

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

        b.buffer_ec(&ec, &[tx], ms(1_000));
        b.buffer_ec(&ec, &[tx], ms(2_000));

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

        b.buffer_ec(&ec, &[tx_a, tx_b], ms(1_000));

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
        b.buffer_ec(&ec, &[tx_a, tx_b], ms(1_000));

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
        b.buffer_ec(&ec, &[tx_a, tx_b], ms(1_000));

        let drained = b.drain_ecs_for_txs(&[tx_a, tx_b]);
        assert_eq!(drained.len(), 1, "identity-dedup on Arc pointer");
    }

    #[test]
    fn gc_stale_ecs_respects_retention_and_cleans_reverse_index() {
        let mut b = EarlyArrivalBuffer::new();
        let w_old = wave(1);
        let w_fresh = wave(2);
        let tx_old = TxHash::from_raw(Hash::from_bytes(b"old"));
        let tx_fresh = TxHash::from_raw(Hash::from_bytes(b"fresh"));

        b.buffer_ec(&make_ec(w_old, &[tx_old]), &[tx_old], ms(1_000));
        b.buffer_ec(&make_ec(w_fresh, &[tx_fresh]), &[tx_fresh], ms(50_000));

        // Retention = 60s. At now_ts = 65_000, cutoff = 5_000. The old
        // entry (buffered at 1_000) is evicted; the fresh one survives.
        let evicted = b.gc_stale_ecs(ms(65_000));
        assert_eq!(evicted, 1);
        assert_eq!(b.pending_routing_len(), 1);
        assert_eq!(b.attestation_count_for_tx(&tx_old), 0);
        assert_eq!(b.attestation_count_for_tx(&tx_fresh), 1);
    }

    #[test]
    fn gc_stale_ecs_noop_before_retention_window_reached() {
        let mut b = EarlyArrivalBuffer::new();
        let w = wave(1);
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        b.buffer_ec(&make_ec(w, &[tx]), &[tx], ms(0));

        // now_ts below EC_BUFFER_RETENTION → no-op, even though the entry
        // was buffered at timestamp 0.
        let just_under = u64::try_from(EC_BUFFER_RETENTION.as_millis()).unwrap_or(u64::MAX) - 1;
        assert_eq!(b.gc_stale_ecs(ms(just_under)), 0);
        assert_eq!(b.pending_routing_len(), 1);
    }

    #[test]
    fn retro_stamp_updates_zero_buffered_entries_only() {
        let mut b = EarlyArrivalBuffer::new();
        let w_zero = wave(1);
        let w_stamped = wave(2);
        let tx_z = TxHash::from_raw(Hash::from_bytes(b"z"));
        let tx_s = TxHash::from_raw(Hash::from_bytes(b"s"));
        b.buffer_ec(&make_ec(w_zero, &[tx_z]), &[tx_z], ms(0));
        b.buffer_ec(&make_ec(w_stamped, &[tx_s]), &[tx_s], ms(30_000));

        b.retro_stamp_zero_timestamps(ms(50_000));

        // After retro-stamp the "zero" entry now has buffered_at = 50_000.
        // At now_ts = 65_000 (cutoff = 5_000), only the stamped entry
        // (30_000 > 5_000) AND the retro-stamped entry (50_000 > 5_000)
        // both survive. The retro-stamped entry, had it NOT been updated,
        // would have been evicted.
        let evicted = b.gc_stale_ecs(ms(65_000));
        assert_eq!(evicted, 0);
        assert_eq!(b.pending_routing_len(), 2);
    }

    // ─── Property tests ─────────────────────────────────────────────────

    use proptest::prelude::*;

    // drain_votes_for_wave is idempotent: draining returns all buffered
    // votes and a subsequent drain returns empty.
    proptest! {
        #[test]
        fn drain_votes_is_idempotent(
            heights in proptest::collection::vec(0u64..20, 1..20),
            anchors in proptest::collection::vec(0u64..10_000, 1..20),
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

    // GC never drops an EC whose buffered_at is strictly greater than
    // the retention cutoff (now_ts - EC_BUFFER_RETENTION).
    proptest! {
        #[test]
        fn gc_preserves_fresh_entries(
            heights in proptest::collection::vec(0u64..20, 1..10),
            ages_ms in proptest::collection::vec(0u64..120_000, 1..10),
            now_ms in 60_000u64..600_000,
        ) {
            let mut b = EarlyArrivalBuffer::new();
            for (i, h) in heights.iter().enumerate() {
                let w = wave(*h);
                let tx = TxHash::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap_or(u8::MAX); 32]));
                let age = ages_ms[i % ages_ms.len()];
                let ts = if age >= now_ms { ms(0) } else { ms(now_ms - age) };
                b.buffer_ec(&make_ec(w.clone(), &[tx]), &[tx], ts);
            }
            let before = b.pending_routing_len();

            b.gc_stale_ecs(ms(now_ms));

            // Every surviving entry must be strictly newer than the cutoff.
            let cutoff = ms(now_ms).minus(EC_BUFFER_RETENTION);
            for entry in b.pending_routing.values() {
                prop_assert!(
                    entry.buffered_at > cutoff,
                    "GC left a stale entry: buffered_at={:?}, cutoff={:?}",
                    entry.buffered_at,
                    cutoff
                );
            }
            // Invariant: we never GAIN entries from a GC call.
            prop_assert!(b.pending_routing_len() <= before);
        }
    }
}
