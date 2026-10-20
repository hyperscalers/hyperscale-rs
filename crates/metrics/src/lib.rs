//! Metrics facade for Hyperscale.
//!
//! Provides a [`MetricsRecorder`] trait with domain-specific methods and default
//! no-op implementations. A global singleton recorder is accessed via [`recorder()`],
//! and convenience free functions delegate to it.
//!
//! # Usage
//!
//! Callers record metrics via free functions:
//! ```ignore
//! hyperscale_metrics::record_storage_read(latency_secs);
//! hyperscale_metrics::record_block_committed(shard, latency_secs, "qc");
//! ```
//!
//! At startup, install a backend:
//! ```ignore
//! // Production:
//! hyperscale_metrics_prometheus::install();
//!
//! // Simulation (optional — defaults to no-op):
//! hyperscale_metrics_noop::install();
//! ```

use std::cell::RefCell;
use std::sync::{Arc, OnceLock};

// ═══════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════

/// Which coordinator a memory readout belongs to. One gauge family per
/// variant; the readout's own name is the label within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryFamily {
    /// Shard consensus coordinator.
    Shard,
    /// Execution coordinator.
    Execution,
    /// Mempool coordinator.
    Mempool,
    /// Remote-header coordinator.
    RemoteHeaders,
    /// Provision coordinator.
    Provisions,
}

// ═══════════════════════════════════════════════════════════════════════
// Trait
// ═══════════════════════════════════════════════════════════════════════

/// Domain-specific metrics recording trait.
///
/// All methods have default no-op implementations so backends only need
/// to override the metrics they care about.
#[allow(unused_variables)]
pub trait MetricsRecorder: Send + Sync + 'static {
    // ── Storage ──────────────────────────────────────────────────────

    /// Record a storage read latency.
    fn record_storage_read(&self, latency_secs: f64) {}

    /// Record a storage write latency.
    fn record_storage_write(&self, latency_secs: f64) {}

    /// Record a named storage operation latency.
    fn record_storage_operation(&self, operation: &str, latency_secs: f64) {}

    /// Record the number of writes in a block's atomic commit batch.
    fn record_storage_batch_size(&self, size: usize) {}

    /// Record a committed block the store wrote. A block the store
    /// already holds, handed to it again, is not counted.
    fn record_block_persisted(&self) {}

    /// Record a commit whose `BlockCommitted` waits for persistence to
    /// catch up.
    fn record_block_commit_deferred(&self) {}

    /// Record the finalizations a persisted block carries.
    fn record_certificates_persisted(&self, count: usize) {}

    /// Record the transactions a persisted block carries.
    fn record_transactions_persisted(&self, count: usize) {}

    // ── Consensus ────────────────────────────────────────────────────

    /// Record a block committed on `shard`.
    fn record_block_committed(&self, shard: u64, commit_latency_secs: f64, source: &str) {}

    /// Record a transaction finalized.
    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {}

    /// Record one engine execution of a transaction. Together with
    /// [`Self::record_transaction_finalized`] this yields executions per
    /// terminal transaction — the replicated-execution factor.
    fn record_transaction_executed(&self) {}

    /// Set the current block height gauge for a shard.
    fn set_block_height(&self, shard: u64, height: u64) {}

    /// Set the current shard round gauge for one hosted vnode.
    fn set_shard_round(&self, shard: u64, validator_id: u64, round: u64) {}

    /// Set the view changes gauge (self-originated round advances) for one vnode.
    fn set_view_changes(&self, shard: u64, validator_id: u64, count: u64) {}

    /// Set the view syncs gauge (rounds caught up to from peers) for one vnode.
    fn set_view_syncs(&self, shard: u64, validator_id: u64, count: u64) {}

    /// Set the mempool size gauge for one vnode.
    fn set_mempool_size(&self, shard: u64, validator_id: u64, size: usize) {}

    /// Set the drain the committed tip records for one vnode, in the
    /// units `MAX_UNSETTLED_TXS` bounds.
    fn set_in_flight(&self, shard: u64, validator_id: u64, drain: u64) {}

    /// Set whether one vnode's drain has reached its budget, which stops
    /// both RPC admission and the proposer taking new transactions.
    fn set_backpressure_active(&self, shard: u64, validator_id: u64, active: bool) {}

    // ── Infrastructure ───────────────────────────────────────────────

    /// Set thread pool queue depths.
    fn set_pool_queue_depths(&self, consensus: usize, throughput: usize) {}

    /// Record a completed pool task with its duration.
    ///
    /// The histogram's `_count` gives throughput (tasks/sec via `rate()`),
    /// and `_sum / threads` gives utilization per pool.
    fn record_pool_task_completed(&self, pool: &str, latency_secs: f64) {}

    /// Set the depths of one shard loop's callback and timer channels.
    fn set_shard_channel_depths(&self, shard: u64, callback: usize, timer: usize) {}

    /// Record execution latency.
    fn record_execution_latency(&self, latency_secs: f64) {}

    /// Record signature verification latency by type.
    fn record_signature_verification_latency(&self, sig_type: &str, latency_secs: f64) {}

    /// Record a signature verification that failed, by the same type
    /// [`Self::record_signature_verification_latency`] times it under.
    fn record_signature_verification_failure(&self, sig_type: &str) {}

    // ── Network ──────────────────────────────────────────────────────

    /// Record a network message sent.
    fn record_network_message_sent(&self) {}

    /// Record a network message received.
    fn record_network_message_received(&self) {}

    /// Set the libp2p peer count gauge.
    fn set_libp2p_peers(&self, count: usize) {}

    /// Record libp2p bandwidth.
    fn record_libp2p_bandwidth(&self, bytes_in: u64, bytes_out: u64) {}

    /// Record a gossipsub publish failure.
    fn record_gossipsub_publish_failure(&self, topic: &str) {}

    /// Record a network request retry.
    fn record_request_retry(&self, request_type: &str) {}

    /// Increment dispatch failure counter.
    fn increment_dispatch_failures(&self, message_type: &str) {}

    /// Record a backpressure event.
    fn record_backpressure_event(&self, source: &str) {}

    /// Record an execution vote for a tick not yet committed that the
    /// early-arrival buffer refused, being at capacity. Its sender's
    /// retry is what brings it back.
    fn record_early_vote_refused(&self) {}

    /// Record a committed transaction this shard can no longer produce an
    /// outcome for, which the chain ends by a fate and no certificate.
    /// `cause` says whether a committed boundary record had covered it — a
    /// chain that ran out of room to get the abort committed — or whether
    /// none ever did, which is a counterpart that settled the transaction
    /// before it left, or evidence that never arrived.
    fn record_unresolvable_tx(&self, cause: &str) {}

    /// Record an entry rebuilt from a committed boundary record, the
    /// ledger having held nothing for the transaction it named.
    ///
    /// Read it across the replicas of one shard rather than on its own: a
    /// replica counting these where its peers count none is one whose
    /// rebuild did not reach the transaction's own block, and the record
    /// is what puts it back in step with them.
    fn record_rebuilt_record_entry(&self) {}

    /// Record a dispatched tick this node could not run, for want of a
    /// package's code.
    ///
    /// The shard's execution stops at that tick until the code lands, so
    /// any rate here is a stalled replica. One replica counting these
    /// where its peers count none is one whose acquisition has fallen
    /// behind; every replica counting them is code nobody can serve.
    fn record_batch_unavailable(&self) {}

    /// Record a core member's sibling whose committed cell a committed
    /// proof read absent inside its window, the fold every replica of a
    /// shard reaches at the same height. Each one covers the member's
    /// entry and licenses its abandonment.
    fn record_sibling_absence_read(&self) {}

    /// Record the escrowed records a committed block took back on their
    /// consumers' `Never`, crediting each where its return lands.
    fn record_reclaim_folded(&self, records: usize) {
        let _ = records;
    }

    /// Record the escrowed records a committed block declined for its
    /// consumers here, writing the `Never` each is taken back on.
    fn record_decline_folded(&self, records: usize) {
        let _ = records;
    }

    /// Record a sibling's committed cell this validator's own fetch read
    /// as answering nothing: the cell present, so the sibling included
    /// the transaction, or a reading for a member already answered for.
    /// A member still waiting puts its question again at a newer header.
    fn record_sibling_question_pending(&self) {}

    /// Pending core members a proposed block leaves out behind the holds
    /// of a core member awaiting a shard they await too, one per pair:
    /// summed over blocks, how long such pairs stand.
    fn record_hold_contentions(&self, pairs: usize) {}

    /// Pending core members a proposed block aborts as the proven victims
    /// of a hold cycle.
    fn record_hold_inversions_proven(&self, victims: usize) {}

    /// Stated or accepted rows a terminal's manifest fated or ended, one
    /// count per row at each derivation of that manifest: the proposer's,
    /// each voter's and each re-proposal's, so a nonzero total scales with
    /// the committee. Any count is a cut the quiet gate should have held.
    fn record_terminal_fated_hearing_rows(&self, rows: usize) {}

    /// The bytes a committed block's state claims weigh between them,
    /// proofs included, by kind: every claim but the verdict claims
    /// (`bytes`), against their budget, and the verdict claims
    /// (`verdict_bytes`), which spend what those leave of the section's.
    fn record_state_claims_weight(&self, bytes: usize, verdict_bytes: usize) {}

    /// What a committed block's claims carry that one of the
    /// committed blocks just below it carried too, by kind: cells read
    /// at one anchor by claims that delete and return nothing, record
    /// keys read absent, `Never` keys read present, and crossings read
    /// at the parent.
    fn record_claims_recarried(
        &self,
        cells: usize,
        deletions: usize,
        returns: usize,
        local: usize,
    ) {
    }

    /// The verdict cells of one committed block: the cells of the claims
    /// that name a member (`named`), the ones of those its hear step
    /// read for a hearing row (`carried`), and the ones of those in a
    /// reading that changed a row's entry (`changed`). What was named
    /// and not carried reached no row that hears; what was carried and
    /// changed nothing was a copy, since every proposer between a
    /// reading's first carry and its commit offers its own.
    fn record_verdict_cells(&self, named: usize, carried: usize, changed: usize) {}

    /// The bytes those cells weigh in the block's claims, proofs
    /// included, in the same three counts.
    fn record_verdict_claims_weight(&self, named: usize, carried: usize, changed: usize) {}

    /// Members a committed block's finalizations settled whose verdict a
    /// counterpart shares: what the verdict figures are read per.
    fn record_core_members_settled(&self, members: usize) {}

    /// The crossing answers standing under `shard`'s prefix at a commit,
    /// and the bytes their leaves hold, key and value. An answer stands
    /// from its writing to the first boundary of its record's shard that
    /// shows the record gone and its producing member exited.
    fn set_standing_answers(&self, shard: u64, answers: usize, bytes: usize) {
        let _ = (shard, answers, bytes);
    }

    /// The boundary claims of one committed block: the bytes they weigh,
    /// proofs included, and the answer deletions they read.
    fn record_boundary_claims_carried(&self, bytes: usize, deletions: usize) {
        let _ = (bytes, deletions);
    }

    /// Cells a validator asked at a boundary the beacon recorded, for
    /// the answers it could delete there.
    fn record_boundary_cells_asked(&self, cells: usize) {
        let _ = cells;
    }

    /// The span, on the committed clock, from a validator's ask at a
    /// boundary to the commit at which it holds no deletion read there:
    /// every one carried by a block, or let go.
    fn record_boundary_drained(&self, millis: u64) {
        let _ = millis;
    }

    /// The blocks between a row's stating and the first commit at which
    /// it holds a reading of every sibling it awaits.
    fn record_blocks_from_stated_to_heard(&self, blocks: u64) {}

    /// The accepted rows standing toward the sibling most of them await,
    /// at one commit: what the rows waiting for an end line hold of the
    /// cap on rows toward one shard.
    fn record_accepted_rows_toward_a_sibling(&self, rows: usize) {}

    /// What a consumer chain stands holding toward one lineage of its
    /// trie (`lineage`), or toward all of them (`"total"`), at a commit:
    /// its answers and the crossings its rows owe, which the cap holds.
    fn set_standing_answers_by_lineage(&self, lineage: &str, standing: u64) {}

    /// What a proposal left out to stay within the cap on its chain's
    /// standing answers, by what it was: `"arrival"` for a record a
    /// claim would have answered, `"transaction"` for one owing
    /// crossings.
    fn record_intake_capped(&self, what: &str, count: u64) {}

    /// A consumer asking a producer's chain for a crossing record it
    /// waits on: the fallback read a push did not make unnecessary.
    fn record_record_ask(&self) {}

    /// A crossing question asked past its transaction's deadline, where
    /// a push did not answer it, by who asks: the record's producer
    /// (`"producer"`), of its consumer's answers.
    fn record_crossing_fallback_ask(&self, asker: &str) {
        let _ = asker;
    }

    /// A claim the commit fold acts on by its anchor: one carrying a
    /// record presence (`"record"`), either carried by a committed block
    /// or dropped from what a validator held to offer because the block
    /// raised its producer's read frontier above it, or a boundary claim
    /// carrying a deleting absence (`"removed"`), which a block carries
    /// and no frontier refuses.
    fn record_fenced_claim(&self, reading: &str, carried: bool) {
        let _ = (reading, carried);
    }

    /// A leader proposed at once rather than holding an empty block, by
    /// the condition that held it to network speed.
    fn record_eager_proposal(&self, reason: &str) {}

    /// A pushed crossing reading dropped on the consumer's side, by the
    /// check that dropped it: at ingress, at the anchor, or at the
    /// park. Each drop is one the fallback read has to make up.
    fn record_crossing_push_dropped(&self, reason: &str) {}

    /// A fetch response the requester's own check refused, by fetch kind
    /// and the check that refused it.
    ///
    /// Every evidence seam is a payload held against something the
    /// checker already has, and the refusal is the only place the check
    /// is observable: what the caller sees afterwards is the value
    /// arriving from an honest peer instead, which an unattacked run
    /// produces too. A rate above zero here is a responder answering
    /// wrongly.
    fn record_fetch_response_refused(&self, kind: &str, reason: &str) {}

    /// Set the in-flight request slot count for a `MessageClass`.
    ///
    /// Sampled by the request manager whenever a slot is acquired or
    /// released. The total across classes equals the global `in_flight`.
    fn set_request_slots_in_flight(&self, class: &str, count: usize) {}

    /// Record how long a request waited inside the `acquire_slot` CAS loop
    /// before admission. P99 spikes on a sheddable class mean the subset
    /// cap is biting; spikes on hot classes mean the global pool is
    /// saturated.
    fn record_request_slot_wait(&self, class: &str, wait_secs: f64) {}

    /// Record a gossipsub validation outcome (`accept` / `reject` /
    /// `ignore`). Reject spikes mean peers are sending invalid data;
    /// `ignore` spikes typically mean handler panics or unregistered
    /// topics.
    fn record_gossipsub_validation(&self, outcome: &str) {}

    /// Set the inbound serving stream count for a protocol
    /// (`request` / `notify`). Approaching `MAX_INBOUND_CONCURRENT`
    /// means new inbound streams are about to be rejected.
    fn set_inbound_streams_in_use(&self, protocol: &str, count: usize) {}

    // ── Sync ─────────────────────────────────────────────────────────
    //
    // Two scopes share these metrics: `kind="block"` for block-sync and
    // `kind="remote_header"` for remote-header sync. Both run as
    // `Sync<Binding>` FSMs that fetch *ranges* of contiguous heights, not
    // individual ids — keep their counters separate from the per-id Fetch
    // family below so dashboards aren't comparing range-rate to id-rate
    // under one chart.

    /// Set the per-scope `blocks_behind` gauge.
    fn set_sync_blocks_behind(&self, kind: &str, shard: u64, blocks_behind: u64) {}

    /// Set the per-scope `in_progress` gauge (0/1).
    fn set_sync_in_progress(&self, kind: &str, shard: u64, in_progress: bool) {}

    /// Record a sync response that was filtered out before delivery
    /// (height mismatch, QC mismatch, certificate-root mismatch, etc.).
    fn record_sync_block_filtered(&self, kind: &str, reason: &str) {}

    /// Record a sync response error (rehydration miss, `fetch_failed`, etc.).
    fn record_sync_response_error(&self, kind: &str, error_type: &str) {}

    /// Record a sync range round-trip started (network request emitted).
    fn record_sync_round_started(&self, kind: &str) {}

    /// Record a retained ex-member's tip offer refused by a halt
    /// recovery's fresh committee because the fresh chain had already
    /// certified past the anchor.
    fn record_halt_recovery_offer_refused(&self) {}

    /// Record a sync range round-trip that completed successfully.
    fn record_sync_round_completed(&self, kind: &str) {}

    /// Record a sync range round-trip released for retry. Increments per
    /// release-for-retry, not per unrecoverable failure.
    fn record_sync_round_retried(&self, kind: &str) {}

    /// Set the per-scope in-flight range gauge.
    fn set_sync_round_in_flight(&self, kind: &str, shard: u64, count: usize) {}

    // ── Fetch ────────────────────────────────────────────────────────
    //
    // Per-`kind` counters and gauge for outbound per-id fetches. Always
    // counted in *ids*. Range round-trips driven by sync FSMs use the
    // `sync_round_*` family above, not these.

    /// Record a fetch operation started.
    fn record_fetch_started(&self, kind: &str) {}

    /// Record a fetch operation completed — payload landed via fetch response,
    /// gossip, or local production and drained the pending entry.
    fn record_fetch_completed(&self, kind: &str) {}

    /// Record a fetch operation cancelled by an explicit `Action::AbandonFetch`
    /// — the originating coordinator gave up on the id without it ever being
    /// admitted. Distinct from `record_fetch_completed` so the two populations
    /// can be tracked separately in observability.
    fn record_fetch_abandoned(&self, kind: &str) {}

    /// Record a fetch operation released for retry. Increments per release-
    /// for-retry, not per unrecoverable failure — the retry budget is owned
    /// by the network layer, so this is genuinely a retry counter.
    fn record_fetch_retried(&self, kind: &str) {}

    /// Record how long an admitted fetch waited from its latest dispatch.
    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {}

    /// Set the fetch in-flight gauge (per kind).
    fn set_fetch_in_flight(&self, kind: &str, shard: u64, count: usize) {}

    /// Set the age (in ms) of the longest-running in-flight fetch entry
    /// (per kind, per shard). Zero when nothing is in flight.
    fn set_fetch_oldest_in_flight_age_ms(&self, kind: &str, shard: u64, age_ms: u64) {}

    /// Record items sent in response to a fetch request.
    fn record_fetch_response_sent(&self, kind: &str, count: usize) {}

    // ── Transaction Ingress ──────────────────────────────────────────

    /// Record a transaction rejected because node is syncing.
    fn record_tx_ingress_rejected_syncing(&self) {}

    /// Record a transaction rejected because pending count is too high.
    fn record_tx_ingress_rejected_pending_limit(&self) {}

    /// Record a transaction rejected with reason.
    fn record_transaction_rejected(&self, reason: &str) {}

    /// Record an invalid message received.
    fn record_invalid_message(&self) {}

    // ── Livelock ─────────────────────────────────────────────────────

    /// Record a cross-shard transaction abort (timeout or conflict).
    fn record_transaction_aborted(&self) {}

    /// Record an expected cross-shard tx dropped past `RETENTION_HORIZON`
    /// without arriving via gossip, submit, fetch, or block inclusion. A
    /// non-zero rate here means cross-shard data availability has failed for
    /// some payload (bug, attack, or partition past every other timeout).
    fn record_expected_tx_dropped(&self) {}

    // ── Memory ────────────────────────────────────────────────────────

    /// Set one collection-size readout for a coordinator on one vnode.
    /// `family` names the coordinator ("shard", "exec", …), `field` the
    /// readout within it.
    fn set_vnode_memory_gauge(
        &self,
        family: MemoryFamily,
        field: &str,
        shard: u64,
        validator_id: u64,
        value: usize,
    ) {
    }

    /// Set one collection-size readout for shard-scoped runner state,
    /// which no single vnode owns.
    fn set_shard_memory_gauge(&self, field: &str, shard: u64, value: usize) {}
}

// ═══════════════════════════════════════════════════════════════════════
// Global singleton
// ═══════════════════════════════════════════════════════════════════════

struct NoopRecorder;
impl MetricsRecorder for NoopRecorder {}

static RECORDER: OnceLock<Box<dyn MetricsRecorder>> = OnceLock::new();
static NOOP: NoopRecorder = NoopRecorder;

thread_local! {
    static SCOPED_RECORDER: RefCell<Option<Arc<dyn MetricsRecorder>>> =
        const { RefCell::new(None) };
}

/// Install a global metrics recorder.
///
/// Can only be called once. Subsequent calls are silently ignored.
pub fn set_global_recorder(recorder: Box<dyn MetricsRecorder>) {
    let _ = RECORDER.set(recorder);
}

/// Run `f` with `recorder` installed as the thread-local metrics recorder.
///
/// All emissions on this thread for the duration of `f` route to `recorder`
/// instead of the global. Used in tests so concurrent simulations (cargo
/// runs each test on its own thread) don't share counters. Thread-local
/// scoping does not propagate across `spawn_blocking` / rayon workers.
pub fn with_scoped_recorder<R>(recorder: Arc<dyn MetricsRecorder>, f: impl FnOnce() -> R) -> R {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            SCOPED_RECORDER.with(|cell| cell.borrow_mut().take());
        }
    }
    SCOPED_RECORDER.with(|cell| *cell.borrow_mut() = Some(recorder));
    let _guard = Guard;
    f()
}

/// Handle to the active metrics recorder. Holds either a thread-local `Arc`
/// (when a scoped recorder is installed) or a static reference to the global.
enum RecorderHandle {
    Scoped(Arc<dyn MetricsRecorder>),
    Static(&'static dyn MetricsRecorder),
}

impl std::ops::Deref for RecorderHandle {
    type Target = dyn MetricsRecorder;
    #[inline]
    fn deref(&self) -> &(dyn MetricsRecorder + 'static) {
        match self {
            Self::Scoped(arc) => &**arc,
            Self::Static(r) => *r,
        }
    }
}

/// Get the active metrics recorder.
///
/// Prefers the thread-local scoped recorder if set; otherwise falls back to
/// the global recorder, or a no-op if none has been installed.
#[inline]
fn recorder() -> RecorderHandle {
    if let Some(scoped) = SCOPED_RECORDER.with(|cell| cell.borrow().clone()) {
        return RecorderHandle::Scoped(scoped);
    }
    RecorderHandle::Static(
        RECORDER
            .get()
            .map_or(&NOOP as &dyn MetricsRecorder, AsRef::as_ref),
    )
}

// ═══════════════════════════════════════════════════════════════════════
// Convenience free functions
// ═══════════════════════════════════════════════════════════════════════

// ── Storage ──────────────────────────────────────────────────────────

/// Record a storage read latency.
#[inline]
pub fn record_storage_read(latency_secs: f64) {
    recorder().record_storage_read(latency_secs);
}

/// Record a storage write latency.
#[inline]
pub fn record_storage_write(latency_secs: f64) {
    recorder().record_storage_write(latency_secs);
}

/// Record a named storage operation latency.
#[inline]
pub fn record_storage_operation(operation: &str, latency_secs: f64) {
    recorder().record_storage_operation(operation, latency_secs);
}

/// Record the number of writes in a block's atomic commit batch.
#[inline]
pub fn record_storage_batch_size(size: usize) {
    recorder().record_storage_batch_size(size);
}

/// Record a committed block the store wrote.
#[inline]
pub fn record_block_persisted() {
    recorder().record_block_persisted();
}

/// Record a commit whose `BlockCommitted` waits for persistence to catch
/// up.
#[inline]
pub fn record_block_commit_deferred() {
    recorder().record_block_commit_deferred();
}

/// Record the finalizations a persisted block carries.
#[inline]
pub fn record_certificates_persisted(count: usize) {
    recorder().record_certificates_persisted(count);
}

/// Record the transactions a persisted block carries.
#[inline]
pub fn record_transactions_persisted(count: usize) {
    recorder().record_transactions_persisted(count);
}

// ── Consensus ────────────────────────────────────────────────────────

/// Record a block committed on `shard`.
#[inline]
pub fn record_block_committed(shard: u64, commit_latency_secs: f64, source: &str) {
    recorder().record_block_committed(shard, commit_latency_secs, source);
}

/// Record a transaction finalized.
#[inline]
pub fn record_transaction_finalized(latency_secs: f64, cross_shard: bool) {
    recorder().record_transaction_finalized(latency_secs, cross_shard);
}

/// Record one engine execution of a transaction.
#[inline]
pub fn record_transaction_executed() {
    recorder().record_transaction_executed();
}

/// Set the current block height gauge for a shard.
#[inline]
pub fn set_block_height(shard: u64, height: u64) {
    recorder().set_block_height(shard, height);
}

/// Set the current shard round gauge for one hosted vnode.
#[inline]
pub fn set_shard_round(shard: u64, validator_id: u64, round: u64) {
    recorder().set_shard_round(shard, validator_id, round);
}

/// Set the view changes gauge for one hosted vnode.
#[inline]
pub fn set_view_changes(shard: u64, validator_id: u64, count: u64) {
    recorder().set_view_changes(shard, validator_id, count);
}

/// Set the view syncs gauge for one hosted vnode.
#[inline]
pub fn set_view_syncs(shard: u64, validator_id: u64, count: u64) {
    recorder().set_view_syncs(shard, validator_id, count);
}

/// Set the mempool size gauge for one hosted vnode.
#[inline]
pub fn set_mempool_size(shard: u64, validator_id: u64, size: usize) {
    recorder().set_mempool_size(shard, validator_id, size);
}

/// Set the drain the committed tip records for one hosted vnode.
#[inline]
pub fn set_in_flight(shard: u64, validator_id: u64, drain: u64) {
    recorder().set_in_flight(shard, validator_id, drain);
}

/// Set whether one hosted vnode's drain has reached its budget.
#[inline]
pub fn set_backpressure_active(shard: u64, validator_id: u64, active: bool) {
    recorder().set_backpressure_active(shard, validator_id, active);
}

// ── Infrastructure ───────────────────────────────────────────────────

/// Set thread pool queue depths.
#[inline]
pub fn set_pool_queue_depths(consensus: usize, throughput: usize) {
    recorder().set_pool_queue_depths(consensus, throughput);
}

/// Record a completed pool task with its duration.
#[inline]
pub fn record_pool_task_completed(pool: &str, latency_secs: f64) {
    recorder().record_pool_task_completed(pool, latency_secs);
}

/// Set the depths of one shard loop's callback and timer channels.
#[inline]
pub fn set_shard_channel_depths(shard: u64, callback: usize, timer: usize) {
    recorder().set_shard_channel_depths(shard, callback, timer);
}

/// Record execution latency.
#[inline]
pub fn record_execution_latency(latency_secs: f64) {
    recorder().record_execution_latency(latency_secs);
}

/// Record signature verification latency by type.
#[inline]
pub fn record_signature_verification_latency(sig_type: &str, latency_secs: f64) {
    recorder().record_signature_verification_latency(sig_type, latency_secs);
}

/// Record a failed signature verification by type.
#[inline]
pub fn record_signature_verification_failure(sig_type: &str) {
    recorder().record_signature_verification_failure(sig_type);
}

// ── Network ──────────────────────────────────────────────────────────

/// Record a network message sent.
#[inline]
pub fn record_network_message_sent() {
    recorder().record_network_message_sent();
}

/// Record a network message received.
#[inline]
pub fn record_network_message_received() {
    recorder().record_network_message_received();
}

/// Set the libp2p peer count gauge.
#[inline]
pub fn set_libp2p_peers(count: usize) {
    recorder().set_libp2p_peers(count);
}

/// Record libp2p bandwidth.
#[inline]
pub fn record_libp2p_bandwidth(bytes_in: u64, bytes_out: u64) {
    recorder().record_libp2p_bandwidth(bytes_in, bytes_out);
}

/// Record a gossipsub publish failure.
#[inline]
pub fn record_gossipsub_publish_failure(topic: &str) {
    recorder().record_gossipsub_publish_failure(topic);
}

/// Record a network request retry.
#[inline]
pub fn record_request_retry(request_type: &str) {
    recorder().record_request_retry(request_type);
}

/// Increment dispatch failure counter.
#[inline]
pub fn increment_dispatch_failures(message_type: &str) {
    recorder().increment_dispatch_failures(message_type);
}

/// Record a backpressure event.
#[inline]
pub fn record_backpressure_event(source: &str) {
    recorder().record_backpressure_event(source);
}

/// Record an early execution vote the buffer refused at capacity.
#[inline]
pub fn record_early_vote_refused() {
    recorder().record_early_vote_refused();
}

/// Record a committed transaction whose outcome this shard can no longer
/// produce, which the chain ends by a fate.
#[inline]
pub fn record_unresolvable_tx(cause: &str) {
    recorder().record_unresolvable_tx(cause);
}

/// Record an entry rebuilt from a committed boundary record.
#[inline]
pub fn record_rebuilt_record_entry() {
    recorder().record_rebuilt_record_entry();
}

/// Record a dispatched tick this node could not run for want of code.
#[inline]
pub fn record_batch_unavailable() {
    recorder().record_batch_unavailable();
}

/// Record a sibling's committed cell a committed proof read absent.
#[inline]
pub fn record_sibling_absence_read() {
    recorder().record_sibling_absence_read();
}

/// Record the escrowed records a committed block took back.
#[inline]
pub fn record_reclaim_folded(records: usize) {
    recorder().record_reclaim_folded(records);
}

/// Record the escrowed records a committed block declined.
#[inline]
pub fn record_decline_folded(records: usize) {
    recorder().record_decline_folded(records);
}

/// Record a sibling's committed cell a fetch read as answering nothing yet.
#[inline]
pub fn record_sibling_question_pending() {
    recorder().record_sibling_question_pending();
}

/// Record the hold contentions a proposed block leaves standing.
#[inline]
pub fn record_hold_contentions(pairs: usize) {
    recorder().record_hold_contentions(pairs);
}

/// Record the hold cycle victims a proposed block aborts.
#[inline]
pub fn record_hold_inversions_proven(victims: usize) {
    recorder().record_hold_inversions_proven(victims);
}

/// Record the hearing rows one derivation of a terminal's manifest named.
#[inline]
pub fn record_terminal_fated_hearing_rows(rows: usize) {
    recorder().record_terminal_fated_hearing_rows(rows);
}

/// Record the bytes a committed block's state claims weigh: its
/// verdict claims, and every other claim.
#[inline]
pub fn record_state_claims_weight(bytes: usize, verdict_bytes: usize) {
    recorder().record_state_claims_weight(bytes, verdict_bytes);
}

/// Record what a committed block's claims carry that a committed block
/// just below it carried too.
#[inline]
pub fn record_claims_recarried(cells: usize, deletions: usize, returns: usize, local: usize) {
    recorder().record_claims_recarried(cells, deletions, returns, local);
}

/// Record the verdict cells a committed block's rows heard.
#[inline]
pub fn record_verdict_cells(named: usize, carried: usize, changed: usize) {
    recorder().record_verdict_cells(named, carried, changed);
}

/// Record the bytes a committed block's heard verdict cells weigh.
#[inline]
pub fn record_verdict_claims_weight(named: usize, carried: usize, changed: usize) {
    recorder().record_verdict_claims_weight(named, carried, changed);
}

/// Set the crossing answers standing under a shard's prefix.
#[inline]
pub fn set_standing_answers(shard: u64, answers: usize, bytes: usize) {
    recorder().set_standing_answers(shard, answers, bytes);
}

/// Record the boundary claims a committed block carried.
#[inline]
pub fn record_boundary_claims_carried(bytes: usize, deletions: usize) {
    recorder().record_boundary_claims_carried(bytes, deletions);
}

/// Record cells asked at a boundary the beacon recorded.
#[inline]
pub fn record_boundary_cells_asked(cells: usize) {
    recorder().record_boundary_cells_asked(cells);
}

/// Record the span from an ask at a boundary to its last deletion gone.
#[inline]
pub fn record_boundary_drained(millis: u64) {
    recorder().record_boundary_drained(millis);
}

/// Record the core members a committed block settled.
#[inline]
pub fn record_core_members_settled(members: usize) {
    recorder().record_core_members_settled(members);
}

/// Record the blocks a row took from stated to heard.
#[inline]
pub fn record_blocks_from_stated_to_heard(blocks: u64) {
    recorder().record_blocks_from_stated_to_heard(blocks);
}

/// Record the accepted rows standing toward the most awaited sibling.
#[inline]
pub fn record_accepted_rows_toward_a_sibling(rows: usize) {
    recorder().record_accepted_rows_toward_a_sibling(rows);
}

/// Record what a consumer chain stands holding toward a lineage.
#[inline]
pub fn set_standing_answers_by_lineage(lineage: &str, standing: u64) {
    recorder().set_standing_answers_by_lineage(lineage, standing);
}

/// Record what a proposal left out to stay within the answer cap.
#[inline]
pub fn record_intake_capped(what: &str, count: u64) {
    if count != 0 {
        recorder().record_intake_capped(what, count);
    }
}

/// Record a consumer's ask for a crossing record.
#[inline]
pub fn record_record_ask() {
    recorder().record_record_ask();
}

/// Record a crossing question asked past its deadline, by `asker`.
#[inline]
pub fn record_crossing_fallback_ask(asker: &str) {
    recorder().record_crossing_fallback_ask(asker);
}

/// Record a fenced claim carried by a block or refused by the read
/// frontier, by what it read.
#[inline]
pub fn record_fenced_claim(reading: &str, carried: bool) {
    recorder().record_fenced_claim(reading, carried);
}

/// Record a proposal a leader made at once, by the condition that forced it.
#[inline]
pub fn record_eager_proposal(reason: &str) {
    recorder().record_eager_proposal(reason);
}

/// Record a pushed crossing reading dropped by the consumer, by reason.
#[inline]
pub fn record_crossing_push_dropped(reason: &str) {
    recorder().record_crossing_push_dropped(reason);
}

/// Record a fetch response refused by the requester's own check.
#[inline]
pub fn record_fetch_response_refused(kind: &str, reason: &str) {
    recorder().record_fetch_response_refused(kind, reason);
}

/// Set the in-flight request slot count for a class.
#[inline]
pub fn set_request_slots_in_flight(class: &str, count: usize) {
    recorder().set_request_slots_in_flight(class, count);
}

/// Record `acquire_slot` wait time.
#[inline]
pub fn record_request_slot_wait(class: &str, wait_secs: f64) {
    recorder().record_request_slot_wait(class, wait_secs);
}

/// Record a gossipsub validation outcome.
#[inline]
pub fn record_gossipsub_validation(outcome: &str) {
    recorder().record_gossipsub_validation(outcome);
}

/// Set the inbound serving stream count for a protocol.
#[inline]
pub fn set_inbound_streams_in_use(protocol: &str, count: usize) {
    recorder().set_inbound_streams_in_use(protocol, count);
}

// ── Sync ─────────────────────────────────────────────────────────────

/// Set the per-scope `blocks_behind` gauge for a shard.
#[inline]
pub fn set_sync_blocks_behind(kind: &str, shard: u64, blocks_behind: u64) {
    recorder().set_sync_blocks_behind(kind, shard, blocks_behind);
}

/// Set the per-scope `in_progress` gauge (0/1) for a shard.
#[inline]
pub fn set_sync_in_progress(kind: &str, shard: u64, in_progress: bool) {
    recorder().set_sync_in_progress(kind, shard, in_progress);
}

/// Record a sync response filtered out before delivery.
#[inline]
pub fn record_sync_block_filtered(kind: &str, reason: &str) {
    recorder().record_sync_block_filtered(kind, reason);
}

/// Record a sync response error.
#[inline]
pub fn record_sync_response_error(kind: &str, error_type: &str) {
    recorder().record_sync_response_error(kind, error_type);
}

/// Record a sync range round-trip started.
#[inline]
pub fn record_sync_round_started(kind: &str) {
    recorder().record_sync_round_started(kind);
}

/// Record a retained tip offer refused after the fresh chain moved on.
#[inline]
pub fn record_halt_recovery_offer_refused() {
    recorder().record_halt_recovery_offer_refused();
}

/// Record a sync range round-trip completed successfully.
#[inline]
pub fn record_sync_round_completed(kind: &str) {
    recorder().record_sync_round_completed(kind);
}

/// Record a sync range round-trip released for retry.
#[inline]
pub fn record_sync_round_retried(kind: &str) {
    recorder().record_sync_round_retried(kind);
}

/// Set the per-scope in-flight range gauge for a shard.
#[inline]
pub fn set_sync_round_in_flight(kind: &str, shard: u64, count: usize) {
    recorder().set_sync_round_in_flight(kind, shard, count);
}

// ── Fetch ────────────────────────────────────────────────────────────

/// Record a fetch operation started.
#[inline]
pub fn record_fetch_started(kind: &str) {
    recorder().record_fetch_started(kind);
}

/// Record a fetch operation completed (payload landed and drained the entry).
#[inline]
pub fn record_fetch_completed(kind: &str) {
    recorder().record_fetch_completed(kind);
}

/// Record a fetch operation cancelled by `Action::AbandonFetch`.
#[inline]
pub fn record_fetch_abandoned(kind: &str) {
    recorder().record_fetch_abandoned(kind);
}

/// Record a fetch operation released for retry.
#[inline]
pub fn record_fetch_retried(kind: &str) {
    recorder().record_fetch_retried(kind);
}

/// Record how long an admitted fetch waited from its latest dispatch.
#[inline]
pub fn record_fetch_latency(kind: &str, latency_secs: f64) {
    recorder().record_fetch_latency(kind, latency_secs);
}

/// Set the fetch in-flight gauge (per kind, per shard).
#[inline]
pub fn set_fetch_in_flight(kind: &str, shard: u64, count: usize) {
    recorder().set_fetch_in_flight(kind, shard, count);
}

/// Set the age (in ms) of the longest-running in-flight fetch entry
/// (per kind, per shard).
#[inline]
pub fn set_fetch_oldest_in_flight_age_ms(kind: &str, shard: u64, age_ms: u64) {
    recorder().set_fetch_oldest_in_flight_age_ms(kind, shard, age_ms);
}

/// Record items sent in response to a fetch request.
#[inline]
pub fn record_fetch_response_sent(kind: &str, count: usize) {
    recorder().record_fetch_response_sent(kind, count);
}

// ── Transaction Ingress ──────────────────────────────────────────────

/// Record a transaction rejected because node is syncing.
#[inline]
pub fn record_tx_ingress_rejected_syncing() {
    recorder().record_tx_ingress_rejected_syncing();
}

/// Record a transaction rejected because pending count is too high.
#[inline]
pub fn record_tx_ingress_rejected_pending_limit() {
    recorder().record_tx_ingress_rejected_pending_limit();
}

/// Record a transaction rejected with reason.
#[inline]
pub fn record_transaction_rejected(reason: &str) {
    recorder().record_transaction_rejected(reason);
}

/// Record an invalid message received.
#[inline]
pub fn record_invalid_message() {
    recorder().record_invalid_message();
}

// ── Aborted Transactions ─────────────────────────────────────────────

/// Record a cross-shard transaction abort (timeout or conflict).
#[inline]
pub fn record_transaction_aborted() {
    recorder().record_transaction_aborted();
}

/// Record an expected cross-shard tx dropped past `RETENTION_HORIZON`.
#[inline]
pub fn record_expected_tx_dropped() {
    recorder().record_expected_tx_dropped();
}

// ── Memory ────────────────────────────────────────────────────────

/// Set one collection-size readout for a coordinator on one vnode.
#[inline]
pub fn set_vnode_memory_gauge(
    family: MemoryFamily,
    field: &str,
    shard: u64,
    validator_id: u64,
    value: usize,
) {
    recorder().set_vnode_memory_gauge(family, field, shard, validator_id, value);
}

/// Set one collection-size readout for shard-scoped runner state.
#[inline]
pub fn set_shard_memory_gauge(field: &str, shard: u64, value: usize) {
    recorder().set_shard_memory_gauge(field, shard, value);
}
