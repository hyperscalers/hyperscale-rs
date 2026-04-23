//! Per-wave execution state.
//!
//! One `WaveState` owns an in-flight wave from block commit through
//! finalization: per-tx execution progress, local vote generation, and
//! cross-shard EC collection all live here.
//!
//! ## Wave lifecycle
//!
//! 1. **Created** in `ExecutionCoordinator::on_block_committed` when waves are assigned
//!    for a newly committed block. At creation, each tx's already-received
//!    provisions are folded in — if every tx is fully provisioned at that point
//!    (single-shard waves are trivially so), `all_provisioned_at` is set to the
//!    block's own height.
//! 2. **Waits for provisions** until every tx has all required remote shards'
//!    state. Each `mark_provisioned(tx, at_height)` call that completes the
//!    final missing tx sets `all_provisioned_at = Some(at_height)` and returns
//!    `true` — the caller uses that as the dispatch trigger.
//! 3. **Executes atomically** — one `ExecuteTransactions` /
//!    `ExecuteCrossShardTransactions` action per wave. Results land via
//!    `record_execution_result`.
//! 4. **Votes** once all results present (or at the `wave_start_ts +
//!    WAVE_TIMEOUT` deadline if still not provisioned — entire wave aborts).
//! 5. **Collects ECs** from all participating shards via
//!    `add_execution_certificate`. When every tx is covered (or aborted, which
//!    is terminal-covered), the wave is complete and ready for finalization.

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    compute_execution_receipt_root, BlockHash, BlockHeight, ExecutionCertificate,
    ExecutionCertificateHash, ExecutionOutcome, GlobalReceiptRoot, ReceiptBundle,
    RoutableTransaction, ShardGroupId, TransactionDecision, TxHash, TxOutcome, WaveCertificate,
    WaveId, WeightedTimestamp, WAVE_TIMEOUT,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// Age at which a still-alive wave emits a single diagnostic warning. Set
/// past `WAVE_TIMEOUT` so waves resolving via the normal timeout-abort path
/// (including cross-shard cert gossip) pass silently; only genuinely-wedged
/// waves surface.
pub const WAVE_OVERDUE_WARN: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() * 2);

/// Per-wave state across the entire execution lifecycle.
#[derive(Debug)]
pub struct WaveState {
    // ── Identity ────────────────────────────────────────────────────────
    wave_id: WaveId,
    block_hash: BlockHash,

    // ── Tx layout (in block order) ──────────────────────────────────────
    tx_hashes: Vec<TxHash>,
    /// Participating shards per tx — the shards whose ECs must cover each tx
    /// for completion. Always includes local shard; cross-shard txs include
    /// remote shards too.
    participating_shards: HashMap<TxHash, BTreeSet<ShardGroupId>>,
    /// O(1) membership check (mirrors `tx_hashes`).
    tx_hash_set: HashSet<TxHash>,
    /// Transactions owned by the wave, used to build execution requests at
    /// dispatch time.
    transactions: HashMap<TxHash, Arc<RoutableTransaction>>,

    /// BFT-authenticated weighted timestamp of the wave-starting block.
    /// Anchor for wave-level wall-clock timeouts (wave abort, vote anchor
    /// in the timeout path).
    wave_start_ts: WeightedTimestamp,

    // ── Provisioning phase ──────────────────────────────────────────────
    /// Txs whose required remote-shard provisions have all arrived.
    provisioned_txs: HashSet<TxHash>,
    /// Per-tx earliest ready timestamp. `all_provisioned_at` is
    /// the max across this map — deterministic regardless of call order.
    provisioned_tx_ts: HashMap<TxHash, WeightedTimestamp>,
    /// The weighted timestamp at which every tx in the wave became
    /// ready. `None` until `provisioned_txs` is full.
    all_provisioned_at: Option<WeightedTimestamp>,
    /// Whether execution has been dispatched (single `ExecuteTransactions` /
    /// `ExecuteCrossShardTransactions` emitted). Set true once execution fires.
    dispatched: bool,

    // ── Local execution outputs ─────────────────────────────────────────
    /// Execution results from the engine (per-tx). Non-abort outcomes only.
    execution_results: HashMap<TxHash, ExecutionOutcome>,
    /// Local receipts from the engine, one per executed tx. Drained into the
    /// `FinalizedWave` at finalization via `take_receipt`. Scoping these to
    /// the wave (rather than a process-wide cache) prevents a receipt from a
    /// locally-executed tx from leaking into a `FinalizedWave` whose EC later
    /// attests that tx as `Aborted` — the `ExtraReceipt` race.
    execution_receipts: HashMap<TxHash, ReceiptBundle>,
    /// Explicit aborts from `ConflictDetector`. Distinct from remote-reported
    /// aborts in `tracker_aborted` — these are local pre-vote decisions.
    explicit_aborts: HashSet<TxHash>,
    /// Whether the local vote has been emitted (`build_vote_data` called once).
    voted: bool,
    /// Whether the local EC has been added to `execution_certificates`. Gates
    /// wave completion: `is_complete` requires the local EC to be present.
    local_ec_emitted: bool,
    /// Latches `log_if_overdue`: fires once per wave after crossing the
    /// `WAVE_OVERDUE_WARN` threshold. Under ts-based ages we can't rely on
    /// exact equality (commits can skip over any given ms value).
    overdue_warned: bool,

    // ── Cross-shard EC collection ───────────────────────────────────────
    /// Per-tx, which shards have reported via an EC.
    covered_shards: HashMap<TxHash, BTreeSet<ShardGroupId>>,
    /// Per-tx, whether any shard's EC reported abort. Terminal — an aborted tx
    /// doesn't require further remote coverage.
    tracker_aborted: HashSet<TxHash>,
    /// Per-tx, whether any shard's EC reported a non-success outcome.
    tx_has_failure: HashSet<TxHash>,
    /// All collected ECs (local + remote).
    execution_certificates: Vec<Arc<ExecutionCertificate>>,
    /// Deduplication of received ECs by canonical hash.
    seen_ec_hashes: HashSet<ExecutionCertificateHash>,
}

impl WaveState {
    /// Create a new wave state.
    ///
    /// `txs` is in block order. Each entry is `(transaction, participating_shards)`.
    /// `single_shard` indicates whether this is a single-shard wave (`remote_shards` empty);
    /// if so, `all_provisioned_at` / `all_provisioned_at` are set to the
    /// wave-starting block's height/timestamp immediately.
    pub fn new(
        wave_id: WaveId,
        block_hash: BlockHash,
        wave_start_ts: WeightedTimestamp,
        txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)>,
        single_shard: bool,
    ) -> Self {
        let mut tx_hashes: Vec<TxHash> = Vec::with_capacity(txs.len());
        let mut transactions: HashMap<TxHash, Arc<RoutableTransaction>> =
            HashMap::with_capacity(txs.len());
        let mut participating_shards: HashMap<TxHash, BTreeSet<ShardGroupId>> =
            HashMap::with_capacity(txs.len());
        let mut covered_shards: HashMap<TxHash, BTreeSet<ShardGroupId>> =
            HashMap::with_capacity(txs.len());

        for (tx, shards) in txs {
            let h = tx.hash();
            tx_hashes.push(h);
            transactions.insert(h, tx);
            participating_shards.insert(h, shards);
            covered_shards.insert(h, BTreeSet::new());
        }

        let tx_hash_set: HashSet<TxHash> = tx_hashes.iter().copied().collect();

        // Single-shard waves are trivially provisioned at creation.
        let (provisioned_txs, provisioned_tx_ts, all_provisioned_at) = if single_shard {
            let ts_map: HashMap<TxHash, WeightedTimestamp> =
                tx_hashes.iter().map(|h| (*h, wave_start_ts)).collect();
            (tx_hash_set.clone(), ts_map, Some(wave_start_ts))
        } else {
            (HashSet::new(), HashMap::new(), None)
        };

        Self {
            wave_id,
            block_hash,
            wave_start_ts,
            tx_hashes,
            participating_shards,
            tx_hash_set,
            transactions,
            provisioned_txs,
            provisioned_tx_ts,
            all_provisioned_at,
            dispatched: false,
            execution_results: HashMap::new(),
            execution_receipts: HashMap::new(),
            explicit_aborts: HashSet::new(),
            voted: false,
            local_ec_emitted: false,
            overdue_warned: false,
            covered_shards,
            tracker_aborted: HashSet::new(),
            tx_has_failure: HashSet::new(),
            execution_certificates: Vec::new(),
            seen_ec_hashes: HashSet::new(),
        }
    }

    // ── Identity getters ────────────────────────────────────────────────

    pub fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    pub fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    pub fn block_height(&self) -> BlockHeight {
        self.wave_id.block_height
    }

    pub fn tx_hashes(&self) -> &[TxHash] {
        &self.tx_hashes
    }

    /// Transaction data by hash (for building execution requests).
    pub fn transaction(&self, tx_hash: &TxHash) -> Option<&Arc<RoutableTransaction>> {
        self.transactions.get(tx_hash)
    }

    // ── Provisioning ────────────────────────────────────────────────────

    /// Whether this wave has reached full provisioning.
    pub fn is_fully_provisioned(&self) -> bool {
        self.all_provisioned_at.is_some()
    }

    /// Whether execution has been dispatched for this wave.
    pub fn dispatched(&self) -> bool {
        self.dispatched
    }

    /// Whether the local EC has been fed into this wave (via
    /// `add_execution_certificate` with `ec.wave_id == self.wave_id`).
    pub fn local_ec_emitted(&self) -> bool {
        self.local_ec_emitted
    }

    /// Mark the wave as having dispatched execution. Idempotent: second calls
    /// are no-ops. Returns whether this call flipped the flag.
    pub fn mark_dispatched(&mut self) -> bool {
        if self.dispatched {
            false
        } else {
            self.dispatched = true;
            true
        }
    }

    /// Mark a single tx as provisioned. Keeps the earliest `at` per tx
    /// so the wave's transition timestamp is a pure function of the event
    /// set.
    ///
    /// Returns `true` iff this call transitioned the wave from "partial" to
    /// "all provisioned" — the caller uses that signal to emit the single
    /// per-wave execution dispatch action.
    pub fn mark_tx_provisioned(&mut self, tx_hash: TxHash, at: WeightedTimestamp) -> bool {
        if !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }

        self.provisioned_tx_ts
            .entry(tx_hash)
            .and_modify(|t| *t = (*t).min(at))
            .or_insert(at);

        let is_new = self.provisioned_txs.insert(tx_hash);

        if is_new
            && self.all_provisioned_at.is_none()
            && self.provisioned_txs.len() == self.tx_hashes.len()
        {
            let max_ts = self.provisioned_tx_ts.values().copied().max().unwrap_or(at);
            self.all_provisioned_at = Some(max_ts);
            true
        } else {
            false
        }
    }

    // ── Local execution bookkeeping ─────────────────────────────────────

    /// Record an execution outcome from the engine. First-write-wins.
    /// Returns `true` if the wave now has an outcome (execution result or
    /// explicit abort) for every tx.
    pub fn record_execution_result(&mut self, tx_hash: TxHash, outcome: ExecutionOutcome) -> bool {
        if !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }
        self.execution_results.entry(tx_hash).or_insert(outcome);
        self.has_outcome_for_every_tx()
    }

    /// Record a local receipt from the engine. First-write-wins.
    ///
    /// Paired with `record_execution_result`: both flow from the same
    /// `ExecutionBatchCompleted` event and are scoped to this wave. Receipts
    /// for txs not in the wave are silently dropped.
    pub fn record_receipt(&mut self, bundle: ReceiptBundle) {
        if !self.tx_hash_set.contains(&bundle.tx_hash) {
            return;
        }
        self.execution_receipts
            .entry(bundle.tx_hash)
            .or_insert(bundle);
    }

    /// Number of receipts currently held by this wave. Exposed for memory
    /// stats; receipts drain at finalization.
    pub fn receipt_count(&self) -> usize {
        self.execution_receipts.len()
    }

    /// Take the receipt for a tx, removing it from the wave.
    ///
    /// Used at finalization time, walking the local EC's `tx_outcomes` in
    /// canonical order and pulling a receipt for each non-aborted outcome.
    /// Returns `None` if the receipt is absent — for an aborted outcome this
    /// is expected; for a non-aborted outcome it indicates the
    /// `has_local_receipts_for_non_aborted` gate was bypassed, which would
    /// be a bug.
    pub fn take_receipt(&mut self, tx_hash: &TxHash) -> Option<ReceiptBundle> {
        self.execution_receipts.remove(tx_hash)
    }

    /// Record an explicit abort from `ConflictDetector`. Keeps the earliest
    /// commit height if called multiple times for the same tx.
    /// Returns `true` if the wave now has an outcome (execution result or
    /// explicit abort) for every tx.
    ///
    /// No-op once the wave has dispatched: a dispatched wave is committed to
    /// executing what it started with, and mid-flight conflict aborts would
    /// introduce non-determinism across validators (the conflict batch lands
    /// at slightly different wall-clock offsets from `ExecutionBatchCompleted`
    /// on each node). Conflict detection's purpose — deadlock avoidance — is
    /// served by the pre-dispatch path only.
    ///
    /// Also marks the tx as provisioned — an aborted tx has a determinate
    /// outcome, so the wave shouldn't block waiting for provisions that will
    /// never arrive. Without this, a single aborted tx forced the wave into
    /// the timeout branch, which then marked every tx Aborted (including the
    /// ones that executed successfully).
    pub fn record_abort(&mut self, tx_hash: TxHash, committed_at: WeightedTimestamp) -> bool {
        if self.dispatched || !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }
        self.explicit_aborts.insert(tx_hash);
        self.mark_tx_provisioned(tx_hash, committed_at);
        self.has_outcome_for_every_tx()
    }

    /// True if each tx has either an execution result or an explicit abort.
    fn has_outcome_for_every_tx(&self) -> bool {
        self.tx_hashes
            .iter()
            .all(|h| self.execution_results.contains_key(h) || self.explicit_aborts.contains(h))
    }

    /// True if, for every non-aborted outcome in the local EC, this validator
    /// has produced a matching local receipt. Aborted outcomes need no receipt.
    ///
    /// Gates [`Self::is_complete`] so `finalize_wave` can't produce a
    /// [`FinalizedWave`] that fails
    /// [`FinalizedWave::validate_receipts_against_ec`]. The check mirrors that
    /// invariant: a receipt is needed exactly for the outcomes the EC attests
    /// as `Executed`. When this validator's local abort decision disagrees
    /// with the quorum's EC (e.g. its conflict detector aborted a tx peers
    /// executed), the gate blocks here rather than synthesizing a
    /// FinalizedWave with missing receipts. Recovery flows through the
    /// existing peer-fetch path.
    ///
    /// Returns false if the local EC hasn't arrived yet; `local_ec_emitted`
    /// is checked separately by [`Self::is_complete`] for the same reason.
    ///
    /// [`FinalizedWave`]: hyperscale_types::FinalizedWave
    /// [`FinalizedWave::validate_receipts_against_ec`]:
    ///     hyperscale_types::FinalizedWave::validate_receipts_against_ec
    fn has_local_receipts_for_non_aborted(&self) -> bool {
        let Some(local_ec) = self
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == self.wave_id)
        else {
            return false;
        };
        local_ec.tx_outcomes.iter().all(|outcome| {
            outcome.is_aborted() || self.execution_receipts.contains_key(&outcome.tx_hash)
        })
    }

    // ── Vote emission ───────────────────────────────────────────────────

    /// Vote anchor timestamp — the BFT-authenticated weighted timestamp (ms)
    /// at which this wave's outcome is fixed.
    /// - Fully provisioned: `all_provisioned_at` (max provisioning ts
    ///   across txs in the wave).
    /// - Timed out: `wave_start_ts + WAVE_TIMEOUT` (deterministic abort
    ///   anchor).
    ///
    /// Included in the vote payload and the EC canonical hash, so all
    /// validators aggregate under the same identifier.
    fn target_vote_anchor_ts(&self) -> WeightedTimestamp {
        match self.all_provisioned_at {
            Some(ts_ms) => ts_ms,
            None => self.wave_start_ts.plus(WAVE_TIMEOUT),
        }
    }

    /// Whether the local vote can be emitted at the given committed timestamp.
    ///
    /// Two branches:
    /// - Fully provisioned: need `committed_ts >= all_provisioned_at`
    ///   AND every tx has an execution result or explicit abort.
    /// - Not provisioned: wait until `committed_ts >= wave_start_ts +
    ///   WAVE_TIMEOUT`. Upon timeout, every tx in the wave is implicitly
    ///   aborted.
    pub fn can_emit_vote(&self, committed_ts: WeightedTimestamp) -> bool {
        if self.voted {
            return false;
        }
        match self.all_provisioned_at {
            Some(provisioned_at) => {
                committed_ts >= provisioned_at && self.has_outcome_for_every_tx()
            }
            None => committed_ts >= self.wave_start_ts.plus(WAVE_TIMEOUT),
        }
    }

    /// Build vote payload at the target anchor, consuming the one-shot vote.
    ///
    /// Returns `(vote_anchor_ts, global_receipt_root, tx_outcomes)`.
    /// Returns `None` if `can_emit_vote` is false.
    ///
    /// In the timeout-abort branch (`all_provisioned_at = None`), every
    /// tx gets an `ExecutionOutcome::Aborted`. In the provisioned branch,
    /// each tx's outcome is its explicit abort (if any) or execution result.
    pub fn build_vote_data(
        &mut self,
        committed_ts: WeightedTimestamp,
    ) -> Option<(WeightedTimestamp, GlobalReceiptRoot, Vec<TxOutcome>)> {
        if !self.can_emit_vote(committed_ts) {
            return None;
        }

        let target = self.target_vote_anchor_ts();
        let timed_out = self.all_provisioned_at.is_none();

        let outcomes: Vec<TxOutcome> = self
            .tx_hashes
            .iter()
            .map(|tx_hash| {
                let outcome = if timed_out || self.explicit_aborts.contains(tx_hash) {
                    ExecutionOutcome::Aborted
                } else {
                    // Safe: has_outcome_for_every_tx() ensured presence
                    self.execution_results
                        .get(tx_hash)
                        .cloned()
                        .expect("execution result must be present under provisioned branch")
                };
                TxOutcome {
                    tx_hash: *tx_hash,
                    outcome,
                }
            })
            .collect();

        let root = compute_execution_receipt_root(&outcomes);
        self.voted = true;
        Some((target, root, outcomes))
    }

    // ── Cross-shard EC collection ───────────────────────────────────────

    /// Feed an EC into the wave. Handles dedup (by canonical hash), updates
    /// per-tx coverage, and tracks aborts/failures. If the EC is our own local
    /// EC (`ec.wave_id == self.wave_id`), flips `local_ec_emitted` true.
    ///
    /// Returns `true` if the wave is now complete (ready for `finalize_wave`).
    pub fn add_execution_certificate(&mut self, ec: Arc<ExecutionCertificate>) -> bool {
        let ec_hash = ec.canonical_hash();
        if !self.seen_ec_hashes.insert(ec_hash) {
            return self.is_complete();
        }

        let shard = ec.shard_group_id();
        let is_local = ec.wave_id == self.wave_id;

        for outcome in &ec.tx_outcomes {
            if let Some(covered) = self.covered_shards.get_mut(&outcome.tx_hash) {
                covered.insert(shard);
                if outcome.is_aborted() {
                    self.tracker_aborted.insert(outcome.tx_hash);
                }
                if !matches!(
                    outcome.outcome,
                    ExecutionOutcome::Executed { success: true, .. }
                ) {
                    self.tx_has_failure.insert(outcome.tx_hash);
                }
            }
        }

        self.execution_certificates.push(ec);
        if is_local {
            self.local_ec_emitted = true;
        }

        self.is_complete()
    }

    /// Whether the wave is complete: local EC present, every non-aborted
    /// tx has a local execution result on this validator, and every tx
    /// either aborted (terminal) or covered by every participating shard.
    ///
    /// The local-receipt gate prevents the race where a cross-shard wave's
    /// local EC arrives (aggregated from other validators' votes) before
    /// this validator's engine finishes executing — without it,
    /// `finalize_wave` silently drops the pending txs' receipt slots and
    /// produces a divergent FinalizedWave.
    pub fn is_complete(&self) -> bool {
        if !self.local_ec_emitted {
            return false;
        }
        if !self.has_local_receipts_for_non_aborted() {
            return false;
        }
        for tx_hash in &self.tx_hashes {
            if self.tracker_aborted.contains(tx_hash) {
                continue;
            }
            let Some(expected) = self.participating_shards.get(tx_hash) else {
                return false;
            };
            let Some(covered) = self.covered_shards.get(tx_hash) else {
                return false;
            };
            if !expected.is_subset(covered) {
                return false;
            }
        }
        true
    }

    /// Whether a tx was aborted before dispatch (pre-dispatch reverse-conflict).
    /// Used by dispatch to skip executing txs the wave has already decided to
    /// abort.
    pub fn is_tx_explicitly_aborted(&self, tx_hash: &TxHash) -> bool {
        self.explicit_aborts.contains(tx_hash)
    }

    /// Emit a `warn!` log exactly once, when the wave reaches
    /// `WAVE_OVERDUE_WARN` of age without completing. Dumps enough state to
    /// diagnose what phase it's stuck in (provisioning / dispatch / voting /
    /// EC collection). Called once per committed block per surviving wave;
    /// we latch the warning at the first crossing of the threshold using
    /// tick-transition detection by the caller.
    pub fn log_if_overdue(&mut self, committed_ts: WeightedTimestamp) {
        if self.overdue_warned {
            return;
        }
        let age = committed_ts.elapsed_since(self.wave_start_ts);
        if age < WAVE_OVERDUE_WARN {
            return;
        }
        self.overdue_warned = true;

        let total = self.tx_hashes.len();
        let provisioned = self.provisioned_txs.len();

        let mut missing_coverage: Vec<String> = Vec::new();
        for tx_hash in &self.tx_hashes {
            if self.tracker_aborted.contains(tx_hash) {
                continue;
            }
            let expected = self
                .participating_shards
                .get(tx_hash)
                .cloned()
                .unwrap_or_default();
            let covered = self
                .covered_shards
                .get(tx_hash)
                .cloned()
                .unwrap_or_default();
            let missing: BTreeSet<ShardGroupId> = expected.difference(&covered).copied().collect();
            if !missing.is_empty() {
                let missing_list: Vec<String> = missing.iter().map(|s| s.0.to_string()).collect();
                missing_coverage.push(format!("{:?}→[{}]", tx_hash, missing_list.join(",")));
            }
        }

        let local_receipts_ready = self.has_local_receipts_for_non_aborted();

        tracing::warn!(
            wave = %self.wave_id,
            block_hash = ?self.block_hash,
            block_height = self.wave_id.block_height.0,
            wave_start_ts = self.wave_start_ts.as_millis(),
            committed_ts = committed_ts.as_millis(),
            age_ms = age.as_millis() as u64,
            timeout_ms = WAVE_TIMEOUT.as_millis() as u64,
            num_txs = total,
            provisioned = format!("{}/{}", provisioned, total),
            all_provisioned_at = ?self.all_provisioned_at.map(|t| t.as_millis()),
            dispatched = self.dispatched,
            voted = self.voted,
            local_ec_emitted = self.local_ec_emitted,
            local_receipts_ready,
            execution_results = self.execution_results.len(),
            explicit_aborts = self.explicit_aborts.len(),
            tracker_aborted = self.tracker_aborted.len(),
            ecs_collected = self.execution_certificates.len(),
            is_complete = self.is_complete(),
            missing_coverage = missing_coverage.join(" "),
            "Wave overdue: alive past execution timeout without completing"
        );
    }

    /// Build the final `WaveCertificate`. Local EC is always included;
    /// remote ECs are included only if they cover at least one non-aborted
    /// tx. Deterministic order: `(shard_group_id, canonical_hash)`.
    ///
    /// Callers should invoke only when `is_complete()` is true.
    pub fn create_wave_certificate(&self) -> WaveCertificate {
        let required_remote_ec_hashes: HashSet<ExecutionCertificateHash> = self
            .execution_certificates
            .iter()
            .filter(|ec| ec.wave_id != self.wave_id)
            .filter(|ec| {
                ec.tx_outcomes.iter().any(|outcome| {
                    self.participating_shards.contains_key(&outcome.tx_hash)
                        && !self.tracker_aborted.contains(&outcome.tx_hash)
                })
            })
            .map(|ec| ec.canonical_hash())
            .collect();

        let mut ecs: Vec<Arc<ExecutionCertificate>> = self
            .execution_certificates
            .iter()
            .filter(|ec| {
                ec.wave_id == self.wave_id
                    || required_remote_ec_hashes.contains(&ec.canonical_hash())
            })
            .cloned()
            .collect();

        ecs.sort_by(|a, b| {
            (&a.shard_group_id(), &a.canonical_hash())
                .cmp(&(&b.shard_group_id(), &b.canonical_hash()))
        });

        WaveCertificate {
            wave_id: self.wave_id.clone(),
            execution_certificates: ecs,
        }
    }

    /// Per-tx terminal decisions derived from collected ECs.
    /// Priority: Aborted > Reject > Accept.
    pub fn tx_decisions(&self) -> Vec<(TxHash, TransactionDecision)> {
        self.tx_hashes
            .iter()
            .map(|tx_hash| {
                let decision = if self.tracker_aborted.contains(tx_hash) {
                    TransactionDecision::Aborted
                } else if self.tx_has_failure.contains(tx_hash) {
                    TransactionDecision::Reject
                } else {
                    TransactionDecision::Accept
                };
                (*tx_hash, decision)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        test_utils::{test_node, test_transaction_with_nodes},
        Bls12381G2Signature, GlobalReceiptHash, LocalReceipt, SignerBitfield, TransactionOutcome,
    };

    const WAVE_START: BlockHeight = BlockHeight(10);

    fn make_tx(seed: u8) -> Arc<RoutableTransaction> {
        Arc::new(test_transaction_with_nodes(
            &[seed, seed + 1, seed + 2],
            vec![test_node(seed)],
            vec![test_node(seed + 50)],
        ))
    }

    /// Tests use synthetic timestamps proportional to block heights so the
    /// block-height intuition in assertions maps cleanly to ts space.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    fn ts_for(height: BlockHeight) -> WeightedTimestamp {
        WeightedTimestamp(height.0 * TEST_BLOCK_INTERVAL_MS)
    }

    fn make_single_shard_wave(n: usize) -> WaveState {
        let txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)> = (0..n)
            .map(|i| (make_tx(i as u8), BTreeSet::from([ShardGroupId(0)])))
            .collect();
        WaveState::new(
            WaveId::new(ShardGroupId(0), WAVE_START, BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ts_for(WAVE_START),
            txs,
            true,
        )
    }

    fn make_cross_shard_wave(n: usize) -> WaveState {
        let shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)> =
            (0..n).map(|i| (make_tx(i as u8), shards.clone())).collect();
        WaveState::new(
            WaveId::new(
                ShardGroupId(0),
                WAVE_START,
                BTreeSet::from([ShardGroupId(1)]),
            ),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            ts_for(WAVE_START),
            txs,
            false,
        )
    }

    fn executed(success: bool) -> ExecutionOutcome {
        ExecutionOutcome::Executed {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"r")),
            success,
        }
    }

    /// Record a result + matching receipt, as the production path does
    /// via `on_execution_batch_completed`. Tests that need execution to
    /// look "real" should use this rather than `record_execution_result`
    /// alone — the `is_complete` gate keys off `execution_receipts`.
    fn record_executed(w: &mut WaveState, tx_hash: TxHash, success: bool) {
        w.record_execution_result(tx_hash, executed(success));
        w.record_receipt(ReceiptBundle {
            tx_hash,
            local_receipt: Arc::new(LocalReceipt {
                outcome: if success {
                    TransactionOutcome::Success
                } else {
                    TransactionOutcome::Failure
                },
                database_updates: Default::default(),
                application_events: vec![],
            }),
            execution_output: None,
        });
    }

    fn make_ec(
        wave_id: &WaveId,
        ec_shard: ShardGroupId,
        tx_hashes: &[TxHash],
        success: bool,
    ) -> Arc<ExecutionCertificate> {
        let outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| TxOutcome {
                tx_hash: *h,
                outcome: if success {
                    executed(true)
                } else {
                    ExecutionOutcome::Aborted
                },
            })
            .collect();
        let ec_wave_id = WaveId::new(
            ec_shard,
            wave_id.block_height,
            wave_id.remote_shards.clone(),
        );
        Arc::new(ExecutionCertificate::new(
            ec_wave_id,
            WeightedTimestamp(wave_id.block_height.0 + 1),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"global_receipt_root")),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn single_shard_is_provisioned_on_creation() {
        let w = make_single_shard_wave(2);
        assert!(w.is_fully_provisioned());
        assert_eq!(w.all_provisioned_at, Some(ts_for(WAVE_START)));
    }

    #[test]
    fn cross_shard_not_provisioned_on_creation() {
        let w = make_cross_shard_wave(2);
        assert!(!w.is_fully_provisioned());
        assert_eq!(w.all_provisioned_at, None);
    }

    #[test]
    fn mark_tx_provisioned_transitions_exactly_once() {
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        assert!(!w.mark_tx_provisioned(h0, ts_for(WAVE_START + 1)));
        assert!(!w.is_fully_provisioned());
        assert!(w.mark_tx_provisioned(h1, ts_for(WAVE_START + 2)));
        assert!(w.is_fully_provisioned());
        assert_eq!(w.all_provisioned_at, Some(ts_for(WAVE_START + 2)));

        // Idempotent: repeat calls don't retransition.
        assert!(!w.mark_tx_provisioned(h1, ts_for(WAVE_START + 3)));
    }

    #[test]
    fn can_emit_vote_requires_results_when_provisioned() {
        let mut w = make_single_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // No results yet.
        assert!(!w.can_emit_vote(ts_for(WAVE_START)));

        w.record_execution_result(h0, executed(true));
        assert!(!w.can_emit_vote(ts_for(WAVE_START)));

        w.record_execution_result(h1, executed(true));
        assert!(w.can_emit_vote(ts_for(WAVE_START)));
    }

    #[test]
    fn timeout_abort_without_provisions() {
        let mut w = make_cross_shard_wave(2);
        let wave_start_ts = ts_for(WAVE_START);
        let at_timeout = wave_start_ts.plus(WAVE_TIMEOUT);
        let just_before = WeightedTimestamp(at_timeout.as_millis() - 1);

        // Not yet at timeout.
        assert!(!w.can_emit_vote(just_before));

        // At timeout — all txs implicitly abort.
        assert!(w.can_emit_vote(at_timeout));

        let (anchor, _root, outcomes) = w.build_vote_data(at_timeout).unwrap();
        assert_eq!(anchor, at_timeout);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|o| matches!(o.outcome, ExecutionOutcome::Aborted)));
    }

    #[test]
    fn vote_exactly_once() {
        let mut w = make_single_shard_wave(1);
        let h0 = w.tx_hashes()[0];
        w.record_execution_result(h0, executed(true));

        assert!(w.build_vote_data(ts_for(WAVE_START)).is_some());
        // Already voted; can't again.
        assert!(!w.can_emit_vote(ts_for(WAVE_START + 100)));
        assert!(w.build_vote_data(ts_for(WAVE_START + 100)).is_none());
    }

    #[test]
    fn explicit_abort_produces_abort_outcome() {
        let mut w = make_single_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        w.record_execution_result(h0, executed(true));
        w.record_abort(h1, ts_for(WAVE_START + 3));

        let (_, _, outcomes) = w.build_vote_data(ts_for(WAVE_START + 3)).unwrap();
        assert!(matches!(
            outcomes[0].outcome,
            ExecutionOutcome::Executed { .. }
        ));
        assert!(matches!(outcomes[1].outcome, ExecutionOutcome::Aborted));
    }

    #[test]
    fn abort_marks_tx_as_aborted() {
        let mut w = make_single_shard_wave(1);
        let h0 = w.tx_hashes()[0];
        w.record_abort(h0, ts_for(BlockHeight(20)));
        assert!(w.explicit_aborts.contains(&h0));
        // Idempotent: calling again doesn't clear or duplicate.
        w.record_abort(h0, ts_for(BlockHeight(15)));
        assert!(w.explicit_aborts.contains(&h0));
        assert_eq!(w.explicit_aborts.len(), 1);
    }

    #[test]
    fn cross_shard_wave_requires_local_and_remote_ec() {
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // Fully provision and execute locally.
        w.mark_tx_provisioned(h0, ts_for(WAVE_START + 1));
        w.mark_tx_provisioned(h1, ts_for(WAVE_START + 1));
        record_executed(&mut w, h0, true);
        record_executed(&mut w, h1, true);

        // Remote-only EC doesn't complete.
        let ec_remote = make_ec(w.wave_id(), ShardGroupId(1), &[h0, h1], true);
        assert!(!w.add_execution_certificate(ec_remote));
        assert!(!w.is_complete());

        // Add local EC — now complete.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], true);
        assert!(w.add_execution_certificate(ec_local));
        assert!(w.is_complete());
    }

    #[test]
    fn is_complete_false_when_local_ec_arrives_before_engine_results() {
        // The race the gate is designed to catch: a cross-shard wave's
        // local EC is aggregated from *other* validators' votes while this
        // validator's engine is still running. Coverage looks good but
        // there are no local receipts yet — finalizing here would produce
        // a `FinalizedWave` with missing receipts. Gate must hold until
        // the engine catches up.
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        w.mark_tx_provisioned(h0, ts_for(WAVE_START + 1));
        w.mark_tx_provisioned(h1, ts_for(WAVE_START + 1));

        // Remote EC lands first (other shard was fast).
        let ec_remote = make_ec(w.wave_id(), ShardGroupId(1), &[h0, h1], true);
        w.add_execution_certificate(ec_remote);

        // Local EC lands — built from the other three committee members'
        // votes without this validator contributing. Coverage is complete
        // but no local engine result yet.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], true);
        w.add_execution_certificate(ec_local);
        assert!(
            !w.is_complete(),
            "wave must not be complete before local engine results arrive"
        );

        // Engine finishes — first result not yet enough.
        record_executed(&mut w, h0, true);
        assert!(!w.is_complete());

        // Second result — now fully resolvable.
        record_executed(&mut w, h1, true);
        assert!(w.is_complete());
    }

    #[test]
    fn is_complete_when_ec_attests_abort_without_local_result() {
        // Symmetric to the race fix: if the local EC marks a tx aborted,
        // that tx legitimately has no local receipt. The gate must not
        // stall on such txs — `tracker_aborted` covers for them.
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        w.mark_tx_provisioned(h0, ts_for(WAVE_START + 1));
        w.mark_tx_provisioned(h1, ts_for(WAVE_START + 1));

        // Local EC attests both txs aborted. No execution results needed.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], false);
        w.add_execution_certificate(ec_local);
        assert!(
            w.is_complete(),
            "all-aborted wave resolves without local engine results"
        );
    }

    #[test]
    fn is_complete_false_when_explicit_abort_disagrees_with_local_ec() {
        // This validator's conflict detector aborted h0 locally (e.g. because
        // it was behind on commits and saw different prior provisions). The
        // quorum executed h0 and aggregated a local EC attesting Executed.
        // Without a receipt-vs-EC gate, finalize_wave would build a
        // FinalizedWave missing h0's receipt — which later fails
        // `validate_receipts_against_ec` on any peer. The gate must block
        // and let the existing peer-fetch path recover.
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // h0: local explicit abort. h1: executed, receipt recorded.
        w.record_abort(h0, ts_for(WAVE_START + 1));
        record_executed(&mut w, h1, true);

        // Local EC disagrees: attests BOTH executed.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], true);
        w.add_execution_certificate(ec_local);

        assert!(
            !w.is_complete(),
            "must not finalize when local abort disagrees with quorum's EC"
        );
    }

    #[test]
    fn aborted_tx_does_not_require_remote_coverage() {
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // Local EC marks both aborted; tracker.aborted covers h0, h1.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], false);
        assert!(w.add_execution_certificate(ec_local));
        // Complete despite remote never sending a matching EC.
        assert!(w.is_complete());
    }

    #[test]
    fn record_abort_is_noop_once_dispatched() {
        // Once a wave has dispatched, mid-flight conflict aborts must not
        // mutate the wave — doing so would introduce receipt-level
        // non-determinism across validators (the conflict batch lands at
        // slightly different offsets from ExecutionBatchCompleted on each
        // node). The fix guards `record_abort` on `dispatched`.
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // Fully provision and dispatch.
        w.mark_tx_provisioned(h0, ts_for(WAVE_START + 1));
        w.mark_tx_provisioned(h1, ts_for(WAVE_START + 1));
        assert!(w.mark_dispatched());

        // A post-dispatch conflict abort must be rejected.
        assert!(!w.record_abort(h0, ts_for(WAVE_START + 2)));
        // No explicit abort was recorded.
        w.record_execution_result(h0, executed(true));
        w.record_execution_result(h1, executed(true));
        // If record_abort had mutated, h0's outcome would have flipped to Aborted.
        let (_, _, outcomes) = w.build_vote_data(ts_for(WAVE_START + 2)).unwrap();
        assert!(matches!(
            outcomes[0].outcome,
            ExecutionOutcome::Executed { success: true, .. }
        ));
    }

    #[test]
    fn duplicate_ec_ignored() {
        let mut w = make_cross_shard_wave(1);
        let h0 = w.tx_hashes()[0];
        let ec1 = make_ec(w.wave_id(), ShardGroupId(0), &[h0], true);
        let ec2 = Arc::clone(&ec1);
        w.add_execution_certificate(ec1);
        let before = w.execution_certificates.len();
        w.add_execution_certificate(ec2);
        assert_eq!(w.execution_certificates.len(), before);
    }

    #[test]
    fn wave_certificate_excludes_remote_covering_only_aborts() {
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // Both sides all-abort.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], false);
        let ec_remote = make_ec(w.wave_id(), ShardGroupId(1), &[h0, h1], false);
        w.add_execution_certificate(ec_local);
        w.add_execution_certificate(ec_remote);

        let wc = w.create_wave_certificate();
        assert_eq!(wc.execution_certificates().len(), 1);
        assert_eq!(
            wc.execution_certificates()[0].wave_id.shard_group_id,
            ShardGroupId(0)
        );
    }

    #[test]
    fn tx_decisions_priority() {
        let mut w = make_cross_shard_wave(3);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];
        let h2 = w.tx_hashes()[2];

        // h0: executed success; h1: abort from remote; h2: failure (non-success exec)
        let ec_local_mixed = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1, h2], true);
        w.add_execution_certificate(ec_local_mixed);

        // Remote aborts h1, succeeds h0, h2
        let mut outcomes = vec![
            TxOutcome {
                tx_hash: h0,
                outcome: executed(true),
            },
            TxOutcome {
                tx_hash: h1,
                outcome: ExecutionOutcome::Aborted,
            },
            TxOutcome {
                tx_hash: h2,
                outcome: executed(false),
            },
        ];
        let ec_wave_id = WaveId::new(
            ShardGroupId(1),
            w.wave_id().block_height,
            w.wave_id().remote_shards.clone(),
        );
        let ec_remote = Arc::new(ExecutionCertificate::new(
            ec_wave_id,
            WeightedTimestamp(w.wave_id().block_height.0 + 1),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"gr")),
            std::mem::take(&mut outcomes),
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ));
        w.add_execution_certificate(ec_remote);

        let decisions: HashMap<TxHash, TransactionDecision> =
            w.tx_decisions().into_iter().collect();
        assert_eq!(decisions[&h1], TransactionDecision::Aborted);
        assert_eq!(decisions[&h2], TransactionDecision::Reject);
        assert_eq!(decisions[&h0], TransactionDecision::Accept);
    }
}
