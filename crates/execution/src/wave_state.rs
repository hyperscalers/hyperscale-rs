//! Per-wave execution state.
//!
//! One `WaveState` owns an in-flight wave from block commit through
//! finalization: per-tx execution progress, local vote generation, and
//! cross-shard EC collection all live here.
//!
//! ## Wave lifecycle
//!
//! 1. **Created** in `ExecutionState::on_block_committed` when waves are assigned
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
//! 4. **Votes** once all results present (or at the block-height +
//!    `WAVE_TIMEOUT_BLOCKS` deadline if still not provisioned — entire wave
//!    aborts).
//! 5. **Collects ECs** from all participating shards via
//!    `add_execution_certificate`. When every tx is covered (or aborted, which
//!    is terminal-covered), the wave is complete and ready for finalization.

use hyperscale_types::{
    compute_execution_receipt_root, ExecutionCertificate, ExecutionOutcome, Hash,
    RoutableTransaction, ShardGroupId, TransactionDecision, TxOutcome, WaveCertificate, WaveId,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Number of blocks after wave start before a not-fully-provisioned wave is
/// aborted in its entirety. Deterministic — every validator computes the same
/// timeout from the same wave start height.
pub const WAVE_TIMEOUT_BLOCKS: u64 = 32;

/// Age at which a still-alive wave emits a single diagnostic warning. Set
/// comfortably past `WAVE_TIMEOUT_BLOCKS` so that waves resolving via the
/// normal timeout-abort path (including cross-shard cert gossip) pass
/// silently; only genuinely-wedged waves surface.
pub const WAVE_OVERDUE_WARN_BLOCKS: u64 = 64;

/// Per-wave state across the entire execution lifecycle.
#[derive(Debug)]
pub struct WaveState {
    // ── Identity ────────────────────────────────────────────────────────
    wave_id: WaveId,
    block_hash: Hash,
    /// Wave-starting block height (= `wave_id.block_height`).
    block_height: u64,

    // ── Tx layout (in block order) ──────────────────────────────────────
    tx_hashes: Vec<Hash>,
    /// Participating shards per tx — the shards whose ECs must cover each tx
    /// for completion. Always includes local shard; cross-shard txs include
    /// remote shards too.
    participating_shards: HashMap<Hash, BTreeSet<ShardGroupId>>,
    /// O(1) membership check (mirrors `tx_hashes`).
    tx_hash_set: HashSet<Hash>,
    /// Transactions owned by the wave, used to build execution requests at
    /// dispatch time.
    transactions: HashMap<Hash, Arc<RoutableTransaction>>,

    // ── Provisioning phase ──────────────────────────────────────────────
    /// Txs whose required remote-shard provisions have all arrived.
    provisioned_txs: HashSet<Hash>,
    /// Per-tx earliest ready height. `all_provisioned_at` is the max across
    /// this map — deterministic regardless of call order.
    provisioned_tx_heights: HashMap<Hash, u64>,
    /// The block height at which every tx in the wave became ready. `None`
    /// until `provisioned_txs` is full.
    all_provisioned_at: Option<u64>,
    /// Whether execution has been dispatched (single `ExecuteTransactions` /
    /// `ExecuteCrossShardTransactions` emitted). Set true once execution fires.
    dispatched: bool,

    // ── Local execution outputs ─────────────────────────────────────────
    /// Execution results from the engine (per-tx). Non-abort outcomes only.
    execution_results: HashMap<Hash, ExecutionOutcome>,
    /// Explicit aborts from `ConflictDetector`. Value = the local block height
    /// at which the conflict was committed. Distinct from remote-reported
    /// aborts in `tracker_aborted` — these are local pre-vote decisions.
    explicit_aborts: HashMap<Hash, u64>,
    /// Whether the local vote has been emitted (`build_vote_data` called once).
    voted: bool,
    /// Whether the local EC has been added to `execution_certificates`. Gates
    /// wave completion: `is_complete` requires the local EC to be present.
    local_ec_emitted: bool,

    // ── Cross-shard EC collection ───────────────────────────────────────
    /// Per-tx, which shards have reported via an EC.
    covered_shards: HashMap<Hash, BTreeSet<ShardGroupId>>,
    /// Per-tx, whether any shard's EC reported abort. Terminal — an aborted tx
    /// doesn't require further remote coverage.
    tracker_aborted: HashSet<Hash>,
    /// Per-tx, whether any shard's EC reported a non-success outcome.
    tx_has_failure: HashSet<Hash>,
    /// All collected ECs (local + remote).
    execution_certificates: Vec<Arc<ExecutionCertificate>>,
    /// Deduplication of received ECs by canonical hash.
    seen_ec_hashes: HashSet<Hash>,
}

impl WaveState {
    /// Create a new wave state.
    ///
    /// `txs` is in block order. Each entry is `(transaction, participating_shards)`.
    /// `single_shard` indicates whether this is a single-shard wave (`remote_shards` empty);
    /// if so, `all_provisioned_at` is set to `block_height` immediately.
    pub fn new(
        wave_id: WaveId,
        block_hash: Hash,
        block_height: u64,
        txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)>,
        single_shard: bool,
    ) -> Self {
        let mut tx_hashes: Vec<Hash> = Vec::with_capacity(txs.len());
        let mut transactions: HashMap<Hash, Arc<RoutableTransaction>> =
            HashMap::with_capacity(txs.len());
        let mut participating_shards: HashMap<Hash, BTreeSet<ShardGroupId>> =
            HashMap::with_capacity(txs.len());
        let mut covered_shards: HashMap<Hash, BTreeSet<ShardGroupId>> =
            HashMap::with_capacity(txs.len());

        for (tx, shards) in txs {
            let h = tx.hash();
            tx_hashes.push(h);
            transactions.insert(h, tx);
            participating_shards.insert(h, shards);
            covered_shards.insert(h, BTreeSet::new());
        }

        let tx_hash_set: HashSet<Hash> = tx_hashes.iter().copied().collect();

        // Single-shard waves are trivially provisioned at creation.
        let (provisioned_txs, provisioned_tx_heights, all_provisioned_at) = if single_shard {
            let heights: HashMap<Hash, u64> =
                tx_hashes.iter().map(|h| (*h, block_height)).collect();
            (tx_hash_set.clone(), heights, Some(block_height))
        } else {
            (HashSet::new(), HashMap::new(), None)
        };

        Self {
            wave_id,
            block_hash,
            block_height,
            tx_hashes,
            participating_shards,
            tx_hash_set,
            transactions,
            provisioned_txs,
            provisioned_tx_heights,
            all_provisioned_at,
            dispatched: false,
            execution_results: HashMap::new(),
            explicit_aborts: HashMap::new(),
            voted: false,
            local_ec_emitted: false,
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

    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }

    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn tx_hashes(&self) -> &[Hash] {
        &self.tx_hashes
    }

    /// Transaction data by hash (for building execution requests).
    pub fn transaction(&self, tx_hash: &Hash) -> Option<&Arc<RoutableTransaction>> {
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

    /// Mark a single tx as provisioned. Keeps the earliest `at_height` per tx
    /// so the wave's transition height is a pure function of the event set.
    ///
    /// Returns `true` iff this call transitioned the wave from "partial" to
    /// "all provisioned" — the caller uses that signal to emit the single
    /// per-wave execution dispatch action.
    pub fn mark_tx_provisioned(&mut self, tx_hash: Hash, at_height: u64) -> bool {
        if !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }

        self.provisioned_tx_heights
            .entry(tx_hash)
            .and_modify(|h| *h = (*h).min(at_height))
            .or_insert(at_height);

        let is_new = self.provisioned_txs.insert(tx_hash);

        if is_new
            && self.all_provisioned_at.is_none()
            && self.provisioned_txs.len() == self.tx_hashes.len()
        {
            let max_height = self
                .provisioned_tx_heights
                .values()
                .copied()
                .max()
                .unwrap_or(at_height);
            self.all_provisioned_at = Some(max_height);
            true
        } else {
            false
        }
    }

    // ── Local execution bookkeeping ─────────────────────────────────────

    /// Record an execution outcome from the engine. First-write-wins.
    /// Returns `true` if the wave now has an outcome (execution result or
    /// explicit abort) for every tx.
    pub fn record_execution_result(&mut self, tx_hash: Hash, outcome: ExecutionOutcome) -> bool {
        if !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }
        self.execution_results.entry(tx_hash).or_insert(outcome);
        self.has_outcome_for_every_tx()
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
    pub fn record_abort(&mut self, tx_hash: Hash, committed_at_height: u64) -> bool {
        if self.dispatched || !self.tx_hash_set.contains(&tx_hash) {
            return false;
        }
        self.explicit_aborts
            .entry(tx_hash)
            .and_modify(|h| *h = (*h).min(committed_at_height))
            .or_insert(committed_at_height);
        self.mark_tx_provisioned(tx_hash, committed_at_height);
        self.has_outcome_for_every_tx()
    }

    /// True if each tx has either an execution result or an explicit abort.
    fn has_outcome_for_every_tx(&self) -> bool {
        self.tx_hashes
            .iter()
            .all(|h| self.execution_results.contains_key(h) || self.explicit_aborts.contains_key(h))
    }

    /// True if, for every non-aborted tx in the wave, local execution has
    /// produced a result. Aborted txs (via pre-dispatch conflict, explicit
    /// intent, or cert-attested `Aborted` outcome) don't require a receipt.
    ///
    /// Gates [`Self::is_complete`] so `finalize_wave` can't run while any
    /// non-aborted tx's receipt is still in flight from the engine —
    /// without this check, a cross-shard wave whose local EC arrives
    /// before this validator's engine results would finalize with missing
    /// receipts.
    fn has_local_receipts_for_non_aborted(&self) -> bool {
        self.tx_hashes.iter().all(|h| {
            self.tracker_aborted.contains(h)
                || self.explicit_aborts.contains_key(h)
                || self.execution_results.contains_key(h)
        })
    }

    // ── Vote emission ───────────────────────────────────────────────────

    /// Vote height (relative to `block_height`):
    /// - If fully provisioned: `all_provisioned_at - block_height`
    /// - Else: `WAVE_TIMEOUT_BLOCKS` (wave-abort case)
    fn target_vote_height(&self) -> u64 {
        match self.all_provisioned_at {
            Some(h) => h.saturating_sub(self.block_height),
            None => WAVE_TIMEOUT_BLOCKS,
        }
    }

    /// Whether the local vote can be emitted at the given committed height.
    ///
    /// Two branches:
    /// - Fully provisioned: need `committed_height >= all_provisioned_at` AND
    ///   every tx has an execution result or explicit abort.
    /// - Not provisioned: wait until `committed_height >= block_height + WAVE_TIMEOUT_BLOCKS`.
    ///   Upon timeout, every tx in the wave is implicitly aborted.
    pub fn can_emit_vote(&self, committed_height: u64) -> bool {
        if self.voted {
            return false;
        }
        match self.all_provisioned_at {
            Some(provisioned_at) => {
                committed_height >= provisioned_at && self.has_outcome_for_every_tx()
            }
            None => committed_height >= self.block_height + WAVE_TIMEOUT_BLOCKS,
        }
    }

    /// Build vote payload at the target height, consuming the one-shot vote.
    ///
    /// Returns `(vote_height, global_receipt_root, tx_outcomes)`. Returns
    /// `None` if `can_emit_vote` is false.
    ///
    /// In the timeout-abort branch (`all_provisioned_at = None`), every tx
    /// gets an `ExecutionOutcome::Aborted`. In the provisioned branch, each
    /// tx's outcome is its explicit abort (if any) or execution result.
    pub fn build_vote_data(
        &mut self,
        committed_height: u64,
    ) -> Option<(u64, Hash, Vec<TxOutcome>)> {
        if !self.can_emit_vote(committed_height) {
            return None;
        }

        let target = self.target_vote_height();
        let timed_out = self.all_provisioned_at.is_none();

        let outcomes: Vec<TxOutcome> = self
            .tx_hashes
            .iter()
            .map(|tx_hash| {
                let outcome = if timed_out || self.explicit_aborts.contains_key(tx_hash) {
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
    pub fn is_tx_explicitly_aborted(&self, tx_hash: &Hash) -> bool {
        self.explicit_aborts.contains_key(tx_hash)
    }

    /// Emit a `warn!` log exactly once, when the wave reaches
    /// `WAVE_OVERDUE_WARN_BLOCKS` of age without completing. Dumps enough
    /// state to diagnose what phase it's stuck in (provisioning / dispatch /
    /// voting / EC collection). Called once per committed block per surviving
    /// wave; the `==` guard ensures a single emission per wave.
    pub fn log_if_overdue(&self, committed_height: u64) {
        let age = committed_height.saturating_sub(self.block_height);
        if age != WAVE_OVERDUE_WARN_BLOCKS {
            return;
        }

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
            block_height = self.block_height,
            committed_height,
            age_blocks = age,
            timeout_blocks = WAVE_TIMEOUT_BLOCKS,
            num_txs = total,
            provisioned = format!("{}/{}", provisioned, total),
            all_provisioned_at = ?self.all_provisioned_at,
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
        let required_remote_ec_hashes: HashSet<Hash> = self
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
    pub fn tx_decisions(&self) -> Vec<(Hash, TransactionDecision)> {
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
        Bls12381G2Signature, SignerBitfield,
    };

    const WAVE_START: u64 = 10;

    fn make_tx(seed: u8) -> Arc<RoutableTransaction> {
        Arc::new(test_transaction_with_nodes(
            &[seed, seed + 1, seed + 2],
            vec![test_node(seed)],
            vec![test_node(seed + 50)],
        ))
    }

    fn make_single_shard_wave(n: usize) -> WaveState {
        let txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)> = (0..n)
            .map(|i| (make_tx(i as u8), BTreeSet::from([ShardGroupId(0)])))
            .collect();
        WaveState::new(
            WaveId::new(ShardGroupId(0), WAVE_START, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            WAVE_START,
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
            Hash::from_bytes(b"block"),
            WAVE_START,
            txs,
            false,
        )
    }

    fn executed(success: bool) -> ExecutionOutcome {
        ExecutionOutcome::Executed {
            receipt_hash: Hash::from_bytes(b"r"),
            success,
        }
    }

    fn make_ec(
        wave_id: &WaveId,
        ec_shard: ShardGroupId,
        tx_hashes: &[Hash],
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
            wave_id.block_height + 1,
            Hash::from_bytes(b"global_receipt_root"),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn single_shard_is_provisioned_on_creation() {
        let w = make_single_shard_wave(2);
        assert!(w.is_fully_provisioned());
        assert_eq!(w.all_provisioned_at, Some(WAVE_START));
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

        assert!(!w.mark_tx_provisioned(h0, WAVE_START + 1));
        assert!(!w.is_fully_provisioned());
        assert!(w.mark_tx_provisioned(h1, WAVE_START + 2));
        assert!(w.is_fully_provisioned());
        assert_eq!(w.all_provisioned_at, Some(WAVE_START + 2));

        // Idempotent: repeat calls don't retransition.
        assert!(!w.mark_tx_provisioned(h1, WAVE_START + 3));
    }

    #[test]
    fn can_emit_vote_requires_results_when_provisioned() {
        let mut w = make_single_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // No results yet.
        assert!(!w.can_emit_vote(WAVE_START));

        w.record_execution_result(h0, executed(true));
        assert!(!w.can_emit_vote(WAVE_START));

        w.record_execution_result(h1, executed(true));
        assert!(w.can_emit_vote(WAVE_START));
    }

    #[test]
    fn timeout_abort_without_provisions() {
        let mut w = make_cross_shard_wave(2);

        // Not yet at timeout.
        assert!(!w.can_emit_vote(WAVE_START + WAVE_TIMEOUT_BLOCKS - 1));

        // Exactly at timeout — all txs implicitly abort.
        assert!(w.can_emit_vote(WAVE_START + WAVE_TIMEOUT_BLOCKS));

        let (vh, _root, outcomes) = w.build_vote_data(WAVE_START + WAVE_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(vh, WAVE_TIMEOUT_BLOCKS);
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

        assert!(w.build_vote_data(WAVE_START).is_some());
        // Already voted; can't again.
        assert!(!w.can_emit_vote(WAVE_START + 100));
        assert!(w.build_vote_data(WAVE_START + 100).is_none());
    }

    #[test]
    fn explicit_abort_produces_abort_outcome() {
        let mut w = make_single_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        w.record_execution_result(h0, executed(true));
        w.record_abort(h1, WAVE_START + 3);

        let (_, _, outcomes) = w.build_vote_data(WAVE_START + 3).unwrap();
        assert!(matches!(
            outcomes[0].outcome,
            ExecutionOutcome::Executed { .. }
        ));
        assert!(matches!(outcomes[1].outcome, ExecutionOutcome::Aborted));
    }

    #[test]
    fn abort_keeps_earliest_height() {
        let mut w = make_single_shard_wave(1);
        let h0 = w.tx_hashes()[0];
        w.record_abort(h0, 20);
        w.record_abort(h0, 15);
        assert_eq!(w.explicit_aborts.get(&h0), Some(&15));
    }

    #[test]
    fn cross_shard_wave_requires_local_and_remote_ec() {
        let mut w = make_cross_shard_wave(2);
        let h0 = w.tx_hashes()[0];
        let h1 = w.tx_hashes()[1];

        // Fully provision and execute locally.
        w.mark_tx_provisioned(h0, WAVE_START + 1);
        w.mark_tx_provisioned(h1, WAVE_START + 1);
        w.record_execution_result(h0, executed(true));
        w.record_execution_result(h1, executed(true));

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

        w.mark_tx_provisioned(h0, WAVE_START + 1);
        w.mark_tx_provisioned(h1, WAVE_START + 1);

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
        w.record_execution_result(h0, executed(true));
        assert!(!w.is_complete());

        // Second result — now fully resolvable.
        w.record_execution_result(h1, executed(true));
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

        w.mark_tx_provisioned(h0, WAVE_START + 1);
        w.mark_tx_provisioned(h1, WAVE_START + 1);

        // Local EC attests both txs aborted. No execution results needed.
        let ec_local = make_ec(w.wave_id(), ShardGroupId(0), &[h0, h1], false);
        w.add_execution_certificate(ec_local);
        assert!(
            w.is_complete(),
            "all-aborted wave resolves without local engine results"
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
        w.mark_tx_provisioned(h0, WAVE_START + 1);
        w.mark_tx_provisioned(h1, WAVE_START + 1);
        assert!(w.mark_dispatched());

        // A post-dispatch conflict abort must be rejected.
        assert!(!w.record_abort(h0, WAVE_START + 2));
        // No explicit abort was recorded.
        w.record_execution_result(h0, executed(true));
        w.record_execution_result(h1, executed(true));
        // If record_abort had mutated, h0's outcome would have flipped to Aborted.
        let (_, _, outcomes) = w.build_vote_data(WAVE_START + 2).unwrap();
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
            w.wave_id().block_height + 1,
            Hash::from_bytes(b"gr"),
            std::mem::take(&mut outcomes),
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ));
        w.add_execution_certificate(ec_remote);

        let decisions: HashMap<Hash, TransactionDecision> = w.tx_decisions().into_iter().collect();
        assert_eq!(decisions[&h1], TransactionDecision::Aborted);
        assert_eq!(decisions[&h2], TransactionDecision::Reject);
        assert_eq!(decisions[&h0], TransactionDecision::Accept);
    }
}
