//! Provision absorption, conflict detection, and readiness tracking for
//! cross-shard transactions.
//!
//! Three correlated maps plus an inner [`ConflictDetector`]:
//!
//! - [`verified`](ProvisioningTracker::verified) — committed
//!   [`StateProvision`]s keyed by `tx_hash`. Feeds the cross-shard dispatch
//!   action for each tx.
//! - `required` — the set of remote shards each cross-shard tx needs
//!   provisions from. Populated when the tx's wave is created.
//! - `received` — the set of remote shards whose provisions have actually
//!   landed. Populated by [`absorb_provisions`](ProvisioningTracker::absorb_provisions).
//!
//! A tx is fully provisioned when `required ⊆ received`; that predicate is
//! surfaced as [`is_fully_provisioned`](ProvisioningTracker::is_fully_provisioned)
//! so callers never inspect the underlying sets.
//!
//! The [`ConflictDetector`] sits alongside as a field because conflict
//! resolution is only meaningful in the context of committed provisions —
//! both forward detection (via
//! [`detect_conflicts`](ProvisioningTracker::detect_conflicts)) and reverse
//! registration (via [`register_tx`](ProvisioningTracker::register_tx))
//! flow through the tracker.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_types::{
    NodeId, Provisions, RETENTION_HORIZON, ShardGroupId, StateProvision, TopologySnapshot, TxHash,
    WeightedTimestamp,
};

use crate::conflict::{ConflictDetector, DetectedConflict};

pub struct ProvisioningTracker {
    /// Verified provisions keyed by `tx_hash`. Written when provisions are
    /// absorbed; read when a cross-shard wave dispatches. Cleared on the
    /// terminal-state path ([`remove_tx`]) when a wave certificate
    /// commits, and swept by [`gc_stale_provisions`] for txs whose
    /// retention horizon elapsed without ever finalizing.
    verified: HashMap<TxHash, Vec<StateProvision>>,

    /// Remote shards each cross-shard tx needs provisions from. Populated
    /// at wave creation.
    required: HashMap<TxHash, BTreeSet<ShardGroupId>>,

    /// Remote shards whose provisions have been received. Populated by
    /// [`absorb_provisions`].
    received: HashMap<TxHash, BTreeSet<ShardGroupId>>,

    /// Per-tx retention deadline = the latest `now + RETENTION_HORIZON`
    /// observed at any insert point that touches the tx. Past the
    /// deadline the tx is provably terminal everywhere — every shard
    /// has either committed an EC for it or its `validity_range` has
    /// expired and any wave that admitted it has timed out. Anchored
    /// on BFT-attested `committed_ts`, matching the sender-side
    /// deadline used by [`OutboundProvisionTracker`](hyperscale_provisions::OutboundProvisionTracker).
    deadlines: HashMap<TxHash, WeightedTimestamp>,

    /// Latest BFT-attested local-commit weighted timestamp seen via
    /// [`advance_clock`]. Drives deadline stamping deterministically
    /// across validators.
    now: WeightedTimestamp,

    /// Detects node-ID overlap conflicts between local cross-shard txs and
    /// committed remote provisions. Deterministic because provisions are
    /// consensus-committed via `provision_root`.
    conflict_detector: ConflictDetector,
}

impl ProvisioningTracker {
    pub fn new() -> Self {
        Self {
            verified: HashMap::new(),
            required: HashMap::new(),
            received: HashMap::new(),
            deadlines: HashMap::new(),
            now: WeightedTimestamp::ZERO,
            conflict_detector: ConflictDetector::new(),
        }
    }

    /// Update the BFT-attested local-commit clock used for deadline
    /// stamping. Called once per `on_block_committed`. Monotone — out-of-order
    /// or stale calls are ignored.
    pub fn advance_clock(&mut self, now: WeightedTimestamp) {
        if now > self.now {
            self.now = now;
        }
    }

    /// Stamp `tx_hash` with a deadline of `self.now + RETENTION_HORIZON`,
    /// taking the latest of any existing entry. Idempotent re-stamping
    /// only ever extends the deadline forward, so a late-arriving
    /// provision never causes earlier eviction than its predecessor.
    fn stamp_deadline(&mut self, tx_hash: TxHash) {
        let deadline = self.now.plus(RETENTION_HORIZON);
        self.deadlines
            .entry(tx_hash)
            .and_modify(|d| {
                if deadline > *d {
                    *d = deadline;
                }
            })
            .or_insert(deadline);
    }

    // ─── Required / received ────────────────────────────────────────────

    /// Record the remote shards `tx_hash` needs provisions from. Overwrites
    /// any previous entry — callers set this once per wave creation.
    pub fn record_required(&mut self, tx_hash: TxHash, remote_shards: BTreeSet<ShardGroupId>) {
        self.required.insert(tx_hash, remote_shards);
        self.stamp_deadline(tx_hash);
    }

    /// Whether every remote shard's provision for `tx_hash` has been
    /// received. Returns `false` for txs with no recorded requirements
    /// (single-shard txs or txs we aren't tracking).
    pub fn is_fully_provisioned(&self, tx_hash: &TxHash) -> bool {
        self.required.get(tx_hash).is_some_and(|required| {
            self.received
                .get(tx_hash)
                .is_some_and(|received| required.is_subset(received))
        })
    }

    // ─── Batch absorption ───────────────────────────────────────────────

    /// Absorb a committed provisions. Adds one [`StateProvision`] per
    /// `tx_entry` to the verified map and records `provisions.source_shard`
    /// under `received[tx_hash]`.
    ///
    /// Returns the `tx_hash`es touched — the caller uses these to compute
    /// which local waves are affected and to drive the dispatch check.
    /// Preserves iteration order of `provisions.transactions` (callers sort
    /// batches upstream for determinism).
    pub fn absorb_provisions(
        &mut self,
        provisions: &Provisions,
        local_shard: ShardGroupId,
    ) -> Vec<TxHash> {
        let mut touched = Vec::with_capacity(provisions.transactions.len());
        let source_shard = provisions.source_shard;
        for tx_entry in provisions.transactions.iter() {
            let tx_hash = tx_entry.tx_hash;
            let provision = StateProvision {
                transaction_hash: tx_hash,
                target_shard: local_shard,
                source_shard,
                block_height: provisions.block_height,
                entries: Arc::new(tx_entry.entries.0.clone()),
            };
            self.verified.entry(tx_hash).or_default().push(provision);
            self.received
                .entry(tx_hash)
                .or_default()
                .insert(source_shard);
            self.stamp_deadline(tx_hash);
            touched.push(tx_hash);
        }
        touched
    }

    // ─── Conflict detection ─────────────────────────────────────────────

    /// Forward-register a local cross-shard tx against the conflict
    /// detector. Returns any reverse conflicts where the new tx loses to a
    /// previously-committed remote provision. Conflict resolution uses
    /// lower-hash-wins; the caller decides whether to apply each conflict
    /// (i.e. whether the tx is already fully provisioned — in which case
    /// execution can proceed and the deadlock resolution is moot).
    pub fn register_tx(
        &mut self,
        tx_hash: TxHash,
        topology: &TopologySnapshot,
        declared_reads: &[NodeId],
        declared_writes: &[NodeId],
    ) -> Vec<DetectedConflict> {
        self.conflict_detector
            .register_tx(tx_hash, topology, declared_reads, declared_writes)
    }

    /// Forward-detect conflicts as a remote provisions commits.
    /// Returns any conflicts where a local tx loses against the incoming
    /// provisions.
    pub fn detect_conflicts(
        &mut self,
        provisions: &Provisions,
        committed_at: WeightedTimestamp,
    ) -> Vec<DetectedConflict> {
        self.conflict_detector
            .detect_conflicts(provisions, committed_at)
    }

    /// Drop the conflict-detector's stored provision history older than
    /// the cutoff. Returns the number of entries removed.
    pub fn prune_old_provisions(&mut self, cutoff: WeightedTimestamp) -> usize {
        self.conflict_detector.prune_provisions_older_than(cutoff)
    }

    // ─── Terminal cleanup ───────────────────────────────────────────────

    /// Drop all state for `tx_hash` across every owned map. Called when a
    /// wave certificate commits and the transaction reaches terminal state.
    pub fn remove_tx(&mut self, tx_hash: &TxHash) {
        self.verified.remove(tx_hash);
        self.required.remove(tx_hash);
        self.received.remove(tx_hash);
        self.deadlines.remove(tx_hash);
        self.conflict_detector.remove_tx(tx_hash);
    }

    /// Drop tracker state for txs whose retention horizon elapsed without
    /// reaching wave finalization. Past `now + RETENTION_HORIZON` from the
    /// latest insert touching the tx, the tx is provably terminal everywhere
    /// — every shard has either committed an EC for it or its
    /// `validity_range` has expired and any wave that admitted it has timed
    /// out — so no future local wave can still consume the verified
    /// provisions. Returns the number of txs swept.
    pub fn gc_stale_provisions(&mut self, now_ts: WeightedTimestamp) -> usize {
        let stale: Vec<TxHash> = self
            .deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now_ts)
            .map(|(tx, _)| *tx)
            .collect();
        let count = stale.len();
        for tx in stale {
            self.remove_tx(&tx);
        }
        count
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Borrow the verified-provisions map. Used by the coordinator when
    /// passing it to `handlers::build_dispatch_action`, which needs a
    /// per-tx lookup and doesn't care about the surrounding tracker state.
    pub const fn verified(&self) -> &HashMap<TxHash, Vec<StateProvision>> {
        &self.verified
    }

    pub fn verified_len(&self) -> usize {
        self.verified.len()
    }

    pub fn required_len(&self) -> usize {
        self.required.len()
    }

    pub fn received_len(&self) -> usize {
        self.received.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, Hash, MerkleInclusionProof, TxEntries};

    use super::*;

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId::new(n)
    }

    fn make_provisions(
        source: ShardGroupId,
        block_height: BlockHeight,
        tx_hashes: Vec<TxHash>,
    ) -> Arc<Provisions> {
        let transactions: Vec<TxEntries> = tx_hashes
            .into_iter()
            .map(|tx_hash| TxEntries::new(tx_hash, vec![], vec![]))
            .collect();
        Arc::new(Provisions::new(
            source,
            ShardGroupId::new(0),
            block_height,
            MerkleInclusionProof::dummy(),
            transactions,
        ))
    }

    #[test]
    fn fresh_tracker_reports_no_state() {
        let t = ProvisioningTracker::new();
        assert_eq!(t.verified_len(), 0);
        assert_eq!(t.required_len(), 0);
        assert_eq!(t.received_len(), 0);
        assert!(!t.is_fully_provisioned(&TxHash::from_raw(Hash::from_bytes(b"missing"))));
    }

    #[test]
    fn is_fully_provisioned_requires_required_subset_of_received() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        t.record_required(tx, [shard(1), shard(2)].into_iter().collect());

        assert!(!t.is_fully_provisioned(&tx));

        // Only shard 1 landed.
        let batch1 = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&batch1, shard(0));
        assert!(!t.is_fully_provisioned(&tx));

        // Shard 2 lands → fully provisioned.
        let batch2 = make_provisions(shard(2), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&batch2, shard(0));
        assert!(t.is_fully_provisioned(&tx));
    }

    #[test]
    fn is_fully_provisioned_false_without_required_entry() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        // Absorbed provisions records `received[tx]` but there's no `required` —
        // the query must not report fully-provisioned just because
        // anything landed.
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&provisions, shard(0));
        assert!(!t.is_fully_provisioned(&tx));
    }

    #[test]
    fn absorb_provisions_returns_touched_tx_hashes_in_order() {
        let mut t = ProvisioningTracker::new();
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx_a, tx_b]);
        let touched = t.absorb_provisions(&provisions, shard(0));
        assert_eq!(touched, vec![tx_a, tx_b]);
    }

    #[test]
    fn absorb_provisions_populates_verified_and_received_maps() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&provisions, shard(0));

        assert_eq!(t.verified_len(), 1);
        assert_eq!(t.received_len(), 1);
        assert_eq!(
            t.verified.get(&tx).map_or(0, Vec::len),
            1,
            "one provision recorded per provisions entry"
        );
    }

    #[test]
    fn absorb_multiple_batches_for_same_tx_accumulates() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        t.absorb_provisions(
            &make_provisions(shard(1), BlockHeight::new(5), vec![tx]),
            shard(0),
        );
        t.absorb_provisions(
            &make_provisions(shard(2), BlockHeight::new(5), vec![tx]),
            shard(0),
        );

        // Two distinct source shards → two StateProvisions and two received
        // entries.
        assert_eq!(t.verified.get(&tx).map_or(0, Vec::len), 2);
        assert_eq!(
            t.received.get(&tx).map_or(0, BTreeSet::len),
            2,
            "received set contains both source shards"
        );
    }

    #[test]
    fn remove_tx_drops_state_from_every_owned_map() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        t.record_required(tx, std::iter::once(shard(1)).collect());
        let provisions = make_provisions(shard(1), BlockHeight::new(5), vec![tx]);
        t.absorb_provisions(&provisions, shard(0));
        assert!(t.is_fully_provisioned(&tx));

        t.remove_tx(&tx);

        assert!(!t.is_fully_provisioned(&tx));
        assert_eq!(t.verified_len(), 0);
        assert_eq!(t.required_len(), 0);
        assert_eq!(t.received_len(), 0);
    }

    #[test]
    fn record_required_overwrites_existing_entry() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        t.record_required(tx, std::iter::once(shard(1)).collect());
        // Re-record with a different requirement set.
        t.record_required(tx, [shard(1), shard(2)].into_iter().collect());
        assert_eq!(t.required.get(&tx).map_or(0, BTreeSet::len), 2);
    }

    #[test]
    fn gc_stale_provisions_evicts_past_horizon_and_keeps_fresh() {
        use hyperscale_types::RETENTION_HORIZON;

        let mut t = ProvisioningTracker::new();
        let tx_old = TxHash::from_raw(Hash::from_bytes(b"old"));
        let tx_fresh = TxHash::from_raw(Hash::from_bytes(b"fresh"));

        // Old tx absorbed at clock = ms(1_000).
        t.advance_clock(WeightedTimestamp::from_millis(1_000));
        t.record_required(tx_old, std::iter::once(shard(1)).collect());
        t.absorb_provisions(
            &make_provisions(shard(1), BlockHeight::new(5), vec![tx_old]),
            shard(0),
        );

        // Fresh tx absorbed at clock = ms(60_000).
        t.advance_clock(WeightedTimestamp::from_millis(60_000));
        t.record_required(tx_fresh, std::iter::once(shard(1)).collect());
        t.absorb_provisions(
            &make_provisions(shard(1), BlockHeight::new(6), vec![tx_fresh]),
            shard(0),
        );

        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX);
        // Past tx_old's deadline (1_000 + horizon) but not tx_fresh's
        // (60_000 + horizon).
        let now = WeightedTimestamp::from_millis(1_000 + horizon_ms + 1);
        assert!(now.as_millis() < 60_000 + horizon_ms);

        let evicted = t.gc_stale_provisions(now);
        assert_eq!(evicted, 1);

        assert!(!t.verified.contains_key(&tx_old));
        assert!(!t.received.contains_key(&tx_old));
        assert!(!t.required.contains_key(&tx_old));
        assert!(t.verified.contains_key(&tx_fresh));
        assert!(t.received.contains_key(&tx_fresh));
        assert!(t.required.contains_key(&tx_fresh));
    }

    #[test]
    fn gc_stale_provisions_late_insert_extends_deadline() {
        use hyperscale_types::RETENTION_HORIZON;

        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));

        // First insert at clock = ms(1_000) → deadline = 1_000 + horizon.
        t.advance_clock(WeightedTimestamp::from_millis(1_000));
        t.absorb_provisions(
            &make_provisions(shard(1), BlockHeight::new(5), vec![tx]),
            shard(0),
        );

        // Second insert at clock = ms(60_000) → deadline extended to
        // 60_000 + horizon.
        t.advance_clock(WeightedTimestamp::from_millis(60_000));
        t.absorb_provisions(
            &make_provisions(shard(2), BlockHeight::new(5), vec![tx]),
            shard(0),
        );

        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX);
        // Past the FIRST deadline but not the SECOND. Entry must survive.
        let now = WeightedTimestamp::from_millis(1_000 + horizon_ms + 1);
        assert_eq!(t.gc_stale_provisions(now), 0);
        assert!(t.verified.contains_key(&tx));
    }
}
