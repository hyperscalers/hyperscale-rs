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

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    NodeId, Provisions, ShardGroupId, StateProvision, TopologySnapshot, TxHash, WeightedTimestamp,
};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use crate::conflict::{ConflictDetector, DetectedConflict};

pub(crate) struct ProvisioningTracker {
    /// Verified provisions keyed by `tx_hash`. Written when provisions are
    /// absorbed; read when a cross-shard wave dispatches. Cleaned only when
    /// the wave certificate is committed (terminal state).
    verified: HashMap<TxHash, Vec<StateProvision>>,

    /// Remote shards each cross-shard tx needs provisions from. Populated
    /// at wave creation.
    required: HashMap<TxHash, BTreeSet<ShardGroupId>>,

    /// Remote shards whose provisions have been received. Populated by
    /// [`absorb_provisions`].
    received: HashMap<TxHash, BTreeSet<ShardGroupId>>,

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
            conflict_detector: ConflictDetector::new(),
        }
    }

    // ─── Required / received ────────────────────────────────────────────

    /// Record the remote shards `tx_hash` needs provisions from. Overwrites
    /// any previous entry — callers set this once per wave creation.
    pub fn record_required(&mut self, tx_hash: TxHash, remote_shards: BTreeSet<ShardGroupId>) {
        self.required.insert(tx_hash, remote_shards);
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
        for tx_entry in &provisions.transactions {
            let tx_hash = tx_entry.tx_hash;
            let provision = StateProvision {
                transaction_hash: tx_hash,
                target_shard: local_shard,
                source_shard,
                block_height: provisions.block_height,
                entries: Arc::new(tx_entry.entries.clone()),
            };
            self.verified.entry(tx_hash).or_default().push(provision);
            self.received
                .entry(tx_hash)
                .or_default()
                .insert(source_shard);
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
        self.conflict_detector.remove_tx(tx_hash);
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Borrow the verified-provisions map. Used by the coordinator when
    /// passing it to `handlers::build_dispatch_action`, which needs a
    /// per-tx lookup and doesn't care about the surrounding tracker state.
    pub fn verified(&self) -> &HashMap<TxHash, Vec<StateProvision>> {
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
    use super::*;
    use hyperscale_types::{BlockHeight, MerkleInclusionProof, TxEntries};

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId(n)
    }

    fn make_provisions(
        source: ShardGroupId,
        block_height: BlockHeight,
        tx_hashes: Vec<TxHash>,
    ) -> Arc<Provisions> {
        let transactions: Vec<TxEntries> = tx_hashes
            .into_iter()
            .map(|tx_hash| TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            })
            .collect();
        Arc::new(Provisions::new(
            source,
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
        let batch1 = make_provisions(shard(1), BlockHeight(5), vec![tx]);
        t.absorb_provisions(&batch1, shard(0));
        assert!(!t.is_fully_provisioned(&tx));

        // Shard 2 lands → fully provisioned.
        let batch2 = make_provisions(shard(2), BlockHeight(5), vec![tx]);
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
        let provisions = make_provisions(shard(1), BlockHeight(5), vec![tx]);
        t.absorb_provisions(&provisions, shard(0));
        assert!(!t.is_fully_provisioned(&tx));
    }

    #[test]
    fn absorb_provisions_returns_touched_tx_hashes_in_order() {
        let mut t = ProvisioningTracker::new();
        let tx_a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let tx_b = TxHash::from_raw(Hash::from_bytes(b"b"));
        let provisions = make_provisions(shard(1), BlockHeight(5), vec![tx_a, tx_b]);
        let touched = t.absorb_provisions(&provisions, shard(0));
        assert_eq!(touched, vec![tx_a, tx_b]);
    }

    #[test]
    fn absorb_provisions_populates_verified_and_received_maps() {
        let mut t = ProvisioningTracker::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let provisions = make_provisions(shard(1), BlockHeight(5), vec![tx]);
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
            &make_provisions(shard(1), BlockHeight(5), vec![tx]),
            shard(0),
        );
        t.absorb_provisions(
            &make_provisions(shard(2), BlockHeight(5), vec![tx]),
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
        t.record_required(tx, [shard(1)].into_iter().collect());
        let provisions = make_provisions(shard(1), BlockHeight(5), vec![tx]);
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
        t.record_required(tx, [shard(1)].into_iter().collect());
        // Re-record with a different requirement set.
        t.record_required(tx, [shard(1), shard(2)].into_iter().collect());
        assert_eq!(t.required.get(&tx).map_or(0, BTreeSet::len), 2);
    }
}
