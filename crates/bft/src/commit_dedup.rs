//! Deduplication index for committed artifacts referenced by block contents.
//!
//! The BFT layer enforces a single contract: every committed artifact (tx,
//! cert, provision) appears in the chain exactly once. This index is the
//! mechanism — proposers consult it to filter candidates, validators
//! consult it to reject duplicate inclusions.
//!
//! Per-artifact deadline maps bound the index by artifact-specific
//! BFT-attested horizons:
//!
//! - **txs**: each tx's own `end_timestamp_exclusive` (capped by
//!   `MAX_VALIDITY_RANGE` at admission).
//! - **certs**: `vote_anchor_ts + RETENTION_HORIZON` from the wave's local
//!   EC.
//! - **provisions**: `local_committed_ts + RETENTION_HORIZON`, a
//!   conservative surrogate for `source_weighted_ts` (the source block was
//!   committed before we observed these provisions, so
//!   `local_committed_ts >= source_weighted_ts` always).
//!
//! Pruned when `committed_ts >= deadline`. Past expiry, independent rules
//! reject re-inclusion, so the entry is no longer correctness-bearing.
//!
//! Registration is synchronous with BFT commit (called from
//! [`crate::coordinator::BftCoordinator::record_block_committed`]) so the
//! just-committed block's contents are visible to any subsequent
//! `try_propose` in the same tick — closing the on-qc-formed re-inclusion
//! race without a separate bridge buffer.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_types::{
    FinalizedWave, ProvisionHash, Provisions, RETENTION_HORIZON, RoutableTransaction, TxHash,
    WaveId, WeightedTimestamp,
};

#[allow(clippy::struct_field_names)] // shared `_retention` postfix is the artifact-tier convention
pub struct CommitDedupIndex {
    /// `tx_hash → end_timestamp_exclusive`. Pruned when
    /// `end_timestamp_exclusive <= current_committed_ts`.
    tx_retention: HashMap<TxHash, WeightedTimestamp>,
    /// `wave_id → vote_anchor_ts + RETENTION_HORIZON`. Pruned when
    /// `deadline <= current_committed_ts`. Past the horizon, every tx the
    /// wave covered has terminated everywhere, so no future block can
    /// legitimately reference the same `wave_id`.
    cert_retention: HashMap<WaveId, WeightedTimestamp>,
    /// `provision_hash → local_committed_ts + RETENTION_HORIZON`. Pruned
    /// when `deadline <= current_committed_ts`. Past the horizon, every tx
    /// the batch carried has expired its `validity_range` and terminated
    /// everywhere, so no future block can legitimately reference the same
    /// content-addressed batch.
    provision_retention: HashMap<ProvisionHash, WeightedTimestamp>,
}

impl CommitDedupIndex {
    pub fn new() -> Self {
        Self {
            tx_retention: HashMap::new(),
            cert_retention: HashMap::new(),
            provision_retention: HashMap::new(),
        }
    }

    /// Record a block's transactions in the retention lookup. Each entry's
    /// stored value is the tx's `validity_range.end_timestamp_exclusive`.
    pub fn register_committed_txs(&mut self, transactions: &[Arc<RoutableTransaction>]) {
        for tx in transactions {
            let tx_hash = tx.hash();
            let end = tx.validity_range.end_timestamp_exclusive;
            self.tx_retention.entry(tx_hash).or_insert(end);
        }
    }

    /// Record a block's finalized waves in the retention lookup. Each
    /// entry's deadline is the wave's local EC `vote_anchor_ts +
    /// RETENTION_HORIZON`.
    pub fn register_committed_certs(&mut self, finalized_waves: &[Arc<FinalizedWave>]) {
        for fw in finalized_waves {
            let wave_id = fw.wave_id().clone();
            let deadline = fw.local_ec().deadline();
            self.cert_retention.entry(wave_id).or_insert(deadline);
        }
    }

    /// Record a block's provisions in the retention lookup. Anchored on
    /// `local_committed_ts` (a conservative surrogate for
    /// `source_weighted_ts`).
    pub fn register_committed_provisions(
        &mut self,
        provisions: &[Arc<Provisions>],
        local_committed_ts: WeightedTimestamp,
    ) {
        let deadline = local_committed_ts.plus(RETENTION_HORIZON);
        for batch in provisions {
            self.provision_retention
                .entry(batch.hash())
                .or_insert(deadline);
        }
    }

    /// Drop retention-lookup entries past their deadline. `now` is the
    /// `weighted_timestamp` of the latest committed block. Past expiry,
    /// independent rules (tx validity check; wave-timeout) reject any
    /// re-inclusion, so the entry is no longer correctness-bearing.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        self.tx_retention.retain(|_, end| *end > now);
        self.cert_retention.retain(|_, deadline| *deadline > now);
        self.provision_retention
            .retain(|_, deadline| *deadline > now);
    }

    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.tx_retention.contains_key(tx_hash)
    }

    pub fn contains_cert(&self, wave_id: &WaveId) -> bool {
        self.cert_retention.contains_key(wave_id)
    }

    pub fn contains_provision(&self, provision_hash: &ProvisionHash) -> bool {
        self.provision_retention.contains_key(provision_hash)
    }

    pub fn tx_retention_len(&self) -> usize {
        self.tx_retention.len()
    }

    pub fn cert_retention_len(&self) -> usize {
        self.cert_retention.len()
    }

    pub fn provision_retention_len(&self) -> usize {
        self.provision_retention.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_test_helpers::make_finalized_wave;
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{
        BlockHeight, Hash, MerkleInclusionProof, ShardGroupId, TimestampRange, TransactionDecision,
        TxEntries, routable_from_notarized_v1,
    };

    use super::*;

    /// Build a test tx whose `validity_range.end_timestamp_exclusive == end_ms`.
    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<RoutableTransaction> {
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(WeightedTimestamp::ZERO, WeightedTimestamp(end_ms));
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"))
    }

    fn make_fw(height: u64) -> Arc<FinalizedWave> {
        Arc::new(make_finalized_wave(
            BlockHeight::new(height),
            TxHash::from_raw(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            TransactionDecision::Accept,
        ))
    }

    fn make_provisions(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight::new(u64::from(seed)),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            }],
        ))
    }

    // ─── Txs ────────────────────────────────────────────────────────────

    #[test]
    fn register_txs_populates_retention() {
        let mut idx = CommitDedupIndex::new();
        let tx = tx_with_end(1, 60_000);
        let tx_hash = tx.hash();
        idx.register_committed_txs(std::slice::from_ref(&tx));
        assert!(idx.contains_tx(&tx_hash));
        assert_eq!(idx.tx_retention_len(), 1);
    }

    #[test]
    fn prune_drops_txs_past_their_end_exclusive() {
        let mut idx = CommitDedupIndex::new();
        let early = tx_with_end(1, 100);
        let later = tx_with_end(2, 900);
        let early_hash = early.hash();
        let later_hash = later.hash();
        idx.register_committed_txs(&[early, later]);

        idx.prune(WeightedTimestamp(500));

        assert!(!idx.contains_tx(&early_hash));
        assert!(idx.contains_tx(&later_hash));
    }

    // ─── Certs ──────────────────────────────────────────────────────────

    #[test]
    fn register_certs_populates_retention() {
        let mut idx = CommitDedupIndex::new();
        let fw = make_fw(1);
        idx.register_committed_certs(std::slice::from_ref(&fw));
        assert!(idx.contains_cert(fw.wave_id()));
        assert_eq!(idx.cert_retention_len(), 1);
    }

    #[test]
    fn prune_drops_certs_past_their_deadline() {
        // make_finalized_wave sets vote_anchor_ts = block_height + 1.
        // Deadline = vote_anchor_ts + RETENTION_HORIZON.
        let mut idx = CommitDedupIndex::new();
        let fw = make_fw(1);
        idx.register_committed_certs(&[Arc::clone(&fw)]);

        idx.prune(WeightedTimestamp::ZERO);
        assert!(idx.contains_cert(fw.wave_id()));

        let past = fw
            .local_ec()
            .deadline()
            .plus(std::time::Duration::from_millis(1));
        idx.prune(past);
        assert!(!idx.contains_cert(fw.wave_id()));
    }

    // ─── Provisions ─────────────────────────────────────────────────────

    #[test]
    fn register_provisions_populates_retention() {
        let mut idx = CommitDedupIndex::new();
        let p = make_provisions(1);
        idx.register_committed_provisions(std::slice::from_ref(&p), WeightedTimestamp(1_000));
        assert!(idx.contains_provision(&p.hash()));
        assert_eq!(idx.provision_retention_len(), 1);
    }

    #[test]
    fn prune_drops_provisions_past_their_deadline() {
        let mut idx = CommitDedupIndex::new();
        let p = make_provisions(1);
        let now = WeightedTimestamp(1_000);
        idx.register_committed_provisions(std::slice::from_ref(&p), now);

        idx.prune(now);
        assert!(idx.contains_provision(&p.hash()));

        let past = now
            .plus(RETENTION_HORIZON)
            .plus(std::time::Duration::from_millis(1));
        idx.prune(past);
        assert!(!idx.contains_provision(&p.hash()));
    }
}
