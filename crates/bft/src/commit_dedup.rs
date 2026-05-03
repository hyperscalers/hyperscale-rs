//! Deduplication index for committed artifacts referenced by block contents.
//!
//! The BFT layer enforces a single contract: every committed artifact (tx,
//! cert, provision) appears in the chain exactly once. This index is the
//! mechanism — proposers consult it to filter candidates, validators consult
//! it to reject duplicate inclusions.
//!
//! Two complementary tiers share the index:
//!
//! 1. **Bridge buffer** (`recent_*`): hashes from blocks just committed by
//!    BFT, held synchronously until the post-commit registration path runs.
//!    Covers the gap where the just-committed block has been evicted from
//!    `pending_blocks` but the QC-chain walk doesn't yet see it via durable
//!    storage. Drained by `register_committed_*`.
//!
//! 2. **Retention lookup** (`*_retention`): per-artifact deadline maps
//!    surviving the bridge drain. Each entry is bounded by an artifact-
//!    specific BFT-attested horizon — for txs, the tx's own
//!    `end_timestamp_exclusive` (capped by `MAX_VALIDITY_RANGE` at
//!    admission); for certs, `vote_anchor_ts + RETENTION_HORIZON` from the
//!    wave's local EC; for provisions, `local_committed_ts +
//!    RETENTION_HORIZON` (a conservative surrogate for `source_weighted_ts`
//!    used because the source-shard QC ts isn't available at register
//!    time — `local_committed_ts >= source_weighted_ts` always). Pruned
//!    when `committed_ts >= deadline`. Past expiry, independent rules
//!    reject re-inclusion, so the entry is no longer correctness-bearing.

use hyperscale_types::{
    FinalizedWave, ProvisionHash, Provisions, RoutableTransaction, TxHash, WaveId,
    WeightedTimestamp,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
    recent_txs: HashSet<TxHash>,
    recent_certs: HashSet<WaveId>,
    recent_provisions: HashSet<ProvisionHash>,
}

impl CommitDedupIndex {
    pub fn new() -> Self {
        Self {
            tx_retention: HashMap::new(),
            cert_retention: HashMap::new(),
            provision_retention: HashMap::new(),
            recent_txs: HashSet::new(),
            recent_certs: HashSet::new(),
            recent_provisions: HashSet::new(),
        }
    }

    /// Buffer tx hashes, cert ids, and provision hashes from a freshly
    /// committed block. Called synchronously at BFT commit time; entries
    /// are cleared by `register_committed_*` once the post-commit
    /// registration path runs.
    pub fn buffer_commit(
        &mut self,
        tx_hashes: impl IntoIterator<Item = TxHash>,
        cert_ids: impl IntoIterator<Item = WaveId>,
        provision_hashes: impl IntoIterator<Item = ProvisionHash>,
    ) {
        self.recent_txs.extend(tx_hashes);
        self.recent_certs.extend(cert_ids);
        self.recent_provisions.extend(provision_hashes);
    }

    /// Promote a block's transactions from the bridge buffer into the
    /// retention lookup. Each entry's stored value is the tx's
    /// `validity_range.end_timestamp_exclusive`, which bounds the entry's
    /// lifetime. Called by the node state layer after the mempool
    /// processes a committed block.
    pub fn register_committed_txs(&mut self, transactions: &[Arc<RoutableTransaction>]) {
        for tx in transactions {
            let tx_hash = tx.hash();
            let end = tx.validity_range.end_timestamp_exclusive;
            self.tx_retention.entry(tx_hash).or_insert(end);
            self.recent_txs.remove(&tx_hash);
        }
    }

    /// Promote a block's finalized waves from the bridge buffer into the
    /// retention lookup. Each entry's deadline is the wave's local EC
    /// `vote_anchor_ts + RETENTION_HORIZON` — past that horizon, every tx
    /// the wave covered has terminated everywhere and no future block can
    /// legitimately reference the same `wave_id`.
    pub fn register_committed_certs(&mut self, finalized_waves: &[Arc<FinalizedWave>]) {
        for fw in finalized_waves {
            let wave_id = fw.wave_id().clone();
            let deadline = fw.local_ec().deadline();
            self.cert_retention
                .entry(wave_id.clone())
                .or_insert(deadline);
            self.recent_certs.remove(&wave_id);
        }
    }

    /// Promote a block's provisions from the bridge buffer into the
    /// retention lookup. Anchored on `local_committed_ts` (a conservative
    /// surrogate for `source_weighted_ts` — the source block was committed
    /// before we observed these provisions, so `local_committed_ts >=
    /// source_weighted_ts` always). Past `local_committed_ts +
    /// RETENTION_HORIZON`, every tx the batch carried has terminated
    /// everywhere.
    pub fn register_committed_provisions(
        &mut self,
        provisions: &[Arc<Provisions>],
        local_committed_ts: WeightedTimestamp,
    ) {
        let deadline = local_committed_ts.plus(hyperscale_types::RETENTION_HORIZON);
        for batch in provisions {
            let provision_hash = batch.hash();
            self.provision_retention
                .entry(provision_hash)
                .or_insert(deadline);
            self.recent_provisions.remove(&provision_hash);
        }
    }

    /// Remove a finalized transaction from the retention lookup. Called when
    /// a TC is committed, so the tx is no longer relevant for timeout
    /// validation.
    pub fn remove_tx(&mut self, tx_hash: &TxHash) {
        self.tx_retention.remove(tx_hash);
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

    pub fn recent_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.recent_txs.iter().copied()
    }

    pub fn recent_cert_ids(&self) -> impl Iterator<Item = WaveId> + '_ {
        self.recent_certs.iter().cloned()
    }

    pub fn recent_provision_hashes(&self) -> impl Iterator<Item = ProvisionHash> + '_ {
        self.recent_provisions.iter().copied()
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

    pub fn recent_txs_len(&self) -> usize {
        self.recent_txs.len()
    }

    pub fn recent_certs_len(&self) -> usize {
        self.recent_certs.len()
    }

    pub fn recent_provisions_len(&self) -> usize {
        self.recent_provisions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{
        BlockHeight, Hash, ShardGroupId, TimestampRange, routable_from_notarized_v1,
    };
    use std::collections::BTreeSet;

    fn wid(height: u64) -> WaveId {
        WaveId::new(ShardGroupId(0), BlockHeight(height), BTreeSet::new())
    }

    fn th(b: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(b))
    }

    /// Build a test tx whose `validity_range.end_timestamp_exclusive == end_ms`.
    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<RoutableTransaction> {
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(WeightedTimestamp::ZERO, WeightedTimestamp(end_ms));
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"))
    }

    #[test]
    fn buffered_hashes_surface_in_recent_iterators() {
        let mut cache = CommitDedupIndex::new();
        let c1 = wid(1);
        cache.buffer_commit([th(b"tx1"), th(b"tx2")], [c1.clone()], []);

        let txs: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        let certs: HashSet<WaveId> = cache.recent_cert_ids().collect();
        assert_eq!(txs, HashSet::from([th(b"tx1"), th(b"tx2")]));
        assert_eq!(certs, HashSet::from([c1]));
    }

    #[test]
    fn register_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommitDedupIndex::new();
        let tx1 = tx_with_end(1, 60_000);
        let tx1_hash = tx1.hash();
        // tx2 is in the bridge but not registered — it should stay buffered.
        let tx2_hash = th(b"tx2");
        cache.buffer_commit([tx1_hash, tx2_hash], [], []);
        cache.register_committed_txs(std::slice::from_ref(&tx1));

        assert!(cache.contains_tx(&tx1_hash));
        assert!(!cache.contains_tx(&tx2_hash));

        let remaining: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        assert_eq!(remaining, HashSet::from([tx2_hash]));
    }

    #[test]
    fn prune_drops_entries_past_their_end_exclusive() {
        let mut cache = CommitDedupIndex::new();
        let early = tx_with_end(1, 100);
        let later = tx_with_end(2, 900);
        let early_hash = early.hash();
        let later_hash = later.hash();
        cache.register_committed_txs(&[early, later]);

        // At now=500: early (end=100) is past expiry, later (end=900) survives.
        cache.prune(WeightedTimestamp(500));

        assert!(!cache.contains_tx(&early_hash));
        assert!(cache.contains_tx(&later_hash));
    }

    #[test]
    fn remove_clears_lookup() {
        let mut cache = CommitDedupIndex::new();
        let tx = tx_with_end(1, 60_000);
        let tx_hash = tx.hash();
        cache.register_committed_txs(&[tx]);

        cache.remove_tx(&tx_hash);

        assert!(!cache.contains_tx(&tx_hash));
    }

    // ─── Certs ──────────────────────────────────────────────────────────

    fn make_fw(height: u64) -> Arc<FinalizedWave> {
        Arc::new(hyperscale_test_helpers::make_finalized_wave(
            BlockHeight(height),
            TxHash::from_raw(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            hyperscale_types::TransactionDecision::Accept,
        ))
    }

    #[test]
    fn register_certs_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommitDedupIndex::new();
        let fw1 = make_fw(1);
        let fw2_id = wid(2);
        // fw1 is registered after being buffered; wid(2) stays in the bridge.
        cache.buffer_commit([], [fw1.wave_id().clone(), fw2_id.clone()], []);
        cache.register_committed_certs(std::slice::from_ref(&fw1));

        assert!(cache.contains_cert(fw1.wave_id()));
        assert!(!cache.contains_cert(&fw2_id));

        let remaining: HashSet<WaveId> = cache.recent_cert_ids().collect();
        assert_eq!(remaining, HashSet::from([fw2_id]));
    }

    #[test]
    fn prune_drops_certs_past_their_deadline() {
        // make_finalized_wave sets vote_anchor_ts = block_height + 1.
        // Deadline = vote_anchor_ts + RETENTION_HORIZON.
        let mut cache = CommitDedupIndex::new();
        let fw = make_fw(1);
        cache.register_committed_certs(&[Arc::clone(&fw)]);
        assert!(cache.contains_cert(fw.wave_id()));

        // At now=ZERO the deadline (ts(2) + horizon) is far in the future.
        cache.prune(WeightedTimestamp::ZERO);
        assert!(cache.contains_cert(fw.wave_id()));

        // Past the deadline: entry evicts.
        let past = fw
            .local_ec()
            .deadline()
            .plus(std::time::Duration::from_millis(1));
        cache.prune(past);
        assert!(!cache.contains_cert(fw.wave_id()));
    }

    // ─── Provisions ─────────────────────────────────────────────────────

    fn make_provisions(seed: u8) -> Arc<Provisions> {
        use hyperscale_types::{MerkleInclusionProof, ShardGroupId, TxEntries};
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(u64::from(seed)),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            }],
        ))
    }

    #[test]
    fn register_provisions_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommitDedupIndex::new();
        let p1 = make_provisions(1);
        let p2 = make_provisions(2);
        // p1 is registered after being buffered; p2 stays in the bridge.
        cache.buffer_commit([], [], [p1.hash(), p2.hash()]);
        cache.register_committed_provisions(std::slice::from_ref(&p1), WeightedTimestamp(1_000));

        assert!(cache.contains_provision(&p1.hash()));
        assert!(!cache.contains_provision(&p2.hash()));

        let remaining: HashSet<ProvisionHash> = cache.recent_provision_hashes().collect();
        assert_eq!(remaining, HashSet::from([p2.hash()]));
    }

    #[test]
    fn prune_drops_provisions_past_their_deadline() {
        let mut cache = CommitDedupIndex::new();
        let p = make_provisions(1);
        let now = WeightedTimestamp(1_000);
        cache.register_committed_provisions(std::slice::from_ref(&p), now);
        assert!(cache.contains_provision(&p.hash()));

        // Well within the horizon: entry survives.
        cache.prune(now);
        assert!(cache.contains_provision(&p.hash()));

        // Past `now + RETENTION_HORIZON`: entry evicts.
        let past = now
            .plus(hyperscale_types::RETENTION_HORIZON)
            .plus(std::time::Duration::from_millis(1));
        cache.prune(past);
        assert!(!cache.contains_provision(&p.hash()));
    }
}
