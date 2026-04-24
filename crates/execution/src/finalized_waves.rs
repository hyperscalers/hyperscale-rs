//! Terminal-state lookup for finalized waves.
//!
//! A wave lands here after its local EC is aggregated and every remote shard
//! has attested coverage — at that point the wave has a [`WaveCertificate`]
//! and its receipts are ready for block inclusion. Entries are removed by the
//! coordinator once the containing wave-cert block commits; until then the
//! store answers tx-membership and wave-id-hash lookups for peers that need
//! to fetch the finalized data to vote.
//!
//! This is write-once, read-many — the [`WaveRegistry`](crate::state) owns
//! the mutable in-flight lifecycle (waves, vote trackers, retries) and hands
//! wave off to this store at the moment of finalization.
//!
//! The underlying map is a `BTreeMap<WaveId, FinalizedWave>` so iteration is
//! deterministic — load-bearing for simulation determinism and for proposal
//! building, which iterates the store to include finalized waves in block
//! order.

use hyperscale_types::{
    BloomFilter, FinalizedWave, TxHash, WaveCertificate, WaveId, WaveIdHash, DEFAULT_FPR,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

pub(crate) struct FinalizedWaveStore {
    waves: BTreeMap<WaveId, FinalizedWave>,
}

impl FinalizedWaveStore {
    pub fn new() -> Self {
        Self {
            waves: BTreeMap::new(),
        }
    }

    /// Record a newly-finalized wave under its `WaveId`.
    pub fn insert(&mut self, wave_id: WaveId, fw: FinalizedWave) {
        self.waves.insert(wave_id, fw);
    }

    /// Remove the entry for `wave_id`, if any. No-op when absent (sync
    /// paths may remove a wave the local node never aggregated).
    pub fn remove(&mut self, wave_id: &WaveId) {
        self.waves.remove(wave_id);
    }

    /// All finalized waves in `WaveId` order, each wrapped in a fresh `Arc`.
    /// Used by the proposer to include finalized waves in the next block.
    pub fn all_waves(&self) -> Vec<Arc<FinalizedWave>> {
        self.waves.values().map(|fw| Arc::new(fw.clone())).collect()
    }

    /// Lookup by the hash of a wave's `WaveId`. Peers reference waves by
    /// `wave_id.hash()` in fetch requests, so this is the primary ingress
    /// lookup for serving finalized-wave data.
    pub fn get_by_wave_id_hash(&self, wave_id_hash: &WaveIdHash) -> Option<Arc<FinalizedWave>> {
        self.waves
            .values()
            .find(|fw| fw.certificate.wave_id.hash() == *wave_id_hash)
            .map(|fw| Arc::new(fw.clone()))
    }

    /// Certificate containing `tx_hash`, if any. Used to answer
    /// terminal-state queries for a single transaction (e.g. RPC, mempool
    /// status). Returns `None` once the wave has been removed — callers
    /// then fall back to persisted storage.
    pub fn get_certificate_for_tx(&self, tx_hash: &TxHash) -> Option<Arc<WaveCertificate>> {
        self.waves
            .values()
            .find(|fw| fw.contains_tx(tx_hash))
            .map(|fw| Arc::clone(&fw.certificate))
    }

    /// Whether `tx_hash` is part of any currently-tracked finalized wave.
    pub fn is_finalized(&self, tx_hash: &TxHash) -> bool {
        self.waves.values().any(|fw| fw.contains_tx(tx_hash))
    }

    /// Flatten every tracked wave's tx hashes into a single set.
    ///
    /// The node passes this to BFT for conflict filtering — a transaction
    /// whose wave is already finalized should not be re-proposed.
    pub fn all_tx_hashes(&self) -> HashSet<TxHash> {
        self.waves.values().flat_map(|fw| fw.tx_hashes()).collect()
    }

    /// Whether a wave with this `WaveId` is tracked. Used by debug/query
    /// paths to distinguish "wave is finalized" from "wave has no tracker".
    pub fn contains(&self, wave_id: &WaveId) -> bool {
        self.waves.contains_key(wave_id)
    }

    pub fn len(&self) -> usize {
        self.waves.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.waves.is_empty()
    }

    /// Build a bloom filter over every tracked `WaveIdHash`. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide finalized-wave certificates the requester already has.
    pub fn cert_bloom_snapshot(&self) -> Option<BloomFilter<WaveIdHash>> {
        let mut bf = BloomFilter::with_capacity(self.waves.len(), DEFAULT_FPR)?;
        for wave_id in self.waves.keys() {
            bf.insert(&wave_id.hash());
        }
        Some(bf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        zero_bls_signature, BlockHeight, ExecutionCertificate, ExecutionOutcome, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, ShardGroupId, SignerBitfield, TxHash, TxOutcome,
        WeightedTimestamp,
    };

    fn make_wave_id(block_height: u64) -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(0),
            block_height: BlockHeight(block_height),
            remote_shards: Default::default(),
        }
    }

    fn make_finalized_wave(block_height: u64, tx_hashes: &[TxHash]) -> (WaveId, FinalizedWave) {
        let wave_id = make_wave_id(block_height);
        let tx_outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| TxOutcome {
                tx_hash: *h,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    success: true,
                },
            })
            .collect();
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            tx_outcomes,
            zero_bls_signature(),
            SignerBitfield::new(4),
        );
        let cert = WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![Arc::new(ec)],
        };
        // Lookups in this module only inspect the certificate's outcomes; an
        // empty receipts vector is fine for the store's contract.
        let fw = FinalizedWave {
            certificate: Arc::new(cert),
            receipts: vec![],
        };
        (wave_id, fw)
    }

    #[test]
    fn empty_store_reports_no_finalized_state() {
        let store = FinalizedWaveStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(!store.is_finalized(&TxHash::from_raw(Hash::from_bytes(b"anything"))));
        assert!(store.all_tx_hashes().is_empty());
        assert!(store.all_waves().is_empty());
    }

    #[test]
    fn insert_then_lookup_by_tx_hash() {
        let mut store = FinalizedWaveStore::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let (wid, fw) = make_finalized_wave(1, &[tx]);

        store.insert(wid.clone(), fw);

        assert!(store.is_finalized(&tx));
        assert!(store.contains(&wid));
        assert_eq!(store.len(), 1);
        let cert = store.get_certificate_for_tx(&tx).expect("cert present");
        assert_eq!(cert.wave_id, wid);
    }

    #[test]
    fn lookup_by_wave_id_hash_matches_inserted_wave() {
        let mut store = FinalizedWaveStore::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let (wid, fw) = make_finalized_wave(1, &[tx]);
        let expected_hash = wid.hash();

        store.insert(wid.clone(), fw);

        let looked_up = store
            .get_by_wave_id_hash(&expected_hash)
            .expect("wave present by hash");
        assert_eq!(looked_up.certificate.wave_id, wid);

        // Unknown hash returns None.
        assert!(store
            .get_by_wave_id_hash(&WaveIdHash::from_raw(Hash::from_bytes(b"unknown")))
            .is_none());
    }

    #[test]
    fn all_tx_hashes_flattens_across_waves() {
        let mut store = FinalizedWaveStore::new();
        let a = TxHash::from_raw(Hash::from_bytes(b"a"));
        let b = TxHash::from_raw(Hash::from_bytes(b"b"));
        let c = TxHash::from_raw(Hash::from_bytes(b"c"));
        let (wid1, fw1) = make_finalized_wave(1, &[a, b]);
        let (wid2, fw2) = make_finalized_wave(2, &[c]);

        store.insert(wid1, fw1);
        store.insert(wid2, fw2);

        let all = store.all_tx_hashes();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&a));
        assert!(all.contains(&b));
        assert!(all.contains(&c));
    }

    #[test]
    fn remove_drops_only_the_named_wave() {
        let mut store = FinalizedWaveStore::new();
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from_raw(Hash::from_bytes(b"tx2"));
        let (wid1, fw1) = make_finalized_wave(1, &[tx1]);
        let (wid2, fw2) = make_finalized_wave(2, &[tx2]);

        store.insert(wid1.clone(), fw1);
        store.insert(wid2.clone(), fw2);

        store.remove(&wid1);

        assert!(!store.contains(&wid1));
        assert!(store.contains(&wid2));
        assert!(!store.is_finalized(&tx1));
        assert!(store.is_finalized(&tx2));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn cert_bloom_snapshot_contains_every_tracked_wave() {
        let mut store = FinalizedWaveStore::new();
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from_raw(Hash::from_bytes(b"tx2"));
        let (wid1, fw1) = make_finalized_wave(1, &[tx1]);
        let (wid2, fw2) = make_finalized_wave(2, &[tx2]);
        store.insert(wid1.clone(), fw1);
        store.insert(wid2.clone(), fw2);

        let bf = store.cert_bloom_snapshot().expect("sizing ok");
        assert!(bf.contains(&wid1.hash()));
        assert!(bf.contains(&wid2.hash()));
        // Untracked wave-id hash: exercises the filter's zero region.
        let absent = make_wave_id(99).hash();
        assert!(!bf.contains(&absent));
    }

    #[test]
    fn remove_absent_wave_is_noop() {
        let mut store = FinalizedWaveStore::new();
        let missing = make_wave_id(42);
        // No panic, no state change.
        store.remove(&missing);
        assert!(store.is_empty());
    }

    #[test]
    fn all_waves_iterates_in_wave_id_order() {
        let mut store = FinalizedWaveStore::new();
        let (wid_high, fw_high) =
            make_finalized_wave(5, &[TxHash::from_raw(Hash::from_bytes(b"hi"))]);
        let (wid_low, fw_low) =
            make_finalized_wave(1, &[TxHash::from_raw(Hash::from_bytes(b"lo"))]);

        store.insert(wid_high, fw_high);
        store.insert(wid_low, fw_low);

        let waves = store.all_waves();
        assert_eq!(waves.len(), 2);
        // BTreeMap iteration is ordered by key; lower block_height comes first.
        assert_eq!(waves[0].certificate.wave_id.block_height.0, 1);
        assert_eq!(waves[1].certificate.wave_id.block_height.0, 5);
    }
}
