//! Pending block assembly.
//!
//! Tracks blocks being assembled from headers + gossiped transactions + finalized waves.

use hyperscale_core::Action;
#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockManifest, FinalizedWave, Provision, ProvisionHash,
    RoutableTransaction, TopologySnapshot, TxHash, WaveIdHash,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Tracks a block being assembled from header + gossiped transactions + finalized waves.
///
/// # Lifecycle
///
/// 1. Created from BlockHeader (all transactions/waves marked as absent by hash)
/// 2. Full Transaction objects arrive via gossip (stored in received_transactions map)
/// 3. FinalizedWaves arrive when verifier independently finalizes each wave
///    (carries certificate + receipts + ECs)
/// 4. When all transactions and finalized waves received, block can be constructed
/// 5. Block stored to storage
/// 6. Block ready for voting
#[derive(Debug, Clone)]
pub struct PendingBlock {
    /// Block header (received first).
    header: BlockHeader,

    /// Block contents manifest (transaction hashes, certificates, etc.)
    manifest: BlockManifest,

    /// Map of transaction hash -> Arc<RoutableTransaction> (for received transactions).
    received_transactions: HashMap<TxHash, Arc<RoutableTransaction>>,

    /// Set of transaction hashes we're still waiting for (HashSet for O(1) lookup).
    missing_transaction_hashes: HashSet<TxHash>,

    /// Map of wave_id hash -> Arc<FinalizedWave> (carries cert + receipts + ECs).
    ///
    /// A block is complete once
    /// all its waves have been independently finalized by this validator.
    received_waves: BTreeMap<WaveIdHash, Arc<FinalizedWave>>,

    /// Set of wave_id hashes we're still waiting for.
    missing_wave_hashes: HashSet<WaveIdHash>,

    /// Received provision batches keyed by batch hash. BTreeMap so
    /// `provisions()` iteration is deterministic across validators.
    received_provisions: BTreeMap<ProvisionHash, Arc<Provision>>,

    /// Set of provision batch hashes we're still waiting for.
    missing_provision_hashes: HashSet<ProvisionHash>,

    /// The fully constructed block (None until all transactions/waves received).
    constructed_block: Option<Arc<Block>>,

    /// Time at which this pending block was first observed. Used to schedule
    /// fetch requests for missing data after a gossip grace period.
    created_at: Duration,
}

impl PendingBlock {
    /// Create a pending block from a header and manifest.
    pub fn from_manifest(
        header: BlockHeader,
        manifest: BlockManifest,
        created_at: Duration,
    ) -> Self {
        let total_tx_count = manifest.transaction_count();
        let missing_transaction_hashes: HashSet<TxHash> =
            manifest.tx_hashes.iter().copied().collect();
        let missing_wave_hashes: HashSet<WaveIdHash> =
            manifest.cert_hashes.iter().copied().collect();
        let missing_provision_hashes: HashSet<ProvisionHash> =
            manifest.provision_hashes.iter().copied().collect();

        Self {
            header,
            received_transactions: HashMap::with_capacity(total_tx_count),
            missing_transaction_hashes,
            received_waves: BTreeMap::new(),
            missing_wave_hashes,
            received_provisions: BTreeMap::new(),
            missing_provision_hashes,
            manifest,
            constructed_block: None,
            created_at,
        }
    }

    /// Create a pending block from a complete block (proposer's own block).
    ///
    /// The proposer already has all transactions, finalized waves, and provision
    /// batches. Provision hashes are derived (and sorted) from the batches so the
    /// resulting `PendingBlock` is self-contained: both the manifest hashes and
    /// `received_provisions` are populated from the same source.
    pub fn from_complete_block(
        block: &Block,
        finalized_waves: Vec<Arc<FinalizedWave>>,
        provisions: Vec<Arc<Provision>>,
        created_at: Duration,
    ) -> Self {
        let mut provision_hashes: Vec<ProvisionHash> =
            provisions.iter().map(|p| p.hash()).collect();
        provision_hashes.sort();
        let mut manifest = BlockManifest::from_block(block);
        manifest.provision_hashes = provision_hashes;
        let mut received_provisions: BTreeMap<ProvisionHash, Arc<Provision>> = BTreeMap::new();
        for batch in provisions {
            received_provisions.insert(batch.hash(), batch);
        }
        let mut pending = Self {
            header: block.header().clone(),
            received_transactions: HashMap::new(),
            missing_transaction_hashes: HashSet::new(),
            received_waves: BTreeMap::new(),
            missing_wave_hashes: HashSet::new(),
            received_provisions,
            missing_provision_hashes: HashSet::new(),
            manifest,
            constructed_block: None,
            created_at,
        };
        // Fill in all transactions
        for tx in block.transactions() {
            pending
                .received_transactions
                .insert(tx.hash(), Arc::clone(tx));
        }
        // Fill in all finalized waves
        for fw in finalized_waves {
            pending.received_waves.insert(fw.wave_id_hash(), fw);
        }
        pending
    }

    /// Add a received transaction.
    ///
    /// Returns true if this transaction was needed, false if duplicate or not in this block.
    pub fn add_transaction_arc(&mut self, tx: Arc<RoutableTransaction>) -> bool {
        let hash = tx.hash();
        if self.missing_transaction_hashes.remove(&hash) {
            self.received_transactions.insert(hash, tx);
            true
        } else {
            false
        }
    }

    /// Add a finalized wave (carries certificate + receipts + ECs).
    ///
    /// Returns true if this wave was needed, false if duplicate or not in this block.
    pub fn add_finalized_wave(&mut self, fw: Arc<FinalizedWave>) -> bool {
        let wave_hash = fw.wave_id_hash();
        if self.missing_wave_hashes.remove(&wave_hash) {
            self.received_waves.insert(wave_hash, fw);
            true
        } else {
            false
        }
    }

    /// Check if all transactions, finalized waves, and provisions have been received.
    pub fn is_complete(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
            && self.missing_wave_hashes.is_empty()
            && self.missing_provision_hashes.is_empty()
    }

    /// Check if all transactions have been received (waves may still be pending).
    #[cfg(test)]
    pub fn has_all_transactions(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
    }

    /// Get the number of missing transaction hashes.
    pub fn missing_transaction_count(&self) -> usize {
        self.missing_transaction_hashes.len()
    }

    /// Get the missing transaction hashes as a Vec (for iteration/display).
    pub fn missing_transactions(&self) -> Vec<TxHash> {
        self.missing_transaction_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific transaction.
    pub fn needs_transaction(&self, tx_hash: &TxHash) -> bool {
        self.missing_transaction_hashes.contains(tx_hash)
    }

    /// Get the number of missing wave hashes.
    pub fn missing_wave_count(&self) -> usize {
        self.missing_wave_hashes.len()
    }

    /// Check if this pending block needs a specific finalized wave.
    pub fn needs_wave(&self, wave_id_hash: &WaveIdHash) -> bool {
        self.missing_wave_hashes.contains(wave_id_hash)
    }

    /// Add a received provision batch.
    ///
    /// Returns true if this provision was needed, false if duplicate or not in this block.
    pub fn add_provision(&mut self, batch: Arc<Provision>) -> bool {
        let hash = batch.hash();
        if self.missing_provision_hashes.remove(&hash) {
            self.received_provisions.insert(hash, batch);
            true
        } else {
            false
        }
    }

    /// Get the missing provision batch hashes as a Vec.
    pub fn missing_provisions(&self) -> Vec<ProvisionHash> {
        self.missing_provision_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific provision batch.
    pub fn needs_provision(&self, batch_hash: &ProvisionHash) -> bool {
        self.missing_provision_hashes.contains(batch_hash)
    }

    /// Get the missing wave ID hashes as a Vec.
    pub fn missing_waves(&self) -> Vec<WaveIdHash> {
        self.missing_wave_hashes.iter().copied().collect()
    }

    /// Get all received finalized waves.
    pub fn finalized_waves(&self) -> Vec<Arc<FinalizedWave>> {
        self.received_waves.values().cloned().collect()
    }

    /// Construct the block from header + received transactions + received waves.
    ///
    /// Should only be called when is_complete() returns true.
    pub fn construct_block(&mut self) -> Result<Arc<Block>, String> {
        if !self.is_complete() {
            return Err(format!(
                "Cannot construct block: {} transactions, {} waves still missing",
                self.missing_transaction_hashes.len(),
                self.missing_wave_hashes.len()
            ));
        }

        if let Some(ref block) = self.constructed_block {
            return Ok(Arc::clone(block));
        }

        // Build transactions in the ORIGINAL order from the gossip message.
        let transactions: Vec<Arc<RoutableTransaction>> = self
            .manifest
            .tx_hashes
            .iter()
            .filter_map(|hash| self.received_transactions.remove(hash))
            .collect();

        // Pass finalized waves into the block in manifest order.
        let certificates: Vec<Arc<FinalizedWave>> = self
            .manifest
            .cert_hashes
            .iter()
            .filter_map(|hash| self.received_waves.get(hash).cloned())
            .collect();

        // Attach provisions in manifest order. `received_provisions` is
        // populated as provision batches arrive via gossip / local fetch,
        // and `is_complete()` gates assembly on all of them being present.
        let provisions: Vec<Arc<Provision>> = self
            .manifest
            .provision_hashes
            .iter()
            .filter_map(|hash| self.received_provisions.get(hash).cloned())
            .collect();

        let block = Arc::new(Block::Live {
            header: self.header.clone(),
            transactions,
            certificates,
            provisions,
        });

        self.constructed_block = Some(Arc::clone(&block));
        Ok(block)
    }

    /// Get the constructed block, if available.
    pub fn block(&self) -> Option<Arc<Block>> {
        self.constructed_block.as_ref().map(Arc::clone)
    }

    /// Get the block header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Time at which this pending block was first observed.
    pub fn created_at(&self) -> Duration {
        self.created_at
    }

    /// Get the block manifest.
    pub fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Get total transaction count across all sections.
    pub fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }

    /// Get certificate count.
    pub fn certificate_count(&self) -> usize {
        self.manifest.cert_hashes.len()
    }
}

/// Emit fetch actions for pending blocks whose missing data has been
/// outstanding longer than `timeout`. Skips complete blocks.
///
/// Called periodically by the cleanup timer so gossip and local certificate
/// production have a chance to fill the data first. `force_immediate`
/// bypasses the age check — used after sync resumes to pull any lingering
/// holes without another timeout cycle.
pub(crate) fn check_fetches(
    pending_blocks: &HashMap<BlockHash, PendingBlock>,
    topology: &TopologySnapshot,
    now: Duration,
    timeout: Duration,
    force_immediate: bool,
) -> Vec<Action> {
    let mut actions = Vec::new();

    for (block_hash, pending) in pending_blocks {
        if pending.is_complete() {
            continue;
        }

        let age = now.saturating_sub(pending.created_at());
        let ready = force_immediate || age >= timeout;
        if !ready {
            continue;
        }

        let proposer = pending.header().proposer;

        let missing_txs = pending.missing_transactions();
        if !missing_txs.is_empty() {
            debug!(
                validator = ?topology.local_validator_id(),
                block_hash = ?block_hash,
                missing_tx_count = missing_txs.len(),
                age_ms = age.as_millis(),
                timeout_ms = timeout.as_millis(),
                "Fetch timeout reached, requesting missing transactions"
            );
            actions.push(Action::FetchTransactions {
                block_hash: *block_hash,
                proposer,
                tx_hashes: missing_txs,
            });
        }

        let missing_provisions = pending.missing_provisions();
        if !missing_provisions.is_empty() {
            debug!(
                validator = ?topology.local_validator_id(),
                block_hash = ?block_hash,
                missing_provision_count = missing_provisions.len(),
                age_ms = age.as_millis(),
                "Fetch timeout reached, requesting missing provisions"
            );
            actions.push(Action::FetchProvisionLocal {
                block_hash: *block_hash,
                proposer,
                batch_hashes: missing_provisions,
            });
        }

        let missing_waves = pending.missing_waves();
        if !missing_waves.is_empty() {
            debug!(
                validator = ?topology.local_validator_id(),
                block_hash = ?block_hash,
                missing_wave_count = missing_waves.len(),
                age_ms = age.as_millis(),
                "Fetch timeout reached, requesting missing finalized waves"
            );
            actions.push(Action::FetchFinalizedWave {
                block_hash: *block_hash,
                proposer,
                wave_id_hashes: missing_waves,
            });
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeight, CertificateRoot, LocalReceiptRoot, ProvisionsRoot, QuorumCertificate, Round,
        ShardGroupId, StateRoot, TransactionRoot, ValidatorId,
    };

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: hyperscale_types::ProposerTimestamp(1234567890),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    #[test]
    fn test_pending_block_creation() {
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from_raw(Hash::from_bytes(b"tx2"));
        let header = make_header(BlockHeight(1));

        let pb = PendingBlock::from_manifest(
            header.clone(),
            BlockManifest {
                tx_hashes: vec![tx1, tx2],
                ..Default::default()
            },
            Duration::ZERO,
        );

        assert_eq!(pb.missing_transactions().len(), 2);
        assert!(pb.missing_transactions().contains(&tx1));
        assert!(pb.missing_transactions().contains(&tx2));
        assert!(!pb.is_complete());
        assert!(pb.block().is_none());
    }

    #[test]
    fn test_empty_block_is_complete() {
        let header = make_header(BlockHeight(1));
        let pb = PendingBlock::from_manifest(header, BlockManifest::default(), Duration::ZERO);

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_waves() {
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let wave1 = WaveIdHash::from_raw(Hash::from_bytes(b"wave1"));
        let wave2 = WaveIdHash::from_raw(Hash::from_bytes(b"wave2"));
        let header = make_header(BlockHeight(1));

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                tx_hashes: vec![tx1],
                cert_hashes: vec![wave1, wave2],
                ..Default::default()
            },
            Duration::ZERO,
        );

        assert_eq!(pb.missing_transaction_count(), 1);
        assert_eq!(pb.missing_wave_count(), 2);
        assert!(pb.needs_wave(&wave1));
        assert!(pb.needs_wave(&wave2));
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_finalized_wave() {
        use hyperscale_types::{BlockHeight, WaveCertificate, WaveId};

        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), Default::default());
        let wave_hash = wave_id.hash();
        let header = make_header(BlockHeight(1));

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                cert_hashes: vec![wave_hash],
                ..Default::default()
            },
            Duration::ZERO,
        );

        assert_eq!(pb.missing_wave_count(), 1);
        assert!(!pb.is_complete());

        let fw = Arc::new(FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![],
            }),
            receipts: vec![],
        });

        let added = pb.add_finalized_wave(fw);
        assert!(added);
        assert_eq!(pb.missing_wave_count(), 0);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_block_needs_transactions_and_waves() {
        use hyperscale_types::{
            test_utils::test_transaction, BlockHeight, WaveCertificate, WaveId,
        };

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), Default::default());
        let wave_hash = wave_id.hash();
        let header = make_header(BlockHeight(1));

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest {
                tx_hashes: vec![tx_hash],
                cert_hashes: vec![wave_hash],
                ..Default::default()
            },
            Duration::ZERO,
        );

        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction_arc(tx);
        assert!(pb.has_all_transactions());
        assert!(!pb.is_complete()); // Still missing wave

        // Add finalized wave
        let fw = Arc::new(FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![],
            }),
            receipts: vec![],
        });
        pb.add_finalized_wave(fw);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_from_complete_block_is_complete() {
        use hyperscale_types::{Block, BlockHeight, WaveCertificate, WaveId};

        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), Default::default());
        let cert = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![],
        });

        let fw = Arc::new(FinalizedWave {
            certificate: cert,
            receipts: vec![],
        });

        let block = Block::Live {
            header: make_header(BlockHeight(1)),
            transactions: vec![],
            certificates: vec![Arc::clone(&fw)],
            provisions: vec![],
        };

        let pending = PendingBlock::from_complete_block(&block, vec![fw], vec![], Duration::ZERO);
        assert!(pending.is_complete());
    }
}
