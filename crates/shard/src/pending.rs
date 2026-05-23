//! Pending block assembly.
//!
//! Tracks blocks being assembled from headers + gossiped transactions + finalized waves.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchRequest};
#[cfg(test)]
use hyperscale_types::{BeaconWitnessLeafCount, BeaconWitnessRoot};
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, FinalizedWave, LocalTimestamp,
    ProvisionHash, Provisions, RoutableTransaction, TopologySnapshot, TxHash, WaveId,
};
use tracing::{debug, warn};

/// Map of block hash → [`PendingBlock`] for blocks currently being assembled.
///
/// Keys are derived from `block.header().hash()` on insert.
#[derive(Default)]
pub struct PendingBlocks(HashMap<BlockHash, PendingBlock>);

impl PendingBlocks {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, block_hash: BlockHash) -> Option<&PendingBlock> {
        self.0.get(&block_hash)
    }

    pub fn get_mut(&mut self, block_hash: BlockHash) -> Option<&mut PendingBlock> {
        self.0.get_mut(&block_hash)
    }

    /// Insert `block` keyed on its own header hash. Silently overwrites any
    /// prior entry under the same hash; callers that need to gate on
    /// duplicates check [`contains_key`](Self::contains_key) first.
    pub fn insert(&mut self, block: PendingBlock) {
        self.0.insert(block.header().hash(), block);
    }

    pub fn remove(&mut self, block_hash: BlockHash) -> Option<PendingBlock> {
        self.0.remove(&block_hash)
    }

    pub fn contains_key(&self, block_hash: BlockHash) -> bool {
        self.0.contains_key(&block_hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn values(&self) -> impl Iterator<Item = &PendingBlock> {
        self.0.values()
    }

    /// Drop pending blocks whose header height is at or below
    /// `committed_height`. Returns the union of their outstanding
    /// missing-provision hashes — any in-flight local-DA fetch on those
    /// hashes is now orphaned and the caller is responsible for emitting
    /// `AbandonFetch::LocalProvisions` so the FSM releases its slots.
    pub fn prune_committed(&mut self, committed_height: BlockHeight) -> Vec<ProvisionHash> {
        let mut orphaned = Vec::new();
        self.0.retain(|_, pending| {
            if pending.header().height() > committed_height {
                return true;
            }
            orphaned.extend(pending.missing_provision_hashes.iter().copied());
            false
        });
        orphaned
    }

    /// Header for the pending block at `block_hash`, if present.
    pub fn get_header(&self, block_hash: BlockHash) -> Option<&BlockHeader> {
        self.0.get(&block_hash).map(PendingBlock::header)
    }

    /// Constructed [`Block`] for `block_hash`, if the pending block has fully
    /// assembled. Returns `None` when the hash is unknown OR when the block
    /// is still awaiting transactions/waves/provisions.
    pub fn get_block(&self, block_hash: BlockHash) -> Option<&Arc<Block>> {
        self.0.get(&block_hash)?.block()
    }

    /// True when the pending block at `block_hash` has all data and the
    /// inner [`Block`] is ready to be built. False when the hash is unknown.
    pub fn is_complete(&self, block_hash: BlockHash) -> bool {
        self.0
            .get(&block_hash)
            .is_some_and(PendingBlock::is_complete)
    }

    /// True when some pending block at `height` is complete AND already has
    /// its inner [`Block`] constructed.
    pub fn has_complete_at(&self, height: BlockHeight) -> bool {
        self.0.values().any(|pending| {
            pending.header().height() == height
                && pending.is_complete()
                && pending.block().is_some()
        })
    }

    /// True when any pending block sits at `height`, regardless of completion
    /// state.
    pub fn has_any_at(&self, height: BlockHeight) -> bool {
        self.0
            .values()
            .any(|pending| pending.header().height() == height)
    }

    /// Total transaction count across all pending blocks (manifest counts,
    /// independent of how much data has actually arrived).
    pub fn total_transaction_count(&self) -> usize {
        self.0.values().map(PendingBlock::transaction_count).sum()
    }

    /// Total certificate count across all pending blocks.
    pub fn total_certificate_count(&self) -> usize {
        self.0.values().map(PendingBlock::certificate_count).sum()
    }

    /// Build a [`PendingBlock`] from `header` + `manifest`, populate it from
    /// the supplied lookups, and insert it.
    pub fn assemble(
        &mut self,
        header: BlockHeader,
        manifest: BlockManifest,
        now: LocalTimestamp,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<RoutableTransaction>>,
        lookup_finalized_wave: impl Fn(&WaveId) -> Option<Arc<FinalizedWave>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Provisions>>,
    ) {
        let mut pending = PendingBlock::from_manifest(header, manifest, now);

        // Borrow the manifest only long enough to collect locally-available
        // Arcs, releasing it before the mutable `add_*` calls below.
        let txs: Vec<Arc<RoutableTransaction>> = pending
            .manifest()
            .tx_hashes()
            .iter()
            .filter_map(&lookup_tx)
            .collect();
        for tx in txs {
            pending.add_transaction(tx);
        }

        let waves: Vec<Arc<FinalizedWave>> = pending
            .manifest()
            .cert_ids()
            .iter()
            .filter_map(&lookup_finalized_wave)
            .collect();
        for fw in waves {
            pending.add_finalized_wave(fw);
        }

        let provisions: Vec<Arc<Provisions>> = pending
            .manifest()
            .provision_hashes()
            .iter()
            .filter_map(&lookup_provision)
            .collect();
        for p in provisions {
            pending.add_provision(p);
        }

        self.insert(pending);
    }

    /// Fold an arrival into every pending block that needs it. Returns the
    /// hashes of blocks that became complete and successfully constructed
    /// their inner [`Block`].
    fn fold_arrival<F, M>(&mut self, needs: F, apply: M) -> Vec<BlockHash>
    where
        F: Fn(&PendingBlock) -> bool,
        M: Fn(&mut PendingBlock),
    {
        let mut block_hashes: Vec<BlockHash> = self
            .0
            .iter()
            .filter(|(_, pending)| needs(pending))
            .map(|(hash, _)| *hash)
            .collect();
        block_hashes.sort();

        let mut newly_complete = Vec::new();
        for block_hash in block_hashes {
            if let Some(pending) = self.0.get_mut(&block_hash) {
                apply(pending);
                if Self::try_construct(pending) {
                    newly_complete.push(block_hash);
                }
            }
        }
        newly_complete
    }

    fn try_construct(pending: &mut PendingBlock) -> bool {
        if !pending.is_complete() {
            return false;
        }
        if pending.block().is_some() {
            return true;
        }
        match pending.construct_block() {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "Failed to construct block after arrival");
                false
            }
        }
    }

    /// Record an arrived transaction against any pending block that needs it.
    /// Returns the hashes of blocks that became complete as a result.
    pub fn receive_transaction(&mut self, tx: &Arc<RoutableTransaction>) -> Vec<BlockHash> {
        let tx_hash = tx.hash();
        self.fold_arrival(
            |pending| pending.needs_transaction(&tx_hash),
            |pending| {
                pending.add_transaction(Arc::clone(tx));
            },
        )
    }

    /// Record an arrived finalized wave against any pending block that needs
    /// it. Returns the hashes of blocks that became complete as a result.
    pub fn receive_finalized_wave(&mut self, fw: &Arc<FinalizedWave>) -> Vec<BlockHash> {
        let wave_id = fw.wave_id().clone();
        self.fold_arrival(
            |pending| pending.needs_wave(&wave_id),
            |pending| {
                pending.add_finalized_wave(Arc::clone(fw));
            },
        )
    }

    /// Record an arrived provisions batch against any pending block that
    /// needs it. Returns the hashes of blocks that became complete as a
    /// result.
    pub fn receive_provision(&mut self, batch: &Arc<Provisions>) -> Vec<BlockHash> {
        let provisions_hash = batch.hash();
        self.fold_arrival(
            |pending| pending.needs_provision(&provisions_hash),
            |pending| {
                pending.add_provision(Arc::clone(batch));
            },
        )
    }

    /// Emit fetch actions for pending blocks whose missing data has been
    /// outstanding longer than `timeout`. Skips complete blocks.
    /// `force_immediate` bypasses the age check.
    pub fn check_fetches(
        &self,
        topology: &TopologySnapshot,
        now: LocalTimestamp,
        timeout: Duration,
        force_immediate: bool,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        for (block_hash, pending) in &self.0 {
            if pending.is_complete() {
                continue;
            }

            let age = now.elapsed_since(pending.created_at());
            let ready = force_immediate || age >= timeout;
            if !ready {
                continue;
            }

            let proposer = pending.header().proposer();
            let local_shard = topology.local_shard();

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
                actions.push(Action::Fetch(FetchRequest::Transactions {
                    ids: missing_txs,
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
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
                actions.push(Action::Fetch(FetchRequest::LocalProvisions {
                    ids: missing_provisions,
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
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
                actions.push(Action::Fetch(FetchRequest::FinalizedWaves {
                    ids: missing_waves,
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
            }
        }

        actions
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Tracks a block being assembled from header + gossiped transactions + finalized waves.
///
/// # Lifecycle
///
/// 1. Created from `BlockHeader` (all transactions/waves marked as absent by hash)
/// 2. Full `Transaction` objects arrive via gossip (stored in `received_transactions` map)
/// 3. `FinalizedWave`s arrive when verifier independently finalizes each wave
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

    /// Set of transaction hashes we're still waiting for (`HashSet` for O(1) lookup).
    missing_transaction_hashes: HashSet<TxHash>,

    /// Map of `WaveId` -> `Arc<FinalizedWave>` (carries cert + receipts + ECs).
    ///
    /// A block is complete once
    /// all its waves have been independently finalized by this validator.
    received_waves: BTreeMap<WaveId, Arc<FinalizedWave>>,

    /// Set of `WaveId`s we're still waiting for.
    missing_wave_ids: HashSet<WaveId>,

    /// Received provisions keyed by provisions hash. `BTreeMap` so
    /// `provisions()` iteration is deterministic across validators.
    received_provisions: BTreeMap<ProvisionHash, Arc<Provisions>>,

    /// Set of provisions hashes we're still waiting for.
    missing_provision_hashes: HashSet<ProvisionHash>,

    /// The fully constructed block (None until all transactions/waves received).
    constructed_block: Option<Arc<Block>>,

    /// Time at which this pending block was first observed. Used to schedule
    /// fetch requests for missing data after a gossip grace period.
    created_at: LocalTimestamp,
}

impl PendingBlock {
    /// Create a pending block from a header and manifest.
    pub fn from_manifest(
        header: BlockHeader,
        manifest: BlockManifest,
        created_at: LocalTimestamp,
    ) -> Self {
        let total_tx_count = manifest.transaction_count();
        let missing_transaction_hashes: HashSet<TxHash> =
            manifest.tx_hashes().iter().copied().collect();
        let missing_wave_ids: HashSet<WaveId> = manifest.cert_ids().iter().cloned().collect();
        let missing_provision_hashes: HashSet<ProvisionHash> =
            manifest.provision_hashes().iter().copied().collect();

        Self {
            header,
            received_transactions: HashMap::with_capacity(total_tx_count),
            missing_transaction_hashes,
            received_waves: BTreeMap::new(),
            missing_wave_ids,
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
        provisions: Vec<Arc<Provisions>>,
        created_at: LocalTimestamp,
    ) -> Self {
        let mut provision_hashes: Vec<ProvisionHash> =
            provisions.iter().map(|p| p.hash()).collect();
        provision_hashes.sort();
        let tx_hashes: Vec<TxHash> = block.transactions().iter().map(|tx| tx.hash()).collect();
        let cert_ids: Vec<WaveId> = block
            .certificates()
            .iter()
            .map(|c| c.wave_id().clone())
            .collect();
        let manifest = BlockManifest::new(tx_hashes, cert_ids, provision_hashes, vec![]);
        let mut received_provisions: BTreeMap<ProvisionHash, Arc<Provisions>> = BTreeMap::new();
        for p in provisions {
            received_provisions.insert(p.hash(), p);
        }
        let mut pending = Self {
            header: block.header().clone(),
            received_transactions: HashMap::new(),
            missing_transaction_hashes: HashSet::new(),
            received_waves: BTreeMap::new(),
            missing_wave_ids: HashSet::new(),
            received_provisions,
            missing_provision_hashes: HashSet::new(),
            manifest,
            constructed_block: None,
            created_at,
        };
        // Fill in all transactions
        for tx in block.transactions().iter() {
            pending
                .received_transactions
                .insert(tx.hash(), Arc::clone(tx));
        }
        // Fill in all finalized waves
        for fw in finalized_waves {
            pending.received_waves.insert(fw.wave_id().clone(), fw);
        }
        pending
    }

    /// Add a received transaction.
    ///
    /// Returns true if this transaction was needed, false if duplicate or not in this block.
    pub fn add_transaction(&mut self, tx: Arc<RoutableTransaction>) -> bool {
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
        let wave_id = fw.wave_id().clone();
        if self.missing_wave_ids.remove(&wave_id) {
            self.received_waves.insert(wave_id, fw);
            true
        } else {
            false
        }
    }

    /// Check if all transactions, finalized waves, and provisions have been received.
    pub fn is_complete(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
            && self.missing_wave_ids.is_empty()
            && self.missing_provision_hashes.is_empty()
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

    /// Get the number of missing waves.
    pub fn missing_wave_count(&self) -> usize {
        self.missing_wave_ids.len()
    }

    /// Get the number of missing provision batches.
    pub fn missing_provision_count(&self) -> usize {
        self.missing_provision_hashes.len()
    }

    /// Check if this pending block needs a specific finalized wave.
    pub fn needs_wave(&self, wave_id: &WaveId) -> bool {
        self.missing_wave_ids.contains(wave_id)
    }

    /// Add a received provisions.
    ///
    /// Returns true if this provision was needed, false if duplicate or not in this block.
    pub fn add_provision(&mut self, provisions: Arc<Provisions>) -> bool {
        let hash = provisions.hash();
        if self.missing_provision_hashes.remove(&hash) {
            self.received_provisions.insert(hash, provisions);
            true
        } else {
            false
        }
    }

    /// Get the missing provisions hashes as a Vec.
    pub fn missing_provisions(&self) -> Vec<ProvisionHash> {
        self.missing_provision_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific provisions.
    pub fn needs_provision(&self, batch_hash: &ProvisionHash) -> bool {
        self.missing_provision_hashes.contains(batch_hash)
    }

    /// Get the missing wave ids as a Vec.
    pub fn missing_waves(&self) -> Vec<WaveId> {
        self.missing_wave_ids.iter().cloned().collect()
    }

    /// Get all received finalized waves.
    pub fn finalized_waves(&self) -> Vec<Arc<FinalizedWave>> {
        self.received_waves.values().cloned().collect()
    }

    /// Construct the block from header + received transactions + received waves.
    ///
    /// Should only be called when `is_complete()` returns true.
    pub fn construct_block(&mut self) -> Result<Arc<Block>, String> {
        if !self.is_complete() {
            return Err(format!(
                "Cannot construct block: {} transactions, {} waves still missing",
                self.missing_transaction_hashes.len(),
                self.missing_wave_ids.len()
            ));
        }

        if let Some(ref block) = self.constructed_block {
            return Ok(Arc::clone(block));
        }

        // Build transactions in the ORIGINAL order from the gossip message.
        let transactions: Vec<Arc<RoutableTransaction>> = self
            .manifest
            .tx_hashes()
            .iter()
            .filter_map(|hash| self.received_transactions.remove(hash))
            .collect();

        // Pass finalized waves into the block in manifest order.
        let certificates: Vec<Arc<FinalizedWave>> = self
            .manifest
            .cert_ids()
            .iter()
            .filter_map(|id| self.received_waves.get(id).cloned())
            .collect();

        // Attach provisions in manifest order. `received_provisions` is
        // populated as provisions arrive via gossip / local fetch,
        // and `is_complete()` gates assembly on all of them being present.
        let provisions: Vec<Arc<Provisions>> = self
            .manifest
            .provision_hashes()
            .iter()
            .filter_map(|hash| self.received_provisions.get(hash).cloned())
            .collect();

        let block = Arc::new(Block::Live {
            header: self.header.clone(),
            transactions: Arc::new(transactions.into()),
            certificates: Arc::new(certificates.into()),
            provisions: Arc::new(provisions.into()),
        });

        self.constructed_block = Some(Arc::clone(&block));
        Ok(block)
    }

    /// Get the constructed block, if available.
    pub const fn block(&self) -> Option<&Arc<Block>> {
        self.constructed_block.as_ref()
    }

    /// Get the block header.
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Time at which this pending block was first observed.
    pub const fn created_at(&self) -> LocalTimestamp {
        self.created_at
    }

    /// Get the block manifest.
    pub const fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Get total transaction count across all sections.
    pub const fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }

    /// Get certificate count.
    pub const fn certificate_count(&self) -> usize {
        self.manifest.cert_ids().len()
    }
}

#[cfg(test)]
impl PendingBlock {
    /// Check if all transactions have been received (waves may still be pending).
    pub fn has_all_transactions(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        Block, BlockHeight, BoundedVec, CertificateRoot, Hash, InFlightCount, LocalReceiptRoot,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, StateRoot,
        TransactionRoot, ValidatorId, WaveCertificate, WaveId,
    };

    use super::*;

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    #[test]
    fn test_pending_block_creation() {
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from_raw(Hash::from_bytes(b"tx2"));
        let header = make_header(BlockHeight::new(1));

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(vec![tx1, tx2], vec![], vec![], vec![]),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_transactions().len(), 2);
        assert!(pb.missing_transactions().contains(&tx1));
        assert!(pb.missing_transactions().contains(&tx2));
        assert!(!pb.is_complete());
        assert!(pb.block().is_none());
    }

    #[test]
    fn test_empty_block_is_complete() {
        let header = make_header(BlockHeight::new(1));
        let pb =
            PendingBlock::from_manifest(header, BlockManifest::default(), LocalTimestamp::ZERO);

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_waves() {
        let tx1 = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        let wave1 = WaveId::new(ShardGroupId::new(0), BlockHeight::new(1), BTreeSet::new());
        let wave2 = WaveId::new(ShardGroupId::new(0), BlockHeight::new(2), BTreeSet::new());
        let header = make_header(BlockHeight::new(1));

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(
                vec![tx1],
                vec![wave1.clone(), wave2.clone()],
                vec![],
                vec![],
            ),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_transaction_count(), 1);
        assert_eq!(pb.missing_wave_count(), 2);
        assert!(pb.needs_wave(&wave1));
        assert!(pb.needs_wave(&wave2));
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_finalized_wave() {
        let wave_id = WaveId::new(ShardGroupId::new(0), BlockHeight::new(1), BTreeSet::new());
        let header = make_header(BlockHeight::new(1));

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(vec![], vec![wave_id.clone()], vec![], vec![]),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_wave_count(), 1);
        assert!(!pb.is_complete());

        let fw = Arc::new(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![])),
            vec![],
        ));

        let added = pb.add_finalized_wave(fw);
        assert!(added);
        assert_eq!(pb.missing_wave_count(), 0);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_block_needs_transactions_and_waves() {
        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let wave_id = WaveId::new(ShardGroupId::new(0), BlockHeight::new(1), BTreeSet::new());
        let header = make_header(BlockHeight::new(1));

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(vec![tx_hash], vec![wave_id.clone()], vec![], vec![]),
            LocalTimestamp::ZERO,
        );

        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction(tx);
        assert!(pb.has_all_transactions());
        assert!(!pb.is_complete()); // Still missing wave

        // Add finalized wave
        let fw = Arc::new(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![])),
            vec![],
        ));
        pb.add_finalized_wave(fw);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_from_complete_block_is_complete() {
        let wave_id = WaveId::new(ShardGroupId::new(0), BlockHeight::new(1), BTreeSet::new());
        let cert = Arc::new(WaveCertificate::new(wave_id, vec![]));

        let fw = Arc::new(FinalizedWave::new(cert, vec![]));

        let block = Block::Live {
            header: make_header(BlockHeight::new(1)),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(vec![Arc::clone(&fw)].into()),
            provisions: Arc::new(BoundedVec::new()),
        };

        let pending =
            PendingBlock::from_complete_block(&block, vec![fw], vec![], LocalTimestamp::ZERO);
        assert!(pending.is_complete());
    }

    #[test]
    fn prune_committed_surfaces_orphaned_provision_hashes() {
        // Two pending blocks: one at the committed height with outstanding
        // provisions (will be pruned), one above (will be kept). The pruned
        // block's missing-provision ids must come back out so the caller
        // can cancel any pinned local-DA fetches.
        let mut pending_blocks = PendingBlocks::new();
        let prov_a = ProvisionHash::from_raw(Hash::from_bytes(b"prov_a"));
        let prov_b = ProvisionHash::from_raw(Hash::from_bytes(b"prov_b"));

        let stale = PendingBlock::from_manifest(
            make_header(BlockHeight::new(5)),
            BlockManifest::new(vec![], vec![], vec![prov_a, prov_b], vec![]),
            LocalTimestamp::ZERO,
        );
        let live = PendingBlock::from_manifest(
            make_header(BlockHeight::new(10)),
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(stale);
        pending_blocks.insert(live);

        let orphaned = pending_blocks.prune_committed(BlockHeight::new(5));
        let orphaned_set: HashSet<_> = orphaned.into_iter().collect();
        assert_eq!(orphaned_set, HashSet::from([prov_a, prov_b]));
        assert_eq!(pending_blocks.len(), 1, "live block must remain");
    }

    #[test]
    fn prune_committed_yields_no_hashes_when_dropped_block_was_complete() {
        let mut pending_blocks = PendingBlocks::new();
        let complete = PendingBlock::from_manifest(
            make_header(BlockHeight::new(5)),
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(complete);

        let orphaned = pending_blocks.prune_committed(BlockHeight::new(5));
        assert!(orphaned.is_empty());
        assert_eq!(pending_blocks.len(), 0);
    }
}
