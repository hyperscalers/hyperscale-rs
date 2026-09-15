//! Denormalized block storage in `RocksDB`.
//!
//! A committed [`CertifiedBlock`] is sharded across four column families:
//! [`BlocksCf`] holds per-height [`BlockMetadata`] (header + manifest + qc),
//! [`TransactionsCf`] holds individual transactions keyed by [`TxHash`],
//! [`CertificatesCf`] holds finalizations keyed by [`TickId`], and
//! [`ConsensusReceiptsCf`] holds the consensus receipt for each block.
//!
//! Reading a block reconstructs it via `get_block_denormalized`, which
//! reads metadata then `multi_get`s the referenced transactions and
//! certificates. This layout keeps individual transactions independently
//! seekable (used by the RPC `/transactions/:hash` endpoint and by
//! cross-shard fetch protocols) while avoiding write amplification on
//! commit, since each transaction is only written once even when it
//! appears in multiple block-level views.

use std::sync::Arc;
use std::time::Instant;

use hyperscale_metrics::{record_storage_operation, record_storage_read};
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, BlockMetadata,
    CertifiedBlock, Finalization, FinalizationHash, Hash, ProvisionHash, QuorumCertificate,
    Transaction, TxHash, Verifiable, Verified,
};
use rocksdb::{ColumnFamily, WriteBatch};

use super::column_families::{
    BeaconWitnessesCf, BlocksCf, CertificatesCf, ConsensusReceiptsCf, ProvisionKeyCodec,
    ProvisionsCf, TransactionsCf, VotedBlockKeyCodec, VotedBlocksCf,
};
use super::core::RocksDbShardStorage;
use super::metadata::{read_committed_hash, read_committed_height, read_committed_qc};
use crate::typed_cf::{DbEncode, TypedCf, batch_put, batch_put_raw, get, multi_get};

impl RocksDbShardStorage {
    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order. Uses `get_block_denormalized`
    /// for each height to properly reconstruct blocks from metadata + individual
    /// transaction/certificate entries.
    #[must_use]
    pub fn get_blocks_range(&self, from: BlockHeight, to: BlockHeight) -> Vec<CertifiedBlock> {
        let mut result = Vec::new();
        let mut h = from.inner();
        while h < to.inner() {
            if let Some(certified) = self.get_block_denormalized(BlockHeight::new(h)) {
                result.push(certified);
            }
            h += 1;
        }
        result
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Transaction storage (denormalized)
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a transaction by hash.
    ///
    /// This is idempotent - storing the same transaction twice is safe.
    /// Used by `put_block_denormalized` to store transactions separately from block metadata.
    pub fn put_transaction(&self, tx: &Transaction) {
        self.cf_put_sync::<TransactionsCf>(&Hash::from(tx.hash()), tx);
    }

    /// Get a transaction by hash.
    #[must_use]
    pub fn get_transaction(&self, hash: &TxHash) -> Option<Transaction> {
        let start = Instant::now();
        let result = self.cf_get::<TransactionsCf>(&Hash::from(*hash));
        record_storage_read(start.elapsed().as_secs_f64());
        result
    }

    /// Get multiple transactions by hash (batch read).
    ///
    /// Uses `RocksDB`'s `multi_get_cf` for efficient batch retrieval.
    /// Returns only transactions that were found (missing hashes are skipped).
    #[must_use]
    pub(crate) fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Transaction> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let raw: Vec<Hash> = hashes.iter().map(|h| Hash::from(*h)).collect();
        let results = self.cf_multi_get::<TransactionsCf>(&raw);

        let txs: Vec<_> = results.into_iter().flatten().collect();

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_transactions_batch", elapsed);

        txs
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Denormalized block storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a committed block with denormalized storage.
    ///
    /// Atomically writes:
    /// - Block metadata (header + hashes) to "blocks" CF
    /// - Each transaction to "transactions" CF
    /// - Each certificate to "certificates" CF
    ///
    /// This eliminates duplication: transactions and certificates are stored once
    /// by hash, and the block metadata references them.
    ///
    /// # Panics
    ///
    /// Panics if the block cannot be persisted. This is intentional: committed blocks
    /// are essential for crash recovery.
    /// Append block data to an existing `WriteBatch` (for atomic commit).
    ///
    /// `beacon_witness_leaf_count_at_block_end` is stamped into the
    /// `BlockMetadata`. Callers that have a witness-leaf delta also call
    /// [`Self::append_beacon_witnesses_to_batch`] against the same
    /// `WriteBatch` so the leaves and the count land atomically.
    pub(crate) fn append_block_to_batch(
        &self,
        batch: &mut WriteBatch,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
        beacon_witness_leaf_count_at_block_end: BeaconWitnessLeafCount,
        retention_floor: u64,
    ) {
        // Resolve column-family handles once for the whole append loop.
        // Per-call `cf_put`/`cf_put_raw` would each invoke `self.cf()`,
        // re-walking all 12 CFs through `RocksDB`'s name → handle map per
        // transaction and per certificate.
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let transactions_cf = TransactionsCf::handle(&cf);
        let certificates_cf = CertificatesCf::handle(&cf);

        let metadata = BlockMetadata::from_block_with_witness_count(
            block,
            qc.clone(),
            beacon_witness_leaf_count_at_block_end,
        );
        batch_put::<BlocksCf>(batch, blocks_cf, &block.height().inner(), &metadata);
        // The chain now holds this height, so the vote justifications at
        // or below it — this block and any fork sibling — have nothing
        // left to justify. One range delete, in the commit's own batch.
        batch.delete_range_cf(
            VotedBlocksCf::handle(&cf),
            VotedBlockKeyCodec.encode(&(BlockHeight::GENESIS, BlockHash::ZERO)),
            VotedBlockKeyCodec.encode(&(block.height().next(), BlockHash::ZERO)),
        );
        for tx in block.transactions().iter() {
            batch_put_raw::<TransactionsCf>(
                batch,
                transactions_cf,
                &Hash::from(tx.hash()),
                tx.as_ref(),
                Some(tx.cached_wire_bytes()),
            );
        }
        for fw in block.certificates().iter() {
            batch_put::<CertificatesCf>(
                batch,
                certificates_cf,
                &fw.receipt_hash(),
                &fw.attestation(),
            );
        }
        self.append_provisions_to_batch(batch, block, retention_floor);
    }

    /// Append a block that sits below the store's committed frontier:
    /// its metadata row, its certificates and its transaction bodies.
    ///
    /// Everything the commit path does *around* the row is deliberately
    /// absent. The vote justifications a commit clears sit above this
    /// height and are not this block's to retire; the provision prune a
    /// commit carries cuts at a floor this write does not move; and no
    /// chain metadata advances, because the frontier is already past
    /// here. What is written is exactly what the attested window folds
    /// read back — the header's parent-QC anchor, the manifest, and the
    /// certificates the settled side folds.
    pub(crate) fn append_historical_block_to_batch(
        &self,
        batch: &mut WriteBatch,
        certified: &CertifiedBlock,
    ) {
        let block = certified.block();
        let cf = self.cf();
        let metadata = BlockMetadata::from_block(block, certified.qc_verifiable().clone());
        batch_put::<BlocksCf>(
            batch,
            BlocksCf::handle(&cf),
            &block.height().inner(),
            &metadata,
        );
        let transactions_cf = TransactionsCf::handle(&cf);
        for tx in block.transactions().iter() {
            batch_put_raw::<TransactionsCf>(
                batch,
                transactions_cf,
                &Hash::from(tx.hash()),
                tx.as_ref(),
                Some(tx.cached_wire_bytes()),
            );
        }
        let certificates_cf = CertificatesCf::handle(&cf);
        for fw in block.certificates().iter() {
            batch_put::<CertificatesCf>(
                batch,
                certificates_cf,
                &fw.receipt_hash(),
                &fw.attestation(),
            );
        }
    }

    /// Fold a block's provision bodies into the same batch, and drop
    /// every body a replay could no longer read.
    ///
    /// The block is still `Live` here — `into_sealed` runs on the way
    /// into the blocks CF in this same call — so this is the last point
    /// the bundles exist to be written.
    ///
    /// The floor is the history retention floor rather than the
    /// unresolved set's: a replay reads state as of the block below the
    /// one it starts at, and `snapshot_at` cannot serve below the floor.
    /// Nothing kept under that line could be replayed against, so nothing
    /// under it is worth keeping.
    ///
    /// The floor is the one this commit's own advance established, passed
    /// in rather than read back: the store still holds the previous one
    /// until the batch lands, and cutting at that would keep a block of
    /// bundles nothing can replay against.
    fn append_provisions_to_batch(&self, batch: &mut WriteBatch, block: &Block, floor: u64) {
        let provisions = block.provisions();
        let height = block.height();
        let cf = self.cf();
        let provisions_cf = ProvisionsCf::handle(&cf);

        if floor > 0 {
            let codec = ProvisionKeyCodec;
            batch.delete_range_cf(
                provisions_cf,
                codec.encode(&(BlockHeight::GENESIS, ProvisionHash::from_raw(Hash::ZERO))),
                codec.encode(&(BlockHeight::new(floor), ProvisionHash::from_raw(Hash::ZERO))),
            );
        }

        for bundle in provisions {
            batch_put::<ProvisionsCf>(
                batch,
                provisions_cf,
                &(height, bundle.hash()),
                bundle.as_unverified(),
            );
        }
    }

    /// Fold a block's beacon-witness commit into an existing
    /// `WriteBatch`: each appended leaf at position `i` lands at key
    /// `starting_leaf_index + i` in
    /// [`BeaconWitnessesCf`](crate::column_families::BeaconWitnessesCf),
    /// and a carried retention floor range-deletes the leaves below it.
    ///
    /// Called from the prepared commit so the witness writes commit in
    /// the same atomic batch as the block + JMT.
    pub(crate) fn append_beacon_witnesses_to_batch(
        &self,
        batch: &mut WriteBatch,
        witness: &BeaconWitnessCommit,
    ) {
        let cf = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cf);
        if let Some(floor) = witness.prune_persisted_below
            && floor.inner() > 0
        {
            // BE-encoded u64 keys are byte-ordered, so the range delete
            // drops exactly the leaves below the floor.
            batch.delete_range_cf(
                beacon_witnesses_cf,
                0u64.to_be_bytes(),
                floor.inner().to_be_bytes(),
            );
        }
        let start = witness.starting_leaf_index.inner();
        for (offset, payload) in witness.leaves.iter().enumerate() {
            let leaf_index = start + offset as u64;
            batch_put::<BeaconWitnessesCf>(batch, beacon_witnesses_cf, &leaf_index, payload);
        }
    }

    /// Get a committed block by height (reconstructs from denormalized storage).
    ///
    /// Fetches block metadata, then batch-fetches transactions and certificates
    /// using the stored hashes to reconstruct the full block.
    ///
    /// Returns `None` if the block metadata is not found, or if any referenced
    /// transactions or certificates are missing. This ensures sync responses
    /// always contain complete, self-contained blocks.
    pub(crate) fn get_block_denormalized(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        let start = Instant::now();

        // Resolve column-family handles once for the whole reconstruction.
        // Per-method `cf_get`/`cf_multi_get`/`get_consensus_receipt` would
        // each invoke `self.cf()`, re-walking all 12 CFs through `RocksDB`'s
        // name → handle map per call — and the per-receipt loop below would
        // pay that cost N times.
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let transactions_cf = TransactionsCf::handle(&cf);
        let certificates_cf = CertificatesCf::handle(&cf);
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);

        // 1. Get block metadata
        let metadata: BlockMetadata = get::<BlocksCf>(&*self.db, blocks_cf, &height.inner())?;

        let (header, manifest, qc, _) = metadata.into_parts();

        // 2. Batch-fetch transactions (preserving order)
        let transactions =
            self.get_transactions_batch_ordered(transactions_cf, manifest.tx_hashes());

        // Verify we got ALL transactions - return None if any are missing
        let total_expected = manifest.transaction_count();
        if transactions.len() != total_expected {
            tracing::warn!(
                height = height.inner(),
                expected = total_expected,
                found = transactions.len(),
                "Block has missing transactions - cannot serve sync request"
            );
            return None;
        }

        // 3. Batch-fetch certificates (preserving order)
        let certs = self.get_certificates_batch_ordered(certificates_cf, manifest.cert_ids());

        // Verify we got ALL certificates - return None if any are missing
        if certs.len() != manifest.cert_ids().len() {
            tracing::warn!(
                height = height.inner(),
                expected = manifest.cert_ids().len(),
                found = certs.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            return None;
        }

        // 4. Reconstruct each Finalization from cert + stored receipts.
        //
        // The reconstructed ticks arrive at the Block as
        // `Verifiable::Unverified`: the on-disk shape didn't carry the
        // marker, so the upstream verification claim isn't available here.
        // Downstream readers run the predicate when needed.
        let certificates: Option<Vec<Arc<Verifiable<Finalization>>>> = certs
            .into_iter()
            .map(|cert| {
                Finalization::reconstruct(cert, |h| {
                    get::<ConsensusReceiptsCf>(&*self.db, consensus_cf, &Hash::from(*h))
                        .map(Arc::new)
                })
                .map(|fw| Arc::new(fw.into()))
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::warn!(
                height = height.inner(),
                "Block has missing receipts for a non-aborted tx - cannot reconstruct Finalization"
            );
            return None;
        };

        // 5. Reconstruct as `Sealed` — the on-disk shape never carries
        // provision bodies, but the manifest's provision-hash list rides
        // along so sync-serving glue can re-attach bodies from the
        // in-memory cache when a requester is still within the
        // execution window.
        let transactions: Vec<Arc<Verifiable<Transaction>>> = transactions
            .into_iter()
            .map(|tx| {
                Arc::new(Verifiable::from(Verified::<Transaction>::from_persisted(
                    (*tx).clone(),
                )))
            })
            .collect();
        let block = Block::Sealed {
            header,
            transactions: Arc::new(transactions),
            certificates: Arc::new(certificates),
            provision_hashes: Arc::new(manifest.provision_hashes().clone()),
            abandonment_records: Arc::new(manifest.abandonment_records().clone()),
            state_claims: Arc::new(manifest.state_claims().clone()),
            witness_sources: Arc::new(manifest.witness_sources().clone()),
        };

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_denormalized", elapsed);

        match CertifiedBlock::new_checked(block, qc) {
            Ok(certified) => Some(certified),
            Err(err) => {
                tracing::error!(
                    height = height.inner(),
                    block_hash = ?err.block_hash,
                    qc_block_hash = ?err.qc_block_hash,
                    "Stored block and QC have mismatched hashes — possible corruption"
                );
                None
            }
        }
    }

    /// Get a complete block for serving sync requests.
    ///
    /// Returns `Some((block, qc))` only if the full block is available with all
    /// transactions and certificates. Returns `None` if:
    /// - Block metadata doesn't exist at this height
    /// - Any transactions are missing
    /// - Any certificates are missing
    ///
    /// This ensures sync responses always contain complete, self-contained blocks.
    /// If a peer can't provide a complete block, the requester should try another peer.
    pub(crate) fn get_block_for_sync(
        &self,
        height: BlockHeight,
    ) -> Option<(Block, QuorumCertificate, Vec<ProvisionHash>)> {
        let start = Instant::now();

        // Hoist for the same reason as `get_block_denormalized`.
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let transactions_cf = TransactionsCf::handle(&cf);
        let certificates_cf = CertificatesCf::handle(&cf);
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);

        // 1. Get block metadata
        let metadata: BlockMetadata = get::<BlocksCf>(&*self.db, blocks_cf, &height.inner())?;
        let (header, manifest, qc, _) = metadata.into_parts();
        let qc = qc.into_unverified();

        // 2. Try to batch-fetch transactions (preserving order)
        let transactions =
            self.get_transactions_batch_ordered(transactions_cf, manifest.tx_hashes());

        // Check if all transactions are present - if not, return None
        let total_expected = manifest.transaction_count();
        if transactions.len() != total_expected {
            tracing::debug!(
                height = height.inner(),
                expected = total_expected,
                found = transactions.len(),
                "Block has missing transactions - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 3. Try to batch-fetch certificates (preserving order)
        let certs = self.get_certificates_batch_ordered(certificates_cf, manifest.cert_ids());

        // Check if all certificates are present - if not, return None
        if certs.len() != manifest.cert_ids().len() {
            tracing::debug!(
                height = height.inner(),
                expected = manifest.cert_ids().len(),
                found = certs.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 4. Reconstruct each Finalization from cert + stored receipts. If any
        // tick has a non-aborted tx whose receipt is missing, the block is not
        // servable and the syncing peer must try a different source.
        //
        // Reconstructed ticks arrive at the Block as
        // `Verifiable::Unverified` — see the sibling reader above for
        // rationale.
        let certificates: Option<Vec<Arc<Verifiable<Finalization>>>> = certs
            .into_iter()
            .map(|cert| {
                Finalization::reconstruct(cert, |h| {
                    get::<ConsensusReceiptsCf>(&*self.db, consensus_cf, &Hash::from(*h))
                        .map(Arc::new)
                })
                .map(|fw| Arc::new(fw.into()))
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::debug!(
                height = height.inner(),
                "Block has missing receipts - cannot reconstruct Finalization for sync"
            );
            let elapsed = start.elapsed().as_secs_f64();
            record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        };

        // 5. Full block available - reconstruct as `Sealed`: on-disk form
        // carries no provision bodies, but the manifest's hash list rides
        // along on `Block::Sealed.provision_hashes` so sync-serving glue
        // can attach bodies from the in-memory cache when the requester
        // needs them.
        let provision_hashes_bounded = manifest.provision_hashes().clone();
        let transactions: Vec<Arc<Verifiable<Transaction>>> = transactions
            .into_iter()
            .map(|tx| {
                Arc::new(Verifiable::from(Verified::<Transaction>::from_persisted(
                    (*tx).clone(),
                )))
            })
            .collect();
        let block = Block::Sealed {
            header,
            transactions: Arc::new(transactions),
            certificates: Arc::new(certificates),
            provision_hashes: Arc::new(provision_hashes_bounded.clone()),
            abandonment_records: Arc::new(manifest.abandonment_records().clone()),
            state_claims: Arc::new(manifest.state_claims().clone()),
            witness_sources: Arc::new(manifest.witness_sources().clone()),
        };
        let provision_hashes = provision_hashes_bounded;

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_for_sync_complete", elapsed);

        Some((block, qc, provision_hashes))
    }

    /// Get multiple transactions by hash, preserving order.
    ///
    /// Unlike `get_transactions_batch`, this returns results in the same order
    /// as the input hashes, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_transactions_batch_ordered(
        &self,
        transactions_cf: &ColumnFamily,
        hashes: &[TxHash],
    ) -> Vec<Arc<Transaction>> {
        if hashes.is_empty() {
            return vec![];
        }

        let raw: Vec<Hash> = hashes.iter().map(|h| Hash::from(*h)).collect();
        let results = multi_get::<TransactionsCf>(&*self.db, transactions_cf, &raw);

        results
            .into_iter()
            .zip(hashes.iter())
            .filter_map(|(result, hash)| {
                let Some(tx) = result else {
                    tracing::trace!(?hash, "Transaction not found in storage");
                    return None;
                };
                Some(Arc::new(tx))
            })
            .collect()
    }

    /// Get multiple certificates by `TickId`, preserving order.
    ///
    /// Unlike `get_certificates_batch`, this returns results in the same order
    /// as the input ids, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_certificates_batch_ordered(
        &self,
        certificates_cf: &ColumnFamily,
        ids: &[FinalizationHash],
    ) -> Vec<Finalization> {
        if ids.is_empty() {
            return vec![];
        }

        let results = multi_get::<CertificatesCf>(&*self.db, certificates_cf, ids);

        results
            .into_iter()
            .zip(ids.iter())
            .filter_map(|(result, id)| {
                result.or_else(|| {
                    tracing::trace!(?id, "Certificate not found in storage");
                    None
                })
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Chain metadata
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the chain metadata (committed height, hash, and QC).
    ///
    /// Reads all three chain metadata keys in one call. Use the individual
    /// `read_committed_height`, `read_committed_hash`, `read_latest_qc`
    /// methods when only one value is needed.
    #[must_use]
    pub(crate) fn get_chain_metadata(
        &self,
    ) -> (
        BlockHeight,
        Option<Hash>,
        Option<Verified<QuorumCertificate>>,
    ) {
        let start = Instant::now();

        let height = self.read_committed_height();
        let hash = self.read_committed_hash();
        let qc = self.read_latest_qc();

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_chain_metadata", elapsed);

        (height, hash, qc)
    }

    /// Read only the committed height from `RocksDB`.
    pub(crate) fn read_committed_height(&self) -> BlockHeight {
        read_committed_height(&*self.db)
    }

    /// Read only the committed hash from `RocksDB`.
    pub(crate) fn read_committed_hash(&self) -> Option<Hash> {
        read_committed_hash(&*self.db)
    }

    /// Read only the latest QC from `RocksDB`.
    pub(crate) fn read_latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        read_committed_qc(&*self.db).map(Verified::<QuorumCertificate>::from_persisted)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a finalization's attestation.
    pub fn put_certificate(&self, id: &FinalizationHash, cert: &Finalization) {
        self.cf_put_sync::<CertificatesCf>(id, cert);
    }

    /// Get a finalization's attestation by identity.
    #[must_use]
    pub fn get_certificate(&self, id: &FinalizationHash) -> Option<Finalization> {
        self.cf_get::<CertificatesCf>(id)
    }

    /// Get multiple attestations by identity (batch read).
    ///
    /// Uses `RocksDB`'s `multi_get_cf` for efficient batch retrieval.
    /// Returns only certificates that were found (missing ids are skipped).
    #[must_use]
    pub(crate) fn get_certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        if ids.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let results = self.cf_multi_get::<CertificatesCf>(ids);
        let certs: Vec<_> = results.into_iter().flatten().collect();

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_certificates_batch", elapsed);

        certs
    }
}

// ─── Test-only helpers ───────────────────────────────────────────────────────
//
// These methods bypass the production `commit_lock` discipline (e.g.,
// `set_chain_metadata` writes the chain-metadata keys outside the main
// commit batch). They exist purely so tests can seed storage state without
// going through full block commits. Gated to test builds so production
// code can't accidentally call them.
#[cfg(test)]
mod test_helpers {
    use hyperscale_types::{BlockHeight, Hash, QuorumCertificate};
    use rocksdb::{WriteBatch, WriteOptions};

    use super::super::core::RocksDbShardStorage;
    use super::super::metadata::{
        write_committed_hash, write_committed_height, write_committed_qc,
    };

    impl RocksDbShardStorage {
        /// Test-only seed for `committed_height` / `committed_hash` /
        /// `latest_qc`. Production block commits write these three keys
        /// inside the main commit batch via `append_consensus_to_batch`,
        /// folded into the atomic JMT-update flush under `commit_lock`.
        ///
        /// # Panics
        /// Panics if the synced `WriteBatch` fails.
        pub(crate) fn set_chain_metadata(
            &self,
            height: BlockHeight,
            hash: Option<Hash>,
            qc: Option<&QuorumCertificate>,
        ) {
            let mut batch = WriteBatch::default();
            write_committed_height(&mut batch, height);
            if let Some(h) = hash {
                write_committed_hash(&mut batch, &h);
            }
            if let Some(qc) = qc {
                write_committed_qc(&mut batch, qc);
            }
            let mut opts = WriteOptions::default();
            opts.set_sync(true);
            self.db
                .write_opt(batch, &opts)
                .expect("set_chain_metadata: synced write failed");
        }
    }
}
