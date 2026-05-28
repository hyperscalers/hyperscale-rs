//! Denormalized block storage in `RocksDB`.
//!
//! A committed [`CertifiedBlock`] is sharded across four column families:
//! [`BlocksCf`] holds per-height [`BlockMetadata`] (header + manifest + qc),
//! [`TransactionsCf`] holds individual transactions keyed by [`TxHash`],
//! [`CertificatesCf`] holds wave certificates keyed by [`WaveId`], and
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
    BeaconWitnessLeafCount, Block, BlockHeight, BlockMetadata, CertifiedBlock, FinalizedWave, Hash,
    ProvisionHash, QuorumCertificate, RoutableTransaction, ShardWitnessPayload, TxHash, Verifiable,
    Verified, WaveCertificate, WaveId,
};
use rocksdb::{ColumnFamily, WriteBatch};

use super::column_families::{
    BeaconWitnessesCf, BlocksCf, CertificatesCf, ConsensusReceiptsCf, TransactionsCf,
};
use super::core::RocksDbShardStorage;
use super::metadata::{read_committed_hash, read_committed_height, read_committed_qc};
use crate::typed_cf::{TypedCf, batch_put, batch_put_raw, get, multi_get};

impl RocksDbShardStorage {
    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order. Uses `get_block_denormalized`
    /// for each height to properly reconstruct blocks from metadata + individual
    /// transaction/certificate entries.
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
    pub fn put_transaction(&self, tx: &RoutableTransaction) {
        self.cf_put_sync::<TransactionsCf>(tx.hash().as_raw(), tx);
    }

    /// Get a transaction by hash.
    pub fn get_transaction(&self, hash: &TxHash) -> Option<RoutableTransaction> {
        let start = Instant::now();
        let result = self.cf_get::<TransactionsCf>(hash.as_raw());
        record_storage_read(start.elapsed().as_secs_f64());
        result
    }

    /// Get multiple transactions by hash (batch read).
    ///
    /// Uses `RocksDB`'s `multi_get_cf` for efficient batch retrieval.
    /// Returns only transactions that were found (missing hashes are skipped).
    pub fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let raw: Vec<Hash> = hashes.iter().map(|h| h.into_raw()).collect();
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
        for tx in block.transactions().iter() {
            batch_put_raw::<TransactionsCf>(
                batch,
                transactions_cf,
                tx.hash().as_raw(),
                tx.as_ref(),
                Some(tx.cached_sbor_bytes()),
            );
        }
        for fw in block.certificates().iter() {
            batch_put::<CertificatesCf>(
                batch,
                certificates_cf,
                fw.wave_id(),
                fw.certificate().as_ref(),
            );
        }
    }

    /// Append per-block beacon-witness leaves into an existing
    /// `WriteBatch`. Each leaf at position `i` lands at key
    /// `starting_leaf_index + i` in
    /// [`BeaconWitnessesCf`](crate::column_families::BeaconWitnessesCf).
    ///
    /// No-op when `leaves` is empty. Called from `commit_prepared_blocks`
    /// and `commit_block` so the witness writes commit in the same
    /// atomic batch as the block + JMT.
    pub(crate) fn append_beacon_witnesses_to_batch(
        &self,
        batch: &mut WriteBatch,
        starting_leaf_index: BeaconWitnessLeafCount,
        leaves: &[ShardWitnessPayload],
    ) {
        if leaves.is_empty() {
            return;
        }
        let cf = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cf);
        let start = starting_leaf_index.inner();
        for (offset, payload) in leaves.iter().enumerate() {
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

        // 4. Reconstruct each FinalizedWave from cert + stored receipts.
        //
        // The reconstructed waves arrive at the Block as
        // [`Verifiable::Unverified`]: the on-disk shape didn't carry the
        // marker, so the upstream verification claim isn't available here.
        // Downstream readers run the predicate when needed.
        let certificates: Option<Vec<Arc<Verifiable<FinalizedWave>>>> = certs
            .into_iter()
            .map(|cert| {
                FinalizedWave::reconstruct(cert, |h| {
                    get::<ConsensusReceiptsCf>(&*self.db, consensus_cf, h.as_raw()).map(Arc::new)
                })
                .map(|fw| Arc::new(fw.into()))
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::warn!(
                height = height.inner(),
                "Block has missing receipts for a non-aborted tx - cannot reconstruct FinalizedWave"
            );
            return None;
        };

        // 5. Reconstruct as `Sealed` — the on-disk shape never carries
        // provision bodies, but the manifest's provision-hash list rides
        // along so sync-serving glue can re-attach bodies from the
        // in-memory cache when a requester is still within the
        // execution window.
        let transactions: Vec<Arc<Verifiable<RoutableTransaction>>> = transactions
            .into_iter()
            .map(|tx| {
                Arc::new(Verifiable::from(
                    Verified::<RoutableTransaction>::from_persisted((*tx).clone()),
                ))
            })
            .collect();
        let block = Block::Sealed {
            header,
            transactions: Arc::new(transactions.into()),
            certificates: Arc::new(certificates.into()),
            provision_hashes: Arc::new(manifest.provision_hashes().clone()),
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

    /// Get block metadata only (without fetching transactions/certificates).
    ///
    /// This is much faster than `get_block_denormalized` because it only
    /// reads the block metadata from storage, not the full transaction and
    /// certificate data.
    ///
    /// Used for partial sync responses when the full block cannot be
    /// reconstructed (e.g., missing transactions or certificates).
    pub fn get_block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        let start = Instant::now();
        let metadata = self.cf_get::<BlocksCf>(&height.inner())?;
        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_metadata", elapsed);
        Some(metadata)
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
    pub fn get_block_for_sync(
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

        // 4. Reconstruct each FinalizedWave from cert + stored receipts. If any
        // wave has a non-aborted tx whose receipt is missing, the block is not
        // servable and the syncing peer must try a different source.
        //
        // Reconstructed waves arrive at the Block as
        // [`Verifiable::Unverified`] — see the sibling reader above for
        // rationale.
        let certificates: Option<Vec<Arc<Verifiable<FinalizedWave>>>> = certs
            .into_iter()
            .map(|cert| {
                FinalizedWave::reconstruct(cert, |h| {
                    get::<ConsensusReceiptsCf>(&*self.db, consensus_cf, h.as_raw()).map(Arc::new)
                })
                .map(|fw| Arc::new(fw.into()))
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::debug!(
                height = height.inner(),
                "Block has missing receipts - cannot reconstruct FinalizedWave for sync"
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
        let transactions: Vec<Arc<Verifiable<RoutableTransaction>>> = transactions
            .into_iter()
            .map(|tx| {
                Arc::new(Verifiable::from(
                    Verified::<RoutableTransaction>::from_persisted((*tx).clone()),
                ))
            })
            .collect();
        let block = Block::Sealed {
            header,
            transactions: Arc::new(transactions.into()),
            certificates: Arc::new(certificates.into()),
            provision_hashes: Arc::new(provision_hashes_bounded.clone()),
        };
        let provision_hashes = provision_hashes_bounded.into_inner();

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
    ) -> Vec<Arc<RoutableTransaction>> {
        if hashes.is_empty() {
            return vec![];
        }

        let raw: Vec<Hash> = hashes.iter().map(|h| h.into_raw()).collect();
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

    /// Get multiple certificates by `WaveId`, preserving order.
    ///
    /// Unlike `get_certificates_batch`, this returns results in the same order
    /// as the input ids, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_certificates_batch_ordered(
        &self,
        certificates_cf: &ColumnFamily,
        ids: &[WaveId],
    ) -> Vec<Arc<WaveCertificate>> {
        if ids.is_empty() {
            return vec![];
        }

        let results = multi_get::<CertificatesCf>(&*self.db, certificates_cf, ids);

        results
            .into_iter()
            .zip(ids.iter())
            .filter_map(|(result, id)| {
                result.map_or_else(
                    || {
                        tracing::trace!(?id, "Certificate not found in storage");
                        None
                    },
                    |cert| Some(Arc::new(cert)),
                )
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
    pub fn get_chain_metadata(&self) -> (BlockHeight, Option<Hash>, Option<QuorumCertificate>) {
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
    pub(crate) fn read_latest_qc(&self) -> Option<QuorumCertificate> {
        read_committed_qc(&*self.db)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a wave certificate.
    pub fn put_certificate(&self, id: &WaveId, cert: &WaveCertificate) {
        self.cf_put_sync::<CertificatesCf>(id, cert);
    }

    /// Get a wave certificate by `WaveId`.
    pub fn get_certificate(&self, id: &WaveId) -> Option<WaveCertificate> {
        self.cf_get::<CertificatesCf>(id)
    }

    /// Get multiple certificates by `WaveId` (batch read).
    ///
    /// Uses `RocksDB`'s `multi_get_cf` for efficient batch retrieval.
    /// Returns only certificates that were found (missing ids are skipped).
    pub fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
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
    use hyperscale_metrics::{
        record_certificate_persisted, record_storage_batch_size, record_storage_operation,
        record_storage_write,
    };
    use hyperscale_storage::{DatabaseUpdates, PartitionDatabaseUpdates};
    use hyperscale_types::{BlockHeight, Hash, QuorumCertificate, WaveCertificate};
    use rocksdb::{WriteBatch, WriteOptions};
    use tracing::field::Empty;
    use tracing::{Level, Span, instrument};

    use super::super::column_families::CertificatesCf;
    use super::super::core::RocksDbShardStorage;
    use super::super::metadata::{
        write_committed_hash, write_committed_height, write_committed_qc,
    };
    use super::Instant;

    impl RocksDbShardStorage {
        /// Test-only seed for `committed_height` / `committed_hash` /
        /// `latest_qc`. Production block commits write these three keys
        /// inside the main commit batch via `append_consensus_to_batch`,
        /// folded into the atomic JMT-update flush under `commit_lock`.
        ///
        /// # Panics
        /// Panics if the synced `WriteBatch` fails.
        pub fn set_chain_metadata(
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

        /// Test-only deferred-commit shim for a single wave certificate
        /// plus its state writes. Production goes through `commit_block`,
        /// which folds the cert and state writes into the atomic
        /// JMT-update batch under `commit_lock`.
        ///
        /// # Panics
        /// Panics if the synced commit fails.
        #[instrument(level = Level::DEBUG, skip_all, fields(
            wave_id = ?certificate.wave_id(),
            latency_us = Empty,
            otel.kind = "INTERNAL",
        ))]
        pub fn commit_certificate_with_writes(
            &self,
            certificate: &WaveCertificate,
            updates: &DatabaseUpdates,
        ) {
            let start = Instant::now();
            let mut batch = WriteBatch::default();
            let mut write_count = 0usize;

            self.cf_put::<CertificatesCf>(&mut batch, certificate.wave_id(), certificate);
            write_count += 1;

            // Append substate writes to the cert batch at the current JMT
            // version. Delegates to `append_substate_writes_to_batch` so
            // the state-history capture stays single-sourced with the
            // production commit path.
            let version = self.read_jmt_metadata().0;
            let _reset_old_keys = self.append_substate_writes_to_batch(
                &mut batch, updates, version, /* write_history */ true,
                /* base_reads */ None,
            );
            for (_db_node_key, node_updates) in &updates.node_updates {
                for (_partition_num, partition_updates) in &node_updates.partition_updates {
                    if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates
                    {
                        write_count += substate_updates.len();
                    }
                }
            }

            let mut write_opts = WriteOptions::default();
            write_opts.set_sync(true);
            self.db
                .write_opt(batch, &write_opts)
                .expect("commit_certificate_with_writes: synced commit failed");

            tracing::debug!(
                wave_id = ?certificate.wave_id(),
                write_count,
                "Certificate state writes committed (JMT deferred to block commit)"
            );

            let elapsed = start.elapsed();
            record_storage_write(elapsed.as_secs_f64());
            record_storage_operation("commit_cert_writes", elapsed.as_secs_f64());
            record_storage_batch_size(write_count);
            record_certificate_persisted();

            Span::current().record(
                "latency_us",
                u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            );
        }
    }
}
