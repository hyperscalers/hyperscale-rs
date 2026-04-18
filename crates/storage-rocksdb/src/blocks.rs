//! Denormalized block storage, transaction/certificate CRUD, and chain metadata.

use crate::column_families::{BlocksCf, CertificatesCf, TransactionsCf};
use crate::core::RocksDbStorage;

#[cfg(test)]
use crate::typed_cf::TypedCf;
use hyperscale_metrics as metrics;
use hyperscale_types::{
    Block, BlockHeight, BlockMetadata, FinalizedWave, Hash, QuorumCertificate, RoutableTransaction,
    WaveCertificate,
};
use rocksdb::{WriteBatch, WriteOptions};
use std::sync::Arc;
use std::time::Instant;
#[cfg(test)]
use tracing::{instrument, Level};

impl RocksDbStorage {
    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order. Uses `get_block_denormalized`
    /// for each height to properly reconstruct blocks from metadata + individual
    /// transaction/certificate entries.
    pub fn get_blocks_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Vec<(Block, QuorumCertificate)> {
        let mut result = Vec::new();
        let mut h = from.0;
        while h < to.0 {
            if let Some(block_qc) = self.get_block_denormalized(BlockHeight(h)) {
                result.push(block_qc);
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
        self.cf_put_sync::<TransactionsCf>(&tx.hash(), tx);
    }

    /// Get a transaction by hash.
    pub fn get_transaction(&self, hash: &Hash) -> Option<RoutableTransaction> {
        let start = Instant::now();
        let result = self.cf_get::<TransactionsCf>(hash);
        metrics::record_storage_read(start.elapsed().as_secs_f64());
        result
    }

    /// Get multiple transactions by hash (batch read).
    ///
    /// Uses RocksDB's `multi_get_cf` for efficient batch retrieval.
    /// Returns only transactions that were found (missing hashes are skipped).
    pub fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let results = self.cf_multi_get::<TransactionsCf>(hashes);

        let txs: Vec<_> = results.into_iter().flatten().collect();

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_transactions_batch", elapsed);

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
    /// Append block data to an existing WriteBatch (for atomic commit).
    pub(crate) fn append_block_to_batch(
        &self,
        batch: &mut rocksdb::WriteBatch,
        block: &Block,
        qc: &QuorumCertificate,
    ) {
        let metadata = BlockMetadata::from_block(block, qc.clone());
        self.cf_put::<BlocksCf>(batch, &block.header.height.0, &metadata);
        for tx in block.transactions.iter() {
            self.cf_put_raw::<TransactionsCf>(
                batch,
                &tx.hash(),
                tx.as_ref(),
                tx.cached_sbor_bytes(),
            );
        }
        for fw in &block.certificates {
            self.cf_put::<CertificatesCf>(batch, &fw.wave_id().hash(), fw.certificate.as_ref());
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
    pub(crate) fn get_block_denormalized(
        &self,
        height: BlockHeight,
    ) -> Option<(Block, QuorumCertificate)> {
        let start = Instant::now();

        // 1. Get block metadata
        let metadata: BlockMetadata = self.cf_get::<BlocksCf>(&height.0)?;

        // 2. Batch-fetch transactions (preserving order)
        let transactions = self.get_transactions_batch_ordered(&metadata.manifest.tx_hashes);

        // Verify we got ALL transactions - return None if any are missing
        let total_expected = metadata.manifest.transaction_count();
        if transactions.len() != total_expected {
            tracing::warn!(
                height = height.0,
                expected = total_expected,
                found = transactions.len(),
                "Block has missing transactions - cannot serve sync request"
            );
            return None;
        }

        // 3. Batch-fetch certificates (preserving order)
        let certs = self.get_certificates_batch_ordered(&metadata.manifest.cert_hashes);

        // Verify we got ALL certificates - return None if any are missing
        if certs.len() != metadata.manifest.cert_hashes.len() {
            tracing::warn!(
                height = height.0,
                expected = metadata.manifest.cert_hashes.len(),
                found = certs.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            return None;
        }

        // 4. Reconstruct each FinalizedWave from cert + stored receipts.
        let certificates: Option<Vec<Arc<FinalizedWave>>> = certs
            .into_iter()
            .map(|cert| {
                FinalizedWave::reconstruct(cert, |h| self.get_local_receipt(h)).map(Arc::new)
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::warn!(
                height = height.0,
                "Block has missing receipts for a non-aborted tx - cannot reconstruct FinalizedWave"
            );
            return None;
        };

        // 5. Reconstruct block
        let block = Block {
            header: metadata.header,
            transactions,
            certificates,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_block_denormalized", elapsed);

        Some((block, metadata.qc))
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
        let metadata = self.cf_get::<BlocksCf>(&height.0)?;
        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_block_metadata", elapsed);
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
    pub fn get_block_for_sync(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        let start = Instant::now();

        // 1. Get block metadata
        let metadata: BlockMetadata = self.cf_get::<BlocksCf>(&height.0)?;

        // 2. Try to batch-fetch transactions (preserving order)
        let transactions = self.get_transactions_batch_ordered(&metadata.manifest.tx_hashes);

        // Check if all transactions are present - if not, return None
        let total_expected = metadata.manifest.transaction_count();
        if transactions.len() != total_expected {
            tracing::debug!(
                height = height.0,
                expected = total_expected,
                found = transactions.len(),
                "Block has missing transactions - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            metrics::record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 3. Try to batch-fetch certificates (preserving order)
        let certs = self.get_certificates_batch_ordered(&metadata.manifest.cert_hashes);

        // Check if all certificates are present - if not, return None
        if certs.len() != metadata.manifest.cert_hashes.len() {
            tracing::debug!(
                height = height.0,
                expected = metadata.manifest.cert_hashes.len(),
                found = certs.len(),
                "Block has missing certificates - cannot serve sync request"
            );
            let elapsed = start.elapsed().as_secs_f64();
            metrics::record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        }

        // 4. Reconstruct each FinalizedWave from cert + stored receipts. If any
        // wave has a non-aborted tx whose receipt is missing, the block is not
        // servable and the syncing peer must try a different source.
        let certificates: Option<Vec<Arc<FinalizedWave>>> = certs
            .into_iter()
            .map(|cert| {
                FinalizedWave::reconstruct(cert, |h| self.get_local_receipt(h)).map(Arc::new)
            })
            .collect();
        let Some(certificates) = certificates else {
            tracing::debug!(
                height = height.0,
                "Block has missing receipts - cannot reconstruct FinalizedWave for sync"
            );
            let elapsed = start.elapsed().as_secs_f64();
            metrics::record_storage_operation("get_block_for_sync_incomplete", elapsed);
            return None;
        };

        // 5. Full block available - reconstruct it
        let block = Block {
            header: metadata.header,
            transactions,
            certificates,
        };

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_block_for_sync_complete", elapsed);

        Some((block, metadata.qc))
    }

    /// Get multiple transactions by hash, preserving order.
    ///
    /// Unlike `get_transactions_batch`, this returns results in the same order
    /// as the input hashes, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_transactions_batch_ordered(&self, hashes: &[Hash]) -> Vec<Arc<RoutableTransaction>> {
        if hashes.is_empty() {
            return vec![];
        }

        let results = self.cf_multi_get::<TransactionsCf>(hashes);

        results
            .into_iter()
            .zip(hashes.iter())
            .filter_map(|(result, hash)| match result {
                Some(tx) => Some(Arc::new(tx)),
                None => {
                    tracing::trace!(?hash, "Transaction not found in storage");
                    None
                }
            })
            .collect()
    }

    /// Get multiple certificates by hash, preserving order.
    ///
    /// Unlike `get_certificates_batch`, this returns results in the same order
    /// as the input hashes, with missing entries causing the result to be shorter.
    /// Callers should check that the result length matches the input length.
    fn get_certificates_batch_ordered(&self, hashes: &[Hash]) -> Vec<Arc<WaveCertificate>> {
        if hashes.is_empty() {
            return vec![];
        }

        let results = self.cf_multi_get::<CertificatesCf>(hashes);

        results
            .into_iter()
            .zip(hashes.iter())
            .filter_map(|(result, hash)| match result {
                Some(cert) => Some(Arc::new(cert)),
                None => {
                    tracing::trace!(?hash, "Certificate not found in storage");
                    None
                }
            })
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Chain metadata
    // ═══════════════════════════════════════════════════════════════════════

    /// Set the highest committed block height and hash.
    pub fn set_chain_metadata(
        &self,
        height: BlockHeight,
        hash: Option<Hash>,
        qc: Option<&QuorumCertificate>,
    ) {
        let mut batch = WriteBatch::default();
        crate::metadata::write_committed_height(&mut batch, height);
        if let Some(h) = hash {
            crate::metadata::write_committed_hash(&mut batch, &h);
        }
        if let Some(qc) = qc {
            crate::metadata::write_committed_qc(&mut batch, qc);
        }
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.db
            .write_opt(batch, &opts)
            .expect("BFT SAFETY CRITICAL: chain metadata write failed");
    }

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
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_chain_metadata", elapsed);

        (height, hash, qc)
    }

    /// Read only the committed height from RocksDB.
    pub(crate) fn read_committed_height(&self) -> BlockHeight {
        crate::metadata::read_committed_height(&*self.db)
    }

    /// Read only the committed hash from RocksDB.
    pub(crate) fn read_committed_hash(&self) -> Option<Hash> {
        crate::metadata::read_committed_hash(&*self.db)
    }

    /// Read only the latest QC from RocksDB.
    pub(crate) fn read_latest_qc(&self) -> Option<QuorumCertificate> {
        crate::metadata::read_committed_qc(&*self.db)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate storage
    // ═══════════════════════════════════════════════════════════════════════

    /// Store a wave certificate.
    pub fn put_certificate(&self, hash: &Hash, cert: &WaveCertificate) {
        self.cf_put_sync::<CertificatesCf>(hash, cert);
    }

    /// Get a wave certificate by wave_id hash.
    pub fn get_certificate(&self, hash: &Hash) -> Option<WaveCertificate> {
        self.cf_get::<CertificatesCf>(hash)
    }

    /// Get multiple certificates by hash (batch read).
    ///
    /// Uses RocksDB's `multi_get_cf` for efficient batch retrieval.
    /// Returns only certificates that were found (missing hashes are skipped).
    pub fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        if hashes.is_empty() {
            return vec![];
        }

        let start = Instant::now();
        let results = self.cf_multi_get::<CertificatesCf>(hashes);
        let certs: Vec<_> = results.into_iter().flatten().collect();

        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_storage_read(elapsed);
        metrics::record_storage_operation("get_certificates_batch", elapsed);

        certs
    }

    /// Atomically commit a wave certificate and its state writes.
    ///
    /// This is the deferred commit operation that applies state writes when
    /// a `WaveCertificate` is included in a committed block.
    ///
    /// Uses a RocksDB WriteBatch for atomicity - either both the certificate
    /// and state writes are persisted, or neither is.
    ///
    /// # Panics
    ///
    /// Panics if the commit fails. This is intentional: if we cannot persist the
    /// certificate and state writes, the node's state will diverge from the network.
    #[cfg(test)]
    #[instrument(level = Level::DEBUG, skip_all, fields(
        wave_hash = %certificate.wave_id.hash(),
        latency_us = tracing::field::Empty,
        otel.kind = "INTERNAL",
    ))]
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &WaveCertificate,
        updates: &hyperscale_storage::DatabaseUpdates,
    ) {
        let start = Instant::now();
        let mut batch = rocksdb::WriteBatch::default();
        let mut write_count = 0usize;
        let cf = self.cf();

        // 1. Serialize and add certificate to batch
        self.cf_put::<CertificatesCf>(&mut batch, &certificate.wave_id.hash(), certificate);
        write_count += 1;

        // 2. Add state writes to batch at the current JMT version (this
        //    helper is test-only; production goes through `commit_block`).
        let state_cf = crate::column_families::StateCf::handle(&cf);
        let version = self.read_jmt_metadata().0;
        for (db_node_key, node_updates) in &updates.node_updates {
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                if let hyperscale_storage::PartitionDatabaseUpdates::Delta { substate_updates } =
                    partition_updates
                {
                    for (db_sort_key, update) in substate_updates {
                        let partition_key = hyperscale_storage::DbPartitionKey {
                            node_key: db_node_key.clone(),
                            partition_num: *partition_num,
                        };
                        let key = ((partition_key, db_sort_key.clone()), version);

                        let value_bytes: Vec<u8> = match update {
                            hyperscale_storage::DatabaseUpdate::Set(value) => value.clone(),
                            hyperscale_storage::DatabaseUpdate::Delete => Vec::new(),
                        };
                        crate::typed_cf::batch_put::<crate::column_families::StateCf>(
                            &mut batch,
                            state_cf,
                            &key,
                            &value_bytes,
                        );
                        write_count += 1;
                    }
                }
            }
        }

        // 3. Write batch atomically with sync for durability (JMT deferred to block commit)
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db.write_opt(batch, &write_opts).expect(
            "BFT SAFETY CRITICAL: certificate commit failed - node state would diverge from network",
        );

        tracing::debug!(
            wave_hash = %certificate.wave_id.hash(),
            write_count,
            "Certificate state writes committed (JMT deferred to block commit)"
        );

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("commit_cert_writes", elapsed.as_secs_f64());
        metrics::record_storage_batch_size(write_count);
        metrics::record_certificate_persisted();

        // Record span fields
        tracing::Span::current().record("latency_us", elapsed.as_micros() as u64);
    }
}
