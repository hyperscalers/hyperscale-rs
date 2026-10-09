//! Denormalized block storage in `RocksDB`.
//!
//! A committed [`CertifiedBlock`] is sharded across four column families:
//! [`BlocksCf`] holds per-height [`BlockMetadata`] (header + manifest + qc),
//! [`TransactionsCf`] holds individual transactions keyed by [`TxHash`],
//! [`CertificatesCf`] holds finalization attestations keyed by their
//! [`FinalizationHash`], and [`ConsensusReceiptsCf`] holds the consensus
//! receipt each transaction settled.
//!
//! Reading a block rebuilds it from those rows through
//! [`reconstruct_block`], the reconstruction every backend shares. This
//! layout keeps individual transactions independently seekable (used by
//! the RPC `/transactions/:hash` endpoint and by cross-shard fetch
//! protocols) while avoiding write amplification on commit, since each
//! transaction is only written once even when it appears in multiple
//! block-level views.

use std::sync::Arc;
use std::time::Instant;

use hyperscale_metrics::{record_storage_operation, record_storage_read};
use hyperscale_storage::{
    BlockForSync, BlockRowKeys, BlockRows, ChainHold, Unbuilt, reconstruct_block,
};
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, BlockMetadata,
    CertifiedBlock, ConsensusReceipt, Finalization, FinalizationHash, GlobalReceiptHash, Hash,
    ProvisionHash, QuorumCertificate, ShardId, Transaction, TxHash, Verified,
};
use rocksdb::{ColumnFamily, DB, WriteBatch};

use super::column_families::{
    BeaconWitnessesCf, BlocksCf, CertificatesCf, CfHandles, ConsensusReceiptsCf, ProvisionKeyCodec,
    ProvisionsCf, TransactionsCf, TxFinalizationsCf, VotedBlockKeyCodec, VotedBlocksCf,
};
use super::core::RocksDbShardStorage;
use super::metadata::{
    read_chain_floor, read_committed_hash, read_committed_height, read_committed_qc,
};
use super::receipts::add_receipts_to_batch;
use crate::typed_cf::{
    self, BeU64Codec, DbEncode, TypedCf, batch_put, batch_put_raw, get, multi_get,
};

impl RocksDbShardStorage {
    /// Get a range of committed blocks [from, to).
    ///
    /// Returns blocks in ascending height order, each rebuilt from its
    /// rows; a height that does not rebuild is skipped.
    #[must_use]
    pub fn get_blocks_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Vec<Verified<CertifiedBlock>> {
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
        let tx_finalizations_cf = TxFinalizationsCf::handle(&cf);
        let local_shard = block.header().shard_id();
        for fw in block.certificates().iter() {
            let hash = fw.receipt_hash();
            batch_put::<CertificatesCf>(batch, certificates_cf, &hash, &fw.attestation());
            // The by-transaction index rides the same batch, so a crash
            // cannot leave a key naming a finalization the certificates
            // family lacks. Only a finalization of this shard's own tick
            // is indexed, and only for its local certificate: a
            // counterpart's certificate riding inside it answers a
            // question nobody asks this shard, and an asker served its
            // own certificate back refuses it as unsolicited and asks
            // again.
            if fw.tick_id().shard_id() != local_shard {
                continue;
            }
            for outcome in fw.local_ec().tx_outcomes() {
                batch_put::<TxFinalizationsCf>(
                    batch,
                    tx_finalizations_cf,
                    &(outcome.tx_hash(), hash),
                    &(),
                );
            }
        }
        self.append_provisions_to_batch(batch, block, retention_floor);
    }

    /// Drop every block row at or above `from` — each height's metadata
    /// row and the provision bundles filed under it — in `batch`.
    ///
    /// A store holds no block above its committed tip, so every reader of
    /// a height trusts what it finds there to be this chain's.
    pub(crate) fn drop_blocks_from_to_batch(&self, batch: &mut WriteBatch, from: BlockHeight) {
        let cf = self.cf();
        batch.delete_range_cf(
            BlocksCf::handle(&cf),
            BeU64Codec.encode(&from.inner()),
            BeU64Codec.encode(&u64::MAX),
        );
        let codec = ProvisionKeyCodec;
        batch.delete_range_cf(
            ProvisionsCf::handle(&cf),
            codec.encode(&(from, ProvisionHash::from_raw(Hash::ZERO))),
            codec.encode(&(
                BlockHeight::new(u64::MAX),
                ProvisionHash::from_raw(Hash::ZERO),
            )),
        );
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
        // The receipts the block's finalizations carry, as a live commit
        // writes them: reading the block back rebuilds each finalization
        // from its attestation and these rows, and a block missing one
        // does not rebuild at all.
        add_receipts_to_batch(
            batch,
            ConsensusReceiptsCf::handle(&cf),
            block.certificates().iter().flat_map(|fw| fw.receipts()),
        );
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

    /// Get a committed block by height, rebuilt from its rows through
    /// [`reconstruct_block`].
    ///
    /// `None` when no block is stored at the height, or when any row its
    /// manifest names is missing: a block is served whole or not at all.
    pub(crate) fn get_block_denormalized(
        &self,
        height: BlockHeight,
    ) -> Option<Verified<CertifiedBlock>> {
        let start = Instant::now();
        let cf = self.cf();
        let rebuilt = match reconstruct_block(&CfBlockRows::new(&self.db, &cf), height) {
            Ok(rebuilt) => rebuilt,
            Err(Unbuilt::Absent) => return None,
            Err(missing) => {
                tracing::warn!(
                    height = height.inner(),
                    ?missing,
                    "Block has missing rows - cannot reconstruct it"
                );
                return None;
            }
        };
        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_denormalized", elapsed);
        rebuilt.certified()
    }

    /// Get a complete block for serving sync requests, rebuilt from its
    /// rows through [`reconstruct_block`].
    ///
    /// `None` when no block is stored at the height or any row its
    /// manifest names is missing, so a sync response always carries a
    /// complete, self-contained block and a requester denied one tries
    /// another peer.
    pub(crate) fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        let start = Instant::now();
        let cf = self.cf();
        let rebuilt = match reconstruct_block(&CfBlockRows::new(&self.db, &cf), height) {
            Ok(rebuilt) => rebuilt,
            Err(Unbuilt::Absent) => return None,
            Err(missing) => {
                tracing::debug!(
                    height = height.inner(),
                    ?missing,
                    "Block has missing rows - cannot serve sync request"
                );
                let elapsed = start.elapsed().as_secs_f64();
                record_storage_operation("get_block_for_sync_incomplete", elapsed);
                return None;
            }
        };
        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_for_sync_complete", elapsed);
        Some(rebuilt.for_sync())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Chain metadata
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the chain metadata (committed height, hash, and QC), all three
    /// read from one snapshot.
    #[must_use]
    pub(crate) fn get_chain_metadata(
        &self,
    ) -> (
        BlockHeight,
        Option<Hash>,
        Option<Verified<QuorumCertificate>>,
    ) {
        let start = Instant::now();

        let snapshot = self.db.snapshot();
        let height = read_committed_height(&snapshot);
        let hash = read_committed_hash(&snapshot);
        let qc = read_committed_qc(&snapshot).map(Verified::<QuorumCertificate>::from_persisted);

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_chain_metadata", elapsed);

        (height, hash, qc)
    }

    /// Read only the committed height from `RocksDB`.
    pub(crate) fn read_committed_height(&self) -> BlockHeight {
        read_committed_height(&*self.db)
    }

    /// Read the committed height and hash from one snapshot.
    pub(crate) fn read_committed_head(&self) -> (BlockHeight, Option<Hash>) {
        let snapshot = self.db.snapshot();
        (
            read_committed_height(&snapshot),
            read_committed_hash(&snapshot),
        )
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

/// Heights one chain collection pass deletes at most, so a pass over a
/// long backlog — a split child's inherited rows, a store whose floor
/// first moved — never holds one batch of unbounded size.
const CHAIN_GC_BATCH: usize = 1024;

impl RocksDbShardStorage {
    /// Delete the heights of `shard`'s chain beneath the chain floor:
    /// each one's metadata row and every row its manifest names, keeping
    /// the bodies and the metadata rows the store's [`ChainHold`] keeps.
    /// Hash-keyed rows cannot be range-deleted, so each height's rows are
    /// read off its manifest before it goes.
    ///
    /// Returns the heights deleted this pass.
    ///
    /// # Panics
    ///
    /// If the collection's batch fails to persist.
    #[must_use]
    pub fn run_chain_gc(&self, shard: ShardId) -> usize {
        let floor = read_chain_floor(&*self.db);
        if floor == BlockHeight::GENESIS {
            return 0;
        }
        // Read after the floor, so every row standing for a height
        // beneath it is in the hold.
        let hold = ChainHold::load(self, shard);

        let cf = self.cf();
        let rows = CfBlockRows::new(&self.db, &cf);
        let blocks_cf = BlocksCf::handle(&cf);
        let mut batch = WriteBatch::default();
        let mut deleted = 0;
        // A held height keeps its row and is walked again each pass, so
        // only the heights that go count toward the pass's bound.
        let below = typed_cf::iter_all::<BlocksCf>(&self.db, blocks_cf)
            .take_while(|(height, _)| *height < floor.inner());
        for (height, metadata) in below {
            if deleted >= CHAIN_GC_BATCH {
                break;
            }
            let keys = BlockRowKeys::of(&rows, &metadata);
            for tx in keys.transactions {
                if !hold.keeps_body(tx) {
                    typed_cf::batch_delete::<TransactionsCf>(
                        &mut batch,
                        TransactionsCf::handle(&cf),
                        &Hash::from(tx),
                    );
                }
            }
            for id in &keys.attestations {
                typed_cf::batch_delete::<CertificatesCf>(
                    &mut batch,
                    CertificatesCf::handle(&cf),
                    id,
                );
            }
            for key in &keys.receipts {
                typed_cf::batch_delete::<ConsensusReceiptsCf>(
                    &mut batch,
                    ConsensusReceiptsCf::handle(&cf),
                    key,
                );
            }
            for key in &keys.tx_finalizations {
                typed_cf::batch_delete::<TxFinalizationsCf>(
                    &mut batch,
                    TxFinalizationsCf::handle(&cf),
                    key,
                );
            }
            if !hold.keeps_row(BlockHeight::new(height)) {
                typed_cf::batch_delete::<BlocksCf>(&mut batch, blocks_cf, &height);
                deleted += 1;
            }
        }
        if !batch.is_empty() {
            self.db
                .write(batch)
                .expect("failed to persist the chain collection");
        }
        deleted
    }
}

/// A committed block's rows read straight off their column families,
/// with every handle resolved once for the whole reconstruction rather
/// than re-walked through `RocksDB`'s name-to-handle map per row.
struct CfBlockRows<'a> {
    db: &'a DB,
    blocks: &'a ColumnFamily,
    transactions: &'a ColumnFamily,
    certificates: &'a ColumnFamily,
    receipts: &'a ColumnFamily,
}

impl<'a> CfBlockRows<'a> {
    fn new(db: &'a DB, cf: &CfHandles<'a>) -> Self {
        Self {
            db,
            blocks: BlocksCf::handle(cf),
            transactions: TransactionsCf::handle(cf),
            certificates: CertificatesCf::handle(cf),
            receipts: ConsensusReceiptsCf::handle(cf),
        }
    }
}

impl BlockRows for CfBlockRows<'_> {
    fn block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        get::<BlocksCf>(self.db, self.blocks, &height.inner())
    }

    fn transactions(&self, hashes: &[TxHash]) -> Vec<Transaction> {
        if hashes.is_empty() {
            return Vec::new();
        }
        let raw: Vec<Hash> = hashes.iter().map(|h| Hash::from(*h)).collect();
        multi_get::<TransactionsCf>(self.db, self.transactions, &raw)
            .into_iter()
            .flatten()
            .collect()
    }

    fn attestations(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        if ids.is_empty() {
            return Vec::new();
        }
        multi_get::<CertificatesCf>(self.db, self.certificates, ids)
            .into_iter()
            .flatten()
            .collect()
    }

    fn consensus_receipt(
        &self,
        tx_hash: &TxHash,
        receipt_hash: &GlobalReceiptHash,
    ) -> Option<Arc<ConsensusReceipt>> {
        get::<ConsensusReceiptsCf>(self.db, self.receipts, &(*tx_hash, *receipt_hash)).map(Arc::new)
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
