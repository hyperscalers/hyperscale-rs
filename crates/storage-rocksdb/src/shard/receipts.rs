//! Receipt storage for `RocksDB`.

use std::sync::Arc;

use hyperscale_types::{ConsensusReceipt, ExecutionMetadata, StoredReceipt, TxHash};
use rocksdb::{ColumnFamily, WriteBatch};

use super::column_families::{ConsensusReceiptsCf, ExecutionMetadataCf};
use super::core::RocksDbShardStorage;
use crate::typed_cf::{TypedCf, batch_put};

impl RocksDbShardStorage {
    /// One-shot variant of [`Self::store_receipts`] for a single receipt.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipt(&self, receipt: &StoredReceipt) {
        let mut batch = WriteBatch::default();
        let cf = self.cf();
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);
        let metadata_cf = ExecutionMetadataCf::handle(&cf);
        add_receipt_to_batch(&mut batch, consensus_cf, metadata_cf, receipt);
        self.db.write(batch).expect("failed to persist receipt");
    }

    /// Atomic batch persist — consensus and metadata land together so a
    /// crash mid-batch can't leave metadata referencing a missing receipt
    /// (or vice versa).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipts(&self, receipts: &[StoredReceipt]) {
        if receipts.is_empty() {
            return;
        }
        let mut batch = WriteBatch::default();
        let cf = self.cf();
        let consensus_cf = ConsensusReceiptsCf::handle(&cf);
        let metadata_cf = ExecutionMetadataCf::handle(&cf);
        for receipt in receipts {
            add_receipt_to_batch(&mut batch, consensus_cf, metadata_cf, receipt);
        }
        tracing::debug!(
            count = receipts.len(),
            tx_hashes = ?receipts.iter().map(|r| r.tx_hash).collect::<Vec<_>>(),
            "Persisting receipts to RocksDB"
        );
        self.db.write(batch).expect("failed to persist receipts");
    }

    /// Read the consensus portion. Present for any tx that committed
    /// (success or failure); absent for aborted txs and unknown hashes.
    pub fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.cf_get::<ConsensusReceiptsCf>(tx_hash.as_raw())
            .map(Arc::new)
    }

    /// Read the local-only metadata. `None` when the tx was synced from
    /// a peer (peers don't ship their metadata) or pruned earlier than
    /// the consensus portion.
    pub fn get_execution_metadata(&self, tx_hash: &TxHash) -> Option<ExecutionMetadata> {
        self.cf_get::<ExecutionMetadataCf>(tx_hash.as_raw())
    }
}

/// Append a single receipt's writes against pre-resolved column-family
/// handles. Use this from per-block receipt loops where the caller has
/// already paid for one [`RocksDbShardStorage::cf`] resolution; the
/// `&mut self`-method form on `RocksDbShardStorage` repeats that resolution
/// per call and is the right shape only for one-shot writes.
pub fn add_receipt_to_batch(
    batch: &mut WriteBatch,
    consensus_cf: &ColumnFamily,
    metadata_cf: &ColumnFamily,
    receipt: &StoredReceipt,
) {
    batch_put::<ConsensusReceiptsCf>(
        batch,
        consensus_cf,
        receipt.tx_hash.as_raw(),
        &receipt.consensus,
    );

    if let Some(ref metadata) = receipt.metadata {
        batch_put::<ExecutionMetadataCf>(batch, metadata_cf, receipt.tx_hash.as_raw(), metadata);
    }
}
