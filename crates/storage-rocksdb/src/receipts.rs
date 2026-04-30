//! Receipt storage for `RocksDB`.

use crate::column_families::{ConsensusReceiptsCf, ExecutionMetadataCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{self, TypedCf};

use hyperscale_types::TxHash;
use rocksdb::WriteBatch;
use std::sync::Arc;

impl RocksDbStorage {
    /// Store a stored receipt (consensus portion + optional metadata).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipt(&self, receipt: &hyperscale_types::StoredReceipt) {
        let mut batch = WriteBatch::default();
        self.add_receipt_to_batch(&mut batch, receipt);
        self.db.write(batch).expect("failed to persist receipt");
    }

    /// Store multiple stored receipts in a single atomic `WriteBatch`.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipts(&self, receipts: &[hyperscale_types::StoredReceipt]) {
        if receipts.is_empty() {
            return;
        }
        let mut batch = WriteBatch::default();
        for receipt in receipts {
            self.add_receipt_to_batch(&mut batch, receipt);
        }
        tracing::debug!(
            count = receipts.len(),
            tx_hashes = ?receipts.iter().map(|r| r.tx_hash).collect::<Vec<_>>(),
            "Persisting receipts to RocksDB"
        );
        self.db.write(batch).expect("failed to persist receipts");
    }

    /// Add a single stored receipt's writes to an existing `WriteBatch`.
    pub(crate) fn add_receipt_to_batch(
        &self,
        batch: &mut WriteBatch,
        receipt: &hyperscale_types::StoredReceipt,
    ) {
        let cf = self.cf();

        typed_cf::batch_put::<ConsensusReceiptsCf>(
            batch,
            ConsensusReceiptsCf::handle(&cf),
            receipt.tx_hash.as_raw(),
            &receipt.consensus,
        );

        if let Some(ref metadata) = receipt.metadata {
            typed_cf::batch_put::<ExecutionMetadataCf>(
                batch,
                ExecutionMetadataCf::handle(&cf),
                receipt.tx_hash.as_raw(),
                metadata,
            );
        }
    }

    /// Retrieve the consensus-bound receipt portion for a transaction.
    pub fn get_consensus_receipt(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Arc<hyperscale_types::ConsensusReceipt>> {
        self.cf_get::<ConsensusReceiptsCf>(tx_hash.as_raw())
            .map(Arc::new)
    }

    /// Retrieve execution metadata for a transaction.
    pub fn get_execution_metadata(
        &self,
        tx_hash: &TxHash,
    ) -> Option<hyperscale_types::ExecutionMetadata> {
        self.cf_get::<ExecutionMetadataCf>(tx_hash.as_raw())
    }
}
