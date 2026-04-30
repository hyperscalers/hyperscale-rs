//! Receipt storage for `RocksDB`.

use crate::column_families::{ConsensusReceiptsCf, ExecutionOutputsCf};
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
    pub fn store_receipt_bundle(&self, bundle: &hyperscale_types::StoredReceipt) {
        let mut batch = WriteBatch::default();
        self.add_receipt_bundle_to_batch(&mut batch, bundle);
        self.db
            .write(batch)
            .expect("failed to persist receipt bundle");
    }

    /// Store multiple stored receipts in a single atomic `WriteBatch`.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipt_bundles(&self, bundles: &[hyperscale_types::StoredReceipt]) {
        if bundles.is_empty() {
            return;
        }
        let mut batch = WriteBatch::default();
        for bundle in bundles {
            self.add_receipt_bundle_to_batch(&mut batch, bundle);
        }
        tracing::debug!(
            count = bundles.len(),
            tx_hashes = ?bundles.iter().map(|b| b.tx_hash).collect::<Vec<_>>(),
            "Persisting stored receipts to RocksDB"
        );
        self.db
            .write(batch)
            .expect("failed to persist stored receipts");
    }

    /// Add a single stored receipt's writes to an existing `WriteBatch`.
    pub(crate) fn add_receipt_bundle_to_batch(
        &self,
        batch: &mut WriteBatch,
        bundle: &hyperscale_types::StoredReceipt,
    ) {
        let cf = self.cf();

        typed_cf::batch_put::<ConsensusReceiptsCf>(
            batch,
            ConsensusReceiptsCf::handle(&cf),
            bundle.tx_hash.as_raw(),
            &bundle.consensus,
        );

        if let Some(ref metadata) = bundle.metadata {
            typed_cf::batch_put::<ExecutionOutputsCf>(
                batch,
                ExecutionOutputsCf::handle(&cf),
                bundle.tx_hash.as_raw(),
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
    pub fn get_execution_output(
        &self,
        tx_hash: &TxHash,
    ) -> Option<hyperscale_types::ExecutionMetadata> {
        self.cf_get::<ExecutionOutputsCf>(tx_hash.as_raw())
    }
}
