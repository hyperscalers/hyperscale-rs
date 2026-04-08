//! Receipt storage for RocksDB.

use crate::column_families::{ExecutionOutputsCf, LocalReceiptsCf};
use crate::core::RocksDbStorage;
use crate::typed_cf::{self, TypedCf};

use hyperscale_types::Hash;
use rocksdb::WriteBatch;
use std::sync::Arc;

impl RocksDbStorage {
    /// Store a receipt bundle (local receipt + optional execution output).
    pub fn store_receipt_bundle(&self, bundle: &hyperscale_types::ReceiptBundle) {
        let mut batch = WriteBatch::default();
        self.add_receipt_bundle_to_batch(&mut batch, bundle);
        self.db
            .write(batch)
            .expect("failed to persist receipt bundle");
    }

    /// Store multiple receipt bundles in a single atomic WriteBatch.
    pub fn store_receipt_bundles(&self, bundles: &[hyperscale_types::ReceiptBundle]) {
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
            "Persisting receipt bundles to RocksDB"
        );
        self.db
            .write(batch)
            .expect("failed to persist receipt bundles");
    }

    /// Add a single receipt bundle's writes to an existing WriteBatch.
    pub(crate) fn add_receipt_bundle_to_batch(
        &self,
        batch: &mut WriteBatch,
        bundle: &hyperscale_types::ReceiptBundle,
    ) {
        let cf = self.cf();

        typed_cf::batch_put::<LocalReceiptsCf>(
            batch,
            LocalReceiptsCf::handle(&cf),
            &bundle.tx_hash,
            bundle.local_receipt.as_ref(),
        );

        if let Some(ref local) = bundle.execution_output {
            typed_cf::batch_put::<ExecutionOutputsCf>(
                batch,
                ExecutionOutputsCf::handle(&cf),
                &bundle.tx_hash,
                local,
            );
        }
    }

    /// Retrieve the local receipt for a transaction.
    pub fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<hyperscale_types::LocalReceipt>> {
        self.cf_get::<LocalReceiptsCf>(tx_hash).map(Arc::new)
    }

    /// Retrieve execution output details for a transaction.
    pub fn get_execution_output(
        &self,
        tx_hash: &Hash,
    ) -> Option<hyperscale_types::ExecutionOutput> {
        self.cf_get::<ExecutionOutputsCf>(tx_hash)
    }
}
