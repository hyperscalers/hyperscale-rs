//! Receipt storage for RocksDB.

use crate::core::RocksDbStorage;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use rocksdb::WriteBatch;
use std::sync::Arc;

impl<D: Dispatch + 'static> RocksDbStorage<D> {
    /// Store a receipt bundle (ledger receipt + optional local execution).
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
        let receipts_cf = self
            .db
            .cf_handle("ledger_receipts")
            .expect("ledger_receipts column family must exist");
        let receipt_bytes = if let Some(ref updates) = bundle.database_updates {
            let mut receipt = (*bundle.ledger_receipt).clone();
            receipt.state_changes = hyperscale_storage::extract_state_changes(updates);
            sbor::basic_encode(&receipt).expect("ledger receipt encoding must succeed")
        } else {
            sbor::basic_encode(bundle.ledger_receipt.as_ref())
                .expect("ledger receipt encoding must succeed")
        };
        batch.put_cf(receipts_cf, bundle.tx_hash.as_bytes(), receipt_bytes);

        if let Some(ref local) = bundle.local_execution {
            let local_cf = self
                .db
                .cf_handle("local_executions")
                .expect("local_executions column family must exist");
            let local_bytes =
                sbor::basic_encode(local).expect("local execution encoding must succeed");
            batch.put_cf(local_cf, bundle.tx_hash.as_bytes(), local_bytes);
        }
    }

    /// Retrieve the ledger receipt for a transaction.
    pub fn get_ledger_receipt(
        &self,
        tx_hash: &Hash,
    ) -> Option<Arc<hyperscale_types::LedgerTransactionReceipt>> {
        let cf = self.db.cf_handle("ledger_receipts")?;
        match self.db.get_cf(cf, tx_hash.as_bytes()) {
            Ok(Some(value)) => {
                match sbor::basic_decode::<hyperscale_types::LedgerTransactionReceipt>(&value) {
                    Ok(receipt) => Some(Arc::new(receipt)),
                    Err(e) => {
                        tracing::error!(
                            ?tx_hash,
                            bytes_len = value.len(),
                            error = ?e,
                            "Ledger receipt exists in storage but SBOR decode failed"
                        );
                        None
                    }
                }
            }
            _ => None,
        }
    }

    /// Retrieve local execution details for a transaction.
    pub fn get_local_execution(
        &self,
        tx_hash: &Hash,
    ) -> Option<hyperscale_types::LocalTransactionExecution> {
        let cf = self.db.cf_handle("local_executions")?;
        match self.db.get_cf(cf, tx_hash.as_bytes()) {
            Ok(Some(value)) => sbor::basic_decode(&value).ok(),
            _ => None,
        }
    }
}
