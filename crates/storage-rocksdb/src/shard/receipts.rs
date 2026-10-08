//! Receipt storage for `RocksDB`.

use std::sync::Arc;

use hyperscale_types::{ConsensusReceipt, GlobalReceiptHash, Hash, StoredReceipt, TxHash};
use rocksdb::{ColumnFamily, WriteBatch};

use super::column_families::ConsensusReceiptsCf;
use super::core::RocksDbShardStorage;
use crate::typed_cf::{TypedCf, batch_put, iter_from};

impl RocksDbShardStorage {
    /// Persist one receipt outside any block commit.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `RocksDB` write fails.
    pub fn store_receipt(&self, receipt: &StoredReceipt) {
        let mut batch = WriteBatch::default();
        let cf = self.cf();
        add_receipts_to_batch(&mut batch, ConsensusReceiptsCf::handle(&cf), [receipt]);
        self.db.write(batch).expect("failed to persist receipt");
    }

    /// Read the consensus receipt `tx_hash` settled under `receipt_hash`.
    /// Absent for aborted txs, unknown hashes, and a hash the transaction
    /// never settled here.
    pub(crate) fn get_consensus_receipt(
        &self,
        tx_hash: &TxHash,
        receipt_hash: &GlobalReceiptHash,
    ) -> Option<Arc<ConsensusReceipt>> {
        self.cf_get::<ConsensusReceiptsCf>(&(*tx_hash, *receipt_hash))
            .map(Arc::new)
    }

    /// Every consensus receipt `tx_hash` settled here, in receipt-hash
    /// order.
    pub(crate) fn get_consensus_receipts(&self, tx_hash: &TxHash) -> Vec<Arc<ConsensusReceipt>> {
        let cf = self.cf();
        iter_from::<ConsensusReceiptsCf>(
            &self.db,
            ConsensusReceiptsCf::handle(&cf),
            &(*tx_hash, GlobalReceiptHash::from_raw(Hash::ZERO)),
        )
        .take_while(|((at, _), _)| at == tx_hash)
        .map(|(_, receipt)| Arc::new(receipt))
        .collect()
    }
}

/// Append `receipts` to `batch` against a pre-resolved column-family
/// handle, each under its transaction and its own hash.
pub fn add_receipts_to_batch<'a>(
    batch: &mut WriteBatch,
    consensus_cf: &ColumnFamily,
    receipts: impl IntoIterator<Item = &'a StoredReceipt>,
) {
    for receipt in receipts {
        batch_put::<ConsensusReceiptsCf>(
            batch,
            consensus_cf,
            &(receipt.tx_hash, receipt.consensus.receipt_hash()),
            &receipt.consensus,
        );
    }
}
