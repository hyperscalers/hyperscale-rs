//! `ChainReader` implementation for `SimStorage`.

use crate::core::SimStorage;

use hyperscale_storage::ChainReader;
use hyperscale_types::{
    Block, BlockHeight, ExecutionCertificate, Hash, LocalReceipt, QuorumCertificate,
    RoutableTransaction, ShardGroupId, WaveCertificate,
};
use std::sync::Arc;

impl ChainReader for SimStorage {
    fn get_block(&self, height: BlockHeight) -> Option<(Block, QuorumCertificate)> {
        self.consensus.read().unwrap().blocks.get(&height).cloned()
    }

    fn committed_height(&self) -> BlockHeight {
        self.consensus.read().unwrap().committed_height
    }

    fn committed_hash(&self) -> Option<Hash> {
        self.consensus.read().unwrap().committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        self.consensus.read().unwrap().committed_qc.clone()
    }

    fn get_block_for_sync(
        &self,
        height: BlockHeight,
    ) -> Option<(Block, QuorumCertificate, Vec<Hash>)> {
        self.consensus
            .read()
            .unwrap()
            .blocks
            .get(&height)
            .cloned()
            .map(|(block, qc)| {
                let provision_hashes =
                    hyperscale_types::BlockManifest::from_block(&block).provision_hashes;
                // The on-disk (persisted) shape is always `Sealed`. Collapse
                // to `Sealed` here so memory and rocksdb backends return the
                // same variant; sync-serving glue upgrades to `Live` when
                // the requester is still in the execution window.
                let sealed = Block::Sealed {
                    header: block.header().clone(),
                    transactions: block.transactions().to_vec(),
                    certificates: block.certificates().to_vec(),
                };
                (sealed, qc, provision_hashes)
            })
    }

    fn get_transactions_batch(&self, hashes: &[Hash]) -> Vec<RoutableTransaction> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, hashes: &[Hash]) -> Vec<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        hashes
            .iter()
            .filter_map(|h| c.certificates.get(h).cloned())
            .collect()
    }

    fn get_local_receipt(&self, tx_hash: &Hash) -> Option<Arc<LocalReceipt>> {
        self.consensus
            .read()
            .unwrap()
            .local_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificates_by_height(&self, block_height: u64) -> Vec<ExecutionCertificate> {
        let c = self.consensus.read().unwrap();
        c.execution_certs_by_height
            .get(&block_height)
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|h| c.execution_certs.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_wave_certificate_for_tx(&self, tx_hash: &Hash) -> Option<WaveCertificate> {
        let c = self.consensus.read().unwrap();
        let wave_id_hash = c.tx_to_wave.get(tx_hash)?;
        c.certificates.get(wave_id_hash).cloned()
    }

    fn get_ec_hashes_for_tx(&self, tx_hash: &Hash) -> Option<Vec<(ShardGroupId, Hash)>> {
        self.consensus
            .read()
            .unwrap()
            .tx_to_ec
            .get(tx_hash)
            .cloned()
    }
}
