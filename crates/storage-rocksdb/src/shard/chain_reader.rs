//! `ShardChainReader` implementation for `RocksDbShardStorage`.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_storage::{BlockForSync, ShardChainReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, CertifiedBlock, CertifiedBlockHeader,
    ConsensusReceipt, ExecutionCertificate, Finalization, FinalizationHash, Hash, ProvisionHash,
    Provisions, QuorumCertificate, ShardWitnessPayload, TickId, Transaction, TxHash, Verifiable,
    Verified,
};

use super::column_families::{BeaconWitnessesCf, ExecutionCertsCf, ProvisionsCf, TxCertIndexCf};
use super::core::RocksDbShardStorage;
use super::metadata::read_boundary_header;
use crate::typed_cf::{TypedCf, get, iter_all, iter_from};

impl ShardChainReader for RocksDbShardStorage {
    fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        self.get_block_denormalized(height)
            .map(Verified::<CertifiedBlock>::from_persisted)
    }

    fn provisions_at(&self, height: BlockHeight) -> Vec<Arc<Verifiable<Provisions>>> {
        let cf = self.cf();
        let provisions_cf = ProvisionsCf::handle(&cf);
        iter_from::<ProvisionsCf>(
            &self.db,
            provisions_cf,
            &(height, ProvisionHash::from_raw(Hash::ZERO)),
        )
        .take_while(|((at, _), _)| *at == height)
        .map(|(_, provisions)| Arc::new(Verifiable::from(provisions)))
        .collect()
    }

    fn get_certified_header(&self, height: BlockHeight) -> Option<Verified<CertifiedBlockHeader>> {
        self.get_block_metadata(height)
            .map(|metadata| {
                let (header, _, qc, _) = metadata.into_parts();
                CertifiedBlockHeader::new(header, qc)
            })
            .or_else(|| {
                read_boundary_header(&*self.db)
                    .filter(|boundary| boundary.header().height() == height)
            })
            .map(Verified::<CertifiedBlockHeader>::from_persisted)
    }

    fn committed_height(&self) -> BlockHeight {
        self.read_committed_height()
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        self.read_committed_hash().map(BlockHash::from_raw)
    }

    fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        self.read_latest_qc()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        Self::get_block_for_sync(self, height).map(|(block, qc, provision_hashes)| BlockForSync {
            block,
            qc,
            provision_hashes,
        })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<Transaction>> {
        Self::get_transactions_batch(self, hashes)
            .into_iter()
            .map(Verified::<Transaction>::from_persisted)
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        Self::get_certificates_batch(self, ids)
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        Self::get_consensus_receipt(self, tx_hash)
    }

    fn get_execution_certificate(
        &self,
        tick_id: &TickId,
    ) -> Option<Verified<ExecutionCertificate>> {
        let cfs = self.cf();
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        get::<ExecutionCertsCf>(&*self.db, certs_cf, tick_id)
            .map(Verified::<ExecutionCertificate>::from_persisted)
    }

    fn get_execution_certificates_batch(
        &self,
        tick_ids: &[TickId],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let cfs = self.cf();
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        tick_ids
            .iter()
            .filter_map(|wid| get::<ExecutionCertsCf>(&*self.db, certs_cf, wid))
            .map(Verified::<ExecutionCertificate>::from_persisted)
            .collect()
    }

    fn get_execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let cfs = self.cf();
        let index_cf = TxCertIndexCf::handle(&cfs);
        let certs_cf = ExecutionCertsCf::handle(&cfs);
        let mut seen: HashSet<TickId> = HashSet::new();
        tx_hashes
            .iter()
            .filter_map(|tx| get::<TxCertIndexCf>(&*self.db, index_cf, &Hash::from(*tx)))
            .flatten()
            .filter(|tick_id| seen.insert(*tick_id))
            .filter_map(|tick_id| get::<ExecutionCertsCf>(&*self.db, certs_cf, &tick_id))
            .map(Verified::<ExecutionCertificate>::from_persisted)
            .collect()
    }

    fn get_beacon_witness_payloads(&self, end: BeaconWitnessLeafCount) -> Vec<ShardWitnessPayload> {
        let end_raw = end.inner();
        if end_raw == 0 {
            return Vec::new();
        }
        let cfs = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cfs);
        // Big-endian leaf-index keys: a full scan yields leaves in
        // ascending index order; stop once we pass the requested end.
        let mut out = Vec::with_capacity(usize::try_from(end_raw).unwrap_or(usize::MAX));
        for (leaf_index, payload) in iter_all::<BeaconWitnessesCf>(&self.db, beacon_witnesses_cf) {
            if leaf_index >= end_raw {
                break;
            }
            out.push(payload);
        }
        out
    }

    fn get_beacon_witness_payload_range(&self, start: u64, end: u64) -> Vec<ShardWitnessPayload> {
        if start >= end {
            return Vec::new();
        }
        let cfs = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cfs);
        iter_from::<BeaconWitnessesCf>(&self.db, beacon_witnesses_cf, &start)
            .take_while(|(leaf_index, _)| *leaf_index < end)
            .map(|(_, payload)| payload)
            .collect()
    }
}
