//! `ShardChainReader` implementation for `RocksDbShardStorage`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use hyperscale_metrics::{record_storage_operation, record_storage_read};
use hyperscale_storage::{BlockForSync, ShardChainReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockMetadata, CertifiedBlock,
    CertifiedBlockHeader, ConsensusReceipt, ExecutionCertificate, Finalization, FinalizationHash,
    Hash, ProvisionHash, Provisions, QuorumCertificate, ShardWitnessPayload, Transaction, TxHash,
    Verifiable, Verified,
};

use super::column_families::{BeaconWitnessesCf, BlocksCf, ProvisionsCf, TxFinalizationsCf};
use super::core::RocksDbShardStorage;
use super::metadata::read_boundary_header;
use crate::typed_cf::{TypedCf, iter_all, iter_from};

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

    fn get_block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        let start = Instant::now();
        let metadata = self.cf_get::<BlocksCf>(&height.inner())?;
        let elapsed = start.elapsed().as_secs_f64();
        record_storage_read(elapsed);
        record_storage_operation("get_block_metadata", elapsed);
        Some(metadata)
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

    fn committed_head(&self) -> (BlockHeight, Option<BlockHash>) {
        let (height, hash) = self.read_committed_head();
        (height, hash.map(BlockHash::from_raw))
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

    fn get_execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let cfs = self.cf();
        let index_cf = TxFinalizationsCf::handle(&cfs);
        // Every finalization any asked transaction names, read once each:
        // one finalization commonly answers for several of them.
        let asked: BTreeSet<TxHash> = tx_hashes.iter().copied().collect();
        let finalizations: BTreeSet<FinalizationHash> = asked
            .iter()
            .flat_map(|tx| {
                iter_from::<TxFinalizationsCf>(
                    &self.db,
                    index_cf,
                    &(*tx, FinalizationHash::from_raw(Hash::ZERO)),
                )
                .take_while(move |((at, _), ())| at == tx)
                .map(|((_, finalization), ())| finalization)
            })
            .collect();
        let ids: Vec<FinalizationHash> = finalizations.into_iter().collect();
        self.get_certificates_batch(&ids)
            .iter()
            .map(|fw| fw.local_ec().clone())
            .filter(|cert| asked.iter().any(|tx| cert.covers(tx)))
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
