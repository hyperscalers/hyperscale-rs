//! `ShardChainReader` implementation for `SimShardStorage`.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_storage::{
    BlockForSync, BlockRows, RebuiltBlock, RecoveredState, ShardChainReader, reconstruct_block,
};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockMetadata, CertifiedBlock,
    CertifiedBlockHeader, ConsensusReceipt, ExecutionCertificate, Finalization, FinalizationHash,
    GlobalReceiptHash, Hash, ProvisionHash, Provisions, QuorumCertificate, ShardId,
    ShardWitnessPayload, Transaction, TxHash, Verifiable, Verified,
};

use super::core::SimShardStorage;

impl ShardChainReader for SimShardStorage {
    fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        reconstruct_block(&*read_or_recover(&self.consensus), height)
            .ok()?
            .certified()
    }

    fn provisions_at(&self, height: BlockHeight) -> Vec<Arc<Verifiable<Provisions>>> {
        read_or_recover(&self.consensus)
            .provisions
            .range((height, ProvisionHash::from_raw(Hash::ZERO))..)
            .take_while(|((at, _), _)| *at == height)
            .map(|(_, provisions)| Arc::new(Verifiable::from((**provisions).clone())))
            .collect()
    }

    fn get_block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        read_or_recover(&self.consensus).block_metadata(height)
    }

    fn get_certified_header(&self, height: BlockHeight) -> Option<Verified<CertifiedBlockHeader>> {
        let consensus = read_or_recover(&self.consensus);
        consensus
            .block_metadata(height)
            .map(|metadata| {
                let (header, _, _, qc, _) = metadata.into_parts();
                CertifiedBlockHeader::new(header, qc)
            })
            .or_else(|| {
                consensus
                    .boundary_headers
                    .get(&height)
                    .map(|header| (**header).clone())
            })
            .map(Verified::<CertifiedBlockHeader>::from_persisted)
    }

    fn committed_height(&self) -> BlockHeight {
        read_or_recover(&self.consensus).committed_height
    }

    fn installed_genesis(&self) -> Option<BlockHeight> {
        read_or_recover(&self.consensus).installed_genesis
    }

    fn chain_floor(&self) -> BlockHeight {
        read_or_recover(&self.consensus).chain_floor
    }

    fn committed_head(&self) -> (BlockHeight, Option<BlockHash>) {
        let consensus = read_or_recover(&self.consensus);
        (consensus.committed_height, consensus.committed_hash)
    }

    fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        read_or_recover(&self.consensus)
            .committed_qc
            .clone()
            .map(Verified::<QuorumCertificate>::from_persisted)
    }

    fn load_recovered_state(&self, shard: ShardId) -> RecoveredState {
        Self::load_recovered_state(self, shard)
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        reconstruct_block(&*read_or_recover(&self.consensus), height)
            .ok()
            .map(RebuiltBlock::for_sync)
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<Transaction>> {
        let c = read_or_recover(&self.consensus);
        c.transactions(hashes)
            .into_iter()
            .map(Verified::<Transaction>::from_persisted)
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        read_or_recover(&self.consensus).attestations(ids)
    }

    fn get_consensus_receipt(
        &self,
        tx_hash: &TxHash,
        receipt_hash: &GlobalReceiptHash,
    ) -> Option<Arc<ConsensusReceipt>> {
        read_or_recover(&self.consensus).consensus_receipt(tx_hash, receipt_hash)
    }

    fn get_consensus_receipts(&self, tx_hash: &TxHash) -> Vec<Arc<ConsensusReceipt>> {
        read_or_recover(&self.consensus).consensus_receipts_of(tx_hash)
    }

    fn get_execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let c = read_or_recover(&self.consensus);
        // Every finalization any asked transaction names, read once each:
        // one finalization commonly answers for several of them.
        let asked: BTreeSet<TxHash> = tx_hashes.iter().copied().collect();
        let finalizations: BTreeSet<FinalizationHash> = asked
            .iter()
            .flat_map(|tx| {
                c.tx_finalizations
                    .range((*tx, FinalizationHash::from_raw(Hash::ZERO))..)
                    .take_while(move |(at, _)| at == tx)
                    .map(|(_, finalization)| *finalization)
            })
            .collect();
        finalizations
            .iter()
            .filter_map(|id| c.attestation(id))
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
        let c = read_or_recover(&self.consensus);
        c.beacon_witnesses
            .range(0u64..end_raw)
            .map(|(_, payload)| payload.clone())
            .collect()
    }

    fn get_beacon_witness_payload_range(&self, start: u64, end: u64) -> Vec<ShardWitnessPayload> {
        let c = read_or_recover(&self.consensus);
        c.beacon_witnesses
            .range(start..end)
            .map(|(_, payload)| payload.clone())
            .collect()
    }
}
