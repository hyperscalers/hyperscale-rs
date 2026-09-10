//! `ShardChainReader` implementation for `SimShardStorage`.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_storage::{BlockForSync, ShardChainReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockManifest, CertifiedBlock,
    CertifiedBlockHeader, ConsensusReceipt, ExecutionCertificate, Finalization, FinalizationHash,
    Hash, ProvisionHash, Provisions, QuorumCertificate, ShardWitnessPayload, TickId, Transaction,
    TxHash, Verifiable, Verified,
};

use super::core::SimShardStorage;

impl ShardChainReader for SimShardStorage {
    fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
            .map(Verified::<CertifiedBlock>::from_persisted)
    }

    fn provisions_at(&self, height: BlockHeight) -> Vec<Arc<Verifiable<Provisions>>> {
        read_or_recover(&self.consensus)
            .provisions
            .range((height, ProvisionHash::from_raw(Hash::ZERO))..)
            .take_while(|((at, _), _)| *at == height)
            .map(|(_, provisions)| Arc::new(Verifiable::from((**provisions).clone())))
            .collect()
    }

    fn get_certified_header(&self, height: BlockHeight) -> Option<Verified<CertifiedBlockHeader>> {
        let consensus = read_or_recover(&self.consensus);
        consensus
            .blocks
            .get(&height)
            .map(|certified| {
                CertifiedBlockHeader::new(
                    certified.block().header().clone(),
                    certified.qc().clone(),
                )
            })
            .or_else(|| consensus.boundary_headers.get(&height).cloned())
            .map(Verified::<CertifiedBlockHeader>::from_persisted)
    }

    fn committed_height(&self) -> BlockHeight {
        read_or_recover(&self.consensus).committed_height
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        read_or_recover(&self.consensus).committed_hash
    }

    fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        read_or_recover(&self.consensus)
            .committed_qc
            .clone()
            .map(Verified::<QuorumCertificate>::from_persisted)
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
            .map(|certified| {
                let (block, qc) = certified.into_parts();
                let provision_hashes = BlockManifest::from_block(&block).provision_hashes().clone();
                BlockForSync {
                    block,
                    qc: qc.into_unverified(),
                    provision_hashes,
                }
            })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<Transaction>> {
        let c = read_or_recover(&self.consensus);
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .map(Verified::<Transaction>::from_persisted)
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        let c = read_or_recover(&self.consensus);
        ids.iter()
            .filter_map(|id| c.certificates.get(id).cloned())
            .collect()
    }

    fn get_consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        read_or_recover(&self.consensus)
            .consensus_receipts
            .get(tx_hash)
            .cloned()
    }

    fn get_execution_certificate(
        &self,
        tick_id: &TickId,
    ) -> Option<Verified<ExecutionCertificate>> {
        read_or_recover(&self.consensus)
            .execution_certs
            .get(tick_id)
            .cloned()
            .map(Verified::<ExecutionCertificate>::from_persisted)
    }

    fn get_execution_certificates_batch(
        &self,
        tick_ids: &[TickId],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let c = read_or_recover(&self.consensus);
        tick_ids
            .iter()
            .filter_map(|wid| c.execution_certs.get(wid).cloned())
            .map(Verified::<ExecutionCertificate>::from_persisted)
            .collect()
    }

    fn get_execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>> {
        let c = read_or_recover(&self.consensus);
        let mut seen: HashSet<&TickId> = HashSet::new();
        tx_hashes
            .iter()
            .filter_map(|tx| c.tx_cert_index.get(tx))
            .flatten()
            .filter(|tick_id| seen.insert(tick_id))
            .filter_map(|tick_id| c.execution_certs.get(tick_id).cloned())
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
