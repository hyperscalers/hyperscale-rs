//! `ShardChainReader` implementation for `SimShardStorage`.

use std::sync::Arc;

use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_storage::{BlockForSync, ShardChainReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockManifest, CertifiedBlock,
    CommittedBlockHeader, ConsensusReceipt, ExecutionCertificate, QuorumCertificate,
    RoutableTransaction, ShardWitnessPayload, TxHash, WaveCertificate, WaveId,
};

use super::core::SimShardStorage;

impl ShardChainReader for SimShardStorage {
    fn get_block(&self, height: BlockHeight) -> Option<CertifiedBlock> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
    }

    fn get_committed_header(&self, height: BlockHeight) -> Option<CommittedBlockHeader> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .map(|certified| {
                CommittedBlockHeader::new(
                    certified.block().header().clone(),
                    certified.qc().clone(),
                )
            })
    }

    fn committed_height(&self) -> BlockHeight {
        read_or_recover(&self.consensus).committed_height
    }

    fn committed_hash(&self) -> Option<BlockHash> {
        read_or_recover(&self.consensus).committed_hash
    }

    fn latest_qc(&self) -> Option<QuorumCertificate> {
        read_or_recover(&self.consensus).committed_qc.clone()
    }

    fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        read_or_recover(&self.consensus)
            .blocks
            .get(&height)
            .cloned()
            .map(|certified| {
                let (block, qc) = certified.into_parts();
                let provision_hashes = BlockManifest::from_block(&block)
                    .provision_hashes()
                    .clone()
                    .into_inner();
                BlockForSync {
                    block,
                    qc: qc.into_unverified(),
                    provision_hashes,
                }
            })
    }

    fn get_transactions_batch(&self, hashes: &[TxHash]) -> Vec<RoutableTransaction> {
        let c = read_or_recover(&self.consensus);
        hashes
            .iter()
            .filter_map(|h| c.transactions.get(h).cloned())
            .collect()
    }

    fn get_certificates_batch(&self, ids: &[WaveId]) -> Vec<WaveCertificate> {
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

    fn get_execution_certificate(&self, wave_id: &WaveId) -> Option<ExecutionCertificate> {
        read_or_recover(&self.consensus)
            .execution_certs
            .get(wave_id)
            .cloned()
    }

    fn get_execution_certificates_batch(&self, wave_ids: &[WaveId]) -> Vec<ExecutionCertificate> {
        let c = read_or_recover(&self.consensus);
        wave_ids
            .iter()
            .filter_map(|wid| c.execution_certs.get(wid).cloned())
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
}
