//! FinalizedWave — a completed wave with all data needed for block commit.

use crate::{
    ExecutionCertificate, Hash, ReceiptBundle, TransactionDecision, WaveCertificate, WaveId,
};
use std::sync::Arc;

/// Per-transaction decision derived from EC outcomes across shards.
#[derive(Debug, Clone)]
pub struct TxDecision {
    pub tx_hash: Hash,
    pub decision: TransactionDecision,
}

/// A finalized wave — all participating shards have reported, WaveCertificate created.
///
/// Holds all data needed for block commit: the wave certificate, execution certificates,
/// per-tx decisions, and receipt bundles. Receipts are written atomically with the
/// block at commit time (not fire-and-forget).
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone)]
pub struct FinalizedWave {
    pub certificate: Arc<WaveCertificate>,
    pub tx_hashes: Vec<Hash>,
    pub execution_certificates: Vec<Arc<ExecutionCertificate>>,
    pub tx_decisions: Vec<TxDecision>,
    /// Receipt bundles for all transactions in this wave.
    /// Held in-memory until block commit, then written atomically with block metadata.
    pub receipts: Vec<ReceiptBundle>,
    pub finalized_height: u64,
}

impl FinalizedWave {
    /// Get the wave ID from the certificate.
    pub fn wave_id(&self) -> &WaveId {
        &self.certificate.wave_id
    }

    /// Get the wave ID hash (used as key in pending block tracking).
    pub fn wave_id_hash(&self) -> Hash {
        self.certificate.wave_id.hash()
    }
}
