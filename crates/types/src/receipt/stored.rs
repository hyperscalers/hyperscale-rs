//! Persisted receipt — consensus portion plus optional local metadata.

use crate::{ConsensusReceipt, ExecutionMetadata, TxHash};
use std::sync::Arc;

/// A persisted receipt: consensus-bound portion paired with optional
/// local-only metadata.
///
/// `metadata` is `None` when this receipt was received from a peer (sync
/// or catch-up) — peers don't ship their local logs/fees/errors. When
/// the local node executed the transaction, `metadata` is `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceipt {
    /// Primary key in the per-tx receipt store and the join key against
    /// `WaveCertificate` outcomes during validation.
    pub tx_hash: TxHash,
    /// Shared via `Arc` so flowing a receipt through `PendingChain`,
    /// validation, and persistence is `Arc::clone`-cheap rather than
    /// deep-cloning the substate writes.
    pub consensus: Arc<ConsensusReceipt>,
    /// `Some` ⇔ this node executed the tx locally. Synced-from-peer and
    /// reconstructed receipts are `None` (peers don't ship metadata),
    /// and metadata may also be pruned earlier than the consensus
    /// portion since it's not consensus-critical.
    pub metadata: Option<ExecutionMetadata>,
}

impl StoredReceipt {
    /// Construct a synced receipt — consensus only, no local metadata.
    /// Use at sync-ingress sites where peer-shipped receipts arrive
    /// without their originator's logs/fees/errors.
    #[must_use]
    pub const fn synced(tx_hash: TxHash, consensus: Arc<ConsensusReceipt>) -> Self {
        Self {
            tx_hash,
            consensus,
            metadata: None,
        }
    }
}

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for StoredReceipt
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(self.consensus.as_ref())?;
        encoder.encode(&self.metadata)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for StoredReceipt
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let tx_hash: TxHash = decoder.decode()?;
        let consensus: ConsensusReceipt = decoder.decode()?;
        let metadata: Option<ExecutionMetadata> = decoder.decode()?;
        Ok(Self {
            tx_hash,
            consensus: Arc::new(consensus),
            metadata,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for StoredReceipt {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for StoredReceipt {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("StoredReceipt", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationEvent, DatabaseUpdates, FeeSummary, GlobalReceiptHash, Hash};

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }
    }

    #[test]
    fn synced_receipt_has_no_metadata() {
        let synced = StoredReceipt::synced(
            TxHash::from_raw(Hash::from_bytes(b"synced_tx")),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: DatabaseUpdates::default(),
                application_events: vec![make_event(1)],
            }),
        );
        assert!(synced.metadata.is_none());
    }

    #[test]
    fn locally_executed_receipt_carries_metadata() {
        let local = StoredReceipt {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"local_tx")),
            consensus: Arc::new(ConsensusReceipt::Failed),
            metadata: Some(ExecutionMetadata {
                fee_summary: FeeSummary {
                    total_execution_cost: vec![],
                    total_royalty_cost: vec![],
                    total_storage_cost: vec![],
                    total_tipping_cost: vec![],
                },
                log_messages: vec![],
                error_message: Some("test error".into()),
            }),
        };
        assert!(local.metadata.is_some());
        assert!(!local.consensus.is_success());
    }
}
