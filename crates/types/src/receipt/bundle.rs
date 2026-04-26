//! Storage / network bundle pairing a `LocalReceipt` with optional engine output.

use std::sync::Arc;

use crate::{ExecutionMetadata, LocalReceipt, TxHash};

/// A receipt bundle for storage — local receipt + optional execution output.
///
/// `execution_output` is `None` when the receipt was fetched from a peer (sync/catch-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBundle {
    /// Hash of the executed transaction this bundle belongs to.
    pub tx_hash: TxHash,
    /// Per-shard receipt produced by execution.
    pub local_receipt: Arc<LocalReceipt>,
    /// Only populated when this node executed the transaction locally.
    pub execution_output: Option<ExecutionMetadata>,
}

// Manual SBOR implementation (Arc doesn't derive BasicSbor)
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for ReceiptBundle
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(self.local_receipt.as_ref())?;
        encoder.encode(&self.execution_output)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for ReceiptBundle
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
        let local_receipt: LocalReceipt = decoder.decode()?;
        let execution_output: Option<ExecutionMetadata> = decoder.decode()?;

        Ok(Self {
            tx_hash,
            local_receipt: Arc::new(local_receipt),
            execution_output,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for ReceiptBundle {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for ReceiptBundle {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("ReceiptBundle", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationEvent, Hash, TransactionOutcome};

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }
    }

    fn make_receipt(events: Vec<ApplicationEvent>) -> LocalReceipt {
        LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: crate::DatabaseUpdates::default(),
            application_events: events,
        }
    }

    #[test]
    fn test_receipt_bundle_optional_execution_output() {
        let receipt = Arc::new(make_receipt(vec![make_event(1)]));

        // Bundle without execution output (synced from peer)
        let synced = ReceiptBundle {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"synced_tx")),
            local_receipt: Arc::clone(&receipt),
            execution_output: None,
        };
        assert!(synced.execution_output.is_none());

        // Bundle with execution output (executed locally)
        let local = ReceiptBundle {
            tx_hash: TxHash::from_raw(Hash::from_bytes(b"local_tx")),
            local_receipt: receipt,
            execution_output: Some(ExecutionMetadata::failure(Some("test error".to_string()))),
        };
        assert!(local.execution_output.is_some());
    }
}
