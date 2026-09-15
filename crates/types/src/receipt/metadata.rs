//! Fee summary, log levels, and node-local execution metadata.

use hyperscale_hbor::Hbor;

/// Cap on `ExecutionMetadata.log_messages` count at decode time. Receipts
/// emit a handful of log lines per tx; 1024 is far above any legitimate
/// workload.
pub const MAX_LOG_MESSAGES_PER_TX: usize = 1024;

/// Cap on a single engine-produced diagnostic string at decode time —
/// applies to both each `log_messages` entry and `error_message`. Engine
/// diagnostics are short; 4 KiB rejects obviously oversized arrivals
/// before any per-byte allocation.
pub const MAX_DIAGNOSTIC_STRING_LEN: usize = 4 * 1024;

/// Fee metrics from transaction execution.
///
/// Costs are denominated in quanta (10⁻¹⁸ whole tokens), the same scale
/// [`Stake`](crate::Stake) uses. Each is `Some` for receipts the engine
/// actually produced and `None` for synthetic-failure records
/// ([`ExecutionMetadata::empty`]) where the executor never reached the
/// guest and has no fees to report.
#[allow(missing_docs)] // the field names are the documentation
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct FeeSummary {
    pub total_execution_cost: Option<u128>,
    pub total_royalty_cost: Option<u128>,
    pub total_storage_cost: Option<u128>,
    pub total_tipping_cost: Option<u128>,
}

/// Log severity level from transaction execution. Variants follow the
/// standard `tracing` severity ordering.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Node-local execution metadata — fees, logs, error messages.
///
/// Not consensus-critical. Only available when this node executed the
/// transaction locally (not available for synced receipts).
///
/// Written atomically with block commit but on a separate pruning cycle
/// (can be pruned earlier than the consensus receipt since not needed for state verification).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(validate = check_diagnostic_lengths)]
pub struct ExecutionMetadata {
    /// Fee breakdown reported by the engine.
    pub fee_summary: FeeSummary,
    /// Engine log lines emitted during execution. Each message string is
    /// capped at [`MAX_DIAGNOSTIC_STRING_LEN`] by the type's validator —
    /// the cap sits inside a tuple element, out of a field attribute's
    /// reach.
    #[hbor(max = MAX_LOG_MESSAGES_PER_TX)]
    pub(crate) log_messages: Vec<(LogLevel, String)>,
    /// Engine error message when `outcome == Failure`.
    #[hbor(max = MAX_DIAGNOSTIC_STRING_LEN)]
    pub(crate) error_message: Option<String>,
}

/// The per-log-string cap, checked at the wire boundary. It sits inside
/// a tuple element, out of a field attribute's reach.
fn check_diagnostic_lengths(meta: &ExecutionMetadata) -> Result<(), &'static str> {
    if meta
        .log_messages
        .iter()
        .all(|(_, msg)| msg.len() <= MAX_DIAGNOSTIC_STRING_LEN)
    {
        Ok(())
    } else {
        Err("diagnostic string exceeds the length cap")
    }
}

impl ExecutionMetadata {
    /// Build from the engine's raw outputs.
    ///
    /// # Panics
    ///
    /// Panics if `log_messages.len() > MAX_LOG_MESSAGES_PER_TX`, if any
    /// `log_messages` entry's string exceeds `MAX_DIAGNOSTIC_STRING_LEN`,
    /// or if `error_message` exceeds `MAX_DIAGNOSTIC_STRING_LEN`.
    #[must_use]
    pub fn new(
        fee_summary: FeeSummary,
        log_messages: Vec<(LogLevel, String)>,
        error_message: Option<String>,
    ) -> Self {
        assert!(
            log_messages.len() <= MAX_LOG_MESSAGES_PER_TX,
            "log messages past the per-transaction cap",
        );
        let out = Self {
            fee_summary,
            log_messages,
            error_message,
        };
        assert!(
            check_diagnostic_lengths(&out).is_ok(),
            "diagnostic string exceeds the length cap",
        );
        out
    }

    /// All-zero metadata: empty fees, no logs, no error.
    ///
    /// Used by the engine's synthetic-failure path (`ExecutedTx::failure`
    /// in the `hyperscale_engine` crate) when the executor never reached
    /// the guest and so has no diagnostic to report. Real failed receipts
    /// carry `error_message`, `log_messages` and `fee_summary` from the
    /// kernel's own receipt.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            fee_summary: FeeSummary {
                total_execution_cost: None,
                total_royalty_cost: None,
                total_storage_cost: None,
                total_tipping_cost: None,
            },
            log_messages: Vec::new(),
            error_message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::Stake;

    #[test]
    fn fee_summary_roundtrip_some() {
        let fs = FeeSummary {
            total_execution_cost: Some(123),
            total_royalty_cost: Some(Stake::QUANTA_PER_WHOLE),
            total_storage_cost: Some(0),
            total_tipping_cost: Some(0),
        };
        let bytes = hbor_to_vec(&fs).unwrap();
        let decoded: FeeSummary = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, fs);
    }

    #[test]
    fn fee_summary_roundtrip_none_for_synthetic_failure() {
        let fs = FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        };
        let bytes = hbor_to_vec(&fs).unwrap();
        let decoded: FeeSummary = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, fs);
    }

    fn sample_metadata() -> ExecutionMetadata {
        ExecutionMetadata::new(
            FeeSummary {
                total_execution_cost: None,
                total_royalty_cost: None,
                total_storage_cost: None,
                total_tipping_cost: None,
            },
            vec![
                (LogLevel::Info, "started".to_string()),
                (LogLevel::Error, "boom".to_string()),
            ],
            Some("explanatory text".to_string()),
        )
    }

    #[test]
    fn execution_metadata_roundtrip() {
        let meta = sample_metadata();
        let bytes = hbor_to_vec(&meta).unwrap();
        let decoded: ExecutionMetadata = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn execution_metadata_roundtrip_empty() {
        let meta = ExecutionMetadata::empty();
        let bytes = hbor_to_vec(&meta).unwrap();
        let decoded: ExecutionMetadata = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    /// Hand-roll metadata whose `log_messages` count exceeds the cap and
    /// verify decode rejects it before iterating.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_messages_count() {
        let mut buf = hbor_to_vec(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        varint::write(&mut buf, MAX_LOG_MESSAGES_PER_TX + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_LOG_MESSAGES_PER_TX + 1) * 8));
        let err = hbor_from_slice::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_LOG_MESSAGES_PER_TX && actual == MAX_LOG_MESSAGES_PER_TX + 1
        ));
    }

    /// Hand-roll metadata with a single oversized log-message string and
    /// verify decode rejects it through the type's validator — the cap
    /// sits inside a tuple element, out of a field bound's reach.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_message_string() {
        let mut buf = hbor_to_vec(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: Vec<(LogLevel, String)> with one entry whose string
        // is oversized.
        varint::write(&mut buf, 1).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&LogLevel::Info).unwrap());
        varint::write(&mut buf, MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_DIAGNOSTIC_STRING_LEN + 1));
        // error_message: None, so the value decodes fully and the
        // validator is what rejects it.
        buf.push(0);
        let err = hbor_from_slice::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    /// Hand-roll metadata with an oversized `error_message` string and
    /// verify decode rejects it through the cap reaching into the
    /// `Option`.
    #[test]
    fn execution_metadata_decode_rejects_oversized_error_message() {
        let mut buf = hbor_to_vec(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: empty.
        buf.extend_from_slice(&hbor_to_vec(&Vec::<(LogLevel, String)>::new()).unwrap());
        // error_message: Some with an oversized string length.
        buf.push(1);
        varint::write(&mut buf, MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_DIAGNOSTIC_STRING_LEN + 1));
        let err = hbor_from_slice::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_DIAGNOSTIC_STRING_LEN && actual == MAX_DIAGNOSTIC_STRING_LEN + 1
        ));
    }
}
