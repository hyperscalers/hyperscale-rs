//! Application events, fee summary, log levels, and node-local execution metadata.

use radix_common::data::scrypto::{scrypto_decode, scrypto_encode};
use radix_common::math::Decimal;
use radix_engine_interface::types::EventTypeIdentifier;
use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::sbor_codec::decode_bounded_bytes;
use crate::{BoundedString, BoundedVec, Hash};

/// Cap on `ApplicationEvent.type_id` and `ApplicationEvent.data` at decode
/// time. Events are short user-defined strings + SBOR payloads; 64 KiB is
/// far above any legitimate event and rejects oversized arrivals before
/// allocation.
const MAX_APPLICATION_EVENT_FIELD_LEN: usize = 64 * 1024;

/// Cap on `ExecutionMetadata.log_messages` count at decode time. Receipts
/// emit a handful of log lines per tx; 1024 is far above any legitimate
/// workload.
pub const MAX_LOG_MESSAGES_PER_TX: usize = 1024;

/// Cap on a single engine-produced diagnostic string at decode time —
/// applies to both each `log_messages` entry and `error_message`. Engine
/// diagnostics are short; 4 KiB rejects obviously oversized arrivals
/// before any per-byte allocation.
pub const MAX_DIAGNOSTIC_STRING_LEN: usize = 4 * 1024;

/// `Decimal` is `I192`, a 192-bit signed integer. We encode it on the wire
/// as exactly this many little-endian bytes — fixed-size, no length
/// prefix from a peer, no scrypto SBOR round-trip.
const DECIMAL_BYTE_LEN: usize = Decimal::BITS / 8;

/// SBOR-encoded event payload.
///
/// Opaque on the receiving end — the encoder handed us the bytes, we do not
/// inspect them. Distinct from [`EventTypeIdentifier`] so an argument-order
/// swap when constructing an [`ApplicationEvent`] fails to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventData(pub Vec<u8>);

/// An application-level event emitted by Scrypto component logic.
///
/// Events are identical across shards for the same transaction (they come from
/// user logic which sees the same merged state on all shards).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationEvent {
    /// Schema identifier for the event (emitter + event name).
    pub type_id: EventTypeIdentifier,
    /// SBOR-encoded event payload.
    pub data: EventData,
}

impl ApplicationEvent {
    /// Compute a deterministic hash of this event.
    ///
    /// # Panics
    ///
    /// Panics if scrypto-encoding `type_id` fails — the type is a closed
    /// Radix struct and encoding is infallible in practice.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let type_id_bytes = scrypto_encode(&self.type_id)
            .expect("scrypto_encode(EventTypeIdentifier) is infallible for a valid struct");
        Hash::from_parts(&[&type_id_bytes, &self.data.0])
    }
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for ApplicationEvent {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        // `type_id` is scrypto-encoded to bytes and written as a `Vec<u8>` —
        // basic-SBOR can't reach into the scrypto custom value kinds, so
        // bytes is the universal carrier. `EventTypeIdentifier` is a closed
        // Radix struct (address + strings), so encoding is infallible in
        // practice; matches the `expect` in `ConsensusReceipt::local_receipt_hash`.
        let type_id_bytes = scrypto_encode(&self.type_id)
            .expect("scrypto_encode(EventTypeIdentifier) is infallible for a valid struct");
        encoder.write_size(2)?;
        encoder.encode(&type_id_bytes)?;
        encoder.encode(&self.data.0)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for ApplicationEvent {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let type_id_bytes = decode_bounded_bytes(decoder, MAX_APPLICATION_EVENT_FIELD_LEN)?;
        let type_id = scrypto_decode::<EventTypeIdentifier>(&type_id_bytes)
            .map_err(|_| DecodeError::InvalidCustomValue)?;
        let data = EventData(decode_bounded_bytes(
            decoder,
            MAX_APPLICATION_EVENT_FIELD_LEN,
        )?);
        Ok(Self { type_id, data })
    }
}

impl Categorize<NoCustomValueKind> for ApplicationEvent {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for ApplicationEvent {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("ApplicationEvent", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

/// Fee metrics from transaction execution.
///
/// Each cost is `Some(Decimal)` for receipts the engine actually produced,
/// and `None` for synthetic-failure records (`ExecutionMetadata::empty`)
/// where the executor never reached the VM and has no fees to report.
/// Wire encoding writes the `Decimal` as its raw little-endian `I192`
/// bytes, so the on-wire shape matches the type — no scrypto round-trip,
/// no peer-controllable length prefix.
#[allow(missing_docs)] // the field names are the documentation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeSummary {
    pub total_execution_cost: Option<Decimal>,
    pub total_royalty_cost: Option<Decimal>,
    pub total_storage_cost: Option<Decimal>,
    pub total_tipping_cost: Option<Decimal>,
}

/// Encode `Option<Decimal>` directly: a basic-SBOR `Option` discriminator,
/// plus (for `Some`) the `Decimal`'s little-endian `I192` bytes wrapped as
/// a fixed-size SBOR byte array. No length prefix variation, no scrypto
/// SBOR round-trip — the wire form matches the type.
fn encode_optional_decimal<E: Encoder<NoCustomValueKind>>(
    encoder: &mut E,
    value: Option<&Decimal>,
) -> Result<(), EncodeError> {
    encoder.write_value_kind(ValueKind::Enum)?;
    if let Some(decimal) = value {
        encoder.write_discriminator(1)?;
        encoder.write_size(1)?;
        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(ValueKind::U8)?;
        encoder.write_size(DECIMAL_BYTE_LEN)?;
        encoder.write_slice(&decimal.to_vec())?;
    } else {
        encoder.write_discriminator(0)?;
        encoder.write_size(0)?;
    }
    Ok(())
}

fn decode_optional_decimal<D: Decoder<NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Option<Decimal>, DecodeError> {
    decoder.read_and_check_value_kind(ValueKind::Enum)?;
    let discriminator = decoder.read_discriminator()?;
    match discriminator {
        0 => {
            decoder.read_and_check_size(0)?;
            Ok(None)
        }
        1 => {
            decoder.read_and_check_size(1)?;
            decoder.read_and_check_value_kind(ValueKind::Array)?;
            decoder.read_and_check_value_kind(ValueKind::U8)?;
            let len = decoder.read_size()?;
            if len != DECIMAL_BYTE_LEN {
                return Err(DecodeError::UnexpectedSize {
                    expected: DECIMAL_BYTE_LEN,
                    actual: len,
                });
            }
            let slice = decoder.read_slice(DECIMAL_BYTE_LEN)?;
            let decimal = Decimal::try_from(slice).map_err(|_| DecodeError::InvalidCustomValue)?;
            Ok(Some(decimal))
        }
        _ => Err(DecodeError::UnknownDiscriminator(discriminator)),
    }
}

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for FeeSummary {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(4)?;
        encode_optional_decimal(encoder, self.total_execution_cost.as_ref())?;
        encode_optional_decimal(encoder, self.total_royalty_cost.as_ref())?;
        encode_optional_decimal(encoder, self.total_storage_cost.as_ref())?;
        encode_optional_decimal(encoder, self.total_tipping_cost.as_ref())?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for FeeSummary {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 4 {
            return Err(DecodeError::UnexpectedSize {
                expected: 4,
                actual: length,
            });
        }
        let total_execution_cost = decode_optional_decimal(decoder)?;
        let total_royalty_cost = decode_optional_decimal(decoder)?;
        let total_storage_cost = decode_optional_decimal(decoder)?;
        let total_tipping_cost = decode_optional_decimal(decoder)?;
        Ok(Self {
            total_execution_cost,
            total_royalty_cost,
            total_storage_cost,
            total_tipping_cost,
        })
    }
}

impl Categorize<NoCustomValueKind> for FeeSummary {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for FeeSummary {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("FeeSummary", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

/// Log severity level from transaction execution. Variants follow the
/// standard `tracing` severity ordering.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionMetadata {
    /// Fee breakdown reported by the engine.
    pub fee_summary: FeeSummary,
    /// Engine log lines emitted during execution.
    pub log_messages:
        BoundedVec<(LogLevel, BoundedString<MAX_DIAGNOSTIC_STRING_LEN>), MAX_LOG_MESSAGES_PER_TX>,
    /// Engine error message when `outcome == Failure`.
    pub error_message: Option<BoundedString<MAX_DIAGNOSTIC_STRING_LEN>>,
}

impl ExecutionMetadata {
    /// Build from raw `Vec`/`String` inputs, wrapping each into its
    /// bounded type.
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
        Self {
            fee_summary,
            log_messages: log_messages
                .into_iter()
                .map(|(level, msg)| (level, BoundedString::from(msg)))
                .collect::<Vec<_>>()
                .into(),
            error_message: error_message.map(BoundedString::from),
        }
    }

    /// All-zero metadata: empty fees, no logs, no error.
    ///
    /// Used by the engine's synthetic-failure path (`ExecutedTx::failure`
    /// in the `hyperscale_engine` crate) when no Radix-produced
    /// diagnostic exists — the executor never reached the VM and has
    /// nothing meaningful to populate. Real failed receipts come from
    /// `build_execution_metadata` and populate `error_message`,
    /// `log_messages`, and `fee_summary` directly from the Radix
    /// transaction receipt.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            fee_summary: FeeSummary {
                total_execution_cost: None,
                total_royalty_cost: None,
                total_storage_cost: None,
                total_tipping_cost: None,
            },
            log_messages: BoundedVec::new(),
            error_message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder, basic_decode,
        basic_encode,
    };

    use super::*;
    use crate::test_utils::test_event_type_identifier;

    #[test]
    fn application_event_roundtrip() {
        let ev = ApplicationEvent {
            type_id: test_event_type_identifier(7),
            data: EventData(vec![4, 5, 6, 7]),
        };
        let bytes = basic_encode(&ev).unwrap();
        let decoded: ApplicationEvent = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, ev);
    }

    #[test]
    fn application_event_decode_rejects_oversized_type_id() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_APPLICATION_EVENT_FIELD_LEN + 1).unwrap();
        let err = basic_decode::<ApplicationEvent>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_APPLICATION_EVENT_FIELD_LEN,
                actual,
            } if actual == MAX_APPLICATION_EVENT_FIELD_LEN + 1
        ));
    }

    #[test]
    fn fee_summary_roundtrip_some() {
        use std::str::FromStr;
        let fs = FeeSummary {
            total_execution_cost: Some(Decimal::from_str("0.000000000000000123").unwrap()),
            total_royalty_cost: Some(Decimal::from_str("1").unwrap()),
            total_storage_cost: Some(Decimal::ZERO),
            total_tipping_cost: Some(Decimal::ZERO),
        };
        let bytes = basic_encode(&fs).unwrap();
        let decoded: FeeSummary = basic_decode(&bytes).unwrap();
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
        let bytes = basic_encode(&fs).unwrap();
        let decoded: FeeSummary = basic_decode(&bytes).unwrap();
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
        let bytes = basic_encode(&meta).unwrap();
        let decoded: ExecutionMetadata = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn execution_metadata_roundtrip_empty() {
        let meta = ExecutionMetadata::empty();
        let bytes = basic_encode(&meta).unwrap();
        let decoded: ExecutionMetadata = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    /// Hand-roll metadata whose `log_messages` count exceeds the cap and
    /// verify decode rejects it before iterating.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_messages_count() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(MAX_LOG_MESSAGES_PER_TX + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_LOG_MESSAGES_PER_TX,
                actual,
            } if actual == MAX_LOG_MESSAGES_PER_TX + 1
        ));
    }

    /// Hand-roll metadata with a single oversized log-message string and
    /// verify decode rejects it before allocating the string buffer.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_message_string() {
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: Vec<(LogLevel, String)> with one entry whose string
        // is oversized.
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(1).unwrap();
        enc.write_size(2).unwrap();
        enc.encode(&LogLevel::Info).unwrap();
        enc.write_value_kind(ValueKind::String).unwrap();
        enc.write_size(MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DIAGNOSTIC_STRING_LEN,
                actual,
            } if actual == MAX_DIAGNOSTIC_STRING_LEN + 1
        ));
    }

    /// Hand-roll metadata with an oversized `error_message` string and
    /// verify decode rejects it before allocating the string buffer.
    #[test]
    fn execution_metadata_decode_rejects_oversized_error_message() {
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: empty.
        enc.encode(&Vec::<(LogLevel, String)>::new()).unwrap();
        // error_message: Option::Some<String> with oversized length.
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(1).unwrap();
        enc.write_size(1).unwrap();
        enc.write_value_kind(ValueKind::String).unwrap();
        enc.write_size(MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DIAGNOSTIC_STRING_LEN,
                actual,
            } if actual == MAX_DIAGNOSTIC_STRING_LEN + 1
        ));
    }

    /// Decimal SBOR is fixed at `DECIMAL_BYTE_LEN` bytes; any other claimed
    /// length is rejected before allocation.
    #[test]
    fn fee_summary_decode_rejects_wrong_length_cost_field() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(4).unwrap();
        // First field: an Option::Some<[u8; ?]> with the wrong length.
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(1).unwrap();
        enc.write_size(1).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(DECIMAL_BYTE_LEN + 1).unwrap();
        let err = basic_decode::<FeeSummary>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: DECIMAL_BYTE_LEN,
                actual,
            } if actual == DECIMAL_BYTE_LEN + 1
        ));
    }
}
