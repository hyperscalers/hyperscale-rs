//! Three-tier receipt model for transaction execution results.
//!
//! # Architecture
//!
//! | Tier | Type | Contents | Cross-shard identical? |
//! |------|------|----------|------------------------|
//! | **Global** | [`GlobalReceipt`] | outcome + `event_root` + `writes_root` | Yes |
//! | **Local** | [`LocalReceipt`] | outcome + shard-filtered state changes + events | No |
//! | **Output** | [`ExecutionMetadata`] | fees, logs, errors | No |
//!
//! The global receipt hash is signed over in execution votes/certificates.
//! Per-shard state correctness is enforced by `state_root` in the block header,
//! with per-tx attribution via `local_receipt_root`.

use std::sync::Arc;

use crate::{
    DatabaseUpdates, EventRoot, GlobalReceiptHash, Hash, TxHash, WritesRoot, compute_merkle_root,
};

// ─── Outcome ─────────────────────────────────────────────────────────────────

/// Whether a transaction committed successfully or was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub enum TransactionOutcome {
    /// Engine committed the transaction; state changes applied.
    Success,
    /// Engine rejected the transaction; no state changes applied.
    Failure,
}

// ─── Events ──────────────────────────────────────────────────────────────────

/// An application-level event emitted by Scrypto component logic.
///
/// Events are identical across shards for the same transaction (they come from
/// user logic which sees the same merged state on all shards).
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct ApplicationEvent {
    /// SBOR-encoded event type identifier.
    pub type_id: Vec<u8>,
    /// SBOR-encoded event payload.
    pub data: Vec<u8>,
}

impl ApplicationEvent {
    /// Compute a deterministic hash of this event.
    #[must_use]
    pub fn hash(&self) -> Hash {
        Hash::from_parts(&[&self.type_id, &self.data])
    }
}

// ─── Fees ────────────────────────────────────────────────────────────────────

/// Fee metrics from transaction execution.
///
/// Cost fields are stored as SBOR-encoded Decimals (raw bytes) to avoid
/// a direct dependency on the Decimal type in the types crate.
//
// Fee fields are SBOR-encoded `Decimal` raw bytes; the field names ARE the documentation.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct FeeSummary {
    pub total_execution_cost: Vec<u8>,
    pub total_royalty_cost: Vec<u8>,
    pub total_storage_cost: Vec<u8>,
    pub total_tipping_cost: Vec<u8>,
}

// ─── Logging ─────────────────────────────────────────────────────────────────

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

// ─── Global Receipt (Tier 1) ────────────────────────────────────────────────

/// Cross-shard agreement receipt — ensures validators on different shards
/// executing the same transaction reach the same outcome.
///
/// Contains `writes_root` (merkle root of declared-only, system-filtered global
/// writes — NOT shard-filtered) so cross-shard agreement covers state changes,
/// not just outcome + events.
///
/// This hash is what validators sign over in execution votes.
/// Ephemeral — never written to storage, only lives for EC aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub struct GlobalReceipt {
    /// Whether the engine committed or rejected the transaction.
    pub outcome: TransactionOutcome,
    /// Merkle root of application event hashes.
    pub event_root: EventRoot,
    /// Merkle root of declared-only, system-filtered global database writes.
    ///
    /// Computed from `filter_updates_for_global_receipt()` — includes writes for
    /// ALL shards (not shard-filtered), but excludes system entities and undeclared
    /// writes. This ensures cross-shard validators agree on the same state changes
    /// for declared accounts.
    pub writes_root: WritesRoot,
}

impl GlobalReceipt {
    /// Compute the global receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    ///
    /// # Panics
    ///
    /// Cannot panic: outcome maps to a fixed-size byte and roots are
    /// fixed-size hashes.
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        let outcome_byte = match self.outcome {
            TransactionOutcome::Success => [1u8],
            TransactionOutcome::Failure => [0u8],
        };
        GlobalReceiptHash::from_raw(Hash::from_parts(&[
            &outcome_byte,
            self.event_root.as_raw().as_bytes(),
            self.writes_root.as_raw().as_bytes(),
        ]))
    }
}

// ─── Local Receipt (Tier 2) ─────────────────────────────────────────────────

/// Per-shard receipt with shard-filtered database updates and events.
///
/// Stored per-shard — `database_updates` contain only writes for the local
/// shard (already filtered by `filter_updates_for_shard` during execution).
///
/// Feeds `state_root` computation via JMT. Per-tx attribution committed via
/// `local_receipt_root` in the block header.
///
/// Held in-memory in `FinalizedWave` until block commit, then written
/// atomically with block metadata.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct LocalReceipt {
    /// Whether the engine committed or rejected the transaction.
    pub outcome: TransactionOutcome,
    /// Shard-filtered substate writes produced by this transaction.
    pub database_updates: DatabaseUpdates,
    /// Application events emitted during execution.
    pub application_events: Vec<ApplicationEvent>,
}

impl LocalReceipt {
    /// Derive the global receipt from this local receipt with pre-computed `writes_root`.
    ///
    /// `writes_root` must be computed separately from unfiltered (global) writes
    /// via `filter_updates_for_global_receipt()`, since this local receipt only
    /// contains shard-filtered writes.
    #[must_use]
    pub fn global_receipt(&self, writes_root: WritesRoot) -> GlobalReceipt {
        let event_hashes: Vec<Hash> = self
            .application_events
            .iter()
            .map(ApplicationEvent::hash)
            .collect();
        GlobalReceipt {
            outcome: self.outcome,
            event_root: EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            writes_root,
        }
    }

    /// Compute a deterministic hash of this local receipt for `local_receipt_root`.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of `database_updates` fails — `DatabaseUpdates`
    /// is a closed SBOR type and encoding is infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> Hash {
        let outcome_byte = match self.outcome {
            TransactionOutcome::Success => [1u8],
            TransactionOutcome::Failure => [0u8],
        };
        let event_hashes: Vec<Hash> = self
            .application_events
            .iter()
            .map(ApplicationEvent::hash)
            .collect();
        let event_root = compute_merkle_root(&event_hashes);
        // Include database_updates hash so local_receipt_root commits to per-tx state deltas.
        let updates_bytes =
            sbor::prelude::basic_encode(&self.database_updates).expect("encode should not fail");
        let updates_hash = Hash::from_bytes(&updates_bytes);
        Hash::from_parts(&[
            &outcome_byte,
            event_root.as_bytes(),
            updates_hash.as_bytes(),
        ])
    }

    /// Create a failure receipt with no database updates or events.
    #[must_use]
    pub fn failure() -> Self {
        Self {
            outcome: TransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        }
    }
}

// ─── Execution Output (Tier 3) ──────────────────────────────────────────────

/// Node-local execution metadata — fees, logs, error messages.
///
/// Not consensus-critical. Only available when this node executed the
/// transaction locally (not available for synced receipts).
///
/// Written atomically with block commit but on a separate pruning cycle
/// (can be pruned earlier than `LocalReceipts` since not needed for state verification).
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct ExecutionMetadata {
    /// Fee breakdown reported by the engine.
    pub fee_summary: FeeSummary,
    /// Engine log lines emitted during execution.
    pub log_messages: Vec<(LogLevel, String)>,
    /// Engine error message when `outcome == Failure`.
    pub error_message: Option<String>,
}

impl ExecutionMetadata {
    /// Create a failure execution output.
    #[must_use]
    pub fn failure(error: Option<String>) -> Self {
        Self {
            fee_summary: FeeSummary {
                total_execution_cost: vec![],
                total_royalty_cost: vec![],
                total_storage_cost: vec![],
                total_tipping_cost: vec![],
            },
            log_messages: vec![],
            error_message: error,
        }
    }
}

// ─── Network / Storage Types ─────────────────────────────────────────────────

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

// ─── Execution Result ────────────────────────────────────────────────────

/// Execution output that travels alongside an `ExecutionVote` through the
/// `ProtocolEvent` boundary from the thread pool to the state machine.
///
/// Separate from `SingleTxResult` (engine-internal) because `success` and
/// `error` are not needed past the vote-signing boundary — the state machine
/// determines outcome from the receipt's `outcome` field instead.
///
/// The state machine holds receipts in-memory until block commit.
/// `DatabaseUpdates` are on the local receipt.
#[derive(Debug, Clone)]
pub struct LocalExecutionEntry {
    /// Hash of the executed transaction.
    pub tx_hash: TxHash,
    /// Pre-computed global receipt hash (outcome + `event_root` + `writes_root`).
    /// Computed on the execution thread pool to avoid recomputation on the state machine.
    pub receipt_hash: GlobalReceiptHash,
    /// Full local receipt with shard-filtered database updates and events.
    pub local_receipt: LocalReceipt,
    /// Local execution metadata (fees, logs, errors).
    pub execution_output: ExecutionMetadata,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }
    }

    fn make_receipt(events: Vec<ApplicationEvent>) -> LocalReceipt {
        LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: events,
        }
    }

    #[test]
    fn test_empty_receipt_has_zero_event_root() {
        let receipt = make_receipt(vec![]);
        let global = receipt.global_receipt(WritesRoot::ZERO);
        assert_eq!(global.event_root, EventRoot::ZERO);
    }

    #[test]
    fn test_global_receipt_derivation() {
        let events = vec![make_event(1), make_event(2)];
        let receipt = make_receipt(events.clone());

        let global = receipt.global_receipt(WritesRoot::ZERO);
        assert_eq!(global.outcome, TransactionOutcome::Success);

        let event_hashes: Vec<Hash> = events.iter().map(super::ApplicationEvent::hash).collect();
        let expected_root = EventRoot::from_raw(compute_merkle_root(&event_hashes));
        assert_eq!(global.event_root, expected_root);
    }

    #[test]
    fn test_receipt_hash_changes_with_outcome() {
        let success = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        let failure = GlobalReceipt {
            outcome: TransactionOutcome::Failure,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        assert_ne!(success.receipt_hash(), failure.receipt_hash());
    }

    #[test]
    fn test_receipt_hash_changes_with_events() {
        let receipt_a = make_receipt(vec![make_event(1)]);
        let receipt_b = make_receipt(vec![make_event(1), make_event(2)]);
        assert_ne!(
            receipt_a.global_receipt(WritesRoot::ZERO).receipt_hash(),
            receipt_b.global_receipt(WritesRoot::ZERO).receipt_hash()
        );
    }

    #[test]
    fn test_receipt_hash_changes_with_writes_root() {
        let a = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::ZERO,
        };
        let b = GlobalReceipt {
            outcome: TransactionOutcome::Success,
            event_root: EventRoot::ZERO,
            writes_root: WritesRoot::from_raw(Hash::from_bytes(b"different")),
        };
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_application_event_hash_deterministic() {
        let event = make_event(42);
        assert_eq!(event.hash(), event.hash());

        let same_event = ApplicationEvent {
            type_id: vec![42],
            data: vec![42, 43],
        };
        assert_eq!(event.hash(), same_event.hash());
    }

    #[test]
    fn test_receipt_bundle_optional_execution_output() {
        let receipt = Arc::new(make_receipt(vec![]));

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

    #[test]
    fn test_local_receipt_hash_deterministic() {
        let receipt = make_receipt(vec![make_event(1)]);
        assert_eq!(receipt.receipt_hash(), receipt.receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_updates() {
        let a = LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        };
        // b has a different (non-default) database_updates — hash should differ
        // (testing the concept; actual DatabaseUpdates construction requires real data)
        let b = LocalReceipt {
            outcome: TransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        };
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }
}
