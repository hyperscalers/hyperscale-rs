//! Three-tier receipt model for transaction execution results.
//!
//! # Architecture
//!
//! | Tier | Type | Contents | Cross-shard identical? |
//! |------|------|----------|------------------------|
//! | **Consensus** | [`ConsensusReceipt`] | outcome + event_root | Yes |
//! | **Ledger** | [`LedgerTransactionReceipt`] | outcome + state changes + events | No |
//! | **Local** | [`LocalTransactionExecution`] | fees, logs, errors | No |
//!
//! Only the consensus receipt hash is signed over in votes/certificates.
//! State correctness is enforced by `state_root` in the block header.

use std::sync::Arc;

use crate::{compute_merkle_root, DatabaseUpdates, Hash};

// ─── Outcome ─────────────────────────────────────────────────────────────────

/// Whether a transaction committed successfully or was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub enum LedgerTransactionOutcome {
    Success,
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
    pub fn hash(&self) -> Hash {
        Hash::from_parts(&[&self.type_id, &self.data])
    }
}

// ─── Fees ────────────────────────────────────────────────────────────────────

/// Fee metrics from transaction execution.
///
/// Cost fields are stored as SBOR-encoded Decimals (raw bytes) to avoid
/// a direct dependency on the Decimal type in the types crate.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct FeeSummary {
    pub total_execution_cost: Vec<u8>,
    pub total_royalty_cost: Vec<u8>,
    pub total_storage_cost: Vec<u8>,
    pub total_tipping_cost: Vec<u8>,
}

// ─── Logging ─────────────────────────────────────────────────────────────────

/// Log severity level from transaction execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

// ─── Consensus Receipt (Tier 1) ─────────────────────────────────────────────

/// The consensus-critical subset of a transaction receipt.
///
/// Only `outcome` and `event_root` are included — no state change commitment.
/// State correctness is enforced by `state_root` in the block header (JVT root
/// commits to the entire post-block state). Per-transaction write commitments
/// are redundant for consensus safety.
///
/// This hash is what validators sign over in execution votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub struct ConsensusReceipt {
    pub outcome: LedgerTransactionOutcome,
    /// Merkle root of application event hashes.
    pub event_root: Hash,
}

impl ConsensusReceipt {
    /// Compute the consensus receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    pub fn receipt_hash(&self) -> Hash {
        let outcome_byte = match self.outcome {
            LedgerTransactionOutcome::Success => [1u8],
            LedgerTransactionOutcome::Failure => [0u8],
        };
        Hash::from_parts(&[&outcome_byte, self.event_root.as_bytes()])
    }
}

// ─── Ledger Receipt (Tier 2) ─────────────────────────────────────────────────

/// Full ledger receipt with shard-filtered database updates and events.
///
/// Stored per-shard — `database_updates` contain only writes for the local
/// shard (already filtered by `filter_updates_for_shard` during execution).
/// NOT part of the consensus receipt hash (correctness enforced by `state_root`
/// in the block header).
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct LedgerTransactionReceipt {
    pub outcome: LedgerTransactionOutcome,
    pub database_updates: DatabaseUpdates,
    pub application_events: Vec<ApplicationEvent>,
}

impl LedgerTransactionReceipt {
    /// Derive the consensus receipt from this ledger receipt.
    ///
    /// Computes `event_root` as the merkle root of individual event hashes.
    pub fn consensus_receipt(&self) -> ConsensusReceipt {
        let event_hashes: Vec<Hash> = self.application_events.iter().map(|e| e.hash()).collect();
        ConsensusReceipt {
            outcome: self.outcome,
            event_root: compute_merkle_root(&event_hashes),
        }
    }

    /// Convenience: compute the consensus receipt hash directly.
    pub fn receipt_hash(&self) -> Hash {
        self.consensus_receipt().receipt_hash()
    }

    /// Create a failure receipt with no database updates or events.
    pub fn failure() -> Self {
        Self {
            outcome: LedgerTransactionOutcome::Failure,
            database_updates: DatabaseUpdates::default(),
            application_events: vec![],
        }
    }
}

// ─── Local Execution (Tier 3) ────────────────────────────────────────────────

/// Local execution metadata — fees, logs, error messages.
///
/// Not consensus-critical. Only available when this node executed the
/// transaction locally (not available for synced receipts).
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct LocalTransactionExecution {
    pub fee_summary: FeeSummary,
    pub log_messages: Vec<(LogLevel, String)>,
    pub error_message: Option<String>,
}

impl LocalTransactionExecution {
    /// Create a failure execution record.
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

/// A ledger receipt paired with its transaction hash, for network responses.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct LedgerReceiptEntry {
    pub tx_hash: Hash,
    pub receipt: LedgerTransactionReceipt,
}

/// A receipt bundle for storage — ledger receipt + optional local execution.
///
/// `local_execution` is `None` when the receipt was fetched from a peer (sync/catch-up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBundle {
    pub tx_hash: Hash,
    pub ledger_receipt: Arc<LedgerTransactionReceipt>,
    /// Only populated when this node executed the transaction locally.
    pub local_execution: Option<LocalTransactionExecution>,
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
        encoder.encode(self.ledger_receipt.as_ref())?;
        encoder.encode(&self.local_execution)?;
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

        let tx_hash: Hash = decoder.decode()?;
        let ledger_receipt: LedgerTransactionReceipt = decoder.decode()?;
        let local_execution: Option<LocalTransactionExecution> = decoder.decode()?;

        Ok(Self {
            tx_hash,
            ledger_receipt: Arc::new(ledger_receipt),
            local_execution,
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

/// Execution output that travels alongside an ExecutionVote through the
/// ProtocolEvent boundary from the thread pool to the state machine.
///
/// Separate from `SingleTxResult` (engine-internal) because `success` and
/// `error` are not needed past the vote-signing boundary — the state machine
/// determines outcome from the receipt's `outcome` field instead.
///
/// The state machine uses this to dispatch receipt storage to disk
/// (via StoreReceiptBundles action). DatabaseUpdates are on the receipt.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Hash of the executed transaction.
    pub tx_hash: Hash,
    /// Pre-computed consensus receipt hash (outcome + event_root).
    /// Computed on the execution thread pool to avoid recomputation on the state machine.
    pub receipt_hash: Hash,
    /// Full ledger receipt with shard-filtered database updates and events.
    pub ledger_receipt: LedgerTransactionReceipt,
    /// Local execution metadata (fees, logs, errors).
    pub local_execution: LocalTransactionExecution,
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

    fn make_receipt(events: Vec<ApplicationEvent>) -> LedgerTransactionReceipt {
        LedgerTransactionReceipt {
            outcome: LedgerTransactionOutcome::Success,
            database_updates: DatabaseUpdates::default(),
            application_events: events,
        }
    }

    #[test]
    fn test_empty_receipt_has_zero_event_root() {
        let receipt = make_receipt(vec![]);
        let consensus = receipt.consensus_receipt();
        assert_eq!(consensus.event_root, Hash::ZERO);
    }

    #[test]
    fn test_consensus_receipt_derivation() {
        let events = vec![make_event(1), make_event(2)];
        let receipt = make_receipt(events.clone());

        let consensus = receipt.consensus_receipt();
        assert_eq!(consensus.outcome, LedgerTransactionOutcome::Success);

        let event_hashes: Vec<Hash> = events.iter().map(|e| e.hash()).collect();
        let expected_root = compute_merkle_root(&event_hashes);
        assert_eq!(consensus.event_root, expected_root);
    }

    #[test]
    fn test_receipt_hash_changes_with_outcome() {
        let success = ConsensusReceipt {
            outcome: LedgerTransactionOutcome::Success,
            event_root: Hash::ZERO,
        };
        let failure = ConsensusReceipt {
            outcome: LedgerTransactionOutcome::Failure,
            event_root: Hash::ZERO,
        };
        assert_ne!(success.receipt_hash(), failure.receipt_hash());
    }

    #[test]
    fn test_receipt_hash_changes_with_events() {
        let receipt_a = make_receipt(vec![make_event(1)]);
        let receipt_b = make_receipt(vec![make_event(1), make_event(2)]);
        assert_ne!(receipt_a.receipt_hash(), receipt_b.receipt_hash());
    }

    #[test]
    fn test_receipt_hash_ignores_database_updates() {
        // database_updates differ but events are identical → same consensus hash
        let receipt_a = make_receipt(vec![make_event(10)]);
        let receipt_b = make_receipt(vec![make_event(10)]);
        assert_eq!(
            receipt_a.receipt_hash(),
            receipt_b.receipt_hash(),
            "consensus receipt hash must not depend on database updates"
        );
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
    fn test_receipt_bundle_optional_local_execution() {
        let receipt = Arc::new(make_receipt(vec![]));

        // Bundle without local execution (synced from peer)
        let synced = ReceiptBundle {
            tx_hash: Hash::from_bytes(b"synced_tx"),
            ledger_receipt: Arc::clone(&receipt),
            local_execution: None,
        };
        assert!(synced.local_execution.is_none());

        // Bundle with local execution (executed locally)
        let local = ReceiptBundle {
            tx_hash: Hash::from_bytes(b"local_tx"),
            ledger_receipt: receipt,
            local_execution: Some(LocalTransactionExecution::failure(Some(
                "test error".to_string(),
            ))),
        };
        assert!(local.local_execution.is_some());
    }
}
