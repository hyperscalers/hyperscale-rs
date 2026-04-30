//! Application events, fee summary, log levels, and node-local execution metadata.

use crate::Hash;

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

/// Fee metrics from transaction execution.
///
/// Cost fields are stored as SBOR-encoded Decimals (raw bytes) to avoid
/// a direct dependency on the Decimal type in the types crate.
#[allow(missing_docs)] // the field names are the documentation
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct FeeSummary {
    pub total_execution_cost: Vec<u8>,
    pub total_royalty_cost: Vec<u8>,
    pub total_storage_cost: Vec<u8>,
    pub total_tipping_cost: Vec<u8>,
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
                total_execution_cost: vec![],
                total_royalty_cost: vec![],
                total_storage_cost: vec![],
                total_tipping_cost: vec![],
            },
            log_messages: vec![],
            error_message: None,
        }
    }
}
