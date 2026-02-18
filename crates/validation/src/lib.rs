//! Transaction validation abstraction and batched validator.
//!
//! This crate provides:
//! - [`TransactionSink`]: Trait for submitting transactions to a validation pipeline
//! - [`ValidationBatcher`]: Production batched validator using dispatch pools
//! - [`InlineValidator`]: Synchronous validator for simulation
//!
//! # Architecture
//!
//! The network layer decodes transaction gossip and submits via `TransactionSink`.
//! This decouples the network from the concrete validation implementation:
//!
//! ```text
//! Network ──► TransactionSink::submit() ──► validation pipeline ──► Event channel
//! ```
//!
//! Production uses `ValidationBatcher` (dedup + batched parallel validation).
//! Simulation uses `InlineValidator` (immediate synchronous validation).

mod batcher;
mod inline;

pub use batcher::{
    spawn_tx_validation_batcher, ValidationBatcher, ValidationBatcherConfig,
    ValidationBatcherHandle, ValidationBatcherStats,
};
pub use inline::InlineValidator;

// Re-export TransactionSink from core (canonical definition lives there)
pub use hyperscale_core::TransactionSink;
