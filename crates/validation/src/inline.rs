//! Synchronous inline transaction validator for simulation.
//!
//! Validates transactions immediately on the calling thread and delivers
//! valid transactions as events. No batching, no async — deterministic.

use crate::TransactionSink;
use hyperscale_core::Event;
use hyperscale_engine::TransactionValidation;
use hyperscale_types::RoutableTransaction;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Synchronous transaction validator for simulation.
///
/// Validates each transaction immediately on `submit()` and sends valid
/// transactions to the event channel. No deduplication or batching —
/// the simulation runner handles ordering deterministically.
pub struct InlineValidator {
    validator: Arc<TransactionValidation>,
    output_tx: mpsc::UnboundedSender<Event>,
}

impl InlineValidator {
    /// Create a new inline validator.
    pub fn new(
        validator: Arc<TransactionValidation>,
        output_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            validator,
            output_tx,
        }
    }
}

impl TransactionSink for InlineValidator {
    fn submit(&self, tx: Arc<RoutableTransaction>) -> bool {
        match self.validator.validate_transaction(&tx) {
            Ok(()) => {
                trace!(tx_hash = ?tx.hash(), "Transaction validated (inline)");
                self.output_tx
                    .send(Event::TransactionGossipReceived { tx })
                    .is_ok()
            }
            Err(e) => {
                debug!(
                    tx_hash = ?tx.hash(),
                    error = %e,
                    "Transaction validation failed (inline)"
                );
                false
            }
        }
    }
}
