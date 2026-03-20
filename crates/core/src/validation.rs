//! Transaction validation trait.
//!
//! Defines the interface for validating transactions before mempool acceptance.

use hyperscale_types::TypeConfig;

/// Errors from transaction validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Transaction failed signature validation.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Transaction failed structural validation.
    #[error("Invalid transaction structure: {0}")]
    InvalidStructure(String),

    /// Transaction failed preparation (encoding/decoding issues).
    #[error("Preparation failed: {0}")]
    PreparationFailed(String),
}

/// Transaction validator trait.
///
/// Validates transactions before they enter the mempool. This is critical for
/// security (reject invalid transactions at ingress) and DoS prevention
/// (don't gossip or store invalid transactions).
pub trait TransactionValidator<C: TypeConfig>: Clone + Send + Sync + 'static {
    /// Validate a transaction.
    ///
    /// Returns `Ok(())` if the transaction is valid, `Err(ValidationError)` otherwise.
    fn validate_transaction(&self, tx: &C::Transaction) -> Result<(), ValidationError>;
}
