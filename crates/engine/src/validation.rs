//! Transaction signature validation.
//!
//! This module provides signature validation for transactions before they
//! enter the mempool. This is critical for:
//!
//! 1. **Security**: Reject invalid transactions at ingress, not execution
//! 2. **DoS prevention**: Don't gossip or store invalid transactions
//! 3. **Consistency**: Match Babylon node behavior (validate before mempool)
//!
//! # Usage
//!
//! ```ignore
//! use hyperscale_engine::{TransactionValidation, ValidationError};
//! use radix_common::network::NetworkDefinition;
//!
//! let validator = TransactionValidation::new(NetworkDefinition::simulator());
//!
//! // Synchronous validation (for simulation)
//! match validator.validate_transaction(&routable_tx) {
//!     Ok(()) => { /* accept into mempool */ }
//!     Err(e) => { /* reject with error */ }
//! }
//! ```

use hyperscale_types::RoutableTransaction;
use radix_common::network::NetworkDefinition;
use radix_transactions::errors::TransactionValidationError;
use radix_transactions::validation::TransactionValidator;
use thiserror::Error;

/// Errors from transaction validation.
#[derive(Debug, Error)]
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

impl From<TransactionValidationError> for ValidationError {
    fn from(e: TransactionValidationError) -> Self {
        // Categorize the error type for better error messages
        let msg = format!("{:?}", e);
        if msg.contains("Signature") || msg.contains("signature") {
            ValidationError::InvalidSignature(msg)
        } else {
            ValidationError::InvalidStructure(msg)
        }
    }
}

/// Transaction validator for signature verification before mempool acceptance.
///
/// This wraps the Radix `TransactionValidator` and provides a simpler interface
/// for our use case. The full Radix validation includes:
///
/// - Intent signature verification
/// - Notary signature verification
/// - Signature count limits
/// - Transaction header validation (epochs, nonce, etc.)
///
/// # Thread Safety
///
/// `TransactionValidation` is `Send + Sync` and can be shared across threads.
/// For production, validation should be dispatched to the crypto thread pool.
#[derive(Clone)]
pub struct TransactionValidation {
    network: NetworkDefinition,
    /// Cached Radix transaction validator
    validator: TransactionValidator,
}

impl TransactionValidation {
    /// Create a new transaction validator for the given network.
    pub fn new(network: NetworkDefinition) -> Self {
        let validator = TransactionValidator::new_with_latest_config(&network);
        Self { network, validator }
    }

    /// Validate a transaction's signatures synchronously.
    ///
    /// This performs full Radix transaction validation including:
    /// - Preparation (decode and hash computation)
    /// - Signature verification (intent + notary)
    /// - Structural validation
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the transaction is valid
    /// - `Err(ValidationError)` if validation fails
    ///
    /// # Performance
    ///
    /// Signature verification is CPU-intensive. In production, this should
    /// be called on the crypto thread pool, not the main event loop.
    pub fn validate_transaction(&self, tx: &RoutableTransaction) -> Result<(), ValidationError> {
        // Use cached validation if available, otherwise validate and cache
        tx.get_or_validate(&self.validator)
            .ok_or_else(|| ValidationError::PreparationFailed("Validation failed".to_string()))?;

        Ok(())
    }

    /// Validate a transaction and return a result suitable for async dispatch.
    ///
    /// This is a convenience wrapper that captures the transaction hash
    /// along with the validation result, making it easier to process
    /// results asynchronously.
    pub fn validate_with_hash(
        &self,
        tx: &RoutableTransaction,
    ) -> (hyperscale_types::Hash, Result<(), ValidationError>) {
        let hash = tx.hash();
        let result = self.validate_transaction(tx);
        (hash, result)
    }

    /// Get the network definition.
    pub fn network(&self) -> &NetworkDefinition {
        &self.network
    }
}

/// Result of batch transaction validation.
#[derive(Debug)]
pub struct BatchValidationResult {
    /// Transaction hash.
    pub tx_hash: hyperscale_types::Hash,
    /// Validation result.
    pub result: Result<(), ValidationError>,
}

impl TransactionValidation {
    /// Validate multiple transactions.
    ///
    /// This validates each transaction independently. For production use,
    /// consider dispatching these to the crypto thread pool in parallel
    /// using rayon.
    ///
    /// # Note
    ///
    /// Unlike BLS signature aggregation, Ed25519/secp256k1 signature
    /// verification cannot be meaningfully batched at the crypto level.
    /// However, this method allows the caller to process multiple
    /// transactions in a single call for convenience.
    pub fn validate_batch(&self, txs: &[&RoutableTransaction]) -> Vec<BatchValidationResult> {
        txs.iter()
            .map(|tx| BatchValidationResult {
                tx_hash: tx.hash(),
                result: self.validate_transaction(tx),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::generate_ed25519_keypair;
    use radix_common::network::NetworkDefinition;
    use radix_transactions::builder::ManifestBuilder;

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InvalidSignature("bad sig".to_string());
        assert!(err.to_string().contains("Invalid signature"));

        let err = ValidationError::InvalidStructure("bad struct".to_string());
        assert!(err.to_string().contains("Invalid transaction structure"));

        let err = ValidationError::PreparationFailed("prep failed".to_string());
        assert!(err.to_string().contains("Preparation failed"));
    }

    #[test]
    fn test_validator_creation() {
        let validator = TransactionValidation::new(NetworkDefinition::simulator());
        assert_eq!(validator.network().id, NetworkDefinition::simulator().id);
    }

    #[test]
    fn test_validate_properly_signed_transaction() {
        // Create a properly signed transaction
        let network = NetworkDefinition::simulator();
        let signer = generate_ed25519_keypair();

        // Build a simple manifest
        let manifest = ManifestBuilder::new().drop_all_proofs().build();

        // Sign and notarize
        let notarized =
            hyperscale_types::sign_and_notarize(manifest, &network, 1, &signer).unwrap();

        // Convert to RoutableTransaction
        let routable: RoutableTransaction = notarized.try_into().unwrap();

        // Validate
        let validator = TransactionValidation::new(network);
        let result = validator.validate_transaction(&routable);

        // Should pass validation
        assert!(
            result.is_ok(),
            "Valid transaction should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_with_hash() {
        let network = NetworkDefinition::simulator();
        let signer = generate_ed25519_keypair();

        let manifest = ManifestBuilder::new().drop_all_proofs().build();
        let notarized =
            hyperscale_types::sign_and_notarize(manifest, &network, 1, &signer).unwrap();
        let routable: RoutableTransaction = notarized.try_into().unwrap();
        let expected_hash = routable.hash();

        let validator = TransactionValidation::new(network);
        let (hash, result) = validator.validate_with_hash(&routable);

        assert_eq!(hash, expected_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_batch_validation() {
        let network = NetworkDefinition::simulator();
        let signer = generate_ed25519_keypair();

        // Create two valid transactions
        let manifest1 = ManifestBuilder::new().drop_all_proofs().build();
        let manifest2 = ManifestBuilder::new().drop_all_proofs().build();

        let notarized1 =
            hyperscale_types::sign_and_notarize(manifest1, &network, 1, &signer).unwrap();
        let notarized2 =
            hyperscale_types::sign_and_notarize(manifest2, &network, 2, &signer).unwrap();

        let routable1: RoutableTransaction = notarized1.try_into().unwrap();
        let routable2: RoutableTransaction = notarized2.try_into().unwrap();

        let validator = TransactionValidation::new(network);
        let results = validator.validate_batch(&[&routable1, &routable2]);

        assert_eq!(results.len(), 2);
        assert!(results[0].result.is_ok());
        assert!(results[1].result.is_ok());
    }
}
