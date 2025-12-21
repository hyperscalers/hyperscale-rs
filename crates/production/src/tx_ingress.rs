//! Transaction ingress with semaphore-based backpressure.
//!
//! This module provides a high-performance transaction ingress system that uses
//! `tokio::sync::Semaphore` for lock-free backpressure instead of RwLock-based
//! mempool snapshot checking.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    TRANSACTION INGRESS ARCHITECTURE                     │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//!     RPC Handler                   Network Gossip
//!           │                             │
//!           ▼                             ▼
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │               INGRESS HANDLE (lock-free)                        │
//!     │                                                                 │
//!     │  try_acquire_permit() ──► Semaphore::try_acquire()              │
//!     │  submit_with_permit() ──► bounded channel                       │
//!     │                                                                 │
//!     │  Metrics: permits_available, submissions_rejected               │
//!     └─────────────────────────────────────────────────────────────────┘
//!                                     │
//!                                     ▼
//!     ┌─────────────────────────────────────────────────────────────────┐
//!     │               MAIN EVENT LOOP (runner)                          │
//!     │                                                                 │
//!     │  recv() ──► process transaction                                 │
//!     │          ──► release permit on completion                       │
//!     └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Benefits
//!
//! 1. **Lock-Free**: Semaphore permits are acquired atomically
//! 2. **Bounded Memory**: Fixed number of in-flight transactions
//! 3. **Immediate Rejection**: No waiting on locks when capacity exhausted
//! 4. **Real-Time Backpressure**: No stale snapshot issues

use hyperscale_types::RoutableTransaction;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};

/// Configuration for the transaction ingress system.
#[derive(Debug, Clone)]
pub struct TxIngressConfig {
    /// Maximum number of concurrent in-flight transactions.
    /// When this limit is reached, new submissions are rejected immediately.
    /// Default: 5000
    pub max_in_flight: usize,

    /// Channel capacity for buffered transactions.
    /// Should be smaller than max_in_flight to prevent channel backup.
    /// Default: 1024
    pub channel_capacity: usize,
}

impl Default for TxIngressConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 5000,
            channel_capacity: 1024,
        }
    }
}

/// Statistics for the transaction ingress system.
#[derive(Debug, Default)]
pub struct TxIngressStats {
    /// Total transactions submitted successfully.
    pub submitted: AtomicU64,
    /// Total transactions rejected due to backpressure.
    pub rejected: AtomicU64,
    /// Total permits released (transactions processed or dropped).
    pub released: AtomicU64,
}

impl TxIngressStats {
    /// Get current rejection ratio (0.0 to 1.0).
    pub fn rejection_ratio(&self) -> f64 {
        let submitted = self.submitted.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);
        let total = submitted + rejected;
        if total == 0 {
            0.0
        } else {
            rejected as f64 / total as f64
        }
    }
}

/// A permit that must be held while a transaction is in-flight.
///
/// When dropped, the permit is released and another transaction can be submitted.
/// This is a wrapper around `tokio::sync::OwnedSemaphorePermit`.
pub struct IngressPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    stats: Arc<TxIngressStats>,
}

impl Drop for IngressPermit {
    fn drop(&mut self) {
        self.stats.released.fetch_add(1, Ordering::Relaxed);
    }
}

/// Transaction with its associated ingress permit.
///
/// The permit is held until the transaction is processed or dropped.
pub struct PermittedTransaction {
    /// The transaction to process.
    pub tx: Arc<RoutableTransaction>,
    /// Permit that is released when this is dropped.
    /// Kept as `Option` to allow explicit release if needed.
    permit: Option<IngressPermit>,
}

impl PermittedTransaction {
    /// Take the permit from this transaction.
    ///
    /// After calling this, dropping the `PermittedTransaction` will not release the permit.
    /// The caller is responsible for holding/dropping the permit appropriately.
    pub fn take_permit(&mut self) -> Option<IngressPermit> {
        self.permit.take()
    }
}

/// Handle for submitting transactions with backpressure.
///
/// This handle is cheap to clone and can be shared across threads.
/// All operations are lock-free.
#[derive(Clone)]
pub struct TxIngressHandle {
    semaphore: Arc<Semaphore>,
    tx: mpsc::Sender<PermittedTransaction>,
    stats: Arc<TxIngressStats>,
    max_permits: usize,
}

impl TxIngressHandle {
    /// Try to submit a transaction.
    ///
    /// Returns `Ok(())` if the transaction was accepted, `Err(tx)` if rejected
    /// due to backpressure (no permits available).
    ///
    /// This is a lock-free operation.
    pub fn try_submit(&self, tx: Arc<RoutableTransaction>) -> Result<(), Arc<RoutableTransaction>> {
        // Try to acquire a permit (non-blocking, atomic operation)
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                crate::metrics::record_tx_ingress_rejected();
                return Err(tx);
            }
        };

        let ingress_permit = IngressPermit {
            _permit: permit,
            stats: Arc::clone(&self.stats),
        };

        let permitted_tx = PermittedTransaction {
            tx,
            permit: Some(ingress_permit),
        };

        // Try to send to channel (non-blocking)
        match self.tx.try_send(permitted_tx) {
            Ok(()) => {
                self.stats.submitted.fetch_add(1, Ordering::Relaxed);
                crate::metrics::record_tx_ingress_submitted();
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(permitted_tx)) => {
                // Channel full - permit will be released when permitted_tx is dropped
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                crate::metrics::record_tx_ingress_rejected();
                Err(permitted_tx.tx)
            }
            Err(mpsc::error::TrySendError::Closed(permitted_tx)) => {
                // Channel closed - permit will be released when permitted_tx is dropped
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                crate::metrics::record_tx_ingress_rejected();
                Err(permitted_tx.tx)
            }
        }
    }

    /// Check if permits are available (for metrics/display).
    ///
    /// Note: This is racy - permits may be acquired/released between
    /// calling this and actually submitting.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Check if backpressure is active (no permits available).
    pub fn is_backpressured(&self) -> bool {
        self.semaphore.available_permits() == 0
    }

    /// Get current statistics.
    pub fn stats(&self) -> &TxIngressStats {
        &self.stats
    }

    /// Get maximum permits (configured limit).
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }
}

/// Receiver for permitted transactions.
///
/// The runner uses this to receive transactions. When the transaction is
/// processed, the permit is automatically released when the `PermittedTransaction`
/// is dropped.
pub struct TxIngressReceiver {
    rx: mpsc::Receiver<PermittedTransaction>,
}

impl TxIngressReceiver {
    /// Receive the next permitted transaction.
    ///
    /// Returns `None` if the channel is closed.
    pub async fn recv(&mut self) -> Option<PermittedTransaction> {
        self.rx.recv().await
    }

    /// Try to receive without blocking.
    pub fn try_recv(&mut self) -> Result<PermittedTransaction, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// Get the number of buffered transactions.
    pub fn len(&self) -> usize {
        // Note: mpsc::Receiver doesn't expose len(), but we can check capacity usage
        // For now, return 0 as a placeholder
        0
    }
}

/// Create a transaction ingress system.
///
/// Returns a handle for submitting transactions and a receiver for processing them.
pub fn create_tx_ingress(config: TxIngressConfig) -> (TxIngressHandle, TxIngressReceiver) {
    let semaphore = Arc::new(Semaphore::new(config.max_in_flight));
    let (tx, rx) = mpsc::channel(config.channel_capacity);
    let stats = Arc::new(TxIngressStats::default());

    let handle = TxIngressHandle {
        semaphore,
        tx,
        stats,
        max_permits: config.max_in_flight,
    };

    let receiver = TxIngressReceiver { rx };

    (handle, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_transaction;

    fn make_test_tx() -> Arc<RoutableTransaction> {
        Arc::new(test_transaction(1))
    }

    #[tokio::test]
    async fn test_basic_submission() {
        let config = TxIngressConfig {
            max_in_flight: 10,
            channel_capacity: 10,
        };
        let (handle, mut rx) = create_tx_ingress(config);

        let tx = make_test_tx();
        assert!(handle.try_submit(tx).is_ok());
        assert_eq!(handle.stats().submitted.load(Ordering::Relaxed), 1);
        assert_eq!(handle.stats().rejected.load(Ordering::Relaxed), 0);

        // Should receive the transaction
        let permitted = rx.recv().await.unwrap();
        // Verify we got a transaction (exact content depends on test_transaction implementation)
        assert!(!permitted.tx.hash().as_bytes().iter().all(|&b| b == 0));

        // Permit should be released when dropped
        drop(permitted);
        assert_eq!(handle.stats().released.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_backpressure() {
        let config = TxIngressConfig {
            max_in_flight: 2,
            channel_capacity: 10,
        };
        let (handle, _rx) = create_tx_ingress(config);

        // Submit 2 transactions (should succeed)
        let tx1 = make_test_tx();
        let tx2 = make_test_tx();
        assert!(handle.try_submit(tx1).is_ok());
        assert!(handle.try_submit(tx2).is_ok());

        // Third should be rejected (no permits)
        let tx3 = make_test_tx();
        assert!(handle.try_submit(tx3).is_err());
        assert_eq!(handle.stats().rejected.load(Ordering::Relaxed), 1);
        assert!(handle.is_backpressured());
    }

    #[tokio::test]
    async fn test_permit_release() {
        let config = TxIngressConfig {
            max_in_flight: 1,
            channel_capacity: 10,
        };
        let (handle, mut rx) = create_tx_ingress(config);

        // Submit 1 transaction
        let tx1 = make_test_tx();
        assert!(handle.try_submit(tx1).is_ok());
        assert!(handle.is_backpressured());

        // Receive and drop to release permit
        let permitted = rx.recv().await.unwrap();
        drop(permitted);

        // Now should be able to submit again
        let tx2 = make_test_tx();
        assert!(handle.try_submit(tx2).is_ok());
    }

    #[test]
    fn test_config_defaults() {
        let config = TxIngressConfig::default();
        assert_eq!(config.max_in_flight, 5000);
        assert_eq!(config.channel_capacity, 1024);
    }

    #[test]
    fn test_rejection_ratio() {
        let stats = TxIngressStats::default();
        assert_eq!(stats.rejection_ratio(), 0.0);

        stats.submitted.store(80, Ordering::Relaxed);
        stats.rejected.store(20, Ordering::Relaxed);
        assert!((stats.rejection_ratio() - 0.2).abs() < 0.001);
    }
}
