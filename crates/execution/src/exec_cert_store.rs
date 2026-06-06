//! Shared execution-certificate store.
//!
//! Single source of truth for aggregated [`ExecutionCertificate`]s during the
//! window between local aggregation/verification and the wave's containing
//! block committing. Held behind an `Arc` so the single-threaded execution
//! coordinator (the sole writer) and the network worker thread (read-only,
//! serving cross-shard EC fetch requests) can share the same map without
//! channel-bouncing or contending on a coordinator lock.
//!
//! Two writers — both inside the coordinator — feed this store:
//!
//! - **Wave-leader path** inserts on local EC aggregation, before the cert is
//!   broadcast to local peers and remote shards.
//! - **Non-leader path** inserts after verifying a local-shard EC received via
//!   broadcast, so any node can serve fallback EC fetches for its own shard.
//!
//! Eviction is lifecycle-driven: entries are dropped in
//! [`ExecutionCoordinator::remove_finalized_wave`] once the wave's containing
//! block commits, at which point the EC is durably available via
//! [`ShardStorage::get_execution_certificates_by_height`] and the network handler
//! falls through to that on cache miss.
//!
//! Mirrors [`hyperscale_mempool::TxStore`] in shape and intent: a single
//! primary index keyed by the natural identifier (`WaveId` here, `TxHash`
//! there), no secondary indexes (EC fetches are wave-id-keyed only).
//!
//! Backed by [`papaya::HashMap`] — a lock-free concurrent map. Reads from the
//! network worker are wait-free in the common case and never contend with
//! the single state-machine writer.
//!
//! [`ExecutionCertificate`]: hyperscale_types::ExecutionCertificate
//! [`ExecutionCoordinator::remove_finalized_wave`]: crate::ExecutionCoordinator::remove_finalized_wave
//! [`ShardStorage::get_execution_certificates_by_height`]: hyperscale_storage::ShardStorage::get_execution_certificates_by_height

use std::sync::Arc;

use hyperscale_types::{ExecutionCertificate, Verified, WaveId};
use papaya::HashMap;

/// Shared, content-addressed store of aggregated [`ExecutionCertificate`]s
/// awaiting block commit.
///
/// Read-heavy on the network worker thread (one lookup per inbound EC
/// fetch); writes (insert on aggregation/verification, evict on wave-cert
/// commit) are infrequent and single-threaded (state machine).
pub struct ExecCertStore {
    inner: HashMap<WaveId, Arc<Verified<ExecutionCertificate>>>,
}

impl ExecCertStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a verified execution certificate. Idempotent: re-inserting
    /// the same `WaveId` is a no-op (the existing `Arc` is preserved so
    /// callers holding clones keep pointing at the same allocation).
    pub fn insert(&self, cert: Arc<Verified<ExecutionCertificate>>) {
        let wave_id = cert.wave_id().clone();
        self.inner.pin().get_or_insert_with(wave_id, || cert);
    }

    /// Look up a verified execution certificate by `WaveId`.
    #[must_use]
    pub fn get(&self, wave_id: &WaveId) -> Option<Arc<Verified<ExecutionCertificate>>> {
        self.inner.pin().get(wave_id).cloned()
    }

    /// Drop the entry for `wave_id`, if any.
    pub fn evict(&self, wave_id: &WaveId) {
        self.inner.pin().remove(wave_id);
    }

    /// Number of certificates currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the store holds no certificates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for ExecCertStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BlockHeight, GlobalReceiptRoot, ShardId, SignerBitfield, WeightedTimestamp,
        zero_bls_signature,
    };

    use super::*;

    fn cert(block_height: u64) -> Arc<Verified<ExecutionCertificate>> {
        let wave_id = WaveId::new(
            ShardId::ROOT,
            BlockHeight::new(block_height),
            BTreeSet::new(),
        );
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        )))
    }

    #[test]
    fn insert_then_get_round_trips() {
        let store = ExecCertStore::new();
        let c = cert(1);
        let id = c.wave_id().clone();
        store.insert(Arc::clone(&c));
        assert_eq!(store.get(&id).map(|a| a.wave_id().clone()), Some(id));
    }

    #[test]
    fn insert_is_idempotent() {
        let store = ExecCertStore::new();
        let c = cert(1);
        store.insert(Arc::clone(&c));
        store.insert(Arc::clone(&c));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn evict_removes_only_named_entry() {
        let store = ExecCertStore::new();
        let a = cert(1);
        let b = cert(2);
        store.insert(Arc::clone(&a));
        store.insert(Arc::clone(&b));
        store.evict(a.wave_id());
        assert!(store.get(a.wave_id()).is_none());
        assert!(store.get(b.wave_id()).is_some());
    }

    #[test]
    fn evict_absent_is_noop() {
        let store = ExecCertStore::new();
        let a = cert(1);
        store.evict(a.wave_id());
        assert!(store.is_empty());
    }
}
