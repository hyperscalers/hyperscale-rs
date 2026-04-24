//! Shared provision-batch store.
//!
//! Single source of truth for provision bodies, keyed by content hash.
//! Held behind an `Arc` so both the single-threaded provisions state
//! machine and network-thread request handlers can read/write through
//! the same map. Eviction is driven exclusively by the post-commit
//! retention sweep in [`crate::state::ProvisionCoordinator`] — entries
//! for uncommitted batches persist until a local block commit references
//! them, matching the lifetime of the batch's usefulness for serving
//! `local_provision.request` fetches.

use hyperscale_types::{Provision, ProvisionHash};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct ProvisionStore {
    inner: Mutex<HashMap<ProvisionHash, Arc<Provision>>>,
}

impl ProvisionStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a batch. Idempotent: re-inserting the same hash is a no-op.
    pub fn insert(&self, batch: Arc<Provision>) {
        let hash = batch.hash();
        let mut g = self.inner.lock().unwrap();
        g.entry(hash).or_insert(batch);
    }

    /// Look up a batch by content hash.
    pub fn get(&self, hash: &ProvisionHash) -> Option<Arc<Provision>> {
        self.inner.lock().unwrap().get(hash).cloned()
    }

    /// Evict batches whose retention window has elapsed. Called from the
    /// post-commit sweep in [`crate::state::ProvisionCoordinator`].
    /// Returns the number of entries actually removed.
    pub fn evict(&self, hashes: impl IntoIterator<Item = ProvisionHash>) -> usize {
        let mut g = self.inner.lock().unwrap();
        hashes.into_iter().filter(|h| g.remove(h).is_some()).count()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

impl Default for ProvisionStore {
    fn default() -> Self {
        Self::new()
    }
}
