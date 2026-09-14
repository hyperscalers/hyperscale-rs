//! The node-level cache of package artifacts fetched from other shards.

use hyperscale_types::Hash;

/// Fetched-package persistence beside the beacon chain: artifacts this
/// node pulled to run something that named them, so a restart re-learns
/// foreign code without refetching the world.
///
/// A cache and never an authority — the cell under each artifact's own
/// address is that, on whichever shard holds that prefix; content
/// addressing makes every copy equal, which is what lets this one be
/// pruned and refetched freely. Defaults are the empty cache, for stores
/// that never fetch.
pub trait FetchedPackageStore {
    /// Persist one fetched artifact under its content address.
    fn store_fetched_package(&self, package: Hash, artifact: &[u8]) {
        let _ = (package, artifact);
    }

    /// Every fetched artifact's bytes.
    fn fetched_packages(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}
