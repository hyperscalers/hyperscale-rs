//! The node-level copy of component records fetched from other shards.

use hyperscale_types::Address;

/// Fetched-record persistence beside the beacon chain.
///
/// The records of foreign components this node pulled to route something
/// that named them, kept so neither a restart nor a bounded cache letting
/// one go leaves a transaction this node once routed unroutable.
///
/// A copy and never an authority: the `CONFIG` leaf under each
/// component's own prefix is that, on whichever shard holds it. A record
/// is the hash preimage of its address, so every copy is the same copy
/// and a reader verifies one by re-deriving the address it is keyed by.
/// Defaults are the empty store, for stores that never fetch.
pub trait FetchedInstanceStore {
    /// Persist fetched records, each under the address it derives.
    ///
    /// Durable before it returns: a transaction routed on one of these
    /// commits only after this, and a replay of that commit derives the
    /// transaction again from what this kept.
    fn store_fetched_instances(&self, records: &[(Address, Vec<u8>)]) {
        let _ = records;
    }

    /// The record fetched for `instance`, if this node ever fetched one.
    fn fetched_instance(&self, instance: Address) -> Option<Vec<u8>> {
        let _ = instance;
        None
    }
}
