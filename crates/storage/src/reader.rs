//! Byte-level substate read interface.
//!
//! [`SubstateReader`] provides framework-level access to substate storage
//! without depending on Radix-specific types (`DbPartitionKey`, `DbSortKey`,
//! `SubstateDatabase`). Storage backends implement this trait alongside
//! the Radix-specific `SubstateDatabase` trait.
//!
//! The Radix executor bridges from `SubstateReader` to `SubstateDatabase`
//! via `RadixStorageAdapter` in the engine crate.

/// Read-only byte-level access to substate storage.
///
/// This is the framework's storage read interface, free of Radix-specific
/// types. Both the storage itself and its snapshots implement this trait.
///
/// # Key encoding
///
/// - `node_key`: The raw entity key bytes (hash-prefixed NodeId, typically
///   50 bytes: 20-byte hash prefix + 30-byte NodeId).
/// - `partition_num`: Partition number within the entity (u8).
/// - `sort_key`: Sort key bytes within the partition.
pub trait SubstateReader: Send + Sync {
    /// Read a single substate value.
    ///
    /// Returns `None` if the substate does not exist.
    fn get_raw_substate(
        &self,
        node_key: &[u8],
        partition_num: u8,
        sort_key: &[u8],
    ) -> Option<Vec<u8>>;

    /// List substates in a partition, optionally starting from a sort key.
    ///
    /// Returns an iterator of `(sort_key, value)` pairs in sort order.
    fn list_raw_substates(
        &self,
        node_key: &[u8],
        partition_num: u8,
        from_sort_key: Option<&[u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>;
}
