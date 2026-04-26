//! Typed accessors for default-CF metadata entries.
//!
//! Each metadata key is a [`MetadataEntry`](crate::typed_cf::MetadataEntry) —
//! the key bytes, value type, and codec are declared once in `typed_cf.rs`.
//! These thin wrappers provide domain-specific names and handle default values.

use crate::typed_cf::{
    self, CommittedHashEntry, CommittedHeightEntry, CommittedQcEntry, JmtMetadataEntry,
    ReadableStore,
};

use hyperscale_storage::StateRoot;
use hyperscale_types::{BlockHeight, Hash, QuorumCertificate};
use rocksdb::WriteBatch;

// ─── Chain metadata ──────────────────────────────────────────────────────────

pub fn write_committed_height(batch: &mut WriteBatch, height: BlockHeight) {
    typed_cf::meta_write::<CommittedHeightEntry>(batch, &height);
}

pub fn read_committed_height(store: &impl ReadableStore) -> BlockHeight {
    typed_cf::meta_read::<CommittedHeightEntry>(store).unwrap_or(BlockHeight(0))
}

pub fn write_committed_hash(batch: &mut WriteBatch, hash: &Hash) {
    typed_cf::meta_write::<CommittedHashEntry>(batch, hash);
}

pub fn read_committed_hash(store: &impl ReadableStore) -> Option<Hash> {
    typed_cf::meta_read::<CommittedHashEntry>(store)
}

pub fn write_committed_qc(batch: &mut WriteBatch, qc: &QuorumCertificate) {
    typed_cf::meta_write::<CommittedQcEntry>(batch, qc);
}

pub fn read_committed_qc(store: &impl ReadableStore) -> Option<QuorumCertificate> {
    typed_cf::meta_read::<CommittedQcEntry>(store)
}

// ─── JMT metadata ────────────────────────────────────────────────────────────

pub fn write_jmt_metadata(batch: &mut WriteBatch, version: u64, root: StateRoot) {
    typed_cf::meta_write::<JmtMetadataEntry>(batch, &(version, root));
}

/// Read JMT version + root hash.
///
/// Returns `(0, ZERO)` for an uninitialized database.
pub fn read_jmt_metadata(store: &impl ReadableStore) -> (u64, StateRoot) {
    typed_cf::meta_read::<JmtMetadataEntry>(store).unwrap_or((0, StateRoot::ZERO))
}
