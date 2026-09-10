//! Typed accessors for default-CF metadata entries.
//!
//! Each metadata key is a [`MetadataEntry`](crate::typed_cf::MetadataEntry) —
//! the key bytes, value type, and codec are declared once in `typed_cf.rs`.
//! These thin wrappers provide domain-specific names and handle default values.

use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, ChainOrigin, Hash, QuorumCertificate, StateRoot,
};
use rocksdb::WriteBatch;

use crate::typed_cf::{
    self, BoundaryHeaderEntry, ChainOriginEntry, CommittedHashEntry, CommittedHeightEntry,
    CommittedQcEntry, JmtMetadataEntry, ReadableStore, RetentionFloorEntry,
};

// ─── Chain metadata ──────────────────────────────────────────────────────────

pub fn write_committed_height(batch: &mut WriteBatch, height: BlockHeight) {
    typed_cf::meta_write::<CommittedHeightEntry>(batch, &height);
}

pub fn read_committed_height(store: &impl ReadableStore) -> BlockHeight {
    typed_cf::meta_read::<CommittedHeightEntry>(store).unwrap_or(BlockHeight::new(0))
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

/// Drop the stored latest QC. A split-child adoption resets the
/// checkpoint-inherited parent QC this way: the child chain holds no QC
/// at its genesis, and recovery's `latest_qc: None` makes the first
/// proposal extend the structural genesis QC reconstructed from the
/// chain origin.
pub fn delete_committed_qc(batch: &mut WriteBatch) {
    typed_cf::meta_delete::<CommittedQcEntry>(batch);
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

/// Move the retention floor to `version`.
pub fn write_retention_floor(batch: &mut WriteBatch, version: u64) {
    typed_cf::meta_write::<RetentionFloorEntry>(batch, &version);
}

/// The oldest version still inside the retention horizon.
///
/// Returns `0` for a store that has never written one, which retains
/// everything it holds — the answer a chain that has not yet run for a
/// horizon's worth of time gives anyway.
pub fn read_retention_floor(store: &impl ReadableStore) -> u64 {
    typed_cf::meta_read::<RetentionFloorEntry>(store).unwrap_or(0)
}

// ─── Imported boundary header ────────────────────────────────────────────────

pub fn write_boundary_header(batch: &mut WriteBatch, header: &CertifiedBlockHeader) {
    typed_cf::meta_write::<BoundaryHeaderEntry>(batch, header);
}

/// The certified header of the boundary this store imported, if it was
/// snap-synced and the import carried one.
pub fn read_boundary_header(store: &impl ReadableStore) -> Option<CertifiedBlockHeader> {
    typed_cf::meta_read::<BoundaryHeaderEntry>(store)
}

// ─── Chain origin ────────────────────────────────────────────────────────────

pub fn write_chain_origin(batch: &mut WriteBatch, origin: ChainOrigin) {
    typed_cf::meta_write::<ChainOriginEntry>(batch, &origin);
}

/// Read the chain's origin — genesis height plus start-time anchor.
///
/// Returns [`ChainOrigin::ROOT`] when no record exists: only split-child
/// adoption writes one, so every store predating it is a chain born at
/// network genesis.
pub fn read_chain_origin(store: &impl ReadableStore) -> ChainOrigin {
    typed_cf::meta_read::<ChainOriginEntry>(store).unwrap_or(ChainOrigin::ROOT)
}
