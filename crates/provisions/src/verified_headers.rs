//! Verified remote committed block header buffer.
//!
//! Stores remote headers that have already passed QC verification (via the
//! `RemoteHeaderCoordinator`) and are paired with provisions awaiting
//! verification or commit. Pure map operations — no topology, no time, no
//! verification logic.
//!
//! Two reasons a header lives here:
//! 1. The coordinator needs it to verify provisions' merkle proof
//!    against the source block's `state_root`.
//! 2. The expected-provisions tracker has registered outstanding
//!    provisions against this `(shard, height)` and the header is
//!    their anchor.
//!
//! Eviction triggers from the coordinator: deadline sweep on the paired
//! provisions, expectation cleared on verification, or orphan cutoff in
//! `on_block_committed`.
//!
//! Backed by [`papaya::HashMap`] so the network worker can read entries
//! wait-free for the `local_provision.request` serve path while the
//! single state-machine writer mutates through `&self`.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId};
use papaya::HashMap;

type Key = (ShardGroupId, BlockHeight);

/// Map of `(shard, height) → verified remote header`. Concurrent-safe so
/// it can be `Arc`-shared between the provisions coordinator (writer) and
/// inbound request handlers (readers).
#[derive(Debug, Default)]
pub struct VerifiedHeaderBuffer {
    headers: HashMap<Key, Arc<CommittedBlockHeader>>,
}

impl VerifiedHeaderBuffer {
    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    /// Insert a verified header. Overwrites any previous entry for the same key.
    pub fn insert(&self, key: Key, header: Arc<CommittedBlockHeader>) {
        self.headers.pin().insert(key, header);
    }

    /// Look up a verified header by key.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<Arc<CommittedBlockHeader>> {
        self.headers.pin().get(&key).cloned()
    }

    /// Remove and return a verified header.
    pub fn remove(&self, key: Key) -> Option<Arc<CommittedBlockHeader>> {
        self.headers.pin().remove(&key).cloned()
    }

    /// Current number of stored headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// True when no headers are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BlockHash, BlockHeader, CertificateRoot, InFlightCount, LocalReceiptRoot,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, SignerBitfield, StateRoot,
        TransactionRoot, ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn make_header(shard: ShardGroupId, height: BlockHeight) -> Arc<CommittedBlockHeader> {
        let header = BlockHeader::new(
            shard,
            height,
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
        );
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        Arc::new(CommittedBlockHeader::new(header, qc))
    }

    #[test]
    fn empty_buffer_has_no_entries() {
        let buf = VerifiedHeaderBuffer::new();
        assert_eq!(buf.len(), 0);
        assert!(
            buf.get((ShardGroupId::new(1), BlockHeight::new(0)))
                .is_none()
        );
    }

    #[test]
    fn insert_and_get_round_trip() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId::new(1), BlockHeight::new(10));
        let header = make_header(ShardGroupId::new(1), BlockHeight::new(10));
        buf.insert(key, Arc::clone(&header));
        assert_eq!(buf.len(), 1);
        let stored = buf.get(key).expect("present");
        assert!(Arc::ptr_eq(&stored, &header));
    }

    #[test]
    fn insert_overwrites_existing_key() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId::new(1), BlockHeight::new(10));
        buf.insert(key, make_header(ShardGroupId::new(1), BlockHeight::new(10)));
        buf.insert(key, make_header(ShardGroupId::new(1), BlockHeight::new(10)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn remove_returns_stored_header_and_drops_entry() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId::new(1), BlockHeight::new(10));
        buf.insert(key, make_header(ShardGroupId::new(1), BlockHeight::new(10)));
        assert!(buf.remove(key).is_some());
        assert_eq!(buf.len(), 0);
        assert!(buf.remove(key).is_none());
    }
}
