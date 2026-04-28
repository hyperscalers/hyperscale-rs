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

use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId};
use std::collections::HashMap;
use std::sync::Arc;

type Key = (ShardGroupId, BlockHeight);

/// Map of `(shard, height) → verified remote header`.
#[derive(Debug, Default)]
pub struct VerifiedHeaderBuffer {
    headers: HashMap<Key, Arc<CommittedBlockHeader>>,
}

impl VerifiedHeaderBuffer {
    pub(crate) fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    /// Insert a verified header. Overwrites any previous entry for the same key.
    pub(crate) fn insert(&mut self, key: Key, header: Arc<CommittedBlockHeader>) {
        self.headers.insert(key, header);
    }

    /// Look up a verified header by key.
    pub(crate) fn get(&self, key: Key) -> Option<&Arc<CommittedBlockHeader>> {
        self.headers.get(&key)
    }

    /// Remove and return a verified header.
    pub(crate) fn remove(&mut self, key: Key) -> Option<Arc<CommittedBlockHeader>> {
        self.headers.remove(&key)
    }

    pub(crate) fn len(&self) -> usize {
        self.headers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHash, BlockHeader, CertificateRoot, LocalReceiptRoot, ProvisionsRoot,
        QuorumCertificate, Round, StateRoot, TransactionRoot, ValidatorId,
    };
    use std::collections::BTreeMap;

    fn make_header(shard: ShardGroupId, height: BlockHeight) -> Arc<CommittedBlockHeader> {
        let header = BlockHeader {
            shard_group_id: shard,
            height,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: hyperscale_types::ProposerTimestamp(0),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        qc.height = height;
        Arc::new(CommittedBlockHeader::new(header, qc))
    }

    #[test]
    fn empty_buffer_has_no_entries() {
        let buf = VerifiedHeaderBuffer::new();
        assert_eq!(buf.len(), 0);
        assert!(buf.get((ShardGroupId(1), BlockHeight(0))).is_none());
    }

    #[test]
    fn insert_and_get_round_trip() {
        let mut buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId(1), BlockHeight(10));
        let header = make_header(ShardGroupId(1), BlockHeight(10));
        buf.insert(key, Arc::clone(&header));
        assert_eq!(buf.len(), 1);
        let stored = buf.get(key).expect("present");
        assert!(Arc::ptr_eq(stored, &header));
    }

    #[test]
    fn insert_overwrites_existing_key() {
        let mut buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId(1), BlockHeight(10));
        buf.insert(key, make_header(ShardGroupId(1), BlockHeight(10)));
        buf.insert(key, make_header(ShardGroupId(1), BlockHeight(10)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn remove_returns_stored_header_and_drops_entry() {
        let mut buf = VerifiedHeaderBuffer::new();
        let key = (ShardGroupId(1), BlockHeight(10));
        buf.insert(key, make_header(ShardGroupId(1), BlockHeight(10)));
        assert!(buf.remove(key).is_some());
        assert_eq!(buf.len(), 0);
        assert!(buf.remove(key).is_none());
    }
}
