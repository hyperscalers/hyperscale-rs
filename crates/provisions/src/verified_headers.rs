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
//! Eviction triggers, all from the coordinator: the deadline sweep on the
//! paired provisions, the orphan cutoff in `on_block_committed`, and the
//! fenced-shard purge that drops everything above a recovery or fork
//! frontier. Clearing an expectation on verification does NOT evict —
//! the header stays until one of those three reaches it, because a
//! second bundle at the same source block still needs it as its anchor.
//!
//! Backed by [`papaya::HashMap`] so the network worker can read entries
//! wait-free for the `local_provision.request` serve path while the
//! single state-machine writer mutates through `&self`.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, CertifiedBlockHeader, ShardId, Verified};
use papaya::HashMap;

type Key = (ShardId, BlockHeight);

/// Map of `(shard, height) → verified remote header`. Concurrent-safe so
/// it can be `Arc`-shared between the provisions coordinator (writer) and
/// inbound request handlers (readers).
#[derive(Debug, Default)]
pub struct VerifiedHeaderBuffer {
    headers: HashMap<Key, Arc<Verified<CertifiedBlockHeader>>>,
}

impl VerifiedHeaderBuffer {
    /// Create an empty buffer.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    /// Insert a verified header. Overwrites any previous entry for the same key.
    pub(crate) fn insert(&self, key: Key, header: Arc<Verified<CertifiedBlockHeader>>) {
        self.headers.pin().insert(key, header);
    }

    /// Look up a verified header by key.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        self.headers.pin().get(&key).cloned()
    }

    /// Remove every entry for `shard` strictly above `frontier`, returning
    /// the removed keys. Applied when a pending recovery fences the shard:
    /// above the attested frontier the retained committee's certified
    /// history is rejected network-wide, so a pre-admitted header must not
    /// keep anchoring provision verification.
    pub(crate) fn remove_above(&self, shard: ShardId, frontier: BlockHeight) -> Vec<Key> {
        let map = self.headers.pin();
        let keys: Vec<Key> = map
            .keys()
            .filter(|&&(s, h)| s == shard && h > frontier)
            .copied()
            .collect();
        for key in &keys {
            map.remove(key);
        }
        keys
    }

    /// Remove and return a verified header.
    pub(crate) fn remove(&self, key: Key) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        self.headers.pin().remove(&key).cloned()
    }

    /// Current number of stored headers.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
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
        AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, ChainOrigin,
        ProposerTimestamp, QuorumCertificate, Round, SignerBitfield, WeightedTimestamp,
    };

    use super::*;

    fn make_header(shard: ShardId, height: BlockHeight) -> Arc<Verified<CertifiedBlockHeader>> {
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(0),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        });
        let header_hash = header.hash();
        let qc = QuorumCertificate::new(
            header_hash,
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    #[test]
    fn empty_buffer_has_no_entries() {
        let buf = VerifiedHeaderBuffer::new();
        assert_eq!(buf.len(), 0);
        assert!(
            buf.get((ShardId::leaf(1, 1), BlockHeight::new(0)))
                .is_none()
        );
    }

    #[test]
    fn insert_and_get_round_trip() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardId::leaf(1, 1), BlockHeight::new(10));
        let header = make_header(ShardId::leaf(1, 1), BlockHeight::new(10));
        buf.insert(key, Arc::clone(&header));
        assert_eq!(buf.len(), 1);
        let stored = buf.get(key).expect("present");
        assert!(Arc::ptr_eq(&stored, &header));
    }

    #[test]
    fn insert_overwrites_existing_key() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardId::leaf(1, 1), BlockHeight::new(10));
        buf.insert(key, make_header(ShardId::leaf(1, 1), BlockHeight::new(10)));
        buf.insert(key, make_header(ShardId::leaf(1, 1), BlockHeight::new(10)));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn remove_returns_stored_header_and_drops_entry() {
        let buf = VerifiedHeaderBuffer::new();
        let key = (ShardId::leaf(1, 1), BlockHeight::new(10));
        buf.insert(key, make_header(ShardId::leaf(1, 1), BlockHeight::new(10)));
        assert!(buf.remove(key).is_some());
        assert_eq!(buf.len(), 0);
        assert!(buf.remove(key).is_none());
    }
}
