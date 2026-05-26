//! Gossip-arrival cache for beacon blocks awaiting verification.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{BeaconBlockHash, CertifiedBeaconBlock, Epoch};

/// Map of `BeaconBlockHash → Arc<CertifiedBeaconBlock>` for blocks
/// received via gossip but not yet verified or applied.
///
/// Bounded by [`Self::prune_committed`] — callers invoke it after
/// every committed epoch to drop settled entries.
#[derive(Debug, Default)]
pub struct PendingBeaconBlocks(BTreeMap<BeaconBlockHash, Arc<CertifiedBeaconBlock>>);

impl PendingBeaconBlocks {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `block` keyed on its own block hash. Returns the
    /// prior entry under the same hash, if any.
    pub fn insert(
        &mut self,
        block: Arc<CertifiedBeaconBlock>,
    ) -> Option<Arc<CertifiedBeaconBlock>> {
        self.0.insert(block.block_hash(), block)
    }

    /// Drop entries whose epoch is `<= committed_epoch`. Returns the
    /// number of entries removed.
    pub fn prune_committed(&mut self, committed_epoch: Epoch) -> usize {
        let before = self.0.len();
        self.0.retain(|_, block| block.epoch() > committed_epoch);
        before - self.0.len()
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl PendingBeaconBlocks {
    #[must_use]
    pub fn get(&self, hash: BeaconBlockHash) -> Option<&Arc<CertifiedBeaconBlock>> {
        self.0.get(&hash)
    }

    pub fn remove(&mut self, hash: BeaconBlockHash) -> Option<Arc<CertifiedBeaconBlock>> {
        self.0.remove(&hash)
    }

    #[must_use]
    pub fn contains_key(&self, hash: BeaconBlockHash) -> bool {
        self.0.contains_key(&hash)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlock, BeaconBlockHash, BeaconCert, Bls12381G2Signature, CertifiedBeaconBlock, Epoch,
        GenesisConfigHash, Hash, SignerBitfield, SkipEpochCert,
    };

    use super::*;

    fn block_at(epoch: u64, tag: &[u8]) -> Arc<CertifiedBeaconBlock> {
        // Past genesis: use a Skip-shaped block so we have an empty
        // proposal list without needing to manufacture an SPC cert. The
        // tests only care about hash/epoch identity, not cert content.
        if epoch == 0 {
            return Arc::new(CertifiedBeaconBlock::genesis(GenesisConfigHash::ZERO));
        }
        let block = BeaconBlock::skip(
            Epoch::new(epoch),
            BeaconBlockHash::from_raw(Hash::from_bytes(tag)),
        );
        let skip_cert = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(epoch),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        );
        Arc::new(CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Skip(skip_cert),
            None,
        ))
    }

    #[test]
    fn empty_after_new() {
        let p = PendingBeaconBlocks::new();
        assert_eq!(p.len(), 0);
        assert!(p.is_empty());
        assert!(p.get(BeaconBlockHash::ZERO).is_none());
        assert!(!p.contains_key(BeaconBlockHash::ZERO));
    }

    #[test]
    fn insert_then_get_round_trips() {
        let mut p = PendingBeaconBlocks::new();
        let b = block_at(5, b"five");
        let hash = b.block_hash();
        assert!(p.insert(Arc::clone(&b)).is_none());
        assert!(p.contains_key(hash));
        assert_eq!(p.get(hash).map(|x| x.epoch()), Some(Epoch::new(5)));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn duplicate_insert_returns_prior_entry() {
        let mut p = PendingBeaconBlocks::new();
        let b = block_at(5, b"five");
        let dup = Arc::clone(&b);
        p.insert(b);
        let returned = p.insert(dup);
        assert!(returned.is_some());
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn remove_returns_entry_and_clears_it() {
        let mut p = PendingBeaconBlocks::new();
        let b = block_at(5, b"five");
        let hash = b.block_hash();
        p.insert(b);
        let taken = p.remove(hash);
        assert!(taken.is_some());
        assert!(!p.contains_key(hash));
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn prune_drops_at_or_below_committed_keeps_future() {
        use std::collections::BTreeMap;
        let mut p = PendingBeaconBlocks::new();
        let mut hashes_by_epoch = BTreeMap::new();
        for epoch in 1u64..=5 {
            let b = block_at(epoch, format!("e{epoch}").as_bytes());
            hashes_by_epoch.insert(epoch, b.block_hash());
            p.insert(b);
        }
        let dropped = p.prune_committed(Epoch::new(3));
        assert_eq!(dropped, 3);
        assert_eq!(p.len(), 2);
        for epoch in 1u64..=3 {
            assert!(!p.contains_key(hashes_by_epoch[&epoch]));
        }
        for epoch in 4u64..=5 {
            assert!(p.contains_key(hashes_by_epoch[&epoch]));
        }
    }

    #[test]
    fn prune_returns_zero_when_nothing_to_drop() {
        let mut p = PendingBeaconBlocks::new();
        p.insert(block_at(7, b"seven"));
        let dropped = p.prune_committed(Epoch::new(3));
        assert_eq!(dropped, 0);
        assert_eq!(p.len(), 1);
    }
}
