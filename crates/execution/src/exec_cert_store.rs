//! Shared execution-certificate store.
//!
//! This shard's aggregated [`ExecutionCertificate`]s during the window
//! between local aggregation or verification and the tick's containing
//! block committing: a late voter is answered with the certificate, and a
//! retransmit of one already verified skips verification. Held behind an
//! `Arc` so the shard loop's request serving reads the replica's map.
//!
//! Two writers — both inside the coordinator — feed this store:
//!
//! - **Tick-leader path** inserts on local EC aggregation, before the cert is
//!   broadcast to local peers and remote shards.
//! - **Non-leader path** inserts after verifying a local-shard EC received via
//!   broadcast.
//!
//! Eviction is lifecycle-driven: entries are dropped in
//! [`ExecutionCoordinator::remove_finalization`] once the tick's containing
//! block commits.
//!
//! Backed by [`papaya::HashMap`] — a lock-free concurrent map.
//!
//! [`ExecutionCertificate`]: hyperscale_types::ExecutionCertificate
//! [`ExecutionCoordinator::remove_finalization`]: crate::ExecutionCoordinator::remove_finalization

use std::sync::Arc;

use hyperscale_types::{ExecutionCertificate, TickId, Verified};
use papaya::HashMap;

/// Shared store of aggregated [`ExecutionCertificate`]s awaiting block
/// commit, by tick.
pub struct ExecCertStore {
    inner: HashMap<TickId, Arc<Verified<ExecutionCertificate>>>,
}

impl ExecCertStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a verified execution certificate. Idempotent: re-inserting
    /// the same `TickId` is a no-op (the existing `Arc` is preserved so
    /// callers holding clones keep pointing at the same allocation).
    ///
    /// A no-op for a wider copy of a held tick too. The writer is single,
    /// so the check and the insert do not race.
    ///
    /// The one copy that replaces a held one carries the same outcomes
    /// at a later anchor: a tick re-attested by a later committee. Every
    /// verifier resolves a certificate's committee at its own anchor and
    /// stops resolving an old one once that window is evicted, so the
    /// later copy is the one still worth serving.
    pub fn insert(&self, cert: Arc<Verified<ExecutionCertificate>>) {
        let tick_id = *cert.tick_id();
        let inner = self.inner.pin();
        if let Some(held) = inner.get(&tick_id) {
            if cert.vote_anchor_ts() > held.vote_anchor_ts()
                && cert.tx_outcomes() == held.tx_outcomes()
            {
                inner.insert(tick_id, cert);
            }
            return;
        }
        inner.get_or_insert_with(tick_id, || cert);
    }

    /// Look up a verified execution certificate by `TickId`.
    #[must_use]
    pub(crate) fn get(&self, tick_id: &TickId) -> Option<Arc<Verified<ExecutionCertificate>>> {
        self.inner.pin().get(tick_id).cloned()
    }

    /// Drop the entry for `tick_id`, if any.
    pub(crate) fn evict(&self, tick_id: &TickId) {
        self.inner.pin().remove(tick_id);
    }

    /// Number of certificates currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the store holds no certificates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for ExecCertStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        AggregateSignature, BlockHeight, ExecutionOutcome, GlobalReceiptRoot, Hash, Role, ShardId,
        SignerBitfield, TxHash, TxOutcome, WeightedTimestamp,
    };

    use super::*;

    fn cert(block_height: u64) -> Arc<Verified<ExecutionCertificate>> {
        anchored(block_height, WeightedTimestamp::ZERO, vec![])
    }

    /// A certificate at `block_height` attesting `outcomes` at `anchor`.
    fn anchored(
        block_height: u64,
        anchor: WeightedTimestamp,
        outcomes: Vec<TxOutcome>,
    ) -> Arc<Verified<ExecutionCertificate>> {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(block_height));
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            tick_id,
            anchor,
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )))
    }

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    fn outcome(tx_hash: TxHash, role: Role) -> TxOutcome {
        TxOutcome::new(tx_hash, ExecutionOutcome::Aborted).as_role(role)
    }

    /// A re-attested copy of a held tick displaces the earlier one, and
    /// an earlier copy never displaces a later one.
    #[test]
    fn a_later_anchored_copy_displaces_the_held_one() {
        let store = ExecCertStore::new();
        let outcomes = vec![outcome(tx(1), Role::Core)];
        let first = anchored(1, WeightedTimestamp::from_millis(10), outcomes.clone());
        let later = anchored(1, WeightedTimestamp::from_millis(500), outcomes);
        store.insert(Arc::clone(&first));
        store.insert(Arc::clone(&later));
        let held =
            |store: &ExecCertStore| store.get(first.tick_id()).map(|cert| cert.vote_anchor_ts());
        assert_eq!(held(&store), Some(WeightedTimestamp::from_millis(500)));

        store.insert(Arc::clone(&first));
        assert_eq!(held(&store), Some(WeightedTimestamp::from_millis(500)));
    }

    #[test]
    fn insert_then_get_round_trips() {
        let store = ExecCertStore::new();
        let c = cert(1);
        let id = *c.tick_id();
        store.insert(Arc::clone(&c));
        assert_eq!(store.get(&id).map(|a| *a.tick_id()), Some(id));
    }

    #[test]
    fn insert_is_idempotent() {
        let store = ExecCertStore::new();
        let c = cert(1);
        store.insert(Arc::clone(&c));
        store.insert(Arc::clone(&c));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn evict_removes_only_named_entry() {
        let store = ExecCertStore::new();
        let a = cert(1);
        let b = cert(2);
        store.insert(Arc::clone(&a));
        store.insert(Arc::clone(&b));
        store.evict(a.tick_id());
        assert!(store.get(a.tick_id()).is_none());
        assert!(store.get(b.tick_id()).is_some());
    }

    #[test]
    fn evict_absent_is_noop() {
        let store = ExecCertStore::new();
        let a = cert(1);
        store.evict(a.tick_id());
        assert!(store.is_empty());
    }
}
