//! What a source block owes each target: the keys each transaction's
//! part serves, and the leaves its header commits, one per transaction
//! the request rule owes the target, in block order, each binding the
//! transaction to the keys its part serves.

use std::collections::BTreeMap;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_storage::Substates;
use hyperscale_types::{
    EntryKey, Hash, ProtocolHasher, ProvisionTxRoot, ProvisionTxRootsMap, ShardId, ShardTrie,
    SubstateKey, Transaction, TxHash, Verifiable, WeightedTimestamp, entry_leaf_key,
    provision_leaf, served_digest,
};
use thiserror::Error;

use crate::requests::provision_request;

/// The keys `request`'s part serves out of `state`, the state the
/// source block left.
///
/// Every declared local cell, and the leaf of each entry a declared
/// local range holds in `state`, up to its cap; ascending, one copy
/// each. The one function that decides a part's keys. Cells cost no
/// read: a part's proof binds their presence and values. Only ranges
/// read state.
#[must_use]
pub fn served_keys(state: &impl Substates, request: &ProvisionsRequest) -> Vec<SubstateKey> {
    let mut keys = request.local_keys.clone();
    for range in &request.local_ranges {
        let held = state.entries_in_range(
            range.owner,
            range.collection,
            range.lo,
            range.hi,
            range.cap as usize,
        );
        keys.extend(held.into_iter().map(|(order, _)| {
            entry_leaf_key(
                &ProtocolHasher,
                EntryKey {
                    owner: range.owner,
                    collection: range.collection,
                    order,
                },
            )
        }));
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// A block transaction this node has not derived, so cannot route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("transaction {tx_hash} is not routed here")]
pub struct Unrouted {
    /// The transaction.
    pub tx_hash: TxHash,
}

/// The leaf `request`'s part sits at under each of its targets' roots,
/// over `keys`, its [`served_keys`], at the request's clock.
#[must_use]
pub fn served_leaf(request: &ProvisionsRequest, keys: &[SubstateKey]) -> Hash {
    provision_leaf(
        request.tx_hash,
        request.clock,
        served_digest(keys.iter().copied()),
    )
}

/// Each request's [`served_keys`] out of `state`, in request order: read
/// once however many targets a request names.
#[must_use]
pub fn keys_over_requests(
    state: &impl Substates,
    requests: &[ProvisionsRequest],
) -> Vec<Vec<SubstateKey>> {
    requests
        .iter()
        .map(|request| served_keys(state, request))
        .collect()
}

/// The leaves each target's root holds over `requests`, whose served
/// keys out of `state` are read once each, in request order. A target no
/// request names holds none.
#[must_use]
pub fn leaves_over_requests(
    state: &impl Substates,
    requests: &[ProvisionsRequest],
) -> BTreeMap<ShardId, Vec<Hash>> {
    let mut leaves: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
    for request in requests {
        let leaf = served_leaf(request, &served_keys(state, request));
        for target in &request.targets {
            leaves.entry(*target).or_default().push(leaf);
        }
    }
    leaves
}

/// The per-target provision roots of a block `local_shard` holds with
/// `transactions`, routed under `trie`, over `state`, the state the block
/// leaves: one entry for each target owed at least one leaf.
///
/// Each leaf binds `clock`, the block's parent-QC weighted timestamp.
///
/// # Errors
///
/// [`Unrouted`] for the first transaction this node has not derived:
/// whether it owes anyone a leaf is a derivation this node lacks, so it
/// has no root to state, rather than one taken over the rest.
///
/// # Panics
///
/// Never: a block owes at most one entry per other shard, which is what
/// [`ProvisionTxRootsMap`] caps.
pub fn provision_tx_roots(
    state: &impl Substates,
    trie: &ShardTrie,
    local_shard: ShardId,
    clock: WeightedTimestamp,
    transactions: &[Verifiable<Transaction>],
) -> Result<ProvisionTxRootsMap, Unrouted> {
    let mut requests = Vec::new();
    for tx in transactions {
        if !tx.as_unverified().is_routed() {
            return Err(Unrouted { tx_hash: tx.hash() });
        }
        requests.extend(provision_request(trie, tx, local_shard, clock));
    }
    Ok(Capped::new(
        leaves_over_requests(state, &requests)
            .into_iter()
            .map(|(target, leaves)| (target, ProvisionTxRoot::over(&leaves)))
            .collect(),
    )
    .expect("a block owes one entry per other shard"))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, test_prefix, test_transaction_with_prefixes,
    };
    use hyperscale_types::{Address, CollectionId};

    use super::*;

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const REMOTE: ShardId = ShardId::leaf(1, 1);

    /// A state holding nothing.
    struct Empty;

    impl Substates for Empty {
        fn cell(&self, _: SubstateKey) -> Option<Vec<u8>> {
            None
        }

        fn entries_in_range(
            &self,
            _: Address,
            _: CollectionId,
            _: u128,
            _: u128,
            _: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    /// A routed transaction paid from `seed` on this shard and writing
    /// under `prefixes`.
    fn routed(seed: u8, prefixes: &[Address]) -> Verifiable<Transaction> {
        install_stub_protocol_statics();
        Verifiable::from(test_transaction_with_prefixes(&[seed], &[], prefixes))
    }

    fn roots(transactions: &[Verifiable<Transaction>]) -> Result<ProvisionTxRootsMap, Unrouted> {
        provision_tx_roots(
            &Empty,
            &ShardTrie::uniform(1),
            LOCAL,
            WeightedTimestamp::ZERO,
            transactions,
        )
    }

    /// The leaf `tx`'s part to [`REMOTE`] sits at.
    fn leaf_of(tx: &Verifiable<Transaction>) -> Hash {
        let request = provision_request(&ShardTrie::uniform(1), tx, LOCAL, WeightedTimestamp::ZERO)
            .expect("the transaction owes the remote shard");
        served_leaf(&request, &served_keys(&Empty, &request))
    }

    #[test]
    fn an_empty_block_owes_no_root() {
        assert_eq!(roots(&[]).map(|map| map.is_empty()), Ok(true));
    }

    #[test]
    fn a_single_shard_transaction_owes_no_root() {
        let tx = routed(1, &[test_prefix(0x01)]);
        assert_eq!(roots(&[tx]).map(|map| map.is_empty()), Ok(true));
    }

    /// Each target's root holds one leaf per transaction owed to it, in
    /// block order, and the block's own shard holds none.
    #[test]
    fn a_target_root_holds_its_transactions_in_block_order() {
        let (a, b) = (
            routed(1, &[test_prefix(0x01), test_prefix(0x81)]),
            routed(2, &[test_prefix(0x01), test_prefix(0x81)]),
        );
        let map = roots(&[a.clone(), b.clone()]).expect("both are routed");
        assert_eq!(map.keys().copied().collect::<Vec<_>>(), vec![REMOTE]);
        assert_eq!(
            map[&REMOTE],
            ProvisionTxRoot::over(&[leaf_of(&a), leaf_of(&b)]),
        );
    }

    /// A transaction this node has not derived leaves it no root to
    /// state, rather than one over the rest of the block.
    #[test]
    fn an_unrouted_transaction_refuses_the_roots() {
        let routed = routed(1, &[test_prefix(0x01), test_prefix(0x81)]);
        let unrouted = Verifiable::from(Transaction::new(routed.as_unverified().body().clone()));
        assert_eq!(
            roots(&[routed, unrouted.clone()]),
            Err(Unrouted {
                tx_hash: unrouted.hash()
            }),
        );
    }
}
