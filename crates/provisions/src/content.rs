//! What a source block's header commits to each target: one leaf per
//! transaction the request rule owes it, in block order.

use std::collections::BTreeMap;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_types::{
    Hash, ProvisionTxRoot, ProvisionTxRootsMap, ShardId, ShardTrie, Transaction, TxHash,
    Verifiable, provision_leaf,
};
use thiserror::Error;

use crate::requests::provision_request;

/// A block transaction this node has not derived, so cannot route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("transaction {tx_hash} is not routed here")]
pub struct Unrouted {
    /// The transaction.
    pub tx_hash: TxHash,
}

/// The leaves each target's root holds over `requests`, in request
/// order. A target no request names holds none.
#[must_use]
pub fn leaves_over_requests(requests: &[ProvisionsRequest]) -> BTreeMap<ShardId, Vec<Hash>> {
    let mut leaves: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();
    for request in requests {
        for target in &request.targets {
            leaves
                .entry(*target)
                .or_default()
                .push(provision_leaf(request.tx_hash));
        }
    }
    leaves
}

/// The per-target provision roots of a block `local_shard` holds with
/// `transactions`, routed under `trie`: one entry for each target owed
/// at least one leaf.
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
    trie: &ShardTrie,
    local_shard: ShardId,
    transactions: &[Verifiable<Transaction>],
) -> Result<ProvisionTxRootsMap, Unrouted> {
    let mut requests = Vec::new();
    for tx in transactions {
        if !tx.as_unverified().is_routed() {
            return Err(Unrouted { tx_hash: tx.hash() });
        }
        requests.extend(provision_request(trie, tx, local_shard));
    }
    Ok(Capped::new(
        leaves_over_requests(&requests)
            .into_iter()
            .map(|(target, leaves)| (target, ProvisionTxRoot::over(&leaves)))
            .collect(),
    )
    .expect("a block owes one entry per other shard"))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Address;
    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, test_prefix, test_transaction_with_prefixes,
    };

    use super::*;

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const REMOTE: ShardId = ShardId::leaf(1, 1);

    /// A routed transaction paid from `seed` on this shard and writing
    /// under `prefixes`.
    fn routed(seed: u8, prefixes: &[Address]) -> Verifiable<Transaction> {
        install_stub_protocol_statics();
        Verifiable::from(test_transaction_with_prefixes(&[seed], &[], prefixes))
    }

    fn roots(transactions: &[Verifiable<Transaction>]) -> Result<ProvisionTxRootsMap, Unrouted> {
        provision_tx_roots(&ShardTrie::uniform(1), LOCAL, transactions)
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
            ProvisionTxRoot::over(&[provision_leaf(a.hash()), provision_leaf(b.hash())]),
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
