//! What a source block owes each target: the keys each transaction's
//! part serves, and the leaves its header commits, one per transaction
//! the request rule owes the target, in block order, each binding the
//! transaction to the keys its part serves.

use std::collections::BTreeMap;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_storage::Substates;
use hyperscale_types::{
    BlockHeight, EntryKey, Hash, ProtocolHasher, ProvisionTxRoot, ProvisionTxRootsMap, ShardId,
    ShardTrie, SubstateKey, Transaction, TxHash, Verifiable, WeightedTimestamp, entry_leaf_key,
    provision_leaf, range_lift, served_digest,
};
use thiserror::Error;

use crate::requests::block_requests;

/// The keys `request`'s part serves out of `state`, the state the
/// source block left.
///
/// Every declared local cell, and the leaf of each of the lowest
/// [`range_lift`] entries a declared local range holds in `state` — one
/// past its cap, which is the successor a reader's coverage answer
/// turns on; ascending, one copy each. The one function that decides a
/// part's keys. Cells cost no read: a part's proof binds their presence
/// and values. Only ranges read state.
#[must_use]
pub fn served_keys(state: &impl Substates, request: &ProvisionsRequest) -> Vec<SubstateKey> {
    let mut keys = request.local_keys.clone();
    for range in &request.local_ranges {
        let held = state.entries_in_range(
            range.owner,
            range.collection,
            range.lo,
            range.hi,
            range_lift(range.lo, range.hi, range.cap),
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

/// The per-target provision roots of a block over its
/// [`block_requests`]: one entry for each target owed at least one leaf.
///
/// The block stands at `height` on `local_shard` with `transactions`,
/// routed under `trie` and committed at `clock`, its parent-QC weighted
/// timestamp; `state` is the state it leaves. Each leaf binds the clock
/// of the block that committed its transaction: `clock` for the block's
/// own, and its row's `committed` for a member the block makes head.
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
    height: BlockHeight,
    clock: WeightedTimestamp,
    transactions: &[Verifiable<Transaction>],
) -> Result<ProvisionTxRootsMap, Unrouted> {
    if let Some(tx) = transactions
        .iter()
        .find(|tx| !tx.as_unverified().is_routed())
    {
        return Err(Unrouted { tx_hash: tx.hash() });
    }
    let requests = block_requests(state, trie, local_shard, height, clock, transactions);
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
    use hyperscale_core::ProvisionsRequest;
    use hyperscale_engine::tick_select::terms_of;
    use hyperscale_storage::test_helpers::{headed_at, pending_row, serving_entries};
    use hyperscale_storage::{Head, MemberRow, pinned_holds};
    use hyperscale_types::test_utils::{
        TestCommittee, install_stub_protocol_statics, leg_shape, test_prefix, test_principal,
        test_transaction_with_prefixes,
    };
    use hyperscale_types::{
        Address, AddressClass, CollectionId, DeclaredRange, LegRole, MemberTerms, Mode,
        TopologySnapshot,
    };

    use super::*;
    use crate::provision_request;
    use crate::test_fixtures::{CREDIT, Entries, WRITE, cell, shaped};

    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const REMOTE: ShardId = ShardId::leaf(1, 1);
    const HEIGHT: BlockHeight = BlockHeight::new(5);

    /// A routed transaction paid from `seed` on this shard and writing
    /// under `prefixes`.
    fn routed(seed: u8, prefixes: &[Address]) -> Verifiable<Transaction> {
        install_stub_protocol_statics();
        Verifiable::from(test_transaction_with_prefixes(&[seed], &[], prefixes))
    }

    fn ms(millis: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(millis)
    }

    /// The roots of the block at [`HEIGHT`] on `local` under `trie`
    /// committing `transactions` at `clock` over `state`.
    fn roots_on(
        state: &Entries,
        trie: &ShardTrie,
        local: ShardId,
        clock: WeightedTimestamp,
        transactions: &[Verifiable<Transaction>],
    ) -> Result<ProvisionTxRootsMap, Unrouted> {
        provision_tx_roots(state, trie, local, HEIGHT, clock, transactions)
    }

    fn roots(transactions: &[Verifiable<Transaction>]) -> Result<ProvisionTxRootsMap, Unrouted> {
        roots_on(
            &Entries::empty(),
            &ShardTrie::uniform(1),
            LOCAL,
            WeightedTimestamp::ZERO,
            transactions,
        )
    }

    /// The leaf `request`'s part sits at, its cells all it serves.
    fn leaf(request: &ProvisionsRequest) -> Hash {
        served_leaf(request, &served_keys(&Entries::empty(), request))
    }

    /// The leaf `tx`'s part to [`REMOTE`] sits at, committed at `clock`.
    fn leaf_of(tx: &Verifiable<Transaction>, clock: WeightedTimestamp) -> Hash {
        leaf(
            &provision_request(&ShardTrie::uniform(1), tx, LOCAL, clock)
                .expect("the transaction owes the remote shard"),
        )
    }

    /// The leaf `row`'s part sits at, served from its head: its served
    /// keys at the clock that committed it.
    fn row_leaf(row: &MemberRow, local: ShardId) -> Hash {
        let declared = pinned_holds(row);
        let mut keys: Vec<SubstateKey> = declared
            .iter()
            .filter(|(_, mode)| matches!(mode, Mode::Read | Mode::Write { .. }))
            .filter_map(|(key, _)| key.cell())
            .filter(|key| ShardTrie::shard_owns_prefix(local, key.owner))
            .collect();
        keys.sort_unstable();
        provision_leaf(row.tx, row.committed, served_digest(keys.into_iter()))
    }

    /// A window of `count` shards.
    fn window(count: u64) -> TopologySnapshot {
        TestCommittee::new(4, 1).topology_snapshot(count)
    }

    /// `tx`'s row on `local`, committed by the block at `height` at
    /// `committed` on its terms under `window`, and made head by the
    /// block at [`HEIGHT`] at `clock`.
    fn headed(
        tx: &Verifiable<Transaction>,
        window: &TopologySnapshot,
        local: ShardId,
        committed: (BlockHeight, WeightedTimestamp),
        clock: WeightedTimestamp,
    ) -> MemberRow {
        let terms: MemberTerms = terms_of(tx, window, local);
        headed_at(
            pending_row(tx.hash(), committed.0, committed.1, &terms),
            HEIGHT,
            clock,
        )
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
        let declared = [
            (cell(test_prefix(0x01), 1), CREDIT),
            (cell(test_prefix(0x81), 1), WRITE),
        ];
        let (a, b) = (
            shaped(test_principal(0x01), &declared, Vec::new()),
            shaped(test_principal(0x02), &declared, Vec::new()),
        );
        let map = roots(&[a.clone(), b.clone()]).expect("both are routed");
        assert_eq!(map.keys().copied().collect::<Vec<_>>(), vec![REMOTE]);
        assert_eq!(
            map[&REMOTE],
            ProvisionTxRoot::over(&[leaf_of(&a, ms(0)), leaf_of(&b, ms(0))]),
        );
    }

    /// A member that shares its verdict and is keyed here is not served
    /// by the block committing it while it is not head: no target it
    /// shares that verdict with is rooted there.
    #[test]
    fn a_keyed_shared_transaction_is_not_rooted_before_its_head() {
        let tx = shaped(
            test_principal(0x01),
            &[
                (cell(test_prefix(0x01), 1), WRITE),
                (cell(test_prefix(0x81), 1), WRITE),
            ],
            Vec::new(),
        );
        assert_eq!(roots(&[tx]).map(|map| map.is_empty()), Ok(true));
    }

    /// A shared member keyed nowhere here, folded by the real fold, heads
    /// in the block committing it and roots no `Serves` entry: it is
    /// served once, by that block's commit.
    #[test]
    fn an_unkeyed_shared_row_heads_without_a_serve_and_is_served_at_commit() {
        use std::collections::BTreeMap;

        use hyperscale_storage::{
            MemberIndex, MemberInputs, MemberSections, member_writes, served_rows,
        };
        use hyperscale_types::{EpochWindows, SettledWrites, Settlement, StatedTerms};

        let window = window(2);
        let tx = shaped(
            test_principal(0x01),
            &[
                (cell(test_prefix(0x01), 1), CREDIT),
                (cell(test_prefix(0x81), 1), WRITE),
            ],
            Vec::new(),
        );
        let terms = terms_of(&tx, &window, LOCAL);
        assert_eq!(terms.settlement, Settlement::Shared);
        let inputs = MemberInputs::deriving(
            LOCAL,
            HEIGHT,
            ms(5_000),
            [tx.as_unverified()],
            MemberSections {
                certificates: &[],
                records: &[],
                claims: &[],
            },
            EpochWindows::new(0, 0),
            vec![StatedTerms {
                tx: tx.hash(),
                terms,
            }],
        );
        let state = Entries::of(&SettledWrites::from_parts(
            BTreeMap::new(),
            member_writes(&Entries::empty(), &inputs),
        ));

        let rows = MemberIndex::load(&state, LOCAL);
        assert!(
            rows.members[&tx.hash()].head.is_some(),
            "nothing ahead of it on its keys"
        );
        assert!(
            served_rows(&state, LOCAL, HEIGHT).is_empty(),
            "an unkeyed row roots no serve from its head"
        );
        let map = roots_on(
            &state,
            window.shard_trie(),
            LOCAL,
            ms(5_000),
            std::slice::from_ref(&tx),
        )
        .expect("routed");
        assert_eq!(
            map[&REMOTE],
            ProvisionTxRoot::over(&[leaf_of(&tx, ms(5_000))]),
            "the commit serves it"
        );
    }

    /// A block roots its own transactions' requests in block order and
    /// then the rows it makes head, in rank order; a row made head by
    /// another block is not rooted here. Each row's leaf binds the clock
    /// that committed it.
    #[test]
    fn a_block_roots_its_own_requests_then_the_rows_it_makes_head() {
        let window = window(2);
        let keyed = |payer: u8| {
            shaped(
                test_principal(payer),
                &[
                    (cell(test_prefix(0x01), payer), WRITE),
                    (cell(test_prefix(0x81), payer), WRITE),
                ],
                Vec::new(),
            )
        };
        let (first, second, earlier) = (keyed(0x03), keyed(0x04), keyed(0x05));
        let rows = [
            headed(
                &first,
                &window,
                LOCAL,
                (BlockHeight::new(2), ms(2_000)),
                ms(5_000),
            ),
            headed(
                &second,
                &window,
                LOCAL,
                (BlockHeight::new(3), ms(3_000)),
                ms(5_000),
            ),
        ];
        let mut ranked = rows.to_vec();
        ranked.sort_by_key(|row| row.head.expect("head").rank);
        let mut made_head_before = headed(
            &earlier,
            &window,
            LOCAL,
            (BlockHeight::new(2), ms(2_000)),
            ms(4_000),
        );
        made_head_before.head = made_head_before.head.map(|head| Head {
            height: BlockHeight::new(4),
            ..head
        });
        let mut standing = rows.to_vec();
        standing.push(made_head_before);
        let state = Entries::of(&serving_entries(LOCAL, &standing));

        let declared = [
            (cell(test_prefix(0x01), 9), CREDIT),
            (cell(test_prefix(0x81), 9), WRITE),
        ];
        let own = shaped(test_principal(0x02), &declared, Vec::new());
        let map = roots_on(
            &state,
            window.shard_trie(),
            LOCAL,
            ms(5_000),
            std::slice::from_ref(&own),
        )
        .expect("routed");
        let mut leaves = vec![leaf_of(&own, ms(5_000))];
        leaves.extend(ranked.iter().map(|row| row_leaf(row, LOCAL)));
        assert_eq!(map.keys().copied().collect::<Vec<_>>(), vec![REMOTE]);
        assert_eq!(map[&REMOTE], ProvisionTxRoot::over(&leaves));
    }

    /// A divided transaction with a core here, a core sibling and a leg
    /// on the payer's shard: on the core shard here.
    fn divided() -> (Verifiable<Transaction>, ShardId, ShardId, ShardId) {
        let (here, sibling, payer) = (0x01, 0x41, 0x81);
        let tx = shaped(
            test_principal(payer),
            &[
                (cell(test_prefix(here), 1), WRITE),
                (cell(test_prefix(sibling), 1), WRITE),
            ],
            vec![
                leg_shape(test_principal(payer).address(), LegRole::Inbound, &[]),
                leg_shape(test_prefix(here), LegRole::Core, &[(0, 0)]),
                leg_shape(test_prefix(sibling), LegRole::Core, &[(0, 1)]),
            ],
        );
        let trie = ShardTrie::uniform(2);
        (
            tx,
            trie.shard_for_prefix(test_prefix(here)),
            trie.shard_for_prefix(test_prefix(sibling)),
            trie.shard_for_prefix(test_principal(payer).address()),
        )
    }

    /// A core member's part to a leg's shard is rooted by the block
    /// committing it, since the leg shares no verdict with the core and
    /// the core waits on the leg's record; its core sibling's is not.
    #[test]
    fn a_core_part_to_a_legs_shard_is_rooted_at_commit() {
        let (tx, here, sibling, leg) = divided();
        let map = roots_on(
            &Entries::empty(),
            &ShardTrie::uniform(2),
            here,
            ms(2_000),
            std::slice::from_ref(&tx),
        )
        .expect("routed");
        assert!(
            map.contains_key(&leg),
            "the leg's shard is served at commit"
        );
        assert!(
            !map.contains_key(&sibling),
            "the sibling is served from head"
        );
    }

    /// Across the block committing a member and the block making it
    /// head, every target's roots hold one leaf for it: the leg's shard
    /// at commit, the core sibling at head, both at the committing clock.
    #[test]
    fn each_target_roots_one_leaf_per_transaction() {
        let (tx, here, sibling, leg) = divided();
        let window = window(4);
        let trie = window.shard_trie();
        let at_commit = roots_on(
            &Entries::empty(),
            trie,
            here,
            ms(2_000),
            std::slice::from_ref(&tx),
        )
        .expect("routed");
        let row = headed(
            &tx,
            &window,
            here,
            (BlockHeight::new(2), ms(2_000)),
            ms(5_000),
        );
        let at_head = roots_on(
            &Entries::of(&serving_entries(here, std::slice::from_ref(&row))),
            trie,
            here,
            ms(5_000),
            &[],
        )
        .expect("routed");
        let commit_request = provision_request(trie, &tx, here, ms(2_000)).expect("owes the leg");
        assert_eq!(commit_request.targets, vec![leg]);
        assert_eq!(
            at_commit.get(&leg),
            Some(&ProvisionTxRoot::over(&[leaf(&commit_request)])),
        );
        assert_eq!(
            at_head.get(&sibling),
            Some(&ProvisionTxRoot::over(&[row_leaf(&row, here)])),
        );
        assert!(!at_commit.contains_key(&sibling) && !at_head.contains_key(&leg));
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

    const OWNER: Address = Address::new([0x11; 31], AddressClass::Component);
    const COLLECTION: CollectionId = CollectionId([4; 16]);

    /// One collection holding an entry at each of `orders`.
    struct Holding(Vec<u128>);

    impl Substates for Holding {
        fn cell(&self, _: SubstateKey) -> Option<Vec<u8>> {
            None
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            if owner != OWNER || collection != COLLECTION {
                return Vec::new();
            }
            self.0
                .iter()
                .copied()
                .filter(|order| (lo..=hi).contains(order))
                .take(limit)
                .map(|order| (order, vec![1]))
                .collect()
        }
    }

    /// The orders whose leaves a part declaring `[lo, hi]` at `cap` over
    /// `held` serves, ascending.
    fn served_orders(held: &[u128], lo: u128, hi: u128, cap: u32) -> Vec<SubstateKey> {
        let request = ProvisionsRequest {
            tx_hash: TxHash::from(Hash::from_bytes(b"ranged")),
            targets: vec![REMOTE],
            local_keys: Vec::new(),
            local_ranges: vec![DeclaredRange {
                owner: OWNER,
                collection: COLLECTION,
                lo,
                hi,
                cap,
            }],
            clock: WeightedTimestamp::ZERO,
        };
        served_keys(&Holding(held.to_vec()), &request)
    }

    /// The leaves of `orders`, ascending as a part serves them.
    fn leaves(orders: &[u128]) -> Vec<SubstateKey> {
        let mut keys: Vec<SubstateKey> = orders
            .iter()
            .map(|order| {
                entry_leaf_key(
                    &ProtocolHasher,
                    EntryKey {
                        owner: OWNER,
                        collection: COLLECTION,
                        order: *order,
                    },
                )
            })
            .collect();
        keys.sort_unstable();
        keys
    }

    /// A range holding more than its cap serves the entry past it, so a
    /// counterpart reads the same successor the source's page does.
    #[test]
    fn a_full_range_serves_the_entry_past_its_cap() {
        let held = [10, 20, 30, 40, 50];
        assert_eq!(
            served_orders(&held, 0, u128::MAX, 3),
            leaves(&[10, 20, 30, 40])
        );
    }

    /// A range holding no more than its cap serves what it holds.
    #[test]
    fn a_short_range_serves_what_it_holds() {
        let held = [10, 20];
        assert_eq!(served_orders(&held, 0, u128::MAX, 3), leaves(&[10, 20]));
    }

    /// An entry is its width-one interval: it serves itself and no
    /// neighbour past it.
    #[test]
    fn an_entry_serves_no_successor() {
        let held = [10, 11, 12];
        assert_eq!(served_orders(&held, 11, 11, 1), leaves(&[11]));
    }
}
