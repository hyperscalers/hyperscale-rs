//! A part that serves other keys than its source committed: one that
//! omits an entry of a declared interval, shifts a capped interval past
//! an omitted entry, drops a declared cell, adds a key, or is stripped
//! to nothing.
//!
//! Each forgery carries a proof of exactly what it carries, so its own
//! proof check passes it. Its leaf binds the keys it carries, and the
//! source header's root binds the keys its served keys give, so the leaf
//! check a receiver runs on every part refuses it.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_provisions::{build_provisions, leaves_over_requests};
use hyperscale_storage::test_helpers::{entry_key, state_key};
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateStore, Substates};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    Anchor, BlockHeight, DeclaredRange, Hash, MerkleInclusionProof, ProtocolHasher, Provision,
    ProvisionContext, ProvisionParts, ProvisionTxRoot, SettledWrites, ShardId, SubstateEntry,
    SubstateKey, TxHash, Verify, WeightedTimestamp, entry_leaf_key,
};

/// The owner of the declared collection.
const OWNER_SEED: u8 = 7;
/// The owner of the declared cell, and of the one a forger adds.
const CELL_OWNER_SEED: u8 = 9;

const SOURCE: ShardId = ShardId::ROOT;
const TARGET: ShardId = ShardId::leaf(1, 1);

/// A source holding the collection `{5, 10, 20}`, the declared cell and
/// one more, a transaction reading the cell and the whole collection up
/// to `cap`, and the root its header commits for the target.
struct Source {
    chain: Arc<PendingChain<SimShardStorage>>,
    anchor: Anchor,
    request: ProvisionsRequest,
    root: ProvisionTxRoot,
}

impl Source {
    fn new(cap: u32) -> Self {
        let storage = SimShardStorage::default();
        let seeded = SettledWrites::from_parts(
            BTreeMap::from([
                (state_key(CELL_OWNER_SEED, 1), Some(vec![1])),
                (state_key(CELL_OWNER_SEED, 2), Some(vec![2])),
            ]),
            [5u128, 10, 20]
                .into_iter()
                .map(|order| {
                    (
                        entry_key(OWNER_SEED, order),
                        Some(vec![u8::try_from(order).expect("a small order")]),
                    )
                })
                .collect(),
        );
        storage.install_genesis(&seeded, &seeded);
        let anchor = Anchor {
            shard: SOURCE,
            height: BlockHeight::GENESIS,
            state_root: SubstateStore::state_root(&storage),
            ts: WeightedTimestamp::from_millis(0),
        };
        let probe = entry_key(OWNER_SEED, 5);
        let request = ProvisionsRequest {
            tx_hash: TxHash::from(Hash::from_bytes(b"range-tx")),
            targets: vec![TARGET],
            local_keys: vec![state_key(CELL_OWNER_SEED, 1)],
            local_ranges: vec![DeclaredRange {
                owner: probe.owner,
                collection: probe.collection,
                lo: 0,
                hi: u128::MAX,
                cap,
            }],
        };
        let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
        let view = chain.view_at_persisted_tip();
        let state = view.served_snapshot().expect("genesis is held");
        let leaves = leaves_over_requests(&state, std::slice::from_ref(&request))
            .remove(&TARGET)
            .expect("the transaction owes the target");
        Self {
            chain,
            anchor,
            request,
            root: ProvisionTxRoot::over(&leaves),
        }
    }

    /// The part the source builds.
    fn honest(&self) -> Provision {
        let [part] = build_provisions(
            &self.chain.view_at_persisted_tip(),
            SOURCE,
            TARGET,
            self.anchor.ts,
            std::slice::from_ref(&self.request),
            |_| true,
        )
        .try_into()
        .expect("one transaction builds one part");
        part
    }

    /// The honest part with its keys replaced by `keys`, each carrying
    /// the value the source holds, under a fresh proof of exactly them.
    fn forged(&self, keys: &[SubstateKey]) -> Provision {
        let honest = self.honest();
        let view = self.chain.view_at_persisted_tip();
        let state = view.served_snapshot().expect("genesis is held");
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        let entries: Vec<SubstateEntry> = keys
            .iter()
            .map(|key| {
                SubstateEntry::new(
                    *key,
                    state
                        .cell(*key)
                        .map(|value| Bytes::new(value).expect("a small value")),
                )
            })
            .collect();
        let proof = if keys.is_empty() {
            MerkleInclusionProof::new(Vec::new())
        } else {
            generate_proof(&*view, &keys, BlockHeight::GENESIS).expect("the proof builds")
        };
        Provision::new(ProvisionParts {
            source_shard: honest.source_shard(),
            target_shard: honest.target_shard(),
            block_height: honest.block_height(),
            source_block_ts: honest.source_block_ts(),
            tx_hash: honest.tx_hash(),
            entries: Capped::new(entries).expect("within the cap"),
            proof,
            leaf: honest.leaf().clone(),
        })
    }

    /// The keys the honest part carries.
    fn honest_keys(&self) -> Vec<SubstateKey> {
        self.honest()
            .entries()
            .iter()
            .map(|entry| entry.key)
            .collect()
    }

    /// Whether a receiver's leaf check admits `part` under the header's
    /// root.
    fn walks_to_the_root(&self, part: &Provision) -> bool {
        ProvisionTxRoot::through(part.leaf_hash(), part.leaf()) == Some(self.root)
    }

    /// The honest part is admitted. The forgery proves what it carries,
    /// so only its leaf stands between it and admission, and is refused.
    fn assert_refused(&self, forged: &Provision) {
        let ctx = ProvisionContext {
            anchor: self.anchor,
        };
        let honest = self.honest();
        honest
            .verify(&ctx)
            .expect("the honest part proves its entries");
        assert!(self.walks_to_the_root(&honest), "the honest part is owed");

        assert_ne!(forged.hash(), honest.hash());
        forged
            .verify(&ctx)
            .expect("the forgery proves exactly what it carries");
        assert!(
            !self.walks_to_the_root(forged),
            "the forgery's leaf does not walk to the header's root",
        );
    }
}

/// The leaf key of `order` in the declared collection.
fn entry_leaf(order: u128) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, entry_key(OWNER_SEED, order))
}

#[test]
fn a_part_omitting_an_interval_entry_is_refused() {
    let source = Source::new(u32::MAX);
    let keys: Vec<SubstateKey> = source
        .honest_keys()
        .into_iter()
        .filter(|key| *key != entry_leaf(10))
        .collect();
    assert_eq!(keys.len(), 3, "the cell and two of the three entries");
    source.assert_refused(&source.forged(&keys));
}

#[test]
fn a_capped_interval_shifted_past_an_omitted_entry_is_refused() {
    // Cap 2: the honest part serves the two lowest orders. A forger drops
    // 10 and serves 20 in its place, still within the cap.
    let source = Source::new(2);
    let mut honest = source.honest_keys();
    assert!(honest.contains(&entry_leaf(10)));
    assert!(!honest.contains(&entry_leaf(20)));
    honest.retain(|key| *key != entry_leaf(10));
    honest.push(entry_leaf(20));
    source.assert_refused(&source.forged(&honest));
}

#[test]
fn a_part_dropping_a_declared_cell_is_refused() {
    let source = Source::new(u32::MAX);
    let keys: Vec<SubstateKey> = source
        .honest_keys()
        .into_iter()
        .filter(|key| *key != state_key(CELL_OWNER_SEED, 1))
        .collect();
    source.assert_refused(&source.forged(&keys));
}

#[test]
fn a_part_adding_an_undeclared_key_is_refused() {
    let source = Source::new(u32::MAX);
    let mut keys = source.honest_keys();
    keys.push(state_key(CELL_OWNER_SEED, 2));
    source.assert_refused(&source.forged(&keys));
}

#[test]
fn a_part_stripped_to_empty_is_refused() {
    let source = Source::new(u32::MAX);
    source.assert_refused(&source.forged(&[]));
}
