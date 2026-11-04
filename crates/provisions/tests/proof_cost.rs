//! What isolation costs a source in bytes: one block of 4,096 transfers
//! to one target, over a store of 2^20 leaves, provisioned once as one
//! bundle under one multiproof and once as one part per transaction.
//!
//! The bundle is the shape a source shipped before parts: one
//! `Provisions` per target block, its entries grouped by transaction
//! under a single proof over every key, gossiped in one notification
//! and carried inline by block sync as one row. It is rebuilt here from
//! the same proof builder over the same store, and encoded through
//! mirrors of its wire structs. The parts come from the production
//! builder.
//!
//! A part's proof stops sharing upper siblings with its neighbours: at
//! these sizes about 20 siblings per key against about 7 under the
//! shared proof, and a leaf path into the target's root besides. The
//! bound accepted for that is at most 3× the bundle's gossiped bytes,
//! and 3.1× its inline sync bytes.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::{Bytes, Hbor};
use hyperscale_jmt::MultiProof;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::tree::proofs::generate_proof;
use hyperscale_storage::{GenesisCommit, PendingChain, SubstateView, Substates};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::network::encoded_len;
use hyperscale_types::network::notification::ProvisionsNotification;
use hyperscale_types::{
    Address, AddressClass, BlockHeight, ConsensusSignature, Hash, LeafPath, LocalKey,
    MerkleInclusionProof, Provision, ProvisionHash, SettledWrites, ShardId, SubstateEntry,
    SubstateKey, TxHash, ValidatorId, Verifiable, WeightedTimestamp,
};

/// Leaves in the source's tree.
const LEAVES: u32 = 1 << 20;
/// Transfers in the source block, each reading one cell, all owed to
/// one target: a full block.
const TRANSFERS: u32 = 4_096;
/// Raw value bytes per cell, the order of a vault balance.
const VALUE_BYTES: usize = 32;

/// The accepted price of isolation in gossiped bytes.
const GOSSIP_BOUND: f64 = 3.0;
/// The accepted price of isolation in inline sync bytes.
const SYNC_BOUND: f64 = 3.1; // the per-row ProvisionHash takes sync past the gossip ratio

const SOURCE: ShardId = ShardId::ROOT;
const TARGET: ShardId = ShardId::leaf(1, 1);

/// The bundle's wire shape: one source block's entries for one target,
/// under one proof.
#[derive(Clone, Hbor)]
struct BundleWire {
    source_shard: ShardId,
    target_shard: ShardId,
    block_height: BlockHeight,
    source_block_ts: WeightedTimestamp,
    proof: MerkleInclusionProof,
    transactions: Vec<BundleEntryWire>,
}

/// One transaction's entries within a bundle.
#[derive(Clone, Hbor)]
struct BundleEntryWire {
    tx_hash: TxHash,
    entries: Vec<SubstateEntry>,
}

/// The bundle's gossip notification.
#[derive(Hbor)]
struct BundleNotificationWire {
    provisions: BundleWire,
    sender: ValidatorId,
    sender_signature: ConsensusSignature,
}

/// A part's wire shape, mirrored the way the bundle's is, so the mirror
/// is checked against a type that still exists.
#[derive(Hbor)]
struct PartWire {
    source_shard: ShardId,
    target_shard: ShardId,
    block_height: BlockHeight,
    source_block_ts: WeightedTimestamp,
    tx_hash: TxHash,
    entries: Vec<SubstateEntry>,
    proof: MerkleInclusionProof,
    leaf: LeafPath,
}

/// The `index`th cell of the source, under an owner spread over the key
/// space as hashed addresses are.
fn cell(index: u32) -> SubstateKey {
    let digest = Hash::from_bytes(&index.to_be_bytes());
    let mut body = [0u8; 31];
    body.copy_from_slice(&digest.as_bytes()[..31]);
    SubstateKey {
        owner: Address::new(body, AddressClass::Principal),
        local: LocalKey([0u8; 16]),
    }
}

/// The value the `index`th cell holds.
fn value(index: u32) -> Vec<u8> {
    let mut value = vec![0u8; VALUE_BYTES];
    value[..4].copy_from_slice(&index.to_be_bytes());
    value
}

/// The siblings and the claims a proof carries.
fn proof_shape(proof: &MerkleInclusionProof) -> (usize, usize) {
    let proof = MultiProof::decode(proof.as_bytes()).expect("a built proof decodes");
    (proof.siblings.len(), proof.claims.len())
}

/// `over` divided by `under`, both counts this test keeps well inside a
/// `u32`.
fn ratio(over: usize, under: usize) -> f64 {
    let exact = |count: usize| f64::from(u32::try_from(count).expect("a count inside a u32"));
    exact(over) / exact(under)
}

/// A source of [`LEAVES`] cells at genesis, viewed as its proposer reads
/// it, and one request per transfer, each reading one cell: every 256th,
/// so the block reads across the whole tree.
fn source() -> (Arc<SubstateView<SimShardStorage>>, Vec<ProvisionsRequest>) {
    let storage = SimShardStorage::default();
    let cells: BTreeMap<SubstateKey, Option<Vec<u8>>> =
        (0..LEAVES).map(|i| (cell(i), Some(value(i)))).collect();
    let seeded = SettledWrites::from_parts(cells, BTreeMap::new());
    storage.install_genesis(&seeded, &seeded);
    let stride = LEAVES / TRANSFERS;
    let requests = (0..TRANSFERS)
        .map(|t| ProvisionsRequest {
            tx_hash: TxHash::from(Hash::from_bytes(&t.to_be_bytes())),
            targets: vec![TARGET],
            local_keys: vec![cell(t * stride)],
            local_ranges: vec![],
        })
        .collect();
    let chain = Arc::new(PendingChain::new(Arc::new(storage), BlockHeight::GENESIS));
    (chain.view_at_persisted_tip(), requests)
}

/// The bundle a source built for `requests`: every transaction's
/// entries, and one proof over all their keys.
fn bundle(
    view: &SubstateView<SimShardStorage>,
    requests: &[ProvisionsRequest],
    ts: WeightedTimestamp,
) -> BundleWire {
    let state = view.served_snapshot().expect("genesis is held");
    let mut keys = Vec::new();
    let transactions = requests
        .iter()
        .map(|request| BundleEntryWire {
            tx_hash: request.tx_hash,
            entries: request
                .local_keys
                .iter()
                .map(|&key| {
                    keys.push(key);
                    let value = state.cell(key).expect("every read cell is held");
                    SubstateEntry::new(key, Some(Bytes::new(value).expect("a small value")))
                })
                .collect(),
        })
        .collect();
    BundleWire {
        source_shard: SOURCE,
        target_shard: TARGET,
        block_height: BlockHeight::GENESIS,
        source_block_ts: ts,
        proof: generate_proof(view, &keys, BlockHeight::GENESIS).expect("the bundle proof builds"),
        transactions,
    }
}

/// `part` through the mirror, so the mirror's encoding can be held to
/// the type's.
fn mirrored(part: &Provision) -> PartWire {
    PartWire {
        source_shard: part.source_shard(),
        target_shard: part.target_shard(),
        block_height: part.block_height(),
        source_block_ts: part.source_block_ts(),
        tx_hash: part.tx_hash(),
        entries: part.entries().to_vec(),
        proof: part.proof().clone(),
        leaf: part.leaf().clone(),
    }
}

#[test]
fn per_part_provisions_cost_at_most_three_times_the_bundle() {
    let (view, requests) = source();
    let ts = WeightedTimestamp::from_millis(0);

    let parts = build_provisions(&view, SOURCE, TARGET, ts, &requests, |_| true);
    assert_eq!(parts.len(), requests.len(), "every transfer builds a part");
    let bundle = bundle(&view, &requests, ts);
    assert_eq!(encoded_len(&mirrored(&parts[0])), encoded_len(&parts[0]));

    let (part_siblings, part_claims) = parts
        .iter()
        .map(|part| proof_shape(part.proof()))
        .fold((0, 0), |(s, c), (ps, pc)| (s + ps, c + pc));
    let (bundle_siblings, bundle_claims) = proof_shape(&bundle.proof);

    // Provision content: the bundle against every part.
    let bundle_bytes = encoded_len(&bundle);
    let part_bytes: usize = parts.iter().map(encoded_len).sum();

    // Gossip: the bundle's one notification against the parts'. Every
    // part fits one notification, so the parts ship as one too.
    let sender = ValidatorId::new(0);
    let signature = ConsensusSignature::new([0x33; 96]);
    let bundle_gossip = encoded_len(&BundleNotificationWire {
        provisions: bundle.clone(),
        sender,
        sender_signature: signature,
    });
    let packed: Vec<Verifiable<Provision>> = parts.into_iter().map(Verifiable::from).collect();
    let parts_gossip = encoded_len(&ProvisionsNotification::new(
        SOURCE,
        TARGET,
        BlockHeight::GENESIS,
        packed
            .clone()
            .try_into()
            .expect("a block's parts fit one notification"),
        sender,
        signature,
    ));

    // Inline sync: a target block naming the source block's provisions
    // carries one row per provision it names, its hash beside its body.
    let bundle_hash = ProvisionHash::from_raw(Hash::from_bytes(b"bundle"));
    let bundle_rows: Vec<(ProvisionHash, Option<BundleWire>)> = vec![(bundle_hash, Some(bundle))];
    let part_rows: Vec<(ProvisionHash, Option<Verifiable<Provision>>)> = packed
        .into_iter()
        .map(|part| (part.as_unverified().hash(), Some(part)))
        .collect();
    let bundle_sync = encoded_len(&bundle_rows);
    let parts_sync = encoded_len(&part_rows);

    let content = ratio(part_bytes, bundle_bytes);
    let gossip = ratio(parts_gossip, bundle_gossip);
    let sync = ratio(parts_sync, bundle_sync);
    println!(
        "siblings per key: parts {:.2}, bundle {:.2}\n\
         content: parts {part_bytes} B, bundle {bundle_bytes} B, {content:.3}x\n\
         gossip:  parts {parts_gossip} B, bundle {bundle_gossip} B, {gossip:.3}x\n\
         sync:    parts {parts_sync} B, bundle {bundle_sync} B, {sync:.3}x",
        ratio(part_siblings, part_claims),
        ratio(bundle_siblings, bundle_claims),
    );
    assert!(
        gossip <= GOSSIP_BOUND,
        "provision bytes {gossip:.3}x the bundle's"
    );
    assert!(
        sync <= SYNC_BOUND,
        "inline sync bytes {sync:.3}x the bundle's"
    );
}
