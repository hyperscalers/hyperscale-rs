//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`,
//! `WaveCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_jmt::TreeReader;
use hyperscale_types::test_utils::test_event_type_identifier;
use hyperscale_types::{
    ApplicationEvent, BeaconBlock, BeaconBlockHash, BeaconCert, BeaconChainConfig, BeaconState,
    BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader,
    BlockHeight, Bls12381G2Signature, BoundedVec, CertificateRoot, CertifiedBeaconBlock,
    CertifiedBlock, ChainOrigin, ConsensusReceipt, Epoch, EventData, ExecutionCertificate,
    ExecutionMetadata, ExecutionOutcome, FeeSummary, FinalizedWave, GlobalReceiptHash,
    GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, LogLevel, NodeId, PcQc2, PcQc3,
    PcSignerLengths, PcVector, PcXpProof, ProposerTimestamp, ProvisionsRoot, QuorumCertificate,
    Randomness, Round, ShardAnchor, ShardId, ShardWitnessPayload, SignerBitfield, SpcCert, SpcView,
    Stake, StakePoolId, StateRoot, StoredReceipt, TransactionRoot, TxHash, TxOutcome, ValidatorId,
    Verifiable, Verified, WaveCertificate, WaveId, WeightedTimestamp, compute_global_receipt_root,
    compute_merkle_root, zero_bls_signature,
};
use indexmap::IndexMap;
use radix_common::math::Decimal;
use radix_common::prelude::DatabaseUpdate;
use radix_common::types::{NodeId as RadixNodeId, PartitionNumber};
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

use crate::tree::Jmt;
use crate::{
    BOUNDARY_RETAIN, BoundaryStore, DatabaseUpdates, DbSortKey, ImportLeaf, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, ResolveLeaf, ShardChainReader, ShardChainWriter, SubstateStore,
};

/// Build a `DatabaseUpdates` containing a single `Set` operation.
#[must_use]
pub fn make_database_update(
    node_key: Vec<u8>,
    partition: u8,
    sort_key: Vec<u8>,
    value: Vec<u8>,
) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        node_key,
        NodeDatabaseUpdates {
            partition_updates: std::iter::once((
                partition,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((
                        DbSortKey(sort_key),
                        DatabaseUpdate::Set(value),
                    ))
                    .collect(),
                },
            ))
            .collect(),
        },
    );
    updates
}

/// A realistic 50-byte `db_node_key` for the logical node `[seed; 30]`, using
/// the same `SpreadPrefixKeyMapper` encoding the engine produces for real
/// substates.
#[must_use]
pub fn db_node_key(seed: u8) -> Vec<u8> {
    SpreadPrefixKeyMapper::to_db_node_key(&RadixNodeId(NodeId([seed; 30]).0))
}

/// Build `DatabaseUpdates` from a logical node seed, using `SpreadPrefixKeyMapper`
/// to compute the correct `db_node_key` — matching the storage format used in production.
///
/// The `NodeId` is `[node_seed; 30]`, consistent with other test helpers.
#[must_use]
pub fn make_mapped_database_update(
    node_seed: u8,
    partition: u8,
    sort_key: Vec<u8>,
    value: Vec<u8>,
) -> DatabaseUpdates {
    let radix_node_id = RadixNodeId(NodeId([node_seed; 30]).0);
    let radix_partition = PartitionNumber(partition);
    let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
    let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
    let db_sort_key = DbSortKey(sort_key);

    let mut updates = DatabaseUpdates::default();
    let node_updates = updates.node_updates.entry(db_node_key).or_default();
    let partition_updates = node_updates
        .partition_updates
        .entry(db_partition_num)
        .or_insert_with(|| PartitionDatabaseUpdates::Delta {
            substate_updates: IndexMap::new(),
        });
    if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
        substate_updates.insert(db_sort_key, DatabaseUpdate::Set(value));
    }
    updates
}

/// Build a test `WaveCertificate` at the given height.
///
/// Includes a single placeholder local EC so the certificate satisfies the
/// invariant enforced at decode time (one EC per wave whose `wave_id` matches
/// `wc.wave_id`).
#[must_use]
pub fn make_test_wave_certificate(height: BlockHeight, shard: ShardId) -> WaveCertificate {
    let wave_id = WaveId::new(shard, height, BTreeSet::new());
    let local_ec = Arc::new(ExecutionCertificate::new(
        wave_id.clone(),
        WeightedTimestamp::from_millis(0),
        GlobalReceiptRoot::ZERO,
        Vec::new(),
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::empty(),
    ));
    WaveCertificate::new(wave_id, vec![local_ec])
}

/// Build a minimal `Block` at the given height.
#[must_use]
pub fn make_test_block(height: BlockHeight) -> Block {
    // Use the full u64 bytes for the parent hash so heights > 255 don't alias.
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    Block::Live {
        header: BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(height.inner() * 1000),
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
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        ),
        transactions: Arc::new(BoundedVec::new()),
        certificates: Arc::new(BoundedVec::new()),
        provisions: Arc::new(BoundedVec::new()),
    }
}

/// Build a verified `QuorumCertificate` that references the given block.
///
/// The signature is the zero placeholder — these fixtures don't drive real
/// verification, they exercise storage and pipeline shapes. The `Verified`
/// wrapper is `new_unchecked` because the test cluster predates a real BLS
/// signing path; consumers downstream of storage and the commit pipeline
/// require the verified marker.
#[must_use]
pub fn make_test_qc(block: &Block) -> Verified<QuorumCertificate> {
    // SAFETY: synthetic test fixture, no real signature.
    Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
        block.hash(),
        ShardId::ROOT,
        block.height(),
        block.header().parent_block_hash(),
        Round::INITIAL,
        SignerBitfield::new(4),
        zero_bls_signature(),
        WeightedTimestamp::from_millis(block.header().timestamp().as_millis()),
    ))
}

/// Build a `Verified<CertifiedBlock>` for use with `commit_block` and the
/// commit-pipeline test fixtures.
///
/// # Panics
///
/// Panics if internal `CertifiedBlock` construction fails — only happens
/// when callers feed a `qc` whose `block_hash` doesn't match `block`, which
/// the helper precludes by construction.
#[must_use]
pub fn make_test_certified(block: Block) -> Arc<Verified<CertifiedBlock>> {
    let qc = make_test_qc(&block);
    let certified = CertifiedBlock::new_unchecked(block, qc);
    // SAFETY: synthetic test fixture; storage round-trip tests don't
    // exercise the `Verified<CertifiedBlock>` predicate.
    Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
        certified,
    ))
}

/// Build a placeholder [`SpcCert::Direct`] for test fixtures.
///
/// The embedded `PcQc3` is structurally well-formed but doesn't
/// verify; the cert is intended for storage round-trip tests, not
/// consensus verification.
#[must_use]
fn placeholder_cert() -> SpcCert {
    let qc2 = PcQc2::new(
        PcVector::empty(),
        SignerBitfield::new(4),
        Bls12381G2Signature([0x11; 96]),
        PcXpProof::Full,
    );
    let proof = PcQc3::new(
        PcVector::empty(),
        qc2,
        None,
        None,
        SignerBitfield::new(4),
        PcSignerLengths::Uniform(0),
        Bls12381G2Signature([0x33; 96]),
    );
    SpcCert::Direct {
        prev_view: SpcView::new(1),
        value: PcVector::empty(),
        proof: proof.into(),
    }
}

/// Build a certified beacon block at `epoch` with tag-derived
/// `prev_block_hash`.
///
/// The cert is a structurally-valid but cryptographically-unverified
/// placeholder. Suitable for storage round-trip tests, not for
/// consensus verification.
#[must_use]
pub fn make_test_beacon_block(epoch: u64, tag: &[u8]) -> Arc<Verified<CertifiedBeaconBlock>> {
    let block = BeaconBlock::new(
        Epoch::new(epoch),
        BeaconBlockHash::from_raw(Hash::from_bytes(tag)),
        Vec::new(),
    );
    Arc::new(Verified::new_unchecked_for_test(
        CertifiedBeaconBlock::new_unchecked(
            block,
            BeaconCert::Normal(Box::new(placeholder_cert())),
        ),
    ))
}

/// Build a minimal `BeaconState` at `epoch` whose `randomness` is
/// derived from `tag`. All collection fields are empty.
///
/// Sufficient to drive storage round-trip tests — every field is
/// stable across SBOR encoding and two calls with identical inputs
/// produce equal states. Not a valid state under beacon-state
/// verification.
#[must_use]
pub fn make_test_beacon_state(epoch: u64, tag: &[u8]) -> Arc<BeaconState> {
    use std::collections::BTreeMap;
    let mut randomness = [0u8; 32];
    let copy_len = tag.len().min(32);
    randomness[..copy_len].copy_from_slice(&tag[..copy_len]);
    Arc::new(BeaconState {
        chain_config: BeaconChainConfig::default(),
        current_epoch: Epoch::new(epoch),
        validators: BTreeMap::new(),
        pools: BTreeMap::new(),
        randomness: Randomness::new(randomness),
        committee: Vec::new(),
        shard_committees: BTreeMap::new(),
        next_shard_committees: BTreeMap::new(),
        shard_consensus_members: BTreeMap::new(),
        witness_window_bases: BTreeMap::new(),
        split_pending_window: BTreeSet::new(),
        boundaries: BTreeMap::new(),
        pending_reshapes: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    })
}

/// Build a `(block, state)` pair for storage round-trip tests.
///
/// Under the cert-as-authenticator model the block's `state_root` is
/// no longer carried on-chain (it's derived by re-running `apply_epoch`),
/// so this helper just produces a structurally well-formed block paired
/// with an arbitrary state.
#[must_use]
pub fn make_test_block_and_state(
    epoch: u64,
    tag: &[u8],
) -> (Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>) {
    let state = make_test_beacon_state(epoch, tag);
    let block = make_test_beacon_block(epoch, tag);
    (block, state)
}

/// Build a deterministic locally-executed `StoredReceipt` from `seed`
/// — succeeded, with a single application event and a non-empty fee
/// summary so equality checks across seeds distinguish entries.
#[must_use]
pub fn make_test_receipt(seed: u8) -> StoredReceipt {
    let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
    let consensus = ConsensusReceipt::Succeeded {
        receipt_hash: GlobalReceiptHash::ZERO,
        database_updates: DatabaseUpdates::default(),
        owned_nodes: BoundedVec::new(),
        application_events: vec![ApplicationEvent {
            type_id: test_event_type_identifier(seed),
            data: EventData(vec![seed, seed + 1]),
        }],
        beacon_witness_events: Vec::new(),
    };
    let metadata = Some(ExecutionMetadata::new(
        FeeSummary {
            total_execution_cost: Some(Decimal::from(u64::from(seed))),
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        },
        vec![(LogLevel::Info, format!("tx {seed}"))],
        None,
    ));
    StoredReceipt {
        tx_hash,
        consensus: Arc::new(consensus),
        metadata,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Execution Certificate helpers
// ═══════════════════════════════════════════════════════════════════════

/// Build a test `ExecutionCertificate` at the given block height with a
/// deterministic outcome derived from `seed`.
///
/// `seed` also disambiguates the `WaveId` (via `remote_shards`), so two ECs
/// at the same `block_height` with different seeds have distinct identities
/// — matching the protocol invariant that one wave produces one EC.
#[must_use]
pub fn make_test_execution_certificate(
    seed: u8,
    block_height: BlockHeight,
) -> ExecutionCertificate {
    let outcomes = vec![TxOutcome::new(
        TxHash::from_raw(Hash::from_bytes(&[seed + 100; 32])),
        ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 150; 32])),
        },
    )];
    let global_receipt_root = compute_global_receipt_root(&outcomes);
    let mut remote_shards = BTreeSet::new();
    remote_shards.insert(ShardId::leaf(8, u64::from(seed) + 1));
    ExecutionCertificate::new(
        WaveId::new(ShardId::ROOT, block_height, remote_shards),
        WeightedTimestamp::from_millis(block_height.inner() + 1),
        global_receipt_root,
        outcomes,
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::new(4),
    )
}

/// Build a test block that carries ECs inside its wave certificates.
///
/// The wave-certificate's `wave_id` is taken from the first EC's `wave_id` so
/// the local-EC decode invariant is satisfied without injecting a placeholder.
fn make_test_block_with_ecs(height: BlockHeight, ecs: Vec<Arc<ExecutionCertificate>>) -> Block {
    let block = make_test_block(height);
    if ecs.is_empty() {
        return block;
    }
    let certificate = Arc::new(WaveCertificate::new(ecs[0].wave_id().clone(), ecs));
    push_certificate(
        block,
        Arc::new(FinalizedWave::new(certificate, vec![]).into()),
    )
}

/// Append a finalized wave to `block`'s certificate list, preserving
/// the block variant.
fn push_certificate(block: Block, fw: Arc<Verifiable<FinalizedWave>>) -> Block {
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Live {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provisions,
            }
        }
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provision_hashes,
            }
        }
    }
}

/// Helper to commit empty blocks up to (but not including) the target height.
fn commit_empty_blocks_up_to(storage: &impl ShardChainWriter, target: BlockHeight) {
    let witness = empty_witness();
    for h in 0..target.inner() {
        let certified = make_test_certified(make_test_block(BlockHeight::new(h)));
        storage.commit_block(&certified, &witness);
    }
}

/// Commit `updates` at `height` through the production block-commit path.
///
/// The updates ride a single-receipt finalized wave inside a test block,
/// so substates, state history, the JMT, and leaf associations all land
/// exactly as a live commit writes them. Returns the resulting state
/// root.
pub fn commit_block_with_updates(
    storage: &impl ShardChainWriter,
    height: BlockHeight,
    updates: &DatabaseUpdates,
) -> StateRoot {
    let receipt = StoredReceipt {
        tx_hash: TxHash::ZERO,
        consensus: Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            database_updates: updates.clone(),
            owned_nodes: BoundedVec::new(),
            application_events: vec![],
            beacon_witness_events: Vec::new(),
        }),
        metadata: None,
    };
    let certificate = Arc::new(WaveCertificate::new(
        WaveId::new(ShardId::ROOT, height, BTreeSet::new()),
        vec![],
    ));
    let finalized = Arc::new(FinalizedWave::new(certificate, vec![receipt]).into());
    let block = push_certificate(make_test_block(height), finalized);
    storage.commit_block(&make_test_certified(block), &empty_witness())
}

const fn empty_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}

/// Commit a block at `height` whose header commits the beacon-witness
/// accumulator state after appending `leaves`.
///
/// The header carries the leaves' merkle root and cumulative count, and
/// the leaves fold into the same atomic write. Returns the committed
/// block hash.
pub fn commit_block_with_witnesses(
    storage: &impl ShardChainWriter,
    height: BlockHeight,
    leaves: &[ShardWitnessPayload],
) -> BlockHash {
    let leaf_hashes: Vec<Hash> = leaves.iter().map(ShardWitnessPayload::leaf_hash).collect();
    let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes));
    let count = BeaconWitnessLeafCount::new(leaves.len() as u64);
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    let block = Block::Live {
        header: BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(height.inner() * 1000),
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
            root,
            count,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        ),
        transactions: Arc::new(BoundedVec::new()),
        certificates: Arc::new(BoundedVec::new()),
        provisions: Arc::new(BoundedVec::new()),
    };
    let block_hash = block.hash();
    let witness = BeaconWitnessCommit {
        starting_leaf_index: BeaconWitnessLeafCount::ZERO,
        leaves: leaves.to_vec(),
        leaf_count_at_block_end: count,
        prune_persisted_below: None,
    };
    storage.commit_block(&make_test_certified(block), &witness);
    block_hash
}

/// Commit a block at `height` whose header commits the witness window
/// `[base, base + window.len())`.
///
/// The header carries the root over `window`, the cumulative count, and
/// `base` as its window base. The commit appends `appended` (the
/// window's tail at `base + window.len() - appended.len()`) and carries
/// `prune_persisted_below` so backend retention behaviour is
/// observable. Returns the committed block hash.
///
/// # Panics
///
/// Panics if `appended` is longer than `window` — the appended tail
/// must lie inside the committed window.
pub fn commit_block_with_witness_window(
    storage: &impl ShardChainWriter,
    height: BlockHeight,
    base: u64,
    window: &[ShardWitnessPayload],
    appended: &[ShardWitnessPayload],
    prune_persisted_below: Option<BeaconWitnessLeafCount>,
) -> BlockHash {
    assert!(appended.len() <= window.len());
    let leaf_hashes: Vec<Hash> = window.iter().map(ShardWitnessPayload::leaf_hash).collect();
    let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaf_hashes));
    let count = BeaconWitnessLeafCount::new(base + window.len() as u64);
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    let block = Block::Live {
        header: BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(height.inner() * 1000),
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
            root,
            count,
            BeaconWitnessLeafCount::new(base),
            None,
            None,
        ),
        transactions: Arc::new(BoundedVec::new()),
        certificates: Arc::new(BoundedVec::new()),
        provisions: Arc::new(BoundedVec::new()),
    };
    let block_hash = block.hash();
    let witness = BeaconWitnessCommit {
        starting_leaf_index: BeaconWitnessLeafCount::new(count.inner() - appended.len() as u64),
        leaves: appended.to_vec(),
        leaf_count_at_block_end: count,
        prune_persisted_below,
    };
    storage.commit_block(&make_test_certified(block), &witness);
    block_hash
}

/// A `ShardWitnessPayload::StakeDeposit` fixture.
#[must_use]
pub const fn stake_deposit(amount: u64) -> ShardWitnessPayload {
    ShardWitnessPayload::StakeDeposit {
        pool_id: StakePoolId::new(1),
        amount: Stake::from_whole_tokens(amount),
    }
}

/// Seed `entries` single-substate block commits at heights
/// `1..=entries`, each writing one distinct node keyed by its seed
/// byte.
pub fn seed_substate_commits(storage: &impl ShardChainWriter, entries: u8) {
    for seed in 1..=entries {
        let updates = make_database_update(vec![seed; 50], 0, vec![seed], vec![seed, seed, seed]);
        commit_block_with_updates(storage, BlockHeight::new(u64::from(seed)), &updates);
    }
}

/// A snap-sync serving replica.
///
/// Seeds `entries` substate commits, then a boundary block at
/// `entries + 1` whose header carries the witness commitment over
/// `leaves`, pinned for serving. Returns the anchor a joiner verifies
/// against.
///
/// # Panics
///
/// Panics if pinning fails (this is a test helper).
pub fn pin_snap_sync_replica(
    storage: &(impl ShardChainWriter + BoundaryStore + SubstateStore),
    entries: u8,
    leaves: &[ShardWitnessPayload],
) -> ShardAnchor {
    seed_substate_commits(storage, entries);
    let anchor_height = BlockHeight::new(u64::from(entries) + 1);
    let block_hash = commit_block_with_witnesses(storage, anchor_height, leaves);
    storage.pin_boundary(anchor_height).unwrap();
    ShardAnchor {
        state_root: storage.state_root(),
        block_hash,
        height: anchor_height,
        settled_waves_root: None,
    }
}

/// Shared range-read test for `get_beacon_witness_payload_range`.
///
/// The range read must agree with the full prefix read on interior
/// pages, clamp nothing (callers bound `end`), and return empty for
/// degenerate or out-of-range spans.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_witness_payload_range_reads(storage: &(impl ShardChainReader + ShardChainWriter)) {
    let leaves: Vec<ShardWitnessPayload> = (1u64..=5).map(stake_deposit).collect();
    commit_block_with_witnesses(storage, BlockHeight::new(1), &leaves);

    let all = storage.get_beacon_witness_payloads(BeaconWitnessLeafCount::new(5));
    assert_eq!(all.len(), 5);
    assert_eq!(storage.get_beacon_witness_payload_range(0, 5), all);
    assert_eq!(storage.get_beacon_witness_payload_range(1, 3), all[1..3]);
    assert_eq!(storage.get_beacon_witness_payload_range(4, 9), all[4..]);
    assert!(storage.get_beacon_witness_payload_range(3, 3).is_empty());
    assert!(storage.get_beacon_witness_payload_range(7, 9).is_empty());
}

/// Shared EC roundtrip test: commit a block carrying an EC, then read it
/// back by `wave_id`.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_roundtrip(storage: &(impl ShardChainReader + ShardChainWriter)) {
    let ec = make_test_execution_certificate(1, BlockHeight::new(10));
    let wave_id = ec.wave_id().clone();

    // Initially absent.
    assert!(storage.get_execution_certificate(&wave_id).is_none());

    commit_empty_blocks_up_to(storage, BlockHeight::new(10));
    let block = make_test_block_with_ecs(BlockHeight::new(10), vec![Arc::new(ec)]);
    let certified = make_test_certified(block);
    storage.commit_block(&certified, &empty_witness());

    let direct = storage
        .get_execution_certificate(&wave_id)
        .expect("EC must be retrievable by wave_id");
    assert_eq!(direct.wave_id(), &wave_id);
    assert_eq!(direct.block_height(), BlockHeight::new(10));
}

/// Shared EC batch test: commit two ECs at one height plus one at another,
/// confirm batch read returns hits and skips misses.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_batch(storage: &(impl ShardChainReader + ShardChainWriter)) {
    let ec1 = make_test_execution_certificate(1, BlockHeight::new(10));
    let ec2 = make_test_execution_certificate(2, BlockHeight::new(10));
    let ec3 = make_test_execution_certificate(3, BlockHeight::new(20));

    commit_empty_blocks_up_to(storage, BlockHeight::new(10));
    let block10 = make_test_block_with_ecs(
        BlockHeight::new(10),
        vec![Arc::new(ec1.clone()), Arc::new(ec2.clone())],
    );
    storage.commit_block(&make_test_certified(block10), &empty_witness());

    for h in 11..20 {
        let certified = make_test_certified(make_test_block(BlockHeight::new(h)));
        storage.commit_block(&certified, &empty_witness());
    }
    let block20 = make_test_block_with_ecs(BlockHeight::new(20), vec![Arc::new(ec3.clone())]);
    storage.commit_block(&make_test_certified(block20), &empty_witness());

    let known = [
        ec1.wave_id().clone(),
        ec2.wave_id().clone(),
        ec3.wave_id().clone(),
    ];
    let batch = storage.get_execution_certificates_batch(&known);
    assert_eq!(batch.len(), 3);

    let missing_wave_id = WaveId::new(
        known[0].shard_id(),
        BlockHeight::new(999),
        known[0].remote_shards().iter().copied().collect(),
    );
    let partial =
        storage.get_execution_certificates_batch(&[ec3.wave_id().clone(), missing_wave_id]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].wave_id(), ec3.wave_id());
}

/// Shared boundary retention test: pin one height past
/// [`BOUNDARY_RETAIN`] and check eviction stops serving only the
/// oldest pin.
///
/// `commit_one` performs one backend-native substate commit for the
/// given seed — backends differ in their raw commit entry points.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_retention_evicts_oldest<S: BoundaryStore>(
    storage: &S,
    commit_one: impl Fn(u8),
) {
    let last = u64::try_from(BOUNDARY_RETAIN).expect("small const") + 1;
    for height in 1..=last {
        commit_one(u8::try_from(height).expect("small loop bound"));
        storage.pin_boundary(BlockHeight::new(height)).unwrap();
    }
    assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
    assert!(storage.open_boundary(BlockHeight::new(2)).is_some());
    assert!(storage.open_boundary(BlockHeight::new(last)).is_some());
}

/// Shared boundary gating test: a committed but never-pinned height is
/// not served.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_unpinned_height_not_served<S: BoundaryStore>(
    storage: &S,
    commit_one: impl Fn(u8),
) {
    commit_one(1);
    assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
}

/// Shared serve → import round trip: leaves enumerated and resolved
/// from `serving`'s pinned boundary rebuild an identical store in
/// `fresh`, with the raw substates readable and a second import
/// rejected.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_boundary_import_roundtrip<S>(serving: &S, fresh: &S, commit_one: impl Fn(u8))
where
    S: BoundaryStore + SubstateStore,
{
    for seed in 1..=6u8 {
        commit_one(seed);
    }
    let source_root = serving.state_root();
    serving.pin_boundary(BlockHeight::new(6)).unwrap();

    let boundary = serving.open_boundary(BlockHeight::new(6)).expect("pinned");
    let root_key = boundary.get_root_key(6).expect("root resolves");
    let chunk = Jmt::collect_range(&boundary, &root_key, &[0u8; 32], &[0xFF; 32], 1_000).unwrap();
    let leaves: Vec<ImportLeaf> = chunk
        .leaves
        .iter()
        .map(|(leaf_key, _)| {
            let (storage_key, value) = boundary.resolve_leaf(leaf_key).expect("resolves");
            ImportLeaf {
                leaf_key: *leaf_key,
                storage_key,
                value,
            }
        })
        .collect();
    assert_eq!(leaves.len(), 6);
    let probe = leaves
        .iter()
        .find(|l| l.value == [3, 3, 3])
        .map(|l| (l.leaf_key, l.storage_key.clone()))
        .expect("seed-3 leaf present");

    let imported_root = fresh
        .import_boundary_state(BlockHeight::new(6), leaves)
        .unwrap();
    assert_eq!(imported_root, source_root);
    assert_eq!(fresh.state_root(), source_root);

    // Imported raw substates read back at the imported state.
    fresh.pin_boundary(BlockHeight::new(6)).unwrap();
    let fresh_boundary = fresh.open_boundary(BlockHeight::new(6)).expect("pinned");
    assert_eq!(
        fresh_boundary.resolve_leaf(&probe.0),
        Some((probe.1, vec![3, 3, 3])),
    );

    // A second import is rejected — the store is no longer empty.
    assert!(
        fresh
            .import_boundary_state(BlockHeight::new(6), Vec::new())
            .is_err()
    );
}
