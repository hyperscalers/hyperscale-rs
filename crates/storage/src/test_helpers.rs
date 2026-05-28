//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`,
//! `WaveCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_types::test_utils::test_event_type_identifier;
use hyperscale_types::{
    ApplicationEvent, BeaconBlock, BeaconBlockHash, BeaconCert, BeaconState,
    BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight,
    Bls12381G2Signature, BoundedVec, CertificateRoot, CertifiedBeaconBlock, CertifiedBlock,
    ConsensusReceipt, Epoch, EventData, ExecutionCertificate, ExecutionMetadata, ExecutionOutcome,
    FeeSummary, FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, Hash, InFlightCount,
    LocalReceiptRoot, LogLevel, NodeId, PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof,
    ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Randomness, Round, ShardGroupId,
    SignerBitfield, SpcCert, SpcView, StateRoot, StoredReceipt, TransactionRoot, TxHash, TxOutcome,
    ValidatorId, Verified, WaveCertificate, WaveId, WeightedTimestamp, compute_global_receipt_root,
    zero_bls_signature,
};
use indexmap::IndexMap;
use radix_common::math::Decimal;
use radix_common::prelude::DatabaseUpdate;
use radix_common::types::{NodeId as RadixNodeId, PartitionNumber};
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

use crate::{
    BeaconWitnessCommit, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    ShardChainReader, ShardChainWriter,
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
pub fn make_test_wave_certificate(height: BlockHeight, shard: ShardGroupId) -> WaveCertificate {
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
            ShardGroupId::new(0),
            height,
            BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
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
    Verified::<QuorumCertificate>::new_unchecked(QuorumCertificate::new(
        block.hash(),
        ShardGroupId::new(0),
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
    Arc::new(Verified::<CertifiedBlock>::new_unchecked(certified))
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
        proof,
    }
}

/// Build a certified beacon block at `epoch` with tag-derived
/// `prev_block_hash`.
///
/// The cert is a structurally-valid but cryptographically-unverified
/// placeholder. Suitable for storage round-trip tests, not for
/// consensus verification.
#[must_use]
pub fn make_test_beacon_block(epoch: u64, tag: &[u8]) -> Arc<CertifiedBeaconBlock> {
    let block = BeaconBlock::new(
        Epoch::new(epoch),
        BeaconBlockHash::from_raw(Hash::from_bytes(tag)),
        Vec::new(),
    );
    Arc::new(CertifiedBeaconBlock::new_unchecked(
        block,
        BeaconCert::Normal(Box::new(placeholder_cert())),
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
        current_epoch: Epoch::new(epoch),
        validators: BTreeMap::new(),
        pools: BTreeMap::new(),
        randomness: Randomness::new(randomness),
        committee: Vec::new(),
        shard_committees: BTreeMap::new(),
        consumed_through: BTreeMap::new(),
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
) -> (Arc<CertifiedBeaconBlock>, Arc<BeaconState>) {
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
    remote_shards.insert(ShardGroupId::new(u64::from(seed) + 1));
    ExecutionCertificate::new(
        WaveId::new(ShardGroupId::new(0), block_height, remote_shards),
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
    let new_fw = Arc::new(FinalizedWave::new(certificate, vec![]));
    match block {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(new_fw);
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
            certificates.push(new_fw);
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
fn commit_empty_blocks_up_to(
    storage: &(impl ShardChainReader + ShardChainWriter),
    target: BlockHeight,
) {
    let witness = empty_witness();
    for h in 0..target.inner() {
        let certified = make_test_certified(make_test_block(BlockHeight::new(h)));
        storage.commit_block(&certified, &witness);
    }
}

const fn empty_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
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
        known[0].shard_group_id(),
        BlockHeight::new(999),
        known[0].remote_shards().iter().copied().collect(),
    );
    let partial =
        storage.get_execution_certificates_batch(&[ec3.wave_id().clone(), missing_wave_id]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].wave_id(), ec3.wave_id());
}
