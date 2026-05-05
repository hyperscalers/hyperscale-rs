//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`,
//! `WaveCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{
    ApplicationEvent, Block, BlockHash, BlockHeader, BlockHeight, Bls12381G2Signature,
    CertificateRoot, ConsensusReceipt, ExecutionCertificate, ExecutionMetadata, ExecutionOutcome,
    FeeSummary, FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, Hash, LocalReceiptRoot,
    LogLevel, NodeId, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardGroupId,
    SignerBitfield, StateRoot, StoredReceipt, TransactionRoot, TxHash, TxOutcome, ValidatorId,
    WaveCertificate, WaveId, WeightedTimestamp, zero_bls_signature,
};
use indexmap::IndexMap;
use radix_common::prelude::DatabaseUpdate;
use radix_common::types::{NodeId as RadixNodeId, PartitionNumber};
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

use crate::{
    ChainReader, ChainWriter, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates,
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
        WeightedTimestamp(0),
        GlobalReceiptRoot::ZERO,
        Vec::new(),
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::empty(),
    ));
    WaveCertificate {
        wave_id,
        execution_certificates: vec![local_ec],
    }
}

/// Build a minimal `Block` at the given height.
#[must_use]
pub fn make_test_block(height: BlockHeight) -> Block {
    // Use the full u64 bytes for the parent hash so heights > 255 don't alias.
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    Block::Live {
        header: BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(&parent_bytes)),
            parent_qc: QuorumCertificate::genesis(ShardGroupId(0)),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(height.0 * 1000),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        },
        transactions: Arc::new(vec![]),
        certificates: Arc::new(vec![]),
        provisions: Arc::new(vec![]),
    }
}

/// Build a `QuorumCertificate` that references the given block.
#[must_use]
pub fn make_test_qc(block: &Block) -> QuorumCertificate {
    QuorumCertificate {
        block_hash: block.hash(),
        shard_group_id: ShardGroupId(0),
        height: block.height(),
        parent_block_hash: block.header().parent_block_hash,
        round: Round::INITIAL,
        aggregated_signature: zero_bls_signature(),
        signers: SignerBitfield::new(4),
        weighted_timestamp: WeightedTimestamp(block.header().timestamp.as_millis()),
    }
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
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }],
    };
    let metadata = Some(ExecutionMetadata {
        fee_summary: FeeSummary {
            total_execution_cost: vec![seed],
            total_royalty_cost: vec![],
            total_storage_cost: vec![],
            total_tipping_cost: vec![],
        },
        log_messages: vec![(LogLevel::Info, format!("tx {seed}"))],
        error_message: None,
    });
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
#[must_use]
pub fn make_test_execution_certificate(
    seed: u8,
    block_height: BlockHeight,
) -> ExecutionCertificate {
    ExecutionCertificate::new(
        WaveId::new(ShardGroupId(0), block_height, BTreeSet::new()),
        WeightedTimestamp(block_height.0 + 1),
        GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 50; 32])),
        vec![TxOutcome {
            tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed + 100; 32])),
            outcome: ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 150; 32])),
            },
        }],
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::new(4),
    )
}

/// Build a test block that carries ECs inside its wave certificates.
///
/// Callers supply ECs whose `wave_id` matches the wave-certificate's
/// `wave_id` (callers in this module use [`make_test_execution_certificate`]
/// at the same `(shard, height)`), so the local-EC invariant enforced at
/// decode time is satisfied without injecting a placeholder.
fn make_test_block_with_ecs(height: BlockHeight, ecs: Vec<Arc<ExecutionCertificate>>) -> Block {
    let block = make_test_block(height);
    if ecs.is_empty() {
        return block;
    }
    let certificate = Arc::new(WaveCertificate {
        wave_id: WaveId::new(ShardGroupId(0), height, BTreeSet::new()),
        execution_certificates: ecs,
    });
    let new_fw = Arc::new(FinalizedWave {
        certificate,
        receipts: vec![],
    });
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
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(new_fw);
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
            }
        }
    }
}

/// Helper to commit empty blocks up to (but not including) the target height.
fn commit_empty_blocks_up_to(storage: &(impl ChainReader + ChainWriter), target: BlockHeight) {
    for h in 0..target.0 {
        let b = make_test_block(BlockHeight(h));
        let q = make_test_qc(&b);
        storage.commit_block(&Arc::new(b), &Arc::new(q));
    }
}

/// Shared EC roundtrip test: commit block with ECs → get by height.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_roundtrip(storage: &(impl ChainReader + ChainWriter)) {
    let ec = make_test_execution_certificate(1, BlockHeight(10));
    let canonical_hash = ec.canonical_hash();

    // Initially empty
    assert!(
        storage
            .get_execution_certificates_by_height(BlockHeight(10))
            .is_empty()
    );

    // Commit intermediate blocks, then block at height 10 carrying the EC
    commit_empty_blocks_up_to(storage, BlockHeight(10));
    let block = make_test_block_with_ecs(BlockHeight(10), vec![Arc::new(ec)]);
    let qc = make_test_qc(&block);
    storage.commit_block(&Arc::new(block), &Arc::new(qc));

    let by_height = storage.get_execution_certificates_by_height(BlockHeight(10));
    assert_eq!(by_height.len(), 1);
    assert_eq!(by_height[0].block_height(), BlockHeight(10));
    assert_eq!(by_height[0].canonical_hash(), canonical_hash);

    // Different height returns empty
    assert!(
        storage
            .get_execution_certificates_by_height(BlockHeight(11))
            .is_empty()
    );
}

/// Shared EC batch test: multiple ECs at same and different heights.
///
/// # Panics
///
/// Panics if any assertion fails (this is a test helper).
pub fn test_ec_storage_batch(storage: &(impl ChainReader + ChainWriter)) {
    let ec1 = make_test_execution_certificate(1, BlockHeight(10));
    let ec2 = make_test_execution_certificate(2, BlockHeight(10));
    let ec3 = make_test_execution_certificate(3, BlockHeight(20));

    // Commit intermediate blocks, then block at height 10 with two ECs
    commit_empty_blocks_up_to(storage, BlockHeight(10));
    let block10 = make_test_block_with_ecs(BlockHeight(10), vec![Arc::new(ec1), Arc::new(ec2)]);
    let qc10 = make_test_qc(&block10);
    storage.commit_block(&Arc::new(block10), &Arc::new(qc10));

    // Commit blocks 11-19, then block 20 with one EC
    for h in 11..20 {
        let b = make_test_block(BlockHeight(h));
        let q = make_test_qc(&b);
        storage.commit_block(&Arc::new(b), &Arc::new(q));
    }
    let block20 = make_test_block_with_ecs(BlockHeight(20), vec![Arc::new(ec3.clone())]);
    let qc20 = make_test_qc(&block20);
    storage.commit_block(&Arc::new(block20), &Arc::new(qc20));

    // Both ECs at height 10
    let at_10 = storage.get_execution_certificates_by_height(BlockHeight(10));
    assert_eq!(at_10.len(), 2);

    // One EC at height 20
    let at_20 = storage.get_execution_certificates_by_height(BlockHeight(20));
    assert_eq!(at_20.len(), 1);
    assert_eq!(at_20[0].canonical_hash(), ec3.canonical_hash());
}
