//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`,
//! `WaveCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use crate::{
    ChainReader, ChainWriter, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates,
};
use hyperscale_types::{
    zero_bls_signature, ApplicationEvent, Block, BlockHeader, BlockHeight, Bls12381G2Signature,
    ExecutionCertificate, ExecutionMetadata, ExecutionOutcome, FeeSummary, Hash, LocalReceipt,
    LogLevel, NodeId, QuorumCertificate, ReceiptBundle, ShardGroupId, SignerBitfield,
    TransactionOutcome, TxOutcome, ValidatorId, WaveCertificate, WaveId,
};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Build a `DatabaseUpdates` containing a single `Set` operation.
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
            partition_updates: [(
                partition,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(DbSortKey(sort_key), DatabaseUpdate::Set(value))]
                        .into_iter()
                        .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    updates
}

/// Build `DatabaseUpdates` from a logical node seed, using SpreadPrefixKeyMapper
/// to compute the correct db_node_key — matching the storage format used in production.
///
/// The `NodeId` is `[node_seed; 30]`, consistent with other test helpers.
pub fn make_mapped_database_update(
    node_seed: u8,
    partition: u8,
    sort_key: Vec<u8>,
    value: Vec<u8>,
) -> DatabaseUpdates {
    let radix_node_id = radix_common::types::NodeId(NodeId([node_seed; 30]).0);
    let radix_partition = radix_common::types::PartitionNumber(partition);
    let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
    let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
    let db_sort_key = DbSortKey(sort_key);

    let mut updates = DatabaseUpdates::default();
    let node_updates = updates.node_updates.entry(db_node_key).or_default();
    let partition_updates = node_updates
        .partition_updates
        .entry(db_partition_num)
        .or_insert_with(|| PartitionDatabaseUpdates::Delta {
            substate_updates: indexmap::IndexMap::new(),
        });
    if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
        substate_updates.insert(db_sort_key, DatabaseUpdate::Set(value));
    }
    updates
}

/// Build a test `WaveCertificate` at the given height.
pub fn make_test_wave_certificate(height: u64, shard: ShardGroupId) -> WaveCertificate {
    WaveCertificate {
        wave_id: WaveId::new(shard, height, BTreeSet::new()),
        attestations: vec![],
    }
}

/// Build a minimal `Block` at the given height.
pub fn make_test_block(height: u64) -> Block {
    // Use the full u64 bytes for the parent hash so heights > 255 don't alias.
    let mut parent_bytes = [0u8; 32];
    parent_bytes[..8].copy_from_slice(&height.to_le_bytes());
    Block {
        header: BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(&parent_bytes),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: height * 1000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            waves: vec![],
        },
        transactions: vec![],
        certificates: vec![],
        conflicts: vec![],
    }
}

/// Build a `QuorumCertificate` that references the given block.
pub fn make_test_qc(block: &Block) -> QuorumCertificate {
    QuorumCertificate {
        block_hash: block.hash(),
        shard_group_id: ShardGroupId(0),
        height: block.header.height,
        parent_block_hash: block.header.parent_hash,
        round: 0,
        aggregated_signature: zero_bls_signature(),
        signers: SignerBitfield::new(4),
        weighted_timestamp_ms: block.header.timestamp,
    }
}

/// Build a `ReceiptBundle` with both local receipt and execution output.
pub fn make_test_receipt_bundle(seed: u8) -> ReceiptBundle {
    let tx_hash = Hash::from_bytes(&[seed; 32]);
    let local_receipt = Arc::new(LocalReceipt {
        outcome: TransactionOutcome::Success,
        database_updates: DatabaseUpdates::default(),
        application_events: vec![ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }],
    });
    let execution_output = Some(ExecutionMetadata {
        fee_summary: FeeSummary {
            total_execution_cost: vec![seed],
            total_royalty_cost: vec![],
            total_storage_cost: vec![],
            total_tipping_cost: vec![],
        },
        log_messages: vec![(LogLevel::Info, format!("tx {seed}"))],
        error_message: None,
    });
    ReceiptBundle {
        tx_hash,
        local_receipt,
        execution_output,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Execution Certificate helpers
// ═══════════════════════════════════════════════════════════════════════

/// Build a test `ExecutionCertificate` at the given block height with a
/// deterministic outcome derived from `seed`.
pub fn make_test_execution_certificate(seed: u8, block_height: u64) -> ExecutionCertificate {
    ExecutionCertificate {
        wave_id: WaveId::new(ShardGroupId(0), block_height, BTreeSet::new()),
        vote_height: block_height + 1,
        global_receipt_root: Hash::from_bytes(&[seed + 50; 32]),
        tx_outcomes: vec![TxOutcome {
            tx_hash: Hash::from_bytes(&[seed + 100; 32]),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(&[seed + 150; 32]),
                success: true,
                write_nodes: vec![],
            },
        }],
        aggregated_signature: Bls12381G2Signature([0u8; 96]),
        signers: SignerBitfield::new(4),
    }
}

/// Helper to commit empty blocks up to (but not including) the target height.
fn commit_empty_blocks_up_to(storage: &(impl ChainReader + ChainWriter), target: u64) {
    for h in 0..target {
        let b = make_test_block(h);
        let q = make_test_qc(&b);
        storage.commit_block(&Arc::new(b), &Arc::new(q), &[], &[]);
    }
}

/// Shared EC roundtrip test: commit block with ECs → get by height.
pub fn test_ec_storage_roundtrip(storage: &(impl ChainReader + ChainWriter)) {
    let ec = make_test_execution_certificate(1, 10);
    let canonical_hash = ec.canonical_hash();

    // Initially empty
    assert!(storage.get_execution_certificates_by_height(10).is_empty());

    // Commit intermediate blocks, then block at height 10 carrying the EC
    commit_empty_blocks_up_to(storage, 10);
    let block = make_test_block(10);
    let qc = make_test_qc(&block);
    storage.commit_block(&Arc::new(block), &Arc::new(qc), &[Arc::new(ec)], &[]);

    let by_height = storage.get_execution_certificates_by_height(10);
    assert_eq!(by_height.len(), 1);
    assert_eq!(by_height[0].block_height(), 10);
    assert_eq!(by_height[0].canonical_hash(), canonical_hash);

    // Different height returns empty
    assert!(storage.get_execution_certificates_by_height(11).is_empty());
}

/// Shared EC batch test: multiple ECs at same and different heights.
pub fn test_ec_storage_batch(storage: &(impl ChainReader + ChainWriter)) {
    let ec1 = make_test_execution_certificate(1, 10);
    let ec2 = make_test_execution_certificate(2, 10);
    let ec3 = make_test_execution_certificate(3, 20);

    // Commit intermediate blocks, then block at height 10 with two ECs
    commit_empty_blocks_up_to(storage, 10);
    let block10 = make_test_block(10);
    let qc10 = make_test_qc(&block10);
    storage.commit_block(
        &Arc::new(block10),
        &Arc::new(qc10),
        &[Arc::new(ec1), Arc::new(ec2)],
        &[],
    );

    // Commit blocks 11-19, then block 20 with one EC
    for h in 11..20 {
        let b = make_test_block(h);
        let q = make_test_qc(&b);
        storage.commit_block(&Arc::new(b), &Arc::new(q), &[], &[]);
    }
    let block20 = make_test_block(20);
    let qc20 = make_test_qc(&block20);
    storage.commit_block(
        &Arc::new(block20),
        &Arc::new(qc20),
        &[Arc::new(ec3.clone())],
        &[],
    );

    // Both ECs at height 10
    let at_10 = storage.get_execution_certificates_by_height(10);
    assert_eq!(at_10.len(), 2);

    // One EC at height 20
    let at_20 = storage.get_execution_certificates_by_height(20);
    assert_eq!(at_20.len(), 1);
    assert_eq!(at_20[0].canonical_hash(), ec3.canonical_hash());
}
