//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`,
//! `TransactionCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use crate::{
    ConsensusStore, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use hyperscale_types::{
    zero_bls_signature, ApplicationEvent, Block, BlockHeader, BlockHeight, ExecutionCertificate,
    FeeSummary, Hash, LedgerTransactionOutcome, LedgerTransactionReceipt,
    LocalTransactionExecution, LogLevel, NodeId, PartitionNumber, QuorumCertificate, ReceiptBundle,
    ShardGroupId, SignerBitfield, SubstateChange, SubstateChangeAction, SubstateRef,
    TransactionCertificate, TransactionDecision, ValidatorId,
};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use std::collections::BTreeMap;
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

/// Build a `TransactionCertificate` with a deterministic hash derived from `tx_seed`.
pub fn make_test_certificate(tx_seed: u8, shard: ShardGroupId) -> TransactionCertificate {
    let tx_hash = Hash::from_bytes(&[tx_seed; 32]);
    let execution_cert = ExecutionCertificate {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        read_nodes: vec![],
        write_nodes: vec![],
        receipt_hash: Hash::from_bytes(&[0; 32]),
        success: true,
        aggregated_signature: zero_bls_signature(),
        signers: SignerBitfield::new(4),
    };
    let mut shard_proofs = BTreeMap::new();
    shard_proofs.insert(shard, execution_cert);
    TransactionCertificate {
        transaction_hash: tx_hash,
        decision: TransactionDecision::Accept,
        shard_proofs,
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
            receipt_root: Hash::ZERO,
            provision_targets: vec![],
        },
        retry_transactions: vec![],
        priority_transactions: vec![],
        transactions: vec![],
        certificates: vec![],
        deferred: vec![],
        aborted: vec![],
        source_attestations: vec![],
        commitment_entries: vec![],
    }
}

/// Build a `TransactionCertificate` with proofs for multiple shards.
pub fn make_multi_shard_certificate(
    tx_seed: u8,
    shards: Vec<ShardGroupId>,
) -> TransactionCertificate {
    let tx_hash = Hash::from_bytes(&[tx_seed; 32]);
    let mut shard_proofs = BTreeMap::new();
    for shard in shards {
        let execution_cert = ExecutionCertificate {
            transaction_hash: tx_hash,
            shard_group_id: shard,
            read_nodes: vec![],
            write_nodes: vec![],
            receipt_hash: Hash::from_bytes(&[0; 32]),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
        };
        shard_proofs.insert(shard, execution_cert);
    }
    TransactionCertificate {
        transaction_hash: tx_hash,
        decision: TransactionDecision::Accept,
        shard_proofs,
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

/// Build a `ReceiptBundle` with both ledger receipt and local execution.
pub fn make_test_receipt_bundle(seed: u8) -> ReceiptBundle {
    let tx_hash = Hash::from_bytes(&[seed; 32]);
    let ledger_receipt = Arc::new(LedgerTransactionReceipt {
        outcome: LedgerTransactionOutcome::Success,
        state_changes: vec![SubstateChange {
            substate_ref: SubstateRef {
                node_id: NodeId([seed; 30]),
                partition: PartitionNumber(0),
                sort_key: vec![seed],
            },
            action: SubstateChangeAction::Create {
                new_value: vec![seed, seed + 1],
            },
        }],
        application_events: vec![ApplicationEvent {
            type_id: vec![seed],
            data: vec![seed, seed + 1],
        }],
    });
    let local_execution = Some(LocalTransactionExecution {
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
        ledger_receipt,
        local_execution,
        database_updates: None,
    }
}

/// Build a `ReceiptBundle` without local execution (simulates synced receipt).
pub fn make_synced_receipt_bundle(seed: u8) -> ReceiptBundle {
    let mut bundle = make_test_receipt_bundle(seed);
    bundle.local_execution = None;
    bundle
}

/// Shared receipt storage roundtrip test. Call from each backend's test suite.
pub fn test_receipt_storage_roundtrip(storage: &impl ConsensusStore) {
    let bundle = make_test_receipt_bundle(42);
    let tx_hash = bundle.tx_hash;

    // Initially no receipt
    assert!(!storage.has_receipt(&tx_hash));
    assert!(storage.get_ledger_receipt(&tx_hash).is_none());
    assert!(storage.get_local_execution(&tx_hash).is_none());

    // Store and verify
    storage.store_receipt_bundle(&bundle);
    assert!(storage.has_receipt(&tx_hash));

    let retrieved = storage.get_ledger_receipt(&tx_hash).unwrap();
    assert_eq!(*retrieved, *bundle.ledger_receipt);

    let local = storage.get_local_execution(&tx_hash).unwrap();
    assert_eq!(local, bundle.local_execution.unwrap());
}

/// Shared test for synced receipt (no local execution).
pub fn test_receipt_storage_synced(storage: &impl ConsensusStore) {
    let bundle = make_synced_receipt_bundle(43);
    let tx_hash = bundle.tx_hash;

    storage.store_receipt_bundle(&bundle);
    assert!(storage.has_receipt(&tx_hash));

    let retrieved = storage.get_ledger_receipt(&tx_hash).unwrap();
    assert_eq!(*retrieved, *bundle.ledger_receipt);

    // Local execution should be None for synced receipts
    assert!(storage.get_local_execution(&tx_hash).is_none());
}

/// Shared test for batch receipt storage.
pub fn test_receipt_batch_storage(storage: &impl ConsensusStore) {
    let bundles: Vec<ReceiptBundle> = (10..13).map(make_test_receipt_bundle).collect();

    storage.store_receipt_bundles(&bundles);

    for bundle in &bundles {
        assert!(storage.has_receipt(&bundle.tx_hash));
        let retrieved = storage.get_ledger_receipt(&bundle.tx_hash).unwrap();
        assert_eq!(*retrieved, *bundle.ledger_receipt);
    }
}

/// Shared test for idempotent receipt overwrite.
pub fn test_receipt_idempotent_overwrite(storage: &impl ConsensusStore) {
    let bundle = make_test_receipt_bundle(44);
    let tx_hash = bundle.tx_hash;

    storage.store_receipt_bundle(&bundle);
    storage.store_receipt_bundle(&bundle); // overwrite with same data

    let retrieved = storage.get_ledger_receipt(&tx_hash).unwrap();
    assert_eq!(*retrieved, *bundle.ledger_receipt);
}
