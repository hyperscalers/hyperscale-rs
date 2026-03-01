//! Shared test helpers for storage crate tests.
//!
//! Provides reusable builder functions for `DatabaseUpdates`, `SubstateWrite`,
//! `TransactionCertificate`, `Block`, and `QuorumCertificate` so that
//! storage-memory and storage-rocksdb tests can share a single source of truth.

use crate::{DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates};
use hyperscale_types::{
    zero_bls_signature, Block, BlockHeader, BlockHeight, Hash, NodeId, PartitionNumber,
    QuorumCertificate, ShardGroupId, SignerBitfield, StateCertificate, SubstateWrite,
    TransactionCertificate, TransactionDecision, ValidatorId, VotePower,
};
use radix_common::prelude::DatabaseUpdate;
use std::collections::BTreeMap;

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

/// Build a `SubstateWrite` with a uniform `NodeId` derived from `node_seed`.
pub fn make_substate_write(
    node_seed: u8,
    partition: u8,
    sort_key: Vec<u8>,
    value: Vec<u8>,
) -> SubstateWrite {
    SubstateWrite {
        node_id: NodeId([node_seed; 30]),
        partition: PartitionNumber(partition),
        sort_key,
        value,
    }
}

/// Build a `TransactionCertificate` with a deterministic hash derived from `tx_seed`.
pub fn make_test_certificate(
    tx_seed: u8,
    shard: ShardGroupId,
    writes: Vec<SubstateWrite>,
) -> TransactionCertificate {
    let tx_hash = Hash::from_bytes(&[tx_seed; 32]);
    let state_cert = StateCertificate {
        transaction_hash: tx_hash,
        shard_group_id: shard,
        read_nodes: vec![],
        state_writes: writes,
        writes_commitment: Hash::from_bytes(&[0; 32]),
        success: true,
        aggregated_signature: zero_bls_signature(),
        signers: SignerBitfield::new(4),
        voting_power: 0,
    };
    let mut shard_proofs = BTreeMap::new();
    shard_proofs.insert(shard, state_cert);
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
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(&parent_bytes),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: height * 1000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        },
        retry_transactions: vec![],
        priority_transactions: vec![],
        transactions: vec![],
        certificates: vec![],
        deferred: vec![],
        aborted: vec![],
        commitment_proofs: std::collections::HashMap::new(),
    }
}

/// Build a `TransactionCertificate` with proofs for multiple shards.
///
/// Each entry in `shard_writes` maps a `ShardGroupId` to its writes.
pub fn make_multi_shard_certificate(
    tx_seed: u8,
    shard_writes: Vec<(ShardGroupId, Vec<SubstateWrite>)>,
) -> TransactionCertificate {
    let tx_hash = Hash::from_bytes(&[tx_seed; 32]);
    let mut shard_proofs = BTreeMap::new();
    for (shard, writes) in shard_writes {
        let state_cert = StateCertificate {
            transaction_hash: tx_hash,
            shard_group_id: shard,
            read_nodes: vec![],
            state_writes: writes,
            writes_commitment: Hash::from_bytes(&[0; 32]),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
            voting_power: 0,
        };
        shard_proofs.insert(shard, state_cert);
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
        voting_power: VotePower(4),
        weighted_timestamp_ms: block.header.timestamp,
    }
}
