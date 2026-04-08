//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use crate::typed_cf::*;

use crate::jvt_stored::{StoredNodeKey, VersionedStoredNode};
use hyperscale_types::{
    BlockMetadata, ExecutionCertificate, Hash, LedgerTransactionReceipt, LocalTransactionExecution,
    RoutableTransaction, TransactionCertificate,
};

// ─── CF name constants ───────────────────────────────────────────────────────

/// Column family name for the default CF (chain metadata, JVT metadata).
pub(crate) const DEFAULT_CF: &str = "default";

/// Column family name for substate data.
pub(crate) const STATE_CF: &str = "state";

/// Column family name for block metadata (header + manifest) keyed by height.
pub(crate) const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub(crate) const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for transaction certificates keyed by hash.
pub(crate) const CERTIFICATES_CF: &str = "certificates";

/// Column family name for BFT votes keyed by height.
pub(crate) const VOTES_CF: &str = "votes";

/// Column family name for JVT tree nodes.
/// The string value remains "jmt_nodes" for backward compatibility with existing
/// RocksDB databases created before the rename to JVT.
pub(crate) const JVT_NODES_CF: &str = "jmt_nodes";

/// Column family for stale JVT nodes pending garbage collection.
/// Key: `version_BE_8B` (the version at which nodes became stale).
/// Value: SBOR-encoded `Vec<StaleTreePart>`.
/// GC deletes entries older than `current_version - jvt_history_length`.
pub(crate) const STALE_JVT_NODES_CF: &str = "stale_jvt_nodes";

/// Column family for MVCC versioned substates.
/// Key: `storage_key_bytes ++ version_BE_8B`, Value: SBOR-encoded substate bytes.
/// Enables historical reads via prefix scan + version filtering.
pub(crate) const VERSIONED_SUBSTATES_CF: &str = "versioned_substates";

/// Column family name for ledger receipts keyed by tx hash.
pub(crate) const LEDGER_RECEIPTS_CF: &str = "ledger_receipts";

/// Column family name for local execution details keyed by tx hash.
pub(crate) const LOCAL_EXECUTIONS_CF: &str = "local_executions";

/// Column family for execution certificates keyed by canonical hash.
pub(crate) const EXECUTION_CERTS_CF: &str = "execution_certs";

/// Column family for execution certificate height index.
/// Key: `block_height_BE_8B ++ canonical_hash_32B`, Value: `()`.
pub(crate) const EXECUTION_CERTS_BY_HEIGHT_CF: &str = "execution_certs_by_height";

// Default-CF metadata keys are defined as MetadataEntry types in typed_cf.rs.
// See CommittedHeightEntry, CommittedHashEntry, CommittedQcEntry, JvtMetadataEntry.

/// CFs with high write throughput — get larger write buffers and tiered compression.
/// State and JVT nodes are updated on every block commit; versioned substates
/// mirror state writes for MVCC.
pub(crate) const HOT_WRITE_COLUMN_FAMILIES: &[&str] =
    &[STATE_CF, JVT_NODES_CF, VERSIONED_SUBSTATES_CF];

/// All column families used by the storage layer.
pub(crate) const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BLOCKS_CF,
    TRANSACTIONS_CF,
    STATE_CF,
    CERTIFICATES_CF,
    VOTES_CF,
    JVT_NODES_CF,
    STALE_JVT_NODES_CF,
    VERSIONED_SUBSTATES_CF,
    LEDGER_RECEIPTS_CF,
    LOCAL_EXECUTIONS_CF,
    EXECUTION_CERTS_CF,
    EXECUTION_CERTS_BY_HEIGHT_CF,
];

// ─── CfHandles ───────────────────────────────────────────────────────────────

/// Column family handles resolved from a `DB` reference.
///
/// Provides typed field access to all column families without repeating
/// `.cf_handle(NAME).expect(...)`. Cheap to construct (HashMap lookups only).
/// Column family handles — fields are private, access only through
/// [`TypedCf::handle()`](crate::typed_cf::TypedCf::handle).
pub(crate) struct CfHandles<'a> {
    state: &'a rocksdb::ColumnFamily,
    blocks: &'a rocksdb::ColumnFamily,
    transactions: &'a rocksdb::ColumnFamily,
    certificates: &'a rocksdb::ColumnFamily,
    votes: &'a rocksdb::ColumnFamily,
    jvt_nodes: &'a rocksdb::ColumnFamily,
    stale_jvt_nodes: &'a rocksdb::ColumnFamily,
    versioned_substates: &'a rocksdb::ColumnFamily,
    ledger_receipts: &'a rocksdb::ColumnFamily,
    local_executions: &'a rocksdb::ColumnFamily,
    execution_certs: &'a rocksdb::ColumnFamily,
    execution_certs_by_height: &'a rocksdb::ColumnFamily,
}

impl<'a> CfHandles<'a> {
    /// Resolve all column family handles from the database.
    ///
    /// # Panics
    /// Panics if any expected column family is missing.
    pub fn resolve(db: &'a rocksdb::DB) -> Self {
        let resolve = |name: &str| -> &'a rocksdb::ColumnFamily {
            db.cf_handle(name)
                .unwrap_or_else(|| panic!("column family '{name}' must exist"))
        };
        Self {
            state: resolve(STATE_CF),
            blocks: resolve(BLOCKS_CF),
            transactions: resolve(TRANSACTIONS_CF),
            certificates: resolve(CERTIFICATES_CF),
            votes: resolve(VOTES_CF),
            jvt_nodes: resolve(JVT_NODES_CF),
            stale_jvt_nodes: resolve(STALE_JVT_NODES_CF),
            versioned_substates: resolve(VERSIONED_SUBSTATES_CF),
            ledger_receipts: resolve(LEDGER_RECEIPTS_CF),
            local_executions: resolve(LOCAL_EXECUTIONS_CF),
            execution_certs: resolve(EXECUTION_CERTS_CF),
            execution_certs_by_height: resolve(EXECUTION_CERTS_BY_HEIGHT_CF),
        }
    }
}

// ─── Typed CF definitions ────────────────────────────────────────────────────

// Block / Transaction storage

pub(crate) struct BlocksCf;
impl TypedCf for BlocksCf {
    const NAME: &'static str = BLOCKS_CF;
    type Key = u64; // block height
    type Value = BlockMetadata;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<BlockMetadata>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.blocks
    }
}

pub(crate) struct TransactionsCf;
impl TypedCf for TransactionsCf {
    const NAME: &'static str = TRANSACTIONS_CF;
    type Key = Hash;
    type Value = RoutableTransaction;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<RoutableTransaction>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.transactions
    }
}

pub(crate) struct CertificatesCf;
impl TypedCf for CertificatesCf {
    const NAME: &'static str = CERTIFICATES_CF;
    type Key = Hash;
    type Value = TransactionCertificate;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<TransactionCertificate>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.certificates
    }
}

// BFT safety

pub(crate) struct VotesCf;
impl TypedCf for VotesCf {
    const NAME: &'static str = VOTES_CF;
    type Key = u64; // height
    type Value = (Hash, u64); // (block_hash, round)
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<(Hash, u64)>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.votes
    }
}

// JVT

pub(crate) struct JvtNodesCf;
impl TypedCf for JvtNodesCf {
    const NAME: &'static str = JVT_NODES_CF;
    type Key = StoredNodeKey;
    type Value = VersionedStoredNode;
    type KeyCodec = JvtKeyCodec;
    type ValueCodec = SborCodec<VersionedStoredNode>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.jvt_nodes
    }
}

pub(crate) struct StaleJvtNodesCf;
impl TypedCf for StaleJvtNodesCf {
    const NAME: &'static str = STALE_JVT_NODES_CF;
    type Key = u64; // version at which nodes became stale
    type Value = Vec<crate::jvt_stored::StaleTreePart>;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<Vec<crate::jvt_stored::StaleTreePart>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.stale_jvt_nodes
    }
}

// State

pub(crate) struct StateCf;
impl TypedCf for StateCf {
    const NAME: &'static str = STATE_CF;
    type Key = (
        radix_substate_store_interface::interface::DbPartitionKey,
        radix_substate_store_interface::interface::DbSortKey,
    );
    type Value = Vec<u8>; // opaque substate bytes — schema owned by Radix engine
    type KeyCodec = crate::substate_key::SubstateKeyCodec;
    type ValueCodec = RawCodec;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.state
    }
}

pub(crate) struct VersionedSubstatesCf;
impl TypedCf for VersionedSubstatesCf {
    const NAME: &'static str = VERSIONED_SUBSTATES_CF;
    type Key = (
        (
            radix_substate_store_interface::interface::DbPartitionKey,
            radix_substate_store_interface::interface::DbSortKey,
        ),
        u64,
    ); // ((partition_key, sort_key), version)
    type Value = Vec<u8>; // opaque substate bytes (empty = tombstone)
    type KeyCodec = crate::versioned_key::VersionedSubstateKeyCodec;
    type ValueCodec = RawCodec;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.versioned_substates
    }
}

// Receipts

pub(crate) struct LedgerReceiptsCf;
impl TypedCf for LedgerReceiptsCf {
    const NAME: &'static str = LEDGER_RECEIPTS_CF;
    type Key = Hash;
    type Value = LedgerTransactionReceipt;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<LedgerTransactionReceipt>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.ledger_receipts
    }
}

pub(crate) struct LocalExecutionsCf;
impl TypedCf for LocalExecutionsCf {
    const NAME: &'static str = LOCAL_EXECUTIONS_CF;
    type Key = Hash;
    type Value = LocalTransactionExecution;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<LocalTransactionExecution>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.local_executions
    }
}

// Execution Certificates

pub(crate) struct ExecutionCertsCf;
impl TypedCf for ExecutionCertsCf {
    const NAME: &'static str = EXECUTION_CERTS_CF;
    type Key = Hash; // canonical hash
    type Value = ExecutionCertificate;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<ExecutionCertificate>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.execution_certs
    }
}

/// Height index for execution certificates.
/// Key: `(block_height, canonical_hash)`, Value: `()`.
pub(crate) struct ExecutionCertsByHeightCf;
impl TypedCf for ExecutionCertsByHeightCf {
    const NAME: &'static str = EXECUTION_CERTS_BY_HEIGHT_CF;
    type Key = (u64, Hash); // (block_height, canonical_hash)
    type Value = ();
    type KeyCodec = HeightHashCodec;
    type ValueCodec = UnitCodec;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.execution_certs_by_height
    }
}

/// Codec for `(u64, Hash)` composite key: `height_BE_8B ++ hash_32B`.
/// Big-endian height ensures lexicographic ordering by height.
#[derive(Default)]
pub(crate) struct HeightHashCodec;

impl DbCodec<(u64, Hash)> for HeightHashCodec {
    fn encode_to(&self, value: &(u64, Hash), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.to_be_bytes());
        buf.extend_from_slice(value.1.as_bytes());
    }

    fn decode(&self, bytes: &[u8]) -> (u64, Hash) {
        assert!(bytes.len() == 40, "HeightHash key must be 40 bytes");
        let height = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let hash = Hash::from_hash_bytes(&bytes[8..40]);
        (height, hash)
    }
}

/// Codec for `()` — empty value.
#[derive(Default)]
pub(crate) struct UnitCodec;

impl DbCodec<()> for UnitCodec {
    fn encode_to(&self, _value: &(), _buf: &mut Vec<u8>) {}
    fn decode(&self, _bytes: &[u8]) {}
}
