//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use crate::typed_cf::*;

use crate::jmt_stored::{StoredNodeKey, VersionedStoredNode};
use hyperscale_types::{
    BlockMetadata, ExecutionCertificate, ExecutionMetadata, Hash, LocalReceipt,
    RoutableTransaction, WaveCertificate,
};

// ─── CF name constants ───────────────────────────────────────────────────────

/// Column family name for the default CF (chain metadata, JMT metadata).
pub(crate) const DEFAULT_CF: &str = "default";

/// Column family name for substate data. This CF is the single source of
/// truth for substates — every write is versioned as `(storage_key,
/// version)`, and the "current state" is simply the latest entry per key.
/// Historical reads use version-aware walks; GC keeps a floor entry per
/// key so reads at any height in the retention window resolve correctly.
pub(crate) const STATE_CF: &str = "state";

/// Column family name for block metadata (header + manifest) keyed by height.
pub(crate) const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub(crate) const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for wave certificates keyed by hash.
pub(crate) const CERTIFICATES_CF: &str = "certificates";

/// Column family name for JMT tree nodes.
pub(crate) const JMT_NODES_CF: &str = "jmt_nodes";

/// Column family for stale JMT nodes pending garbage collection.
/// Key: `version_BE_8B` (the version at which nodes became stale).
/// Value: SBOR-encoded `Vec<StaleTreePart>`.
/// GC deletes entries older than `current_version - jmt_history_length`.
pub(crate) const STALE_JMT_NODES_CF: &str = "stale_jmt_nodes";

/// Column family name for local receipts keyed by tx hash.
pub(crate) const LOCAL_RECEIPTS_CF: &str = "local_receipts";

/// Column family name for execution output details keyed by tx hash.
pub(crate) const EXECUTION_OUTPUTS_CF: &str = "execution_outputs";

/// Column family for execution certificates keyed by canonical hash.
pub(crate) const EXECUTION_CERTS_CF: &str = "execution_certs";

/// Column family for execution certificate height index.
/// Key: `block_height_BE_8B ++ canonical_hash_32B`, Value: `()`.
pub(crate) const EXECUTION_CERTS_BY_HEIGHT_CF: &str = "execution_certs_by_height";

// Default-CF metadata keys are defined as MetadataEntry types in typed_cf.rs.
// See CommittedHeightEntry, CommittedHashEntry, CommittedQcEntry, JmtMetadataEntry.

/// CFs with high write throughput — get larger write buffers and tiered compression.
/// State (MVCC-versioned) and JMT nodes are updated on every block commit.
pub(crate) const HOT_WRITE_COLUMN_FAMILIES: &[&str] = &[STATE_CF, JMT_NODES_CF];

/// All column families used by the storage layer.
pub(crate) const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BLOCKS_CF,
    TRANSACTIONS_CF,
    STATE_CF,
    CERTIFICATES_CF,
    JMT_NODES_CF,
    STALE_JMT_NODES_CF,
    LOCAL_RECEIPTS_CF,
    EXECUTION_OUTPUTS_CF,
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
    jmt_nodes: &'a rocksdb::ColumnFamily,
    stale_jmt_nodes: &'a rocksdb::ColumnFamily,
    local_receipts: &'a rocksdb::ColumnFamily,
    execution_outputs: &'a rocksdb::ColumnFamily,
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
            jmt_nodes: resolve(JMT_NODES_CF),
            stale_jmt_nodes: resolve(STALE_JMT_NODES_CF),
            local_receipts: resolve(LOCAL_RECEIPTS_CF),
            execution_outputs: resolve(EXECUTION_OUTPUTS_CF),
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
    type Value = WaveCertificate;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<WaveCertificate>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.certificates
    }
}

// JMT

pub(crate) struct JmtNodesCf;
impl TypedCf for JmtNodesCf {
    const NAME: &'static str = JMT_NODES_CF;
    type Key = StoredNodeKey;
    type Value = VersionedStoredNode;
    type KeyCodec = JmtKeyCodec;
    type ValueCodec = SborCodec<VersionedStoredNode>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.jmt_nodes
    }
}

pub(crate) struct StaleJmtNodesCf;
impl TypedCf for StaleJmtNodesCf {
    const NAME: &'static str = STALE_JMT_NODES_CF;
    type Key = u64; // version at which nodes became stale
    type Value = Vec<crate::jmt_stored::StaleTreePart>;
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<Vec<crate::jmt_stored::StaleTreePart>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.stale_jmt_nodes
    }
}

// State — MVCC-versioned single source of truth.
//
// Key: `((partition_key, sort_key), version)` encoded as
// `storage_key_bytes ++ version_BE_8B`. Value: opaque substate bytes
// (empty = tombstone).
//
// Reads resolve to the latest version ≤ target via walk-back. "Current
// state" is simply `snapshot_at(jmt_version())`. GC keeps a floor entry
// per key so reads within the retention window always resolve.
pub(crate) struct StateCf;
impl TypedCf for StateCf {
    const NAME: &'static str = STATE_CF;
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
        cf.state
    }
}

// Receipts

pub(crate) struct LocalReceiptsCf;
impl TypedCf for LocalReceiptsCf {
    const NAME: &'static str = LOCAL_RECEIPTS_CF;
    type Key = Hash;
    type Value = LocalReceipt;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<LocalReceipt>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.local_receipts
    }
}

pub(crate) struct ExecutionOutputsCf;
impl TypedCf for ExecutionOutputsCf {
    const NAME: &'static str = EXECUTION_OUTPUTS_CF;
    type Key = Hash;
    type Value = ExecutionMetadata;
    type KeyCodec = HashCodec;
    type ValueCodec = SborCodec<ExecutionMetadata>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.execution_outputs
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
