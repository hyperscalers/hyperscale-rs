//! Column family definitions, constants, and handle resolution.
//!
//! This is the single source of truth for what column families exist,
//! what they store, and how their keys/values are encoded.

use crate::typed_cf::{BeU64Codec, DbCodec, HashCodec, JmtKeyCodec, RawCodec, SborCodec, TypedCf};

use crate::jmt_stored::{StoredNodeKey, VersionedStoredNode};
use hyperscale_types::{
    BlockMetadata, ExecutionCertificate, ExecutionMetadata, Hash, LocalReceipt,
    RoutableTransaction, WaveCertificate,
};

// ─── CF name constants ───────────────────────────────────────────────────────

/// Column family name for the default CF (chain metadata, JMT metadata).
pub const DEFAULT_CF: &str = "default";

/// Column family name for substate data. Stores the current value per
/// unversioned `(partition_key, sort_key)`. History for recent writes
/// lives in `STATE_HISTORY_CF` (same `storage_key` + write-version suffix,
/// value is the pre-write prior state). Current-state reads are a
/// direct point lookup; historical reads at version V seek the smallest
/// state-history entry for the key with `write_version > V` and return
/// its prior value.
pub const STATE_CF: &str = "state";

/// Column family name for the per-write state-history log used by
/// historical reads.
/// Key: `((partition_key, sort_key), write_version)`; value: the prior
/// value at that key immediately before the write at `write_version`.
/// A `None` value means "key was absent before the write."
pub const STATE_HISTORY_CF: &str = "state_history";

/// Column family name for block metadata (header + manifest) keyed by height.
pub const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for wave certificates keyed by hash.
pub const CERTIFICATES_CF: &str = "certificates";

/// Column family name for JMT tree nodes.
pub const JMT_NODES_CF: &str = "jmt_nodes";

/// Column family for stale JMT nodes pending garbage collection.
/// Key: `version_BE_8B` (the version at which nodes became stale).
/// Value: SBOR-encoded `Vec<StaleTreePart>`.
/// GC deletes entries older than `current_version - jmt_history_length`.
pub const STALE_JMT_NODES_CF: &str = "stale_jmt_nodes";

/// Column family indexing `state_history` entries by their write version so
/// GC can delete retention-expired history without scanning the whole
/// `state_history` CF.
///
/// Key: `version_BE_8B` — the `write_version` at which these history entries
/// were created (one entry per block commit).
/// Value: SBOR-encoded `Vec<Vec<u8>>` — the list of raw `state_history` keys
/// (i.e. `storage_key_bytes ++ BE8(version)`) written at that version.
///
/// Written alongside every `state_history` entry. GC iterates this CF in
/// version order (cheap — version-keyed), breaks at `version >= cutoff`, and
/// issues one `delete_cf` per listed history key plus one for the stale-set
/// entry itself. Mirrors the `stale_jmt_nodes` pattern.
pub const STALE_STATE_HISTORY_CF: &str = "stale_state_history";

/// Column family name for local receipts keyed by tx hash.
pub const LOCAL_RECEIPTS_CF: &str = "local_receipts";

/// Column family name for execution output details keyed by tx hash.
pub const EXECUTION_OUTPUTS_CF: &str = "execution_outputs";

/// Column family for execution certificates keyed by canonical hash.
pub const EXECUTION_CERTS_CF: &str = "execution_certs";

/// Column family for execution certificate height index.
/// Key: `block_height_BE_8B ++ canonical_hash_32B`, Value: `()`.
pub const EXECUTION_CERTS_BY_HEIGHT_CF: &str = "execution_certs_by_height";

// Default-CF metadata keys are defined as MetadataEntry types in typed_cf.rs.
// See CommittedHeightEntry, CommittedHashEntry, CommittedQcEntry, JmtMetadataEntry.

/// CFs with high write throughput — get larger write buffers and tiered compression.
/// State, state-history log, and JMT nodes are updated on every block commit.
pub const HOT_WRITE_COLUMN_FAMILIES: &[&str] = &[STATE_CF, STATE_HISTORY_CF, JMT_NODES_CF];

/// All column families used by the storage layer.
pub const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BLOCKS_CF,
    TRANSACTIONS_CF,
    STATE_CF,
    STATE_HISTORY_CF,
    STALE_STATE_HISTORY_CF,
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
/// `.cf_handle(NAME).expect(...)`. Cheap to construct (`HashMap` lookups only).
/// Column family handles — fields are private, access only through
/// [`TypedCf::handle()`](crate::typed_cf::TypedCf::handle).
pub struct CfHandles<'a> {
    state: &'a rocksdb::ColumnFamily,
    state_history: &'a rocksdb::ColumnFamily,
    stale_state_history: &'a rocksdb::ColumnFamily,
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
            state_history: resolve(STATE_HISTORY_CF),
            stale_state_history: resolve(STALE_STATE_HISTORY_CF),
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

pub struct BlocksCf;
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

pub struct TransactionsCf;
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

pub struct CertificatesCf;
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

pub struct JmtNodesCf;
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

pub struct StaleJmtNodesCf;
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

/// Version-indexed list of `state_history` keys written at each version.
/// Enables incremental GC of `state_history` — GC walks this CF in version
/// order, deletes the listed history keys for each version ≤ cutoff, and
/// drops the stale-set entry itself. No full `state_history` scan.
pub struct StaleStateHistoryCf;
impl TypedCf for StaleStateHistoryCf {
    const NAME: &'static str = STALE_STATE_HISTORY_CF;
    type Key = u64; // write_version
    type Value = Vec<Vec<u8>>; // raw `state_history` keys (storage_key ++ BE8(version))
    type KeyCodec = BeU64Codec;
    type ValueCodec = SborCodec<Vec<Vec<u8>>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.stale_state_history
    }
}

// State — current-value-per-key source of truth.
//
// Key: `(partition_key, sort_key)` encoded as `storage_key_bytes`.
// Value: opaque substate bytes. An absent row means "no value for this
// key" — deletions do `batch.delete_cf(state_cf, K)`, not a tombstone
// sentinel.
//
// Current reads are direct point lookups. Historical reads at version V
// go through the companion `StateHistoryCf`: seek the smallest history
// entry for K with `write_version > V` and return its stored prior value.
pub struct StateCf;
impl TypedCf for StateCf {
    const NAME: &'static str = STATE_CF;
    type Key = (
        radix_substate_store_interface::interface::DbPartitionKey,
        radix_substate_store_interface::interface::DbSortKey,
    );
    type Value = Vec<u8>;
    type KeyCodec = crate::substate_key::SubstateKeyCodec;
    type ValueCodec = RawCodec;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.state
    }
}

// State-history log — per-write prior-value entries for historical reads.
//
// Key: `((partition_key, sort_key), write_version)` encoded as
// `storage_key_bytes ++ write_version_BE_8B`. Value:
// `Option<Vec<u8>>` — the value the key held immediately before the
// write at `write_version`. `None` means "key was absent before the
// write."
//
// Every write to `StateCf` at version V captures a history entry at
// `(K, V)` (except during genesis / bootstrap, which skips history
// writes). GC deletes entries older than the retention window; `StateCf`
// is always authoritative for the current tip.
//
// Read-only: historical reads reconstruct the value-at-V by seeking the
// smallest entry for K with `v' > V`. Nothing ever mutates `StateCf`
// from this log.
pub struct StateHistoryCf;
impl TypedCf for StateHistoryCf {
    const NAME: &'static str = STATE_HISTORY_CF;
    type Key = (
        (
            radix_substate_store_interface::interface::DbPartitionKey,
            radix_substate_store_interface::interface::DbSortKey,
        ),
        u64,
    ); // ((partition_key, sort_key), write_version)
    type Value = Option<Vec<u8>>;
    type KeyCodec = crate::versioned_key::VersionedSubstateKeyCodec;
    type ValueCodec = SborCodec<Option<Vec<u8>>>;
    fn handle<'a>(cf: &CfHandles<'a>) -> &'a rocksdb::ColumnFamily {
        cf.state_history
    }
}

// Receipts

pub struct LocalReceiptsCf;
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

pub struct ExecutionOutputsCf;
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

pub struct ExecutionCertsCf;
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
pub struct ExecutionCertsByHeightCf;
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
pub struct HeightHashCodec;

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
pub struct UnitCodec;

impl DbCodec<()> for UnitCodec {
    fn encode_to(&self, _value: &(), _buf: &mut Vec<u8>) {}
    fn decode(&self, _bytes: &[u8]) {}
}
