//! Configuration types and constants for RocksDB storage.

/// Column family name for substate data.
pub(crate) const STATE_CF: &str = "state";

/// Column family name for JVT tree nodes.
/// The string value remains "jmt_nodes" for backward compatibility with existing
/// RocksDB databases created before the rename to JVT.
pub(crate) const JVT_NODES_CF: &str = "jmt_nodes";

/// Column family name for associated state tree values.
/// Used for historical substate queries - maps JVT leaf node keys to substate values.
pub(crate) const ASSOCIATED_STATE_TREE_VALUES_CF: &str = "associated_state_tree_values";

/// Column family name for stale state hash tree parts.
/// Stores stale JVT nodes/subtrees keyed by the version at which they became stale.
/// A background GC process deletes these after the retention window expires.
pub(crate) const STALE_STATE_HASH_TREE_PARTS_CF: &str = "stale_state_hash_tree_parts";

/// Column family for MVCC versioned substates.
/// Key: `storage_key_bytes ++ version_BE_8B`, Value: SBOR-encoded substate bytes.
/// Enables historical reads via prefix scan + version filtering.
pub(crate) const VERSIONED_SUBSTATES_CF: &str = "versioned_substates";

/// Column family name for the default CF (chain metadata, JVT metadata).
pub(crate) const DEFAULT_CF: &str = "default";

/// Column family name for block metadata (header + manifest) keyed by height.
pub(crate) const BLOCKS_CF: &str = "blocks";

/// Column family name for transactions keyed by hash.
pub(crate) const TRANSACTIONS_CF: &str = "transactions";

/// Column family name for transaction certificates keyed by hash.
pub(crate) const CERTIFICATES_CF: &str = "certificates";

/// Column family name for BFT votes keyed by height.
pub(crate) const VOTES_CF: &str = "votes";

/// Column family name for ledger receipts keyed by tx hash.
pub(crate) const LEDGER_RECEIPTS_CF: &str = "ledger_receipts";

/// Column family name for local execution details keyed by tx hash.
pub(crate) const LOCAL_EXECUTIONS_CF: &str = "local_executions";

/// All column families used by the storage layer.
pub(crate) const ALL_COLUMN_FAMILIES: &[&str] = &[
    DEFAULT_CF,
    BLOCKS_CF,
    TRANSACTIONS_CF,
    STATE_CF,
    CERTIFICATES_CF,
    VOTES_CF,
    JVT_NODES_CF,
    ASSOCIATED_STATE_TREE_VALUES_CF,
    STALE_STATE_HASH_TREE_PARTS_CF,
    VERSIONED_SUBSTATES_CF,
    LEDGER_RECEIPTS_CF,
    LOCAL_EXECUTIONS_CF,
];

/// Old storage keys deleted by partition Reset operations, keyed by `(entity_key, partition_num)`.
/// Passed to `put_at_version` so the JVT can generate deletes for the hashed keys.
pub(crate) type ResetOldKeys = std::collections::HashMap<(Vec<u8>, u8), Vec<Vec<u8>>>;

/// Column family handles resolved from a `DB` reference.
///
/// This is cheap to construct (HashMap lookups only) and provides typed access
/// to all column families without repeating `.cf_handle(NAME).expect(...)`.
///
/// Call `CfHandles::resolve(&db)` at the start of any method that needs
/// multiple CF handles, or use `RocksDbStorage::cf()` for convenience.
pub(crate) struct CfHandles<'a> {
    pub state: &'a rocksdb::ColumnFamily,
    pub blocks: &'a rocksdb::ColumnFamily,
    pub transactions: &'a rocksdb::ColumnFamily,
    pub certificates: &'a rocksdb::ColumnFamily,
    pub votes: &'a rocksdb::ColumnFamily,
    pub jvt_nodes: &'a rocksdb::ColumnFamily,
    pub associated_state_tree_values: &'a rocksdb::ColumnFamily,
    pub stale_state_hash_tree_parts: &'a rocksdb::ColumnFamily,
    pub versioned_substates: &'a rocksdb::ColumnFamily,
    pub ledger_receipts: &'a rocksdb::ColumnFamily,
    pub local_executions: &'a rocksdb::ColumnFamily,
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
            associated_state_tree_values: resolve(ASSOCIATED_STATE_TREE_VALUES_CF),
            stale_state_hash_tree_parts: resolve(STALE_STATE_HASH_TREE_PARTS_CF),
            versioned_substates: resolve(VERSIONED_SUBSTATES_CF),
            ledger_receipts: resolve(LEDGER_RECEIPTS_CF),
            local_executions: resolve(LOCAL_EXECUTIONS_CF),
        }
    }
}

/// Compression type for RocksDB.
#[derive(Debug, Clone, Copy, Default)]
pub enum CompressionType {
    None,
    Snappy,
    Zlib,
    #[default]
    Lz4,
    Lz4hc,
    Zstd,
}

impl CompressionType {
    pub(crate) fn to_rocksdb(self) -> rocksdb::DBCompressionType {
        match self {
            CompressionType::None => rocksdb::DBCompressionType::None,
            CompressionType::Snappy => rocksdb::DBCompressionType::Snappy,
            CompressionType::Zlib => rocksdb::DBCompressionType::Zlib,
            CompressionType::Lz4 => rocksdb::DBCompressionType::Lz4,
            CompressionType::Lz4hc => rocksdb::DBCompressionType::Lz4hc,
            CompressionType::Zstd => rocksdb::DBCompressionType::Zstd,
        }
    }
}

/// Configuration for RocksDB storage.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    /// Maximum number of background jobs
    pub max_background_jobs: i32,
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    /// Maximum number of write buffers
    pub max_write_buffer_number: i32,
    /// Block cache size in bytes (None to disable)
    pub block_cache_size: Option<usize>,
    /// Compression type
    pub compression: CompressionType,
    /// Bloom filter bits per key (0 to disable)
    pub bloom_filter_bits: f64,
    /// Bytes per sync (0 to disable)
    pub bytes_per_sync: usize,
    /// Number of log files to keep
    pub keep_log_file_num: usize,
    /// Column families to create
    pub column_families: Vec<String>,
    /// Number of block heights of JVT history to retain before garbage collection.
    ///
    /// Stale JVT nodes and their associations are kept for this many heights
    /// before being eligible for deletion. This enables historical queries within
    /// this window.
    ///
    /// Set to 0 for immediate deletion (no history retention).
    /// Defaults to 256.
    pub jvt_history_length: u64,
}

impl Default for RocksDbConfig {
    fn default() -> Self {
        Self {
            max_background_jobs: 4,
            write_buffer_size: 128 * 1024 * 1024, // 128MB
            max_write_buffer_number: 3,
            block_cache_size: Some(1024 * 1024 * 1024), // 1GB
            compression: CompressionType::Lz4,
            bloom_filter_bits: 10.0,
            bytes_per_sync: 1024 * 1024, // 1MB
            keep_log_file_num: 10,
            column_families: ALL_COLUMN_FAMILIES.iter().map(|s| s.to_string()).collect(),
            jvt_history_length: 256,
        }
    }
}
