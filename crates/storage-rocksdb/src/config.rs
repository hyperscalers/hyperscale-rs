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

/// Old storage keys deleted by partition Reset operations, keyed by `(entity_key, partition_num)`.
/// Passed to `put_at_version` so the JVT can generate deletes for the hashed keys.
pub(crate) type ResetOldKeys = std::collections::HashMap<(Vec<u8>, u8), Vec<Vec<u8>>>;

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
            column_families: vec![
                "default".to_string(),
                "blocks".to_string(),
                "transactions".to_string(),
                "state".to_string(),
                "certificates".to_string(),
                "votes".to_string(),     // BFT safety critical - stores own votes
                "jmt_nodes".to_string(), // JVT tree nodes for state commitment (legacy CF name)
                "associated_state_tree_values".to_string(), // Historical substate values (leaf key -> value)
                "stale_state_hash_tree_parts".to_string(),  // Deferred GC queue for stale JVT nodes
                "versioned_substates".to_string(), // MVCC versioned substates for historical reads
                "ledger_receipts".to_string(),     // Ledger receipts keyed by tx hash
                "local_executions".to_string(),    // Local execution details keyed by tx hash
            ],
            jvt_history_length: 256,
        }
    }
}
