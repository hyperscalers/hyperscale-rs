//! Configuration types for `RocksDB` storage.
//!
//! Pure tuning knobs and options. Column family definitions live in
//! [`column_families`](crate::column_families).

use crate::column_families::ALL_COLUMN_FAMILIES;

/// Compression type for `RocksDB`. Each variant maps 1:1 to the
/// same-named [`rocksdb::DBCompressionType`].
#[derive(Debug, Clone, Copy, Default)]
pub enum CompressionType {
    /// No compression.
    None,
    /// Google Snappy.
    Snappy,
    /// zlib (DEFLATE).
    Zlib,
    /// LZ4 (default — fastest decompression at low ratios).
    #[default]
    Lz4,
    /// LZ4 high-compression mode.
    Lz4hc,
    /// Facebook Zstandard.
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

/// Configuration for `RocksDB` storage.
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
    /// Number of block heights of JMT history to retain before garbage collection.
    ///
    /// Stale JMT nodes and their associations are kept for this many heights
    /// before being eligible for deletion. This enables historical queries within
    /// this window.
    ///
    /// Set to 0 for immediate deletion (no history retention).
    /// Defaults to 256.
    pub jmt_history_length: u64,
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
            column_families: ALL_COLUMN_FAMILIES
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            jmt_history_length: 256,
        }
    }
}
